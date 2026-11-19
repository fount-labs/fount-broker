package coordinator

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	pathpkg "path"
	"strings"
	"time"
	"unicode/utf8"
)

// Creating a worker in Cloud (launch-plan.md, A). The admin device that made
// the worker's address hands the coordinator its keys, worker.json, the
// requesters, the instructions and the reply mode in one request, sealed
// under the worker's DEK:
//
//	PUT /v1/workers/{id}/mail   {"v":1,"sealed":"<base64>"}
//
// sealed is AES-256-GCM under the DEK, nonce || ciphertext, with the AAD
// aad(purposeMailSetup, worker id, ""), of a MailSetup as JSON, decoded
// strictly. Only an admin may send it (opRoles): the address keys go to
// admin devices and the coordinator, never a reviewer's (decision 25). The
// answer is the worker's MailView.
//
// Sending the same setup again, as a retry does, changes nothing. A worker
// that already has another address refuses it (ErrMailboxSet).
const (
	purposeMailSetup = "fount-worker/mail-setup/v1"
	mailSetupVersion = 1

	maxMailSetupBody    = 1 << 20
	maxSetupInstruction = 64 << 10
	maxSetupWorkerFile  = 256 << 10

	// workerFilePath is the worker.json the creating device handed over,
	// kept as it came. Jobs don't see it; it isn't under root/.
	workerFilePath = prefixRecord + "worker.json"
	// instructionsPath is the worker's standing instructions, which jobs
	// and intake read.
	instructionsPath = prefixRoot + "instructions.md"
)

// ErrMailboxSet is a worker that already has another address.
var ErrMailboxSet = errors.New("the worker already has an address")

// MailSetup is what a worker starts its Cloud life with.
type MailSetup struct {
	Mailbox      Mailbox          `json:"mailbox"`
	Requesters   []SetupRequester `json:"requesters"`
	Instructions string           `json:"instructions"`
	// Worker is the creating device's worker.json, kept as it came.
	Worker json.RawMessage `json:"worker"`
	// Reply is setDefaultMode's args, without a base revision: chosen when
	// the worker is made, with nothing preselected (decision 7).
	Reply SetupReply `json:"reply"`
	// AutoRun turns the worker's automatic runs on from now.
	AutoRun bool `json:"autoRun"`
	// Acknowledge sends the fixed acknowledgement (decision 8).
	Acknowledge bool `json:"acknowledge"`
	// RoutingVersion is the version at which the device wrote exactly these
	// requesters to the edge (PUT /routing), or 0 when it hasn't.
	RoutingVersion uint64 `json:"routingVersion"`
}

// SetupRequester is a requester the creating device named.
type SetupRequester struct {
	Address string `json:"address"`
	AutoRun bool   `json:"autoRun"`
}

// SetupReply is the worker's reply mode: notify, full or full_owner, the
// owner (a requester) full_owner puts on Full, and the firm footers name.
type SetupReply struct {
	Mode  string `json:"mode"`
	Owner string `json:"owner,omitempty"`
	Firm  string `json:"firm,omitempty"`
}

// mailSetupBody is PUT /v1/workers/{id}/mail's body.
type mailSetupBody struct {
	V      int    `json:"v"`
	Sealed string `json:"sealed"`
}

func mailSetupAAD(workerID string) []byte { return aad(purposeMailSetup, workerID, "") }

// SealMailSetup seals s for the worker under its DEK, as Desktop does.
func SealMailSetup(dek DEK, workerID string, s MailSetup) ([]byte, error) {
	plain, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return seal(dek[:], plain, mailSetupAAD(workerID))
}

// OpenMailSetup opens and checks a sealed setup: decoded strictly, every
// address checked and lowercased, the reply mode one of the three.
func OpenMailSetup(dek DEK, workerID string, sealed []byte) (*MailSetup, error) {
	plain, err := open(dek[:], sealed, mailSetupAAD(workerID))
	if err != nil {
		return nil, fmt.Errorf("%w: the setup doesn't open under the worker's key", ErrInvalid)
	}
	var s MailSetup
	if err := decodeStrictJSON(plain, &s); err != nil {
		return nil, fmt.Errorf("%w: the setup: %v", ErrInvalid, err)
	}
	if err := s.check(); err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *MailSetup) check() error {
	if err := s.Mailbox.check(); err != nil {
		return err
	}
	s.Mailbox.Address, _ = mailAddress(s.Mailbox.Address)
	if len(s.Requesters) > maxRequesters {
		return fmt.Errorf("%w: a worker has at most %d requesters", ErrInvalid, maxRequesters)
	}
	seen := map[string]bool{}
	for i := range s.Requesters {
		a, err := mailAddress(s.Requesters[i].Address)
		if err != nil {
			return err
		}
		if strings.HasSuffix(a, "@"+domainOf(s.Mailbox.Address)) {
			return fmt.Errorf("%w: %s is a worker's address, which can't send work", ErrInvalid, a)
		}
		if seen[a] {
			return fmt.Errorf("%w: %s is listed twice", ErrInvalid, a)
		}
		seen[a] = true
		s.Requesters[i].Address = a
	}
	if len(s.Instructions) > maxSetupInstruction || !utf8.ValidString(s.Instructions) {
		return fmt.Errorf("%w: instructions are UTF-8 of at most %d bytes", ErrInvalid, maxSetupInstruction)
	}
	if len(s.Worker) > maxSetupWorkerFile || !bytes.HasPrefix(bytes.TrimSpace(s.Worker), []byte("{")) {
		return fmt.Errorf("%w: worker is a JSON object of at most %d bytes", ErrInvalid, maxSetupWorkerFile)
	}
	var named struct {
		Address string `json:"address"`
	}
	if err := json.Unmarshal(s.Worker, &named); err != nil {
		return fmt.Errorf("%w: worker: %v", ErrInvalid, err)
	}
	if named.Address != "" && !strings.EqualFold(strings.TrimSpace(named.Address), s.Mailbox.Address) {
		return fmt.Errorf("%w: worker.json is %s's, not %s's", ErrInvalid, named.Address, s.Mailbox.Address)
	}
	r := &s.Reply
	if r.Mode != modeNotify && r.Mode != modeFull && r.Mode != modeFullOwner {
		return fmt.Errorf("%w: the reply mode is notify, full or full_owner", ErrInvalid)
	}
	r.Firm = strings.Join(strings.Fields(r.Firm), " ")
	if len([]rune(r.Firm)) > maxFirmChars {
		return fmt.Errorf("%w: firm is at most %d characters", ErrInvalid, maxFirmChars)
	}
	if r.Owner != "" {
		owner, err := mailAddress(r.Owner)
		if err != nil {
			return err
		}
		if !seen[owner] {
			return fmt.Errorf("%w: the owner %s isn't a requester", ErrInvalid, owner)
		}
		r.Owner = owner
	}
	if r.Mode == modeFullOwner && r.Owner == "" {
		return fmt.Errorf("%w: full_owner needs the owner's address", ErrInvalid)
	}
	return nil
}

func (m Mailbox) same(o Mailbox) bool {
	return m.Address == o.Address && m.MailboxID == o.MailboxID &&
		subtle.ConstantTimeCompare(m.SigningKey, o.SigningKey) == 1 &&
		subtle.ConstantTimeCompare(m.DecryptionKey, o.DecryptionKey) == 1
}

// SetUpMail opens a sealed setup with the worker's DEK and gives the worker
// everything in it in one commit: its address and keys, its requesters,
// automatic runs and the acknowledgement, its reply mode, its instructions
// and its worker.json. Then its mail loop starts, with the mailbox enrolled
// under this coordinator's generation when it has one.
func (c *Coordinator) SetUpMail(device, workerID string, sealed []byte) error {
	c.mu.Lock()
	w, ok := c.state.Workers[workerID]
	var wrapped []byte
	if ok && w.mayAct(device) {
		wrapped = w.WrappedDEK
	}
	c.mu.Unlock()
	if !ok {
		return ErrNoWorker
	}
	if wrapped == nil {
		return ErrNotGranted
	}
	dek, err := c.cfg.Key.Unwrap(workerID, wrapped)
	if err != nil {
		return err
	}
	s, err := OpenMailSetup(dek, workerID, sealed)
	clear(dek[:])
	if err != nil {
		return err
	}
	keys, _ := s.Mailbox.keys()
	err = c.change(workerID, device, func(t *Tree) error {
		held, err := loadMailbox(t)
		switch {
		case err == nil && held.same(s.Mailbox):
			return nil
		case err == nil:
			return fmt.Errorf("%w: %s", ErrMailboxSet, held.Address)
		case !errors.Is(err, ErrNoMailbox):
			return err
		}
		return writeMailSetup(t, s, time.Now().UTC())
	})
	if err != nil {
		return err
	}
	if err := c.mailboxReady(workerID, s.Mailbox, keys); err != nil {
		return err
	}
	if c.mail == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if w, err := c.Worker(workerID); err == nil {
		if err := c.enrollMail(ctx, w); err != nil {
			log.Printf("mail: worker %s: %v; the mail loop tries again", workerID, err)
		}
	}
	return nil
}

// writeMailSetup stages a setup on a worker with no mailbox yet.
func writeMailSetup(t *Tree, s *MailSetup, now time.Time) error {
	if err := writeJSON(t, mailboxPath, s.Mailbox); err != nil {
		return err
	}
	ms, err := loadMailSettings(t)
	if err != nil {
		return err
	}
	for _, r := range s.Requesters {
		if ms.requester(r.Address) == nil {
			ms.addRequester(Requester{Address: r.Address, AutoRun: r.AutoRun, PairedBy: "added", AddedAt: now}, nil)
		}
	}
	ms.RoutingUnsent = s.RoutingVersion == 0 && len(ms.Requesters) > 0
	if s.AutoRun != ms.AutoRun {
		ms.AutoRun, ms.AutoRunSince = s.AutoRun, now
		ms.AutoRunRev++
	}
	if s.Acknowledge != ms.Acknowledge {
		ms.Acknowledge = s.Acknowledge
		ms.AcknowledgeRev++
	}
	if err := writeJSON(t, mailSettingsPath, ms); err != nil {
		return err
	}
	rs, err := loadReplySettings(t)
	if err != nil {
		return err
	}
	rs.Mode, rs.Owner, rs.Firm = s.Reply.Mode, s.Reply.Owner, s.Reply.Firm
	rs.Revision++
	if err := writeJSON(t, replySettingsPath, rs); err != nil {
		return err
	}
	if strings.TrimSpace(s.Instructions) != "" {
		if err := t.Write(instructionsPath, []byte(s.Instructions)); err != nil {
			return err
		}
	}
	return t.Write(workerFilePath, s.Worker)
}

func (a *api) setUpMail(rw http.ResponseWriter, r *http.Request) {
	w, err := a.worker(r)
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	var body mailSetupBody
	if err := decodeStrict(r.Body, maxMailSetupBody, &body); err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	if body.V != mailSetupVersion {
		fail(rw, http.StatusBadRequest, fmt.Errorf("a mail setup is v %d", mailSetupVersion))
		return
	}
	sealed, err := base64.StdEncoding.Strict().DecodeString(body.Sealed)
	if err != nil {
		fail(rw, http.StatusBadRequest, errors.New("sealed isn't base64"))
		return
	}
	if err := a.c.SetUpMail(a.device(), w.ID, sealed); err != nil {
		if errors.Is(err, ErrMailboxSet) {
			fail(rw, http.StatusConflict, err)
			return
		}
		fail(rw, statusOf(err), err)
		return
	}
	a.getMail(rw, r)
}

// readableByClients says whether a client may read path from a worker's
// tree over the account API: everything but the address keys, which only
// the coordinator reads (decision 25).
func readableByClients(path string) bool {
	return pathpkg.Clean(path) != mailboxPath
}
