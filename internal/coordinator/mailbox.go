package coordinator

import (
	"cmp"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/fount-labs/fount-broker/internal/mail"
)

// A Cloud worker's mail (launch-plan.md, B) is kept in its tree, under its DEK,
// beside its threads:
//
//	record/mail/mailbox.json   the address and its keys
//	record/mail/settings.json  requesters, automatic runs, the acknowledgement, a pairing
//	record/mail/ledger.json    what was acted on (mailledger.go)
//	record/mail/pending.json   what the coordinator still owes a message once acted on (mailintake.go)
//	record/mail/handles.json   each reply-token handle's thread
//	root/threads/<thread>/<YYYY-MM-DD-edge id>/   each message's folder, as intake wrote it
//	record/mail/held/<thread>/<YYYY-MM-DD-edge id>/   a held message's, until it is run
//
// The volume holds only the mailbox id (Worker.Mailbox), so the poller knows
// which workers have mail without opening their trees.
const (
	prefixMailRecord = prefixRecord + "mail/"
	mailboxPath      = prefixMailRecord + "mailbox.json"
	mailSettingsPath = prefixMailRecord + "settings.json"
	mailLedgerPath   = prefixMailRecord + "ledger.json"
	mailPendingPath  = prefixMailRecord + "pending.json"
	mailHandlesPath  = prefixMailRecord + "handles.json"
	// heldMailDir holds held mail's folders, by thread (mailFolderPath).
	heldMailDir = prefixMailRecord + "held/"
)

// ErrNoMailbox is a worker with no address yet.
var ErrNoMailbox = errors.New("the worker has no mailbox")

// Mailbox is an address and the keys the coordinator reads and signs its mail
// with. An admin device hands them over sealed when it makes the worker
// (mailsetup.go); the dev and test API puts them in the clear
// (PUT /v0/workers/{id}/mail).
type Mailbox struct {
	Address   string `json:"address"`
	MailboxID string `json:"mailboxId"`
	// SigningKey is the address's Ed25519 seed; DecryptionKey its X25519 key.
	SigningKey    []byte `json:"signingKey"`
	DecryptionKey []byte `json:"decryptionKey"`
	// NextSigningKey is a rotation's new seed, kept before the edge is
	// asked so a lost answer is retried with the same key (rotate.go).
	// Reply tokens aren't keyed from any of these (Coordinator.mailKeys).
	NextSigningKey []byte `json:"nextSigningKey,omitempty"`
	// NextDecryptionKey is a rotation's new X25519 key, kept the same way,
	// and OlderDecryptionKeys the ones it replaced, newest first, for mail
	// the edge sealed to them before (rotate.go).
	NextDecryptionKey   []byte   `json:"nextDecryptionKey,omitempty"`
	OlderDecryptionKeys [][]byte `json:"olderDecryptionKeys,omitempty"`
}

// replyTokenKeyInfo labels the reply-token key (decision 25).
const replyTokenKeyInfo = "fount-coordinator/reply-token-key/v1"

// mailKeys are mb's keys as the mail loop reads and sends with them, with
// the reply-token key (internal/mail replytoken.go). That key is the
// coordinator's alone: HKDF-SHA256 from its wrapping key, info the label, a
// zero byte and the mailbox id in hex. It's derived, never stored, so it's in
// no tree, backup, export or mail setup, and no device it wraps a DEK or an
// address key to can mint a token. A Cloud worker's address keys are wrapped
// to every admin device; a token keyed from the signing seed would let a
// removed admin forge a thread's token, and its rotation would need the old
// seed kept. This way rotating the signing key leaves every token as it was.
func (c *Coordinator) mailKeys(mb *Mailbox) (*mail.Keys, error) {
	k, err := mb.keys()
	if err != nil {
		return nil, err
	}
	k.TokenKey = c.tokenKey(mb.MailboxID)
	return k, nil
}

func (c *Coordinator) tokenKey(mailboxID string) []byte {
	key, err := hkdf.Key(sha256.New, c.cfg.Key[:], nil, replyTokenKeyInfo+"\x00"+mailboxID, mail.TokenKeySize)
	if err != nil {
		panic("hkdf: " + err.Error())
	}
	return key
}

// keys are mb's keys without the reply-token key: enough to sign a call or
// read mail, not to mint or check a token. The mail loop's are mailKeys.
func (m Mailbox) keys() (*mail.Keys, error) {
	id, err := hex.DecodeString(m.MailboxID)
	if err != nil || len(id) != 32 || hex.EncodeToString(id) != m.MailboxID {
		return nil, fmt.Errorf("%w: mailboxId must be 64 lowercase hex characters", ErrInvalid)
	}
	if len(m.SigningKey) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: signingKey must be a 32-byte Ed25519 seed", ErrInvalid)
	}
	dec, err := ecdh.X25519().NewPrivateKey(m.DecryptionKey)
	if err != nil {
		return nil, fmt.Errorf("%w: decryptionKey must be a 32-byte X25519 key", ErrInvalid)
	}
	k := &mail.Keys{MailboxID: id, Signing: ed25519.NewKeyFromSeed(m.SigningKey), Decryption: dec}
	for _, raw := range append([][]byte{m.NextDecryptionKey}, m.OlderDecryptionKeys...) {
		if raw == nil {
			continue
		}
		older, err := ecdh.X25519().NewPrivateKey(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: a kept decryption key isn't a 32-byte X25519 key", ErrInvalid)
		}
		k.Older = append(k.Older, older)
	}
	return k, nil
}

func (m Mailbox) check() error {
	if _, err := mailAddress(m.Address); err != nil {
		return err
	}
	_, err := m.keys()
	return err
}

// mailAddress is an address, trimmed and lowercase, or ErrInvalid.
func mailAddress(typed string) (string, error) {
	a := strings.ToLower(strings.TrimSpace(typed))
	local, domain, ok := strings.Cut(a, "@")
	if !ok || local == "" || !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") ||
		strings.Contains(domain, "@") || len(a) > 254 || strings.ContainsAny(a, " \t\r\n<>,;\"") {
		return "", fmt.Errorf("%w: %q isn't an email address", ErrInvalid, strings.TrimSpace(typed))
	}
	return a, nil
}

func domainOf(address string) string {
	if at := strings.LastIndexByte(address, '@'); at >= 0 {
		return address[at+1:]
	}
	return ""
}

// Requester is someone whose email can start a job (verdict.rs, worker.rs).
type Requester struct {
	Address string `json:"address"`
	// DKIMDomain is the aligned d= the pairing recorded, or empty.
	DKIMDomain string `json:"dkimDomain,omitempty"`
	AutoRun    bool   `json:"autoRun"`
	// PairedBy is "reply" (they answered the edge's connect email),
	// "confirmed" (someone said in the app an email was theirs) or "added"
	// (added from held mail or settings).
	PairedBy string    `json:"pairedBy"`
	AddedAt  time.Time `json:"addedAt"`
	// Reason is why their jobs need confirming, when they do.
	Reason string `json:"reason,omitempty"`
}

// MailSettings is what decides a worker's mail. Each part names its own
// revision, which an operation changing it gives as its base (decision 5), so
// turning automatic runs on doesn't refuse an addRequester made at the same
// time.
type MailSettings struct {
	Requesters    []Requester `json:"requesters"`
	RequestersRev uint64      `json:"requestersRevision"`
	// AutoRun is the worker's switch: a requester's request runs by itself
	// only while it is on, and only for mail that arrived after AutoRunSince.
	AutoRun      bool      `json:"autoRun"`
	AutoRunSince time.Time `json:"autoRunSince,omitzero"`
	AutoRunRev   uint64    `json:"autoRunRevision"`
	// Acknowledge sends a requester the fixed acknowledgement when their
	// request starts a turn (decision 8). Off by default.
	Acknowledge    bool     `json:"acknowledge"`
	AcknowledgeRev uint64   `json:"acknowledgeRevision"`
	Pairing        *Pairing `json:"pairing,omitempty"`
	PairingRev     uint64   `json:"pairingRevision"`
	// RoutingUnsent is set when the requester list changed since a device
	// last wrote it to the edge (PUT /routing). The owner-change key that
	// signs it is never granted to Cloud, so a device does that and says so
	// with routingSaved. Proofs are connect replies for it to carry.
	RoutingUnsent bool           `json:"routingUnsent"`
	Proofs        []ConnectProof `json:"proofs,omitempty"`
	// JobsPerDay caps the jobs mail starts by itself: Desktop's
	// limits.jobsPerDay. 0 is the default.
	JobsPerDay int `json:"jobsPerDay,omitempty"`
}

// ConnectProof is a requester's reply to the edge's connect email: the
// Message-ID it answered, which PUT /routing carries (Desktop's ConnectProof).
type ConnectProof struct {
	Owner     string `json:"owner"`
	MessageID string `json:"messageId"`
}

const (
	defaultJobsPerDay = 50
	// maxJobsPerSenderPerHour is Desktop's MAX_JOBS_PER_SENDER_PER_HOUR.
	maxJobsPerSenderPerHour = 10
	maxRequesters           = 256
)

func (s *MailSettings) requester(address string) *Requester {
	for i := range s.Requesters {
		if strings.EqualFold(s.Requesters[i].Address, address) {
			return &s.Requesters[i]
		}
	}
	return nil
}

func (s *MailSettings) jobsPerDay() int {
	if s.JobsPerDay > 0 {
		return s.JobsPerDay
	}
	return defaultJobsPerDay
}

// addRequester adds r and moves the list's revision on.
func (s *MailSettings) addRequester(r Requester, proof *ConnectProof) {
	s.Requesters = append(s.Requesters, r)
	s.RequestersRev++
	s.RoutingUnsent = true
	if proof != nil {
		s.Proofs = append(s.Proofs, *proof)
	}
}

func readJSON[T any](t *Tree, path string, v *T) (bool, error) {
	data, err := t.Read(path)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err == nil && path == mailboxPath {
		data, _, err = t.openSecret(path, data)
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}
	return true, nil
}

func writeJSON(t *Tree, path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if path == mailboxPath {
		if data, err = t.sealSecret(path, data); err != nil {
			return err
		}
	}
	return t.Write(path, data)
}

func loadMailbox(t *Tree) (*Mailbox, error) {
	var m Mailbox
	ok, err := readJSON(t, mailboxPath, &m)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNoMailbox
	}
	return &m, nil
}

func loadMailSettings(t *Tree) (*MailSettings, error) {
	s := &MailSettings{}
	if _, err := readJSON(t, mailSettingsPath, s); err != nil {
		return nil, err
	}
	if s.Requesters == nil {
		s.Requesters = []Requester{}
	}
	return s, nil
}

// SetMailbox gives a worker its address and keys, and starts its mail loop.
// requesters, if any, are its first requesters. It is the dev and test API's;
// clients use SetUpMail.
func (c *Coordinator) SetMailbox(workerID string, mb Mailbox, requesters []Requester) error {
	if err := mb.check(); err != nil {
		return err
	}
	mb.Address, _ = mailAddress(mb.Address)
	if err := c.mailboxFree(workerID, mb.MailboxID); err != nil {
		return err
	}
	keys, _ := c.mailKeys(&mb)
	for i := range requesters {
		a, err := mailAddress(requesters[i].Address)
		if err != nil {
			return err
		}
		requesters[i].Address = a
	}
	err := c.change(workerID, anyDevice, func(t *Tree) error {
		if err := writeJSON(t, mailboxPath, mb); err != nil {
			return err
		}
		s, err := loadMailSettings(t)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		for _, r := range requesters {
			if s.requester(r.Address) == nil {
				r.AddedAt = now
				r.PairedBy = cmp.Or(r.PairedBy, "added")
				s.addRequester(r, nil)
			}
		}
		return writeJSON(t, mailSettingsPath, s)
	})
	if err != nil {
		return err
	}
	return c.mailboxReady(workerID, mb, keys)
}

// mailboxReady records a worker's mailbox id on the volume and starts its
// mail loop, once its mailbox is committed to its tree.
func (c *Coordinator) mailboxReady(workerID string, mb Mailbox, keys *mail.Keys) error {
	var err error
	c.mu.Lock()
	if holder := c.mailboxHolder(workerID, mb.MailboxID); holder != "" {
		c.mu.Unlock()
		return fmt.Errorf("%w: worker %s has %s", ErrMailboxTaken, holder, mb.Address)
	}
	if w := c.state.Workers[workerID]; w != nil && w.Mailbox != mb.MailboxID {
		w.Mailbox = mb.MailboxID
		err = c.state.Save(c.cfg.StateDir)
	}
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if c.mail != nil {
		c.mail.service.PutKeys(keys)
		// Synced now, which enrolls it: the changes feed lists only
		// enrolled mailboxes.
		c.mail.kick(workerID)
	}
	return nil
}

// mailboxFree refuses a mailbox id another worker than workerID holds.
func (c *Coordinator) mailboxFree(workerID, mailboxID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if holder := c.mailboxHolder(workerID, mailboxID); holder != "" {
		return fmt.Errorf("%w: worker %s has it", ErrMailboxTaken, holder)
	}
	return nil
}

// mailboxHolder is the worker other than workerID that holds mailboxID, or
// "". Caller holds c.mu.
func (c *Coordinator) mailboxHolder(workerID, mailboxID string) string {
	for id, w := range c.state.Workers {
		if id != workerID && w.Mailbox == mailboxID {
			return id
		}
	}
	return ""
}

// MailView is a worker's mail settings as a client reads them: no keys.
type MailView struct {
	Address string `json:"address"`
	MailSettings
	Renewal *Renewed `json:"renewal,omitempty"`
}

func (c *Coordinator) mailView(device, workerID string) (MailView, error) {
	var v MailView
	err := c.view(workerID, device, func(t *Tree) error {
		mb, err := loadMailbox(t)
		if err != nil {
			return err
		}
		s, err := loadMailSettings(t)
		if err != nil {
			return err
		}
		v = MailView{Address: mb.Address, MailSettings: *s}
		var r Renewed
		if ok, err := readJSON(t, renewedPath, &r); err != nil {
			return err
		} else if ok {
			v.Renewal = &r
		}
		return nil
	})
	return v, err
}

// putMailboxBody is the dev and test API's PUT /v0/workers/{id}/mail.
type putMailboxBody struct {
	Mailbox    Mailbox     `json:"mailbox"`
	Requesters []Requester `json:"requesters,omitempty"`
}

const maxMailboxBody = 64 << 10

func (a *api) putMailbox(rw http.ResponseWriter, r *http.Request) {
	w, err := a.worker(r)
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	var body putMailboxBody
	if err := decodeStrict(r.Body, maxMailboxBody, &body); err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	if err := a.c.SetMailbox(w.ID, body.Mailbox, body.Requesters); err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	a.getMail(rw, r)
}

func (a *api) getMail(rw http.ResponseWriter, r *http.Request) {
	w, err := a.worker(r)
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	v, err := a.c.mailView(a.device(), w.ID)
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusOK, v)
}
