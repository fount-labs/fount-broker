package coordinator

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"
)

// The mail operations (thread-operations.md §5.8, §5.9 and the worker
// operations after it). Two act on a thread's held mail: runHeldMail and
// addRequester. The rest act on the worker's mail settings, and each names the
// revision of the part it changes as its base (decision 5): a stale one is
// WORKER_CHANGED and changes nothing, so of two reviewers the first wins.
//
//	addRequester    {address, baseRevision}       the requester list's
//	setAutoRun      {on, baseRevision}            automatic runs'
//	setAcknowledge  {on, baseRevision}            the acknowledgement's (decision 8)
//	pairingStart    {requester, expiresAt, baseRevision}  the pairing's; a device sent POST /connect
//	pairingConfirm  {mailId, baseRevision}        the pairing's; mailId is an untokened email's edge id
//	routingSaved    {requestersRevision}          a device wrote that list to the edge

// Who may apply each of these is opRoles' (members.go): the account API
// checks the caller's role on the worker before any operation is applied. The
// coordinator's own changes (mail arriving, jobs ending) aren't operations.

const (
	CodeAlreadyRun          OpCode = "ALREADY_RUN"
	CodeAlreadyRequester    OpCode = "ALREADY_REQUESTER"
	CodeFountboxAddress     OpCode = "FOUNTBOX_ADDRESS"
	CodeRecipientNotAllowed OpCode = "RECIPIENT_NOT_ALLOWED"
	CodeWorkerChanged       OpCode = "WORKER_CHANGED"
	CodeNoMailbox           OpCode = "NO_MAILBOX"
	CodePairingClosed       OpCode = "PAIRING_CLOSED"
)

func init() {
	maps.Copy(opMessages, map[OpCode]string{
		CodeAlreadyRun:          "This email is already being worked on.",
		CodeAlreadyRequester:    "This address can already send this worker work.",
		CodeFountboxAddress:     "A Fount worker can't send work to a worker.",
		CodeRecipientNotAllowed: "That address can't send this worker work.",
		CodeWorkerChanged:       "This worker's settings changed since you looked. Look again, then try.",
		CodeNoMailbox:           "This worker has no email address yet.",
		CodePairingClosed:       "This pairing already found its owner, or there's none waiting.",
	})
}

// heldMailArgs are runHeldMail's: the held entry and, optionally, what to do
// with it instead of the standing instructions.
type heldMailArgs struct {
	MailID string  `json:"mailId"`
	Text   *string `json:"text,omitempty"`
}

// mailRequesterArgs are the thread form of addRequester: a held entry's
// sender.
type mailRequesterArgs struct {
	MailID  string `json:"mailId"`
	Address string `json:"address"`
}

// parseMailThreadOp decodes the mail thread operations' args, or reports the
// kind isn't one.
func parseMailThreadOp(env opEnvelope) (any, bool, error) {
	switch env.Kind {
	case "runHeldMail":
		var a heldMailArgs
		if err := decodeArgs(env.Args, &a); err != nil {
			return nil, true, err
		}
		return a, true, checkID("mail", a.MailID)
	case "addRequester":
		var a mailRequesterArgs
		if err := decodeArgs(env.Args, &a); err != nil {
			return nil, true, err
		}
		return a, true, checkID("mail", a.MailID)
	}
	return nil, false, nil
}

// heldMail is the mail entry id names on th.
func heldMail(th *threadRecord, id string) (*threadEntry, error) {
	e := th.entry(id)
	if e == nil || e.Kind != entryMail {
		return nil, refusal{code: CodeNotFound}
	}
	return e, nil
}

// runHeldMail is §5.8: run held mail once. The sender doesn't join the
// thread: running a stranger's email once doesn't make them someone the
// worker emails.
func (c *Coordinator) runHeldMail(t *Tree, th *threadRecord, a heldMailArgs, rev uint64) (effects, error) {
	e, err := heldMail(th, a.MailID)
	if err != nil {
		return effects{}, err
	}
	if e.Mail.Held != heldWaiting {
		return effects{}, refusal{code: CodeAlreadyRun}
	}
	var instruction string
	if a.Text != nil {
		if instruction, err = noteText(*a.Text); err != nil {
			return effects{}, err
		}
	}
	switch {
	case len(c.cfg.JobConfig) == 0:
		return effects{}, refusal{code: CodeNoModel}
	case len(th.Jobs) >= maxThreadJobs:
		return effects{}, refusal{code: CodeThreadCap}
	}
	m := e.Mail
	if instruction == "" {
		instruction = cmp.Or(m.Instruction, "Handle the email in this thread as your instructions say.")
	}
	spec, err := IntakeSpec{Instruction: instruction}.JobSpec(th.ID, th.SessionID, m.Folder, c.cfg.JobConfig)
	if err != nil {
		return effects{}, err
	}
	m.Held, m.Intake, m.JobID, e.Rev = heldRun, intakePending, mailJobID(m.EdgeID), rev
	err = owe(t, pendingMail{Kind: pendingJob, ThreadID: th.ID, EdgeID: m.EdgeID, JobID: m.JobID, Spec: &spec})
	return effects{mail: true}, err
}

// addRequesterFromMail is §5.9 from held mail: the address must be the
// email's checked sender. They join the list with auto-run off and the
// email's aligned domain, and join the thread.
func (c *Coordinator) addRequesterFromMail(t *Tree, th *threadRecord, a mailRequesterArgs, rev uint64, now time.Time) error {
	e, err := heldMail(th, a.MailID)
	if err != nil {
		return err
	}
	address := strings.ToLower(strings.TrimSpace(a.Address))
	if e.Mail.Sender == "" || address != e.Mail.Sender {
		return refusal{code: CodeRecipientNotAllowed, detail: map[string]string{"address": address}}
	}
	mb, err := loadMailbox(t)
	if err != nil {
		return err
	}
	s, err := loadMailSettings(t)
	if err != nil {
		return err
	}
	if err := c.mayAddRequester(mb, s, address); err != nil {
		return err
	}
	s.addRequester(Requester{Address: address, DKIMDomain: e.Mail.Signed, PairedBy: "added", AddedAt: now}, nil)
	if err := writeJSON(t, mailSettingsPath, s); err != nil {
		return err
	}
	e.Mail.Held, e.Rev = heldAdded, rev
	if !th.hasParticipant(address) {
		th.Participants = append(th.Participants, address)
	}
	return th.event(rev, now, "requester_added", map[string]string{"address": address})
}

func (c *Coordinator) mayAddRequester(mb *Mailbox, s *MailSettings, address string) error {
	if _, err := mailAddress(address); err != nil {
		return err
	}
	switch {
	case strings.HasSuffix(address, "@"+domainOf(mb.Address)):
		return refusal{code: CodeFountboxAddress}
	case s.requester(address) != nil:
		return refusal{code: CodeAlreadyRequester}
	case len(s.Requesters) >= maxRequesters:
		return fmt.Errorf("%w: a worker has at most %d requesters", ErrInvalid, maxRequesters)
	}
	return nil
}

// The worker operations on mail settings.

type requesterArgs struct {
	Address      string `json:"address"`
	BaseRevision uint64 `json:"baseRevision"`
}

type switchArgs struct {
	On           bool   `json:"on"`
	BaseRevision uint64 `json:"baseRevision"`
}

type pairingStartArgs struct {
	Requester string `json:"requester"`
	// ExpiresAt is when the edge's connect email stops counting, epoch
	// milliseconds, as POST /connect answered it.
	ExpiresAt    int64  `json:"expiresAt"`
	BaseRevision uint64 `json:"baseRevision"`
}

type pairingConfirmArgs struct {
	MailID       string `json:"mailId"`
	BaseRevision uint64 `json:"baseRevision"`
}

type routingSavedArgs struct {
	RequestersRevision uint64 `json:"requestersRevision"`
}

var mailWorkerOps = map[string]func() any{
	"addRequester":   func() any { return &requesterArgs{} },
	"setAutoRun":     func() any { return &switchArgs{} },
	"setAcknowledge": func() any { return &switchArgs{} },
	"pairingStart":   func() any { return &pairingStartArgs{} },
	"pairingConfirm": func() any { return &pairingConfirmArgs{} },
	"routingSaved":   func() any { return &routingSavedArgs{} },
}

func isMailWorkerOp(kind string) bool {
	_, ok := mailWorkerOps[kind]
	return ok
}

// applyMailWorkerOp checks and applies a worker operation on the mail
// settings, logged with startThread's for retries.
func (c *Coordinator) applyMailWorkerOp(device, workerID string, env workerOpEnvelope) (OpResult, error) {
	if err := checkID("op", env.OpID); err != nil {
		return OpResult{}, err
	}
	args := mailWorkerOps[env.Kind]()
	if err := decodeArgs(env.Args, args); err != nil {
		return OpResult{}, err
	}
	hash := argsHash("", env.Kind, args)
	var result OpResult
	err := c.changeThen(workerID, device, func(t *Tree) error {
		ops, err := loadOpLog(t, workerOps)
		if err != nil {
			return err
		}
		if r, ok := retried(ops, env.OpID, hash, 0); ok {
			result = r
			return nil
		}
		mb, err := loadMailbox(t)
		if errors.Is(err, ErrNoMailbox) {
			result = refused(0, CodeNoMailbox)
			return nil
		}
		if err != nil {
			return err
		}
		s, err := loadMailSettings(t)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		rev, err := c.applyMailSettingsOp(mb, s, args, env.Kind, now)
		var r refusal
		if errors.As(err, &r) {
			result = refused(rev, r.code)
			result.Detail = r.detail
			return nil
		}
		if err != nil {
			return err
		}
		result = OpResult{OK: true, Revision: rev}
		ops[env.OpID] = loggedOp{ArgsHash: hash, Revision: rev, Result: result, At: now}
		if err := writeJSON(t, mailSettingsPath, s); err != nil {
			return err
		}
		return saveOpLog(t, workerOps, ops)
	}, nil)
	return result, err
}

// stale is WORKER_CHANGED unless base is the part's revision now.
func stale(base, current uint64) error {
	if base != current {
		return refusal{code: CodeWorkerChanged, detail: map[string]string{"revision": fmt.Sprint(current)}}
	}
	return nil
}

// applyMailSettingsOp changes s and returns the changed part's revision, or
// on a refusal its revision as it stands.
func (c *Coordinator) applyMailSettingsOp(mb *Mailbox, s *MailSettings, args any, kind string, now time.Time) (uint64, error) {
	switch a := args.(type) {
	case *requesterArgs:
		if err := stale(a.BaseRevision, s.RequestersRev); err != nil {
			return s.RequestersRev, err
		}
		address := strings.ToLower(strings.TrimSpace(a.Address))
		if err := c.mayAddRequester(mb, s, address); err != nil {
			return s.RequestersRev, err
		}
		s.addRequester(Requester{Address: address, PairedBy: "added", AddedAt: now}, nil)
		return s.RequestersRev, nil
	case *switchArgs:
		on, since, rev := &s.AutoRun, &s.AutoRunSince, &s.AutoRunRev
		if kind == "setAcknowledge" {
			on, since, rev = &s.Acknowledge, nil, &s.AcknowledgeRev
		}
		if err := stale(a.BaseRevision, *rev); err != nil {
			return *rev, err
		}
		if *on != a.On {
			*on = a.On
			*rev++
			// Mail that arrived before automatic runs were on never runs
			// by itself (autorun.rs JobSettings.since).
			if since != nil && a.On {
				*since = now
			}
		}
		return *rev, nil
	case *pairingStartArgs:
		if err := stale(a.BaseRevision, s.PairingRev); err != nil {
			return s.PairingRev, err
		}
		address := strings.ToLower(strings.TrimSpace(a.Requester))
		if err := c.mayAddRequester(mb, s, address); err != nil {
			return s.PairingRev, err
		}
		expires := time.UnixMilli(a.ExpiresAt).UTC()
		if !expires.After(now) {
			return s.PairingRev, fmt.Errorf("%w: expiresAt is past", ErrInvalid)
		}
		if limit := now.Add(connectLifetime); expires.After(limit) {
			expires = limit
		}
		// Sending again to the same requester keeps the earlier start, so a
		// reply to the first email still counts (pairing.rs start).
		if p := s.Pairing; p != nil && p.Requester == address && p.Paired == nil {
			if expires.After(p.ExpiresAt) {
				p.ExpiresAt = expires
			}
		} else {
			s.Pairing = &Pairing{Requester: address, StartedAt: now, ExpiresAt: expires, Seen: []string{}, Untokened: []Untokened{}}
		}
		s.PairingRev++
		return s.PairingRev, nil
	case *pairingConfirmArgs:
		if err := stale(a.BaseRevision, s.PairingRev); err != nil {
			return s.PairingRev, err
		}
		p := s.Pairing
		if p == nil || p.Paired != nil {
			return s.PairingRev, refusal{code: CodePairingClosed}
		}
		var u *Untokened
		for i := range p.Untokened {
			if p.Untokened[i].Message == a.MailID {
				u = &p.Untokened[i]
			}
		}
		if u == nil {
			return s.PairingRev, refusal{code: CodeNotFound}
		}
		p.Paired = &PairedOwner{
			Address: u.Address,
			Reason:  "You confirmed this address in the app, so each job from it needs confirming.",
		}
		s.PairingRev++
		if s.requester(u.Address) == nil {
			s.addRequester(p.Paired.requester(now), nil)
		}
		return s.PairingRev, nil
	case *routingSavedArgs:
		if err := stale(a.RequestersRevision, s.RequestersRev); err != nil {
			return s.RequestersRev, err
		}
		s.RoutingUnsent, s.Proofs = false, nil
		return s.RequestersRev, nil
	}
	return 0, fmt.Errorf("%w: no mail operation %q", ErrInvalid, kind)
}
