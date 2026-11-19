package coordinator

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fount-labs/fount-broker/internal/mail"
	"github.com/fount-labs/fount-broker/internal/mail/decide"
)

// The mail loop (launch-plan.md, B) fetches each Cloud worker's mail from the
// edge with internal/mail's Service and acts on each message as Desktop's
// mail sync does: the edge's sender check, then decide against the worker's
// requesters (verdict.rs), a reply token choosing the thread (replies.rs).
// Each message is first read by intake (C, intake.go), which puts its folder
// and the turn's JobSpec together; then a requester's request becomes a turn,
// and anything else waits on a thread as held mail.
//
// Which mailboxes to read comes from the edge's changes feed when there is one
// (MailChanges, M: POST /coordinator/changes), so a thousand mailboxes cost
// one request a poll; without it, and every SweepInterval anyway, each
// mailbox is listed (GET /mail).

// MailConfig turns the mail loop on. A zero MailConfig has no Service, and
// RunMail returns at once.
type MailConfig struct {
	Service *mail.Service
	// Changes is the edge's batched listing (M). Nil lists each mailbox
	// every SweepInterval.
	Changes MailChanges
	// Ack sends the fixed acknowledgement (decision 8). Nil with Send on is
	// the coordinator's own, on the send journal; nil without sends none.
	Ack Acknowledger
	// Send turns sending on: the send journal posts through Service
	// (sendclient.go), naming its generation as every call does. Off,
	// nothing is sent: approved mail waits.
	Send bool
	// Entitlements is fount-infra's issuer of Cloud mailboxes' entitlements
	// (decision 12). Nil renews nothing.
	Entitlements Entitlements
	// Notices emails owners about problems (decision 10): here, a lapsed
	// payment (lapse.go). Nil with Send on is the coordinator's own
	// (NotifyOwner); nil without tells no one.
	Notices OwnerNotices
	// Generations is the vault's coordinator generation (decision 18,
	// mailgen.go). Nil names none, which an edge refuses for any mailbox
	// another coordinator enrolled.
	Generations mail.GenerationSource
	// PollInterval is how often Changes is asked; SweepInterval how often
	// every mailbox is listed. Defaults 5 s and 20 s, or 10 min with Changes.
	PollInterval  time.Duration
	SweepInterval time.Duration
	// Batch bounds the messages fetched from one mailbox in a pass. Default 16.
	Batch int
}

// MailChanges is the edge's changes feed (M, edge DESIGN.md §8: POST
// /coordinator/changes). An implementation signs each call with the current
// generation's coordinator key and sends Fount-Generation; the loop sees
// neither. Changes answers one page after cursor, oldest change first.
type MailChanges interface {
	Changes(ctx context.Context, cursor string, limit int) (ChangesPage, error)
}

type ChangesPage struct {
	Changes []MailboxChange
	// Cursor is the cursor to ask from next; More says another page is
	// waiting now. Reset says the edge didn't know the cursor (empty, from
	// before a restore, or ahead of it), and every mailbox is listed.
	Cursor string
	More   bool
	Reset  bool
}

// MailboxChange is one enrolled mailbox whose record changed: new mail (its
// sequence), pause, lapse, keys, owners, entitlement or enrollment.
type MailboxChange struct {
	MailboxID string
	// Changed is the routing object's version at the change.
	Changed  uint64
	Sequence uint64
	Paused   bool
	Lapsed   bool
}

const (
	// changesLimit is the page size asked for; the edge's default.
	changesLimit = 500
	// maxChangesPages bounds the pages read in one pass; the rest wait for
	// the next.
	maxChangesPages = 20
	// mailCursorFile keeps the feed's cursor on the volume.
	mailCursorFile = "mail-cursor"
)

const (
	defaultPollInterval  = 5 * time.Second
	defaultSweepFallback = 20 * time.Second
	defaultSweepChanges  = 10 * time.Minute
	defaultMailBatch     = 16
	maxPickups           = 256
)

type mailLoop struct {
	cfg     MailConfig
	service *mail.Service
	wake    chan struct{}

	mu sync.Mutex
	// syncs serialize each worker's mail passes.
	syncs map[string]*sync.Mutex
	// restored is the mailboxes whose ledger the Service has from the tree.
	restored map[string]bool
	// kicked is the workers to pass over next, sweep or not.
	kicked map[string]bool
	// slotWaiters is the workers whose intake found no runner slot.
	slotWaiters map[string]bool
	// cursor is the changes feed's, kept in mailCursorFile; loaded says it
	// was read from there.
	cursor    string
	loaded    bool
	lastSweep time.Time
	// pickups is how long recent requests took from arriving to their turn
	// being queued (decision 9), newest last.
	pickups []time.Duration
	renewed map[string]Renewed
	// enrolled is the mailboxes enrolled under this process's generation.
	enrolled map[string]bool
	// stale is set once a newer generation has spoken: the loop stops.
	stale atomic.Bool
}

func newMailLoop(cfg MailConfig) *mailLoop {
	if cfg.Service == nil {
		return nil
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaultPollInterval
	}
	if cfg.SweepInterval <= 0 {
		cfg.SweepInterval = defaultSweepFallback
		if cfg.Changes != nil {
			cfg.SweepInterval = defaultSweepChanges
		}
	}
	if cfg.Batch <= 0 {
		cfg.Batch = defaultMailBatch
	}
	return &mailLoop{
		cfg: cfg, service: cfg.Service, wake: make(chan struct{}, 1),
		syncs: map[string]*sync.Mutex{}, restored: map[string]bool{}, kicked: map[string]bool{}, renewed: map[string]Renewed{},
		enrolled: map[string]bool{}, slotWaiters: map[string]bool{},
	}
}

func (m *mailLoop) poke() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// kick passes over workerID's mail soon, as after an operation that owes a
// message something.
func (m *mailLoop) kick(workerID string) {
	m.mu.Lock()
	m.kicked[workerID] = true
	m.mu.Unlock()
	m.poke()
}

func (m *mailLoop) workerSync(workerID string) *sync.Mutex {
	m.mu.Lock()
	defer m.mu.Unlock()
	l := m.syncs[workerID]
	if l == nil {
		l = &sync.Mutex{}
		m.syncs[workerID] = l
	}
	return l
}

// NoLocalCheck is Cloud's mail.Checker. The coordinator has no local sender
// verifier, so a message from before the edge checked senders is held as
// unchecked.
type NoLocalCheck struct{}

func (NoLocalCheck) Check(context.Context, mail.CheckInput) (json.RawMessage, error) {
	return nil, ErrNoEdgeCheck
}

// RunMail runs the mail loop until ctx ends. Without a MailConfig.Service it
// returns at once.
func (c *Coordinator) RunMail(ctx context.Context) {
	if c.mail == nil {
		return
	}
	if c.mail.cfg.Generations != nil && !c.startGeneration(ctx) {
		return
	}
	tick := time.NewTicker(c.mail.cfg.PollInterval)
	defer tick.Stop()
	for !c.mail.stale.Load() {
		c.mailPass(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-c.mail.wake:
		case <-tick.C:
		}
	}
}

// mailWorkers is every worker with a mailbox and a DEK, by mailbox.
func (c *Coordinator) mailWorkers() map[string]Worker {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]Worker{}
	for _, w := range c.state.Workers {
		if w.Mailbox != "" && w.WrappedDEK != nil {
			out[w.Mailbox] = *w
		}
	}
	return out
}

// mailPass syncs the mailboxes that may have changed, and every one when a
// sweep is due. A sweep also does what earlier passes left owing and renews
// mailboxes due for it.
func (c *Coordinator) mailPass(ctx context.Context, now time.Time) {
	m := c.mail
	if m.stale.Load() {
		return
	}
	workers := c.mailWorkers()
	m.mu.Lock()
	sweep := now.Sub(m.lastSweep) >= m.cfg.SweepInterval
	if sweep {
		m.lastSweep = now
	}
	due := map[string]bool{}
	for id := range m.kicked {
		due[id] = true
	}
	clear(m.kicked)
	if !m.loaded {
		m.loaded = true
		if data, err := os.ReadFile(filepath.Join(c.cfg.StateDir, mailCursorFile)); err == nil {
			m.cursor = strings.TrimSpace(string(data))
		}
	}
	cursor := m.cursor
	m.mu.Unlock()

	// The feed is read on a sweep too, for the cursor to ask from next.
	if m.cfg.Changes != nil && len(workers) > 0 {
		next, changed, reset, err := c.readChanges(ctx, cursor)
		switch {
		case err != nil:
			c.fenced(ctx, "", err)
			log.Printf("mail: the edge's changes feed failed: %v", err)
		case reset:
			sweep = true
		default:
			for _, mb := range changed {
				if w, ok := workers[mb]; ok {
					due[w.ID] = true
				}
			}
		}
		if err == nil && next != cursor {
			c.saveMailCursor(next)
		}
	}
	for _, mb := range slices.Sorted(maps.Keys(workers)) {
		w := workers[mb]
		if ctx.Err() != nil || m.stale.Load() {
			return
		}
		if !sweep && !due[w.ID] {
			continue
		}
		if err := c.syncMail(ctx, w, now); err != nil && !errors.Is(err, ErrNoWorker) {
			c.fenced(ctx, w.Mailbox, err)
			// The cursor has moved past its change: it's tried again next
			// pass, and on every sweep.
			log.Printf("worker %s: mail: %v", w.ID, err)
			// Mail waiting on a runner slot is passed over when one frees.
			if !errors.Is(err, errRunnersBusy) {
				m.kick(w.ID)
			}
		}
		if sweep {
			c.renewDue(ctx, w, now)
		}
	}
	c.rotateDue(ctx)
}

// readChanges reads the feed's pages after cursor: the mailboxes that changed,
// and whether the edge said to list every one.
func (c *Coordinator) readChanges(ctx context.Context, cursor string) (string, []string, bool, error) {
	var changed []string
	reset := cursor == ""
	for range maxChangesPages {
		page, err := c.mail.cfg.Changes.Changes(ctx, cursor, changesLimit)
		if err != nil {
			return cursor, nil, false, err
		}
		reset = reset || page.Reset
		for _, ch := range page.Changes {
			changed = append(changed, ch.MailboxID)
		}
		cursor = page.Cursor
		if !page.More {
			break
		}
	}
	return cursor, changed, reset, nil
}

// saveMailCursor keeps the feed's cursor. Losing it costs a sweep: every
// message's ledger entry, not the cursor, says whether it was acted on.
func (c *Coordinator) saveMailCursor(cursor string) {
	m := c.mail
	m.mu.Lock()
	m.cursor = cursor
	m.mu.Unlock()
	path := filepath.Join(c.cfg.StateDir, mailCursorFile)
	if err := os.WriteFile(path+".tmp", []byte(cursor), 0o600); err != nil {
		log.Printf("mail: couldn't keep the changes cursor: %v", err)
		return
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		log.Printf("mail: couldn't keep the changes cursor: %v", err)
	}
}

// syncMail reads w's new mail and acts on each message, oldest first, each in
// its own tree change.
func (c *Coordinator) syncMail(ctx context.Context, w Worker, now time.Time) error {
	m := c.mail
	lock := m.workerSync(w.ID)
	lock.Lock()
	defer lock.Unlock()

	acted, err := c.prepareMail(w)
	if err != nil {
		return err
	}
	if err := c.enrollMail(ctx, w); err != nil {
		return err
	}
	listing, err := m.service.List(ctx, w.Mailbox)
	if err != nil {
		return fmt.Errorf("listing: %w", err)
	}
	paused := pauseOf(listing.Paused)
	if listing.Lapsed != nil && *listing.Lapsed || m.isLapsed(w.ID) {
		paused = pauseLapsed
	}
	var fetched []*mail.Message
	for _, l := range listing.Messages {
		if acted[l.ID] {
			continue
		}
		if len(fetched) >= m.cfg.Batch {
			m.kick(w.ID)
			break
		}
		msg, err := m.service.Get(ctx, w.Mailbox, l.ID)
		if errors.Is(err, mail.ErrNotFound) {
			continue
		}
		if err != nil {
			// A message that fails to verify or open stays unacted on and
			// is fetched again next pass; the error names no content.
			log.Printf("worker %s: mail %s: %v", w.ID, l.ID, err)
			continue
		}
		fetched = append(fetched, msg)
	}
	slices.SortFunc(fetched, func(a, b *mail.Message) int {
		return cmp.Or(cmp.Compare(a.ReceivedAt, b.ReceivedAt), cmp.Compare(a.Sequence, b.Sequence), strings.Compare(a.ID, b.ID))
	})
	var errs []error
	for _, msg := range fetched {
		err := c.receiveMail(ctx, w.ID, msg, paused, now)
		var stopped intakeStopped
		if errors.As(err, &stopped) {
			// Intake couldn't run: this message and the ones after it
			// wait for the next pass, in order.
			errs = append(errs, fmt.Errorf("mail %s: intake: %w", msg.ID, stopped.err))
			break
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("mail %s: %w", msg.ID, err))
		}
	}
	if err := c.accountGaps(ctx, w); err != nil {
		errs = append(errs, err)
	}
	if err := c.runPending(ctx, w.ID); err != nil {
		errs = append(errs, err)
	}
	if err := c.runSends(ctx, w.ID); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// pause is Desktop's Pause: an edge that didn't say counts as paused, so a
// pause from another device holds.
type pause int

const (
	pauseRunning pause = iota
	pausePaused
	pauseUnknown
	// pauseLapsed is a worker paused for a lapsed payment (lapse.go).
	pauseLapsed
)

func pauseOf(edge *bool) pause {
	switch {
	case edge == nil:
		return pauseUnknown
	case *edge:
		return pausePaused
	}
	return pauseRunning
}

// prepareMail gives the Service w's keys and kept ledger, once per process,
// and returns the messages already acted on.
func (c *Coordinator) prepareMail(w Worker) (map[string]bool, error) {
	m := c.mail
	acted := map[string]bool{}
	err := c.view(w.ID, anyDevice, func(t *Tree) error {
		mb, err := loadMailbox(t)
		if err != nil {
			return err
		}
		l, err := loadMailLedger(t)
		if err != nil {
			return err
		}
		for id := range l.Acted {
			acted[id] = true
		}
		if mb.MailboxID != w.Mailbox {
			return fmt.Errorf("%w: the worker's mailbox isn't the volume's", ErrInvalid)
		}
		if !m.service.HasKeys(w.Mailbox) {
			keys, err := mb.keys()
			if err != nil {
				return err
			}
			m.service.PutKeys(keys)
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if !m.restored[w.Mailbox] {
			m.service.RestoreLedger(w.Mailbox, l.Sequences)
			m.restored[w.Mailbox] = true
		}
		return nil
	})
	return acted, err
}

// accountGaps asks the edge to account for missing sequence numbers, when
// there are any, and keeps the ledger. A number still missing once every
// listed message is read is withheld mail; the ledger keeps it, with any
// anomaly, for the app to show.
func (c *Coordinator) accountGaps(ctx context.Context, w Worker) error {
	s := c.mail.service
	if len(s.Ledger(w.Mailbox).Missing(1)) == 0 {
		return nil
	}
	if _, err := s.Gaps(ctx, w.Mailbox); err != nil {
		return fmt.Errorf("gaps: %w", err)
	}
	return c.change(w.ID, anyDevice, func(t *Tree) error {
		l, err := loadMailLedger(t)
		if err != nil {
			return err
		}
		l.Sequences = s.Ledger(w.Mailbox)
		return writeJSON(t, mailLedgerPath, l)
	})
}

// intook is a message's intake: its result, or why intake couldn't read it.
// ran is false before intake has been asked.
type intook struct {
	ran    bool
	r      IntakeResult
	unread error
}

// errNeedsIntake is place finding a message that becomes a turn or is held,
// with no intake run for it yet. The tree change is dropped, intake runs, and
// the message is placed again.
var errNeedsIntake = errors.New("the message needs intake")

// intakeStopped is intake that couldn't run at all: the message waits.
type intakeStopped struct{ err error }

func (e intakeStopped) Error() string { return e.err.Error() }

// receiveMail acts on one message, running intake only when it is needed.
// The sender check, pairing and decide come first, on what the edge's check
// read of the headers: mail that is ignored (a bounce, a replay) or answers a
// pairing is placed without intake ever reading it. Anything else, a turn or
// held mail, needs intake's folder, so the first change stops with
// errNeedsIntake and is dropped; intake runs; and the message is decided and
// placed again, with its ledger entry, in one change (decision 15). Deciding
// again covers the one input only intake has, whether the email looks
// automatic, which can only turn the decision into ignored, and anything that
// changed on the worker in between.
func (c *Coordinator) receiveMail(ctx context.Context, workerID string, msg *mail.Message, paused pause, now time.Time) error {
	err := c.actOnMail(workerID, msg, intook{}, paused, now)
	if !errors.Is(err, errNeedsIntake) {
		return err
	}
	in, err := c.intakeMail(ctx, workerID, msg)
	if err != nil {
		return intakeStopped{err}
	}
	return c.actOnMail(workerID, msg, in, paused, now)
}

// asMail is the message as intake takes it.
func asMail(msg *mail.Message) *Mail {
	return &Mail{
		EdgeID: msg.ID, Sequence: msg.Sequence, ReceivedAt: msg.ReceivedAt, BootAttested: msg.BootAttested,
		Envelope: msg.Envelope, Check: checkOf(msg), CheckJSON: msg.SenderCheck, CheckError: msg.SenderCheckError, Raw: msg.Raw,
	}
}

// intakeMail runs intake on msg, once receiveMail has found it a turn or held
// mail: decide needs to know whether it looks automatic, and its folder goes
// into the thread in the same commit as the ledger. An email intake refuses
// is placed unread; an error is intake not running at all, and the message
// waits.
func (c *Coordinator) intakeMail(ctx context.Context, workerID string, msg *mail.Message) (intook, error) {
	var req IntakeRequest
	if tok := msg.ReplyToken; tok != nil && tok.Handle != "" {
		req.ReplyHandle = tok.Handle
		sender := ""
		if check := checkOf(msg); check != nil {
			sender = strings.ToLower(strings.TrimSpace(check.From.Address))
		}
		if err := c.view(workerID, anyDevice, func(t *Tree) error {
			h, err := loadHandles(t)
			if err != nil {
				return err
			}
			id, ok := h[tok.Handle]
			if !ok {
				return nil
			}
			th, err := loadThread(t, id)
			if errors.Is(err, ErrNoThread) {
				return nil
			}
			if err != nil {
				return err
			}
			if sender != "" && th.hasParticipant(sender) {
				req.ReplyFolder = "threads/" + th.ID + "/" + MessageFolder(asMail(msg))
			}
			return nil
		}); err != nil {
			return intook{}, err
		}
	}
	r, err := c.Intake(ctx, workerID, asMail(msg), req)
	switch {
	case errors.Is(err, ErrIntake):
		// The error isn't logged: it can quote the email.
		log.Printf("worker %s: intake couldn't read mail %s", workerID, msg.ID)
		return intook{ran: true, unread: err}, nil
	case err != nil:
		return intook{}, err
	}
	return intook{ran: true, r: r}, nil
}

// actOnMail decides one message and applies what it causes, with its ledger
// entry, in one tree change (decision 15).
func (c *Coordinator) actOnMail(workerID string, msg *mail.Message, in intook, paused pause, now time.Time) error {
	var job bool
	err := c.changeThen(workerID, anyDevice, func(t *Tree) error {
		l, err := loadMailLedger(t)
		if err != nil {
			return err
		}
		if _, done := l.Acted[msg.ID]; done {
			return nil
		}
		mb, err := loadMailbox(t)
		if err != nil {
			return err
		}
		s, err := loadMailSettings(t)
		if err != nil {
			return err
		}
		l.Sequences = c.mail.service.Ledger(mb.MailboxID)
		act, err := c.place(t, workerID, mb, s, l, msg, in, paused, now.UTC())
		if err != nil {
			return err
		}
		act.At, act.ReceivedAt, act.Sequence = now.UTC(), msg.ReceivedAt, msg.Sequence
		l.Acted[msg.ID] = act
		job = act.Outcome == outcomeJob
		if err := writeJSON(t, mailSettingsPath, s); err != nil {
			return err
		}
		return writeJSON(t, mailLedgerPath, l)
	}, nil)
	if err == nil && job {
		c.mail.notePickup(now.Sub(time.UnixMilli(msg.ReceivedAt)))
	}
	return err
}

// received is what decide reads of a message.
func received(msg *mail.Message) decide.Received {
	return decide.Received{
		ID: msg.ID, Sequence: msg.Sequence, ReceivedAt: msg.ReceivedAt, BootAttested: msg.BootAttested,
		Reused: msg.Reused, Quarantined: msg.Quarantined, EnvelopeSender: msg.Envelope.Sender,
		SenderCheck: msg.SenderCheck, SenderCheckError: msg.SenderCheckError,
	}
}

// checkOf is the edge's check, or nil when there's none to read.
func checkOf(msg *mail.Message) *mail.EdgeCheck {
	if msg.SenderCheckError != "" || len(msg.SenderCheck) == 0 {
		return nil
	}
	var c mail.EdgeCheck
	if json.Unmarshal(msg.SenderCheck, &c) != nil {
		return nil
	}
	return &c
}

func alignedDomain(c *mail.EdgeCheck) string {
	if c == nil {
		return ""
	}
	for _, s := range c.DKIM {
		if s.Aligned && s.Result == "pass" && strings.EqualFold(s.Domain, c.From.Domain) {
			return strings.ToLower(s.Domain)
		}
	}
	return ""
}

// place decides msg and puts it where it goes: answering a pairing, on the
// thread its reply token names, on a new thread, or nowhere when ignored.
func (c *Coordinator) place(t *Tree, workerID string, mb *Mailbox, s *MailSettings, l *mailLedger, msg *mail.Message, in intook, paused pause, now time.Time) (actedMail, error) {
	check := checkOf(msg)
	sender := ""
	if check != nil {
		sender = strings.ToLower(strings.TrimSpace(check.From.Address))
	}
	r := received(msg)
	for hash, id := range decide.FirstSigners([]decide.Received{r}) {
		if _, seen := l.Signers[hash]; !seen {
			l.Signers[hash] = id
		}
	}
	if s.Pairing != nil && s.Pairing.open(now) {
		switch found := examinePairing(s.Pairing, mb.Address, msg, check); {
		case found.paired != nil:
			s.Pairing.Seen = append(s.Pairing.Seen, msg.ID)
			s.Pairing.Paired, s.Pairing.MessageID = found.paired, found.messageID
			s.PairingRev++
			if s.requester(found.paired.Address) == nil {
				s.addRequester(found.paired.requester(now), &ConnectProof{Owner: found.paired.Address, MessageID: found.messageID})
			}
			return actedMail{Sender: sender, Verdict: "pairing", Outcome: outcomePaired}, nil
		case found.untokened != nil:
			s.Pairing.Seen = append(s.Pairing.Seen, msg.ID)
			s.Pairing.Untokened = append(s.Pairing.Untokened, *found.untokened)
			s.PairingRev++
		}
	}
	worker := decide.Worker{Address: mb.Address}
	for _, q := range s.Requesters {
		worker.Requesters = append(worker.Requesters, decide.Requester{Address: q.Address, DKIMDomain: q.DKIMDomain, AutoRun: q.AutoRun})
	}
	// First without intake: what it would ignore is ignored unread. Then,
	// once intake has run, with whether it found the email automatic, which
	// the coordinator, reading no email, can't tell.
	d := decide.Decide(worker, r, "", l.Signers)
	if d.Verdict != decide.Ignored {
		if !in.ran {
			return actedMail{}, errNeedsIntake
		}
		d = decide.Decide(worker, r, in.r.Spec.Automatic, l.Signers)
	}
	act := actedMail{Sender: sender, Verdict: string(d.Verdict), Reason: d.Reason}
	if d.Verdict == decide.Ignored {
		act.Outcome = outcomeIgnored
		return act, nil
	}

	var th *threadRecord
	verdict, reason := string(d.Verdict), d.Reason
	if tok := msg.ReplyToken; tok != nil && tok.Handle != "" {
		h, err := loadHandles(t)
		if err != nil {
			return act, err
		}
		if id, ok := h[tok.Handle]; ok {
			th, err = loadThread(t, id)
			if err != nil && !errors.Is(err, ErrNoThread) {
				return act, err
			}
			if th != nil {
				// replies.rs reply_verdict.
				switch {
				case d.Verdict == decide.Request && th.hasParticipant(sender):
					verdict = verdictThreadReply
				case d.Verdict == decide.Request:
					verdict, reason = string(decide.NeedsConfirmation), sender+" isn't on this thread"
				}
			}
		}
	}
	if th == nil {
		subject := ""
		if check != nil {
			subject = check.Headers.Subject
		}
		var err error
		if th, err = newMailThread(workerID, subject, now); err != nil {
			return act, err
		}
		if _, err := threadHandle(t, th); err != nil {
			return act, err
		}
	}
	// So follow sees the queue before the checks below.
	if _, err := c.follow(t, th); err != nil {
		return act, err
	}
	if s.requester(sender) != nil && !th.hasParticipant(sender) && (verdict == string(decide.Request) || verdict == verdictThreadReply) {
		th.Participants = append(th.Participants, sender)
	}

	// What a reply on th is besides a turn of its own, decided here and
	// below at "answer by email": first an approval by email (sendapproval.go),
	// which starts no turn; then, for a reply that would start one, an answer
	// to th's waiting question.
	approval, err := c.emailApproval(t, th, mb, s, msg, check, in, now)
	if err != nil {
		return act, err
	}
	if approval {
		verdict, reason = verdictApproval, ""
	}

	folder := MessageFolder(asMail(msg))
	entry := &mailEntry{
		EdgeID: msg.ID, ReceivedAt: msg.ReceivedAt, Sender: sender, Signed: alignedDomain(check),
		CheckError: check == nil, Verdict: verdict, Reason: reason,
		Folder: folder, Instruction: in.r.Spec.Instruction, Unread: in.unread != nil,
	}
	if check != nil {
		h := check.Headers
		entry.SenderName, entry.MessageID, entry.InReplyTo, entry.References, entry.Subject = check.From.Name, angled(h.MessageID), h.InReplyTo, h.References, h.Subject
	}
	var spec *JobSpec
	switch verdict {
	case string(decide.Request), verdictThreadReply:
		why := c.whyNotRun(s, l, th, sender, msg, paused, now)
		if why == "" && in.unread != nil {
			why = "Fount couldn't read this email"
		}
		if why == "" && in.r.Spec.Automatic != "" {
			why = "it looks automatic"
		}
		if why == "" {
			js, err := in.r.Spec.JobSpec(th.ID, th.SessionID, folder, c.cfg.JobConfig)
			if err != nil {
				why = "Fount couldn't read this email"
			} else {
				spec = &js
			}
		}
		if why != "" {
			entry.Held, entry.Reason = heldWaiting, why
		}
	case string(decide.Context), verdictApproval:
	default:
		entry.Held = heldWaiting
	}
	rev := th.Revision + 1
	if spec != nil && verdict == verdictThreadReply {
		// Answer by email (question.go): a reply to th's waiting question
		// resumes its job with the email as the answer, worded as Desktop's
		// reply_arrived words it, instead of starting a turn of its own.
		text := strings.TrimSpace(spec.Instruction + "\n\n(They answered by email: `" + spec.Message + "/`.)")
		answer, err := c.answerByMail(th, sender, text, mailJobID(msg.ID), rev, now)
		if err != nil {
			return act, err
		}
		if answer != nil {
			spec = answer
		}
	}
	if err := writeMailFolder(t, mailFolderPath(th.ID, folder, entry.Held == heldWaiting), msg, in); err != nil {
		return act, err
	}
	run := spec != nil
	if run {
		entry.Intake, entry.JobID = intakePending, mailJobID(msg.ID)
	}
	id, err := th.push(rev, now, threadEntry{Kind: entryMail, Mail: entry})
	if err != nil {
		return act, err
	}
	th.finish(rev, now)
	if err := saveThread(t, th); err != nil {
		return act, err
	}
	act.Thread, act.Entry, act.Verdict, act.Reason = th.ID, id, verdict, entry.Reason
	switch {
	case run:
		act.Outcome, act.Reason = outcomeJob, ""
		if err := owe(t, pendingMail{Kind: pendingJob, ThreadID: th.ID, EdgeID: msg.ID, JobID: entry.JobID, Spec: spec, Requester: sender}); err != nil {
			return act, err
		}
		if s.Acknowledge && c.cfg.Mail.Ack != nil {
			if err := owe(t, pendingMail{Kind: pendingAck, ThreadID: th.ID, EdgeID: msg.ID, Requester: sender}); err != nil {
				return act, err
			}
		}
	case entry.Held == heldWaiting:
		act.Outcome = outcomeHeld
		if err := c.problemNotice(t, workerID, th.ID, noticeHeld, msg.ID, now); err != nil {
			return act, err
		}
	default:
		act.Outcome = outcomeContext
	}
	return act, nil
}

// mailFolderPath is where an email's folder is in the worker's tree, ending
// in "/". Mail that may run is in the worker root, threads/<thread>/<folder>,
// where its turn reads it. Held mail is in the coordinator's record instead,
// sealed with the rest of the tree but given to no job, so a stranger's email
// can't steer another turn on the worker; runHeldMail moves it into the root
// (moveHeldFolder).
func mailFolderPath(threadID, folder string, held bool) string {
	if held {
		return heldMailDir + threadID + "/" + folder + "/"
	}
	return prefixRoot + "threads/" + threadID + "/" + folder + "/"
}

// writeMailFolder puts the email's folder at dir: what intake wrote, or the
// raw email alone when it couldn't read it. Thread files are written once.
func writeMailFolder(t *Tree, dir string, msg *mail.Message, in intook) error {
	files := in.r.Files
	if in.unread != nil || files == nil {
		files = map[string][]byte{"message.eml": msg.Raw}
	}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		if err := checkPath(name); err != nil {
			return fmt.Errorf("%w: intake's file %q", ErrIntake, name)
		}
		if t.Has(dir + name) {
			continue
		}
		if err := t.Write(dir+name, files[name]); err != nil {
			return err
		}
	}
	return nil
}

// moveHeldFolder moves a held email's folder from the record into the worker
// root, as running it makes it a turn's input.
func moveHeldFolder(t *Tree, threadID, folder string) error {
	from, to := mailFolderPath(threadID, folder, true), mailFolderPath(threadID, folder, false)
	for _, p := range t.List(from) {
		rel := strings.TrimPrefix(p, from)
		if !t.Has(to + rel) {
			data, err := t.Read(p)
			if err != nil {
				return err
			}
			if err := t.Write(to+rel, data); err != nil {
				return err
			}
		}
		t.Remove(p)
	}
	return nil
}

// whyNotRun is why a requester's request doesn't run by itself, or empty when
// it does: autorun.rs plan's reasons, in its order.
func (c *Coordinator) whyNotRun(s *MailSettings, l *mailLedger, th *threadRecord, sender string, msg *mail.Message, paused pause, now time.Time) string {
	switch {
	case paused == pauseLapsed:
		return "the account's payment lapsed"
	case !s.AutoRun:
		return "automatic runs are off"
	case time.UnixMilli(msg.ReceivedAt).Before(s.AutoRunSince):
		return "it arrived before automatic runs were turned on"
	case paused == pausePaused:
		return "the worker is paused"
	case paused == pauseUnknown:
		return "Fount couldn't tell whether the worker is paused"
	case len(c.cfg.JobConfig) == 0:
		return "no model is set for this worker's jobs"
	case len(th.Jobs) >= maxThreadJobs:
		return fmt.Sprintf("this thread reached its limit of %d jobs", maxThreadJobs)
	case l.jobsSince(now.Add(-24*time.Hour), "") >= s.jobsPerDay():
		return fmt.Sprintf("the worker's limit of %d jobs a day was reached", s.jobsPerDay())
	case l.jobsSince(now.Add(-time.Hour), sender) >= maxJobsPerSenderPerHour:
		return fmt.Sprintf("%s started %d jobs in the last hour", sender, maxJobsPerSenderPerHour)
	}
	return ""
}

func (m *mailLoop) notePickup(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pickups = append(m.pickups, d)
	if len(m.pickups) > maxPickups {
		m.pickups = m.pickups[len(m.pickups)-maxPickups:]
	}
	log.Printf("mail: a request was picked up %s after it arrived", d.Round(time.Second))
}

// MailStats is how fast requests are picked up (decision 9): from the edge
// receiving each to its turn being queued, over the recent ones.
type MailStats struct {
	Pickups int           `json:"pickups"`
	Median  time.Duration `json:"median"`
	Max     time.Duration `json:"max"`
}

func (c *Coordinator) MailStats() MailStats {
	if c.mail == nil {
		return MailStats{}
	}
	c.mail.mu.Lock()
	p := slices.Clone(c.mail.pickups)
	c.mail.mu.Unlock()
	if len(p) == 0 {
		return MailStats{}
	}
	slices.Sort(p)
	return MailStats{Pickups: len(p), Median: p[len(p)/2], Max: p[len(p)-1]}
}
