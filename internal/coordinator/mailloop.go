package coordinator

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fount-labs/fount-broker/internal/mail"
	"github.com/fount-labs/fount-broker/internal/mail/decide"
)

// The mail loop (launch-plan.md, B) fetches each Cloud worker's mail from the
// edge with internal/mail's Service and acts on each message as Desktop's
// mail sync does: the edge's sender check, then decide against the worker's
// requesters (verdict.rs), a reply token choosing the thread (replies.rs).
// A requester's request becomes a turn through intake (intake.go); anything
// else waits on a thread as held mail.
//
// Which mailboxes to read comes from the edge's batched "changes since"
// listing when there is one (MailChanges, M), so a thousand mailboxes cost one
// request a poll; without it, and every SweepInterval anyway, each mailbox is
// listed.

// MailConfig turns the mail loop on. A zero MailConfig has no Service, and
// RunMail returns at once.
type MailConfig struct {
	Service *mail.Service
	// Changes is the edge's batched listing (M). Nil lists each mailbox
	// every SweepInterval.
	Changes MailChanges
	// Intake is C's intake runner. Nil queues each turn's agent job
	// directly, pointing it at the raw email (directIntake).
	Intake Intake
	// Ack sends the fixed acknowledgement (decision 8). Nil sends none.
	Ack Acknowledger
	// Entitlements is fount-infra's issuer of Cloud mailboxes' entitlements
	// (decision 12). Nil renews nothing.
	Entitlements Entitlements
	// PollInterval is how often Changes is asked; SweepInterval how often
	// every mailbox is listed. Defaults 5 s and 20 s, or 10 min with Changes.
	PollInterval  time.Duration
	SweepInterval time.Duration
	// Batch bounds the messages fetched from one mailbox in a pass. Default 16.
	Batch int
}

// MailChanges is the edge's batched "changes since" listing (lane M; its API
// isn't final). Since answers which of mailboxes may have mail that changed
// after cursor, and the cursor to ask from next. An empty cursor, or Reset in
// the answer, means the edge can't say, and every mailbox is listed.
type MailChanges interface {
	Since(ctx context.Context, cursor string, mailboxes []string) (MailboxChanges, error)
}

type MailboxChanges struct {
	Cursor  string
	Changed []string
	Reset   bool
}

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
	kicked    map[string]bool
	cursor    string
	lastSweep time.Time
	// pickups is how long recent requests took from arriving to their turn
	// being queued (decision 9), newest last.
	pickups []time.Duration
	renewed map[string]Renewed
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
	tick := time.NewTicker(c.mail.cfg.PollInterval)
	defer tick.Stop()
	for {
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
	cursor := m.cursor
	m.mu.Unlock()

	// The changes listing is asked on a sweep too, for the cursor to ask
	// from next.
	if m.cfg.Changes != nil && len(workers) > 0 {
		changes, err := m.cfg.Changes.Since(ctx, cursor, slices.Sorted(maps.Keys(workers)))
		switch {
		case err != nil:
			log.Printf("mail: the edge's changes listing failed: %v", err)
		case changes.Reset || cursor == "":
			sweep = true
		default:
			for _, mb := range changes.Changed {
				if w, ok := workers[mb]; ok {
					due[w.ID] = true
				}
			}
		}
		if err == nil {
			m.mu.Lock()
			m.cursor = changes.Cursor
			m.mu.Unlock()
		}
	}
	for _, mb := range slices.Sorted(maps.Keys(workers)) {
		w := workers[mb]
		if ctx.Err() != nil {
			return
		}
		if !sweep && !due[w.ID] {
			continue
		}
		if err := c.syncMail(ctx, w, now); err != nil && !errors.Is(err, ErrNoWorker) {
			log.Printf("worker %s: mail: %v", w.ID, err)
		}
		if sweep {
			c.renewDue(ctx, w, now)
		}
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
	listing, err := m.service.List(ctx, w.Mailbox)
	if err != nil {
		return fmt.Errorf("listing: %w", err)
	}
	paused := pauseOf(listing.Paused)
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
		if err := c.actOnMail(w.ID, msg, paused, now); err != nil {
			errs = append(errs, fmt.Errorf("mail %s: %w", msg.ID, err))
		}
	}
	if err := c.accountGaps(ctx, w); err != nil {
		errs = append(errs, err)
	}
	if err := c.runPending(ctx, w.ID); err != nil {
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

// actOnMail decides one message and applies what it causes, with its ledger
// entry, in one tree change (decision 15).
func (c *Coordinator) actOnMail(workerID string, msg *mail.Message, paused pause, now time.Time) error {
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
		act, err := c.place(t, workerID, mb, s, l, msg, paused, now.UTC())
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
func (c *Coordinator) place(t *Tree, workerID string, mb *Mailbox, s *MailSettings, l *mailLedger, msg *mail.Message, paused pause, now time.Time) (actedMail, error) {
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
	// Intake (C) says whether an email looks automatic; until it does, the
	// coordinator can't tell, as it reads no email.
	d := decide.Decide(worker, r, "", l.Signers)
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

	entry := &mailEntry{
		EdgeID: msg.ID, ReceivedAt: msg.ReceivedAt, Sender: sender, Signed: alignedDomain(check),
		CheckError: check == nil, Verdict: verdict, Reason: reason,
	}
	if check != nil {
		entry.SenderName = check.From.Name
	}
	run := false
	switch verdict {
	case string(decide.Request), verdictThreadReply:
		if why := c.whyNotRun(s, l, th, sender, msg, paused, now); why != "" {
			entry.Held, entry.Reason = heldWaiting, why
		} else {
			run = true
		}
	case string(decide.Context):
	default:
		entry.Held = heldWaiting
	}
	if err := t.Write(storedMailPath(msg.ID), msg.Raw); err != nil {
		return act, err
	}
	rev := th.Revision + 1
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
		if err := owe(t, pendingMail{Kind: pendingIntake, ThreadID: th.ID, EdgeID: msg.ID, JobID: entry.JobID, Requester: sender}); err != nil {
			return act, err
		}
		if s.Acknowledge && c.cfg.Mail.Ack != nil {
			if err := owe(t, pendingMail{Kind: pendingAck, ThreadID: th.ID, EdgeID: msg.ID, Requester: sender}); err != nil {
				return act, err
			}
		}
	case entry.Held == heldWaiting:
		act.Outcome = outcomeHeld
	default:
		act.Outcome = outcomeContext
	}
	return act, nil
}

// whyNotRun is why a requester's request doesn't run by itself, or empty when
// it does: autorun.rs plan's reasons, in its order.
func (c *Coordinator) whyNotRun(s *MailSettings, l *mailLedger, th *threadRecord, sender string, msg *mail.Message, paused pause, now time.Time) string {
	switch {
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
