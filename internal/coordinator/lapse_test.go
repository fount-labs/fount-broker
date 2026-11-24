package coordinator

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

// standing is fount-infra's entitlement state for the test account.
type standing struct {
	mu     sync.Mutex
	grace  time.Time // past_due until then
	lapsed bool
	issued int
}

func (s *standing) Issue(_ context.Context, req EntitlementRequest) (Entitlement, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issued++
	if s.lapsed {
		return Entitlement{}, fmt.Errorf("fount-infra: %w", ErrAccountLapsed)
	}
	return Entitlement{Token: "ent-" + req.MailboxID[:8], IssuedAt: time.Now(), GraceEnds: s.grace}, nil
}

func (s *standing) set(fn func(*standing)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s)
}

type notices struct {
	mu   sync.Mutex
	sent []OwnerNotice
}

func (n *notices) Notify(_ context.Context, o OwnerNotice) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent = append(n.sent, o)
	return nil
}

func (n *notices) kinds() []NoticeKind {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []NoticeKind
	for _, o := range n.sent {
		out = append(out, o.Kind)
	}
	return out
}

func TestALapsedAccountHoldsMailAndTellsTheOwner(t *testing.T) {
	ents, owner := &standing{}, &notices{}
	r := genRig(t, MailConfig{Entitlements: ents, Notices: owner})
	w, mb := r.worker()
	now := time.Now()
	sweep := func(at time.Time) {
		t.Helper()
		r.c.mail.mu.Lock()
		r.c.mail.lastSweep = time.Time{}
		r.c.mail.mu.Unlock()
		r.c.mailPass(context.Background(), at)
	}
	sweep(now)
	if ents.issued != 1 || len(owner.kinds()) != 0 {
		t.Fatalf("issued %d, notices %v", ents.issued, owner.kinds())
	}

	// Past due: the worker keeps working, and the owner hears once.
	grace := now.Add(72 * time.Hour)
	ents.set(func(s *standing) { s.grace = grace })
	sweep(now.Add(renewAfter + time.Minute))
	sweep(now.Add(renewAfter + 2*time.Minute))
	if k := owner.kinds(); !reflect.DeepEqual(k, []NoticeKind{NoticePastDue}) || !owner.sent[0].Until.Equal(grace) {
		t.Fatalf("notices %v", owner.sent)
	}
	ran := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr})
	sweep(now.Add(renewAfter + 3*time.Minute))
	if r.ledger(w.ID).Acted[ran].Outcome != outcomeJob {
		t.Fatal("a past_due worker stopped working")
	}
	waitJob(t, r.c, mailJobID(ran))

	// Grace ends: asked again then, not a day later. The worker pauses,
	// the edge holds its mail, and its mail is fetched and held.
	ents.set(func(s *standing) { s.lapsed = true })
	lapseAt := grace.Add(time.Minute)
	sweep(lapseAt)
	if !r.edge.coord.Mailbox(mb.MailboxID).Lapsed || !r.c.Lapsed("acct_1") {
		t.Fatal("not lapsed at the edge")
	}
	if k := owner.kinds(); !reflect.DeepEqual(k, []NoticeKind{NoticePastDue, NoticeLapsed}) || owner.sent[1].Until.IsZero() {
		t.Fatalf("notices %+v", owner.sent)
	}
	held := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "During the lapse"})
	sweep(lapseAt.Add(time.Minute))
	act := r.ledger(w.ID).Acted[held]
	if act.Outcome != outcomeHeld || act.Reason != "the account's payment lapsed" {
		t.Fatalf("the lapsed worker's mail: %+v", act)
	}

	// A week before the hold ends, and once it has.
	hold := r.c.mailRenewed(w.ID).Lapsed.HoldUntil
	sweep(hold.Add(-holdWarning + time.Minute))
	sweep(hold.Add(time.Minute))
	sweep(hold.Add(2 * time.Minute))
	want := []NoticeKind{NoticePastDue, NoticeLapsed, NoticeHoldEnding, NoticeBouncing}
	if k := owner.kinds(); !reflect.DeepEqual(k, want) {
		t.Fatalf("notices %v", k)
	}

	// Paid again: the edge stops holding, and the owner hears.
	ents.set(func(s *standing) { s.lapsed, s.grace = false, time.Time{} })
	sweep(hold.Add(renewRetry + 3*time.Minute))
	if r.edge.coord.Mailbox(mb.MailboxID).Lapsed || r.c.Lapsed("acct_1") {
		t.Fatal("still lapsed")
	}
	if k := owner.kinds(); !reflect.DeepEqual(k, append(want, NoticeResumed)) {
		t.Fatalf("notices %v", k)
	}
	again := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr})
	sweep(hold.Add(renewRetry + 4*time.Minute))
	if r.ledger(w.ID).Acted[again].Outcome != outcomeJob {
		t.Fatal("a resumed worker's mail didn't run")
	}
	waitJob(t, r.c, mailJobID(again))
	// Each notice names the account and the worker, and has a key.
	for _, n := range owner.sent {
		if n.Account != "acct_1" || n.WorkerID != w.ID || n.Key == "" {
			t.Fatalf("%+v", n)
		}
	}
}

// teamWorker is one of the rig's workers at address, put in team as a list
// would put it.
func (r *mailRig) teamWorker(team, address string) (Worker, Mailbox) {
	r.t.Helper()
	w, err := r.c.CreateWorker("acct_1", nil)
	if err != nil {
		r.t.Fatal(err)
	}
	mb := newMailbox(r.t, address)
	r.edge.register(mb)
	if err := r.c.SetMailbox(w.ID, mb, []Requester{{Address: "Dana@Example.com", DKIMDomain: "example.com", AutoRun: true, PairedBy: "reply"}}); err != nil {
		r.t.Fatal(err)
	}
	if res := r.workerOp(w.ID, "op_auto", "setAutoRun", switchArgs{On: true}); !res.OK {
		r.t.Fatalf("setAutoRun: %+v", res)
	}
	r.c.mu.Lock()
	r.c.state.Workers[w.ID].Team = team
	if r.c.state.Teams[team] == nil {
		r.c.state.Teams[team] = &Team{ID: team, state: &teamState{}}
	}
	r.c.mu.Unlock()
	w, _ = r.c.Worker(w.ID)
	return w, mb
}

func TestATeamLapsePausesAllItsWorkersAndResumes(t *testing.T) {
	ents, owner, biller := &standing{}, &notices{}, &fakeBiller{}
	r := genRig(t, MailConfig{Entitlements: ents, Notices: owner})
	r.c.cfg.TeamBilling = biller
	team := runnerTeam
	w1, mb1 := r.teamWorker(team, "ap@fountbox.com")
	w2, mb2 := r.teamWorker(team, "ar@fountbox.com")
	sweep := func(at time.Time) {
		t.Helper()
		r.c.mail.mu.Lock()
		r.c.mail.lastSweep = time.Time{}
		r.c.mail.mu.Unlock()
		r.c.mailPass(context.Background(), at)
	}
	refresh := func(answer TeamEntitlement, err error) {
		t.Helper()
		biller.set(answer, err)
		if _, err := r.c.refreshTeamBilling(context.Background(), team); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()

	// No answer from fount-infra yet: nothing lapses, and the renewal is
	// asked as before.
	sweep(now)
	if r.edge.coord.Mailbox(mb1.MailboxID).Lapsed || ents.issued != 2 {
		t.Fatalf("lapsed with no answer; issued %d", ents.issued)
	}

	// The team stops paying: every worker of it pauses at once, without
	// asking its renewal, and the owner hears once per step.
	refresh(TeamEntitlement{}, &TeamNotEntitled{Reason: "period_ended"})
	sweep(now.Add(time.Minute))
	for _, mb := range []Mailbox{mb1, mb2} {
		if !r.edge.coord.Mailbox(mb.MailboxID).Lapsed {
			t.Fatalf("%s isn't held at the edge", mb.Address)
		}
	}
	if ents.issued != 2 {
		t.Fatalf("a renewal was asked for a lapsed team: %d", ents.issued)
	}
	for _, w := range []Worker{w1, w2} {
		if l := r.c.mailRenewed(w.ID).Lapsed; l == nil || !l.Team {
			t.Fatalf("worker %s: %+v", w.ID, l)
		}
	}
	held := r.edge.deliver(mb1, email{from: "dana@example.com", to: mb1.Address, subject: "While unpaid"})
	sweep(now.Add(2 * time.Minute))
	if act := r.ledger(w1.ID).Acted[held]; act.Outcome != outcomeHeld || act.Reason != "the account's payment lapsed" {
		t.Fatalf("an unpaid team's mail: %+v", act)
	}
	lapses := 0
	for _, k := range owner.kinds() {
		if k == NoticeLapsed {
			lapses++
		}
	}
	if lapses != 2 {
		// One per worker here; the real OwnerNotices sends one per Key,
		// which both share.
		t.Fatalf("notices %v", owner.kinds())
	}
	if n := owner.sent[0]; n.Key != owner.sent[1].Key {
		t.Fatalf("the team's workers' notices differ: %+v", owner.sent)
	}

	// Paid again: each resumes on the next sweep, and its renewal goes on.
	refresh(paid, nil)
	sweep(now.Add(3 * time.Minute))
	for _, mb := range []Mailbox{mb1, mb2} {
		if r.edge.coord.Mailbox(mb.MailboxID).Lapsed {
			t.Fatalf("%s still held", mb.Address)
		}
	}
	for _, w := range []Worker{w1, w2} {
		if r.c.mailRenewed(w.ID).Lapsed != nil {
			t.Fatalf("worker %s still lapsed", w.ID)
		}
	}
	if k := owner.kinds(); k[len(k)-1] != NoticeResumed {
		t.Fatalf("notices %v", k)
	}
	again := r.edge.deliver(mb2, email{from: "dana@example.com", to: mb2.Address})
	sweep(now.Add(4 * time.Minute))
	if r.ledger(w2.ID).Acted[again].Outcome != outcomeJob {
		t.Fatal("a resumed team worker's mail didn't run")
	}
	waitJob(t, r.c, mailJobID(again))
}
