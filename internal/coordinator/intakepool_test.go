package coordinator

import (
	"context"
	"sync"
	"testing"
	"time"
)

// poolHolds is the account runnerID holds and its jobs running.
func poolHolds(p *Pool, runnerID string) (string, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := p.find(runnerID)
	return r.account, r.active
}

func poolIdle(t *testing.T, p *Pool) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, r := range p.runners {
		if r.active != 0 || r.account != "" {
			t.Fatalf("%s holds %q with %d running", r.id, r.account, r.active)
		}
	}
}

// withPool restarts the rig's coordinator on p.
func withPool(r *mailRig, p *Pool) {
	r.pool = p
	r.start()
}

type intakeRuns struct {
	mu   sync.Mutex
	runs []string // runner:account:held account:active
	pool *Pool
}

func (s *intakeRuns) hook(runnerID, account string) {
	held, active := poolHolds(s.pool, runnerID)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs = append(s.runs, runnerID+":"+account+":"+held+":"+string(rune('0'+active)))
}

func (s *intakeRuns) got() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.runs...)
}

func TestIntakeTakesARunnerSlotForItsAccount(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	w, mb := r.worker()
	runs := &intakeRuns{pool: r.pool}
	r.intake.set(func(f *fakeIntake) { f.onRun = runs.hook })
	id := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr})
	r.pass()
	if got := runs.got(); len(got) != 1 || got[0] != "runner-1:acct_1:acct_1:1" {
		t.Fatalf("intake ran as %v, want on runner-1 held by acct_1 for it alone", got)
	}
	if j := waitJob(t, r.c, mailJobID(id)); j.State != JobFinished || j.WorkerID != w.ID {
		t.Fatalf("%+v", j)
	}
	poolIdle(t, r.pool)
}

func TestIntakeDoesntShareAnotherAccountsRunner(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	withPool(r, NewPool(2, 2, nil))
	_, mb := r.worker()
	other, ok := r.pool.Acquire("acct_B")
	if !ok || other != "runner-1" {
		t.Fatal(other, ok)
	}
	runs := &intakeRuns{pool: r.pool}
	r.intake.set(func(f *fakeIntake) { f.onRun = runs.hook })
	r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr})
	r.pass()
	if got := runs.got(); len(got) != 1 || got[0] != "runner-2:acct_1:acct_1:1" {
		t.Fatalf("intake ran as %v, want on runner-2, away from acct_B", got)
	}
	if held, active := poolHolds(r.pool, "runner-1"); held != "acct_B" || active != 1 {
		t.Fatalf("acct_B's runner: %q %d", held, active)
	}
}

// A runner with a slot free but held by another account is no slot for
// intake: the email waits.
func TestIntakeWaitsRatherThanJoinAnotherAccount(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	w, mb := r.worker()
	other, _ := r.pool.Acquire("acct_B")
	id := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr})
	r.pass()
	if l := r.ledger(w.ID); len(l.Acted) != 0 || r.intake.runs != 0 {
		t.Fatalf("intake ran %d times beside acct_B; acted %+v", r.intake.runs, l.Acted)
	}
	if err := r.c.releaseRunner(other); err != nil {
		t.Fatal(err)
	}
	r.pass()
	if a := r.ledger(w.ID).Acted[id]; a.Outcome != outcomeJob {
		t.Fatalf("after the slot freed: %+v", a)
	}
}

// A full pool leaves the email unacted on, without the loop spinning on it,
// and the slot freeing passes over it at once, not at the next poll.
func TestAFullPoolDefersMailUntilASlotFrees(t *testing.T) {
	r := newMailRig(t, MailConfig{PollInterval: time.Hour, SweepInterval: time.Hour})
	withPool(r, NewPool(1, 1, nil))
	w, mb := r.worker()
	other, _ := r.pool.Acquire("acct_B")
	first := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr})
	second := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.c.RunMail(ctx)

	waiting := func() bool {
		r.c.mail.mu.Lock()
		defer r.c.mail.mu.Unlock()
		return r.c.mail.slotWaiters[w.ID]
	}
	for deadline := time.Now().Add(10 * time.Second); !waiting(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("intake never found the pool full")
		}
	}
	lists := r.edge.listCalls(mb.MailboxID)
	time.Sleep(300 * time.Millisecond)
	if n := r.edge.listCalls(mb.MailboxID); n > lists+1 {
		t.Fatalf("the loop spun on a full pool: %d listings", n-lists)
	}
	if l := r.ledger(w.ID); len(l.Acted) != 0 || r.intake.runs != 0 {
		t.Fatalf("acted on %+v with the pool full", l.Acted)
	}

	if err := r.c.releaseRunner(other); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{first, second} {
		deadline := time.Now().Add(10 * time.Second)
		for _, err := r.c.Job(mailJobID(id)); err != nil; _, err = r.c.Job(mailJobID(id)) {
			if time.Now().After(deadline) {
				t.Fatalf("mail %s wasn't picked up once a slot freed", id)
			}
			time.Sleep(10 * time.Millisecond)
		}
		if j := waitJob(t, r.c, mailJobID(id)); j.State != JobFinished {
			t.Fatalf("%+v", j)
		}
	}
	l := r.ledger(w.ID)
	if l.Acted[first].Outcome != outcomeJob || l.Acted[second].Outcome != outcomeJob {
		t.Fatalf("%+v", l.Acted)
	}
}

// Intake that errors or is refused gives its slot back: with one slot, the
// next email still gets it.
func TestIntakeReleasesItsSlotOnError(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	withPool(r, NewPool(1, 1, nil))
	w, mb := r.worker()
	r.intake.set(func(f *fakeIntake) { f.down = true })
	down := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr})
	r.pass()
	poolIdle(t, r.pool)
	if len(r.ledger(w.ID).Acted) != 0 {
		t.Fatal("acted on mail intake didn't read")
	}

	r.intake.set(func(f *fakeIntake) { f.down, f.refuse = false, true })
	r.pass()
	poolIdle(t, r.pool)
	if a := r.ledger(w.ID).Acted[down]; a.Outcome != outcomeHeld {
		t.Fatalf("refused intake: %+v", a)
	}

	r.intake.set(func(f *fakeIntake) { f.refuse = false })
	ok := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr})
	r.pass()
	if j := waitJob(t, r.c, mailJobID(ok)); j.State != JobFinished {
		t.Fatalf("%+v", j)
	}
	poolIdle(t, r.pool)
}
