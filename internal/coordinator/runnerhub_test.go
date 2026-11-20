package coordinator

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestAPoolThatIsntReadyHasNoRoom(t *testing.T) {
	var ready atomic.Bool
	p := NewPool(1, 2, nil)
	p.Ready = func(string) bool { return ready.Load() }
	if _, ok := p.Acquire("acct1"); ok {
		t.Fatal("a slot with no runner linked")
	}
	ready.Store(true)
	if _, ok := p.Acquire("acct1"); !ok {
		t.Fatal("no slot once a runner linked")
	}
}

func TestJobsWaitInTheQueueUntilARunnerLinksIn(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	var ready atomic.Bool
	c.cfg.Pool.Ready = func(string) bool { return ready.Load() }
	w, err := c.CreateWorker("acme", nil)
	if err != nil {
		t.Fatal(err)
	}
	c.PutFile(w.ID, "threads/t1/2026-11-13-e_1/message.md", []byte("From Ann: hello"))
	job, err := c.Enqueue(w.ID, spec("t1"))
	if err != nil {
		t.Fatal(err)
	}
	// Longer than the scheduler's tick, so it has looked again.
	time.Sleep(200 * time.Millisecond)
	c.poke()
	time.Sleep(100 * time.Millisecond)
	j, err := c.Job(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	why := c.queued[job.ID]
	c.mu.Unlock()
	if j.State != JobQueued || why != queuedBusy {
		t.Fatalf("with no runner linked the job is %s (%q)", j.State, why)
	}
	ready.Store(true)
	c.RunnersChanged()
	if j := waitJob(t, c, job.ID); j.State != JobFinished {
		t.Fatalf("job %s: %s", j.State, j.Error)
	}
}

func TestTakeWithNoRunnerLinkedGivesUp(t *testing.T) {
	h := NewRunnerHub(nil)
	defer h.Close()
	h.TakeWait = 50 * time.Millisecond
	if h.Ready() {
		t.Fatal("ready with no links")
	}
	if _, err := h.Take(context.Background(), "acct1"); !errors.Is(err, ErrNoRunnerLink) {
		t.Fatalf("%v", err)
	}
}
