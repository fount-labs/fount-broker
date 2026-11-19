package coordinator

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fount-labs/fount-broker/internal/jobwire"
)

// gateRunner holds each agent job until the test releases one of its
// account's, and counts each account's jobs running at once.
type gateRunner struct {
	mu       sync.Mutex
	releases map[string]chan struct{}
	running  map[string]int
	peak     map[string]int
	started  int
}

func (g *gateRunner) Run(ctx context.Context, _, account string, job JobDirs) (RunResult, error) {
	if job.Mode == jobwire.ModeIndex {
		return RunResult{}, os.MkdirAll(job.Index, dirMode)
	}
	g.mu.Lock()
	release := g.releaseOf(account)
	g.started++
	g.running[account]++
	g.peak[account] = max(g.peak[account], g.running[account])
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		g.running[account]--
		g.mu.Unlock()
	}()
	select {
	case <-release:
		return RunResult{}, nil
	case <-ctx.Done():
		return RunResult{}, ctx.Err()
	}
}

func (g *gateRunner) releaseOf(account string) chan struct{} {
	if g.releases[account] == nil {
		g.releases[account] = make(chan struct{})
	}
	return g.releases[account]
}

// release ends one of account's running jobs.
func (g *gateRunner) release(account string) {
	g.mu.Lock()
	ch := g.releaseOf(account)
	g.mu.Unlock()
	ch <- struct{}{}
}

func (g *gateRunner) counts(account string) (running, peak, started int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.running[account], g.peak[account], g.started
}

func newCappedCoordinator(t *testing.T, runners, slots, accountJobs int) (*Coordinator, *gateRunner) {
	t.Helper()
	key, _ := NewWrappingKey()
	dir := t.TempDir()
	g := &gateRunner{releases: map[string]chan struct{}{}, running: map[string]int{}, peak: map[string]int{}}
	c, err := New(Config{
		StateDir:    filepath.Join(dir, "state"),
		WorkDir:     filepath.Join(dir, "work"),
		Store:       DirStore{Root: filepath.Join(dir, "objects")},
		Key:         key,
		Pool:        NewPool(runners, slots, nil),
		Runner:      g,
		AccountJobs: accountJobs,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return c, g
}

// enqueueOnWorkers queues n jobs for account, each on a worker of its own, as
// a worker runs one job at a time.
func enqueueOnWorkers(t *testing.T, c *Coordinator, account string, n int) []string {
	t.Helper()
	var ids []string
	for range n {
		w, err := c.CreateWorker(account, nil)
		if err != nil {
			t.Fatal(err)
		}
		j, err := c.Enqueue(w.ID, spec("t1"))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, j.ID)
	}
	return ids
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("never: %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestAnAccountRunsNoMoreThanItsCap(t *testing.T) {
	c, g := newCappedCoordinator(t, 2, 4, 2)
	ids := enqueueOnWorkers(t, c, "acme", 5)
	eventually(t, "two of acme's jobs run", func() bool { r, _, _ := g.counts("acme"); return r == 2 })
	time.Sleep(100 * time.Millisecond)
	if r, _, _ := g.counts("acme"); r != 2 {
		t.Fatalf("acme runs %d jobs past its cap of 2", r)
	}
	if l := c.Load(); l.Running != 2 || l.Queued != 3 || len(l.Accounts) != 1 || l.AccountJobs != 2 {
		t.Fatalf("load at the cap: %+v", l)
	}

	// Another account's job starts while acme waits at its cap.
	other := enqueueOnWorkers(t, c, "globex", 1)
	eventually(t, "globex's job runs", func() bool { r, _, _ := g.counts("globex"); return r == 1 })
	if l := c.Load(); l.Running != 3 || l.Queued != 3 || len(l.Accounts) != 2 || l.Accounts[0] != (AccountLoad{Running: 2, Queued: 3}) {
		t.Fatalf("load with globex: %+v", l)
	}

	// As each of acme's jobs ends, a queued one takes its place.
	for _, want := range []int{3, 4, 5} {
		g.release("acme")
		eventually(t, "a queued job starts as one ends", func() bool { _, _, s := g.counts(""); return s == want+1 })
	}
	g.release("acme")
	g.release("acme")
	g.release("globex")
	for _, id := range append(ids, other...) {
		if j := waitJob(t, c, id); j.State != JobFinished {
			t.Fatalf("%s: %s %s", id, j.State, j.Error)
		}
	}
	if _, peak, _ := g.counts("acme"); peak != 2 {
		t.Fatalf("acme peaked at %d jobs, past its cap of 2", peak)
	}
	if l := c.Load(); l.Running != 0 || l.Queued != 0 || len(l.Accounts) != 0 {
		t.Fatalf("load once drained: %+v", l)
	}
}

func TestNoAccountCap(t *testing.T) {
	c, g := newCappedCoordinator(t, 1, 8, 0)
	ids := enqueueOnWorkers(t, c, "acme", 6)
	eventually(t, "all six run at once", func() bool { r, _, _ := g.counts("acme"); return r == 6 })
	for range ids {
		g.release("acme")
	}
	for _, id := range ids {
		if j := waitJob(t, c, id); j.State != JobFinished {
			t.Fatalf("%s: %s %s", id, j.State, j.Error)
		}
	}
}

func TestTheNextSlotGoesToTheAccountWithFewestRunning(t *testing.T) {
	c := &Coordinator{
		cfg: Config{AccountJobs: 3},
		state: &State{Workers: map[string]*Worker{
			"w_a1": {ID: "w_a1", Account: "acme"}, "w_a2": {ID: "w_a2", Account: "acme"},
			"w_b1": {ID: "w_b1", Account: "globex"}, "w_c1": {ID: "w_c1", Account: "initech"},
		}},
		busy:        map[string]bool{},
		accountJobs: map[string]int{"acme": 1},
	}
	queued := []*Job{{ID: "j_1", WorkerID: "w_a2", Seq: 1}, {ID: "j_2", WorkerID: "w_b1", Seq: 2}, {ID: "j_3", WorkerID: "w_c1", Seq: 3}}
	if i := c.next(queued, map[string]bool{}); i != 1 {
		t.Fatalf("picked %d, not globex's job: acme already runs one", i)
	}
	if i := c.next(queued, map[string]bool{"globex": true}); i != 2 {
		t.Fatalf("picked %d, not initech's job when globex has no slot", i)
	}
	c.accountJobs = map[string]int{"acme": 3, "globex": 3, "initech": 3}
	if i := c.next(queued, map[string]bool{}); i != -1 {
		t.Fatalf("picked %d with every account at its cap", i)
	}
	c.accountJobs = map[string]int{}
	c.busy["w_a2"] = true
	if i := c.next(queued, map[string]bool{}); i != 1 {
		t.Fatalf("picked %d, a job whose worker is busy", i)
	}
}

// A job that can't start says why: busy when the runners are all in use,
// waiting when its own account is at its cap.
func TestAQueuedJobSaysWhyItWaits(t *testing.T) {
	c, g := newCappedCoordinator(t, 2, 2, 1)
	acme := enqueueOnWorkers(t, c, "acme", 2)
	eventually(t, "one of acme's jobs runs", func() bool { r, _, _ := g.counts("acme"); return r == 1 })
	why := func(id string) string {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.queued[id]
	}
	eventually(t, "acme's second job waits on its cap", func() bool { return why(acme[1]) == queuedWaiting })

	bolt := enqueueOnWorkers(t, c, "bolt", 2)
	eventually(t, "one of bolt's jobs runs", func() bool { r, _, _ := g.counts("bolt"); return r == 1 })
	other := enqueueOnWorkers(t, c, "cove", 1)
	eventually(t, "cove's job finds the runners busy", func() bool { return why(other[0]) == queuedBusy })
	if why(bolt[1]) != queuedWaiting {
		t.Errorf("bolt's second job: %q", why(bolt[1]))
	}
	// A runner serves one account at a time: when acme's job ends, its
	// runner goes to the oldest job of an account with none running.
	g.release("acme")
	eventually(t, "a job takes acme's runner", func() bool { return why(acme[1]) == "" })
	if why(other[0]) != queuedBusy {
		t.Errorf("cove's job: %q", why(other[0]))
	}
}
