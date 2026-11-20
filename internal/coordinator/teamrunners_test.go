package coordinator

import (
	"sync/atomic"
	"testing"
	"time"
)

const runnerTeam = "tm_0123456789abcdef01234567"

func TestTeamRunnerNamesBindOnlyInTheirStage(t *testing.T) {
	h := NewRunnerHub(nil)
	defer h.Close()
	if got := h.teamOf("runner-dev-tm-0123456789abcdef01234567"); got != "" {
		t.Fatalf("with no stage a name bound %q", got)
	}
	h.TeamStage = "dev"
	for name, want := range map[string]string{
		"runner-dev-tm-0123456789abcdef01234567":  runnerTeam,
		"runner-prod-tm-0123456789abcdef01234567": "",
		"runner-dev-tm-0123456789ABCDEF01234567":  "",
		"runner-dev-tm-0123456789abcdef0123456":   "",
		"runner-a":                                "",
		"":                                        "",
	} {
		if got := h.teamOf(name); got != want {
			t.Errorf("%q bound %q, want %q", name, got, want)
		}
	}
	if TeamRunnerName("dev", runnerTeam) != "runner-dev-tm-0123456789abcdef01234567" {
		t.Fatal(TeamRunnerName("dev", runnerTeam))
	}
	if h.Placement(runnerTeam) != runnerTeam || h.Placement("acct1") != "" {
		t.Fatal("placement")
	}
}

func TestARunnerKeyKeepsItsFirstName(t *testing.T) {
	h := NewRunnerHub(nil)
	defer h.Close()
	h.TeamStage = "dev"
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	b, err := h.bind("k1", TeamRunnerName("dev", runnerTeam), now)
	if err != nil || b.account != runnerTeam {
		t.Fatalf("%+v %v", b, err)
	}
	if _, err := h.bind("k1", TeamRunnerName("dev", runnerTeam), now); err != nil {
		t.Fatalf("the same name again: %v", err)
	}
	if _, err := h.bind("k1", "runner-a", now); err != ErrRunnerRenamed {
		t.Fatalf("a pool name for a team's key: %v", err)
	}
	if _, err := h.bind("k1", TeamRunnerName("dev", "tm_ffffffffffffffffffffffff"), now); err != ErrRunnerRenamed {
		t.Fatalf("another team's name: %v", err)
	}
	// Another key may take the team's name: a blue/green update boots a
	// second runner under it.
	if b, err := h.bind("k2", TeamRunnerName("dev", runnerTeam), now); err != nil || b.account != runnerTeam {
		t.Fatalf("%+v %v", b, err)
	}
	if b, err := h.bind("k3", "runner-a", now); err != nil || b.account != "" {
		t.Fatalf("a pool runner: %+v %v", b, err)
	}
	if h.teams[runnerTeam].linked.IsZero() {
		t.Fatal("the team's runner linking isn't activity")
	}
}

func TestATeamsSlotsAreCountedApartFromThePool(t *testing.T) {
	p := NewPool(1, 1, nil)
	p.Dedicated = IsTeamID
	p.DedicatedSlots = 2
	a, ok1 := p.Acquire(runnerTeam)
	b, ok2 := p.Acquire(runnerTeam)
	if !ok1 || !ok2 {
		t.Fatal("no team slot")
	}
	if _, ok := p.Acquire(runnerTeam); ok {
		t.Fatal("a third slot on a runner of two")
	}
	solo, ok := p.Acquire("acct1")
	if !ok {
		t.Fatal("a team's jobs took the pool's slot")
	}
	if err := p.Release(a); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Acquire(runnerTeam); !ok {
		t.Fatal("a released team slot isn't free")
	}
	for _, id := range []string{b, solo} {
		if err := p.Release(id); err != nil {
			t.Fatal(err)
		}
	}
}

func TestATeamsJobWaitsInTheQueueUntilItsRunnerLinks(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	var linked atomic.Bool
	c.cfg.Pool.Ready = func(account string) bool { return !IsTeamID(account) || linked.Load() }
	c.cfg.Pool.Dedicated = IsTeamID
	c.cfg.Pool.DedicatedSlots = 2
	w, err := c.CreateWorker(runnerTeam, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.PutFile(w.ID, "threads/t1/2026-11-13-e_1/message.md", []byte("From Ann: hello"))
	job, err := c.Enqueue(w.ID, spec("t1"))
	if err != nil {
		t.Fatal(err)
	}
	// A solo account's job runs meanwhile, on the pool.
	solo, _ := c.CreateWorker("acme", nil)
	c.PutFile(solo.ID, "threads/t1/2026-11-13-e_1/message.md", []byte("From Ann: hello"))
	soloJob, err := c.Enqueue(solo.ID, spec("t1"))
	if err != nil {
		t.Fatal(err)
	}
	if j := waitJob(t, c, soloJob.ID); j.State != JobFinished {
		t.Fatalf("solo job %s: %s", j.State, j.Error)
	}
	// Longer than the scheduler's tick, so it has looked again.
	time.Sleep(200 * time.Millisecond)
	c.poke()
	time.Sleep(100 * time.Millisecond)
	j, _ := c.Job(job.ID)
	c.mu.Lock()
	why := c.queued[job.ID]
	c.mu.Unlock()
	if j.State != JobQueued || why != queuedBusy {
		t.Fatalf("with its runner stopped the team's job is %s (%q)", j.State, why)
	}
	list := c.TeamRunners("dev", nil, time.Now())
	if len(list) != 1 || list[0].Account != runnerTeam || list[0].Queued != 1 || list[0].Name != "runner-dev-tm-0123456789abcdef01234567" {
		t.Fatalf("control list %+v", list)
	}
	if list[0].LastActivityAt != "" {
		t.Fatalf("a team that never ran has activity %q", list[0].LastActivityAt)
	}

	linked.Store(true)
	c.RunnersChanged()
	if j := waitJob(t, c, job.ID); j.State != JobFinished {
		t.Fatalf("team job %s: %s", j.State, j.Error)
	}
	list = c.TeamRunners("dev", nil, time.Now())
	if len(list) != 1 || list[0].Queued != 0 || list[0].Running != 0 || list[0].LastActivityAt == "" {
		t.Fatalf("after its job %+v", list)
	}
	if at, err := time.Parse(time.RFC3339, list[0].LastActivityAt); err != nil || time.Since(at) > time.Minute {
		t.Fatalf("lastActivityAt %q: %v", list[0].LastActivityAt, err)
	}
	for _, r := range list {
		if r.Account == "acme" {
			t.Fatal("a solo account is listed")
		}
	}
}

func TestTheControlListShowsLinksIntakeAndRetiredTeams(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	now := time.Now()
	linkedTeam := "tm_aaaaaaaaaaaaaaaaaaaaaaaa"
	gone := "tm_dddddddddddddddddddddddd"
	waiting := "tm_eeeeeeeeeeeeeeeeeeeeeeee"
	old := "tm_ffffffffffffffffffffffff"
	w, _ := c.CreateWorker(waiting, nil)
	c.noteIntakeWait(w.ID, waiting, true)
	c.mu.Lock()
	c.state.Teams[gone] = &Team{ID: gone, state: &teamState{deleted: true}}
	c.mu.Unlock()
	links := map[string]TeamLink{
		linkedTeam: {Connected: true, Busy: 1, Last: now.Add(-time.Minute)},
		old:        {Last: now.Add(-48 * time.Hour)},
	}
	got := map[string]ControlRunner{}
	for _, r := range c.TeamRunners("dev", links, now) {
		got[r.Account] = r
	}
	if len(got) != 3 {
		t.Fatalf("listed %+v", got)
	}
	if r := got[linkedTeam]; !r.Connected || r.Running != 1 || r.LastActivityAt != now.Add(-time.Minute).UTC().Format(time.RFC3339) || r.Retired {
		t.Fatalf("linked %+v", r)
	}
	if r := got[gone]; !r.Retired || r.Name != TeamRunnerName("dev", gone) {
		t.Fatalf("deleted %+v", r)
	}
	if r := got[waiting]; r.Queued != 1 {
		t.Fatalf("intake waiting %+v", r)
	}
	// An intake wait that wasn't marked again stops counting.
	for _, r := range c.TeamRunners("dev", nil, now.Add(intakeWaitFresh+time.Minute)) {
		if r.Account == waiting {
			t.Fatalf("a stale intake wait still listed: %+v", r)
		}
	}
	c.noteIntakeWait(w.ID, waiting, false)
	for _, r := range c.TeamRunners("dev", nil, now) {
		if r.Account == waiting {
			t.Fatalf("an intake that got its slot still listed: %+v", r)
		}
	}
}
