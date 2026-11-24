package coordinator

import (
	"cmp"
	"slices"
	"time"
)

// ControlRunner is one team's runner as GET /control/runners reports it to
// the control plane that starts, stops and deletes team runners (fount-infra
// docs/TEAM_RUNNERS.md). It is counts and times: no job data.
type ControlRunner struct {
	Name      string `json:"name"`
	Account   string `json:"account"`
	Queued    int    `json:"queued"`
	Running   int    `json:"running"`
	Connected bool   `json:"connected"`
	// LastActivityAt is RFC 3339, omitted only if the team never had any.
	LastActivityAt string `json:"lastActivityAt,omitempty"`
	Retired        bool   `json:"retired,omitempty"`
}

// recentActivity is how long after its last activity a team with nothing
// queued and no runner linked is still listed. The control plane stops an
// idle runner after 15 minutes.
const recentActivity = 24 * time.Hour

// intakeWaitFresh is how long an intake that found no slot counts as queued.
// A waiting intake is tried again whenever a runner links in or a slot
// frees, and on every mail sweep (10 minutes at most), each time marking it
// again; one whose mail no longer needs it stops counting.
const intakeWaitFresh = 15 * time.Minute

// intakeWait is a worker's intake waiting for a runner slot.
type intakeWait struct {
	account string
	at      time.Time
}

// noteIntakeWait marks workerID's intake as waiting for a slot, or done
// waiting.
func (c *Coordinator) noteIntakeWait(workerID, account string, waiting bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !waiting {
		delete(c.intakeWaits, workerID)
		return
	}
	if c.intakeWaits == nil {
		c.intakeWaits = map[string]intakeWait{}
	}
	c.intakeWaits[workerID] = intakeWait{account: account, at: time.Now()}
}

// TeamRunners lists every team with jobs queued or running, intake waiting,
// a runner linked (links, from RunnerHub.TeamLinks), activity in the last
// day, or a deletion: what /control/runners serves. stage names the runners
// (RunnerHub.TeamStage).
//
// lastActivityAt is the latest of the team's jobs' starts and ends, kept on
// the volume, and its runner's first link of a boot and its links taken and
// ended, since the coordinator started.
//
// retired is a deleted team, listed for as long as the volume keeps its log,
// so its runner is deleted whenever the control plane next reads this, and a
// team whose subscription ended for good (TeamBilling.ended: canceled, or
// over for teamRetireAfter). A team that doesn't pay (admission.go) counts
// nothing queued, so the control plane starts no runner for it: its jobs and
// intake wait until it pays.
func (c *Coordinator) TeamRunners(stage string, links map[string]TeamLink, now time.Time) []ControlRunner {
	c.mu.Lock()
	defer c.mu.Unlock()
	by := map[string]*ControlRunner{}
	last := map[string]time.Time{}
	get := func(team string) *ControlRunner {
		r := by[team]
		if r == nil {
			r = &ControlRunner{Name: TeamRunnerName(stage, team), Account: team}
			by[team] = r
		}
		return r
	}
	unpaid := map[string]bool{}
	for id := range c.state.Teams {
		if IsTeamID(id) && !c.teamRunsJobs(id, now) {
			unpaid[id] = true
		}
	}
	for _, j := range c.state.Jobs {
		w := c.state.Workers[j.WorkerID]
		if w == nil || !IsTeamID(w.Account) {
			continue
		}
		last[w.Account] = latest(last[w.Account], j.Started, j.Ended)
		switch j.State {
		case JobQueued:
			if unpaid[w.Account] {
				continue
			}
			get(w.Account).Queued++
		case JobRunning:
			get(w.Account).Running++
		}
	}
	for id, wait := range c.intakeWaits {
		if c.state.Workers[id] == nil || now.Sub(wait.at) > intakeWaitFresh || unpaid[wait.account] {
			continue
		}
		get(wait.account).Queued++
	}
	for team, l := range links {
		last[team] = latest(last[team], l.Last)
		if l.Connected || l.Busy > 0 {
			r := get(team)
			r.Connected = l.Connected
			r.Running = max(r.Running, l.Busy)
		}
	}
	for team, t := range last {
		if !t.IsZero() && now.Sub(t) < recentActivity {
			get(team)
		}
	}
	for id := range c.state.Teams {
		if !IsTeamID(id) {
			continue
		}
		if st, err := c.teamState(id); err == nil && st.deleted || c.state.Teams[id].Billing.ended(now) {
			get(id).Retired = true
		}
	}
	out := make([]ControlRunner, 0, len(by))
	for team, r := range by {
		if t := last[team]; !t.IsZero() {
			r.LastActivityAt = t.UTC().Format(time.RFC3339)
		}
		out = append(out, *r)
	}
	slices.SortFunc(out, func(a, b ControlRunner) int { return cmp.Compare(a.Account, b.Account) })
	return out
}
