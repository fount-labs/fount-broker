package coordinator

import (
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// What bounds a team's log (fount docs/features/fount-fleet/
// team-billing-security-fixes.md H1). Each append clones the log, replays it
// and rewrites the whole state, so a log that grows without limit slows the
// coordinator for every tenant on it. Three bounds hold for every caller,
// paid or not:
//
//   - who may append: a caller with its own plan, or a member of a firm team
//     while team billing is on (admitTeamLog). A solo account's team is its
//     own plan's (D3), so an account with no plan writes nothing to it;
//   - how fast: each team, and each account across its teams, appends at a
//     steady rate after a burst (teamLogRate);
//   - how much: a team's log holds at most teamLogMaxEntries entries and
//     teamLogMaxBytes bytes. Only the list that deletes the team still goes
//     in past that: the log ends there.
//
// The rates are in memory: a restart refills them.
const (
	// A team of MaxMembers members, each with a few computers, makes a few
	// lists a week and a record for each invite taken, passkey used and
	// recovery started: some hundreds of entries a year. A list of 50
	// members with one computer each is about 34 KiB, one at maxTeamBody
	// 512 KiB.
	teamLogMaxEntries = 20_000
	teamLogMaxBytes   = 64 << 20

	// A team may append teamLogBurst entries at once, as when an admin's
	// invites are taken together after the email goes out, then one each
	// teamLogEvery.
	teamLogBurst = 200
	teamLogEvery = 10 * time.Second

	// An account may append accountLogBurst entries at once across all its
	// teams, then one each accountLogEvery: an admin setting a team up signs
	// a list per change.
	accountLogBurst = 60
	accountLogEvery = 30 * time.Second

	// teamLogRatePrune is how many rate entries are kept before the ones
	// that have refilled are dropped.
	teamLogRatePrune = 1024
)

// TeamLogLimitError is an append past a team's log bounds: 429, with
// Retry-After when waiting helps.
type TeamLogLimitError struct {
	// RetryAfter is how long until the append would go in, or zero for a
	// full log, which no wait opens.
	RetryAfter time.Duration
	why        string
}

func (e *TeamLogLimitError) Error() string {
	if e.RetryAfter == 0 {
		return e.why
	}
	return e.why + "; try again in " + e.RetryAfter.Round(time.Second).String()
}

// The codes a 429 from the team log carries, for Desktop.
const (
	codeTeamLogFull = "team_log_full"
	codeTeamLogRate = "team_log_rate"
)

func (e *TeamLogLimitError) code() string {
	if e.RetryAfter == 0 {
		return codeTeamLogFull
	}
	return codeTeamLogRate
}

// retryAfter sets Retry-After, in whole seconds rounded up, for an error
// that has one.
func (e *TeamLogLimitError) retryAfter(rw http.ResponseWriter) {
	if e.RetryAfter > 0 {
		rw.Header().Set("Retry-After", strconv.Itoa(int((e.RetryAfter+time.Second-1)/time.Second)))
	}
}

// admitTeamLog is the billing half of an append to team's log, for a caller
// the log already lets append: one with its own plan, or a member of a firm
// team while team billing is on, whatever the team's billing says, so a
// lapsed team's admins still remove members and pay. With billing off, as
// on a solo account's team, the caller needs its own plan. Called with c.mu
// held.
func (c *Coordinator) admitTeamLog(caller Caller, team string) error {
	if caller.Paid || (c.cfg.TeamBilling != nil && isFirmTeam(team)) {
		return nil
	}
	if isFirmTeam(team) {
		return fmt.Errorf("%w: to change a team", ErrNoPlan)
	}
	return fmt.Errorf("%w: to change your own team", ErrNoPlan)
}

// planWithoutBilling refuses every route to a caller without its own plan
// while team billing is off: there is no team to pay for it, as before the
// channel took credentials with no plan.
func (c *Coordinator) planWithoutBilling(caller Caller, h http.Handler) http.Handler {
	if caller.Paid {
		return h
	}
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if c.cfg.TeamBilling == nil {
			fail(rw, http.StatusPaymentRequired, fmt.Errorf("%w: team billing is off", ErrNoPlan))
			return
		}
		h.ServeHTTP(rw, r)
	})
}

// teamLogRate is each team's and account's next free append, as a GCRA
// theoretical arrival time: a key at or before now has its whole burst.
type teamLogRate struct {
	teams, accounts map[string]time.Time
}

// rateWait is how long key waits for one more append at now, one each
// every after a burst of burst, or zero.
func rateWait(keys map[string]time.Time, key string, now time.Time, every time.Duration, burst int) time.Duration {
	next := keys[key]
	if next.Before(now) {
		next = now
	}
	return max(next.Add(every).Sub(now)-time.Duration(burst)*every, 0)
}

// rateTake spends one of key's appends at now.
func rateTake(keys map[string]time.Time, key string, now time.Time, every time.Duration) {
	next := keys[key]
	if next.Before(now) {
		next = now
	}
	keys[key] = next.Add(every)
	if len(keys) > teamLogRatePrune {
		for k, t := range keys {
			if !t.After(now) {
				delete(keys, k)
			}
		}
	}
}

// teamLogRoom says whether entry, size bytes, may go on team's log for
// caller at now: its billing, its team's and account's rates and the log's
// bounds. ends is a list that deletes the team. Called with c.mu held.
func (c *Coordinator) teamLogRoom(caller Caller, team string, size int, ends bool, now time.Time) error {
	if err := c.admitTeamLog(caller, team); err != nil {
		return err
	}
	if !ends {
		var entries, total int
		if t := c.state.Teams[team]; t != nil {
			entries = len(t.Log)
			for _, e := range t.Log {
				total += len(e.List) + len(e.Record) + len(e.Hash)
			}
		}
		if entries+1 > teamLogMaxEntries || total+size > teamLogMaxBytes {
			return &TeamLogLimitError{why: fmt.Sprintf("the team's membership log is full (%d entries, %d KiB)", entries, total>>10)}
		}
	}
	r := &c.logRate
	wait := max(rateWait(r.teams, team, now, teamLogEvery, teamLogBurst), rateWait(r.accounts, caller.Account, now, accountLogEvery, accountLogBurst))
	if wait > 0 {
		return &TeamLogLimitError{RetryAfter: wait, why: "the team's membership log is changing too fast"}
	}
	return nil
}

// tookTeamLog spends caller's and team's rate on an entry that went in.
// Called with c.mu held.
func (c *Coordinator) tookTeamLog(caller Caller, team string, now time.Time) {
	r := &c.logRate
	if r.teams == nil {
		r.teams, r.accounts = map[string]time.Time{}, map[string]time.Time{}
	}
	rateTake(r.teams, team, now, teamLogEvery)
	rateTake(r.accounts, caller.Account, now, accountLogEvery)
}
