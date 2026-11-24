package coordinator

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"
)

// Who a firm team's subscription admits (fount docs/features/fount-fleet/
// team-billing-plan.md §6.2, D3, D5-D7). The client channel takes a Cloud
// credential with no plan of its own (channel.Peer.Paid false): it proves
// the account, its device and its verified email, and nothing about paying.
// What such a caller may do:
//
//   - a worker of a firm team whose subscription is entitled (TeamBilling
//     active, or past_due inside its period), with the role the team's log
//     gives it, as any member;
//   - make an empty worker while it is an admin of such a team, which only a
//     list of a team can take in;
//   - read its teams and their logs, open and take an invite, sign the
//     team's lists (seats below), add its own computers with its passkey,
//     recover, and ask for the team's billing and statements: none of it
//     runs a job or reads a worker.
//
// Everything else needs the caller's own plan, as before: minting a team, a
// worker before a list takes it in (save the admin case above), and every
// worker of a solo account's team (pricing.md 5a: each reviewer has their
// own plan). A caller with its own plan reaches every worker its role
// allows, a lapsed firm team's included, so its admins and reviewers can
// still read and export; the team's jobs wait all the same (teamRunsJobs).
//
// Seats: a firm team's list counts its admins, reviewers and pending
// invites, each a member. A list that grows the count past the seats paid
// for is refused with ErrSeats; one that doesn't grow it always passes, so
// removals and role changes work while over. An unentitled team has one
// seat, enough for the admin who sets it up and pays.
//
// With no TeamBiller (Config.TeamBilling nil) none of this applies: there is
// no team billing, and every route needs the caller's own plan.

var (
	// ErrNoPlan is a caller without a plan of its own on a route that needs
	// one.
	ErrNoPlan = errors.New("this needs a paid Fount plan")
	// ErrTeamUnpaid is a member without a plan of its own on a firm team's
	// worker while the team's subscription isn't entitled.
	ErrTeamUnpaid = errors.New("the team's subscription isn't active")
	// ErrSeats is a list that would need more seats than the team paid for.
	ErrSeats = errors.New("the team has no free seat")
)

// The codes a 402's body carries beside its error, for Desktop.
const (
	codeNoPlan     = "no_plan"
	codeTeamUnpaid = "team_unpaid"
	codeSeats      = "seats"
)

// errorCode is the code fail sends with err, or empty.
func errorCode(err error) string {
	switch {
	case errors.Is(err, ErrSeats):
		return codeSeats
	case errors.Is(err, ErrTeamUnpaid):
		return codeTeamUnpaid
	case errors.Is(err, ErrNoPlan):
		return codeNoPlan
	}
	return ""
}

// teamPay is what a team's billing says of it now.
type teamPay int

const (
	// teamPayNA is a team billing doesn't cover: billing is off, or it is a
	// solo account's team, which each account's own plan pays for.
	teamPayNA teamPay = iota
	// teamPaid is a firm team fount-infra entitled, as last answered.
	teamPaid
	// teamUnpaid is a firm team fount-infra's last answer doesn't entitle
	// now.
	teamUnpaid
	// teamPayUnknown is a firm team with no answer yet, or whose last
	// answer ran out while fount-infra wasn't answering. Nothing is paid
	// for, but the team isn't lapsed either.
	teamPayUnknown
)

// teamPayment is team's teamPay at now. Called with c.mu held.
func (c *Coordinator) teamPayment(team string, now time.Time) teamPay {
	if c.cfg.TeamBilling == nil || !isFirmTeam(team) {
		return teamPayNA
	}
	t := c.state.Teams[team]
	if t == nil || t.Billing == nil || t.Billing.CheckedAt.IsZero() {
		return teamPayUnknown
	}
	b := t.Billing
	switch {
	case b.Entitled(now):
		return teamPaid
	case b.Status == BillingNoAccess || b.Error == "":
		return teamUnpaid
	}
	return teamPayUnknown
}

// teamRunsJobs says whether team's jobs may start: a team billing doesn't
// cover, or a firm team that pays. Called with c.mu held.
func (c *Coordinator) teamRunsJobs(team string, now time.Time) bool {
	p := c.teamPayment(team, now)
	return p == teamPayNA || p == teamPaid
}

// admitWorker is the billing half of requireRole, for a caller the team's
// log (or, before one, the worker's creator) already lets in: a caller with
// its own plan, or one a firm team's subscription covers. Called with c.mu
// held.
func (c *Coordinator) admitWorker(caller Caller, w *Worker) error {
	if caller.Paid {
		return nil
	}
	if w.Team == "" {
		return c.admitCreate(caller)
	}
	switch c.teamPayment(w.Team, c.now()) {
	case teamPaid:
		return nil
	case teamPayNA:
		return ErrNoPlan
	}
	return ErrTeamUnpaid
}

// admitCreate says whether caller may make an empty worker: with its own
// plan, or as an admin, on this device, of a firm team that pays. Called
// with c.mu held.
func (c *Coordinator) admitCreate(caller Caller) error {
	if caller.Paid {
		return nil
	}
	now := c.now()
	for _, id := range slices.Sorted(maps.Keys(c.state.Teams)) {
		if c.teamPayment(id, now) != teamPaid {
			continue
		}
		st, err := c.teamState(id)
		if err != nil || st.deleted {
			continue
		}
		if m := st.byDevice[caller.Device]; m != nil && m.Account == caller.Account && m.Role == RoleAdmin {
			return nil
		}
	}
	return fmt.Errorf("%w: to make an email agent, have your own plan or be an admin of a team that pays", ErrNoPlan)
}

// admitTeam says whether caller may act through team's workers on a route
// that isn't a worker's own, as sending an invite from one. Called with c.mu
// held.
func (c *Coordinator) admitTeam(caller Caller, team string) error {
	if caller.Paid {
		return nil
	}
	switch c.teamPayment(team, c.now()) {
	case teamPaid:
		return nil
	case teamPayNA:
		return ErrNoPlan
	}
	return ErrTeamUnpaid
}

// teamSeats is how many members a firm team's list may grow to: the seats
// fount-infra last said were paid for, while the team is entitled, and one
// otherwise. Called with c.mu held.
func (c *Coordinator) teamSeats(team string, now time.Time) int {
	if c.teamPayment(team, now) == teamPaid {
		return max(c.state.Teams[team].Billing.Seats, 1)
	}
	return 1
}

// checkSeats is checkList's seat rule (D5-D7) for a firm team's list: one
// that grows the count of members past the team's seats is refused. Called
// with c.mu held.
func (c *Coordinator) checkSeats(prior *teamState, l TeamList, now time.Time) error {
	if c.cfg.TeamBilling == nil || !isFirmTeam(l.Team) || l.Deleted {
		return nil
	}
	before := 0
	if prior != nil {
		before = len(prior.members)
	}
	after, seats := len(l.Members), c.teamSeats(l.Team, now)
	if after > seats && after > before {
		return fmt.Errorf("%w: it has %d and the list needs %d", ErrSeats, seats, after)
	}
	return nil
}
