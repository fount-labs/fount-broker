package coordinator

import (
	"cmp"
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
//     active, past_due inside its period, or renewing inside its grace),
//     with the role the team's log gives it, as any member;
//   - make an empty worker while it is an admin of such a team, which only a
//     list of a team can take in;
//   - read its teams and their logs, and ask for the team's billing and
//     statements;
//   - on a firm team, whatever its billing says, take an invite, sign the
//     team's lists (seats below), add its own computers with its passkey and
//     recover, so a lapsed team's admins can still remove members and pay:
//     none of it runs a job or reads a worker, and the log's own bounds
//     hold (teamloglimits.go).
//
// Everything else needs the caller's own plan, as before: minting a team, a
// worker before a list takes it in (save the admin case above), and every
// worker of a solo account's team and every entry of its log (pricing.md
// 5a: each reviewer has their own plan). A caller with its own plan reaches
// every worker its role allows, a lapsed firm team's included, so its
// admins and reviewers can still read and export; the team's jobs wait all
// the same (teamRunsJobs).
//
// Seats: a firm team's list counts its admins, reviewers and pending
// invites, each a member. A list that grows the count past the seats paid
// for is refused with ErrSeats; one that doesn't grow it always passes, so
// removals and role changes work while over. An unentitled team has one
// seat, enough for the admin who sets it up and pays.
//
// A team over its seats (they were cut below its members) removes nobody
// (D7). Billing.OverSeatsSince keeps when it went over; once it has been
// over for overSeatsGrace, a billing period, only its first seats members
// with an account, admins first and then by when they joined, are admitted
// without a plan of their own and get seat statements. The rest stay on the
// list and are refused with ErrOverSeats until an admin adds seats or
// removes someone. The grace is the team's once until it has been within
// its seats for a period (trackSeats).
//
// With no TeamBiller (Config.TeamBilling nil) none of this applies: there is
// no team billing, and AccountHandler refuses every route to a caller
// without its own plan (planWithoutBilling).

var (
	// ErrNoPlan is a caller without a plan of its own on a route that needs
	// one.
	ErrNoPlan = errors.New("this needs a paid Fount plan")
	// ErrTeamUnpaid is a member without a plan of its own on a firm team's
	// worker while the team's subscription isn't entitled.
	ErrTeamUnpaid = errors.New("the team's subscription isn't active")
	// ErrSeats is a list that would need more seats than the team paid for.
	ErrSeats = errors.New("the team has no free seat")
	// ErrOverSeats is a member, without a plan of its own, beyond the seats
	// of a firm team that has had more members than seats for
	// overSeatsGrace.
	ErrOverSeats = errors.New("the team has more members than seats, and this member isn't within them")
)

// The codes a 402's body carries beside its error, for Desktop.
const (
	codeNoPlan     = "no_plan"
	codeTeamUnpaid = "team_unpaid"
	codeSeats      = "seats"
	codeOverSeats  = "over_seats"
)

// errorCode is the code fail sends with err, or empty.
func errorCode(err error) string {
	var limit *TeamLogLimitError
	switch {
	case errors.As(err, &limit):
		return limit.code()
	case errors.Is(err, ErrTeamLimit):
		return codeTeamLimit
	case errors.Is(err, ErrSeats):
		return codeSeats
	case errors.Is(err, ErrOverSeats):
		return codeOverSeats
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
	return c.admitTeam(caller, w.Team)
}

// admitCreate says whether caller may make an empty worker: with its own
// plan, or as an admin, on this device, of a firm team that pays. Called
// with c.mu held.
func (c *Coordinator) admitCreate(caller Caller) error {
	if caller.Paid {
		return nil
	}
	now := c.now()
	unseated := false
	for _, id := range slices.Sorted(maps.Keys(c.state.Teams)) {
		if c.teamPayment(id, now) != teamPaid {
			continue
		}
		st, err := c.teamState(id)
		if err != nil || st.deleted {
			continue
		}
		if m := st.byDevice[caller.Device]; m != nil && m.Account == caller.Account && m.Role == RoleAdmin {
			if !c.unseated(id, st, now)[m.ID] {
				return nil
			}
			unseated = true
		}
	}
	if unseated {
		return fmt.Errorf("%w: to make an email agent, add a seat or remove someone", ErrOverSeats)
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
	now := c.now()
	switch c.teamPayment(team, now) {
	case teamPaid:
		return c.requireSeat(caller, team, now)
	case teamPayNA:
		return ErrNoPlan
	}
	return ErrTeamUnpaid
}

// overSeatsGrace is how long a firm team may have more members than seats
// before only the first seats of them are admitted: a billing period, for
// its admins to add seats or remove someone.
const overSeatsGrace = 31 * 24 * time.Hour

// trackSeats keeps OverSeatsSince for a team of members at now: set when the
// team goes over its seats, and cleared only once it has been back within
// them for overSeatsGrace, WithinSeatsSince on. Seats bought are paid from
// now and seats cut go at the period's end, so seats raised just before it
// and cut at it cost an hour of each: were the grace to end the moment the
// team is within, that would buy a new one each period. Within the seats
// every member holds one all the same (unseated). While the team isn't
// entitled its seats aren't known, and both stay as they were, so a lapse
// doesn't start the grace over.
func (b *TeamBilling) trackSeats(members int, now time.Time) {
	switch {
	case !b.Entitled(now):
	case members > max(b.Seats, 1):
		b.WithinSeatsSince = time.Time{}
		if b.OverSeatsSince.IsZero() {
			b.OverSeatsSince = now
		}
	case b.OverSeatsSince.IsZero():
		b.WithinSeatsSince = time.Time{}
	case b.WithinSeatsSince.IsZero():
		b.WithinSeatsSince = now
	case !now.Before(b.WithinSeatsSince.Add(overSeatsGrace)):
		b.OverSeatsSince, b.WithinSeatsSince = time.Time{}, time.Time{}
	}
}

// unseated are the members, by id, of a paying firm team that hold none of
// its seats at now, or nil when every one does: the team has had more
// members than seats for overSeatsGrace, and the member isn't among the first
// seats with an account, admins first, then by when each joined. A pending
// invite counts toward the members but holds no seat. Called with c.mu held.
func (c *Coordinator) unseated(team string, st *teamState, now time.Time) map[string]bool {
	if c.teamPayment(team, now) != teamPaid {
		return nil
	}
	b := c.state.Teams[team].Billing
	seats := max(b.Seats, 1)
	if b.OverSeatsSince.IsZero() || now.Before(b.OverSeatsSince.Add(overSeatsGrace)) || len(st.members) <= seats {
		return nil
	}
	var order []*Member
	for _, m := range st.members {
		if m.Account != "" {
			order = append(order, m)
		}
	}
	if len(order) <= seats {
		return nil
	}
	rank := func(m *Member) int {
		if m.Role == RoleAdmin {
			return 0
		}
		return 1
	}
	slices.SortFunc(order, func(a, b *Member) int {
		return cmp.Or(cmp.Compare(rank(a), rank(b)), cmp.Compare(a.Joined, b.Joined), cmpString(a.ID, b.ID))
	})
	out := map[string]bool{}
	for _, m := range order[seats:] {
		out[m.ID] = true
	}
	return out
}

// requireSeat refuses caller's member of a paying firm team with
// ErrOverSeats when it holds no seat. Called with c.mu held.
func (c *Coordinator) requireSeat(caller Caller, team string, now time.Time) error {
	st, err := c.teamState(team)
	if err != nil {
		return err
	}
	if m := st.byDevice[caller.Device]; m != nil && c.unseated(team, st, now)[m.ID] {
		seats := max(c.state.Teams[team].Billing.Seats, 1)
		return fmt.Errorf("%w: %d members, %d seats; an admin adds a seat or removes someone", ErrOverSeats, len(st.members), seats)
	}
	return nil
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
