package coordinator

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Team billing (fount docs/features/fount-fleet/team-billing-plan.md §6.2,
// D1): a firm team pays for itself, with a subscription row in fount-infra
// keyed by its team id. fount-infra never learns who is in the team; the
// coordinator, which holds the membership log, says what it needs to know
// with statements signed by its attested job-signing key:
//
//	fount-team-admin   this account is an admin of this team (checkout, portal)
//	fount-team-seat    this account holds a seat in this team (Desktop's own AI, D4)
//	fount-team-status  the coordinator asking for the team's subscription
//
// and keeps each firm team's billing as fount-infra last answered it, in
// state.json: daily, after a worker of the team takes a lapse step, and when
// a member asks (POST /v1/teams/{team}/billing-refresh, after checkout).
//
// Who Billing admits, and its seats, are admission.go's; a team's lapse is
// lapse.go's (teamLapseDue), and its runner's start teamrunners.go's.

// StatementKind is what a billing statement says of its account.
type StatementKind string

const (
	StatementAdmin StatementKind = "admin"
	StatementSeat  StatementKind = "seat"
)

// TeamBiller is fount-infra's side of team billing: it signs the statements
// a member's device carries to fount-infra, and asks fount-infra for a
// team's subscription (package teambill).
type TeamBiller interface {
	Statement(kind StatementKind, team, account string) (TeamStatement, error)
	// Status is the team's subscription. A team fount-infra doesn't
	// entitle is a *TeamNotEntitled; any other error is one to retry.
	Status(ctx context.Context, team string) (TeamEntitlement, error)
}

// TeamStatement is a signed statement and when it expires.
type TeamStatement struct {
	Token     string
	ExpiresAt time.Time
}

// TeamEntitlement is fount-infra's answer for an entitled team.
type TeamEntitlement struct {
	Status    string
	Tier      string
	PeriodEnd time.Time
	// GraceEnds is set while the team is past_due: it is entitled until then.
	GraceEnds time.Time
	Seats     int
	// Subscription is the id of the subscription the answer is about, empty
	// from a fount-infra that doesn't say.
	Subscription string
}

// TeamNotEntitled is fount-infra's 403 no_access for a team, with its reason
// (no_subscription, canceled, period_ended, no_cloud_plan), and the id of the
// team's subscription when it has one and fount-infra says.
type TeamNotEntitled struct {
	Reason       string
	Subscription string
}

func (e *TeamNotEntitled) Error() string {
	return "fount-infra: the team isn't entitled (" + e.Reason + ")"
}

// BillingNoAccess is TeamBilling.Status for a team fount-infra refused.
const BillingNoAccess = "no_access"

// TeamBilling is a firm team's billing as fount-infra last answered.
type TeamBilling struct {
	// Status is fount-infra's status (active, past_due), or BillingNoAccess
	// with Reason; empty until it first answers.
	Status    string    `json:"status,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Tier      string    `json:"tier,omitempty"`
	PeriodEnd time.Time `json:"periodEnd,omitzero"`
	GraceEnds time.Time `json:"graceEnds,omitzero"`
	Seats     int       `json:"seats,omitempty"`
	// CheckedAt is fount-infra's last answer; Error is the last failure to
	// get one since, at TriedAt, which keeps the answer before it.
	CheckedAt time.Time `json:"checkedAt,omitzero"`
	TriedAt   time.Time `json:"triedAt,omitzero"`
	Error     string    `json:"error,omitempty"`
	// Since is the first answer, of those since the team was last
	// entitled, that didn't entitle it: how long its subscription has been
	// over (TeamRunners' retired).
	Since time.Time `json:"since,omitzero"`
	// Subscription is the subscription the last answer was about.
	Subscription string `json:"subscription,omitempty"`
	// RetiredAt is the answer that ended the team for good (ended), and
	// RetiredSubscription the subscription it was about: kept while the team
	// stays ended, so the control plane's backstop compares a fixed time and
	// subscription (TeamRunners), and cleared by an answer that doesn't end
	// it.
	RetiredAt           time.Time `json:"retiredAt,omitzero"`
	RetiredSubscription string    `json:"retiredSubscription,omitempty"`
}

// Entitled says whether the team's subscription covers now: active, or
// past_due before its period ends.
func (b *TeamBilling) Entitled(now time.Time) bool {
	if b == nil {
		return false
	}
	switch b.Status {
	case "active":
		return b.PeriodEnd.IsZero() || now.Before(b.PeriodEnd)
	case "past_due":
		return now.Before(b.entitledUntil())
	}
	return false
}

// entitledUntil is when the answer stops entitling the team, or zero for
// one that doesn't end or doesn't entitle.
func (b *TeamBilling) entitledUntil() time.Time {
	switch b.Status {
	case "active":
		return b.PeriodEnd
	case "past_due":
		return cmp.Or(b.GraceEnds, b.PeriodEnd)
	}
	return time.Time{}
}

// teamRetireAfter is how long a firm team's subscription stays over before
// the team counts as ended for good: the edge's hold on a lapsed worker's
// mail.
const teamRetireAfter = 30 * 24 * time.Hour

// ended says whether the team's subscription ended for good: canceled, or
// over for teamRetireAfter. A team that never had one hasn't ended.
func (b *TeamBilling) ended(now time.Time) bool {
	if b == nil || b.Status != BillingNoAccess || b.Reason == "no_subscription" {
		return false
	}
	return b.Reason == "canceled" || !b.Since.IsZero() && now.Sub(b.Since) >= teamRetireAfter
}

// retire keeps, on an answer that ends the team, the answer that first
// ended it (retiredBy of prev, the answer before, when that one had ended it
// too), unless that was about another subscription: the team's next one
// ended as well, and this answer ended it.
func (b *TeamBilling) retire(prev *TeamBilling, now time.Time) {
	b.RetiredAt, b.RetiredSubscription = time.Time{}, ""
	if !b.ended(now) {
		return
	}
	b.RetiredAt, b.RetiredSubscription = b.CheckedAt, b.Subscription
	if prev == nil || !prev.ended(now) {
		return
	}
	if at, sub := prev.retiredBy(); sub == "" || b.Subscription == "" || sub == b.Subscription {
		b.RetiredAt, b.RetiredSubscription = at, cmp.Or(sub, b.Subscription)
	}
}

// retiredBy is the answer that ended the team, and its subscription: RetiredAt,
// or for a team over long enough since its last answer, that answer.
func (b *TeamBilling) retiredBy() (time.Time, string) {
	if !b.RetiredAt.IsZero() {
		return b.RetiredAt, b.RetiredSubscription
	}
	return b.CheckedAt, b.Subscription
}

// TeamBillingView is a team's billing as its members see it (GET /v1/teams,
// the refresh route). Subscription ids are the control plane's, not shown.
type TeamBillingView struct {
	TeamBilling
	Entitled bool `json:"entitled"`
	// Subscription and RetiredSubscription hide TeamBilling's.
	Subscription        string `json:"subscription,omitempty"`
	RetiredSubscription string `json:"retiredSubscription,omitempty"`
}

func billingView(b *TeamBilling, now time.Time) *TeamBillingView {
	if b == nil {
		return &TeamBillingView{}
	}
	return &TeamBillingView{TeamBilling: *b, Entitled: b.Entitled(now)}
}

const (
	// teamBillingEvery is how often each firm team's billing is asked.
	teamBillingEvery = 24 * time.Hour
	// teamBillingRetry spaces out tries after a failure to get an answer.
	teamBillingRetry = time.Hour
	// teamBillingTick is how often the loop looks for teams due.
	teamBillingTick = 10 * time.Minute
	// TeamBillingRefreshGap is the least time between two refreshes of one
	// team that a member or a lapse step asks for.
	TeamBillingRefreshGap = time.Minute
	// maxBillingBody bounds a statement request.
	maxBillingBody = 1 << 10
)

// ErrBillingOff is a coordinator with no TeamBiller.
var ErrBillingOff = fmt.Errorf("%w: team billing", ErrUnsupported)

// RefreshTooSoonError is a refresh asked within TeamBillingRefreshGap of the
// last.
type RefreshTooSoonError struct{ RetryAfter time.Duration }

func (e *RefreshTooSoonError) Error() string {
	return "the team's billing was refreshed moments ago; try again in " + e.RetryAfter.Round(time.Second).String()
}

// teamBillingLoop is the loop's state; its zero value is ready.
type teamBillingLoop struct {
	mu sync.Mutex
	// asked is when each team's last asked-for refresh was tried.
	asked   map[string]time.Time
	pending map[string]bool
	kick    chan struct{}
	// one serializes the calls to fount-infra.
	one sync.Mutex
}

func (l *teamBillingLoop) kicker() chan struct{} {
	if l.kick == nil {
		l.kick = make(chan struct{}, 1)
	}
	return l.kick
}

// isFirmTeam says whether team is a firm team's, which pays for itself; a
// solo account's team is billed through its account.
func isFirmTeam(team string) bool {
	return teamIDPattern.MatchString(team)
}

// claimRefresh takes team's next asked-for refresh, or says how long until
// it may.
func (c *Coordinator) claimRefresh(team string, now time.Time) error {
	l := &c.billing
	l.mu.Lock()
	defer l.mu.Unlock()
	if last, ok := l.asked[team]; ok {
		if wait := TeamBillingRefreshGap - now.Sub(last); wait > 0 {
			return &RefreshTooSoonError{RetryAfter: wait}
		}
	}
	if l.asked == nil {
		l.asked = map[string]time.Time{}
	}
	l.asked[team] = now
	return nil
}

// teamBillingSoon asks the loop to refresh team's billing: a worker of the
// team took a lapse step. One asked within TeamBillingRefreshGap is dropped.
func (c *Coordinator) teamBillingSoon(team string) {
	if c.cfg.TeamBilling == nil || !isFirmTeam(team) {
		return
	}
	// Its own key, so a lapse step doesn't hold up a member's refresh.
	if c.claimRefresh("lapse:"+team, c.now()) != nil {
		return
	}
	l := &c.billing
	l.mu.Lock()
	if l.pending == nil {
		l.pending = map[string]bool{}
	}
	l.pending[team] = true
	kick := l.kicker()
	l.mu.Unlock()
	select {
	case kick <- struct{}{}:
	default:
	}
}

// RunTeamBilling keeps every firm team's billing until ctx ends. Without a
// TeamBiller it returns at once.
func (c *Coordinator) RunTeamBilling(ctx context.Context) {
	if c.cfg.TeamBilling == nil {
		return
	}
	c.billing.mu.Lock()
	kick := c.billing.kicker()
	c.billing.mu.Unlock()
	tick := time.NewTicker(teamBillingTick)
	defer tick.Stop()
	for {
		c.pollTeamBilling(ctx, c.now())
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-kick:
		}
	}
}

// pollTeamBilling refreshes the teams due, and those asked for.
func (c *Coordinator) pollTeamBilling(ctx context.Context, now time.Time) {
	c.billing.mu.Lock()
	asked := c.billing.pending
	c.billing.pending = nil
	c.billing.mu.Unlock()
	for _, team := range c.teamsBillingDue(now, asked) {
		if ctx.Err() != nil {
			return
		}
		if _, err := c.refreshTeamBilling(ctx, team); err != nil {
			log.Printf("team billing: couldn't ask fount-infra for a team's billing: %v", err)
		}
	}
}

// teamsBillingDue are the firm teams whose billing is due, or asked for.
func (c *Coordinator) teamsBillingDue(now time.Time, asked map[string]bool) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, id := range slices.Sorted(maps.Keys(c.state.Teams)) {
		if !isFirmTeam(id) {
			continue
		}
		if st, err := c.teamState(id); err != nil || st.deleted {
			continue
		}
		if asked[id] || billingDue(c.state.Teams[id].Billing, now) {
			out = append(out, id)
		}
	}
	return out
}

func billingDue(b *TeamBilling, now time.Time) bool {
	if b == nil {
		return true
	}
	if b.Error != "" {
		return now.Sub(b.TriedAt) >= teamBillingRetry
	}
	if b.CheckedAt.IsZero() || now.Sub(b.CheckedAt) >= teamBillingEvery {
		return true
	}
	// An answer that entitled the team until a time now passed is asked
	// again then, not a day later: the team renewed, or it lapses.
	end := b.entitledUntil()
	return !end.IsZero() && !now.Before(end) && b.CheckedAt.Before(end)
}

// refreshTeamBilling asks fount-infra for team's billing and keeps the
// answer. A refusal is an answer: Billing says no_access. A failure to get
// one keeps the last answer and says why; it is also returned.
func (c *Coordinator) refreshTeamBilling(ctx context.Context, team string) (TeamBilling, error) {
	if c.cfg.TeamBilling == nil {
		return TeamBilling{}, ErrBillingOff
	}
	c.billing.one.Lock()
	defer c.billing.one.Unlock()
	ent, err := c.cfg.TeamBilling.Status(ctx, team)
	now := c.now().UTC()

	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.state.Teams[team]
	if !ok {
		return TeamBilling{}, ErrNoTeam
	}
	var next TeamBilling
	if t.Billing != nil {
		next = *t.Billing
	}
	var refused *TeamNotEntitled
	switch {
	case err == nil:
		next = TeamBilling{Status: ent.Status, Tier: ent.Tier, PeriodEnd: ent.PeriodEnd.UTC(), Seats: ent.Seats, CheckedAt: now, TriedAt: now, Subscription: ent.Subscription}
		if !ent.GraceEnds.IsZero() {
			next.GraceEnds = ent.GraceEnds.UTC()
		}
	case errors.As(err, &refused):
		next = TeamBilling{Status: BillingNoAccess, Reason: refused.Reason, CheckedAt: now, TriedAt: now, Subscription: refused.Subscription}
		err = nil
	default:
		next.TriedAt, next.Error = now, err.Error()
	}
	if err == nil && !next.Entitled(now) {
		next.Since = now
		if t.Billing != nil && !t.Billing.Since.IsZero() {
			next.Since = t.Billing.Since
		}
	}
	if err == nil {
		next.retire(t.Billing, now)
	}
	prev := t.Billing
	t.Billing = &next
	if serr := c.state.Save(c.cfg.StateDir); serr != nil {
		t.Billing = prev
		return TeamBilling{}, serr
	}
	if prev == nil || prev.Status != next.Status {
		log.Printf("team billing: a team's billing is now %q", next.Status)
	}
	// A team that pays again may have jobs waiting (admission.go).
	c.poke()
	return next, err
}

// BillingStatement signs a statement of kind for the caller's account in
// team: an admin's listed device gets an admin statement, any listed
// member's device a seat statement. Only a firm team has billing.
func (c *Coordinator) BillingStatement(caller Caller, team string, kind StatementKind) (TeamStatement, error) {
	if c.cfg.TeamBilling == nil {
		return TeamStatement{}, ErrBillingOff
	}
	if kind != StatementAdmin && kind != StatementSeat {
		return TeamStatement{}, fmt.Errorf("%w: kind is %q or %q", ErrInvalid, StatementAdmin, StatementSeat)
	}
	if !isFirmTeam(team) {
		return TeamStatement{}, ErrNoTeam
	}
	c.mu.Lock()
	m, st, err := c.requireMember(caller, team)
	if err == nil && st.deleted {
		err = ErrTeamDeleted
	}
	c.mu.Unlock()
	if err != nil {
		return TeamStatement{}, err
	}
	if kind == StatementAdmin && m.Role != RoleAdmin {
		return TeamStatement{}, fmt.Errorf("%w: only an admin's device gets an admin statement", ErrRole)
	}
	return c.cfg.TeamBilling.Statement(kind, team, m.Account)
}

// RefreshTeamBilling is a member asking for the team's billing now, at most
// once per TeamBillingRefreshGap per team.
func (c *Coordinator) RefreshTeamBilling(ctx context.Context, caller Caller, team string) (*TeamBillingView, error) {
	if c.cfg.TeamBilling == nil {
		return nil, ErrBillingOff
	}
	if !isFirmTeam(team) {
		return nil, ErrNoTeam
	}
	c.mu.Lock()
	_, st, err := c.requireMember(caller, team)
	if err == nil && st.deleted {
		err = ErrTeamDeleted
	}
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := c.claimRefresh(team, c.now()); err != nil {
		return nil, err
	}
	b, err := c.refreshTeamBilling(ctx, team)
	if err != nil {
		return nil, err
	}
	return billingView(&b, c.now()), nil
}

// teamBillingFor is team's billing for its members' view, nil for a solo
// account's team. Called with c.mu held.
func (c *Coordinator) teamBillingFor(team string) *TeamBillingView {
	if c.cfg.TeamBilling == nil || !isFirmTeam(team) {
		return nil
	}
	t := c.state.Teams[team]
	if t == nil {
		return nil
	}
	return billingView(t.Billing, c.now())
}

// billingStatement is POST /v1/teams/{team}/billing-statement {"kind":
// "admin"|"seat"}: {"statement", "expiresAt": unix s}.
func (a *api) billingStatement(rw http.ResponseWriter, r *http.Request) {
	var req struct {
		Kind StatementKind `json:"kind"`
	}
	if err := decodeStrict(r.Body, maxBillingBody, &req); err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	s, err := a.c.BillingStatement(*a.caller, r.PathValue("team"), req.Kind)
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusOK, map[string]any{"statement": s.Token, "expiresAt": s.ExpiresAt.Unix()})
}

// billingRefresh is POST /v1/teams/{team}/billing-refresh, no body: the
// team's billing, asked of fount-infra now.
func (a *api) billingRefresh(rw http.ResponseWriter, r *http.Request) {
	if err := decodeEmpty(r); err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	v, err := a.c.RefreshTeamBilling(r.Context(), *a.caller, r.PathValue("team"))
	var soon *RefreshTooSoonError
	switch {
	case errors.As(err, &soon):
		rw.Header().Set("Retry-After", strconv.Itoa(int(soon.RetryAfter.Seconds())+1))
		fail(rw, http.StatusTooManyRequests, err)
	case err != nil:
		status := statusOf(err)
		if status == http.StatusInternalServerError && !errors.Is(err, ErrBillingOff) {
			// fount-infra didn't answer: the last answer stands.
			status = http.StatusBadGateway
		}
		fail(rw, status, err)
	default:
		reply(rw, http.StatusOK, map[string]any{"billing": v})
	}
}

// decodeEmpty takes no body, or an empty JSON object.
func decodeEmpty(r *http.Request) error {
	data, err := io.ReadAll(io.LimitReader(r.Body, 64))
	if err != nil {
		return err
	}
	if body := strings.TrimSpace(string(data)); body != "" && body != "{}" {
		return errors.New("this route takes no body")
	}
	return nil
}
