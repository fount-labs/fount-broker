package coordinator

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"
)

// renewalFixture is a billing fixture with a worker, paid until an hour from
// now: end.
func renewalFixture(t *testing.T) (*billingFixture, Worker, time.Time) {
	t.Helper()
	f := newBillingFixture(t)
	w, err := f.tt.addWorker(f.admin, "acme", DEK{1})
	if err != nil {
		t.Fatal(err)
	}
	end := f.now.Add(time.Hour)
	a := paid
	a.PeriodEnd = end
	f.pay(t, a, nil)
	return f, w, end
}

func (f *billingFixture) at(at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = at
}

func (f *billingFixture) payment() teamPay {
	f.c.mu.Lock()
	defer f.c.mu.Unlock()
	return f.c.teamPayment(f.team, f.c.now())
}

func (f *billingFixture) seats() int {
	f.c.mu.Lock()
	defer f.c.mu.Unlock()
	return f.c.teamSeats(f.team, f.c.now())
}

// The review's TestReviewARenewalRaceLeavesAPayingTeamUnpaidForADay, flipped:
// fount-infra answers period_ended until the renewal's invoice is paid, and
// the team stays paid through it.
func TestARenewalRaceLeavesAPayingTeamPaid(t *testing.T) {
	f, w, end := renewalFixture(t)
	maria := f.reviewer.unpaid("maria")
	ctx := context.Background()

	// The period ends; the loop hasn't asked yet.
	f.at(end.Add(time.Minute))
	if p := f.payment(); p != teamPaid {
		t.Fatalf("at the period end, before an answer: %v", p)
	}
	// Stripe's renewal invoice is paid about an hour later, so fount-infra's
	// row still says the old period.
	f.biller.set(TeamEntitlement{}, &TeamNotEntitled{Reason: "period_ended"})
	before := f.biller.count()
	f.c.pollTeamBilling(ctx, f.c.now())
	if f.biller.count() != before+1 {
		t.Fatal("not asked at the period end")
	}
	b := f.billing(t)
	if b.Status != BillingRenewing || !b.GraceEnds.Equal(end.Add(teamRenewGrace)) || b.Seats != 5 || !b.Since.IsZero() {
		t.Fatalf("billing while renewing: %+v", b)
	}
	if p, n := f.payment(), f.seats(); p != teamPaid || n != 5 {
		t.Fatalf("renewing: pay %v, seats %d", p, n)
	}
	if status, _ := call(t, f.c, maria, "GET", "/v1/workers/"+w.ID); status != http.StatusOK {
		t.Fatalf("the unpaid reviewer got %d while renewing", status)
	}

	// Asked again every teamRenewingEvery, not a day later.
	asked := f.biller.count()
	f.advance(teamRenewingEvery - time.Second)
	f.c.pollTeamBilling(ctx, f.c.now())
	if f.biller.count() != asked {
		t.Fatal("asked again within teamRenewingEvery")
	}
	f.advance(time.Second)
	f.c.pollTeamBilling(ctx, f.c.now())
	if f.biller.count() != asked+1 {
		t.Fatal("not asked again after teamRenewingEvery")
	}
	if !f.billing(t).GraceEnds.Equal(end.Add(teamRenewGrace)) {
		t.Fatal("a second period_ended moved the grace")
	}

	// The renewal lands.
	renewed := paid
	renewed.PeriodEnd = end.Add(30 * 24 * time.Hour)
	f.biller.set(renewed, nil)
	f.advance(teamRenewingEvery)
	f.c.pollTeamBilling(ctx, f.c.now())
	if b := f.billing(t); b.Status != "active" || !b.PeriodEnd.Equal(renewed.PeriodEnd) || !b.Since.IsZero() {
		t.Fatalf("after the renewal: %+v", b)
	}
	for _, after := range []time.Duration{time.Hour, 6 * time.Hour, 23 * time.Hour} {
		f.at(end.Add(5 * time.Minute).Add(after))
		asked := f.biller.count()
		f.c.pollTeamBilling(ctx, f.c.now())
		if f.biller.count() != asked || f.payment() != teamPaid {
			t.Fatalf("%s after the renewal: asked again %v, pay %v", after, f.biller.count() != asked, f.payment())
		}
		if status, _ := call(t, f.c, maria, "GET", "/v1/workers/"+w.ID); status != http.StatusOK {
			t.Fatalf("%s after: the unpaid reviewer got %d", after, status)
		}
	}
}

func TestARealEndAtTheRenewalIsntRenewing(t *testing.T) {
	for _, reason := range []string{"canceled", "past_due", "no_subscription", "no_cloud_plan"} {
		t.Run(reason, func(t *testing.T) {
			f, _, end := renewalFixture(t)
			f.at(end.Add(time.Minute))
			f.pay(t, TeamEntitlement{}, &TeamNotEntitled{Reason: reason})
			if b := f.billing(t); b.Status != BillingNoAccess || b.Since.IsZero() {
				t.Fatalf("billing: %+v", b)
			}
			if p, n := f.payment(), f.seats(); p != teamUnpaid || n != 1 {
				t.Fatalf("pay %v, seats %d", p, n)
			}
		})
	}
}

func TestAPeriodEndedWithoutAnActiveAnswerIsntRenewing(t *testing.T) {
	f := newBillingFixture(t)
	// A team that never paid, and one past_due when its period ended.
	f.pay(t, TeamEntitlement{}, lapsedTeam)
	if p := f.payment(); p != teamUnpaid {
		t.Fatalf("never paid: %v", p)
	}
	due := paid
	due.Status, due.PeriodEnd, due.GraceEnds = "past_due", f.now.Add(time.Hour), f.now.Add(time.Hour)
	f.pay(t, due, nil)
	f.advance(time.Hour + time.Minute)
	f.pay(t, TeamEntitlement{}, lapsedTeam)
	if p := f.payment(); p != teamUnpaid {
		t.Fatalf("past_due, then period_ended: %v", p)
	}
}

func TestARenewalsGraceEnds(t *testing.T) {
	f, _, end := renewalFixture(t)
	ctx := context.Background()
	f.biller.set(TeamEntitlement{}, lapsedTeam)
	f.at(end)
	f.c.pollTeamBilling(ctx, f.c.now())
	if f.billing(t).Status != BillingRenewing {
		t.Fatalf("at the period end: %+v", f.billing(t))
	}
	f.at(end.Add(teamRenewGrace - time.Second))
	f.c.pollTeamBilling(ctx, f.c.now())
	if p := f.payment(); p != teamPaid {
		t.Fatalf("a second before the grace ends: %v", p)
	}
	// The grace ends: asked then, and the answer is a lapse.
	f.at(end.Add(teamRenewGrace))
	if !billingDue(f.billing(t), f.c.now()) {
		t.Fatal("not due at the end of the grace")
	}
	f.c.pollTeamBilling(ctx, f.c.now())
	b := f.billing(t)
	if b.Status != BillingNoAccess || b.Reason != "period_ended" || !b.Since.Equal(f.c.now()) {
		t.Fatalf("after the grace: %+v", b)
	}
	if p, n := f.payment(), f.seats(); p != teamUnpaid || n != 1 {
		t.Fatalf("after the grace: pay %v, seats %d", p, n)
	}
}

func TestARenewingAnswerFromFountInfra(t *testing.T) {
	f, _, end := renewalFixture(t)
	f.at(end.Add(time.Minute))
	f.pay(t, TeamEntitlement{Status: BillingRenewing, Tier: "team", PeriodEnd: end, Seats: 4}, nil)
	b := f.billing(t)
	if b.Status != BillingRenewing || !b.GraceEnds.Equal(end.Add(teamRenewGrace)) || b.Seats != 4 {
		t.Fatalf("billing: %+v", b)
	}
	if p := f.payment(); p != teamPaid {
		t.Fatalf("pay %v", p)
	}
	f.at(end.Add(teamRenewGrace))
	if p := f.payment(); p != teamUnpaid {
		t.Fatalf("past the grace: %v", p)
	}
}

func TestFountInfraDownDuringARenewal(t *testing.T) {
	f, _, end := renewalFixture(t)
	ctx := context.Background()
	f.biller.set(TeamEntitlement{}, errors.New("fount-infra is down"))
	f.at(end)
	f.c.pollTeamBilling(ctx, f.c.now())
	if p := f.payment(); p != teamPaid {
		t.Fatalf("down at the period end: %v", p)
	}
	// Tried again every teamRenewingEvery, not hourly.
	asked := f.biller.count()
	f.advance(teamRenewingEvery)
	f.c.pollTeamBilling(ctx, f.c.now())
	if f.biller.count() != asked+1 {
		t.Fatal("a failure during the renewal wasn't tried again within teamRenewingEvery")
	}
	// Still down when the grace ends: unknown, not lapsed.
	f.at(end.Add(teamRenewGrace))
	if p := f.payment(); p != teamPayUnknown {
		t.Fatalf("down past the grace: %v", p)
	}
}

func TestARenewalNeverLapsesOrNotifies(t *testing.T) {
	ents, owner, biller := &standing{}, &notices{}, &fakeBiller{}
	r := genRig(t, MailConfig{Entitlements: ents, Notices: owner})
	r.c.cfg.TeamBilling = biller
	team := runnerTeam
	_, mb := r.teamWorker(team, "ap@fountbox.com")
	var mu sync.Mutex
	now := time.Now().UTC().Truncate(time.Second)
	r.c.setClock(func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	})
	set := func(at time.Time) {
		mu.Lock()
		defer mu.Unlock()
		now = at
	}
	sweep := func() {
		t.Helper()
		r.c.mail.mu.Lock()
		r.c.mail.lastSweep = time.Time{}
		r.c.mail.mu.Unlock()
		r.c.mailPass(context.Background(), r.c.now())
	}
	refresh := func(answer TeamEntitlement, err error) {
		t.Helper()
		biller.set(answer, err)
		if _, err := r.c.refreshTeamBilling(context.Background(), team); err != nil {
			t.Fatal(err)
		}
	}
	lapsed := func() bool { return r.edge.coord.Mailbox(mb.MailboxID).Lapsed }

	end := now.Add(time.Hour)
	a := paid
	a.PeriodEnd = end
	refresh(a, nil)
	sweep()

	// The period ends, and is swept before fount-infra is asked; then
	// asked, it says period_ended; then the renewal lands.
	set(end.Add(time.Minute))
	sweep()
	set(end.Add(2 * time.Minute))
	refresh(TeamEntitlement{}, lapsedTeam)
	sweep()
	set(end.Add(time.Hour))
	refresh(TeamEntitlement{}, lapsedTeam)
	sweep()
	if lapsed() || len(owner.kinds()) != 0 {
		t.Fatalf("renewing: lapsed %v, notices %v", lapsed(), owner.kinds())
	}
	renewed := paid
	renewed.PeriodEnd = end.Add(30 * 24 * time.Hour)
	refresh(renewed, nil)
	set(end.Add(2 * time.Hour))
	sweep()
	if lapsed() || len(owner.kinds()) != 0 {
		t.Fatalf("renewed: lapsed %v, notices %v", lapsed(), owner.kinds())
	}

	// The next period ends with no renewal: the grace ends and it lapses.
	end = renewed.PeriodEnd
	set(end.Add(time.Minute))
	refresh(TeamEntitlement{}, lapsedTeam)
	sweep()
	if lapsed() {
		t.Fatal("lapsed inside the grace")
	}
	set(end.Add(teamRenewGrace))
	refresh(TeamEntitlement{}, lapsedTeam)
	sweep()
	// The fake edge holds from the real clock, a month back, so the hold's
	// own notices follow.
	if k := owner.kinds(); !lapsed() || len(k) == 0 || k[0] != NoticeLapsed {
		t.Fatalf("after the grace: lapsed %v, notices %v", lapsed(), k)
	}
}

func TestACancelAtTheRenewalLapsesAtOnce(t *testing.T) {
	ents, owner, biller := &standing{}, &notices{}, &fakeBiller{}
	r := genRig(t, MailConfig{Entitlements: ents, Notices: owner})
	r.c.cfg.TeamBilling = biller
	_, mb := r.teamWorker(runnerTeam, "ap@fountbox.com")
	end := time.Now().Add(-time.Minute)
	r.c.mu.Lock()
	r.c.state.Teams[runnerTeam].Billing = &TeamBilling{Status: "active", Tier: "team", PeriodEnd: end, Seats: 5, CheckedAt: end.Add(-time.Hour), TriedAt: end.Add(-time.Hour)}
	r.c.mu.Unlock()
	biller.set(TeamEntitlement{}, &TeamNotEntitled{Reason: "canceled"})
	if _, err := r.c.refreshTeamBilling(context.Background(), runnerTeam); err != nil {
		t.Fatal(err)
	}
	r.c.mailPass(context.Background(), time.Now())
	if !r.edge.coord.Mailbox(mb.MailboxID).Lapsed || len(owner.kinds()) != 1 || owner.kinds()[0] != NoticeLapsed {
		t.Fatalf("canceled at the renewal: notices %v", owner.kinds())
	}
}

func TestEntitledWhileRenewing(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	end := now.Add(-time.Hour)
	for _, tc := range []struct {
		name string
		b    *TeamBilling
		want bool
	}{
		{"active past its period, not asked since", &TeamBilling{Status: "active", PeriodEnd: end, CheckedAt: end.Add(-time.Hour)}, true},
		{"active, answered just past its period", &TeamBilling{Status: "active", PeriodEnd: end, CheckedAt: end.Add(time.Second)}, true},
		{"active past its period and the grace", &TeamBilling{Status: "active", PeriodEnd: now.Add(-teamRenewGrace), CheckedAt: end.Add(-teamRenewGrace)}, false},
		{"active past its period, never answered", &TeamBilling{Status: "active", PeriodEnd: end}, false},
		{"renewing in its grace", &TeamBilling{Status: BillingRenewing, PeriodEnd: end, GraceEnds: end.Add(teamRenewGrace), CheckedAt: now}, true},
		{"renewing past its grace", &TeamBilling{Status: BillingRenewing, PeriodEnd: end, GraceEnds: now, CheckedAt: now}, false},
		{"past_due past its period", &TeamBilling{Status: "past_due", PeriodEnd: end, GraceEnds: end, CheckedAt: end.Add(-time.Hour)}, false},
	} {
		if got := tc.b.Entitled(now); got != tc.want {
			t.Errorf("%s: %v", tc.name, got)
		}
	}
}

// fount-infra's clock a little behind the coordinator's: active, with the
// period that just ended, after it ended. The team stays paid, renewing, and
// is asked again every teamRenewingEvery, not a day later.
func TestAnActiveAnswerJustPastThePeriodEndIsRenewing(t *testing.T) {
	f, w, end := renewalFixture(t)
	maria := f.reviewer.unpaid("maria")
	f.at(end.Add(30 * time.Second))
	late := paid
	late.PeriodEnd = end
	f.pay(t, late, nil)
	if b := f.billing(t); b.Status != "active" || !b.Since.IsZero() {
		t.Fatalf("billing: %+v", b)
	}
	if p, n := f.payment(), f.seats(); p != teamPaid || n != 5 {
		t.Fatalf("pay %v, seats %d", p, n)
	}
	if status, _ := call(t, f.c, maria, "GET", "/v1/workers/"+w.ID); status != http.StatusOK {
		t.Fatalf("the unpaid reviewer got %d", status)
	}
	f.advance(teamRenewingEvery - time.Second)
	if billingDue(f.billing(t), f.c.now()) {
		t.Fatal("due within teamRenewingEvery")
	}
	f.advance(time.Second)
	if !billingDue(f.billing(t), f.c.now()) {
		t.Fatal("not due after teamRenewingEvery")
	}
	f.at(end.Add(teamRenewGrace))
	if p := f.payment(); p != teamUnpaid {
		t.Fatalf("past the grace: %v", p)
	}
}
