package coordinator

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakeBiller signs nothing real: a statement's token names what it says.
type fakeBiller struct {
	mu     sync.Mutex
	answer TeamEntitlement
	err    error
	asked  []string
}

func (f *fakeBiller) Statement(kind StatementKind, team, account string) (TeamStatement, error) {
	return TeamStatement{Token: string(kind) + "|" + team + "|" + account, ExpiresAt: time.Unix(1_800_000_300, 0)}, nil
}

func (f *fakeBiller) Status(_ context.Context, team string) (TeamEntitlement, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, team)
	return f.answer, f.err
}

func (f *fakeBiller) set(answer TeamEntitlement, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answer, f.err = answer, err
}

func (f *fakeBiller) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.asked)
}

// A firm team with an admin and a reviewer, and a stranger's device.
type billingFixture struct {
	c                         *Coordinator
	biller                    *fakeBiller
	team                      string
	admin, reviewer, stranger testDevice
	now                       time.Time
}

func newBillingFixture(t *testing.T) *billingFixture {
	t.Helper()
	c, _ := newTestCoordinator(t, "ok", 0)
	f := &billingFixture{c: c, biller: &fakeBiller{}, admin: newTestDevice(t), reviewer: newTestDevice(t), stranger: newTestDevice(t), now: time.Now().UTC().Truncate(time.Second)}
	c.cfg.TeamBilling = f.biller
	c.clock = func() time.Time { return f.now }
	var err error
	if f.team, err = c.MintTeam(f.admin.caller("acme")); err != nil {
		t.Fatal(err)
	}
	tt := newTestTeam(t, c, f.team)
	tt.set("m_owner", "acme", RoleAdmin, f.admin)
	tt.set("m_maria", "maria", RoleReviewer, f.reviewer)
	if err := tt.push(f.admin, "acme", nil); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *billingFixture) api(t *testing.T, d testDevice, account string) *httptest.Server {
	srv := httptest.NewServer(f.c.AccountHandler(d.caller(account)))
	t.Cleanup(srv.Close)
	return srv
}

func (f *billingFixture) billing(t *testing.T) *TeamBilling {
	t.Helper()
	f.c.mu.Lock()
	defer f.c.mu.Unlock()
	b := f.c.state.Teams[f.team].Billing
	if b == nil {
		return nil
	}
	cp := *b
	return &cp
}

var paid = TeamEntitlement{Status: "active", Tier: "team", PeriodEnd: time.Unix(1_900_000_000, 0).UTC(), Seats: 5}

func TestOnlyAnAdminsDeviceGetsAnAdminStatement(t *testing.T) {
	f := newBillingFixture(t)
	path := "/v1/teams/" + f.team + "/billing-statement"

	code, out := do(t, f.api(t, f.admin, "acme"), "POST", path, `{"kind":"admin"}`)
	if code != 200 || out["statement"] != "admin|"+f.team+"|acme" || out["expiresAt"] != float64(1_800_000_300) {
		t.Fatalf("the admin's statement: %d %v", code, out)
	}
	reviewer := f.api(t, f.reviewer, "maria")
	if code, out := do(t, reviewer, "POST", path, `{"kind":"admin"}`); code != 403 || out["statement"] != nil {
		t.Fatalf("a reviewer's admin statement: %d %v", code, out)
	}
	// A seat statement names the member's own account.
	if code, out := do(t, reviewer, "POST", path, `{"kind":"seat"}`); code != 200 || out["statement"] != "seat|"+f.team+"|maria" {
		t.Fatalf("a reviewer's seat statement: %d %v", code, out)
	}
	if code, _ := do(t, f.api(t, f.admin, "acme"), "POST", path, `{"kind":"seat"}`); code != 200 {
		t.Fatalf("an admin's seat statement: %d", code)
	}

	// A device the team doesn't list, under a member's account or not.
	for _, srv := range []*httptest.Server{f.api(t, f.stranger, "maria"), f.api(t, f.stranger, "globex")} {
		if code, out := do(t, srv, "POST", path, `{"kind":"seat"}`); code != 404 || out["statement"] != nil {
			t.Errorf("an unlisted device's statement: %d %v", code, out)
		}
	}
	// A listed device under another account.
	if code, _ := do(t, f.api(t, f.reviewer, "acme"), "POST", path, `{"kind":"admin"}`); code != 404 {
		t.Errorf("a reviewer's device as the admin's account: %d", code)
	}
	for _, body := range []string{`{"kind":"owner"}`, `{}`, `{"kind":"admin","acct":"globex"}`} {
		if code, _ := do(t, f.api(t, f.admin, "acme"), "POST", path, body); code != 400 {
			t.Errorf("%s: %d", body, code)
		}
	}
}

func TestASoloTeamHasNoBilling(t *testing.T) {
	f := newBillingFixture(t)
	me := newTestDevice(t)
	soloTeam(t, f.c, "solo", me)
	srv := f.api(t, me, "solo")
	if code, _ := do(t, srv, "POST", "/v1/teams/solo/billing-statement", `{"kind":"admin"}`); code != 404 {
		t.Errorf("a solo team's statement: %d", code)
	}
	if code, _ := do(t, srv, "POST", "/v1/teams/solo/billing-refresh", ""); code != 404 {
		t.Errorf("a solo team's refresh: %d", code)
	}
	_, out := do(t, srv, "GET", "/v1/teams", "")
	if b := out["teams"].([]any)[0].(map[string]any)["billing"]; b != nil {
		t.Errorf("a solo team's billing: %v", b)
	}
	f.c.pollTeamBilling(context.Background(), f.now)
	for _, team := range f.biller.asked {
		if team == "solo" {
			t.Error("fount-infra was asked for a solo team")
		}
	}
}

func TestBillingIsOffWithoutABiller(t *testing.T) {
	f := newBillingFixture(t)
	f.c.cfg.TeamBilling = nil
	srv := f.api(t, f.admin, "acme")
	if code, _ := do(t, srv, "POST", "/v1/teams/"+f.team+"/billing-statement", `{"kind":"admin"}`); code != 501 {
		t.Errorf("a statement: %d", code)
	}
	if code, _ := do(t, srv, "POST", "/v1/teams/"+f.team+"/billing-refresh", ""); code != 501 {
		t.Errorf("a refresh: %d", code)
	}
	_, out := do(t, srv, "GET", "/v1/teams", "")
	if b := out["teams"].([]any)[0].(map[string]any)["billing"]; b != nil {
		t.Errorf("billing without a biller: %v", b)
	}
}

func TestAMemberRefreshesTheTeamsBilling(t *testing.T) {
	f := newBillingFixture(t)
	reviewer := f.api(t, f.reviewer, "maria")
	path := "/v1/teams/" + f.team + "/billing-refresh"

	// Never asked: the view says so.
	_, out := do(t, reviewer, "GET", "/v1/teams", "")
	if b := out["teams"].([]any)[0].(map[string]any)["billing"].(map[string]any); b["entitled"] != false || b["status"] != nil {
		t.Fatalf("billing before any answer: %v", b)
	}

	f.biller.set(paid, nil)
	code, out := do(t, reviewer, "POST", path, "")
	if code != 200 {
		t.Fatalf("refresh: %d %v", code, out)
	}
	b := out["billing"].(map[string]any)
	if b["status"] != "active" || b["seats"] != float64(5) || b["tier"] != "team" || b["entitled"] != true || b["periodEnd"] != "2030-03-17T17:46:40Z" {
		t.Fatalf("billing after a refresh: %v", b)
	}
	_, out = do(t, f.api(t, f.admin, "acme"), "GET", "/v1/teams", "")
	if b := out["teams"].([]any)[0].(map[string]any)["billing"].(map[string]any); b["entitled"] != true || b["seats"] != float64(5) {
		t.Fatalf("the team view: %v", b)
	}

	// Once a minute per team.
	if code, _ := do(t, f.api(t, f.admin, "acme"), "POST", path, ""); code != 429 {
		t.Fatalf("a second refresh at once: %d", code)
	}
	if f.biller.count() != 1 {
		t.Fatalf("fount-infra was asked %d times", f.biller.count())
	}

	// A 403 is an answer: not entitled, with the reason.
	f.now = f.now.Add(TeamBillingRefreshGap)
	f.biller.set(TeamEntitlement{}, &TeamNotEntitled{Reason: "canceled"})
	code, out = do(t, reviewer, "POST", path, "")
	if b := out["billing"].(map[string]any); code != 200 || b["status"] != BillingNoAccess || b["reason"] != "canceled" || b["entitled"] != false || b["seats"] != nil {
		t.Fatalf("a refused refresh: %d %v", code, out)
	}

	// No answer keeps the last one, and says why.
	f.now = f.now.Add(TeamBillingRefreshGap)
	f.biller.set(paid, nil)
	do(t, reviewer, "POST", path, "")
	f.now = f.now.Add(TeamBillingRefreshGap)
	f.biller.set(TeamEntitlement{}, errors.New("fount-infra answered 500"))
	if code, _ := do(t, reviewer, "POST", path, ""); code != 502 {
		t.Fatalf("a failed refresh: %d", code)
	}
	if b := f.billing(t); b.Status != "active" || b.Error == "" || !b.Entitled(f.now) || b.TriedAt.Equal(b.CheckedAt) {
		t.Fatalf("billing after a failure: %+v", b)
	}

	// Only members ask.
	if code, _ := do(t, f.api(t, f.stranger, "globex"), "POST", path, ""); code != 404 {
		t.Errorf("a stranger's refresh: %d", code)
	}
	if code, _ := do(t, reviewer, "POST", path, `{"x":1}`); code != 400 {
		t.Errorf("a refresh with a body: %d", code)
	}
}

func TestBillingIsKeptAcrossARestart(t *testing.T) {
	f := newBillingFixture(t)
	f.biller.set(paid, nil)
	if _, err := f.c.refreshTeamBilling(context.Background(), f.team); err != nil {
		t.Fatal(err)
	}
	c2, err := New(f.c.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if b := c2.state.Teams[f.team].Billing; b == nil || b.Seats != 5 || b.Status != "active" {
		t.Fatalf("billing after a restart: %+v", b)
	}
}

func TestTheLoopAsksDailyAndAfterALapseStep(t *testing.T) {
	f := newBillingFixture(t)
	f.biller.set(paid, nil)
	ctx := context.Background()
	poll := func(after time.Duration) int {
		f.now = f.now.Add(after)
		f.c.pollTeamBilling(ctx, f.now)
		return f.biller.count()
	}

	if n := poll(0); n != 1 {
		t.Fatalf("the first poll asked %d times", n)
	}
	if poll(time.Hour) != 1 {
		t.Fatal("asked again within the day")
	}
	if poll(teamBillingEvery) != 2 {
		t.Fatal("not asked again after a day")
	}

	// A worker of the team takes a lapse step: asked at once, once a minute.
	f.c.teamBillingSoon(f.team)
	f.c.teamBillingSoon(f.team)
	if n := poll(time.Second); n != 3 {
		t.Fatalf("after a lapse step: asked %d times", n)
	}
	if poll(time.Second) != 3 {
		t.Fatal("a lapse step was asked twice")
	}
	// A lapse step doesn't hold up a member's refresh.
	if _, err := f.c.RefreshTeamBilling(ctx, f.reviewer.caller("maria"), f.team); err != nil {
		t.Fatalf("a member's refresh after a lapse step: %v", err)
	}

	// A failure is tried again after an hour.
	f.biller.set(TeamEntitlement{}, errors.New("down"))
	n := poll(teamBillingEvery)
	if poll(time.Minute) != n {
		t.Fatal("a failure was tried again at once")
	}
	if poll(teamBillingRetry) != n+1 {
		t.Fatal("a failure wasn't tried again after an hour")
	}
}

func TestEntitled(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, tc := range []struct {
		name string
		b    *TeamBilling
		want bool
	}{
		{"never asked", nil, false},
		{"no answer yet", &TeamBilling{}, false},
		{"active", &TeamBilling{Status: "active", PeriodEnd: now.Add(time.Hour)}, true},
		{"active past its period", &TeamBilling{Status: "active", PeriodEnd: now}, false},
		{"past_due in grace", &TeamBilling{Status: "past_due", PeriodEnd: now.Add(time.Hour), GraceEnds: now.Add(time.Hour)}, true},
		{"past_due after grace", &TeamBilling{Status: "past_due", PeriodEnd: now.Add(-time.Hour), GraceEnds: now.Add(-time.Hour)}, false},
		{"refused", &TeamBilling{Status: BillingNoAccess, Reason: "period_ended"}, false},
	} {
		if got := tc.b.Entitled(now); got != tc.want {
			t.Errorf("%s: %v", tc.name, got)
		}
	}
}
