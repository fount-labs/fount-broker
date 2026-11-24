package coordinator

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// An account with no plan of its own (an identity-only Cloud credential)
// writes nothing to its own solo team's log, list or record: the solo team is
// its own plan's.
func TestAnUnpaidAccountCantWriteItsSoloTeamsLog(t *testing.T) {
	f := newBillingFixture(t)
	eve := newTestDevice(t)
	tt := newTestTeam(t, f.c, "eve")
	tt.set("m_owner", "eve", RoleAdmin, eve)
	for i := range MaxMembers - 1 {
		tt.set(fmt.Sprintf("m_%02d", i), fmt.Sprintf("sock_%02d", i), RoleReviewer, newTestDevice(t))
	}
	l := tt.list()
	err := tt.pushList(eve.unpaid("eve"), eve.sign(t, l), l, nil)
	if !errors.Is(err, ErrNoPlan) || statusOf(err) != http.StatusPaymentRequired || errorCode(err) != codeNoPlan {
		t.Fatalf("a first list from an account with no plan: %v", err)
	}
	f.c.mu.Lock()
	_, made := f.c.state.Teams["eve"]
	f.c.mu.Unlock()
	if made {
		t.Fatal("the refused list made the team")
	}

	// With a plan it goes in; once the plan lapses, neither a list nor a
	// record does.
	if err := tt.push(eve, "eve", nil); err != nil {
		t.Fatalf("with a plan: %v", err)
	}
	tt.drop("m_00")
	l = tt.list()
	if err := tt.pushList(eve.unpaid("eve"), eve.sign(t, l), l, nil); !errors.Is(err, ErrNoPlan) {
		t.Fatalf("a list once the plan lapsed: %v", err)
	}
	rec := TeamRecord{Kind: RecordPasskeyVouch, Member: "m_owner", Account: "eve"}
	if _, err := f.c.appendRecord(eve.unpaid("eve"), "eve", rec, func(*teamState, *Member) error { return nil }); !errors.Is(err, ErrNoPlan) {
		t.Fatalf("a record once the plan lapsed: %v", err)
	}
	f.c.mu.Lock()
	n := len(f.c.state.Teams["eve"].Log)
	f.c.mu.Unlock()
	if n != 1 {
		t.Fatalf("log length %d", n)
	}
}

// An unpaid member of a firm team signs its lists whatever the team's
// billing says, so a lapsed team's admins still remove people.
func TestAnUnpaidAdminOfAFirmTeamStillSignsItsLists(t *testing.T) {
	f := newBillingFixture(t)
	f.pay(t, paid, nil)
	f.tt.update("m_maria", func(m *ListMember) { m.Email = "maria@example.com" })
	l := f.tt.list()
	if err := f.tt.pushList(f.admin.unpaid("acme"), f.admin.sign(t, l), l, nil); err != nil {
		t.Fatalf("an unpaid admin of a paying team: %v", err)
	}
	f.pay(t, TeamEntitlement{}, lapsedTeam)
	f.tt.drop("m_maria")
	l = f.tt.list()
	if err := f.tt.pushList(f.admin.unpaid("acme"), f.admin.sign(t, l), l, nil); err != nil {
		t.Fatalf("an unpaid admin removing a member of a lapsed team: %v", err)
	}
}

// With team billing off there is no team to pay for a caller: it needs its
// own plan on every route, the team's log and its lists included.
func TestWithBillingOffAnUnpaidCallerNeedsItsOwnPlanOnEveryRoute(t *testing.T) {
	f := newBillingFixture(t)
	f.c.cfg.TeamBilling = nil
	maria := f.reviewer.unpaid("maria")
	for _, r := range []struct{ method, path string }{
		{"GET", "/v1/teams"},
		{"GET", "/v1/teams/" + f.team + "/log"},
		{"POST", "/v1/teams/" + f.team + "/log"},
		{"POST", "/v1/teams/" + f.team + "/invites/i_1/open"},
		{"POST", "/v1/teams/" + f.team + "/invites/i_1/accept"},
		{"POST", "/v1/teams/" + f.team + "/passkey-join/challenge"},
		{"POST", "/v1/teams/" + f.team + "/passkey-join"},
		{"POST", "/v1/teams/" + f.team + "/passkey-vouch"},
		{"POST", "/v1/teams/" + f.team + "/recovery-start"},
	} {
		if status, code := call(t, f.c, maria, r.method, r.path); status != http.StatusPaymentRequired || code != codeNoPlan {
			t.Fatalf("%s %s with billing off and no plan: %d %q", r.method, r.path, status, code)
		}
	}
	if status, _ := call(t, f.c, f.reviewer.caller("maria"), "GET", "/v1/teams"); status != http.StatusOK {
		t.Fatalf("with a plan: %d", status)
	}
	f.tt.drop("m_maria")
	l := f.tt.list()
	if err := f.tt.pushList(f.admin.unpaid("acme"), f.admin.sign(t, l), l, nil); !errors.Is(err, ErrNoPlan) {
		t.Fatalf("a firm team's list with billing off and no plan: %v", err)
	}
	if err := f.tt.push(f.admin, "acme", nil); err != nil {
		t.Fatalf("with a plan: %v", err)
	}
}

// A paid account appends a burst, then one each accountLogEvery; past it,
// 429 with Retry-After.
func TestAnAccountsAppendsAreRateLimitedWithAPlan(t *testing.T) {
	f := newBillingFixture(t)
	solo := soloTeam(t, f.c, "solo", f.stranger)
	for i := 1; i < accountLogBurst; i++ {
		solo.update("m_owner", func(m *ListMember) { m.Email = fmt.Sprintf("x%d@example.com", i) })
		if err := solo.push(f.stranger, "solo", nil); err != nil {
			t.Fatalf("list %d inside the burst: %v", i, err)
		}
	}
	solo.update("m_owner", func(m *ListMember) { m.Email = "over@example.com" })
	err := solo.push(f.stranger, "solo", nil)
	var limit *TeamLogLimitError
	if !errors.As(err, &limit) || limit.RetryAfter != accountLogEvery || statusOf(err) != http.StatusTooManyRequests || errorCode(err) != codeTeamLogRate {
		t.Fatalf("past the burst: %v", err)
	}
	rw := httptest.NewRecorder()
	fail(rw, statusOf(err), err)
	if rw.Code != http.StatusTooManyRequests || rw.Header().Get("Retry-After") != "30" || !strings.Contains(rw.Body.String(), codeTeamLogRate) {
		t.Fatalf("the answer: %d %q %s", rw.Code, rw.Header().Get("Retry-After"), rw.Body)
	}
	// Another account's appends don't wait.
	f.tt.drop("m_maria")
	if err := f.tt.push(f.admin, "acme", nil); err != nil {
		t.Fatalf("another account: %v", err)
	}
	f.advance(accountLogEvery)
	if err := solo.push(f.stranger, "solo", nil); err != nil {
		t.Fatalf("after Retry-After: %v", err)
	}
	if err := solo.push(f.stranger, "solo", nil); !errors.As(err, &limit) {
		t.Fatalf("the next at once: %v", err)
	}
}

// A team appends a burst, then one each teamLogEvery, however many of its
// accounts append.
func TestATeamsAppendsAreRateLimitedAcrossItsAccounts(t *testing.T) {
	f := newBillingFixture(t)
	f.c.mu.Lock()
	// The fixture's first list took one.
	for i := range teamLogBurst - 1 {
		f.c.tookTeamLog(Caller{Account: fmt.Sprintf("acct_%d", i)}, f.team, f.now)
	}
	f.c.mu.Unlock()
	f.tt.drop("m_maria")
	err := f.tt.push(f.admin, "acme", nil)
	var limit *TeamLogLimitError
	if !errors.As(err, &limit) || limit.RetryAfter != teamLogEvery {
		t.Fatalf("past the team's burst: %v", err)
	}
	f.advance(teamLogEvery)
	if err := f.tt.push(f.admin, "acme", nil); err != nil {
		t.Fatalf("after Retry-After: %v", err)
	}
}

// A full log takes nothing more, plan or not, save the list that deletes
// the team; no wait opens it, so the answer has no Retry-After.
func TestAFullTeamLogTakesOnlyItsDeletion(t *testing.T) {
	f := newBillingFixture(t)
	payer := f.admin.caller("acme")
	for _, log := range [][]TeamEntry{
		make([]TeamEntry, teamLogMaxEntries),
		{{List: strings.Repeat("x", teamLogMaxBytes-100)}},
	} {
		f.c.mu.Lock()
		f.c.state.Teams["full"] = &Team{ID: "full", Log: log}
		err := f.c.teamLogRoom(payer, "full", 200, false, f.now)
		ends := f.c.teamLogRoom(payer, "full", 200, true, f.now)
		delete(f.c.state.Teams, "full")
		f.c.mu.Unlock()
		var limit *TeamLogLimitError
		if !errors.As(err, &limit) || limit.RetryAfter != 0 || statusOf(err) != http.StatusTooManyRequests || errorCode(err) != codeTeamLogFull {
			t.Fatalf("an entry on a full log: %v", err)
		}
		rw := httptest.NewRecorder()
		fail(rw, statusOf(err), err)
		if rw.Header().Get("Retry-After") != "" {
			t.Fatalf("a full log's Retry-After: %q", rw.Header().Get("Retry-After"))
		}
		if ends != nil {
			t.Fatalf("the team's deletion on a full log: %v", ends)
		}
	}
}

// Rates that have refilled are dropped once there are many.
func TestTeamLogRatesForgetRefilledKeys(t *testing.T) {
	keys := map[string]time.Time{}
	now := time.Unix(1_800_000_000, 0)
	for i := range teamLogRatePrune {
		rateTake(keys, fmt.Sprintf("k%d", i), now, time.Second)
	}
	rateTake(keys, "late", now.Add(time.Hour), time.Second)
	if len(keys) != 1 {
		t.Fatalf("%d keys kept", len(keys))
	}
	if rateWait(keys, "late", now.Add(time.Hour), time.Second, 2) != 0 || rateWait(keys, "late", now.Add(time.Hour), time.Second, 1) != time.Second {
		t.Fatal("the kept key's wait")
	}
}
