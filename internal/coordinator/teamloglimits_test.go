package coordinator

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
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

// The logs of the teams an account made share accountLogMaxBytes: past it,
// none of them takes an entry but its deletion, 429 account_log_full with no
// Retry-After, while another account's teams go on.
func TestTheTeamsAnAccountMadeShareOneBudget(t *testing.T) {
	f := newBillingFixture(t)
	f.c.mu.Lock()
	for i := range accountLogMaxBytes / teamLogMaxBytes {
		id := fmt.Sprintf("tm_%024x", 0xf000+i)
		f.c.state.Teams[id] = &Team{ID: id, Owner: "acme", Log: []TeamEntry{{List: strings.Repeat("x", teamLogMaxBytes-100)}}}
	}
	f.c.mu.Unlock()
	f.tt.drop("m_maria")
	err := f.tt.push(f.admin, "acme", nil)
	var limit *TeamLogLimitError
	if !errors.As(err, &limit) || !limit.Account || limit.RetryAfter != 0 || statusOf(err) != http.StatusTooManyRequests || errorCode(err) != codeAccountLogFull {
		t.Fatalf("an entry past the account's budget: %v", err)
	}
	rw := httptest.NewRecorder()
	fail(rw, statusOf(err), err)
	if rw.Header().Get("Retry-After") != "" || !strings.Contains(rw.Body.String(), codeAccountLogFull) {
		t.Fatalf("the answer: %q %s", rw.Header().Get("Retry-After"), rw.Body)
	}
	// Another account's own team goes on.
	soloTeam(t, f.c, "solo", f.stranger)
	// The deletion still goes in.
	end := deleteList(f.tt)
	if err := f.tt.pushList(f.admin.caller("acme"), f.admin.sign(t, end), end, nil); err != nil {
		t.Fatalf("the team's deletion past the budget: %v", err)
	}
}

// A team's owner is kept in the state, so the budget and the count of teams
// hold across a restart; a team made before it was kept is its first list's
// signer's.
func TestATeamsOwnerIsKeptAndFoundForAnOlderTeam(t *testing.T) {
	f := newBillingFixture(t)
	f.c.mu.Lock()
	defer f.c.mu.Unlock()
	if owner := f.c.state.Teams[f.team].Owner; owner != "acme" {
		t.Fatalf("the firm team's owner: %q", owner)
	}
	dir := t.TempDir()
	if err := f.c.state.Save(dir); err != nil {
		t.Fatal(err)
	}
	st, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Teams[f.team].Owner != "acme" {
		t.Fatalf("the owner after a restart: %q", st.Teams[f.team].Owner)
	}
	f.c.state.Teams[f.team].Owner = ""
	if owner := f.c.teamOwner(f.team); owner != "acme" || f.c.state.Teams[f.team].Owner != "acme" {
		t.Fatalf("an older team's owner: %q", owner)
	}
	if f.c.firmTeamsOf("acme") != 1 || f.c.firmTeamsOf("maria") != 0 {
		t.Fatal("the count of teams an account made")
	}
}

// An account makes maxTeamsPerAccount firm teams, deleted ones included;
// then MintTeam is 429 team_limit. The id it holds unused is still its.
func TestAnAccountMakesAtMostItsFirmTeams(t *testing.T) {
	f := newBillingFixture(t)
	held, err := f.c.MintTeam(f.admin.caller("acme"))
	if err != nil {
		t.Fatal(err)
	}
	f.c.mu.Lock()
	for i := 1; i < maxTeamsPerAccount; i++ {
		id := fmt.Sprintf("tm_%024x", 0xa000+i)
		f.c.state.Teams[id] = &Team{ID: id, Owner: "acme"}
	}
	f.c.mu.Unlock()
	if again, err := f.c.MintTeam(f.admin.caller("acme")); err != nil || again != held {
		t.Fatalf("the held id at the limit: %q %v", again, err)
	}
	f.c.mu.Lock()
	delete(f.c.state.TeamMints, held)
	f.c.mu.Unlock()
	_, err = f.c.MintTeam(f.admin.caller("acme"))
	if !errors.Is(err, ErrTeamLimit) || statusOf(err) != http.StatusTooManyRequests || errorCode(err) != codeTeamLimit {
		t.Fatalf("a team past the limit: %v", err)
	}
	if _, err := f.c.MintTeam(f.stranger.caller("globex")); err != nil {
		t.Fatalf("another account: %v", err)
	}
}

// The rates are checked before the list's signatures: a list past the rate
// is 429 whatever else is wrong with it.
func TestAListPastTheRateIsRefusedBeforeItIsChecked(t *testing.T) {
	f := newBillingFixture(t)
	f.c.mu.Lock()
	for range accountLogBurst {
		f.c.tookTeamLog(f.admin.caller("acme"), "other", f.now)
	}
	f.c.mu.Unlock()
	l := f.tt.list()
	l.Seq++
	err := f.tt.pushList(f.admin.caller("acme"), f.admin.sign(t, l), l, nil)
	if errorCode(err) != codeTeamLogRate {
		t.Fatalf("a stale list past the rate: %v", err)
	}
	f.advance(2 * accountLogEvery)
	if err := f.tt.pushList(f.admin.caller("acme"), f.admin.sign(t, l), l, nil); !errors.Is(err, ErrTeamStale) {
		t.Fatalf("the stale list once the rate allows: %v", err)
	}
}

// BenchmarkTeamLogAtItsCap is a team whose log is at teamLogMaxBytes of the
// lists that check the most signatures (MaxMembers members with
// MaxMemberDevices computers each): an append, and the replay its first use
// after a restart makes.
func BenchmarkTeamLogAtItsCap(b *testing.B) {
	t := b
	c, _ := newTestCoordinator(t, "ok", 0)
	admin := newTestDevice(t)
	tt := newTestTeam(t, c, "big")
	devices := func() []testDevice {
		var ds []testDevice
		for range MaxMemberDevices {
			ds = append(ds, newTestDevice(t))
		}
		return ds
	}
	tt.set("m_owner", "big", RoleAdmin, append(devices()[1:], admin)...)
	for i := 1; i < MaxMembers; i++ {
		tt.set(fmt.Sprintf("m_%02d", i), fmt.Sprintf("acct_%02d", i), RoleReviewer, devices()...)
	}
	for n := 0; ; n++ {
		c.mu.Lock()
		cur := c.state.Teams["big"]
		c.logRate = teamLogRate{}
		c.mu.Unlock()
		tt.update("m_owner", func(m *ListMember) { m.Email = fmt.Sprintf("owner%d@example.com", n) })
		l := tt.list()
		token := admin.sign(t, l)
		if cur != nil && cur.logBytes()+2*len(token) > teamLogMaxBytes {
			break
		}
		if err := tt.pushList(admin.caller("big"), token, l, nil); err != nil {
			b.Fatal(err)
		}
	}
	c.mu.Lock()
	log := slices.Clone(c.state.Teams["big"].Log)
	b.Logf("%d lists, %d KiB", len(log), c.state.Teams["big"].logBytes()>>10)
	c.mu.Unlock()
	b.Run("append", func(b *testing.B) {
		for range b.N {
			b.StopTimer()
			c.mu.Lock()
			c.state.Teams["big"].Log = slices.Clone(log)
			c.state.Teams["big"].state = nil
			if _, err := c.teamState("big"); err != nil {
				b.Fatal(err)
			}
			c.logRate = teamLogRate{}
			c.mu.Unlock()
			l := tt.list()
			token := admin.sign(t, l)
			b.StartTimer()
			if _, err := c.AppendTeamList(admin.caller("big"), "big", token, nil); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("replay", func(b *testing.B) {
		for range b.N {
			if _, err := reduceTeam("big", testAudience, log); err != nil {
				b.Fatal(err)
			}
		}
	})
	// The save each append makes, with one account's whole budget in the
	// state.
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := 1; i < accountLogMaxBytes/teamLogMaxBytes; i++ {
		id := fmt.Sprintf("big%d", i)
		c.state.Teams[id] = &Team{ID: id, Log: log}
	}
	dir := b.TempDir()
	b.Run("save", func(b *testing.B) {
		for range b.N {
			if err := c.state.Save(dir); err != nil {
				b.Fatal(err)
			}
		}
	})
}
