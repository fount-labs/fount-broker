package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// pay sets fount-infra's answer for the fixture's team and takes it.
func (f *billingFixture) pay(t *testing.T, answer TeamEntitlement, err error) {
	t.Helper()
	f.biller.set(answer, err)
	if _, err := f.c.refreshTeamBilling(context.Background(), f.team); err != nil {
		t.Fatal(err)
	}
}

func seats(n int) TeamEntitlement {
	a := paid
	a.Seats = n
	return a
}

var lapsedTeam = &TeamNotEntitled{Reason: "period_ended"}

func newAPI(t *testing.T, c *Coordinator, caller Caller) string {
	srv := httptest.NewServer(c.AccountHandler(caller))
	t.Cleanup(srv.Close)
	return srv.URL
}

// call is one request of caller's account API: the status and the body's
// code.
func call(t *testing.T, c *Coordinator, caller Caller, method, path string) (int, string) {
	t.Helper()
	srv := newAPI(t, c, caller)
	req, _ := http.NewRequest(method, srv+path, strings.NewReader("{}"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct {
		Code string `json:"code"`
	}
	json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body.Code
}

func TestAListPastTheSeatsIsRefusedAndARemovalPasses(t *testing.T) {
	f := newBillingFixture(t)
	f.pay(t, seats(2), nil)
	dev := newTestDevice(t)
	f.tt.set("m_dev", "dev", RoleReviewer, dev)
	err := f.tt.push(f.admin, "acme", nil)
	if !errors.Is(err, ErrSeats) || statusOf(err) != http.StatusPaymentRequired || errorCode(err) != codeSeats {
		t.Fatalf("a third member on two seats: %v", err)
	}
	// A pending invite takes a seat too.
	f.tt.drop("m_dev")
	f.tt.members["m_dev"] = ListMember{ID: "m_dev", Email: "dev@example.com", Role: RoleReviewer, Workers: []string{allWorkers}, Invite: &ListInvite{ID: "i_1", Commit: b64.EncodeToString(make([]byte, 32)), Exp: f.now.Add(time.Hour).Unix()}}
	if err := f.tt.push(f.admin, "acme", nil); !errors.Is(err, ErrSeats) {
		t.Fatalf("an invite past the seats: %v", err)
	}

	f.pay(t, seats(3), nil)
	if err := f.tt.push(f.admin, "acme", nil); err != nil {
		t.Fatalf("a third seat bought: %v", err)
	}

	// Seats cut to one: nobody is removed, and every change that doesn't add
	// a member still passes.
	f.pay(t, seats(1), nil)
	f.tt.update("m_maria", func(m *ListMember) { m.Role = RoleAdmin; m.Workers = nil })
	if err := f.tt.push(f.admin, "acme", nil); err != nil {
		t.Fatalf("a role change while over: %v", err)
	}
	f.tt.drop("m_dev")
	if err := f.tt.push(f.admin, "acme", nil); err != nil {
		t.Fatalf("a removal while over: %v", err)
	}
	f.tt.set("m_dev", "dev", RoleReviewer, dev)
	if err := f.tt.push(f.admin, "acme", nil); !errors.Is(err, ErrSeats) {
		t.Fatalf("adding back while over: %v", err)
	}

	// A team that doesn't pay has one seat.
	f.pay(t, TeamEntitlement{}, lapsedTeam)
	if err := f.tt.push(f.admin, "acme", nil); !errors.Is(err, ErrSeats) {
		t.Fatalf("adding to a lapsed team: %v", err)
	}
	f.tt.drop("m_dev")
	f.tt.drop("m_maria")
	if err := f.tt.push(f.admin, "acme", nil); err != nil {
		t.Fatalf("a removal from a lapsed team: %v", err)
	}
}

func TestASoloTeamHasNoSeatsAndNeedsEachMembersPlan(t *testing.T) {
	f := newBillingFixture(t)
	maria := soloTeam(t, f.c, "maria", f.reviewer)
	for _, id := range []string{"m_a", "m_b", "m_c"} {
		maria.set(id, id, RoleReviewer, newTestDevice(t))
	}
	if err := maria.push(f.reviewer, "maria", nil); err != nil {
		t.Fatalf("a solo team's list counts no seats: %v", err)
	}
	w, err := maria.addWorker(f.reviewer, "maria", DEK{3})
	if err != nil {
		t.Fatal(err)
	}
	if status, code := call(t, f.c, f.reviewer.unpaid("maria"), "GET", "/v1/workers/"+w.ID); status != http.StatusPaymentRequired || code != codeNoPlan {
		t.Fatalf("a solo team's worker with no plan: %d %q", status, code)
	}
	if status, _ := call(t, f.c, f.reviewer.caller("maria"), "GET", "/v1/workers/"+w.ID); status != http.StatusOK {
		t.Fatalf("with a plan: %d", status)
	}
}

func TestAnUnpaidMemberOpensATeamWorkerButNotASoloRoute(t *testing.T) {
	f := newBillingFixture(t)
	f.pay(t, paid, nil)
	w, err := f.tt.addWorker(f.admin, "acme", DEK{1})
	if err != nil {
		t.Fatal(err)
	}
	maria := f.reviewer.unpaid("maria")
	if status, _ := call(t, f.c, maria, "GET", "/v1/workers/"+w.ID); status != http.StatusOK {
		t.Fatalf("an unpaid reviewer on a paying team's worker: %d", status)
	}
	if ws, _ := f.c.reachable(maria); len(ws) != 1 || ws[0].ID != w.ID {
		t.Fatalf("the unpaid reviewer's list: %v", ws)
	}
	if status, _ := call(t, f.c, maria, "GET", "/v1/teams/"+f.team+"/log"); status != http.StatusOK {
		t.Fatalf("the team's log: %d", status)
	}
	for _, route := range []string{"/v1/teams", "/v1/workers"} {
		if status, code := call(t, f.c, maria, "POST", route); status != http.StatusPaymentRequired || code != codeNoPlan {
			t.Fatalf("POST %s with no plan: %d %q", route, status, code)
		}
	}
	// An unpaid admin of a paying team makes the team's next worker; a
	// team of its own needs a plan.
	admin := f.admin.unpaid("acme")
	if status, _ := call(t, f.c, admin, "POST", "/v1/workers"); status != http.StatusCreated {
		t.Fatalf("an unpaid admin's new worker: %d", status)
	}
	if status, code := call(t, f.c, admin, "POST", "/v1/teams"); status != http.StatusPaymentRequired || code != codeNoPlan {
		t.Fatalf("an unpaid admin's new team: %d %q", status, code)
	}
	// Nor can that worker go into a solo team of the admin's own.
	spare, err := f.c.CreateWorkerFor(admin)
	if err != nil {
		t.Fatal(err)
	}
	own := newTestTeam(t, f.c, "acme")
	own.set("m_owner", "acme", RoleAdmin, f.admin)
	own.workers[spare.ID] = DEKCommitment(spare.ID, DEK{2})
	l := own.list()
	if err := own.pushList(admin, f.admin.sign(t, l), l, map[string]DEK{spare.ID: {2}}); !errors.Is(err, ErrNoPlan) {
		t.Fatalf("an unpaid admin's worker into a solo team: %v", err)
	}

	// The team lapses: a member with no plan of their own is shut out; one
	// with a plan still reads.
	f.pay(t, TeamEntitlement{}, lapsedTeam)
	if status, code := call(t, f.c, maria, "GET", "/v1/workers/"+w.ID); status != http.StatusPaymentRequired || code != codeTeamUnpaid {
		t.Fatalf("an unpaid reviewer on a lapsed team: %d %q", status, code)
	}
	if ws, _ := f.c.reachable(maria); len(ws) != 0 {
		t.Fatalf("listed on a lapsed team: %v", ws)
	}
	if status, code := call(t, f.c, admin, "POST", "/v1/workers"); status != http.StatusPaymentRequired || code != codeNoPlan {
		t.Fatalf("an unpaid admin of a lapsed team makes a worker: %d %q", status, code)
	}
	if status, _ := call(t, f.c, f.reviewer.caller("maria"), "GET", "/v1/workers/"+w.ID); status != http.StatusOK {
		t.Fatalf("a reviewer with a plan on a lapsed team: %d", status)
	}
	// Paying needs no plan: the statement and the refresh still answer.
	if _, err := f.c.BillingStatement(admin, f.team, StatementAdmin); err != nil {
		t.Fatalf("an unpaid admin's statement: %v", err)
	}
	// A stranger is told nothing about the worker, plan or not.
	if status, _ := call(t, f.c, f.stranger.unpaid("acme"), "GET", "/v1/workers/"+w.ID); status != http.StatusNotFound {
		t.Fatalf("a stranger: %d", status)
	}
}

func TestABillingRefusalWithoutAnAnswerIsUnknown(t *testing.T) {
	f := newBillingFixture(t)
	w, err := func() (Worker, error) {
		f.c.cfg.TeamBilling = nil
		defer func() { f.c.cfg.TeamBilling = f.biller }()
		return f.tt.addWorker(f.admin, "acme", DEK{1})
	}()
	if err != nil {
		t.Fatal(err)
	}
	maria := f.reviewer.unpaid("maria")
	if status, code := call(t, f.c, maria, "GET", "/v1/workers/"+w.ID); status != http.StatusPaymentRequired || code != codeTeamUnpaid {
		t.Fatalf("no answer yet: %d %q", status, code)
	}
	f.c.mu.Lock()
	got := f.c.teamPayment(f.team, f.now)
	f.c.mu.Unlock()
	if got != teamPayUnknown {
		t.Fatalf("no answer is %v", got)
	}
	// Without a biller there is no team billing: a plan is needed.
	f.c.cfg.TeamBilling = nil
	defer func() { f.c.cfg.TeamBilling = f.biller }()
	if status, code := call(t, f.c, maria, "GET", "/v1/workers/"+w.ID); status != http.StatusPaymentRequired || code != codeNoPlan {
		t.Fatalf("billing off: %d %q", status, code)
	}
}

func TestAJobIsntStartedWhileTheTeamDoesntPay(t *testing.T) {
	f := newBillingFixture(t)
	f.pay(t, paid, nil)
	w, err := f.tt.addWorker(f.admin, "acme", DEK{1})
	if err != nil {
		t.Fatal(err)
	}
	f.pay(t, TeamEntitlement{}, lapsedTeam)
	if err := f.c.PutFile(w.ID, "threads/t1/2026-11-13-e_1/message.md", []byte("From Ann: hello")); err != nil {
		t.Fatal(err)
	}
	job, err := f.c.Enqueue(w.ID, spec("t1"))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	f.c.poke()
	time.Sleep(100 * time.Millisecond)
	if j, _ := f.c.Job(job.ID); j.State != JobQueued {
		t.Fatalf("an unpaid team's job is %s", j.State)
	}
	for _, r := range f.c.TeamRunners("dev", nil, f.now) {
		if r.Account == f.team && r.Queued != 0 {
			t.Fatalf("an unpaid team asks for a runner: %+v", r)
		}
	}
	f.pay(t, paid, nil)
	if j := waitJob(t, f.c, job.ID); j.State != JobFinished {
		t.Fatalf("once paid the job is %s: %s", j.State, j.Error)
	}
}

func TestAnEndedTeamIsRetired(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	c.cfg.TeamBilling = &fakeBiller{}
	now := time.Now()
	teams := map[string]*TeamBilling{
		"tm_aaaaaaaaaaaaaaaaaaaaaaaa": {Status: BillingNoAccess, Reason: "canceled", CheckedAt: now, Since: now},
		"tm_bbbbbbbbbbbbbbbbbbbbbbbb": {Status: BillingNoAccess, Reason: "period_ended", CheckedAt: now, Since: now.Add(-teamRetireAfter - time.Hour)},
		"tm_cccccccccccccccccccccccc": {Status: BillingNoAccess, Reason: "period_ended", CheckedAt: now, Since: now.Add(-24 * time.Hour)},
		"tm_dddddddddddddddddddddddd": {Status: BillingNoAccess, Reason: "no_subscription", CheckedAt: now, Since: now.Add(-2 * teamRetireAfter)},
		"tm_eeeeeeeeeeeeeeeeeeeeeeee": {Status: "active", PeriodEnd: now.Add(time.Hour), CheckedAt: now},
	}
	c.mu.Lock()
	for id, b := range teams {
		c.state.Teams[id] = &Team{ID: id, Billing: b, state: &teamState{}}
	}
	c.mu.Unlock()
	retired := map[string]bool{}
	retiredAt := map[string]string{}
	for _, r := range c.TeamRunners("dev", nil, now) {
		retired[r.Account] = r.Retired
		if r.RetiredAt != "" {
			retiredAt[r.Account] = r.RetiredAt
		}
	}
	want := map[string]bool{"tm_aaaaaaaaaaaaaaaaaaaaaaaa": true, "tm_bbbbbbbbbbbbbbbbbbbbbbbb": true}
	if !reflect.DeepEqual(retired, want) {
		t.Fatalf("retired %v, want %v", retired, want)
	}
	at := now.UTC().Format(time.RFC3339)
	wantAt := map[string]string{"tm_aaaaaaaaaaaaaaaaaaaaaaaa": at, "tm_bbbbbbbbbbbbbbbbbbbbbbbb": at}
	if !reflect.DeepEqual(retiredAt, wantAt) {
		t.Fatalf("retiredAt %v, want %v", retiredAt, wantAt)
	}
}

func TestBillingKeepsWhenItStoppedPayingAndAsksAgainAtTheEnd(t *testing.T) {
	f := newBillingFixture(t)
	f.pay(t, TeamEntitlement{}, lapsedTeam)
	first := f.billing(t).Since
	if first.IsZero() {
		t.Fatal("no since")
	}
	f.now = f.now.Add(time.Hour)
	f.pay(t, TeamEntitlement{}, lapsedTeam)
	if !f.billing(t).Since.Equal(first) {
		t.Fatal("since moved")
	}
	f.biller.set(TeamEntitlement{}, errors.New("fount-infra is down"))
	f.c.refreshTeamBilling(context.Background(), f.team)
	if !f.billing(t).Since.Equal(first) {
		t.Fatal("a failed ask moved since")
	}
	f.pay(t, paid, nil)
	b := f.billing(t)
	if !b.Since.IsZero() {
		t.Fatal("since kept while paid")
	}
	if billingDue(b, b.CheckedAt.Add(time.Hour)) || !billingDue(b, b.PeriodEnd) {
		t.Fatal("not asked again at the period end")
	}
}
