package coordinator

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"
)

// seatCheck says what a member without a plan of its own gets on the team's
// worker and from the seat statement route.
func (f *billingFixture) seatCheck(t *testing.T, workerID, account string, d testDevice) (int, string, error) {
	t.Helper()
	status, code := call(t, f.c, d.unpaid(account), "GET", "/v1/workers/"+workerID)
	_, err := f.c.BillingStatement(d.unpaid(account), f.team, StatementSeat)
	return status, code, err
}

func (f *billingFixture) seated(t *testing.T, workerID, account string, d testDevice) {
	t.Helper()
	if status, code, err := f.seatCheck(t, workerID, account, d); status != http.StatusOK || err != nil {
		t.Fatalf("%s should hold a seat: %d %q, statement %v", account, status, code, err)
	}
}

func (f *billingFixture) unseated(t *testing.T, workerID, account string, d testDevice) {
	t.Helper()
	status, code, err := f.seatCheck(t, workerID, account, d)
	if status != http.StatusPaymentRequired || code != codeOverSeats || !errors.Is(err, ErrOverSeats) || statusOf(err) != http.StatusPaymentRequired {
		t.Fatalf("%s should hold no seat: %d %q, statement %v", account, status, code, err)
	}
}

// push signs and appends the team's next list as its first admin, at the
// fixture's clock.
func (f *billingFixture) push(t *testing.T) error {
	t.Helper()
	l := f.tt.list()
	f.mu.Lock()
	l.Iat = f.now.Unix()
	f.mu.Unlock()
	return f.tt.pushList(f.admin.caller("acme"), f.admin.sign(t, l), l, nil)
}

func (f *billingFixture) view(t *testing.T) *TeamBillingView {
	t.Helper()
	f.c.mu.Lock()
	defer f.c.mu.Unlock()
	return f.c.teamBillingFor(f.team)
}

// Seats cut to one below five members: nobody is removed, and for a billing
// period everyone keeps the team. After it only the admin holds the seat;
// the rest stay listed and are refused until an admin adds seats.
func TestSeatsCutToOneAdmitOnlyTheAdminAfterAPeriod(t *testing.T) {
	f := newBillingFixture(t)
	f.pay(t, seats(5), nil)
	members := map[string]testDevice{"maria": f.reviewer}
	for _, acct := range []string{"bob", "cat", "dan"} {
		d := newTestDevice(t)
		members[acct] = d
		f.tt.set("m_"+acct, acct, RoleReviewer, d)
	}
	if err := f.push(t); err != nil {
		t.Fatal(err)
	}
	w, err := f.tt.addWorker(f.admin, "acme", DEK{2})
	if err != nil {
		t.Fatal(err)
	}
	cut := f.now
	f.pay(t, seats(1), nil)
	if b := f.billing(t); !b.OverSeatsSince.Equal(cut) {
		t.Fatalf("over since %s, want %s", b.OverSeatsSince, cut)
	}

	f.advance(overSeatsGrace - time.Minute)
	for acct, d := range members {
		f.seated(t, w.ID, acct, d)
	}
	if v := f.view(t); !v.SeatsCutAt.Equal(cut.Add(overSeatsGrace)) || len(v.Unseated) != 0 {
		t.Fatalf("inside the grace: %+v", v)
	}

	f.advance(time.Minute)
	for acct, d := range members {
		f.unseated(t, w.ID, acct, d)
	}
	f.seated(t, w.ID, "acme", f.admin)
	if v := f.view(t); !slices.Equal(v.Unseated, []string{"m_bob", "m_cat", "m_dan", "m_maria"}) {
		t.Fatalf("unseated %v", v.Unseated)
	}
	// Nobody left the list, and each still reads the log.
	f.c.mu.Lock()
	st, _ := f.c.teamState(f.team)
	listed := len(st.members)
	f.c.mu.Unlock()
	if listed != 5 {
		t.Fatalf("%d listed", listed)
	}
	if status, _ := call(t, f.c, f.reviewer.unpaid("maria"), "GET", "/v1/teams/"+f.team+"/log"); status != http.StatusOK {
		t.Fatalf("an unseated member's log: %d", status)
	}
	// A member with a plan of its own still reaches the worker.
	if status, _ := call(t, f.c, f.reviewer.caller("maria"), "GET", "/v1/workers/"+w.ID); status != http.StatusOK {
		t.Fatalf("an unseated member with its own plan: %d", status)
	}

	// Seats bought back take everyone in again at once; the grace is
	// spent until they have been kept for a period.
	back := f.now
	f.pay(t, seats(5), nil)
	for acct, d := range members {
		f.seated(t, w.ID, acct, d)
	}
	if b, v := f.billing(t), f.view(t); !b.OverSeatsSince.Equal(cut) || !b.WithinSeatsSince.Equal(back) || !v.SeatsCutAt.IsZero() || len(v.Unseated) != 0 {
		t.Fatalf("back within the seats: %+v", v)
	}
	f.advance(overSeatsGrace)
	f.pay(t, seats(5), nil)
	if b := f.billing(t); !b.OverSeatsSince.IsZero() || !b.WithinSeatsSince.IsZero() {
		t.Fatalf("a period within the seats, over since %s", b.OverSeatsSince)
	}
}

// Over by one: inside the grace everyone holds a seat; past it the member
// who joined last doesn't, an admin keeps theirs whenever they joined, and
// a removal ends it. A lapse doesn't start the grace over.
func TestOverByOneCutsTheLastToJoinAfterTheGraceAdminsFirst(t *testing.T) {
	f := newBillingFixture(t)
	f.pay(t, seats(4), nil)
	bob, cat := newTestDevice(t), newTestDevice(t)
	f.tt.set("m_bob", "bob", RoleReviewer, bob)
	if err := f.push(t); err != nil {
		t.Fatal(err)
	}
	f.tt.set("m_cat", "cat", RoleReviewer, cat)
	if err := f.push(t); err != nil {
		t.Fatal(err)
	}
	w, err := f.tt.addWorker(f.admin, "acme", DEK{4})
	if err != nil {
		t.Fatal(err)
	}
	f.pay(t, seats(3), nil)

	f.advance(overSeatsGrace / 2)
	// The team lapses and pays again: the grace runs on from the cut.
	f.pay(t, TeamEntitlement{}, lapsedTeam)
	f.pay(t, seats(3), nil)
	f.advance(overSeatsGrace/2 - time.Minute)
	f.seated(t, w.ID, "cat", cat)

	f.advance(time.Minute)
	f.seated(t, w.ID, "maria", f.reviewer)
	f.seated(t, w.ID, "bob", bob)
	f.unseated(t, w.ID, "cat", cat)

	// Cat, the last to join, made an admin goes ahead of every reviewer:
	// bob, who joined after maria, is the one left out.
	f.tt.update("m_cat", func(m *ListMember) { m.Role = RoleAdmin; m.Workers = nil })
	if err := f.push(t); err != nil {
		t.Fatal(err)
	}
	f.seated(t, w.ID, "cat", cat)
	f.seated(t, w.ID, "maria", f.reviewer)
	f.unseated(t, w.ID, "bob", bob)

	// An admin makes an email agent only from a seat: past two admins on
	// one seat, the later admin is refused.
	f.pay(t, seats(1), nil)
	f.advance(overSeatsGrace)
	if status, code := call(t, f.c, cat.unpaid("cat"), "POST", "/v1/workers"); status != http.StatusPaymentRequired || code != codeOverSeats {
		t.Fatalf("an unseated admin's new worker: %d %q", status, code)
	}
	if status, _ := call(t, f.c, f.admin.unpaid("acme"), "POST", "/v1/workers"); status != http.StatusCreated {
		t.Fatalf("the seated admin's new worker: %d", status)
	}
	// An admin statement, to buy seats, needs no seat.
	if _, err := f.c.BillingStatement(cat.unpaid("cat"), f.team, StatementAdmin); err != nil {
		t.Fatalf("an unseated admin's admin statement: %v", err)
	}

	// Back within the seats once the others are removed, and the grace is
	// the team's again a period later.
	for _, id := range []string{"m_bob", "m_maria", "m_cat"} {
		f.tt.drop(id)
	}
	if err := f.push(t); err != nil {
		t.Fatal(err)
	}
	f.seated(t, w.ID, "acme", f.admin)
	if v := f.view(t); !v.SeatsCutAt.IsZero() || len(v.Unseated) != 0 {
		t.Fatalf("within the seats: %+v", v)
	}
	f.advance(overSeatsGrace)
	f.pay(t, seats(1), nil)
	if b := f.billing(t); !b.OverSeatsSince.IsZero() {
		t.Fatalf("a period within the seats, over since %s", b.OverSeatsSince)
	}
}

// Seats raised just before the period's end and cut at it buy no new
// grace: the team over its seats since long ago is cut at once. Seats kept
// for a period end the grace, and a later cut starts a new one.
func TestASeatRaiseJustBeforeThePeriodEndBuysNoNewGrace(t *testing.T) {
	f := newBillingFixture(t)
	f.pay(t, seats(5), nil)
	members := map[string]testDevice{"maria": f.reviewer}
	for _, acct := range []string{"bob", "cat", "dan"} {
		d := newTestDevice(t)
		members[acct] = d
		f.tt.set("m_"+acct, acct, RoleReviewer, d)
	}
	if err := f.push(t); err != nil {
		t.Fatal(err)
	}
	w, err := f.tt.addWorker(f.admin, "acme", DEK{3})
	if err != nil {
		t.Fatal(err)
	}
	cut := f.now
	f.pay(t, seats(1), nil)
	f.advance(overSeatsGrace)
	f.unseated(t, w.ID, "maria", f.reviewer)

	// Five seats an hour before the period ends, a list, one seat again.
	f.pay(t, seats(5), nil)
	f.seated(t, w.ID, "maria", f.reviewer)
	f.tt.update("m_maria", func(m *ListMember) { m.Email = "maria@example.com" })
	if err := f.push(t); err != nil {
		t.Fatal(err)
	}
	f.advance(time.Hour)
	f.pay(t, seats(1), nil)
	if b := f.billing(t); !b.OverSeatsSince.Equal(cut) || !b.WithinSeatsSince.IsZero() {
		t.Fatalf("over since %s, want %s", b.OverSeatsSince, cut)
	}
	for acct, d := range members {
		f.unseated(t, w.ID, acct, d)
	}
	f.seated(t, w.ID, "acme", f.admin)

	// Seats bought and kept for a period: the next cut has its grace.
	f.pay(t, seats(5), nil)
	f.advance(overSeatsGrace)
	f.pay(t, seats(5), nil)
	if b := f.billing(t); !b.OverSeatsSince.IsZero() {
		t.Fatalf("seats kept a period, over since %s", b.OverSeatsSince)
	}
	again := f.now
	f.pay(t, seats(1), nil)
	if b := f.billing(t); !b.OverSeatsSince.Equal(again) {
		t.Fatalf("a later cut, over since %s, want %s", b.OverSeatsSince, again)
	}
	for acct, d := range members {
		f.seated(t, w.ID, acct, d)
	}
}

// A swap keeps the count, so it passes with the seats full; once the team
// has been over its seats for a period, the account swapped in joins last
// and gets no seat statement, and the one swapped out gets none either.
func TestASwapMintsNoSeatStatementBeyondThePaidSeats(t *testing.T) {
	f := newBillingFixture(t)
	f.pay(t, seats(2), nil)
	maria := f.reviewer.unpaid("maria")
	if _, err := f.c.BillingStatement(maria, f.team, StatementSeat); err != nil {
		t.Fatal(err)
	}
	// Within the seats a swap passes, and the account swapped out is no
	// longer a member.
	f.tt.drop("m_maria")
	guest := newTestDevice(t)
	f.tt.set("m_guest", "guest", RoleReviewer, guest)
	if err := f.push(t); err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.BillingStatement(maria, f.team, StatementSeat); !errors.Is(err, ErrNoTeam) {
		t.Fatalf("a removed member's seat statement: %v", err)
	}
	if _, err := f.c.BillingStatement(guest.unpaid("guest"), f.team, StatementSeat); err != nil {
		t.Fatal(err)
	}

	// Over the seats past the grace: each account swapped in is refused.
	f.pay(t, seats(3), nil)
	bob := newTestDevice(t)
	f.tt.set("m_bob", "bob", RoleReviewer, bob)
	if err := f.push(t); err != nil {
		t.Fatal(err)
	}
	w, err := f.tt.addWorker(f.admin, "acme", DEK{5})
	if err != nil {
		t.Fatal(err)
	}
	f.pay(t, seats(2), nil)
	f.advance(overSeatsGrace)
	f.unseated(t, w.ID, "bob", bob)
	for i := range 3 {
		f.tt.drop("m_bob")
		for j := range i {
			f.tt.drop(fmt.Sprintf("m_%d", j))
		}
		acct, d := fmt.Sprintf("swap%d", i), newTestDevice(t)
		f.tt.set(fmt.Sprintf("m_%d", i), acct, RoleReviewer, d)
		if err := f.push(t); err != nil {
			t.Fatalf("swap %d: %v", i, err)
		}
		f.unseated(t, w.ID, acct, d)
		f.seated(t, w.ID, "guest", guest)
	}
}

// State saved before seats were tracked has no overSeatsSince; it reads as
// within the seats, and the next answer or list starts tracking.
func TestBillingSavedWithoutOverSeatsSinceReadsWithin(t *testing.T) {
	var b TeamBilling
	if err := decodeStrictJSON([]byte(`{"status":"active","seats":1,"checkedAt":"2026-11-01T00:00:00Z","triedAt":"2026-11-01T00:00:00Z"}`), &b); err != nil {
		t.Fatal(err)
	}
	if !b.OverSeatsSince.IsZero() {
		t.Fatalf("over since %s", b.OverSeatsSince)
	}
	now := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	b.trackSeats(3, now)
	if !b.OverSeatsSince.Equal(now) {
		t.Fatalf("over since %s", b.OverSeatsSince)
	}
}
