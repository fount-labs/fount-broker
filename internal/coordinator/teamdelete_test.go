package coordinator

import (
	"errors"
	"slices"
	"testing"
)

// firmFixture is a firm team: an owner admin, another admin, a reviewer and a
// worker with a mailbox.
func firmFixture(t *testing.T) (*testTeam, testDevice, testDevice, testDevice, Worker) {
	t.Helper()
	c, _ := newTestCoordinator(t, "ok", 0)
	owner, admin, reviewer := newTestDevice(t), newTestDevice(t), newTestDevice(t)
	id, err := c.MintTeam(owner.caller("acme"))
	if err != nil {
		t.Fatal(err)
	}
	tt := newTestTeam(t, c, id)
	tt.set("m_owner", "acme", RoleAdmin, owner)
	tt.set("m_admin", "dev", RoleAdmin, admin)
	tt.set("m_rev", "maria", RoleReviewer, reviewer)
	if err := tt.push(owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	w, err := tt.addWorker(owner, "acme", mustDEK(t))
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.state.Workers[w.ID].Mailbox = "cd00000000000000000000000000000000000000000000000000000000000000"
	c.mu.Unlock()
	return tt, owner, admin, reviewer, w
}

func deleteList(tt *testTeam) TeamList {
	seq, head := tt.head()
	return TeamList{Aud: testAudience, Team: tt.id, Seq: seq + 1, Prev: head, Deleted: true}
}

func TestAnAdminDeletesAFirmTeamAndItsWorkersAddressesAreFreed(t *testing.T) {
	tt, _, admin, reviewer, w := firmFixture(t)

	// A reviewer can't.
	l := deleteList(tt)
	if err := tt.pushList(reviewer.caller("maria"), reviewer.sign(t, l), l, nil); !errors.Is(err, ErrNotAdmin) && !errors.Is(err, ErrRole) && !errors.Is(err, ErrListRefused) {
		t.Fatalf("a reviewer deleting the team: %v", err)
	}
	// Members or workers in a deleting list are refused.
	bad := tt.list()
	bad.Deleted = true
	if err := tt.pushList(admin.caller("dev"), admin.sign(t, bad), bad, nil); err == nil {
		t.Fatal("a deleting list that names members was taken")
	}

	l = deleteList(tt)
	if err := tt.pushList(admin.caller("dev"), admin.sign(t, l), l, nil); err != nil {
		t.Fatal(err)
	}
	c := tt.c
	c.mu.Lock()
	_, alive := c.state.Workers[w.ID]
	releases := slices.Clone(c.state.Releases)
	c.mu.Unlock()
	if alive {
		t.Error("the team's worker survived its team")
	}
	if !slices.Equal(releases, []string{"cd00000000000000000000000000000000000000000000000000000000000000"}) {
		t.Errorf("releases %v", releases)
	}

	// Former members still read the log, to see it go; no one else does.
	c.mu.Lock()
	readErr := c.mayReadLog(reviewer.caller("maria"), tt.id)
	strangerErr := c.mayReadLog(newTestDevice(t).caller("maria"), tt.id)
	c.mu.Unlock()
	if readErr != nil {
		t.Errorf("a former member reading the log: %v", readErr)
	}
	if !errors.Is(strangerErr, ErrNoTeam) {
		t.Errorf("a stranger reading the log: %v", strangerErr)
	}
	if got := c.Memberships(admin.caller("dev")); len(got) != 0 {
		t.Errorf("a deleted team is still a membership: %v", got)
	}

	// Nothing follows the deletion, and it survives a restart.
	tt.set("m_admin", "dev", RoleAdmin, admin)
	if err := tt.push(admin, "dev", nil); !errors.Is(err, ErrTeamDeleted) {
		t.Errorf("a list after the deletion: %v", err)
	}
	c2, err := New(c.cfg)
	if err != nil {
		t.Fatal(err)
	}
	c2.mu.Lock()
	st, err := c2.teamState(tt.id)
	c2.mu.Unlock()
	if err != nil || !st.deleted {
		t.Fatalf("after a restart: %v %v", st, err)
	}
}

func TestATeamOfOneIsntDeleted(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	me := newTestDevice(t)
	tt := soloTeam(t, c, "acme", me)
	l := deleteList(tt)
	if err := tt.pushList(me.caller("acme"), me.sign(t, l), l, nil); !errors.Is(err, ErrListRefused) {
		t.Fatalf("deleting a team of one: %v", err)
	}
}
