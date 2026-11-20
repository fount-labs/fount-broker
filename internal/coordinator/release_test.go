package coordinator

import (
	"slices"
	"testing"
)

// A worker the list leaves out queues its mailbox for removal at the edge in
// the same commit.
func TestADeletedWorkersMailboxIsQueuedForRemoval(t *testing.T) {
	f := newTeamFixture(t)
	const mb = "ab00000000000000000000000000000000000000000000000000000000000000"
	f.c.mu.Lock()
	f.c.state.Workers[f.w2.ID].Mailbox = mb
	f.c.mu.Unlock()
	delete(f.tt.workers, f.w2.ID)
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	f.c.mu.Lock()
	got := slices.Clone(f.c.state.Releases)
	f.c.mu.Unlock()
	if !slices.Equal(got, []string{mb}) {
		t.Fatalf("releases %v", got)
	}
	c2, err := New(f.c.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c2.state.Releases, []string{mb}) {
		t.Fatalf("after a restart: %v", c2.state.Releases)
	}
}

// The mail pass removes a queued mailbox at the edge, retries a failure on
// the next pass, and drops its keys.
func TestTheMailPassRemovesADeletedWorkersMailbox(t *testing.T) {
	r := genRig(t, MailConfig{})
	w, mb := r.worker()
	r.pass()
	if !r.edge.coord.Mailbox(mb.MailboxID).Enrolled {
		t.Fatal("not enrolled")
	}
	r.c.mu.Lock()
	delete(r.c.state.Workers, w.ID)
	r.c.state.Releases = []string{mb.MailboxID}
	r.c.mu.Unlock()
	r.edge.coord.RemoveFailures = 1
	queued := func() bool {
		r.c.mu.Lock()
		defer r.c.mu.Unlock()
		return slices.Contains(r.c.state.Releases, mb.MailboxID)
	}
	r.pass()
	if !queued() {
		t.Fatal("a failed removal left the queue")
	}
	r.pass()
	if queued() {
		t.Fatal("still queued after the edge took it")
	}
	if !r.edge.coord.Mailbox(mb.MailboxID).Removed {
		t.Fatal("the edge didn't remove it")
	}
	if r.c.mail.service.HasKeys(mb.MailboxID) {
		t.Fatal("the service kept its keys")
	}
}
