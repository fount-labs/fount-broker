package coordinator

import (
	"fmt"
	"slices"
	"testing"
)

func TestTheCoordinatorSendsTheRequesterList(t *testing.T) {
	r := genRig(t, MailConfig{})
	w, mb := r.worker()
	if s := r.settings(w.ID); !s.RoutingUnsent {
		t.Fatalf("a new requester isn't owed to the edge: %+v", s)
	}
	r.pass()
	e := r.edge.coord.Mailbox(mb.MailboxID)
	if e.RoutingVersion != 1 || fmt.Sprint(e.Owners) != "[dana@example.com]" {
		t.Fatalf("edge holds %d %v", e.RoutingVersion, e.Owners)
	}
	if s := r.settings(w.ID); s.RoutingUnsent || s.RoutingVersion != 1 {
		t.Fatalf("settings after the send %+v", s)
	}
	calls := len(r.edge.coord.Calls())
	r.pass()
	if slices.Contains(r.edge.coord.Calls()[calls:], "POST /coordinator/routing") {
		t.Fatal("a list the edge took was sent again")
	}

	res := r.workerOp(w.ID, "op_add", "addRequester", requesterArgs{Address: "lee@client.example", BaseRevision: r.settings(w.ID).RequestersRev})
	if !res.OK {
		t.Fatalf("addRequester: %+v", res)
	}
	r.pass()
	if e := r.edge.coord.Mailbox(mb.MailboxID); e.RoutingVersion != 2 || len(e.Owners) != 2 {
		t.Fatalf("edge holds %d %v", e.RoutingVersion, e.Owners)
	}
}

// A list a device wrote before the worker was enrolled is newer than the
// coordinator knows: it steps past it, and keeps where it got to.
func TestAStaleRoutingVersionStepsPast(t *testing.T) {
	r := genRig(t, MailConfig{})
	w, mb := r.worker()
	r.edge.coord.SetRouting(mb.MailboxID, 5, []string{"old@example.com"})
	r.pass()
	if e := r.edge.coord.Mailbox(mb.MailboxID); e.RoutingVersion != 6 || fmt.Sprint(e.Owners) != "[dana@example.com]" {
		t.Fatalf("edge holds %d %v", e.RoutingVersion, e.Owners)
	}
	if s := r.settings(w.ID); s.RoutingUnsent || s.RoutingVersion != 6 {
		t.Fatalf("settings %+v", s)
	}

	// Further ahead than one pass tries: the next pass goes on.
	r.edge.coord.SetRouting(mb.MailboxID, 6+maxRoutingTries+2, []string{"old@example.com"})
	r.workerOp(w.ID, "op_add", "addRequester", requesterArgs{Address: "lee@client.example", BaseRevision: r.settings(w.ID).RequestersRev})
	r.pass()
	if s := r.settings(w.ID); !s.RoutingUnsent || s.RoutingVersion != 6+maxRoutingTries {
		// 7 to 6+maxRoutingTries were tried and refused.
		t.Fatalf("after one pass %+v", s)
	}
	r.pass()
	if s := r.settings(w.ID); s.RoutingUnsent || s.RoutingVersion != 6+maxRoutingTries+3 {
		t.Fatalf("after two passes %+v", s)
	}
}

func TestARefusedConnectProofIsDropped(t *testing.T) {
	r := genRig(t, MailConfig{})
	w, mb := r.worker()
	r.pass()
	if err := r.c.changeMailSettings(w.ID, func(s *MailSettings) bool {
		s.addRequester(Requester{Address: "lee@client.example", PairedBy: "reply"}, &ConnectProof{Owner: "lee@client.example", MessageID: "<c1@fountbox.com>"})
		return true
	}); err != nil {
		t.Fatal(err)
	}
	r.edge.coord.RefuseProofs(true)
	r.pass()
	e := r.edge.coord.Mailbox(mb.MailboxID)
	if len(e.Owners) != 2 || len(e.Proved) != 0 {
		t.Fatalf("edge holds %v proved %v", e.Owners, e.Proved)
	}
	if s := r.settings(w.ID); s.RoutingUnsent || len(s.Proofs) != 0 {
		t.Fatalf("settings %+v", s)
	}
}

func TestSetPausedHoldsMailAndTellsTheEdge(t *testing.T) {
	r := genRig(t, MailConfig{})
	w, mb := r.worker()
	r.pass()
	res := r.workerOp(w.ID, "op_pause", "setPaused", switchArgs{On: true})
	if !res.OK || res.Revision != 1 {
		t.Fatalf("setPaused: %+v", res)
	}
	if s := r.settings(w.ID); !s.Paused || !s.PauseUnsent {
		t.Fatalf("settings %+v", s)
	}
	if res := r.workerOp(w.ID, "op_pause2", "setPaused", switchArgs{On: false}); res.OK || res.Code != CodeWorkerChanged {
		t.Fatalf("a stale base: %+v", res)
	}
	id := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr})
	r.pass()
	if !r.edge.coord.Mailbox(mb.MailboxID).Paused {
		t.Fatal("the edge wasn't told")
	}
	if s := r.settings(w.ID); !s.Paused || s.PauseUnsent {
		t.Fatalf("settings after the send %+v", s)
	}
	if a := r.ledger(w.ID).Acted[id]; a.Outcome != outcomeHeld || a.Reason != "the worker is paused" {
		t.Fatalf("%+v", a)
	}

	if res := r.workerOp(w.ID, "op_resume", "setPaused", switchArgs{On: false, BaseRevision: 1}); !res.OK || res.Revision != 2 {
		t.Fatalf("resume: %+v", res)
	}
	id = r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr})
	r.pass()
	if r.edge.coord.Mailbox(mb.MailboxID).Paused {
		t.Fatal("the edge wasn't told it resumed")
	}
	if a := r.ledger(w.ID).Acted[id]; a.Outcome != outcomeJob {
		t.Fatalf("after resuming %+v", a)
	}
	waitJob(t, r.c, mailJobID(id))
}

// A pause the coordinator hasn't sent holds mail all the same: here, an edge
// with no generation yet to take it.
func TestAnUnsentPauseHoldsMail(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	w, mb := r.worker()
	r.workerOp(w.ID, "op_pause", "setPaused", switchArgs{On: true})
	id := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr})
	r.pass()
	if a := r.ledger(w.ID).Acted[id]; a.Outcome != outcomeHeld || a.Reason != "the worker is paused" {
		t.Fatalf("%+v", a)
	}
	if s := r.settings(w.ID); !s.PauseUnsent {
		t.Fatalf("settings %+v", s)
	}
}

// The edge's own pause (one from before the worker was enrolled) shows on
// the worker, and its resume too.
func TestTheEdgesPauseShows(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	w, _ := r.worker()
	paused := true
	r.edge.mu.Lock()
	r.edge.paused = &paused
	r.edge.mu.Unlock()
	r.pass()
	if s := r.settings(w.ID); !s.Paused || s.PauseUnsent || s.PausedRev != 1 {
		t.Fatalf("settings %+v", s)
	}
	running := false
	r.edge.mu.Lock()
	r.edge.paused = &running
	r.edge.mu.Unlock()
	r.pass()
	if s := r.settings(w.ID); s.Paused || s.PausedRev != 2 {
		t.Fatalf("settings %+v", s)
	}
}
