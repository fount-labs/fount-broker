package coordinator

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fount-labs/fount-broker/internal/mail"
)

// genRig is a mail rig whose coordinator takes its generation from a dev
// source signed by the fake edge's authority, and presents it, as RunMail does.
func genRig(t *testing.T, cfg MailConfig) *mailRig {
	t.Helper()
	r := newMailRig(t, MailConfig{})
	cfg.Generations = &mail.DevGenerations{Authority: r.edge.authority, Path: filepath.Join(r.dir, "generation")}
	r.cfg = cfg
	r.start()
	if !r.c.startGeneration(context.Background()) {
		t.Fatal("the generation wasn't presented")
	}
	return r
}

func TestMailEnrollsAndNamesTheGeneration(t *testing.T) {
	r := genRig(t, MailConfig{})
	if r.edge.coord.Generation() != 1 || r.c.mail.service.Generation() != 1 {
		t.Fatalf("edge at %d, coordinator at %d", r.edge.coord.Generation(), r.c.mail.service.Generation())
	}
	w, mb := r.worker()
	id := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr})
	r.pass()
	if !r.edge.coord.Mailbox(mb.MailboxID).Enrolled {
		t.Fatal("the mailbox wasn't enrolled")
	}
	if r.ledger(w.ID).Acted[id].Outcome != outcomeJob {
		t.Fatal("an enrolled mailbox's mail wasn't acted on")
	}
	waitJob(t, r.c, mailJobID(id))
	r.pass()
	enrolls := 0
	for _, c := range r.edge.coord.Calls() {
		if strings.HasPrefix(c, "PUT /coordinator ") {
			enrolls++
		}
		if strings.HasPrefix(c, "fenced") {
			t.Errorf("the fence refused %s", c)
		}
	}
	if enrolls != 1 {
		t.Fatalf("enrolled %d times in one process", enrolls)
	}

	// A restart is a new process and generation, which enrolls again.
	r.cfg.Generations = &mail.DevGenerations{Authority: r.edge.authority, Path: filepath.Join(r.dir, "generation")}
	r.start()
	if !r.c.startGeneration(context.Background()) {
		t.Fatal("the restart's generation wasn't presented")
	}
	second := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr})
	r.pass()
	if r.edge.coord.Generation() != 2 || r.ledger(w.ID).Acted[second].Outcome != outcomeJob {
		t.Fatalf("generation %d", r.edge.coord.Generation())
	}
	waitJob(t, r.c, mailJobID(second))
}

// A coordinator that names no generation can't read a mailbox another one
// enrolled: the fake edge holds the call to the fence.
func TestAnEnrolledMailboxRefusesNoGeneration(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	w, mb := r.worker()
	pub, _, _ := ed25519.GenerateKey(nil)
	r.edge.coord.Advance(3, pub)
	if err := r.edge.coord.Enroll(mb.MailboxID); err != nil {
		t.Fatal(err)
	}
	id := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr})
	r.pass()
	if _, acted := r.ledger(w.ID).Acted[id]; acted {
		t.Fatal("mail was read without the generation")
	}
	if !slices.Contains(r.edge.coord.Calls(), "fenced GET /mail: generation_required") {
		t.Fatalf("calls %v", r.edge.coord.Calls())
	}
}

// Once a newer coordinator presents its generation, this one stops reading.
func TestANewerGenerationStopsTheMailLoop(t *testing.T) {
	r := genRig(t, MailConfig{})
	w, mb := r.worker()
	r.pass()
	pub, _, _ := ed25519.GenerateKey(nil)
	r.edge.coord.Advance(7, pub)
	id := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr})
	r.pass()
	if !r.c.mail.stale.Load() {
		t.Fatal("the loop didn't stop")
	}
	if _, acted := r.ledger(w.ID).Acted[id]; acted {
		t.Fatal("a stale coordinator acted on mail")
	}
	lists := r.edge.listCalls(mb.MailboxID)
	r.pass()
	if r.edge.listCalls(mb.MailboxID) != lists {
		t.Fatal("a stopped loop listed again")
	}
	// RunMail returns at once.
	done := make(chan struct{})
	go func() {
		r.c.RunMail(context.Background())
		close(done)
	}()
	<-done
}

// The loop reads the edge's own changes feed, signed with the generation:
// only the mailbox with new mail is listed, and a restore of the edge's
// routing object sweeps.
func TestTheEdgesChangesFeedPicksTheMailboxes(t *testing.T) {
	r := genRig(t, MailConfig{SweepInterval: time.Hour})
	r.c.mail.cfg.Changes = EdgeChanges{Service: r.c.mail.service}
	w1, mb1 := r.worker()
	_, mb2 := r.worker()
	now := time.Now()
	ctx := context.Background()
	r.c.mailPass(ctx, now) // the first pass sweeps, which enrolls
	r.c.mailPass(ctx, now.Add(time.Second))
	r.c.mailPass(ctx, now.Add(2*time.Second))
	l1, l2 := r.edge.listCalls(mb1.MailboxID), r.edge.listCalls(mb2.MailboxID)
	r.c.mailPass(ctx, now.Add(3*time.Second))
	if r.edge.listCalls(mb1.MailboxID) != l1 || r.edge.listCalls(mb2.MailboxID) != l2 {
		t.Fatal("a pass with no changes listed a mailbox")
	}
	id := r.edge.deliver(mb1, email{from: "dana@example.com", to: testWorkerAddr})
	r.c.mailPass(ctx, now.Add(4*time.Second))
	if r.edge.listCalls(mb1.MailboxID) != l1+1 || r.edge.listCalls(mb2.MailboxID) != l2 {
		t.Fatalf("listed %d/%d and %d/%d", r.edge.listCalls(mb1.MailboxID), l1, r.edge.listCalls(mb2.MailboxID), l2)
	}
	if r.ledger(w1.ID).Acted[id].Outcome != outcomeJob {
		t.Fatal("the changed mailbox's mail wasn't acted on")
	}
	waitJob(t, r.c, mailJobID(id))

	r.edge.coord.Restore()
	r.c.mailPass(ctx, now.Add(5*time.Second))
	if r.edge.listCalls(mb2.MailboxID) != l2+1 {
		t.Fatal("a reset didn't sweep")
	}
}
