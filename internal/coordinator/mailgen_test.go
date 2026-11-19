package coordinator

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"slices"
	"strings"
	"testing"

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
