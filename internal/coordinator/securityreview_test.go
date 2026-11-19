package coordinator

import (
	"encoding/json"
	"errors"
	"testing"
)

// Regression tests for the security review of 2026-11-19.

// C1: an account names another worker's mailbox id, with its own keys, in a
// mail setup. Before, the Service's keys for the victim's mailbox were
// replaced at once and, after a restart, the attacker's worker read the
// victim's mail.
func TestAMailSetupCantClaimAnotherWorkersMailbox(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	victim, vmb := r.worker()
	dek := mustDEK(t)
	evil, err := r.c.CreateWorker("acct_evil", &dek)
	if err != nil {
		t.Fatal(err)
	}
	s := vectorSetup()
	emb := newMailbox(t, "evil@fountbox.com")
	emb.MailboxID = vmb.MailboxID
	s.Mailbox = emb
	s.Worker = json.RawMessage(`{}`)
	sealed, _ := SealMailSetup(dek, evil.ID, s)
	if err := r.c.SetUpMail(anyDevice, evil.ID, sealed); !errors.Is(err, ErrMailboxTaken) {
		t.Fatalf("a setup naming another worker's mailbox: %v", err)
	}
	if w, _ := r.c.Worker(evil.ID); w.Mailbox != "" {
		t.Fatal("the attacker's worker recorded the victim's mailbox")
	}
	r.edge.deliver(vmb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Victim secret"})
	for range 4 {
		r.pass()
	}
	if len(r.threads(evil.ID)) != 0 || len(r.threads(victim.ID)) != 1 {
		t.Fatalf("victim threads %d, attacker threads %d", len(r.threads(victim.ID)), len(r.threads(evil.ID)))
	}

	// Keys that aren't the mailbox's at the edge are refused before anything
	// records them, even for a mailbox nobody holds.
	fresh := newMailbox(t, "new@fountbox.com")
	r.edge.register(fresh)
	forged := fresh
	forged.SigningKey = newMailbox(t, "x@fountbox.com").SigningKey
	s.Mailbox = forged
	sealed, _ = SealMailSetup(dek, evil.ID, s)
	if err := r.c.SetUpMail(anyDevice, evil.ID, sealed); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a setup with keys the edge refuses: %v", err)
	}
	if w, _ := r.c.Worker(evil.ID); w.Mailbox != "" {
		t.Fatal("recorded a mailbox whose keys the edge refused")
	}
}

// C1: a volume where two workers claim one mailbox gives its mail to neither.
func TestTwoWorkersClaimingAMailboxGetNeither(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	victim, vmb := r.worker()
	dek := mustDEK(t)
	evil, _ := r.c.CreateWorker("acct_evil", &dek)
	r.c.mu.Lock()
	r.c.state.Workers[evil.ID].Mailbox = vmb.MailboxID
	r.c.mu.Unlock()
	if _, ok := r.c.mailWorkers()[vmb.MailboxID]; ok {
		t.Fatal("a mailbox two workers claim went to one of them")
	}
	_ = victim
}
