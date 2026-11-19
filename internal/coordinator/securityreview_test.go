package coordinator

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
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

// H3: whoever accepts an admin invite gets a device that, before the fix,
// signed a list at once dropping every other admin.
func TestARecordAdmittedDeviceSignsNoListUntilAListIncludesIt(t *testing.T) {
	f := newTeamFixture(t)
	secret := make([]byte, InviteSecretSize)
	rand.Read(secret)
	commit, _ := InviteCommit("acme", "m_ann", "i_ann", secret)
	f.tt.members["m_ann"] = ListMember{ID: "m_ann", Email: "ann@firm.com", Role: RoleAdmin,
		Invite: &ListInvite{ID: "i_ann", Commit: commit, Exp: time.Now().Add(time.Hour).Unix()}}
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	eve := newTestDevice(t)
	seq, _ := f.tt.head()
	if _, err := f.c.AcceptInvite(withEmail(eve.caller("eve_acct"), "ann@firm.com"), "acme", "i_ann", "m_ann", secret, eve.include(t, "acme", "eve_acct", seq+1)); err != nil {
		t.Fatal(err)
	}
	// The new device reaches the workers at once.
	if _, _, err := f.c.access(eve.caller("eve_acct"), f.w1.ID, RoleAdmin); err != nil {
		t.Fatalf("the invited admin can't reach the worker: %v", err)
	}
	takeover := newTestTeam(t, f.c, "acme")
	takeover.workers = f.tt.workers
	takeover.set("m_ann", "eve_acct", RoleAdmin, eve)
	takeover.since[eve.id()] = seq + 1
	if err := takeover.push(eve, "eve_acct", nil); !errors.Is(err, ErrNotAdmin) {
		t.Fatalf("a record-admitted device's takeover list: %v", err)
	}
	if _, _, err := f.c.access(f.owner.caller("acme"), f.w1.ID, RoleReviewer); err != nil {
		t.Fatalf("the owner lost access: %v", err)
	}

	// Once an admin's list includes it, it's an admin like any other.
	f.tt.set("m_ann", "eve_acct", RoleAdmin, eve)
	f.tt.since[eve.id()] = seq + 1
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.tt.push(eve, "eve_acct", nil); err != nil {
		t.Fatalf("a listed admin device: %v", err)
	}
}

// H6: a DEK holder (a reviewer, or a removed member) with the bucket opened
// the worker's mailbox.json, and so its address keys.
func TestTheDEKAloneDoesntOpenTheAddressKeys(t *testing.T) {
	v := newVaultRig(t, nil)
	c := v.boot(t.TempDir())
	dek, _ := NewDEK()
	w, err := c.CreateWorker("acct1", &dek)
	if err != nil {
		t.Fatal(err)
	}
	mb := Mailbox{Address: "ap@fountbox.com", MailboxID: hex.EncodeToString(seq(0x81)), SigningKey: seq(0x01), DecryptionKey: seq(0x21)}
	if err := c.SetMailbox(w.ID, mb, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Backup(context.Background()); err != nil {
		t.Fatal(err)
	}
	keys, _ := v.bucket.List(context.Background(), backupObjectPrefix+w.ID+"/")
	opened := 0
	for _, k := range keys {
		sealed, _ := v.bucket.Get(context.Background(), k)
		obj := k[strings.LastIndex(k, "/")+1:]
		plain, err := open(dek[:], sealed, aad(purposeBlob, w.ID, obj))
		if err != nil {
			continue
		}
		opened++
		if bytes.Contains(plain, []byte(`"signingKey"`)) || bytes.Contains(plain, []byte(mb.MailboxID)) {
			t.Fatalf("the DEK alone opened the address keys in %s", k)
		}
	}
	if opened == 0 {
		t.Fatal("opened no object with the DEK: the test isn't looking")
	}
	// The coordinator still reads them, from its tree and from the backup.
	err = c.view(w.ID, anyDevice, func(t *Tree) error {
		got, err := loadMailbox(t)
		if err == nil && got.MailboxID != mb.MailboxID {
			err = errors.New("another mailbox")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// H6: a mailbox.json from before is sealed once the mail loop prepares it.
func TestALegacyMailboxIsSealedOnPrepare(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	w, mb := r.worker()
	plain, _ := json.Marshal(mb)
	if err := r.c.change(w.ID, anyDevice, func(t *Tree) error { return t.Write(mailboxPath, plain) }); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.prepareMail(w); err != nil {
		t.Fatal(err)
	}
	r.c.view(w.ID, anyDevice, func(tr *Tree) error {
		if mailboxLegacy(tr) {
			t.Error("still under the DEK alone")
		}
		return nil
	})
}
