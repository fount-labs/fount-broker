package coordinator

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fount-labs/fount-broker/internal/mail"
)

// A Cloud worker's reply tokens are a MAC under the coordinator's own token
// key (decision 25), so:
//   - the address signing seed, which every admin device can unwrap, mints no
//     token that matches, so a removed admin can't forge one;
//   - rotating the signing key keeps no old seed and every thread's token;
//   - the key is in no stored record.
func TestReplyTokensComeFromTheCoordinatorsKey(t *testing.T) {
	r := genRig(t, MailConfig{})
	w, mb := r.worker()
	first := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Q3"})
	r.pass()
	waitJob(t, r.c, mailJobID(first))
	th := onlyThread(t, r.threads(w.ID))

	keys, err := r.c.mailKeys(&mb)
	if err != nil {
		t.Fatal(err)
	}
	token, err := mail.MintReplyToken(keys, th.Handle)
	if err != nil {
		t.Fatal(err)
	}
	// What a device holding the address keys computes: the old scheme, from
	// the signing seed.
	seedOnly, _ := mb.keys()
	forged, err := mail.MintReplyToken(seedOnly, th.Handle)
	if err != nil {
		t.Fatal(err)
	}
	if forged == token {
		t.Fatal("the signing seed mints the coordinator's token")
	}
	if got := mail.CheckReplyToken(keys, "ap+"+token+"@fountbox.com"); got == nil || got.Handle != th.Handle {
		t.Fatalf("the token doesn't verify with the token key: %+v", got)
	}
	if got := mail.CheckReplyToken(keys, "ap+"+forged+"@fountbox.com"); got == nil || got.Handle != "" {
		t.Fatalf("a seed-minted token verifies: %+v", got)
	}
	// Another coordinator's wrapping key is another token key.
	other := &Coordinator{}
	other.cfg.Key, _ = NewWrappingKey()
	if bytes.Equal(other.tokenKey(mb.MailboxID), keys.TokenKey) {
		t.Fatal("the token key doesn't depend on the wrapping key")
	}

	// The team loses an admin, and the worker's signing key rotates.
	r.c.mu.Lock()
	r.c.state.Teams["t_rot"] = &Team{ID: "t_rot", Rotate: []string{w.ID}}
	r.c.mu.Unlock()
	r.pass()
	var stored Mailbox
	var raw []byte
	err = r.c.view(w.ID, anyDevice, func(t *Tree) error {
		m, err := loadMailbox(t)
		if err != nil {
			return err
		}
		stored = *m
		raw, err = t.Read(mailboxPath)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Equal(stored.SigningKey, mb.SigningKey) {
		t.Fatal("the signing key didn't rotate")
	}
	if strings.Contains(string(raw), "replySeed") || bytes.Contains(raw, keys.TokenKey) || strings.Contains(string(raw), base64.StdEncoding.EncodeToString(keys.TokenKey)) {
		t.Fatalf("the mailbox record keeps a token key or an old seed: %s", raw)
	}
	after, _ := r.c.mailKeys(&stored)
	if again, _ := mail.MintReplyToken(after, th.Handle); again != token {
		t.Fatal("rotating the signing key changed the thread's token")
	}

	// Old threads' replies still match after the rotation; the forged token
	// starts a thread of its own.
	reply := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr, recipient: "ap+" + token + "@fountbox.com", subject: "Re: Q3"})
	forgedReply := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr, recipient: "ap+" + forged + "@fountbox.com", subject: "Re: Q3"})
	r.pass()
	l := r.ledger(w.ID)
	if a := l.Acted[reply]; a.Thread != th.ID {
		t.Fatalf("the reply after the rotation: %+v", a)
	}
	if a := l.Acted[forgedReply]; a.Thread == th.ID || a.Thread == "" {
		t.Fatalf("a token from the old signing seed joined the thread: %+v", a)
	}
}

// teamInviteRig is a sending rig whose coordinator has a team, "acme", with a
// worker that has an address, and ann@firm.com invited, who isn't an owner.
type teamInviteRig struct {
	*sendRig
	owner  testDevice
	tt     *testTeam
	team   Worker
	teamMB Mailbox
}

func newTeamInviteRig(t *testing.T) *teamInviteRig {
	t.Helper()
	r := &teamInviteRig{sendRig: sendRigOn(t, genRig(t, MailConfig{Send: true}), modeNotify), owner: newTestDevice(t)}
	r.tt = soloTeam(t, r.c, "acme", r.owner)
	w, err := r.tt.addWorker(r.owner, "acme", mustDEK(t))
	if err != nil {
		t.Fatal(err)
	}
	r.teamMB = newMailbox(t, "team@fountbox.com")
	r.edge.register(r.teamMB)
	if err := r.c.SetMailbox(w.ID, r.teamMB, nil); err != nil {
		t.Fatal(err)
	}
	r.team, _ = r.c.Worker(w.ID)
	r.send.mu.Lock()
	r.send.strangers["ann@firm.com"], r.send.strangers["bo@firm.com"] = true, true
	r.send.mu.Unlock()
	return r
}

// invite lists email as member with an open invite, and returns its secret.
func (r *teamInviteRig) invite(member, email string) []byte {
	r.t.Helper()
	secret := make([]byte, InviteSecretSize)
	rand.Read(secret)
	commit, err := InviteCommit("acme", member, "i_"+member, secret)
	if err != nil {
		r.t.Fatal(err)
	}
	r.tt.members[member] = ListMember{ID: member, Email: email, Role: RoleReviewer, Workers: []string{allWorkers},
		Invite: &ListInvite{ID: "i_" + member, Commit: commit, Exp: time.Now().Add(24 * time.Hour).Unix()}}
	if err := r.tt.push(r.owner, "acme", nil); err != nil {
		r.t.Fatal(err)
	}
	return secret
}

// settle runs passes until the send record leaves "sending".
func (r *teamInviteRig) settle(id string) *sendRecord {
	r.t.Helper()
	var rec *sendRecord
	for range 5 {
		r.pass()
		err := r.c.view(r.team.ID, anyDevice, func(t *Tree) (err error) {
			rec, err = loadSend(t, id)
			return err
		})
		if err != nil {
			r.t.Fatal(err)
		}
		if rec.State != sendSending {
			return rec
		}
	}
	r.t.Fatalf("the invite is still sending: %+v", rec)
	return nil
}

// An invite to someone who isn't an owner goes on the edge's coordinator
// route, signed by the generation key, and is sent; /send would refuse them.
// The send record finds it through /sent/query and posts it once.
func TestAnInviteGoesOnTheCoordinatorRoute(t *testing.T) {
	r := newTeamInviteRig(t)
	secret := r.invite("m_ann", "ann@firm.com")
	id, err := r.c.SendInvite(r.owner.caller("acme"), "acme", "i_m_ann", "m_ann", secret, "")
	if err != nil {
		t.Fatal(err)
	}
	rec := r.settle(id)
	if rec.Kind != sendKindInvite || rec.State != sendSent || len(rec.Delivery) != 1 || rec.Delivery[0].Address != "ann@firm.com" {
		t.Fatalf("the invite's record: %+v", rec)
	}
	sent := r.send.sentTo("ann@firm.com", "Join")
	if len(sent) != 1 || !r.send.invites[sent[0]] || r.send.count(r.send.delivered, sent[0]) != 1 {
		t.Fatalf("sent %v", sent)
	}
	if !slices.Contains(r.edge.coord.Calls(), "POST /coordinator/invite") {
		t.Fatalf("calls %v", r.edge.coord.Calls())
	}
	raw := string(r.send.raw[sent[0]])
	if !strings.Contains(raw, "Content-Type: text/plain") || !strings.Contains(raw, InviteLink+"fi1.acme.m_ann.i_m_ann.") {
		t.Fatalf("the invite:\n%s", raw)
	}
	// Asking again finds the record: nothing more is posted.
	if again, err := r.c.SendInvite(r.owner.caller("acme"), "acme", "i_m_ann", "m_ann", secret, ""); err != nil || again != id {
		t.Fatalf("again: %s %v", again, err)
	}
	r.pass()
	if r.send.count(r.send.posts, sent[0]) != 1 {
		t.Fatal("the invite was posted twice")
	}
}

// Past the edge's invites for the day, the record fails with the send limit,
// and the admin copies the link instead.
func TestAnInvitePastTheLimitFails(t *testing.T) {
	r := newTeamInviteRig(t)
	secret := r.invite("m_bo", "bo@firm.com")
	r.edge.coord.UseInvites(r.teamMB.MailboxID, 20)
	id, err := r.c.SendInvite(r.owner.caller("acme"), "acme", "i_m_bo", "m_bo", secret, "")
	if err != nil {
		t.Fatal(err)
	}
	rec := r.settle(id)
	if rec.State != sendFailed || rec.Error == nil || rec.Error.Code != CodeSendLimit {
		t.Fatalf("past the limit: %+v", rec)
	}
	if len(r.send.sentTo("bo@firm.com", "")) != 0 {
		t.Fatal("an invite past the limit went out")
	}
}

// Without the invite route, an email to someone who isn't an owner is still
// refused: the notice path's /send.
func TestANoticeToAStrangerIsRefused(t *testing.T) {
	r := newTeamInviteRig(t)
	err := r.c.change(r.team.ID, anyDevice, func(t *Tree) error {
		mb, err := loadMailbox(t)
		if err != nil {
			return err
		}
		rec := &sendRecord{ID: "snd_stranger", Kind: sendKindNotice, Attempt: 1, State: sendSending, To: []string{"ann@firm.com"},
			MessageID: "<fm.stranger@fountbox.com>"}
		raw, err := r.c.buildOut(t, nil, mb, rec, nil, "Hello", "", nil, "Hi.\n", nil, time.Now().UTC())
		if err != nil {
			return err
		}
		_, err = r.c.stageSend(t, r.team.ID, rec, raw)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := r.settle("snd_stranger")
	if rec.State != sendFailed || rec.Error.Code != CodeRecipientNotAllowed {
		t.Fatalf("a notice to a stranger: %+v", rec)
	}
}
