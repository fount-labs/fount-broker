package coordinator

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"
)

// invited lists ann@firm.com as m_ann with an open invite, and returns its
// secret.
func (f teamFixture) invited(t *testing.T, exp time.Time) []byte {
	t.Helper()
	secret := make([]byte, InviteSecretSize)
	rand.Read(secret)
	commit, err := InviteCommit("acme", "m_ann", "i_ann", secret)
	if err != nil {
		t.Fatal(err)
	}
	f.tt.members["m_ann"] = ListMember{ID: "m_ann", Email: "ann@firm.com", Role: RoleReviewer, Workers: []string{allWorkers},
		Invite: &ListInvite{ID: "i_ann", Commit: commit, Exp: exp.Unix()}}
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	return secret
}

func withEmail(c Caller, email string) Caller {
	c.Email = email
	return c
}

func TestAnInviteWorksOnlyWithItsSecretOnceForItsEmail(t *testing.T) {
	f := newTeamFixture(t)
	secret := f.invited(t, time.Now().Add(time.Hour))
	ann, eve := newTestDevice(t), newTestDevice(t)
	seq, _ := f.tt.head()
	accept := func(d testDevice, account, email string, secret []byte, since uint64) error {
		_, err := f.c.AcceptInvite(withEmail(d.caller(account), email), "acme", "i_ann", "m_ann", secret, d.include(t, "acme", account, since))
		return err
	}
	wrong := make([]byte, InviteSecretSize)
	for _, tc := range []struct {
		name          string
		account, mail string
		secret        []byte
	}{
		{"another secret", "ann", "ann@firm.com", wrong},
		{"a short secret", "ann", "ann@firm.com", secret[:16]},
		{"no verified email", "ann", "", secret},
		{"another email", "ann", "eve@firm.com", secret},
		{"a differently cased email", "ann", "Ann@firm.com", secret},
	} {
		if err := accept(ann, tc.account, tc.mail, tc.secret, seq+1); !errors.Is(err, ErrListRefused) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	if _, err := f.c.OpenInvite(withEmail(ann.caller("ann"), "ann@firm.com"), "acme", "i_ann", "m_ann", wrong); err == nil {
		t.Error("opened with another secret")
	}
	v, err := f.c.OpenInvite(withEmail(ann.caller("ann"), "ann@firm.com"), "acme", "i_ann", "m_ann", secret)
	if err != nil || v.Email != "ann@firm.com" || v.Role != RoleReviewer || v.Log.Seq != seq {
		t.Fatalf("open: %v %+v", err, v)
	}
	if s, _ := f.tt.head(); s != seq {
		t.Fatalf("a refused invite moved the log to %d", s)
	}
	if err := accept(ann, "ann", "ann@firm.com", secret, seq+1); err != nil {
		t.Fatal(err)
	}
	if _, role, err := f.c.access(ann.caller("ann"), f.w1.ID, RoleReviewer); err != nil || role != RoleReviewer {
		t.Fatalf("ann after her invite: %v %s", err, role)
	}
	for _, w := range []Worker{f.w1, f.w2} {
		if w, _ := f.c.Worker(w.ID); !slices.ContainsFunc(w.Devices, func(d Device) bool { return d.ID == ann.id() }) {
			t.Errorf("ann has no wrap on %s", w.ID)
		}
	}
	// Once: not again, by anyone, with the secret and the email.
	if err := accept(eve, "eve", "ann@firm.com", secret, seq+2); !errors.Is(err, ErrListRefused) {
		t.Errorf("the invite taken twice: %v", err)
	}
	if _, err := f.c.OpenInvite(withEmail(eve.caller("eve"), "ann@firm.com"), "acme", "i_ann", "m_ann", secret); err == nil {
		t.Error("a used invite opened")
	}
	// The record any client checks carries the proof; one rewritten for
	// another email doesn't replay.
	f.c.mu.Lock()
	log := slices.Clone(f.c.state.Teams["acme"].Log)
	f.c.mu.Unlock()
	if _, err := reduceTeam("acme", testAudience, log); err != nil {
		t.Fatalf("the log with the record: %v", err)
	}
	last := log[len(log)-1]
	var r TeamRecord
	json.Unmarshal(last.Record, &r)
	r.Proof, _ = json.Marshal(InviteProof{Invite: "i_ann", Secret: b64.EncodeToString(secret), Email: "eve@firm.com"})
	last.Record, _ = json.Marshal(r)
	last.Hash = entryHash(TeamRecordContext, last.Record)
	if _, err := reduceTeam("acme", testAudience, append(log[:len(log)-1:len(log)-1], last)); err == nil {
		t.Error("a record for another email replayed")
	}
}

func TestAnInviteDoesntWorkAfterItExpires(t *testing.T) {
	f := newTeamFixture(t)
	secret := f.invited(t, time.Now().Add(time.Hour))
	ann := newTestDevice(t)
	f.c.mu.Lock()
	st, _ := f.c.teamState("acme")
	_, now := checkInvite(st, "acme", "m_ann", "i_ann", secret, withEmail(ann.caller("ann"), "ann@firm.com"), time.Now())
	_, later := checkInvite(st, "acme", "m_ann", "i_ann", secret, withEmail(ann.caller("ann"), "ann@firm.com"), time.Now().Add(61*time.Minute))
	m := st.byID["m_ann"]
	proof, _ := json.Marshal(InviteProof{Invite: "i_ann", Secret: b64.EncodeToString(secret), Email: "ann@firm.com"})
	late := checkInviteProof(st, "acme", TeamRecord{At: m.Invite.Exp, Proof: proof}, m)
	inTime := checkInviteProof(st, "acme", TeamRecord{At: m.Invite.Exp - 1, Proof: proof}, m)
	f.c.mu.Unlock()
	if now != nil || inTime != nil {
		t.Fatalf("in time: %v %v", now, inTime)
	}
	if !errors.Is(later, ErrListRefused) || late == nil {
		t.Errorf("after it expired: %v %v", later, late)
	}
}

func TestASecondDeviceJoinsWithAListedDevicesApproval(t *testing.T) {
	f := newTeamFixture(t)
	phone := newTestDevice(t)
	key, enc := phone.pub(), phone.enc.PublicKey().Bytes()
	if _, err := f.c.StartJoin(newTestDevice(t).caller("maria"), "acme", key, enc); err == nil {
		t.Error("a device asked to join with another's key")
	}
	if _, err := f.c.StartJoin(phone.caller("nobody"), "acme", key, enc); !errors.Is(err, ErrNoTeam) {
		t.Errorf("an account that isn't a member: %v", err)
	}
	st, err := f.c.StartJoin(phone.caller("maria"), "acme", key, enc)
	if err != nil || st.State != "waiting" || st.Member != "m_reviewer" {
		t.Fatalf("start: %v %+v", err, st)
	}
	nonce, _ := b64.DecodeString(st.Nonce)
	if mine, _ := f.c.PendingJoins(f.reviewer.caller("maria"), "acme"); len(mine) != 1 || mine[0].Join != st.Join ||
		JoinCode(st.Join, nonce, key, enc) != JoinCode(mine[0].Join, nonce, key, enc) {
		t.Fatalf("maria's pending joins: %+v", mine)
	}
	if theirs, _ := f.c.PendingJoins(f.owner.caller("acme"), "acme"); len(theirs) != 0 {
		t.Errorf("another member sees maria's request: %+v", theirs)
	}
	seq, _ := f.tt.head()
	if _, err := f.c.AcceptJoin(phone.caller("maria"), "acme", st.Join, phone.include(t, "acme", "maria", seq+1)); !errors.Is(err, ErrListRefused) {
		t.Errorf("accepted before approval: %v", err)
	}
	msg, _ := JoinMessage(testAudience, "acme", "m_reviewer", st.Join, nonce, key, enc)
	if err := f.c.ApproveJoin(f.owner.caller("acme"), "acme", st.Join, ed25519.Sign(f.owner.key, msg)); !errors.Is(err, ErrNotFound) {
		t.Errorf("another member approved: %v", err)
	}
	other, _ := JoinMessage(testAudience, "acme", "m_reviewer", st.Join, nonce, key, make([]byte, 32))
	if err := f.c.ApproveJoin(f.reviewer.caller("maria"), "acme", st.Join, ed25519.Sign(f.reviewer.key, other)); !errors.Is(err, ErrListRefused) {
		t.Errorf("an approval of other keys: %v", err)
	}
	if err := f.c.ApproveJoin(f.reviewer.caller("maria"), "acme", st.Join, ed25519.Sign(f.reviewer.key, msg)); err != nil {
		t.Fatal(err)
	}
	if got, err := f.c.JoinStatusOf(phone.caller("maria"), "acme", st.Join); err != nil || got.State != "approved" || got.Seq != seq {
		t.Fatalf("status: %v %+v", err, got)
	}
	// The inclusion must carry the approved keys.
	if _, err := f.c.AcceptJoin(phone.caller("maria"), "acme", st.Join, newTestDevice(t).include(t, "acme", "maria", seq+1)); err == nil {
		t.Error("accepted with another device's inclusion")
	}
	if _, err := f.c.AcceptJoin(phone.caller("maria"), "acme", st.Join, phone.include(t, "acme", "maria", seq+1)); err != nil {
		t.Fatal(err)
	}
	if _, role, err := f.c.access(phone.caller("maria"), f.w1.ID, RoleReviewer); err != nil || role != RoleReviewer {
		t.Fatalf("maria's phone: %v %s", err, role)
	}
	if _, err := f.c.JoinStatusOf(phone.caller("maria"), "acme", st.Join); !errors.Is(err, ErrNotFound) {
		t.Errorf("the request outlived its record: %v", err)
	}
	// The log replays: the record's proof checks against the state before it.
	f.c.mu.Lock()
	log := slices.Clone(f.c.state.Teams["acme"].Log)
	f.c.mu.Unlock()
	if _, err := reduceTeam("acme", testAudience, log); err != nil {
		t.Fatalf("the log with the join: %v", err)
	}
	last := log[len(log)-1]
	var r TeamRecord
	json.Unmarshal(last.Record, &r)
	var p JoinProof
	json.Unmarshal(r.Proof, &p)
	p.Approver = f.owner.id()
	r.Proof, _ = json.Marshal(p)
	last.Record, _ = json.Marshal(r)
	last.Hash = entryHash(TeamRecordContext, last.Record)
	if _, err := reduceTeam("acme", testAudience, append(log[:len(log)-1:len(log)-1], last)); err == nil {
		t.Error("a join approved by another member's device replayed")
	}
}

func TestARemovedMembersDeviceIsRefused(t *testing.T) {
	f := newTeamFixture(t)
	if _, _, err := f.c.access(f.reviewer.caller("maria"), f.w1.ID, RoleReviewer); err != nil {
		t.Fatal(err)
	}
	f.tt.drop("m_reviewer")
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.c.access(f.reviewer.caller("maria"), f.w1.ID, RoleReviewer); !errors.Is(err, ErrNoWorker) {
		t.Errorf("a removed member: %v", err)
	}
	for _, w := range []Worker{f.w1, f.w2} {
		if w, _ := f.c.Worker(w.ID); slices.ContainsFunc(w.Devices, func(d Device) bool { return d.ID == f.reviewer.id() }) {
			t.Errorf("the removed member keeps a wrap on %s", w.ID)
		}
	}
	if _, err := f.c.StartJoin(newTestDevice(t).caller("maria"), "acme", nil, nil); err == nil {
		t.Error("a removed member's account asked to join")
	}
}

func TestAReviewerCantRemove(t *testing.T) {
	f := newTeamFixture(t)
	f.tt.drop("m_admin")
	if err := f.tt.push(f.reviewer, "maria", nil); !errors.Is(err, ErrNotAdmin) {
		t.Errorf("a reviewer's list: %v", err)
	}
	if _, _, err := f.c.access(f.admin.caller("dev"), f.w1.ID, RoleAdmin); err != nil {
		t.Errorf("the admin after a reviewer's attempt: %v", err)
	}
}

// Removing an admin marks the team's workers (members_test), and the mail
// pass rotates each one's address key at the edge, then keeps the old seed
// for reply tokens. A retry after a lost answer finishes with the same key.
func TestARotationReplacesTheAddressKeyAtTheEdge(t *testing.T) {
	r := genRig(t, MailConfig{})
	w, mb := r.worker()
	r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr})
	r.pass()
	mark := func() {
		r.c.mu.Lock()
		r.c.state.Teams["t_rot"] = &Team{ID: "t_rot", Rotate: []string{w.ID}}
		r.c.mu.Unlock()
	}
	stored := func() Mailbox {
		var out Mailbox
		err := r.c.view(w.ID, anyDevice, func(t *Tree) error {
			m, err := loadMailbox(t)
			if m != nil {
				out = *m
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	rotated := func() bool {
		r.c.mu.Lock()
		defer r.c.mu.Unlock()
		return len(r.c.state.Teams["t_rot"].Rotate) == 0
	}
	first := stored().SigningKey
	mark()
	r.pass()
	got := stored()
	at := r.edge.coord.Mailbox(mb.MailboxID).SigningKey
	if !rotated() || slices.Equal(got.SigningKey, first) || !slices.Equal(got.ReplySeed, first) || got.NextSigningKey != nil {
		t.Fatalf("after the rotation: %v %+v", rotated(), got)
	}
	if !at.Equal(ed25519.NewKeyFromSeed(got.SigningKey).Public()) {
		t.Fatal("the edge has another key")
	}
	// The new key reads mail.
	id := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "after"})
	r.pass()
	if r.ledger(w.ID).Acted[id].Outcome == "" {
		t.Fatal("mail after the rotation wasn't read")
	}
	// The edge took the next key, and its answer was lost.
	next := make([]byte, ed25519.SeedSize)
	rand.Read(next)
	if err := r.c.mail.service.RotateSigningKey(context.Background(), mb.MailboxID, ed25519.NewKeyFromSeed(next)); err != nil {
		t.Fatal(err)
	}
	err := r.c.change(w.ID, anyDevice, func(t *Tree) error {
		m, err := loadMailbox(t)
		if err != nil {
			return err
		}
		m.NextSigningKey = next
		return writeJSON(t, mailboxPath, m)
	})
	if err != nil {
		t.Fatal(err)
	}
	mark()
	r.pass()
	if got := stored(); !rotated() || !slices.Equal(got.SigningKey, next) || !slices.Equal(got.ReplySeed, first) {
		t.Fatalf("the retry: %v %+v", rotated(), got)
	}
}

func TestAClaimLabelsTheDraftAndExpires(t *testing.T) {
	r := newSendRig(t, modeFull)
	th, e := r.drafted()
	op := func(kind, opID string) OpResult {
		th, _ := r.c.thread(anyDevice, r.w.ID, th.ID)
		raw, _ := json.Marshal(map[string]string{"draftId": e.ID})
		res, err := r.c.applyThreadOp(anyDevice, r.w.ID, th.ID, opEnvelope{OpID: opID, ThreadID: th.ID, BaseRevision: th.Revision, Kind: kind, Args: raw})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	before := time.Now()
	if res := op("claimDraft", "op_claim"); !res.OK {
		t.Fatalf("claim: %+v", res)
	}
	cl := r.draft(th.ID, e.ID).Claim
	if cl == nil || cl.By == "" || cl.ExpiresAt.Before(before.Add(claimLifetime)) || cl.ExpiresAt.After(time.Now().Add(claimLifetime)) {
		t.Fatalf("the claim: %+v", cl)
	}
	shown, _ := r.c.thread(anyDevice, r.w.ID, th.ID)
	hideExpiredClaims(shown, time.Now())
	if shown.entry(e.ID).Draft.Claim == nil {
		t.Error("a claim in force was hidden")
	}
	hideExpiredClaims(shown, time.Now().Add(claimLifetime+time.Second))
	if shown.entry(e.ID).Draft.Claim != nil {
		t.Error("a claim outlived its time")
	}
	if res := op("releaseClaim", "op_release"); !res.OK || r.draft(th.ID, e.ID).Claim != nil {
		t.Fatalf("release: %+v", res)
	}
	// A claim blocks nothing: the draft is approved under one.
	op("claimDraft", "op_claim2")
	th, _ = r.c.thread(anyDevice, r.w.ID, th.ID)
	if res := r.approve(th, e, "op_approve", e.Draft.DraftRev); !res.OK {
		t.Fatalf("approve under a claim: %+v", res)
	}
}
