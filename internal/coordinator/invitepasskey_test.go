package coordinator

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// invitePasskey is p's accept of invite as member, from d: its passkey and
// its assertion over InvitePasskeyChallenge.
func (p testPasskey) invitePasskey(t *testing.T, team, member, invite string, d testDevice, o ceremony) InvitePasskey {
	t.Helper()
	ch, err := InvitePasskeyChallenge(testAudience, team, member, invite, d.pub(), d.enc.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return p.invitePasskeyOver(t, ch, o)
}

func (p testPasskey) invitePasskeyOver(t *testing.T, challenge []byte, o ceremony) InvitePasskey {
	t.Helper()
	a := p.assertRaw(t, challenge, o)
	return InvitePasskey{Rec: p.rec(t), AuthenticatorData: b64.EncodeToString(a.AuthenticatorData),
		ClientDataJSON: b64.EncodeToString(a.ClientDataJSON), Signature: b64.EncodeToString(a.Signature)}
}

// inviteRig is acme with ann@firm.com invited as m_ann, and her computer.
type inviteRig struct {
	f      teamFixture
	secret []byte
	ann    testDevice
}

func newInviteRig(t *testing.T) *inviteRig {
	t.Helper()
	f := newTeamFixture(t)
	return &inviteRig{f: f, secret: f.invited(t, time.Now().Add(time.Hour)), ann: newTestDevice(t)}
}

func (r *inviteRig) accept(t *testing.T, d testDevice, pk InvitePasskey) error {
	t.Helper()
	seq, _ := r.f.tt.head()
	_, err := r.f.c.AcceptInvite(withEmail(d.caller("ann"), "ann@firm.com"), "acme", "i_ann", "m_ann", r.secret, d.include(t, "acme", "ann", seq+1), pk)
	return err
}

func (r *inviteRig) log() []TeamEntry {
	r.f.c.mu.Lock()
	defer r.f.c.mu.Unlock()
	return slices.Clone(r.f.c.state.Teams["acme"].Log)
}

func (r *inviteRig) member(t *testing.T, id string) *Member {
	t.Helper()
	r.f.c.mu.Lock()
	defer r.f.c.mu.Unlock()
	st, err := r.f.c.teamState("acme")
	if err != nil {
		t.Fatal(err)
	}
	return st.byID[id]
}

// passkeyJoinAs is a passkey join of d as ann with p.
func (r *inviteRig) passkeyJoinAs(t *testing.T, d testDevice, p testPasskey, o ceremony) error {
	t.Helper()
	ch, err := r.f.c.StartPasskeyJoin(d.caller("ann"), "acme", d.pub(), d.enc.PublicKey().Bytes())
	if err != nil {
		return err
	}
	_, err = r.f.c.PasskeyJoin(d.caller("ann"), "acme", p.request(t, ch, mustB64(t, ch.Challenge), d, "acme", "ann", o))
	return err
}

// The passkey made on accepting an invite is the member's: the record lists
// it, every replay checks its assertion, and it adds the member's next
// computer with no other device.
func TestAcceptingAnInviteListsThePasskeyThatAddsTheNextComputer(t *testing.T) {
	r := newInviteRig(t)
	pk := newTestPasskey(t)
	if err := r.accept(t, r.ann, InvitePasskey{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an accept with no passkey: %v", err)
	}
	if err := r.accept(t, r.ann, pk.invitePasskey(t, "acme", "m_ann", "i_ann", r.ann, ceremony{count: 5})); err != nil {
		t.Fatal(err)
	}
	if m := r.member(t, "m_ann"); m.Rec == nil || *m.Rec != *pk.rec(t) {
		t.Fatalf("ann's passkey after her invite: %+v", m.Rec)
	}
	if _, err := reduceTeam("acme", testAudience, r.log()); err != nil {
		t.Fatalf("the log replays: %v", err)
	}
	f := r.f
	if got := f.c.Memberships(newTestDevice(t).caller("ann")); len(got) != 1 || !got[0].Passkey || got[0].Rec == nil || *got[0].Rec != *pk.rec(t) {
		t.Fatalf("ann's memberships: %+v", got)
	}

	// Her next computer, with that passkey: its count must rise past the
	// invite's.
	laptop := newTestDevice(t)
	if err := r.passkeyJoinAs(t, laptop, pk, ceremony{count: 5}); !errors.Is(err, ErrListRefused) {
		t.Fatalf("a passkey join whose count didn't rise past the invite's: %v", err)
	}
	if err := r.passkeyJoinAs(t, laptop, newTestPasskey(t), ceremony{}); !errors.Is(err, ErrListRefused) {
		t.Fatalf("another passkey: %v", err)
	}
	if err := r.passkeyJoinAs(t, laptop, pk, ceremony{count: 6}); err != nil {
		t.Fatalf("her next computer: %v", err)
	}
	if _, role, err := f.c.access(laptop.caller("ann"), f.w1.ID, RoleReviewer); err != nil || role != RoleReviewer {
		t.Fatalf("her next computer's access: %v %s", err, role)
	}
	if _, err := reduceTeam("acme", testAudience, r.log()); err != nil {
		t.Fatalf("the log replays: %v", err)
	}

	// An admin's next list carries her passkey on; one that names another
	// changes it, and only the new one adds a computer then.
	seq, _ := f.tt.head()
	f.tt.update("m_ann", func(m *ListMember) { m.Account, m.Invite, m.Rec = "ann", nil, pk.rec(t) })
	f.tt.devices["m_ann"] = []testDevice{r.ann, laptop}
	f.tt.since[r.ann.id()], f.tt.since[laptop.id()] = seq-1, seq
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	if m := r.member(t, "m_ann"); m.Rec == nil || *m.Rec != *pk.rec(t) {
		t.Fatalf("ann's passkey after the list: %+v", m.Rec)
	}
	other := newTestPasskey(t)
	f.tt.update("m_ann", func(m *ListMember) { m.Rec = other.rec(t) })
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	if err := r.passkeyJoinAs(t, newTestDevice(t), pk, ceremony{count: 9}); !errors.Is(err, ErrListRefused) {
		t.Fatalf("the replaced passkey: %v", err)
	}
	if err := r.passkeyJoinAs(t, newTestDevice(t), other, ceremony{}); err != nil {
		t.Fatalf("the admin's new passkey for ann: %v", err)
	}
}

// The passkey's assertion binds the invite, the member and the accepting
// device's keys, with a passkey join's strict checks; nothing else lists a
// passkey on an accept.
func TestAnInviteAcceptsOnlyAPasskeyAssertionOverItself(t *testing.T) {
	r := newInviteRig(t)
	pk := newTestPasskey(t)
	ch, _ := InvitePasskeyChallenge(testAudience, "acme", "m_ann", "i_ann", r.ann.pub(), r.ann.enc.PublicKey().Bytes())
	eve := newTestDevice(t)
	over := func(member, invite string, d testDevice) []byte {
		c, _ := InvitePasskeyChallenge(testAudience, "acme", member, invite, d.pub(), d.enc.PublicKey().Bytes())
		return c
	}
	good := pk.invitePasskeyOver(t, ch, ceremony{})
	with := func(f func(*InvitePasskey)) InvitePasskey {
		p := good
		rec := *good.Rec
		p.Rec = &rec
		f(&p)
		return p
	}
	unlisted := newTestPasskey(t)
	before, _ := r.f.tt.head()
	for name, p := range map[string]InvitePasskey{
		"another device's keys": pk.invitePasskeyOver(t, over("m_ann", "i_ann", eve), ceremony{}),
		"another invite":        pk.invitePasskeyOver(t, over("m_ann", "i_other", r.ann), ceremony{}),
		"another member":        pk.invitePasskeyOver(t, over("m_reviewer", "i_ann", r.ann), ceremony{}),
		"another rp":            pk.invitePasskeyOver(t, ch, ceremony{rpID: "evil.example"}),
		"another origin":        pk.invitePasskeyOver(t, ch, ceremony{origin: "https://evil.example"}),
		"no user verification":  pk.invitePasskeyOver(t, ch, ceremony{flags: 0x01}),
		"cross-origin":          pk.invitePasskeyOver(t, ch, ceremony{extra: map[string]any{"crossOrigin": true}}),
		"nested client data":    pk.invitePasskeyOver(t, ch, ceremony{extra: map[string]any{"tokenBinding": map[string]any{"status": "present"}}}),
		"another passkey's key": with(func(p *InvitePasskey) { p.Rec.Pub = unlisted.rec(t).Pub }),
		"a malformed key":       with(func(p *InvitePasskey) { p.Rec.Pub = b64.EncodeToString([]byte{4, 1, 2}) }),
		"no credential id":      with(func(p *InvitePasskey) { p.Rec.Cred = "" }),
		"no signature":          with(func(p *InvitePasskey) { p.Signature = "" }),
	} {
		if err := r.accept(t, r.ann, p); !errors.Is(err, ErrListRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if s, _ := r.f.tt.head(); s != before {
		t.Fatalf("a refused accept moved the log to %d", s)
	}
	if err := r.accept(t, r.ann, good); err != nil {
		t.Fatal(err)
	}

	// A record rewritten after the fact doesn't replay: another key listed
	// for the same assertion, or an assertion with no passkey named.
	log := r.log()
	last := log[len(log)-1]
	rewrite := func(f func(*InviteProof)) []TeamEntry {
		var rec TeamRecord
		json.Unmarshal(last.Record, &rec)
		var p InviteProof
		json.Unmarshal(rec.Proof, &p)
		f(&p)
		rec.Proof, _ = json.Marshal(p)
		e := last
		e.Record, _ = json.Marshal(rec)
		e.Hash = entryHash(TeamRecordContext, e.Record)
		return append(log[:len(log)-1:len(log)-1], e)
	}
	for name, l := range map[string][]TeamEntry{
		"another key":          rewrite(func(p *InviteProof) { p.Rec = unlisted.rec(t) }),
		"an assertion, no rec": rewrite(func(p *InviteProof) { p.Rec = nil }),
		"another client data":  rewrite(func(p *InviteProof) { p.ClientDataJSON = b64.EncodeToString([]byte(`{"type":"webauthn.get"}`)) }),
	} {
		if _, err := reduceTeam("acme", testAudience, l); err == nil {
			t.Errorf("%s: replayed", name)
		}
	}
	// One with no passkey at all, as before passkey-only joins, is refused.
	if _, err := reduceTeam("acme", testAudience, rewrite(func(p *InviteProof) { p.InvitePasskey = InvitePasskey{} })); err == nil || !strings.Contains(err.Error(), ErrInvitePasskey.Error()) {
		t.Fatalf("a record with no passkey: %v", err)
	}
}

// A member who lost their passkey and every computer is invited again: the
// list puts an open invite on the member they are, and accepting it with a
// new passkey lists that one. Only their own account can take it.
func TestAnExistingMemberInvitedAgainGetsBackInWithANewPasskey(t *testing.T) {
	r := newInviteRig(t)
	f := r.f
	lost := newTestPasskey(t)
	if err := r.accept(t, r.ann, lost.invitePasskey(t, "acme", "m_ann", "i_ann", r.ann, ceremony{})); err != nil {
		t.Fatal(err)
	}
	// The admin removes her lost computer, and the lost passkey that added
	// it (M4), and invites her again.
	secret := make([]byte, InviteSecretSize)
	copy(secret, "a new secret for ann, 32 bytes!!")
	commit, _ := InviteCommit("acme", "m_ann", "i_again", secret)
	f.tt.update("m_ann", func(m *ListMember) {
		m.Account, m.Rec = "ann", nil
		m.Invite = &ListInvite{ID: "i_again", Commit: commit, Exp: time.Now().Add(time.Hour).Unix()}
	})
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	seq, _ := f.tt.head()
	accept := func(d testDevice, account string, p testPasskey) error {
		_, err := f.c.AcceptInvite(withEmail(d.caller(account), "ann@firm.com"), "acme", "i_again", "m_ann", secret, d.include(t, "acme", account, seq+1),
			p.invitePasskey(t, "acme", "m_ann", "i_again", d, ceremony{}))
		return err
	}
	fresh, eve := newTestPasskey(t), newTestDevice(t)
	if err := accept(eve, "eve", fresh); !errors.Is(err, ErrListRefused) {
		t.Fatalf("another account with her email took her invite: %v", err)
	}
	desk := newTestDevice(t)
	if err := accept(desk, "ann", fresh); err != nil {
		t.Fatalf("ann invited again: %v", err)
	}
	m := r.member(t, "m_ann")
	if m.Rec == nil || *m.Rec != *fresh.rec(t) || m.Account != "ann" || m.Role != RoleReviewer || m.Invite != nil {
		t.Fatalf("ann after her second invite: %+v", m)
	}
	// Her old computer is removed; the one that took the invite is her only
	// one, and no other member's devices change.
	if len(m.Devices) != 1 || m.Devices[0].ID != desk.id() {
		t.Fatalf("ann's devices after her second invite: %+v", m.Devices)
	}
	if _, _, err := f.c.access(r.ann.caller("ann"), f.w1.ID, RoleReviewer); err == nil {
		t.Error("ann's old computer still reaches the team's workers")
	}
	if _, _, err := f.c.access(desk.caller("ann"), f.w1.ID, RoleReviewer); err != nil {
		t.Errorf("ann's new computer: %v", err)
	}
	if _, _, err := f.c.access(f.reviewer.caller("maria"), f.w1.ID, RoleReviewer); err != nil {
		t.Errorf("another member's device: %v", err)
	}
	if w, _ := f.c.Worker(f.w1.ID); slices.ContainsFunc(w.Devices, func(d Device) bool { return d.ID == r.ann.id() }) {
		t.Error("ann's old computer keeps a wrap")
	}
	st, err := reduceTeam("acme", testAudience, r.log())
	if err != nil {
		t.Fatalf("the log replays: %v", err)
	}
	if m := st.byID["m_ann"]; len(m.Devices) != 1 || st.byDevice[r.ann.id()] != nil || st.byDevice[f.reviewer.id()] == nil {
		t.Fatal("the replay keeps ann's old computer")
	}
	if err := r.passkeyJoinAs(t, newTestDevice(t), lost, ceremony{}); !errors.Is(err, ErrListRefused) {
		t.Fatalf("the lost passkey after the second invite: %v", err)
	}
	if err := r.passkeyJoinAs(t, newTestDevice(t), fresh, ceremony{}); err != nil {
		t.Fatalf("the new passkey: %v", err)
	}

	// A record binding her member to another account doesn't replay.
	f.c.mu.Lock()
	st, _ = f.c.teamState("acme")
	held := *st.byID["m_ann"]
	f.c.mu.Unlock()
	held.Invite = &ListInvite{ID: "i_again", Commit: commit, Exp: time.Now().Add(time.Hour).Unix()}
	proof, _ := json.Marshal(InviteProof{Invite: "i_again", Secret: b64.EncodeToString(secret), Email: "ann@firm.com"})
	if _, _, err := checkInviteProof(st, testAudience, "acme", TeamRecord{Account: "eve", Proof: proof, At: time.Now().Unix()}, &held); err == nil {
		t.Error("an invite record moved a member to another account")
	}
}

// An admin can't invite their own member again (accepting it would remove
// the very computer that signed): their passkey adds their next computer.
// The team's only admin who accepted an invite, so whose devices a record
// admitted, signs lists at once, as with a passkey join (H3).
func TestAnAdminInvitedAgainByTheirOwnListIsRefused(t *testing.T) {
	f := newTeamFixture(t)
	secret := make([]byte, InviteSecretSize)
	commit, _ := InviteCommit("acme", "m_owner", "i_self", secret)
	f.tt.update("m_owner", func(m *ListMember) {
		m.Email = "owner@acme.com"
		m.Invite = &ListInvite{ID: "i_self", Commit: commit, Exp: time.Now().Add(time.Hour).Unix()}
	})
	if err := f.tt.push(f.owner, "acme", nil); !errors.Is(err, ErrListRefused) || !strings.Contains(err.Error(), "invite yourself") {
		t.Fatalf("a list inviting its signer's member again: %v", err)
	}
	f.tt.update("m_owner", func(m *ListMember) { m.Invite = nil })
	f.tt.update("m_admin", func(m *ListMember) {
		m.Email = "dev@acme.com"
		m.Invite = &ListInvite{ID: "i_self", Commit: commit, Exp: time.Now().Add(time.Hour).Unix()}
	})
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatalf("an admin inviting another admin again: %v", err)
	}
}

func TestTheOnlyAdminInvitedAgainSignsLists(t *testing.T) {
	for _, stays := range []bool{true, false} {
		f := newTeamFixture(t)
		secret := make([]byte, InviteSecretSize)
		copy(secret, "the owner's second invite secret")
		commit, _ := InviteCommit("acme", "m_owner", "i_back", secret)
		f.tt.update("m_owner", func(m *ListMember) {
			m.Email = "owner@acme.com"
			m.Invite = &ListInvite{ID: "i_back", Commit: commit, Exp: time.Now().Add(time.Hour).Unix()}
		})
		if !stays {
			f.tt.update("m_admin", func(m *ListMember) { m.Role, m.Workers = RoleReviewer, []string{allWorkers} })
		}
		if err := f.tt.push(f.admin, "dev", nil); err != nil {
			t.Fatal(err)
		}
		// Until it is taken, the owner's own lists keep the invite another
		// admin opened.
		if stays {
			if err := f.tt.push(f.owner, "acme", nil); err != nil {
				t.Fatalf("the owner's list keeping their open invite: %v", err)
			}
		}
		seq, _ := f.tt.head()
		desk, p := newTestDevice(t), newTestPasskey(t)
		if _, err := f.c.AcceptInvite(withEmail(desk.caller("acme"), "owner@acme.com"), "acme", "i_back", "m_owner", secret, desk.include(t, "acme", "acme", seq+1),
			p.invitePasskey(t, "acme", "m_owner", "i_back", desk, ceremony{})); err != nil {
			t.Fatal(err)
		}
		f.tt.devices["m_owner"] = []testDevice{desk}
		f.tt.since[desk.id()] = seq + 1
		f.tt.update("m_owner", func(m *ListMember) { m.Invite, m.Rec = nil, p.rec(t) })
		err := f.tt.push(desk, "acme", nil)
		if stays && !errors.Is(err, ErrNotAdmin) {
			t.Fatalf("with another admin, a re-invited admin's new computer signed: %v", err)
		}
		if !stays && err != nil {
			t.Fatalf("the only admin, invited again, is locked out: %v", err)
		}
	}
}
