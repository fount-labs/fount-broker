package coordinator

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// testPasskey is a member's passkey.
type testPasskey struct {
	key  *ecdsa.PrivateKey
	cred string
}

func newTestPasskey(t *testing.T) testPasskey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cred := make([]byte, 16)
	rand.Read(cred)
	return testPasskey{key: k, cred: b64.EncodeToString(cred)}
}

func (p testPasskey) rec(t *testing.T) *ListRec {
	t.Helper()
	pub, err := p.key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return &ListRec{Cred: p.cred, Pub: b64.EncodeToString(pub)}
}

// ceremony is what the platform puts in an assertion; the zero value is
// what macOS and Desktop's Windows bridge put.
type ceremony struct {
	rpID, origin string
	flags        byte
	count        uint32
	extra        map[string]any
}

func (o ceremony) or() ceremony {
	if o.rpID == "" {
		o.rpID = PasskeyRPID
	}
	if o.origin == "" {
		o.origin = PasskeyOrigins[0]
	}
	if o.flags == 0 {
		o.flags = 0x1d
	}
	return o
}

// assertRaw is the passkey's get() over challenge.
func (p testPasskey) assertRaw(t *testing.T, challenge []byte, o ceremony) passkeyAssertion {
	t.Helper()
	o = o.or()
	rp := sha256.Sum256([]byte(o.rpID))
	auth := binary.BigEndian.AppendUint32(append(rp[:], o.flags), o.count)
	cd := map[string]any{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(challenge), "origin": o.origin}
	for k, v := range o.extra {
		cd[k] = v
	}
	client, _ := json.Marshal(cd)
	ch := sha256.Sum256(client)
	digest := sha256.Sum256(append(append([]byte{}, auth...), ch[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, p.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return passkeyAssertion{AuthenticatorData: auth, ClientDataJSON: client, Signature: sig}
}

// request is a join request for d on ch, with p's assertion over challenge.
func (p testPasskey) request(t *testing.T, ch PasskeyChallenge, challenge []byte, d testDevice, team, account string, o ceremony) PasskeyJoinRequest {
	t.Helper()
	a := p.assertRaw(t, challenge, o)
	return PasskeyJoinRequest{Nonce: ch.Nonce, Cred: p.cred, AuthenticatorData: b64.EncodeToString(a.AuthenticatorData),
		ClientDataJSON: b64.EncodeToString(a.ClientDataJSON), Signature: b64.EncodeToString(a.Signature),
		Device: d.include(t, team, account, ch.Seq+1)}
}

// passkeyRig is a team whose reviewer maria has a passkey, and a new
// computer of hers.
type passkeyRig struct {
	f       teamFixture
	passkey testPasskey
	newDev  testDevice
}

func newPasskeyRig(t *testing.T) *passkeyRig {
	t.Helper()
	f := newTeamFixture(t)
	r := &passkeyRig{f: f, passkey: newTestPasskey(t), newDev: newTestDevice(t)}
	f.tt.update("m_reviewer", func(m *ListMember) { m.Rec = r.passkey.rec(t) })
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *passkeyRig) challenge(t *testing.T, d testDevice) (PasskeyChallenge, []byte) {
	t.Helper()
	ch, err := r.f.c.StartPasskeyJoin(d.caller("maria"), "acme", d.pub(), d.enc.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := b64.DecodeString(ch.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	return ch, raw
}

func (r *passkeyRig) join(t *testing.T, d testDevice, o ceremony) (TeamLogView, error) {
	t.Helper()
	ch, raw := r.challenge(t, d)
	return r.f.c.PasskeyJoin(d.caller("maria"), "acme", r.passkey.request(t, ch, raw, d, "acme", "maria", o))
}

func TestAPasskeyAddsAMembersNewComputerAtOnce(t *testing.T) {
	r := newPasskeyRig(t)
	if ms := r.f.c.Memberships(r.newDev.caller("maria")); len(ms) != 1 || ms[0].Admitted || !ms[0].Passkey {
		t.Fatalf("memberships %+v", ms)
	}
	if _, _, err := r.f.c.access(r.newDev.caller("maria"), r.f.w1.ID, RoleReviewer); err == nil {
		t.Fatal("the new computer reached a worker before it joined")
	}
	ch, raw := r.challenge(t, r.newDev)
	if ch.Member != "m_reviewer" || ch.Cred != r.passkey.cred {
		t.Fatalf("challenge %+v", ch)
	}
	want, _ := PasskeyJoinChallenge(testAudience, "acme", "m_reviewer", ch.Head, mustB64(t, ch.Nonce), r.newDev.pub(), r.newDev.enc.PublicKey().Bytes())
	if string(want) != string(raw) {
		t.Fatal("the challenge isn't PasskeyJoinChallenge over the head and the device's keys")
	}
	req := r.passkey.request(t, ch, raw, r.newDev, "acme", "maria", ceremony{})
	v, err := r.f.c.PasskeyJoin(r.newDev.caller("maria"), "acme", req)
	if err != nil {
		t.Fatal(err)
	}
	if v.Seq != ch.Seq+1 {
		t.Fatalf("view %+v", v)
	}
	if _, _, err := r.f.c.access(r.newDev.caller("maria"), r.f.w1.ID, RoleReviewer); err != nil {
		t.Fatalf("the new computer: %v", err)
	}
	if ms := r.f.c.Memberships(r.newDev.caller("maria")); !ms[0].Admitted {
		t.Fatalf("memberships %+v", ms)
	}
	// The record is checked again on replay, as a client checks it.
	if _, err := reduceTeam("acme", testAudience, r.f.team(t).Log); err != nil {
		t.Fatalf("replay: %v", err)
	}
	// The same request again: the challenge is used.
	if _, err := r.f.c.PasskeyJoin(r.newDev.caller("maria"), "acme", req); !errors.Is(err, ErrPasskeyChallenge) {
		t.Fatalf("a replayed request: %v", err)
	}
	// The member's old computer still reaches the worker; an admin's list
	// removes the new one.
	if _, _, err := r.f.c.access(r.f.reviewer.caller("maria"), r.f.w1.ID, RoleReviewer); err != nil {
		t.Fatalf("the old computer: %v", err)
	}
}

func TestAPasskeyJoinIsForOneDeviceAndOneHead(t *testing.T) {
	r := newPasskeyRig(t)
	other := newTestDevice(t)

	// Another device can't use the new computer's challenge.
	ch, raw := r.challenge(t, r.newDev)
	stolen := r.passkey.request(t, ch, raw, other, "acme", "maria", ceremony{})
	if _, err := r.f.c.PasskeyJoin(other.caller("maria"), "acme", stolen); !errors.Is(err, ErrPasskeyChallenge) {
		t.Fatalf("another device on the challenge: %v", err)
	}
	// The challenge was used up by the try.
	if _, err := r.f.c.PasskeyJoin(r.newDev.caller("maria"), "acme", r.passkey.request(t, ch, raw, r.newDev, "acme", "maria", ceremony{})); !errors.Is(err, ErrPasskeyChallenge) {
		t.Fatalf("a challenge after a failed try: %v", err)
	}

	// An assertion over another device's challenge, on this device's own.
	chA, _ := r.challenge(t, r.newDev)
	_, rawB := r.challenge(t, other)
	if _, err := r.f.c.PasskeyJoin(r.newDev.caller("maria"), "acme", r.passkey.request(t, chA, rawB, r.newDev, "acme", "maria", ceremony{})); !errors.Is(err, ErrListRefused) {
		t.Fatalf("an assertion over another device's challenge: %v", err)
	}
	// An inclusion with keys other than the challenge's.
	chA, rawA := r.challenge(t, r.newDev)
	req := r.passkey.request(t, chA, rawA, r.newDev, "acme", "maria", ceremony{})
	req.Device = other.include(t, "acme", "maria", chA.Seq+1)
	if _, err := r.f.c.PasskeyJoin(r.newDev.caller("maria"), "acme", req); !errors.Is(err, ErrListRefused) {
		t.Fatalf("another device's inclusion: %v", err)
	}

	// The log moves between the challenge and the join.
	chA, rawA = r.challenge(t, r.newDev)
	if err := r.f.tt.push(r.f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	req = r.passkey.request(t, chA, rawA, r.newDev, "acme", "maria", ceremony{})
	req.Device = r.newDev.include(t, "acme", "maria", chA.Seq+2)
	if _, err := r.f.c.PasskeyJoin(r.newDev.caller("maria"), "acme", req); !errors.Is(err, ErrTeamStale) {
		t.Fatalf("a challenge over an old head: %v", err)
	}

	// A record's proof moved onto another device, or another head, doesn't
	// replay.
	if _, err := r.join(t, r.newDev, ceremony{}); err != nil {
		t.Fatal(err)
	}
	log := r.f.team(t).Log
	last := log[len(log)-1]
	var rec TeamRecord
	if err := json.Unmarshal(last.Record, &rec); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*TeamRecord){
		"another device": func(rec *TeamRecord) { rec.Device = other.include(t, "acme", "maria", rec.Seq) },
		"another head":   func(rec *TeamRecord) { rec.Prev = log[len(log)-3].Hash },
	} {
		forged := rec
		change(&forged)
		prior, err := reduceTeam("acme", testAudience, log[:len(log)-1])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := checkPasskeyJoinProof(prior, testAudience, "acme", forged, prior.byID["m_reviewer"]); err == nil {
			t.Errorf("%s: the proof replayed", name)
		}
	}
}

func TestAPasskeyJoinNeedsTheListedPasskeyFromFount(t *testing.T) {
	r := newPasskeyRig(t)
	wrong := newTestPasskey(t)
	wrong.cred = r.passkey.cred
	for name, c := range map[string]struct {
		p testPasskey
		o ceremony
	}{
		"a passkey the list doesn't name": {wrong, ceremony{}},
		"another origin":                  {r.passkey, ceremony{origin: "https://evil.example"}},
		"the www origin":                  {r.passkey, ceremony{origin: "https://www.fount.sh"}},
		"a cross-origin frame":            {r.passkey, ceremony{extra: map[string]any{"crossOrigin": true}}},
		"another relying party":           {r.passkey, ceremony{rpID: "evil.example"}},
		"no user verification":            {r.passkey, ceremony{flags: 0x01}},
		"an escaped client data":          {r.passkey, ceremony{extra: map[string]any{"note": "a\"b"}}},
		"a nested client data":            {r.passkey, ceremony{extra: map[string]any{"tokenBinding": map[string]any{"status": "present"}}}},
		"a number in the client data":     {r.passkey, ceremony{extra: map[string]any{"n": 1}}},
	} {
		ch, raw := r.challenge(t, r.newDev)
		if _, err := r.f.c.PasskeyJoin(r.newDev.caller("maria"), "acme", c.p.request(t, ch, raw, r.newDev, "acme", "maria", c.o)); !errors.Is(err, ErrListRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Another credential id.
	ch, raw := r.challenge(t, r.newDev)
	req := r.passkey.request(t, ch, raw, r.newDev, "acme", "maria", ceremony{})
	req.Cred = newTestPasskey(t).cred
	if _, err := r.f.c.PasskeyJoin(r.newDev.caller("maria"), "acme", req); !errors.Is(err, ErrListRefused) {
		t.Errorf("another credential: %v", err)
	}
	// crossOrigin false is fine.
	if _, err := r.join(t, r.newDev, ceremony{extra: map[string]any{"crossOrigin": false}}); err != nil {
		t.Fatalf("crossOrigin false: %v", err)
	}
}

func TestARevokedMembersPasskeyAddsNothing(t *testing.T) {
	r := newPasskeyRig(t)
	// Another account can't ask for maria's challenge.
	if _, err := r.f.c.StartPasskeyJoin(r.newDev.caller("eve"), "acme", r.newDev.pub(), r.newDev.enc.PublicKey().Bytes()); !errors.Is(err, ErrNoTeam) {
		t.Fatalf("another account: %v", err)
	}
	// A challenge maria's new computer got, then the passkey taken off the
	// list.
	ch, raw := r.challenge(t, r.newDev)
	req := r.passkey.request(t, ch, raw, r.newDev, "acme", "maria", ceremony{})
	prior, err := reduceTeam("acme", testAudience, r.f.team(t).Log)
	if err != nil {
		t.Fatal(err)
	}
	r.f.tt.update("m_reviewer", func(m *ListMember) { m.Rec = nil })
	if err := r.f.tt.push(r.f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := r.f.c.PasskeyJoin(r.newDev.caller("maria"), "acme", req); err == nil {
		t.Fatal("a join on a passkey the list dropped")
	}
	if _, err := r.f.c.StartPasskeyJoin(r.newDev.caller("maria"), "acme", r.newDev.pub(), r.newDev.enc.PublicKey().Bytes()); !errors.Is(err, ErrNoPasskey) {
		t.Fatalf("a challenge with no passkey listed: %v", err)
	}
	// The same proof, checked against a state whose list dropped the passkey.
	proof, _ := json.Marshal(PasskeyJoinProof{Nonce: req.Nonce, Cred: req.Cred, AuthenticatorData: req.AuthenticatorData, ClientDataJSON: req.ClientDataJSON, Signature: req.Signature})
	rec := TeamRecord{Kind: RecordPasskeyJoin, Seq: prior.seq + 1, Prev: prior.head, Member: "m_reviewer", Account: "maria", Device: req.Device, Proof: proof}
	if _, err := checkPasskeyJoinProof(prior, testAudience, "acme", rec, prior.byID["m_reviewer"]); err != nil {
		t.Fatalf("the proof against the state it was made for: %v", err)
	}
	revoked := *prior.byID["m_reviewer"]
	revoked.Rec = nil
	if _, err := checkPasskeyJoinProof(prior, testAudience, "acme", rec, &revoked); err == nil {
		t.Fatal("the proof checked against a member with no passkey")
	}

	// Maria removed from the team: her passkey adds nothing.
	r.f.tt.update("m_reviewer", func(m *ListMember) { m.Rec = r.passkey.rec(t) })
	if err := r.f.tt.push(r.f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	ch, raw = r.challenge(t, r.newDev)
	req = r.passkey.request(t, ch, raw, r.newDev, "acme", "maria", ceremony{})
	r.f.tt.drop("m_reviewer")
	if err := r.f.tt.push(r.f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := r.f.c.PasskeyJoin(r.newDev.caller("maria"), "acme", req); err == nil {
		t.Fatal("a removed member's passkey added a device")
	}
	if _, err := r.f.c.StartPasskeyJoin(r.newDev.caller("maria"), "acme", r.newDev.pub(), r.newDev.enc.PublicKey().Bytes()); !errors.Is(err, ErrNoTeam) {
		t.Fatalf("a removed member's challenge: %v", err)
	}
}

func TestAPasskeysSignCountMustRise(t *testing.T) {
	r := newPasskeyRig(t)
	if _, err := r.join(t, r.newDev, ceremony{count: 5}); err != nil {
		t.Fatal(err)
	}
	for _, count := range []uint32{5, 4, 0} {
		if _, err := r.join(t, newTestDevice(t), ceremony{count: count}); err == nil {
			t.Fatalf("count %d after 5 admitted a device", count)
		}
	}
	if _, err := r.join(t, newTestDevice(t), ceremony{count: 6}); err != nil {
		t.Fatalf("count 6: %v", err)
	}
	if _, err := reduceTeam("acme", testAudience, r.f.team(t).Log); err != nil {
		t.Fatalf("replay: %v", err)
	}

	// A synced passkey keeps no count: 0 every time.
	r = newPasskeyRig(t)
	for range 2 {
		if _, err := r.join(t, newTestDevice(t), ceremony{}); err != nil {
			t.Fatalf("count 0: %v", err)
		}
	}
}

func TestPasskeyChallengesAreBounded(t *testing.T) {
	r := newPasskeyRig(t)
	for range maxMemberPasskeyChallenges {
		r.challenge(t, r.newDev)
	}
	if _, err := r.f.c.StartPasskeyJoin(r.newDev.caller("maria"), "acme", r.newDev.pub(), r.newDev.enc.PublicKey().Bytes()); !errors.Is(err, ErrTooManyUngranted) {
		t.Fatalf("a fourth open challenge: %v", err)
	}
	// An admitted device asks for none.
	if _, err := r.f.c.StartPasskeyJoin(r.f.reviewer.caller("maria"), "acme", r.f.reviewer.pub(), r.f.reviewer.enc.PublicKey().Bytes()); !errors.Is(err, ErrListRefused) {
		t.Fatalf("an admitted device: %v", err)
	}
}

func TestThePasskeyJoinRoutes(t *testing.T) {
	r := newPasskeyRig(t)
	srv := r.f.api(t, r.newDev, "maria")
	code, body := do(t, srv, "GET", "/v1/teams", "")
	if code != 200 || body["teams"].([]any)[0].(map[string]any)["passkey"] != true {
		t.Fatalf("teams: %d %v", code, body)
	}
	keys, _ := json.Marshal(joinKeys{Key: r.newDev.b64(), Enc: b64.EncodeToString(r.newDev.enc.PublicKey().Bytes())})
	code, body = do(t, srv, "POST", "/v1/teams/acme/passkey-join/challenge", string(keys))
	if code != 200 {
		t.Fatalf("challenge: %d %v", code, body)
	}
	ch := PasskeyChallenge{Member: body["member"].(string), Cred: body["cred"].(string), Nonce: body["nonce"].(string), Seq: uint64(body["seq"].(float64)), Head: body["head"].(string), Challenge: body["challenge"].(string)}
	req := r.passkey.request(t, ch, mustB64(t, ch.Challenge), r.newDev, "acme", "maria", ceremony{})
	raw, _ := json.Marshal(req)
	code, body = do(t, srv, "POST", "/v1/teams/acme/passkey-join", string(raw))
	if code != 200 || uint64(body["seq"].(float64)) != ch.Seq+1 {
		t.Fatalf("join: %d %v", code, body)
	}
	if code, body = do(t, srv, "POST", "/v1/teams/acme/passkey-join", string(raw)); code != 404 {
		t.Fatalf("join again: %d %v", code, body)
	}
	// The old recovery routes are gone.
	for _, path := range []string{"/v1/teams/acme/recovery", "/v1/teams/acme/recovery/3/done"} {
		if code, _ := do(t, srv, "POST", path, "{}"); code != 404 && code != 405 {
			t.Errorf("%s: %d", path, code)
		}
	}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := b64.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A passkey join tells the owner, and the member at their own address.
func TestADeviceAddedNoticeGoesToTheOwnerAndTheMember(t *testing.T) {
	r := newSendRig(t, modeNotify)
	ctx := context.Background()
	for _, to := range []string{"", "maria@example.com", "maria@example.com", "Dana@example.com"} {
		key := "acct/device_added/7"
		if to != "" {
			key += "/member"
		}
		if err := r.c.notify(ctx, key, noticeDeviceAdded, r.w.Account, r.w.ID, time.Time{}, to); err != nil {
			t.Fatal(err)
		}
	}
	r.pass()
	owner := r.send.sentTo("dana@example.com", "New computer added to Acme")
	member := r.send.sentTo("maria@example.com", "New computer added to Acme")
	if len(owner) != 1 || len(member) != 1 || !strings.Contains(string(r.send.raw[member[0]]), "remove it in Fount") {
		t.Fatalf("notices: owner %v, member %v", owner, member)
	}
}

// A member invited again is told, as the owner is, that their old
// computers were removed.
func TestAMemberBackNoticeSaysTheOldComputersWereRemoved(t *testing.T) {
	r := newSendRig(t, modeNotify)
	ctx := context.Background()
	if err := r.c.notify(ctx, "acct/member_back/9", noticeMemberBack, r.w.Account, r.w.ID, time.Time{}, ""); err != nil {
		t.Fatal(err)
	}
	if err := r.c.notify(ctx, "acct/member_back/9/member", noticeMemberBack, r.w.Account, r.w.ID, time.Time{}, "maria@example.com"); err != nil {
		t.Fatal(err)
	}
	r.pass()
	for _, to := range []string{"dana@example.com", "maria@example.com"} {
		sent := r.send.sentTo(to, "New computer added to Acme")
		if len(sent) != 1 || !strings.Contains(string(r.send.raw[sent[0]]), "old computers were removed") {
			t.Fatalf("%s: %v", to, sent)
		}
	}
}

// Security review 2026-11-24, M4: Remove on a device the member's passkey
// added revokes the passkey in the same list. A list that keeps it is
// refused, since the passkey would add the device straight back; one that
// clears it, or names a new one, goes through, and the old passkey joins no
// more.
func TestRemovingAPasskeyAddedDeviceRevokesThePasskey(t *testing.T) {
	f := newTeamFixture(t)
	pk := newTestPasskey(t)
	f.tt.update("m_owner", func(m *ListMember) { m.Rec = pk.rec(t) })
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	intruder := newTestDevice(t)
	ownerPasskeyJoin(t, f, pk, intruder)
	if err := f.tt.push(f.owner, "acme", nil); !errors.Is(err, ErrListRefused) || !strings.Contains(err.Error(), "keeps that passkey") {
		t.Fatalf("removing the device and keeping the passkey: %v", err)
	}
	fresh := newTestPasskey(t)
	f.tt.update("m_owner", func(m *ListMember) { m.Rec = fresh.rec(t) })
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatalf("removing the device and naming a new passkey: %v", err)
	}
	again := newTestDevice(t)
	ch, err := f.c.StartPasskeyJoin(again.caller("acme"), "acme", again.pub(), again.enc.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.PasskeyJoin(again.caller("acme"), "acme", pk.request(t, ch, mustB64(t, ch.Challenge), again, "acme", "acme", ceremony{})); !errors.Is(err, ErrListRefused) {
		t.Fatalf("the replaced passkey joining again: %v", err)
	}

	// Cleared, no passkey joins until an admin lists one.
	ownerPasskeyJoin(t, f, fresh, intruder)
	f.tt.update("m_owner", func(m *ListMember) { m.Rec = nil })
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatalf("removing the device and clearing the passkey: %v", err)
	}
	if _, err := f.c.StartPasskeyJoin(again.caller("acme"), "acme", again.pub(), again.enc.PublicKey().Bytes()); !errors.Is(err, ErrNoPasskey) {
		t.Fatalf("a member whose passkey was cleared: %v", err)
	}

	// A list that keeps the device keeps the passkey too; one listed device
	// removed later is an ordinary removal.
	f.tt.update("m_owner", func(m *ListMember) { m.Rec = fresh.rec(t) })
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	laptop := newTestDevice(t)
	ownerPasskeyJoin(t, f, fresh, laptop)
	seq, _ := f.tt.head()
	f.tt.devices["m_owner"] = append(f.tt.devices["m_owner"], laptop)
	f.tt.since[laptop.id()] = seq
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatalf("including the passkey-joined device: %v", err)
	}
	f.tt.devices["m_owner"] = []testDevice{f.owner}
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatalf("removing a device a list included: %v", err)
	}
}
