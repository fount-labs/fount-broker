package coordinator

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"
)

// testPasskey is a member's recovery passkey.
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

// assert is the passkey's get() over challenge for rpID.
func (p testPasskey) assert(t *testing.T, challenge []byte, rpID string) passkeyAssertion {
	t.Helper()
	rp := sha256.Sum256([]byte(rpID))
	auth := append(rp[:], 0x05, 0, 0, 0, 1)
	cd, _ := json.Marshal(map[string]string{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(challenge), "origin": "https://fount.sh"})
	ch := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, auth...), ch[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, p.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return passkeyAssertion{Cred: p.cred, AuthenticatorData: auth, ClientDataJSON: cd, Signature: sig}
}

// recoveryRig is a team whose reviewer maria has a recovery passkey, and a
// new device of hers that lost the old one.
type recoveryRig struct {
	f       teamFixture
	passkey testPasskey
	lost    testDevice
	newDev  testDevice
	now     time.Time
}

func newRecoveryRig(t *testing.T) *recoveryRig {
	t.Helper()
	f := newTeamFixture(t)
	r := &recoveryRig{f: f, passkey: newTestPasskey(t), lost: f.reviewer, newDev: newTestDevice(t), now: time.Now()}
	f.tt.update("m_reviewer", func(m *ListMember) { m.Rec = r.passkey.rec(t) })
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	old := recoveryClock
	recoveryClock = func() time.Time { return r.now }
	t.Cleanup(func() { recoveryClock = old })
	return r
}

func (r *recoveryRig) start(t *testing.T) (Recovery, error) {
	t.Helper()
	teams := r.f.c.RecoverableTeams(r.newDev.caller("maria"))
	if len(teams) != 1 || teams[0].Member != "m_reviewer" || teams[0].Cred != r.passkey.cred {
		t.Fatalf("recoverable teams %+v", teams)
	}
	return r.f.c.StartRecovery(r.newDev.caller("maria"), "acme", "m_reviewer", r.passkey.assert(t, teams[0].Challenge, RecoveryRPID))
}

func (r *recoveryRig) finish(t *testing.T, start uint64) (Recovery, error) {
	t.Helper()
	seq, _ := r.f.tt.head()
	return r.f.c.FinishRecovery(r.newDev.caller("maria"), "acme", start, r.newDev.include(t, "acme", "maria", seq+1))
}

func TestARecoveryWaitsThreeDaysThenAdmitsTheNewDevice(t *testing.T) {
	r := newRecoveryRig(t)
	rec, err := r.start(t)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != recoveryWaiting || rec.Device != r.newDev.id() || !rec.EndsAt.Equal(rec.Started.Add(RecoveryWait)) {
		t.Fatalf("recovery %+v", rec)
	}
	if _, err := r.start(t); !errors.Is(err, ErrListRefused) {
		t.Fatalf("a second recovery while one waits: %v", err)
	}
	// Every listed device sees it; the new device sees its own.
	for _, c := range []Caller{r.f.owner.caller("acme"), r.lost.caller("maria"), r.newDev.caller("maria")} {
		all, err := r.f.c.Recoveries(c, "acme")
		if err != nil || len(all) != 1 || all[0].Start != rec.Start {
			t.Fatalf("%s sees %+v %v", c.Device, all, err)
		}
	}
	if _, err := r.f.c.Recoveries(newTestDevice(t).caller("eve"), "acme"); !errors.Is(err, ErrNoTeam) {
		t.Fatalf("a stranger: %v", err)
	}
	r.now = r.now.Add(RecoveryWait - time.Minute)
	if _, err := r.finish(t, rec.Start); !errors.Is(err, ErrRecoveryWaiting) {
		t.Fatalf("finishing early: %v", err)
	}
	r.now = r.now.Add(2 * time.Minute)
	other := newTestDevice(t)
	seq, _ := r.f.tt.head()
	if _, err := r.f.c.FinishRecovery(other.caller("maria"), "acme", rec.Start, other.include(t, "acme", "maria", seq+1)); !errors.Is(err, ErrListRefused) {
		t.Fatalf("another device finishing it: %v", err)
	}
	done, err := r.finish(t, rec.Start)
	if err != nil {
		t.Fatal(err)
	}
	if done.State != recoveryDone {
		t.Fatalf("recovery %+v", done)
	}
	// The new device reaches maria's workers.
	if _, _, err := r.f.c.access(r.newDev.caller("maria"), r.f.w1.ID, RoleReviewer); err != nil {
		t.Fatalf("the recovered device: %v", err)
	}
	if _, err := r.finish(t, rec.Start); err == nil {
		t.Fatal("a recovery finished twice")
	}
}

func TestAnyListedDeviceCancelsARecovery(t *testing.T) {
	r := newRecoveryRig(t)
	rec, err := r.start(t)
	if err != nil {
		t.Fatal(err)
	}
	stranger := newTestDevice(t)
	if _, err := r.f.c.CancelRecovery(stranger.caller("maria"), "acme", rec.Start, ed25519Sign(stranger, RecoveryCancelMessage("acme", rec.Start))); err == nil {
		t.Fatal("an unlisted device cancelled")
	}
	if _, err := r.f.c.CancelRecovery(r.f.admin.caller("dev"), "acme", rec.Start, ed25519Sign(r.f.admin, []byte("something else"))); err == nil {
		t.Fatal("a cancel signed over something else took")
	}
	// The member's own lost-but-listed device, or an admin, cancels.
	got, err := r.f.c.CancelRecovery(r.lost.caller("maria"), "acme", rec.Start, ed25519Sign(r.lost, RecoveryCancelMessage("acme", rec.Start)))
	if err != nil || got.State != recoveryCancelled {
		t.Fatalf("cancel: %+v %v", got, err)
	}
	r.now = r.now.Add(RecoveryWait + time.Hour)
	if _, err := r.finish(t, rec.Start); !errors.Is(err, ErrNoRecovery) {
		t.Fatalf("finishing a cancelled recovery: %v", err)
	}
	if _, _, err := r.f.c.access(r.newDev.caller("maria"), r.f.w1.ID, RoleReviewer); err == nil {
		t.Fatal("a cancelled recovery's device got in")
	}
	// A new one can start, and an admin cancels it.
	rec2, err := r.start(t)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := r.f.c.CancelRecovery(r.f.admin.caller("dev"), "acme", rec2.Start, ed25519Sign(r.f.admin, RecoveryCancelMessage("acme", rec2.Start))); err != nil || got.State != recoveryCancelled {
		t.Fatalf("an admin's cancel: %+v %v", got, err)
	}
}

func TestARecoveryNeedsTheMembersPasskeyOverThisHead(t *testing.T) {
	r := newRecoveryRig(t)
	teams := r.f.c.RecoverableTeams(r.newDev.caller("maria"))
	challenge := teams[0].Challenge
	wrong := newTestPasskey(t)
	wrong.cred = r.passkey.cred
	for name, a := range map[string]passkeyAssertion{
		"another passkey":       wrong.assert(t, challenge, RecoveryRPID),
		"another relying party": r.passkey.assert(t, challenge, "evil.example"),
		"another challenge":     r.passkey.assert(t, RecoveryChallenge("acme", "m_reviewer", "x", r.newDev.pub()), RecoveryRPID),
		"another device's":      r.passkey.assert(t, RecoveryChallenge("acme", "m_reviewer", teams[0].Head, newTestDevice(t).pub()), RecoveryRPID),
	} {
		if _, err := r.f.c.StartRecovery(r.newDev.caller("maria"), "acme", "m_reviewer", a); !errors.Is(err, ErrListRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Another account can't recover maria.
	a := r.passkey.assert(t, RecoveryChallenge("acme", "m_reviewer", teams[0].Head, r.newDev.pub()), RecoveryRPID)
	if _, err := r.f.c.StartRecovery(r.newDev.caller("eve"), "acme", "m_reviewer", a); !errors.Is(err, ErrListRefused) {
		t.Errorf("another account: %v", err)
	}
	// A list that changes her passkey voids a waiting recovery.
	rec, err := r.start(t)
	if err != nil {
		t.Fatal(err)
	}
	r.f.tt.update("m_reviewer", func(m *ListMember) { m.Rec = newTestPasskey(t).rec(t) })
	if err := r.f.tt.push(r.f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	r.now = r.now.Add(RecoveryWait + time.Hour)
	if _, err := r.finish(t, rec.Start); !errors.Is(err, ErrNoRecovery) {
		t.Fatalf("finishing a recovery whose passkey was replaced: %v", err)
	}
}

// On a team an admin re-adds a member's new device at once, by a list.
func TestAnAdminReAddsAMembersNewDevice(t *testing.T) {
	f := newTeamFixture(t)
	newDev := newTestDevice(t)
	f.tt.set("m_reviewer", "maria", RoleReviewer, newDev)
	if err := f.tt.push(f.admin, "dev", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.c.access(newDev.caller("maria"), f.w1.ID, RoleReviewer); err != nil {
		t.Fatalf("the re-added device: %v", err)
	}
	if _, _, err := f.c.access(f.reviewer.caller("maria"), f.w1.ID, RoleReviewer); err == nil {
		t.Fatal("the lost device kept access")
	}
}

func TestTheRecoveryRoutes(t *testing.T) {
	r := newRecoveryRig(t)
	srv := r.f.api(t, r.newDev, "maria")
	code, body := do(t, srv, "GET", "/v1/recovery/teams", "")
	if code != 200 {
		t.Fatalf("teams: %d %v", code, body)
	}
	teams := body["teams"].([]any)
	if len(teams) != 1 {
		t.Fatalf("teams %v", teams)
	}
	ch, _ := base64.StdEncoding.DecodeString(teams[0].(map[string]any)["challenge"].(string))
	a := r.passkey.assert(t, ch, RecoveryRPID)
	req, _ := json.Marshal(map[string]any{"member": "m_reviewer", "cred": a.Cred, "authenticatorData": a.AuthenticatorData,
		"clientDataJSON": a.ClientDataJSON, "signature": a.Signature})
	code, body = do(t, srv, "POST", "/v1/teams/acme/recovery", string(req))
	if code != 200 || body["state"] != recoveryWaiting {
		t.Fatalf("start: %d %v", code, body)
	}
	start := uint64(body["start"].(float64))
	seq, _ := r.f.tt.head()
	done, _ := json.Marshal(map[string]string{"device": r.newDev.include(t, "acme", "maria", seq+1)})
	if code, body = do(t, srv, "POST", "/v1/teams/acme/recovery/"+itoa(start)+"/done", string(done)); code != 409 {
		t.Fatalf("done early: %d %v", code, body)
	}
	code, body = do(t, srv, "GET", "/v1/teams/acme/recovery", "")
	if code != 200 || len(body["recoveries"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, body)
	}
	lost := r.f.api(t, r.lost, "maria")
	cancel, _ := json.Marshal(map[string][]byte{"sig": ed25519Sign(r.lost, RecoveryCancelMessage("acme", start))})
	if code, body = do(t, lost, "POST", "/v1/teams/acme/recovery/"+itoa(start)+"/cancel", string(cancel)); code != 200 || body["state"] != recoveryCancelled {
		t.Fatalf("cancel: %d %v", code, body)
	}
}

func ed25519Sign(d testDevice, msg []byte) []byte { return ed25519.Sign(d.key, msg) }

func itoa(n uint64) string { return strconv.FormatUint(n, 10) }
