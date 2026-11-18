package coordinator

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/cryptotest"
	"time"
)

// signRaw signs inclusion claims as they are, unlike SignInclusion.
func signRaw(t *testing.T, key ed25519.PrivateKey, c InclusionClaims) string {
	t.Helper()
	payload, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return b64.EncodeToString(payload) + "." + b64.EncodeToString(ed25519.Sign(key, append([]byte(InclusionContext), payload...)))
}

func TestEveryListedDeviceSignsItsOwnInclusion(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	me, admin, attacker := newTestDevice(t), newTestDevice(t), newTestDevice(t)
	dek := mustDEK(t)
	w, _ := c.CreateWorkerFor(me.caller("acme"))
	elsewhere, _ := c.CreateWorkerFor(me.caller("acme"))
	commitment := DEKCommitment(w.ID, dek)
	good := func() testGrant { return me.grant(t, "acme", w.ID, 1, dek, me, admin) }
	with := func(i int, inclusion string) testGrant {
		g := good()
		g.inclusions[i] = inclusion
		return g
	}

	// The attacker signs an inclusion naming the admin's id and key, with
	// its own X25519 key, so the DEK would be wrapped to it.
	forged := signRaw(t, attacker.key, InclusionClaims{V: InclusionVersion, Typ: InclusionType, Aud: testAudience, Acct: "acme", Worker: w.ID, DEK: commitment,
		Dev: admin.id(), Key: admin.b64(), Enc: b64.EncodeToString(attacker.enc.PublicKey().Bytes()), Seq: 1})
	// The attacker's own key, claiming the admin's id.
	lying := signRaw(t, attacker.key, InclusionClaims{V: InclusionVersion, Typ: InclusionType, Aud: testAudience, Acct: "acme", Worker: w.ID, DEK: commitment,
		Dev: admin.id(), Key: attacker.b64(), Enc: b64.EncodeToString(attacker.enc.PublicKey().Bytes()), Seq: 1})
	otherAud := signRaw(t, admin.key, InclusionClaims{V: InclusionVersion, Typ: InclusionType, Aud: "https://other.example", Acct: "acme", Worker: w.ID, DEK: commitment,
		Dev: admin.id(), Key: admin.b64(), Enc: b64.EncodeToString(admin.enc.PublicKey().Bytes()), Seq: 1})
	missing := good()
	missing.inclusions = missing.inclusions[:1]
	missingMine := good()
	missingMine.inclusions = missingMine.inclusions[1:]
	extra := good()
	extra.inclusions = append(extra.inclusions, attacker.include(t, "acme", w.ID, 1, dek))
	twice := good()
	twice.inclusions = append(twice.inclusions, admin.include(t, "acme", w.ID, 1, dek))
	for _, tc := range []struct {
		name string
		g    testGrant
	}{
		{"a forged inclusion", with(1, forged)},
		{"an inclusion whose id isn't its key's", with(1, lying)},
		{"an inclusion from another worker", with(1, admin.include(t, "acme", elsewhere.ID, 1, dek))},
		{"an inclusion from another account", with(1, admin.include(t, "other", w.ID, 1, dek))},
		{"an inclusion for another coordinator", with(1, otherAud)},
		{"an inclusion of another DEK", with(1, admin.include(t, "acme", w.ID, 1, mustDEK(t)))},
		{"an inclusion for a later grant", with(1, admin.include(t, "acme", w.ID, 2, dek))},
		{"an inclusion for no grant", with(1, admin.include(t, "acme", w.ID, 0, dek))},
		{"a malformed inclusion", with(1, "x.y")},
		{"an admin's inclusion missing", missing},
		{"the signer's own inclusion missing", missingMine},
		{"an inclusion of a device it doesn't name", extra},
		{"two inclusions of one device", twice},
	} {
		if _, err := tc.g.to(c, me.caller("acme"), w.ID, dek); !errors.Is(err, ErrGrantRefused) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	if got, _ := c.Worker(w.ID); got.WrappedDEK != nil || got.GrantSeq != 0 {
		t.Fatalf("a refused grant changed the worker: %+v", got)
	}
	if got, err := good().to(c, me.caller("acme"), w.ID, dek); err != nil || !bytes.Equal(got.Devices[1].Enc, admin.enc.PublicKey().Bytes()) || got.Devices[1].Since != 1 || got.DEKCommitment != commitment {
		t.Fatalf("the grant: %v %+v", err, got)
	}
}

func TestEveryListedDeviceHasOneWrap(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	me, admin, stranger := newTestDevice(t), newTestDevice(t), newTestDevice(t)
	dek := mustDEK(t)
	w, _ := c.CreateWorkerFor(me.caller("acme"))
	edit := func(f func(map[string][]byte)) testGrant {
		g := me.grant(t, "acme", w.ID, 1, dek, me, admin)
		f(g.wraps)
		return g
	}
	for _, tc := range []struct {
		name string
		g    testGrant
	}{
		{"an admin's wrap missing", edit(func(m map[string][]byte) { delete(m, admin.id()) })},
		{"the signer's own wrap missing", edit(func(m map[string][]byte) { delete(m, me.id()) })},
		{"no wraps", edit(func(m map[string][]byte) { clear(m) })},
		{"a wrap for a device it doesn't name", edit(func(m map[string][]byte) { m[stranger.id()] = stranger.wrap(t, "acme", w.ID, dek) })},
		{"a short wrap", edit(func(m map[string][]byte) { m[admin.id()] = m[admin.id()][:WrapSize-1] })},
		{"a long wrap", edit(func(m map[string][]byte) { m[admin.id()] = append(m[admin.id()], 0) })},
		// The right size, for the right device, but not the wrap the grant
		// signed: one the broker, say, made to a key of its own.
		{"a wrap swapped for another", edit(func(m map[string][]byte) { m[admin.id()] = admin.wrap(t, "acme", w.ID, dek) })},
		{"two wraps swapped", edit(func(m map[string][]byte) { m[me.id()], m[admin.id()] = m[admin.id()], m[me.id()] })},
	} {
		if _, err := tc.g.to(c, me.caller("acme"), w.ID, dek); !errors.Is(err, ErrGrantRefused) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func TestReGrantsCarryInclusionsAndARemovedDeviceSignsAgain(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	me, admin, second := newTestDevice(t), newTestDevice(t), newTestDevice(t)
	dek := mustDEK(t)
	w := granted(t, c, me, dek)
	grant := func(g testGrant) (Worker, error) { return g.to(c, me.caller("acme"), w.ID, dek) }

	// Grant 2 adds the admin, whose inclusion must be for grant 2; mine
	// stays the one grant 1 listed me on.
	if _, err := grant(me.grant(t, "acme", w.ID, 2, dek, me, admin)); !errors.Is(err, ErrGrantRefused) {
		t.Errorf("a listed device's inclusion re-signed for this grant: %v", err)
	}
	if _, err := grant(me.grantSince(t, "acme", w.ID, 2, dek, map[string]uint64{me.id(): 1, admin.id(): 1}, me, admin)); !errors.Is(err, ErrGrantRefused) {
		t.Errorf("a new device's inclusion for an earlier grant: %v", err)
	}
	if _, err := grant(me.grantSince(t, "acme", w.ID, 2, dek, map[string]uint64{me.id(): 1}, me, admin)); err != nil {
		t.Fatal(err)
	}
	oldAdmin := admin.include(t, "acme", w.ID, 2, dek)

	// Grant 3 swaps the admin for a second device, under the same DEK.
	got, err := grant(me.grantSince(t, "acme", w.ID, 3, dek, map[string]uint64{me.id(): 1}, me, second))
	if err != nil || len(got.Devices) != 2 || got.authorizes(admin.id()) || !got.authorizes(second.id()) {
		t.Fatalf("swapping devices: %v %+v", err, got)
	}
	for _, d := range []testDevice{me, second} {
		var wrap []byte
		for _, gd := range got.Devices {
			if gd.ID == d.id() {
				wrap = gd.Wrap
			}
		}
		if opened, err := OpenWrap(d.enc.Bytes(), "acme", w.ID, d.id(), got.DEKCommitment, wrap); err != nil || opened != dek {
			t.Errorf("device %s's wrap after a re-grant: %v", d.id(), err)
		}
	}

	// The removed admin's old inclusion doesn't bring it back; a new one does.
	back := me.grantSince(t, "acme", w.ID, 4, dek, map[string]uint64{me.id(): 1, second.id(): 3}, me, second, admin)
	back.inclusions[2] = oldAdmin
	if _, err := grant(back); !errors.Is(err, ErrGrantRefused) {
		t.Errorf("a removed device on its old inclusion: %v", err)
	}
	if got, err = grant(me.grantSince(t, "acme", w.ID, 4, dek, map[string]uint64{me.id(): 1, second.id(): 3}, me, second, admin)); err != nil || got.Devices[2].Since != 4 {
		t.Fatalf("a removed device signing again: %v %+v", err, got)
	}
	// Another DEK is still refused, inclusions and all.
	other := mustDEK(t)
	if _, err := me.grantSince(t, "acme", w.ID, 5, other, map[string]uint64{me.id(): 1}).to(c, me.caller("acme"), w.ID, other); !errors.Is(err, ErrDEKChanged) {
		t.Errorf("a re-grant of another DEK: %v", err)
	}
}

func TestAWrapOpensOnlyForItsDeviceWorkerAndDEK(t *testing.T) {
	me, other := newTestDevice(t), newTestDevice(t)
	dek := mustDEK(t)
	const worker = "w_0123456789abcdef01234567"
	wrap := me.wrap(t, "acme", worker, dek)
	commitment := DEKCommitment(worker, dek)
	if len(wrap) != WrapSize {
		t.Fatalf("a wrap of %d bytes", len(wrap))
	}
	if got, err := OpenWrap(me.enc.Bytes(), "acme", worker, me.id(), commitment, wrap); err != nil || got != dek {
		t.Fatalf("open: %v", err)
	}
	if again := me.wrap(t, "acme", worker, dek); bytes.Equal(again, wrap) {
		t.Error("two wraps are the same bytes")
	}
	tampered := bytes.Clone(wrap)
	tampered[len(tampered)-1] ^= 1
	otherDEK := mustDEK(t)
	for _, tc := range []struct {
		name                         string
		priv                         []byte
		account, worker, dev, commit string
		wrap                         []byte
	}{
		{"another device's key", other.enc.Bytes(), "acme", worker, me.id(), commitment, wrap},
		{"another account", me.enc.Bytes(), "other", worker, me.id(), commitment, wrap},
		{"another worker", me.enc.Bytes(), "acme", "w_0123456789abcdef01234568", me.id(), commitment, wrap},
		{"another device id", me.enc.Bytes(), "acme", worker, other.id(), commitment, wrap},
		{"another commitment", me.enc.Bytes(), "acme", worker, me.id(), DEKCommitment(worker, otherDEK), wrap},
		{"tampered", me.enc.Bytes(), "acme", worker, me.id(), commitment, tampered},
		{"short", me.enc.Bytes(), "acme", worker, me.id(), commitment, wrap[:WrapSize-1]},
	} {
		if _, err := OpenWrap(tc.priv, tc.account, tc.worker, tc.dev, tc.commit, tc.wrap); err == nil {
			t.Errorf("%s opened", tc.name)
		}
	}
	// A wrap made with the right AAD but of another DEK than the commitment.
	if _, err := OpenWrap(me.enc.Bytes(), "acme", worker, me.id(), commitment, sealAs(t, me, "acme", worker, commitment, otherDEK)); err == nil {
		t.Error("a wrap of another DEK than its commitment opened")
	}
}

// sealAs seals dek under the AAD of commitment, which needn't be dek's.
func sealAs(t *testing.T, d testDevice, account, workerID, commitment string, dek DEK) []byte {
	t.Helper()
	aad, _ := wrapAAD(account, workerID, d.id(), commitment)
	pk, _ := wrapSuite.kem.NewPublicKey(d.enc.PublicKey().Bytes())
	enc, s, err := hpkeSender(pk)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := s.Seal(aad, dek[:])
	if err != nil {
		t.Fatal(err)
	}
	return append(enc, ct...)
}

// deviceVectors is testdata/device-vectors.json, for Desktop's Rust port:
// fixed keys, the inclusion they sign (Ed25519 is deterministic, so the
// token is too) and a wrap to open. HPKE's ephemeral key is random, so a
// port's own wraps are checked by opening them, not by their bytes.
type deviceVectors struct {
	Comment        string `json:"comment"`
	Ed25519Seed    string `json:"ed25519_seed"`
	Ed25519Public  string `json:"ed25519_public"`
	X25519Private  string `json:"x25519_private"`
	X25519Public   string `json:"x25519_public"`
	Device         string `json:"device"`
	Audience       string `json:"audience"`
	Account        string `json:"account"`
	Worker         string `json:"worker"`
	Seq            uint64 `json:"seq"`
	DEK            string `json:"dek"`
	DEKCommitment  string `json:"dek_commitment"`
	InclusionClaim string `json:"inclusion_claims"`
	Inclusion      string `json:"inclusion"`
	WrapInfo       string `json:"wrap_info"`
	WrapAAD        string `json:"wrap_aad"`
	Wrap           string `json:"wrap"`
	WrapsDigest    string `json:"wraps_digest"`
	GrantClaims    string `json:"grant_claims"`
	Grant          string `json:"grant"`
}

const deviceVectorsPath = "testdata/device-vectors.json"

func seq(from byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = from + byte(i)
	}
	return b
}

// makeDeviceVectors writes the vectors from fixed keys; the wrap's ephemeral
// key comes from a seeded cryptotest source.
func makeDeviceVectors(t *testing.T) deviceVectors {
	t.Helper()
	cryptotest.SetGlobalRandom(t, 1)
	key := ed25519.NewKeyFromSeed(seq(0x01))
	enc, err := ecdh.X25519().NewPrivateKey(seq(0x21))
	if err != nil {
		t.Fatal(err)
	}
	var dek DEK
	copy(dek[:], seq(0x41))
	v := deviceVectors{
		Comment:     "Device inclusion and DEK wrap vectors (internal/coordinator/devicekey.go). Bytes are hex. Test keys only. Rewrite: DEVICE_VECTORS_WRITE=1 go test -run TestDeviceVectors ./internal/coordinator",
		Ed25519Seed: hex.EncodeToString(seq(0x01)), Ed25519Public: hex.EncodeToString(key.Public().(ed25519.PublicKey)),
		X25519Private: hex.EncodeToString(enc.Bytes()), X25519Public: hex.EncodeToString(enc.PublicKey().Bytes()),
		Device: deviceID(key.Public().(ed25519.PublicKey)), Audience: "https://coordinator.example", Account: "acct_vectors", Worker: "w_0123456789abcdef01234567", Seq: 1,
		DEK: hex.EncodeToString(dek[:]), WrapInfo: WrapInfo,
	}
	v.DEKCommitment = DEKCommitment(v.Worker, dek)
	if v.Inclusion, err = SignInclusion(key, enc.PublicKey().Bytes(), InclusionClaims{Aud: v.Audience, Acct: v.Account, Worker: v.Worker, DEK: v.DEKCommitment, Seq: v.Seq}); err != nil {
		t.Fatal(err)
	}
	claims, _ := b64.DecodeString(v.Inclusion[:bytes.IndexByte([]byte(v.Inclusion), '.')])
	v.InclusionClaim = string(claims)
	aad, _ := wrapAAD(v.Account, v.Worker, v.Device, v.DEKCommitment)
	v.WrapAAD = hex.EncodeToString(aad)
	wrap, err := SealWrap(enc.PublicKey().Bytes(), v.Account, v.Worker, v.Device, dek)
	if err != nil {
		t.Fatal(err)
	}
	v.Wrap = hex.EncodeToString(wrap)
	return v
}

// withGrant adds the grant naming the vectors' device alone, with wrap, at a
// fixed time: WrapsDigest depends on the wrap's bytes, so on the file's.
func (v *deviceVectors) withGrant(t *testing.T) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(seq(0x01))
	wrap, _ := hex.DecodeString(v.Wrap)
	var err error
	if v.WrapsDigest, err = WrapsDigest([]string{v.Device}, map[string][]byte{v.Device: wrap}); err != nil {
		t.Fatal(err)
	}
	if v.Grant, err = SignGrant(key, GrantClaims{Op: OpGrant, Aud: v.Audience, Acct: v.Account, Worker: v.Worker, Seq: v.Seq, DEK: v.DEKCommitment,
		Devices: []string{b64.EncodeToString(key.Public().(ed25519.PublicKey))}, Wraps: v.WrapsDigest, Iat: 1798761600}); err != nil {
		t.Fatal(err)
	}
	claims, _ := b64.DecodeString(v.Grant[:bytes.IndexByte([]byte(v.Grant), '.')])
	v.GrantClaims = string(claims)
}

func TestDeviceVectors(t *testing.T) {
	made := makeDeviceVectors(t)
	if os.Getenv("DEVICE_VECTORS_WRITE") != "" {
		made.withGrant(t)
		out, _ := json.MarshalIndent(made, "", "  ")
		os.MkdirAll(filepath.Dir(deviceVectorsPath), 0o755)
		if err := os.WriteFile(deviceVectorsPath, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(deviceVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var v deviceVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	// Everything but the wrap is deterministic, so it must match.
	made.Wrap, made.Comment = v.Wrap, v.Comment
	made.withGrant(t)
	if made != v {
		t.Fatalf("the vectors changed:\n%+v\nwant\n%+v", made, v)
	}
	priv, _ := hex.DecodeString(v.X25519Private)
	wrap, _ := hex.DecodeString(v.Wrap)
	dek, err := OpenWrap(priv, v.Account, v.Worker, v.Device, v.DEKCommitment, wrap)
	if err != nil || hex.EncodeToString(dek[:]) != v.DEK {
		t.Fatalf("the vector wrap: %v", err)
	}
	if _, _, _, err := parseInclusion(v.Inclusion, v.Audience, v.Account, v.Worker, v.DEKCommitment); err != nil {
		t.Fatalf("the vector inclusion: %v", err)
	}
}

func TestGrantsAreForOneCoordinator(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	me := newTestDevice(t)
	dek := mustDEK(t)
	w, _ := c.CreateWorkerFor(me.caller("acme"))
	g := me.grant(t, "acme", w.ID, 1, dek)

	// The same volume under a coordinator of another audience, or of none.
	for _, aud := range []string{"https://other.example", ""} {
		cfg := c.cfg
		cfg.Audience = aud
		other := &Coordinator{cfg: cfg, state: c.state, busy: map[string]bool{}, accountJobs: map[string]int{}, locks: map[string]*sync.Mutex{}}
		if _, err := g.to(other, me.caller("acme"), w.ID, dek); !errors.Is(err, ErrGrantRefused) {
			t.Errorf("a grant on a coordinator of audience %q: %v", aud, err)
		}
		if err := other.Revoke(me.caller("acme"), w.ID, me.revoke(t, "acme", w.ID, 1)); !errors.Is(err, ErrGrantRefused) {
			t.Errorf("a revoke on a coordinator of audience %q: %v", aud, err)
		}
	}
	// A grant whose own aud is another coordinator's, with inclusions for
	// this one.
	claims := GrantClaims{Op: OpGrant, Aud: "https://other.example", Acct: "acme", Worker: w.ID, Seq: 1, DEK: DEKCommitment(w.ID, dek), Devices: []string{me.b64()}, Iat: time.Now().Unix()}
	claims.Wraps, _ = WrapsDigest([]string{me.id()}, g.wraps)
	elsewhere := g
	elsewhere.token, _ = SignGrant(me.key, claims)
	if _, err := elsewhere.to(c, me.caller("acme"), w.ID, dek); !errors.Is(err, ErrGrantRefused) {
		t.Errorf("a grant for another coordinator: %v", err)
	}
	if _, err := g.to(c, me.caller("acme"), w.ID, dek); err != nil {
		t.Fatal(err)
	}
}

func TestAReGrantWithoutWrapsIsRefused(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	me, admin := newTestDevice(t), newTestDevice(t)
	dek := mustDEK(t)
	w := granted(t, c, me, dek)
	if _, err := me.grantSince(t, "acme", w.ID, 2, dek, map[string]uint64{me.id(): 1}, me, admin).to(c, me.caller("acme"), w.ID, dek); err != nil {
		t.Fatal(err)
	}
	// Grant 3 signs the wraps but the body leaves them out, or signs none.
	bare := me.grantSince(t, "acme", w.ID, 3, dek, map[string]uint64{me.id(): 1, admin.id(): 2}, me, admin)
	if _, err := c.Grant(me.caller("acme"), w.ID, dek, bare.token, bare.inclusions, nil); !errors.Is(err, ErrGrantRefused) {
		t.Errorf("a re-grant with no wraps: %v", err)
	}
	unsigned := GrantClaims{Op: OpGrant, Aud: testAudience, Acct: "acme", Worker: w.ID, Seq: 3, DEK: DEKCommitment(w.ID, dek), Devices: []string{me.b64(), admin.b64()}, Iat: time.Now().Unix()}
	token, _ := SignGrant(me.key, unsigned)
	if _, err := c.Grant(me.caller("acme"), w.ID, dek, token, bare.inclusions, bare.wraps); !errors.Is(err, ErrGrantRefused) {
		t.Errorf("a re-grant that signs no wraps: %v", err)
	}
	got, _ := c.Worker(w.ID)
	for _, d := range got.Devices {
		if len(d.Wrap) != WrapSize {
			t.Errorf("device %s lost its wrap: %d bytes", d.ID, len(d.Wrap))
		}
	}
}

// A listed device's X25519 key can't be a low-order point, to which a wrap
// of the DEK would be sealed under a secret anyone can compute.
func TestALowOrderX25519KeyIsRefused(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	me, admin := newTestDevice(t), newTestDevice(t)
	dek := mustDEK(t)
	w, _ := c.CreateWorkerFor(me.caller("acme"))
	commitment := DEKCommitment(w.ID, dek)
	for _, point := range []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000000",
		"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
		"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"0000000000000000000000000000000000000000000000000000000000000080",
	} {
		enc, _ := hex.DecodeString(point)
		if err := checkX25519(enc); err == nil {
			t.Errorf("%s passed", point)
		}
		g := me.grant(t, "acme", w.ID, 1, dek, me, admin)
		g.inclusions[1] = signRaw(t, admin.key, InclusionClaims{V: InclusionVersion, Typ: InclusionType, Aud: testAudience, Acct: "acme", Worker: w.ID, DEK: commitment,
			Dev: admin.id(), Key: admin.b64(), Enc: b64.EncodeToString(enc), Seq: 1})
		if _, err := g.to(c, me.caller("acme"), w.ID, dek); !errors.Is(err, ErrGrantRefused) || !strings.Contains(err.Error(), "low-order") {
			t.Errorf("%s: %v", point, err)
		}
	}
	if err := checkX25519(admin.enc.PublicKey().Bytes()); err != nil {
		t.Errorf("a real key: %v", err)
	}
	if _, err := me.grant(t, "acme", w.ID, 1, dek, me, admin).to(c, me.caller("acme"), w.ID, dek); err != nil {
		t.Errorf("the grant with real keys: %v", err)
	}
}
