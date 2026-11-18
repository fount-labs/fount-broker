package coordinator

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testAudience is the test coordinator's Config.Audience.
const testAudience = "https://coordinator.example"

// testDevice is a Desktop install's device keys.
type testDevice struct {
	key ed25519.PrivateKey
	enc *ecdh.PrivateKey
}

func newTestDevice(t *testing.T) testDevice {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testDevice{key, enc}
}

func (d testDevice) pub() ed25519.PublicKey { return d.key.Public().(ed25519.PublicKey) }

func (d testDevice) id() string { return deviceID(d.pub()) }

func (d testDevice) b64() string { return b64.EncodeToString(d.pub()) }

func (d testDevice) caller(account string) Caller {
	return Caller{Account: account, Device: d.id(), DeviceKey: d.pub()}
}

// include is d's inclusion in a worker, listed from grant since.
func (d testDevice) include(t *testing.T, account, workerID string, since uint64, dek DEK) string {
	t.Helper()
	token, err := SignInclusion(d.key, d.enc.PublicKey().Bytes(), InclusionClaims{Aud: testAudience, Acct: account, Worker: workerID, DEK: DEKCommitment(workerID, dek), Seq: since})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func (d testDevice) wrap(t *testing.T, account, workerID string, dek DEK) []byte {
	t.Helper()
	wrap, err := SealWrap(d.enc.PublicKey().Bytes(), account, workerID, d.id(), dek)
	if err != nil {
		t.Fatal(err)
	}
	return wrap
}

// testGrant is a grant request's parts.
type testGrant struct {
	token      string
	inclusions []string
	wraps      map[string][]byte
}

// grant signs a grant of dek naming devices, or the signer alone, each with
// an inclusion for this grant and a wrap.
func (d testDevice) grant(t *testing.T, account, workerID string, seq uint64, dek DEK, devices ...testDevice) testGrant {
	t.Helper()
	return d.grantSince(t, account, workerID, seq, dek, nil, devices...)
}

// grantSince is grant with the devices already listed on inclusions from the
// grants since names.
func (d testDevice) grantSince(t *testing.T, account, workerID string, seq uint64, dek DEK, since map[string]uint64, devices ...testDevice) testGrant {
	t.Helper()
	if len(devices) == 0 {
		devices = []testDevice{d}
	}
	g := testGrant{wraps: map[string][]byte{}}
	var keys, ids []string
	for _, dev := range devices {
		keys, ids = append(keys, dev.b64()), append(ids, dev.id())
		s, ok := since[dev.id()]
		if !ok {
			s = seq
		}
		g.inclusions = append(g.inclusions, dev.include(t, account, workerID, s, dek))
		g.wraps[dev.id()] = dev.wrap(t, account, workerID, dek)
	}
	digest, err := WrapsDigest(ids, g.wraps)
	if err != nil {
		t.Fatal(err)
	}
	if g.token, err = SignGrant(d.key, GrantClaims{Op: OpGrant, Aud: testAudience, Acct: account, Worker: workerID, Seq: seq, DEK: DEKCommitment(workerID, dek), Devices: keys, Wraps: digest, Iat: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
	return g
}

func (g testGrant) to(c *Coordinator, caller Caller, workerID string, dek DEK) (Worker, error) {
	return c.Grant(caller, workerID, dek, g.token, g.inclusions, g.wraps)
}

func (g testGrant) body(dek DEK) string {
	body, _ := json.Marshal(map[string]any{"v": GrantBodyVersion, "dek": dek[:], "grant": g.token, "inclusions": g.inclusions, "wraps": g.wraps})
	return string(body)
}

func (d testDevice) revoke(t *testing.T, account, workerID string, seq uint64) string {
	t.Helper()
	token, err := SignGrant(d.key, GrantClaims{Op: OpRevoke, Aud: testAudience, Acct: account, Worker: workerID, Seq: seq, Iat: time.Now().Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func (d testDevice) grantBody(t *testing.T, account, workerID string, seq uint64, dek DEK, devices ...testDevice) string {
	t.Helper()
	return d.grant(t, account, workerID, seq, dek, devices...).body(dek)
}

// granted is a worker made by me over the channel and granted dek.
func granted(t *testing.T, c *Coordinator, me testDevice, dek DEK) Worker {
	t.Helper()
	w, err := c.CreateWorkerFor(me.caller("acme"))
	if err != nil {
		t.Fatal(err)
	}
	if w, err = me.grant(t, "acme", w.ID, 1, dek).to(c, me.caller("acme"), w.ID, dek); err != nil {
		t.Fatal(err)
	}
	return w
}

func TestAWorkerRunsOnlyOnceItsDEKIsGranted(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	me := newTestDevice(t)
	w, err := c.CreateWorkerFor(me.caller("acme"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.PutFile(w.ID, "instructions.md", []byte("x")); !errors.Is(err, ErrNotGranted) {
		t.Errorf("a file before the grant: %v", err)
	}
	if _, err := c.Enqueue(w.ID, spec("t1")); !errors.Is(err, ErrNotGranted) {
		t.Errorf("a job before the grant: %v", err)
	}
	dek := mustDEK(t)
	if w, err = me.grant(t, "acme", w.ID, 1, dek).to(c, me.caller("acme"), w.ID, dek); err != nil || w.GrantSeq != 1 {
		t.Fatalf("grant: %v %+v", err, w)
	}
	if err := c.PutFile(w.ID, "instructions.md", []byte("be brief")); err != nil {
		t.Fatal(err)
	}
	j, err := c.Enqueue(w.ID, spec("t1"))
	if err != nil {
		t.Fatal(err)
	}
	if done := waitJob(t, c, j.ID); done.State != JobFinished {
		t.Fatalf("%s %s", done.State, done.Error)
	}
	// The tree is under the DEK Desktop sent, not one the coordinator made.
	tree, err := LoadTree(c.cfg.Store, w.ID, dek, 0)
	if err != nil {
		t.Fatal(err)
	}
	if data, err := tree.Read(prefixRoot + "threads/t1/outputs/" + j.ID + "/reply.md"); err != nil || !strings.Contains(string(data), "be brief") {
		t.Errorf("the reply under the granted DEK: %q %v", data, err)
	}
}

func TestAGrantIsCheckedAgainstItsSignerAndTheWorker(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	me, other := newTestDevice(t), newTestDevice(t)
	w, _ := c.CreateWorkerFor(me.caller("acme"))
	dek, otherDEK := mustDEK(t), mustDEK(t)
	signed := func(c GrantClaims) testGrant {
		g := me.grant(t, "acme", w.ID, 1, dek)
		c.Op, c.Aud, c.Acct, c.Worker, c.Seq, c.DEK = OpGrant, testAudience, "acme", w.ID, 1, DEKCommitment(w.ID, dek)
		ids := []string{}
		for _, k := range c.Devices {
			key, _ := b64.DecodeString(k)
			ids = append(ids, deviceID(key))
		}
		c.Wraps, _ = WrapsDigest(ids, g.wraps)
		if c.Iat == 0 {
			c.Iat = time.Now().Unix()
		}
		g.token, _ = SignGrant(me.key, c)
		return g
	}
	expired := signed(GrantClaims{Devices: []string{me.b64()}, Iat: time.Now().Add(-2 * MaxGrantAge).Unix()})
	twice := signed(GrantClaims{Devices: []string{me.b64(), me.b64()}})
	none := signed(GrantClaims{})
	withoutMe := other.grant(t, "acme", w.ID, 1, dek)
	withoutMe.token = signed(GrantClaims{Devices: []string{other.b64()}}).token
	revoke := me.grant(t, "acme", w.ID, 1, dek)
	revoke.token = me.revoke(t, "acme", w.ID, 1)
	for _, tc := range []struct {
		name   string
		caller Caller
		dek    DEK
		g      testGrant
		want   error
	}{
		{"signed by another device", me.caller("acme"), dek, other.grant(t, "acme", w.ID, 1, dek, me), ErrGrantRefused},
		{"from a device the worker doesn't list", other.caller("acme"), dek, other.grant(t, "acme", w.ID, 1, dek), ErrNoWorker},
		{"for another account", me.caller("acme"), dek, me.grant(t, "other", w.ID, 1, dek), ErrGrantRefused},
		{"for another worker", me.caller("acme"), dek, me.grant(t, "acme", "w_0123456789abcdef01234567", 1, dek), ErrGrantRefused},
		{"of another DEK", me.caller("acme"), otherDEK, me.grant(t, "acme", w.ID, 1, dek), ErrGrantRefused},
		{"a revoke", me.caller("acme"), dek, revoke, ErrGrantRefused},
		{"too old", me.caller("acme"), dek, expired, ErrGrantRefused},
		{"a device twice", me.caller("acme"), dek, twice, ErrGrantRefused},
		{"no devices", me.caller("acme"), dek, none, ErrGrantRefused},
		{"not naming its signer", me.caller("acme"), dek, withoutMe, ErrGrantRefused},
		{"not the next number", me.caller("acme"), dek, me.grant(t, "acme", w.ID, 2, dek), ErrGrantSeq},
	} {
		if _, err := tc.g.to(c, tc.caller, w.ID, tc.dek); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	if got, _ := c.Worker(w.ID); got.WrappedDEK != nil || got.GrantSeq != 0 {
		t.Fatalf("a refused grant changed the worker: %+v", got)
	}
	g := me.grant(t, "acme", w.ID, 1, dek)
	if _, err := g.to(c, me.caller("acme"), w.ID, dek); err != nil {
		t.Fatal(err)
	}
	if _, err := g.to(c, me.caller("acme"), w.ID, dek); !errors.Is(err, ErrGrantSeq) {
		t.Errorf("a replayed grant: %v", err)
	}
}

func TestReGrantsChangeTheDevicesButNeverTheDEK(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	me, admin, stranger := newTestDevice(t), newTestDevice(t), newTestDevice(t)
	dek := mustDEK(t)
	w := granted(t, c, me, dek)

	since := map[string]uint64{me.id(): 1}
	if _, err := me.grantSince(t, "acme", w.ID, 2, mustDEK(t), since).to(c, me.caller("acme"), w.ID, mustDEK(t)); !errors.Is(err, ErrGrantRefused) {
		t.Errorf("a grant whose signature covers another DEK: %v", err)
	}
	other := mustDEK(t)
	if _, err := me.grantSince(t, "acme", w.ID, 2, other, since).to(c, me.caller("acme"), w.ID, other); !errors.Is(err, ErrDEKChanged) {
		t.Errorf("a signed grant of another DEK: %v", err)
	}

	srv := func(d testDevice) *httptest.Server {
		s := httptest.NewServer(c.AccountHandler(d.caller("acme")))
		t.Cleanup(s.Close)
		return s
	}
	adminAPI, strangerAPI := srv(admin), srv(stranger)
	if code, _ := do(t, adminAPI, "GET", "/v1/workers/"+w.ID, ""); code != http.StatusNotFound {
		t.Errorf("an admin device before it is named: %d", code)
	}

	// A version 1 body, with no inclusions, is refused.
	v1, _ := json.Marshal(map[string]any{"v": 1, "dek": dek[:], "grant": me.grantSince(t, "acme", w.ID, 2, dek, since, me, admin).token})
	if code, _ := do(t, srv(me), "POST", "/v1/workers/"+w.ID+"/grant", string(v1)); code != http.StatusBadRequest {
		t.Errorf("a version 1 grant: %d", code)
	}
	// Name the admin device, which signs its inclusion for grant 2.
	body := me.grantSince(t, "acme", w.ID, 2, dek, since, me, admin).body(dek)
	if code, out := do(t, srv(me), "POST", "/v1/workers/"+w.ID+"/grant", body); code != http.StatusOK || out["grantSeq"] != 2.0 || len(out["devices"].([]any)) != 2 || len(out["inclusions"].([]any)) != 2 {
		t.Fatalf("naming an admin: %d %v", code, out)
	}
	code, out := do(t, adminAPI, "GET", "/v1/workers/"+w.ID, "")
	if code != http.StatusOK {
		t.Fatalf("the admin's view: %d %v", code, out)
	}
	wrap, _ := base64.StdEncoding.DecodeString(out["wrap"].(string))
	if got, err := OpenWrap(admin.enc.Bytes(), "acme", w.ID, admin.id(), out["dekCommitment"].(string), wrap); err != nil || got != dek {
		t.Fatalf("the admin's wrap: %v", err)
	}
	if code, _ := do(t, adminAPI, "PUT", "/v1/workers/"+w.ID+"/root/instructions.md", "from the admin"); code != http.StatusNoContent {
		t.Errorf("the admin's write: %d", code)
	}
	// Any device of the account that the grant doesn't name, as one
	// fount-infra could vouch for on its own, sees nothing.
	if code, _ := do(t, strangerAPI, "GET", "/v1/workers/"+w.ID+"/files/root/instructions.md", ""); code != http.StatusNotFound {
		t.Errorf("an unnamed device: %d", code)
	}

	// The admin removes the first device.
	if code, out := do(t, adminAPI, "POST", "/v1/workers/"+w.ID+"/grant", admin.grantSince(t, "acme", w.ID, 3, dek, map[string]uint64{admin.id(): 2}).body(dek)); code != http.StatusOK {
		t.Fatalf("the admin's grant: %d %v", code, out)
	}
	if code, _ := do(t, srv(me), "GET", "/v1/workers/"+w.ID, ""); code != http.StatusNotFound {
		t.Errorf("a removed device: %d", code)
	}
	if code, out := do(t, srv(me), "GET", "/v1/workers", ""); len(out["workers"].([]any)) != 0 {
		t.Errorf("a removed device's list: %d %v", code, out)
	}

	// The list and the DEK outlive a restart.
	c2, err := New(c.cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := c2.Worker(w.ID)
	if got.GrantSeq != 3 || !got.authorizes(admin.id()) || got.authorizes(me.id()) {
		t.Errorf("after a restart: %+v", got)
	}
	if data, err := c2.ReadFile(w.ID, prefixRoot+"instructions.md"); err != nil || string(data) != "from the admin" {
		t.Errorf("after a restart: %q %v", data, err)
	}
}

func TestRevokeMovesTheWorkerBack(t *testing.T) {
	c, cancel := newTestCoordinator(t, "hang", time.Minute)
	me, admin := newTestDevice(t), newTestDevice(t)
	dek := mustDEK(t)
	w := granted(t, c, me, dek)
	if _, err := me.grantSince(t, "acme", w.ID, 2, dek, map[string]uint64{me.id(): 1}, me, admin).to(c, me.caller("acme"), w.ID, dek); err != nil {
		t.Fatal(err)
	}
	c.PutFile(w.ID, "instructions.md", []byte("be brief"))
	running, _ := c.Enqueue(w.ID, spec("t1"))
	queued, _ := c.Enqueue(w.ID, spec("t2"))
	deadline := time.Now().Add(10 * time.Second)
	for j, _ := c.Job(running.ID); j.State != JobRunning && time.Now().Before(deadline); j, _ = c.Job(running.ID) {
		time.Sleep(10 * time.Millisecond)
	}
	if err := c.Revoke(admin.caller("acme"), w.ID, admin.revoke(t, "acme", w.ID, 3)); !errors.Is(err, ErrBusy) {
		t.Fatalf("a revoke while a job runs: %v", err)
	}
	if err := c.Revoke(newTestDevice(t).caller("acme"), w.ID, admin.revoke(t, "acme", w.ID, 3)); !errors.Is(err, ErrGrantRefused) {
		t.Errorf("a revoke the caller didn't sign: %v", err)
	}
	cancel()
	c.running.Wait()

	if err := c.Revoke(admin.caller("acme"), w.ID, admin.revoke(t, "acme", w.ID, 2)); !errors.Is(err, ErrGrantSeq) {
		t.Errorf("a revoke not numbered next: %v", err)
	}
	if err := c.Revoke(admin.caller("acme"), w.ID, admin.revoke(t, "acme", w.ID, 3)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Worker(w.ID); !errors.Is(err, ErrNoWorker) {
		t.Errorf("the worker after a revoke: %v", err)
	}
	for _, id := range []string{running.ID, queued.ID} {
		if _, err := c.Job(id); !errors.Is(err, ErrNoJob) {
			t.Errorf("job %s after a revoke: %v", id, err)
		}
	}
	if left, _ := os.ReadDir(filepath.Join(c.cfg.Store.(DirStore).Root, w.ID)); len(left) != 0 {
		t.Errorf("%d objects left", len(left))
	}
	if _, err := New(c.cfg); err != nil {
		t.Errorf("boot after a revoke: %v", err)
	}
}

func TestTheChannelNeverOpensADevAPIWorker(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	w, _ := c.CreateWorker("acme", nil)
	// An empty worker on the volume too: boot skips the key check for it.
	me := newTestDevice(t)
	if _, err := c.CreateWorkerFor(me.caller("acme")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(c.cfg); err != nil {
		t.Fatalf("boot with an ungranted worker: %v", err)
	}
	api := httptest.NewServer(c.AccountHandler(me.caller("acme")))
	defer api.Close()
	if code, _ := do(t, api, "GET", "/v1/workers/"+w.ID, ""); code != http.StatusNotFound {
		t.Errorf("a dev API worker over the channel: %d", code)
	}
	dek := mustDEK(t)
	if code, _ := do(t, api, "POST", "/v1/workers/"+w.ID+"/grant", me.grantBody(t, "acme", w.ID, 1, dek)); code != http.StatusNotFound {
		t.Errorf("a grant of a dev API worker: %d", code)
	}
	if _, list := do(t, api, "GET", "/v1/workers", ""); len(list["workers"].([]any)) != 1 {
		t.Errorf("the device's workers: %v", list)
	}
	// The dev API's view is as it was.
	dev := httptest.NewServer(c.Handler())
	defer dev.Close()
	if code, out := do(t, dev, "GET", "/v0/workers/"+w.ID, ""); code != 200 || len(out) != 4 {
		t.Errorf("the dev API's view: %d %v", code, out)
	}
}

func TestDEKCommitmentIsBoundToTheWorker(t *testing.T) {
	dek := mustDEK(t)
	a, b := DEKCommitment("w_0123456789abcdef01234567", dek), DEKCommitment("w_0123456789abcdef01234568", dek)
	if a == b || a == DEKCommitment("w_0123456789abcdef01234567", mustDEK(t)) || len(a) != 43 {
		t.Errorf("%s %s", a, b)
	}
}

func TestTheDevAPINeverOpensAChannelWorker(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	me := newTestDevice(t)
	w := granted(t, c, me, mustDEK(t))
	c.PutFile(w.ID, "instructions.md", []byte("be brief"))
	j, _ := c.Enqueue(w.ID, spec("t1"))
	waitJob(t, c, j.ID)
	dev := httptest.NewServer(c.Handler())
	defer dev.Close()
	for _, r := range []struct{ method, path, body string }{
		{"GET", "/v0/workers/" + w.ID, ""},
		{"PUT", "/v0/workers/" + w.ID + "/root/instructions.md", "x"},
		{"GET", "/v0/workers/" + w.ID + "/files", ""},
		{"GET", "/v0/workers/" + w.ID + "/files/root/instructions.md", ""},
		{"POST", "/v0/workers/" + w.ID + "/jobs", `{"threadId":"t2","sessionId":"s2","instruction":"hi","config":{}}`},
		{"GET", "/v0/jobs/" + j.ID, ""},
	} {
		if code, out := do(t, dev, r.method, r.path, r.body); code != http.StatusNotFound {
			t.Errorf("%s %s: %d %v", r.method, r.path, code, out)
		}
	}
}

// Any device of the account that the worker doesn't list, as fount-infra
// could vouch for on its own, finds nothing on any route.
func TestAnUnlistedDeviceFindsNothing(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	me, stranger := newTestDevice(t), newTestDevice(t)
	dek := mustDEK(t)
	w := granted(t, c, me, dek)
	c.PutFile(w.ID, "instructions.md", []byte("be brief"))
	j, _ := c.Enqueue(w.ID, spec("t1"))
	waitJob(t, c, j.ID)
	api := httptest.NewServer(c.AccountHandler(stranger.caller("acme")))
	defer api.Close()
	revoke, _ := json.Marshal(map[string]any{"v": 1, "grant": stranger.revoke(t, "acme", w.ID, 2)})
	for _, r := range []struct{ method, path, body string }{
		{"GET", "/v1/workers/" + w.ID, ""},
		{"PUT", "/v1/workers/" + w.ID + "/root/instructions.md", "x"},
		{"GET", "/v1/workers/" + w.ID + "/files", ""},
		{"GET", "/v1/workers/" + w.ID + "/files/root/instructions.md", ""},
		{"POST", "/v1/workers/" + w.ID + "/jobs", `{"threadId":"t2","sessionId":"s2","instruction":"hi","config":{}}`},
		{"GET", "/v1/jobs/" + j.ID, ""},
		{"POST", "/v1/workers/" + w.ID + "/grant", stranger.grantBody(t, "acme", w.ID, 2, dek, stranger, me)},
		{"POST", "/v1/workers/" + w.ID + "/revoke", string(revoke)},
	} {
		if code, out := do(t, api, r.method, r.path, r.body); code != http.StatusNotFound {
			t.Errorf("%s %s: %d %v", r.method, r.path, code, out)
		}
	}
	if _, list := do(t, api, "GET", "/v1/workers", ""); len(list["workers"].([]any)) != 0 {
		t.Errorf("the stranger's workers: %v", list)
	}
	if got, _ := c.Worker(w.ID); got.GrantSeq != 1 || len(got.Devices) != 1 {
		t.Errorf("the worker after: %+v", got)
	}
}

// A request that passed the API's check but waited for the tree while a
// grant removed its device fails.
func TestARequestRacingARegrantThatRemovesItsDeviceFails(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	me, admin := newTestDevice(t), newTestDevice(t)
	dek := mustDEK(t)
	w := granted(t, c, me, dek)
	if _, err := me.grantSince(t, "acme", w.ID, 2, dek, map[string]uint64{me.id(): 1}, me, admin).to(c, me.caller("acme"), w.ID, dek); err != nil {
		t.Fatal(err)
	}
	c.PutFile(w.ID, "instructions.md", []byte("be brief"))
	lock, _, _ := c.workerLock(w.ID)
	lock.Lock()
	read, write := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := c.readFile(me.id(), w.ID, prefixRoot+"instructions.md")
		read <- err
	}()
	go func() { write <- c.putFile(me.id(), w.ID, "instructions.md", []byte("from a removed device")) }()
	time.Sleep(50 * time.Millisecond)
	// The admin's grant, removing me, lands first, as if it had taken the
	// lock just before them.
	c.mu.Lock()
	c.state.Workers[w.ID].Devices = c.state.Workers[w.ID].Devices[1:]
	c.mu.Unlock()
	lock.Unlock()
	if err := <-read; !errors.Is(err, ErrNoWorker) {
		t.Errorf("the read: %v", err)
	}
	if err := <-write; !errors.Is(err, ErrNoWorker) {
		t.Errorf("the write: %v", err)
	}
	if _, err := c.enqueue(me.id(), w.ID, spec("t1")); !errors.Is(err, ErrNoWorker) {
		t.Errorf("a job: %v", err)
	}
	if data, _ := c.ReadFile(w.ID, prefixRoot+"instructions.md"); string(data) != "be brief" {
		t.Errorf("the file: %q", data)
	}
}

func TestUngrantedWorkersAreCappedAndExpire(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	devices := make([]testDevice, MaxUngrantedPerAccount/MaxUngrantedPerDevice+1)
	for i := range devices {
		devices[i] = newTestDevice(t)
	}
	var first Worker
	for i, d := range devices[:len(devices)-1] {
		for j := range MaxUngrantedPerDevice {
			w, err := c.CreateWorkerFor(d.caller("acme"))
			if err != nil {
				t.Fatalf("device %d, worker %d: %v", i, j, err)
			}
			if i == 0 && j == 0 {
				first = w
			}
		}
		if _, err := c.CreateWorkerFor(d.caller("acme")); !errors.Is(err, ErrTooManyUngranted) {
			t.Errorf("device %d's worker %d: %v", i, MaxUngrantedPerDevice+1, err)
		}
	}
	last := devices[len(devices)-1]
	if _, err := c.CreateWorkerFor(last.caller("acme")); !errors.Is(err, ErrTooManyUngranted) {
		t.Errorf("the account's worker %d: %v", MaxUngrantedPerAccount+1, err)
	}
	api := httptest.NewServer(c.AccountHandler(last.caller("acme")))
	defer api.Close()
	if code, _ := do(t, api, "POST", "/v1/workers", "{}"); code != http.StatusTooManyRequests {
		t.Errorf("over the API: %d", code)
	}
	// Another account's are its own.
	if _, err := c.CreateWorkerFor(last.caller("other")); err != nil {
		t.Errorf("another account: %v", err)
	}
	// A granted worker no longer counts.
	dek := mustDEK(t)
	me := devices[0]
	if _, err := me.grant(t, "acme", first.ID, 1, dek).to(c, me.caller("acme"), first.ID, dek); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateWorkerFor(me.caller("acme")); err != nil {
		t.Errorf("after a grant: %v", err)
	}

	// Past UngrantedTTL the rest go, and can't be granted.
	c.mu.Lock()
	var stale string
	for id, w := range c.state.Workers {
		w.Created = w.Created.Add(-UngrantedTTL)
		if w.WrappedDEK == nil && w.authorizes(me.id()) {
			stale = id
		}
	}
	c.mu.Unlock()
	if _, err := me.grant(t, "acme", stale, 1, dek).to(c, me.caller("acme"), stale, dek); !errors.Is(err, ErrNoWorker) {
		t.Errorf("granting an expired worker: %v", err)
	}
	c.ExpireUngranted()
	c2, err := New(c.cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range []string{"acme", "other"} {
		for _, w := range c2.Workers(account) {
			if w.ID != first.ID {
				t.Errorf("%s's worker %s outlived its TTL", account, w.ID)
			}
		}
	}
	if _, err := c2.Worker(first.ID); err != nil {
		t.Errorf("the granted worker: %v", err)
	}
}
