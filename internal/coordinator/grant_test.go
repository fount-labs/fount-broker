package coordinator

import (
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

// testDevice is a Desktop install's device key.
type testDevice struct{ key ed25519.PrivateKey }

func newTestDevice(t *testing.T) testDevice {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testDevice{key}
}

func (d testDevice) pub() ed25519.PublicKey { return d.key.Public().(ed25519.PublicKey) }

func (d testDevice) id() string { return deviceID(d.pub()) }

func (d testDevice) b64() string { return b64.EncodeToString(d.pub()) }

func (d testDevice) caller(account string) Caller {
	return Caller{Account: account, Device: d.id(), DeviceKey: d.pub()}
}

// grant signs a grant of dek naming devices, or the signer alone.
func (d testDevice) grant(t *testing.T, account, workerID string, seq uint64, dek DEK, devices ...testDevice) string {
	t.Helper()
	if len(devices) == 0 {
		devices = []testDevice{d}
	}
	var keys []string
	for _, dev := range devices {
		keys = append(keys, dev.b64())
	}
	token, err := SignGrant(d.key, GrantClaims{Op: OpGrant, Acct: account, Worker: workerID, Seq: seq, DEK: DEKCommitment(workerID, dek), Devices: keys, Iat: time.Now().Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func (d testDevice) revoke(t *testing.T, account, workerID string, seq uint64) string {
	t.Helper()
	token, err := SignGrant(d.key, GrantClaims{Op: OpRevoke, Acct: account, Worker: workerID, Seq: seq, Iat: time.Now().Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func (d testDevice) grantBody(t *testing.T, account, workerID string, seq uint64, dek DEK, devices ...testDevice) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"v": 1, "dek": dek[:], "grant": d.grant(t, account, workerID, seq, dek, devices...)})
	return string(body)
}

// granted is a worker made by me over the channel and granted dek.
func granted(t *testing.T, c *Coordinator, me testDevice, dek DEK) Worker {
	t.Helper()
	w, err := c.CreateWorkerFor(me.caller("acme"))
	if err != nil {
		t.Fatal(err)
	}
	if w, err = c.Grant(me.caller("acme"), w.ID, dek, me.grant(t, "acme", w.ID, 1, dek), nil); err != nil {
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
	if w, err = c.Grant(me.caller("acme"), w.ID, dek, me.grant(t, "acme", w.ID, 1, dek), nil); err != nil || w.GrantSeq != 1 {
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
	expired, _ := SignGrant(me.key, GrantClaims{Op: OpGrant, Acct: "acme", Worker: w.ID, Seq: 1, DEK: DEKCommitment(w.ID, dek), Devices: []string{me.b64()}, Iat: time.Now().Add(-2 * MaxGrantAge).Unix()})
	twice, _ := SignGrant(me.key, GrantClaims{Op: OpGrant, Acct: "acme", Worker: w.ID, Seq: 1, DEK: DEKCommitment(w.ID, dek), Devices: []string{me.b64(), me.b64()}, Iat: time.Now().Unix()})
	none, _ := SignGrant(me.key, GrantClaims{Op: OpGrant, Acct: "acme", Worker: w.ID, Seq: 1, DEK: DEKCommitment(w.ID, dek), Iat: time.Now().Unix()})
	for _, tc := range []struct {
		name   string
		caller Caller
		dek    DEK
		token  string
		wraps  map[string][]byte
		want   error
	}{
		{"signed by another device", me.caller("acme"), dek, other.grant(t, "acme", w.ID, 1, dek, me), nil, ErrGrantRefused},
		{"from a device the worker doesn't list", other.caller("acme"), dek, other.grant(t, "acme", w.ID, 1, dek), nil, ErrNoWorker},
		{"for another account", me.caller("acme"), dek, me.grant(t, "other", w.ID, 1, dek), nil, ErrGrantRefused},
		{"for another worker", me.caller("acme"), dek, me.grant(t, "acme", "w_0123456789abcdef01234567", 1, dek), nil, ErrGrantRefused},
		{"of another DEK", me.caller("acme"), otherDEK, me.grant(t, "acme", w.ID, 1, dek), nil, ErrGrantRefused},
		{"a revoke", me.caller("acme"), dek, me.revoke(t, "acme", w.ID, 1), nil, ErrGrantRefused},
		{"too old", me.caller("acme"), dek, expired, nil, ErrGrantRefused},
		{"a device twice", me.caller("acme"), dek, twice, nil, ErrGrantRefused},
		{"no devices", me.caller("acme"), dek, none, nil, ErrGrantRefused},
		{"not the next number", me.caller("acme"), dek, me.grant(t, "acme", w.ID, 2, dek), nil, ErrGrantSeq},
		{"a wrap for a device it doesn't name", me.caller("acme"), dek, me.grant(t, "acme", w.ID, 1, dek), map[string][]byte{other.id(): {1}}, ErrGrantRefused},
	} {
		if _, err := c.Grant(tc.caller, w.ID, tc.dek, tc.token, tc.wraps); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	if got, _ := c.Worker(w.ID); got.WrappedDEK != nil || got.GrantSeq != 0 {
		t.Fatalf("a refused grant changed the worker: %+v", got)
	}
	token := me.grant(t, "acme", w.ID, 1, dek)
	if _, err := c.Grant(me.caller("acme"), w.ID, dek, token, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Grant(me.caller("acme"), w.ID, dek, token, nil); !errors.Is(err, ErrGrantSeq) {
		t.Errorf("a replayed grant: %v", err)
	}
}

func TestReGrantsChangeTheDevicesButNeverTheDEK(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	me, admin, stranger := newTestDevice(t), newTestDevice(t), newTestDevice(t)
	dek := mustDEK(t)
	w := granted(t, c, me, dek)

	if _, err := c.Grant(me.caller("acme"), w.ID, mustDEK(t), me.grant(t, "acme", w.ID, 2, mustDEK(t)), nil); !errors.Is(err, ErrGrantRefused) {
		t.Errorf("a grant whose signature covers another DEK: %v", err)
	}
	other := mustDEK(t)
	if _, err := c.Grant(me.caller("acme"), w.ID, other, me.grant(t, "acme", w.ID, 2, other), nil); !errors.Is(err, ErrDEKChanged) {
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

	// Name the admin device, with its wrap of the DEK.
	body, _ := json.Marshal(map[string]any{"v": 1, "dek": dek[:], "grant": me.grant(t, "acme", w.ID, 2, dek, me, admin), "wraps": map[string][]byte{admin.id(): []byte("wrapped to admin")}})
	if code, out := do(t, srv(me), "POST", "/v1/workers/"+w.ID+"/grant", string(body)); code != http.StatusOK || out["grantSeq"] != 2.0 || len(out["devices"].([]any)) != 2 || out["wrap"] != nil {
		t.Fatalf("naming an admin: %d %v", code, out)
	}
	code, out := do(t, adminAPI, "GET", "/v1/workers/"+w.ID, "")
	if code != http.StatusOK || out["wrap"] != base64.StdEncoding.EncodeToString([]byte("wrapped to admin")) {
		t.Fatalf("the admin's view: %d %v", code, out)
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
	if code, out := do(t, adminAPI, "POST", "/v1/workers/"+w.ID+"/grant", admin.grantBody(t, "acme", w.ID, 3, dek)); code != http.StatusOK {
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
	if _, err := c.Grant(me.caller("acme"), w.ID, dek, me.grant(t, "acme", w.ID, 2, dek, me, admin), nil); err != nil {
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
	if _, err := c.Grant(me.caller("acme"), w.ID, dek, me.grant(t, "acme", w.ID, 2, dek, me, admin), nil); err != nil {
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
	if _, err := c.Grant(me.caller("acme"), first.ID, dek, me.grant(t, "acme", first.ID, 1, dek), nil); err != nil {
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
	if _, err := c.Grant(me.caller("acme"), stale, dek, me.grant(t, "acme", stale, 1, dek), nil); !errors.Is(err, ErrNoWorker) {
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
