package coordinator

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
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

func newTestDevice(t testing.TB) testDevice {
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
	return Caller{Account: account, Device: d.id(), DeviceKey: d.pub(), Paid: true}
}

// unpaid is d's caller for account with no plan of its own: an identity-only
// Cloud credential.
func (d testDevice) unpaid(account string) Caller {
	c := d.caller(account)
	c.Paid = false
	return c
}

// include is d's inclusion in a team, under account, admitted from entry
// since.
func (d testDevice) include(t testing.TB, team, account string, since uint64) string {
	t.Helper()
	token, err := SignTeamInclusion(d.key, d.enc.PublicKey().Bytes(), TeamInclusion{Aud: testAudience, Team: team, Acct: account, Seq: since})
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

// sign signs l as d, now.
func (d testDevice) sign(t testing.TB, l TeamList) string {
	t.Helper()
	if l.Iat == 0 {
		l.Iat = time.Now().Unix()
	}
	token, err := SignTeamList(d.key, l)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// testTeam is a team as Desktop keeps it: its members, their devices and
// its workers, from which it signs the list after the coordinator's head.
type testTeam struct {
	t       testing.TB
	c       *Coordinator
	id      string
	members map[string]ListMember
	devices map[string][]testDevice
	workers map[string]string
	// since is each listed device's inclusion number, as the last list
	// the coordinator took had it.
	since map[string]uint64
}

func newTestTeam(t testing.TB, c *Coordinator, id string) *testTeam {
	return &testTeam{t: t, c: c, id: id, members: map[string]ListMember{}, devices: map[string][]testDevice{}, workers: map[string]string{}, since: map[string]uint64{}}
}

// set lists a member; a reviewer reaches every worker unless given some.
func (tt *testTeam) set(id, account string, role Role, devices ...testDevice) *ListMember {
	m := ListMember{ID: id, Account: account, Role: role}
	if role == RoleReviewer {
		m.Workers = []string{allWorkers}
	}
	tt.members[id], tt.devices[id] = m, devices
	return &m
}

func (tt *testTeam) update(id string, f func(*ListMember)) {
	m := tt.members[id]
	f(&m)
	tt.members[id] = m
}

func (tt *testTeam) drop(id string) {
	delete(tt.members, id)
	delete(tt.devices, id)
}

func (tt *testTeam) head() (uint64, string) {
	tt.c.mu.Lock()
	defer tt.c.mu.Unlock()
	v := tt.c.teamLogView(tt.id, ^uint64(0))
	return v.Seq, v.Head
}

// list is the next list, unsigned.
func (tt *testTeam) list() TeamList {
	seq, head := tt.head()
	l := TeamList{Aud: testAudience, Team: tt.id, Seq: seq + 1, Prev: head}
	for _, id := range slices.Sorted(maps.Keys(tt.members)) {
		m := tt.members[id]
		devices := slices.Clone(tt.devices[id])
		slices.SortFunc(devices, func(a, b testDevice) int { return strings.Compare(a.id(), b.id()) })
		m.Devices = nil
		for _, d := range devices {
			since, ok := tt.since[d.id()]
			if !ok {
				since = seq + 1
			}
			m.Devices = append(m.Devices, d.include(tt.t, tt.id, m.Account, since))
		}
		l.Members = append(l.Members, m)
	}
	for _, id := range slices.Sorted(maps.Keys(tt.workers)) {
		l.Workers = append(l.Workers, ListWorker{ID: id, DEK: tt.workers[id]})
	}
	return l
}

// push signs the next list as by, of account, and appends it.
func (tt *testTeam) push(by testDevice, account string, deks map[string]DEK) error {
	tt.t.Helper()
	l := tt.list()
	return tt.pushList(by.caller(account), by.sign(tt.t, l), l, deks)
}

func (tt *testTeam) pushList(caller Caller, token string, l TeamList, deks map[string]DEK) error {
	if _, err := tt.c.AppendTeamList(caller, tt.id, token, deks); err != nil {
		return err
	}
	tt.since = map[string]uint64{}
	for _, m := range l.Members {
		for _, token := range m.Devices {
			d, err := parseTeamInclusion(token, testAudience, tt.id, m.Account)
			if err != nil {
				tt.t.Fatal(err)
			}
			tt.since[d.ID] = d.Since
		}
	}
	return nil
}

// addWorker makes a worker over the channel as by and adds it to the team
// with dek.
func (tt *testTeam) addWorker(by testDevice, account string, dek DEK) (Worker, error) {
	tt.t.Helper()
	w, err := tt.c.CreateWorkerFor(by.caller(account))
	if err != nil {
		tt.t.Fatal(err)
	}
	tt.workers[w.ID] = DEKCommitment(w.ID, dek)
	if err := tt.push(by, account, map[string]DEK{w.ID: dek}); err != nil {
		delete(tt.workers, w.ID)
		return Worker{}, err
	}
	return tt.c.Worker(w.ID)
}

// soloTeam is account's team of one, with me as its admin.
func soloTeam(t *testing.T, c *Coordinator, account string, me testDevice) *testTeam {
	t.Helper()
	tt := newTestTeam(t, c, account)
	tt.set("m_owner", account, RoleAdmin, me)
	if err := tt.push(me, account, nil); err != nil {
		t.Fatal(err)
	}
	return tt
}

// granted is a worker made by me over the channel and put in acme's team of
// one with dek.
func granted(t *testing.T, c *Coordinator, me testDevice, dek DEK) Worker {
	t.Helper()
	w, err := soloTeam(t, c, "acme", me).addWorker(me, "acme", dek)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestAWorkerRunsOnlyOnceItsDEKIsGranted(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	me := newTestDevice(t)
	tt := soloTeam(t, c, "acme", me)
	w, err := c.CreateWorkerFor(me.caller("acme"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.PutFile(w.ID, "instructions.md", []byte("x")); !errors.Is(err, ErrNotGranted) {
		t.Errorf("a file before the list: %v", err)
	}
	if _, err := c.Enqueue(w.ID, spec("t1")); !errors.Is(err, ErrNotGranted) {
		t.Errorf("a job before the list: %v", err)
	}
	dek := mustDEK(t)
	tt.workers[w.ID] = DEKCommitment(w.ID, dek)
	if err := tt.push(me, "acme", map[string]DEK{w.ID: dek}); err != nil {
		t.Fatal(err)
	}
	if w, _ = c.Worker(w.ID); w.Team != "acme" || w.Account != "acme" || len(w.Devices) != 1 {
		t.Fatalf("the worker: %+v", w)
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
	if data, err := tree.Read("jobs/" + j.ID + "/outbox/reply.md"); err != nil || !strings.Contains(string(data), "be brief") {
		t.Errorf("the reply under the granted DEK: %q %v", data, err)
	}
	// The coordinator sealed my wrap, which opens to that DEK.
	if got, err := OpenWrap(me.enc.Bytes(), "acme", w.ID, me.id(), w.DEKCommitment, w.Devices[0].Wrap); err != nil || got != dek {
		t.Errorf("my wrap: %v", err)
	}
}

func TestTheV2GrantRoutesAreRetired(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	me := newTestDevice(t)
	w := granted(t, c, me, mustDEK(t))
	api := httptest.NewServer(c.AccountHandler(me.caller("acme")))
	defer api.Close()
	for _, path := range []string{"/v1/workers/" + w.ID + "/grant", "/v1/workers/" + w.ID + "/revoke"} {
		if code, out := do(t, api, "POST", path, `{"v":2,"grant":"x.y"}`); code != http.StatusGone {
			t.Errorf("%s: %d %v", path, code, out)
		}
	}
	if got, _ := c.Worker(w.ID); got.Team != "acme" {
		t.Errorf("the worker after: %+v", got)
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
	// A list can't take a dev API worker into a team.
	tt := soloTeam(t, c, "acme", me)
	dek := mustDEK(t)
	tt.workers[w.ID] = DEKCommitment(w.ID, dek)
	if err := tt.push(me, "acme", map[string]DEK{w.ID: dek}); !errors.Is(err, ErrListRefused) {
		t.Errorf("a list taking a dev API worker: %v", err)
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

// Any device of the account that the team doesn't admit, as fount-infra
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
	tt := newTestTeam(t, c, "acme")
	tt.set("m_owner", "acme", RoleAdmin, me, stranger)
	tt.workers[w.ID] = w.DEKCommitment
	l := tt.list()
	body, _ := json.Marshal(map[string]any{"v": TeamListVersion, "list": stranger.sign(t, l)})
	for _, r := range []struct {
		method, path, body string
		want               int
	}{
		{"GET", "/v1/workers/" + w.ID, "", 404},
		{"PUT", "/v1/workers/" + w.ID + "/root/instructions.md", "x", 404},
		{"GET", "/v1/workers/" + w.ID + "/files", "", 404},
		{"GET", "/v1/workers/" + w.ID + "/files/root/instructions.md", "", 404},
		{"POST", "/v1/workers/" + w.ID + "/jobs", `{"threadId":"t2","sessionId":"s2","instruction":"hi","config":{}}`, 404},
		{"GET", "/v1/jobs/" + j.ID, "", 404},
		// The account's own team's log it reads, to check the passkey
		// vouched for it before it joins (passkeyvouch.go).
		{"GET", "/v1/teams/acme/log", "", 200},
		// Its own list adding itself: it isn't an admin's device.
		{"POST", "/v1/teams/acme/log", string(body), 403},
	} {
		if code, out := do(t, api, r.method, r.path, r.body); code != r.want {
			t.Errorf("%s %s: %d %v", r.method, r.path, code, out)
		}
	}
	if _, list := do(t, api, "GET", "/v1/workers", ""); len(list["workers"].([]any)) != 0 {
		t.Errorf("the stranger's workers: %v", list)
	}
	if got, _ := c.Worker(w.ID); len(got.Devices) != 1 {
		t.Errorf("the worker after: %+v", got)
	}
}

// A request that passed the API's check but waited for the tree while a list
// removed its device fails.
func TestARequestRacingAListThatRemovesItsDeviceFails(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	me, admin := newTestDevice(t), newTestDevice(t)
	dek := mustDEK(t)
	tt := soloTeam(t, c, "acme", me)
	tt.set("m_admin", "acme2", RoleAdmin, admin)
	if err := tt.push(me, "acme", nil); err != nil {
		t.Fatal(err)
	}
	w, err := tt.addWorker(me, "acme", dek)
	if err != nil {
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
	// The admin's list, removing me, lands first, as if it had taken the
	// lock just before them.
	tt.drop("m_owner")
	l := tt.list()
	appended := make(chan error, 1)
	go func() { appended <- tt.pushList(admin.caller("acme2"), admin.sign(t, l), l, nil) }()
	time.Sleep(50 * time.Millisecond)
	lock.Unlock()
	if err := <-read; err != nil && !errors.Is(err, ErrNoWorker) {
		t.Errorf("the read: %v", err)
	}
	if err := <-appended; err != nil {
		t.Fatal(err)
	}
	if err := <-write; err != nil && !errors.Is(err, ErrNoWorker) {
		t.Errorf("the write: %v", err)
	}
	// Whichever got the lock first, nothing of mine passes after the list.
	if _, err := c.readFile(me.id(), w.ID, prefixRoot+"instructions.md"); !errors.Is(err, ErrNoWorker) {
		t.Errorf("a read after: %v", err)
	}
	if err := c.putFile(me.id(), w.ID, "instructions.md", []byte("again")); !errors.Is(err, ErrNoWorker) {
		t.Errorf("a write after: %v", err)
	}
	if _, err := c.enqueue(me.id(), w.ID, spec("t1")); !errors.Is(err, ErrNoWorker) {
		t.Errorf("a job: %v", err)
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
	// A worker in a team no longer counts.
	dek := mustDEK(t)
	me := devices[0]
	tt := soloTeam(t, c, "acme", me)
	tt.workers[first.ID] = DEKCommitment(first.ID, dek)
	if err := tt.push(me, "acme", map[string]DEK{first.ID: dek}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateWorkerFor(me.caller("acme")); err != nil {
		t.Errorf("after a list: %v", err)
	}

	// Past UngrantedTTL the rest go, and can't join a team.
	c.mu.Lock()
	var stale string
	for id, w := range c.state.Workers {
		w.Created = w.Created.Add(-UngrantedTTL)
		if w.WrappedDEK == nil && w.authorizes(me.id()) {
			stale = id
		}
	}
	c.mu.Unlock()
	tt.workers[stale] = DEKCommitment(stale, dek)
	if err := tt.push(me, "acme", map[string]DEK{stale: dek}); !errors.Is(err, ErrListRefused) {
		t.Errorf("adding an expired worker: %v", err)
	}
	delete(tt.workers, stale)
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
		t.Errorf("the team's worker: %v", err)
	}
}
