package coordinator

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// rawObjects is every object the store holds for a worker, by id.
func rawObjects(t *testing.T, c *Coordinator, workerID string) map[string][]byte {
	t.Helper()
	dir := filepath.Join(c.cfg.Store.(DirStore).Root, workerID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = data
	}
	return out
}

// opensAny says whether dek opens any of objs as a blob or the manifest, at
// any epoch's AAD.
func opensAny(dek DEK, workerID string, objs map[string][]byte) bool {
	for id, sealed := range objs {
		for n := uint32(0); n < 4; n++ {
			if _, err := open(dek[:], sealed, epochAAD(purposeBlob, workerID, id, n)); err == nil {
				return true
			}
			if _, err := open(dek[:], sealed, epochAAD(purposeManifest, workerID, "", n)); err == nil {
				return true
			}
		}
	}
	return false
}

func workerNow(t *testing.T, c *Coordinator, id string) Worker {
	t.Helper()
	w, err := c.Worker(id)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// Finding 2 (team security review 2026-11-23): removing a member gives each
// worker they reached a new DEK epoch. What the worker writes after is under
// it, which the removed device's DEK doesn't open; the remaining devices get
// a wrap of it and the coordinator still reads every file, old and new.
func TestARemovedDeviceDoesntOpenWhatTheWorkerWritesAfter(t *testing.T) {
	f := newTeamFixture(t)
	if err := f.c.PutFile(f.w1.ID, "notes/before.md", []byte("before")); err != nil {
		t.Fatal(err)
	}
	before := rawObjects(t, f.c, f.w1.ID)
	if !opensAny(f.dek1, f.w1.ID, before) {
		t.Fatal("the DEK opens nothing before: the test isn't looking")
	}

	f.tt.drop("m_reviewer")
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	w := workerNow(t, f.c, f.w1.ID)
	if len(w.DEKEpochs) != 1 || w.DEKEpochs[0].Epoch != 1 || w.ManifestEpoch != 1 {
		t.Fatalf("epochs %d, manifest epoch %d", len(w.DEKEpochs), w.ManifestEpoch)
	}
	if w.DEKCommitment != DEKCommitment(w.ID, f.dek1) {
		t.Error("the list's commitment changed")
	}
	if err := f.c.PutFile(f.w1.ID, "notes/after.md", []byte("after")); err != nil {
		t.Fatal(err)
	}
	newObjs := map[string][]byte{}
	for id, data := range rawObjects(t, f.c, f.w1.ID) {
		if old, ok := before[id]; !ok || !bytes.Equal(old, data) {
			newObjs[id] = data
		}
	}
	if len(newObjs) < 2 {
		t.Fatalf("%d new objects, want the file and the manifest", len(newObjs))
	}
	if opensAny(f.dek1, f.w1.ID, newObjs) {
		t.Fatal("the removed device's DEK opens what was written after its removal")
	}
	for _, p := range []string{"notes/before.md", "notes/after.md"} {
		if _, err := f.c.ReadFile(f.w1.ID, prefixRoot+p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}

	// The admin's device gets a wrap of the new epoch, bound to its
	// commitment, and it opens the new objects; the first wrap is as before.
	srv := f.api(t, f.admin, "dev")
	code, out := do(t, srv, "GET", "/v1/workers/"+f.w1.ID, "")
	if code != 200 {
		t.Fatalf("GET: %d %v", code, out)
	}
	raw, _ := json.Marshal(out)
	var view workerView
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatal(err)
	}
	if view.DEKCommitment != w.DEKCommitment || view.Wrap == nil || len(view.Epochs) != 1 {
		t.Fatalf("view: commitment %q, wrap %v, epochs %d", view.DEKCommitment, view.Wrap != nil, len(view.Epochs))
	}
	if _, err := OpenWrap(f.admin.enc.Bytes(), "acme", w.ID, f.admin.id(), view.DEKCommitment, view.Wrap); err != nil {
		t.Errorf("the first wrap: %v", err)
	}
	e := view.Epochs[0]
	dek1, err := OpenWrap(f.admin.enc.Bytes(), "acme", w.ID, f.admin.id(), e.Commitment, e.Wrap)
	if err != nil {
		t.Fatalf("the epoch wrap: %v", err)
	}
	if e.Epoch != 1 || !opensAny(dek1, f.w1.ID, newObjs) {
		t.Error("the epoch-1 wrap doesn't open what's under epoch 1")
	}

	// w2 lost the reviewer too; a list that loses no one adds no epoch.
	if n := len(workerNow(t, f.c, f.w2.ID).DEKEpochs); n != 1 {
		t.Errorf("w2: %d epochs", n)
	}
	f.tt.set("m_zed", "zed", RoleAdmin, newTestDevice(t))
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	if n := len(workerNow(t, f.c, f.w1.ID).DEKEpochs); n != 1 {
		t.Errorf("adding a member: %d epochs", n)
	}
	// The new member's device gets every epoch, so reads old objects too.
	for _, d := range workerNow(t, f.c, f.w1.ID).Devices {
		if d.Wrap == nil || len(d.EpochWraps) != 1 {
			t.Errorf("device %s: wrap %v, %d epoch wraps", d.ID, d.Wrap != nil, len(d.EpochWraps))
		}
	}
}

// Each kind of lost reach rotates; a removed device of a member who stays
// does too.
func TestEveryLostReachRotates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(f teamFixture)
	}{
		{"an admin's device removed", func(f teamFixture) { f.tt.devices["m_admin"] = nil }},
		{"an admin demoted off the worker", func(f teamFixture) {
			f.tt.update("m_admin", func(m *ListMember) { m.Role, m.Workers = RoleReviewer, []string{f.w2.ID} })
		}},
		{"a reviewer unassigned", func(f teamFixture) {
			f.tt.update("m_reviewer", func(m *ListMember) { m.Workers = []string{f.w2.ID} })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newTeamFixture(t)
			tc.change(f)
			if err := f.tt.push(f.owner, "acme", nil); err != nil {
				t.Fatal(err)
			}
			if n := len(workerNow(t, f.c, f.w1.ID).DEKEpochs); n != 1 {
				t.Errorf("%d epochs", n)
			}
		})
	}
}

// Two removals make two epochs; a restart and a backup restored open every
// file, each under the epoch its entry names.
func TestEpochsSurviveARestartAndARestore(t *testing.T) {
	v := newVaultRig(t, nil)
	c := v.boot(t.TempDir())
	owner, admin, reviewer := newTestDevice(t), newTestDevice(t), newTestDevice(t)
	tt := soloTeam(t, c, "acme", owner)
	tt.set("m_admin", "dev", RoleAdmin, admin)
	tt.set("m_reviewer", "maria", RoleReviewer, reviewer)
	if err := tt.push(owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	w, err := tt.addWorker(owner, "acme", mustDEK(t))
	if err != nil {
		t.Fatal(err)
	}
	files := []string{"a.md", "b.md", "c.md"}
	write := func(c *Coordinator, i int) {
		if err := c.PutFile(w.ID, files[i], []byte(files[i])); err != nil {
			t.Fatal(err)
		}
	}
	write(c, 0)
	tt.drop("m_reviewer")
	if err := tt.push(owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	write(c, 1)
	tt.drop("m_admin")
	if err := tt.push(owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	write(c, 2)
	if got := workerNow(t, c, w.ID); len(got.DEKEpochs) != 2 || got.ManifestEpoch != 2 {
		t.Fatalf("epochs %d, manifest %d", len(got.DEKEpochs), got.ManifestEpoch)
	}
	err = c.view(w.ID, anyDevice, func(tr *Tree) error {
		for i, p := range files {
			if e := tr.manifest.Entries[prefixRoot+p]; e.Epoch != uint32(i) {
				t.Errorf("%s: epoch %d, want %d", p, e.Epoch, i)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	check := func(name string, c *Coordinator) {
		for _, p := range files {
			if got, err := c.ReadFile(w.ID, prefixRoot+p); err != nil || string(got) != p {
				t.Errorf("%s: %s: %q %v", name, p, got, err)
			}
		}
	}
	check("before", c)
	c2, err := New(c.cfg)
	if err != nil {
		t.Fatal(err)
	}
	check("after a restart", c2)
	if _, err := c.Backup(t.Context()); err != nil {
		t.Fatal(err)
	}
	restored, _, err := v.restore("")
	if err != nil {
		t.Fatal(err)
	}
	check("restored", restored)
}

// After the reseal, a manifest under an older epoch is refused: a removed
// device with write access to the bucket can't hand the coordinator a tree
// of its own. Until the reseal is recorded, the epoch before is still read,
// so a crash between them loses nothing.
func TestOnlyTheRecordedEpochsOpenTheManifest(t *testing.T) {
	f := newTeamFixture(t)
	if err := f.c.PutFile(f.w1.ID, "x.md", []byte("x")); err != nil {
		t.Fatal(err)
	}
	f.tt.drop("m_reviewer")
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	w := workerNow(t, f.c, f.w1.ID)
	forged, err := json.Marshal(manifest{Version: w.Version + 10, Entries: map[string]entry{}})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := seal(f.dek1[:], forged, aad(purposeManifest, w.ID, ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.c.cfg.Store.Put(w.ID, manifestObject, sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.ReadFile(w.ID, prefixRoot+"x.md"); !errors.Is(err, errOpen) {
		t.Errorf("a manifest under the removed epoch: %v", err)
	}

	// The window: the volume says the manifest is still under epoch 0.
	f.c.mu.Lock()
	f.c.state.Workers[w.ID].ManifestEpoch = 0
	f.c.mu.Unlock()
	if _, err := f.c.ReadFile(w.ID, prefixRoot+"x.md"); err == nil {
		t.Error("the forged manifest named x.md")
	} else if errors.Is(err, errOpen) {
		t.Errorf("in the window, epoch 0 isn't read: %v", err)
	}
}

func TestADEKEpochIsBoundToItsWorkerAndNumber(t *testing.T) {
	key, _ := NewWrappingKey()
	dek := mustDEK(t)
	wrapped, err := key.WrapEpoch("w_a", 2, dek)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := key.UnwrapEpoch("w_a", 2, wrapped); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id string
		n  uint32
	}{{"w_b", 2}, {"w_a", 1}, {"w_a", 0}} {
		if _, err := key.UnwrapEpoch(tc.id, tc.n, wrapped); err == nil {
			t.Errorf("opened as %s epoch %d", tc.id, tc.n)
		}
	}
	// Epochs must be numbered in order on the volume.
	w := &Worker{ID: "w_a", DEKEpochs: []DEKEpoch{{Epoch: 2, Wrapped: wrapped}}}
	if w.WrappedDEK, err = key.Wrap("w_a", dek); err != nil {
		t.Fatal(err)
	}
	if _, err := key.Keyring(w); err == nil {
		t.Error("a keyring with a gap")
	}
}

// A mail setup opens under any epoch: Desktop seals it under the DEK its list
// signed, and may under a later one. One that opens but doesn't check says so.
func TestAMailSetupOpensUnderAnyEpoch(t *testing.T) {
	ring := &Keyring{keys: []DEK{mustDEK(t), mustDEK(t), mustDEK(t)}}
	for n := range ring.keys {
		sealed, err := SealMailSetup(ring.keys[n], "w_a", vectorSetup())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := openMailSetupAnyEpoch(ring, "w_a", sealed); err != nil {
			t.Errorf("epoch %d: %v", n, err)
		}
	}
	bad := vectorSetup()
	bad.Mailbox.Address = "not an address"
	sealed, _ := SealMailSetup(ring.keys[2], "w_a", bad)
	if _, err := openMailSetupAnyEpoch(ring, "w_a", sealed); err == nil || bytes.Contains([]byte(err.Error()), []byte("doesn't open")) {
		t.Errorf("an invalid setup under the last epoch: %v", err)
	}
	other, _ := SealMailSetup(mustDEK(t), "w_a", vectorSetup())
	if _, err := openMailSetupAnyEpoch(ring, "w_a", other); !errors.Is(err, ErrInvalid) {
		t.Errorf("another key: %v", err)
	}
}
