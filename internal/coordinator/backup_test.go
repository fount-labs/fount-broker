package coordinator

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// vaultRig is the Cloud vault's counter and generations and a backup
// bucket, in memory, and the wrapping key the vault releases.
type vaultRig struct {
	t      *testing.T
	vault  *MemVault
	bucket *MemBucket
	key    WrappingKey
}

func newVaultRig(t *testing.T, authority ed25519.PrivateKey) *vaultRig {
	t.Helper()
	if authority == nil {
		_, authority, _ = ed25519.GenerateKey(nil)
	}
	key, err := NewWrappingKey()
	if err != nil {
		t.Fatal(err)
	}
	return &vaultRig{t: t, vault: &MemVault{Authority: authority}, bucket: NewMemBucket(), key: key}
}

func (v *vaultRig) next() *FixedGeneration {
	v.t.Helper()
	g, err := v.vault.Boot()
	if err != nil {
		v.t.Fatal(err)
	}
	return g
}

func (v *vaultRig) backups(g *FixedGeneration) *BackupConfig {
	return &BackupConfig{Bucket: v.bucket, Counter: v.vault, Generations: g}
}

func (v *vaultRig) count() VaultCount {
	c, _ := v.vault.Load(context.Background())
	return c
}

// open starts a coordinator with backups on dir under g.
func (v *vaultRig) open(dir string, g *FixedGeneration) (*Coordinator, error) {
	v.t.Helper()
	self, err := os.Executable()
	if err != nil {
		v.t.Fatal(err)
	}
	c, err := New(Config{
		StateDir: filepath.Join(dir, "state"), WorkDir: filepath.Join(dir, "work"),
		Store: DirStore{Root: filepath.Join(dir, "objects")}, Key: v.key, Pool: NewPool(1, 2, nil),
		Runner: envRunner{LocalRunner{Command: []string{self}}, "ok"}, Audience: testAudience,
		Backup: v.backups(g),
	})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	go c.Run(ctx)
	v.t.Cleanup(func() {
		cancel()
		c.running.Wait()
	})
	return c, nil
}

// boot starts a coordinator on dir under a new generation.
func (v *vaultRig) boot(dir string) *Coordinator {
	v.t.Helper()
	c, err := v.open(dir, v.next())
	if err != nil {
		v.t.Fatal(err)
	}
	return c
}

func (v *vaultRig) roots() []rootRef {
	v.t.Helper()
	roots, err := listRoots(context.Background(), v.bucket)
	if err != nil {
		v.t.Fatal(err)
	}
	return roots
}

func (v *vaultRig) newest() string {
	v.t.Helper()
	roots := v.roots()
	if len(roots) == 0 {
		v.t.Fatal("no backups")
	}
	return roots[len(roots)-1].key
}

// restore restores root (the newest when empty) onto a new volume under a
// new generation, and starts a coordinator on it.
func (v *vaultRig) restore(root string) (*Coordinator, RestoreResult, error) {
	v.t.Helper()
	dir := v.t.TempDir()
	g := v.next()
	res, err := Restore(context.Background(), RestoreOptions{Bucket: v.bucket, Counter: v.vault, Generations: g, Key: v.key,
		StateDir: filepath.Join(dir, "state"), Store: DirStore{Root: filepath.Join(dir, "objects")}, Root: root})
	if err != nil {
		return nil, res, err
	}
	c, err := v.open(dir, g)
	return c, res, err
}

func logSeq(c *Coordinator, team string) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.teamLogView(team, ^uint64(0)).Seq
}

func TestASecurityChangeIsBackedUpAndCountedBeforeItIsAcknowledged(t *testing.T) {
	v := newVaultRig(t, nil)
	c := v.boot(t.TempDir())
	if n := len(v.roots()); n != 1 {
		t.Fatalf("%d backups at boot, want 1", n)
	}
	me := newTestDevice(t)
	soloTeam(t, c, "acme", me)
	if got := v.count(); got.Count != 1 || got.Generation != 1 {
		t.Fatalf("the vault has %+v", got)
	}
	roots := v.roots()
	root, err := openRoot(context.Background(), v.bucket, backupKey(&v.key), roots[len(roots)-1])
	if err != nil {
		t.Fatal(err)
	}
	if root.securitySeq != 1 || !strings.Contains(string(root.body.State), `"acme"`) {
		t.Fatalf("the newest backup has security change %d", root.securitySeq)
	}
	// Unchanged, the loop writes nothing.
	if key, err := c.Backup(context.Background()); err != nil || key != "" {
		t.Fatalf("an unchanged volume was backed up: %q %v", key, err)
	}
}

func TestARestoreBelowTheCounterIsRefused(t *testing.T) {
	v := newVaultRig(t, nil)
	c := v.boot(t.TempDir())
	me, rev := newTestDevice(t), newTestDevice(t)
	tt := soloTeam(t, c, "acme", me)
	older := v.newest()
	tt.set("m_rev", "maria", RoleReviewer, rev)
	if err := tt.push(me, "acme", nil); err != nil {
		t.Fatal(err)
	}
	if v.count().Count != 2 {
		t.Fatalf("the vault has %+v", v.count())
	}
	if _, _, err := v.restore(older); !errors.Is(err, ErrBackupRolledBack) {
		t.Fatalf("restoring the backup before a removal: %v", err)
	}
	restored, res, err := v.restore("")
	if err != nil {
		t.Fatal(err)
	}
	if res.SecuritySeq != 2 || logSeq(restored, "acme") != 2 {
		t.Fatalf("restored %+v, log at %d", res, logSeq(restored, "acme"))
	}
	if !restored.state.Restored.TakenAt.Equal(res.TakenAt.UTC()) {
		t.Fatalf("restore mark %+v", restored.state.Restored)
	}
	// Onto a volume that has state, a restore is refused.
	g := v.next()
	_, err = Restore(context.Background(), RestoreOptions{Bucket: v.bucket, Counter: v.vault, Generations: g, Key: v.key,
		StateDir: restored.cfg.StateDir, Store: restored.cfg.Store})
	if !errors.Is(err, ErrRestoreOverVolume) {
		t.Fatalf("a restore over a volume: %v", err)
	}
	// Under another wrapping key, a backup doesn't open.
	other, _ := NewWrappingKey()
	dir := t.TempDir()
	_, err = Restore(context.Background(), RestoreOptions{Bucket: v.bucket, Counter: v.vault, Generations: v.next(), Key: other,
		StateDir: filepath.Join(dir, "state"), Store: DirStore{Root: filepath.Join(dir, "objects")}})
	if err == nil {
		t.Fatal("a backup opened under another key")
	}
}

func TestAnOldGenerationCoordinatorIsRefused(t *testing.T) {
	v := newVaultRig(t, nil)
	dir := t.TempDir()
	g1 := v.next()
	old, err := v.open(dir, g1)
	if err != nil {
		t.Fatal(err)
	}
	me, rev := newTestDevice(t), newTestDevice(t)
	tt := soloTeam(t, old, "acme", me)
	srv := httptest.NewServer(old.AccountHandler(me.caller("acme")))
	defer srv.Close()
	if code, _ := do(t, srv, "GET", "/v1/teams/acme/log", ""); code != http.StatusOK {
		t.Fatalf("before: %d", code)
	}
	roots := len(v.roots())

	// A newer coordinator takes over: the vault moves its generation.
	v.next()
	tt.set("m_rev", "maria", RoleReviewer, rev)
	if err := tt.push(me, "acme", nil); !errors.Is(err, ErrStaleCoordinator) {
		t.Fatalf("an old generation's append: %v", err)
	}
	if !old.Retired() {
		t.Fatal("the old coordinator wasn't retired")
	}
	if logSeq(old, "acme") != 1 || v.count().Count != 1 || len(v.roots()) != roots {
		t.Fatalf("the old coordinator changed something: log %d, vault %+v, %d backups", logSeq(old, "acme"), v.count(), len(v.roots()))
	}
	if code, _ := do(t, srv, "GET", "/v1/teams/acme/log", ""); code != http.StatusServiceUnavailable {
		t.Fatalf("a retired coordinator served: %d", code)
	}
	if _, err := old.Backup(context.Background()); !errors.Is(err, ErrStaleCoordinator) {
		t.Fatalf("a retired coordinator backed up: %v", err)
	}
	// It doesn't start again on an old generation either.
	old2Dir := t.TempDir()
	if _, err := v.open(old2Dir, g1); !errors.Is(err, ErrStaleCoordinator) {
		t.Fatalf("a boot under an old generation: %v", err)
	}
	// The backup loop notices too, with nothing to append.
	c, _, err := v.restore("")
	if err != nil {
		t.Fatal(err)
	}
	v.next()
	if c.backupPass(context.Background(), time.Now()) || !c.Retired() {
		t.Fatal("the backup loop kept going under an old generation")
	}
}

func TestACrashBetweenTheStateWriteAndTheCounter(t *testing.T) {
	v := newVaultRig(t, nil)
	dir := t.TempDir()
	c := v.boot(dir)
	me, rev := newTestDevice(t), newTestDevice(t)
	tt := soloTeam(t, c, "acme", me)
	before := v.newest()
	failed := false
	v.vault.FailSwap = func(_, _, _ uint64) error {
		if failed {
			return nil
		}
		failed = true
		return errors.New("the vault is unreachable")
	}
	tt.set("m_rev", "maria", RoleReviewer, rev)
	if err := tt.push(me, "acme", nil); !errors.Is(err, ErrNotDurable) {
		t.Fatalf("an append the vault didn't count: %v", err)
	}
	if logSeq(c, "acme") != 1 || v.count().Count != 1 {
		t.Fatalf("an unacknowledged append took: log %d, vault %+v", logSeq(c, "acme"), v.count())
	}
	// The volume and the bucket have it: the crash is here.
	st, err := LoadState(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	if st.SecuritySeq != 2 || len(st.Teams["acme"].Log) != 2 {
		t.Fatalf("the volume has security change %d, %d entries", st.SecuritySeq, len(st.Teams["acme"].Log))
	}
	if v.newest() == before {
		t.Fatal("the change wasn't backed up before the vault was asked")
	}

	// The next boot counts what was saved.
	after := v.boot(dir)
	if logSeq(after, "acme") != 2 || v.count().Count != 2 {
		t.Fatalf("after the crash: log %d, vault %+v", logSeq(after, "acme"), v.count())
	}
	if _, _, err := v.restore(before); !errors.Is(err, ErrBackupRolledBack) {
		t.Fatalf("restoring from before the counted change: %v", err)
	}
	if _, _, err := v.restore(""); err != nil {
		t.Fatalf("restoring the newest: %v", err)
	}
}

func TestAFailedCountDoesntStopTheNextChange(t *testing.T) {
	v := newVaultRig(t, nil)
	c := v.boot(t.TempDir())
	me, rev := newTestDevice(t), newTestDevice(t)
	tt := soloTeam(t, c, "acme", me)
	v.vault.FailSwap = func(_, _, _ uint64) error { return errors.New("the vault is unreachable") }
	tt.set("m_rev", "maria", RoleReviewer, rev)
	if err := tt.push(me, "acme", nil); !errors.Is(err, ErrNotDurable) {
		t.Fatal(err)
	}
	v.vault.FailSwap = nil
	if err := tt.push(me, "acme", nil); err != nil {
		t.Fatal(err)
	}
	if v.count().Count != 3 || logSeq(c, "acme") != 2 {
		t.Fatalf("vault %+v, log %d", v.count(), logSeq(c, "acme"))
	}
}

func TestRetentionKeepsTheLastDayAndOneADay(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	var roots []rootRef
	for i, age := range []time.Duration{50 * 24 * time.Hour, 20*24*time.Hour + time.Hour, 20 * 24 * time.Hour, 3 * time.Hour, time.Hour} {
		taken := now.Add(-age)
		roots = append(roots, rootRef{key: rootKey(1, uint64(i+1), taken), gen: 1, seq: uint64(i + 1), taken: taken})
	}
	keep := keptRoots(roots, 30*24*time.Hour, now)
	want := []bool{false, true, false, true, true}
	for i, r := range roots {
		if keep[r.key] != want[i] {
			t.Errorf("root %d (%s old): kept %v", i, now.Sub(r.taken), keep[r.key])
		}
	}

	v := newVaultRig(t, nil)
	c := v.boot(t.TempDir())
	me := newTestDevice(t)
	soloTeam(t, c, "acme", me)
	w, err := c.CreateWorker("acct_1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Backup(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	v.bucket.Put(ctx, backupObjectPrefix+w.ID+"/obj_orphan", []byte("x"))
	if err := c.pruneBackups(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := v.bucket.Get(ctx, backupObjectPrefix+w.ID+"/obj_orphan"); !errors.Is(err, ErrNotFound) {
		t.Fatal("an object no backup names was kept")
	}
	kept := len(v.roots())
	if kept < 3 {
		t.Fatalf("%d backups from the last day kept", kept)
	}
	if err := c.pruneBackups(ctx, time.Now().Add(40*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := len(v.roots()); n != 1 {
		t.Fatalf("%d backups past the retention, want the newest alone", n)
	}
	if _, _, err := v.restore(""); err != nil {
		t.Fatalf("the kept backup doesn't restore: %v", err)
	}
	if _, err := New(Config{StateDir: t.TempDir(), WorkDir: t.TempDir(), Store: DirStore{Root: t.TempDir()}, Key: v.key, Pool: NewPool(1, 1, nil),
		Runner: envRunner{}, Backup: &BackupConfig{Bucket: v.bucket, Counter: v.vault, Generations: v.next(), Retention: SentRecordWindow}}); err == nil {
		t.Fatal("a retention past the edge's sent records was taken")
	}
}

func TestMailIsDeletedFromTheEdgeOnceEveryRestorableBackupHasActedOnIt(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	v := newVaultRig(t, r.edge.authority)
	v.key = r.key
	r.backup = v.backups(v.next())
	r.backup.DeleteMail = true
	r.start()
	w, mb := r.worker()
	id := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Q3"})
	r.pass()
	waitJob(t, r.c, mailJobID(id))
	if r.ledger(w.ID).Acted[id].Outcome != outcomeJob {
		t.Fatal("the mail wasn't acted on")
	}
	ctx := context.Background()
	if _, err := r.c.Backup(ctx); err != nil {
		t.Fatal(err)
	}
	// The backup from boot is still restorable and hasn't the mail.
	if err := r.c.deleteBackedUpMail(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !r.edgeHas(mb, id) {
		t.Fatal("mail was deleted while a restorable backup lacks it")
	}
	// A security change puts the backup from boot below the counter.
	soloTeam(t, r.c, "acme", newTestDevice(t))
	if err := r.c.deleteBackedUpMail(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if r.edgeHas(mb, id) {
		t.Fatal("mail every restorable backup has acted on wasn't deleted")
	}
}

func (r *mailRig) edgeHas(mb Mailbox, id string) bool {
	r.edge.mu.Lock()
	defer r.edge.mu.Unlock()
	_, ok := r.edge.objects[mb.MailboxID][id]
	return ok
}
