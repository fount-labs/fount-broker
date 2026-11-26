package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// countedRig is a mail rig with backups on, whose volume a test can copy
// and put back, as a host replaying the disk would.
type countedRig struct {
	*mailRig
	v *vaultRig
}

func newCountedRig(t *testing.T) *countedRig {
	t.Helper()
	r := newMailRig(t, MailConfig{})
	v := newVaultRig(t, r.edge.authority)
	v.key = r.key
	r.backup = v.backups(v.next())
	r.start()
	return &countedRig{mailRig: r, v: v}
}

// snapshot copies the volume and the store.
func (r *countedRig) snapshot() string {
	r.t.Helper()
	dst := r.t.TempDir()
	for _, sub := range []string{"state", "objects"} {
		if err := os.CopyFS(filepath.Join(dst, sub), os.DirFS(filepath.Join(r.dir, sub))); err != nil {
			r.t.Fatal(err)
		}
	}
	return dst
}

// replay stops the coordinator, puts snap back as the volume and boots it
// under a new generation.
func (r *countedRig) replay(snap string) error {
	r.t.Helper()
	r.cancel()
	r.c.running.Wait()
	r.cancel = nil
	for _, sub := range []string{"state", "objects"} {
		if err := os.RemoveAll(filepath.Join(r.dir, sub)); err != nil {
			r.t.Fatal(err)
		}
		if err := os.CopyFS(filepath.Join(r.dir, sub), os.DirFS(filepath.Join(snap, sub))); err != nil {
			r.t.Fatal(err)
		}
	}
	r.backup = r.v.backups(r.v.next())
	return r.startErr()
}

// A change that takes something away is counted by the vault before it is
// acknowledged, so a disk replayed to before it is refused; one that gives
// something isn't counted (broker review M1).
func TestAChangeThatTakesAwayIsCountedBeforeItIsAcknowledged(t *testing.T) {
	r := newCountedRig(t)
	w, _ := r.worker()
	before := r.v.count().Count
	snap := r.snapshot()

	if res := r.workerOp(w.ID, "op_pause", "setPaused", switchArgs{On: true}); !res.OK {
		t.Fatalf("setPaused: %+v", res)
	}
	paused := r.v.count()
	if paused.Count != before+1 {
		t.Fatalf("pausing mail left the vault at %d, from %d", paused.Count, before)
	}
	r.c.mu.Lock()
	version, counted := r.c.state.Workers[w.ID].Version, r.c.state.Counted[w.ID]
	digest := securityDigest(r.c.state)
	r.c.mu.Unlock()
	if counted != version || digest != paused.Digest {
		t.Fatalf("the count binds version %d, the tree is at %d", counted, version)
	}
	// Giving back isn't counted.
	if res := r.workerOp(w.ID, "op_unpause", "setPaused", switchArgs{On: false, BaseRevision: 1}); !res.OK {
		t.Fatalf("setPaused off: %+v", res)
	}
	if got := r.v.count().Count; got != paused.Count {
		t.Fatalf("unpausing moved the vault to %d", got)
	}
	if res := r.workerOp(w.ID, "op_auto_off", "setAutoRun", switchArgs{On: false, BaseRevision: 1}); !res.OK {
		t.Fatalf("setAutoRun off: %+v", res)
	}
	if got := r.v.count().Count; got != paused.Count+1 {
		t.Fatalf("turning automatic runs off left the vault at %d", got)
	}

	if err := r.replay(snap); !errors.Is(err, ErrVolumeRolledBack) {
		t.Fatalf("a disk replayed to before the pause: %v", err)
	}
}

// Lowering a thread's reply mode and discarding a draft are counted.
func TestLoweringAThreadAndDiscardingADraftAreCounted(t *testing.T) {
	r := newCountedRig(t)
	s := sendRigOn(t, r.mailRig, modeFull)
	th, e := s.drafted()
	before := r.v.count().Count
	if res := r.threadOp(s.w.ID, th.ID, "op_discard", "discardDraft", map[string]string{"draftId": e.ID}); !res.OK {
		t.Fatalf("discardDraft: %+v", res)
	}
	if got := r.v.count().Count; got != before+1 {
		t.Fatalf("discarding left the vault at %d, from %d", got, before)
	}
	if res := r.threadOp(s.w.ID, th.ID, "op_lower", "setThreadReplyMode", map[string]string{"mode": modeOff}); !res.OK {
		t.Fatalf("setThreadReplyMode: %+v", res)
	}
	if got := r.v.count().Count; got != before+2 {
		t.Fatalf("lowering the thread left the vault at %d, from %d", got, before)
	}
	if res := r.workerOp(s.w.ID, "op_default", "setDefaultMode", defaultModeArgs{Mode: modeNotify, Owner: "dana@example.com", BaseRevision: 1}); !res.OK {
		t.Fatalf("setDefaultMode: %+v", res)
	}
	if got := r.v.count().Count; got != before+3 {
		t.Fatalf("lowering the default mode left the vault at %d, from %d", got, before)
	}
}

// The mail ledger's progress is counted, at most once every
// ledgerCountEvery, by the mail loop.
func TestTheMailLedgersProgressIsCounted(t *testing.T) {
	r := newCountedRig(t)
	w, mb := r.worker()
	before := r.v.count().Count
	id := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Q3"})
	r.pass()
	waitJob(t, r.c, mailJobID(id))
	waitCounted(t, r.c)
	first := r.v.count().Count
	if first != before+1 {
		t.Fatalf("the ledger's progress left the vault at %d, from %d", first, before)
	}
	r.c.mu.Lock()
	counted := r.c.state.Counted[w.ID]
	r.c.mu.Unlock()
	if counted == 0 {
		t.Fatal("the count doesn't bind the worker's tree")
	}
	id2 := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Q4"})
	r.pass()
	waitJob(t, r.c, mailJobID(id2))
	if got := r.v.count().Count; got != first {
		t.Fatalf("a second message within %s moved the vault to %d", ledgerCountEvery, got)
	}
	r.c.countLedger(time.Now().Add(ledgerCountEvery))
	waitCounted(t, r.c)
	if got := r.v.count().Count; got != first+1 {
		t.Fatalf("after %s the vault is at %d", ledgerCountEvery, got)
	}
}

// waitCounted waits for the mail ledger's count in flight, if any.
func waitCounted(t *testing.T, c *Coordinator) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		c.mu.Lock()
		counting := c.counting
		c.mu.Unlock()
		if !counting {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the ledger's count is still in flight")
		}
	}
}

// A volume behind the newest backup of it, at the vault's count, was
// replayed: it boots as a restore, with its earlier mail held.
func TestAVolumeBehindTheNewestBackupRunsAsARestore(t *testing.T) {
	r := newCountedRig(t)
	w, mb := r.worker()
	snap := r.snapshot()
	if err := r.c.PutFile(w.ID, "files/after.md", []byte("a plain change")); err != nil {
		t.Fatal(err)
	}
	newest, err := r.c.Backup(t.Context())
	if err != nil || newest == "" {
		t.Fatalf("backup: %q %v", newest, err)
	}
	// A plain restart isn't a replay.
	r.backup = r.v.backups(r.v.next())
	r.start()
	r.c.mu.Lock()
	mark := r.c.state.Restored
	r.c.mu.Unlock()
	if mark != nil {
		t.Fatalf("a restart marked the volume restored: %+v", mark)
	}

	id := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Q3"})
	if err := r.replay(snap); err != nil {
		t.Fatalf("booting the replayed volume: %v", err)
	}
	r.c.mu.Lock()
	mark = r.c.state.Restored
	r.c.mu.Unlock()
	if mark == nil || !strings.HasPrefix(mark.Root, backupRootPrefix) {
		t.Fatalf("the replayed volume isn't marked restored: %+v", mark)
	}
	r.pass()
	if got := r.ledger(w.ID).Acted[id]; got.Outcome != outcomeHeld {
		t.Fatalf("mail from before the replay was %+v, not held", got)
	}
}

func TestTheDigestCoversCountedTreesOnlyWhenThereAreAny(t *testing.T) {
	st := &State{Workers: map[string]*Worker{}, Teams: map[string]*Team{"acme": {}}, TeamMints: map[string]string{}}
	base := securityDigest(st)
	st.Saves, st.TeamMints["t_x"] = 7, "acct"
	if securityDigest(st) != base {
		t.Fatal("a plain save's fields moved the digest")
	}
	st.Counted = map[string]uint64{}
	if securityDigest(st) != base {
		t.Fatal("an empty Counted moved the digest of a state counted before it")
	}
	st.Counted["w_a"] = 3
	withA := securityDigest(st)
	st.Counted["w_a"] = 4
	if withA == base || securityDigest(st) == withA {
		t.Fatal("the digest doesn't bind the counted tree versions")
	}
}

// hangingVault is a vault whose counter calls hang, while hang is set, until
// their context ends or released is closed.
type hangingVault struct {
	StateCounter
	hang     atomic.Bool
	calls    atomic.Int32
	released chan struct{}
}

func (v *hangingVault) wait(ctx context.Context) error {
	if !v.hang.Load() {
		return nil
	}
	v.calls.Add(1)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-v.released:
		return errors.New("the vault hung up")
	}
}

func (v *hangingVault) Load(ctx context.Context) (VaultCount, error) {
	if err := v.wait(ctx); err != nil {
		return VaultCount{}, err
	}
	return v.StateCounter.Load(ctx)
}

func (v *hangingVault) CompareAndSwapState(ctx context.Context, generation, prev, next uint64, digest string) error {
	if err := v.wait(ctx); err != nil {
		return err
	}
	return v.StateCounter.CompareAndSwapState(ctx, generation, prev, next, digest)
}

// A vault that hangs while the mail ledger's progress is counted holds up
// no team's reads, mail intake, job dispatch or change that takes nothing
// away; the count fails, backs off, and shows on the status (2026-11-25
// re-check, R3-2).
func TestAHangingVaultStallsNothingButTheCount(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	v := newVaultRig(t, r.edge.authority)
	v.key = r.key
	hv := &hangingVault{StateCounter: v.vault, released: make(chan struct{})}
	r.backup = v.backups(v.next())
	r.backup.Counter = hv
	r.start()
	w, mb := r.worker()
	soloTeam(t, r.c, "acme", newTestDevice(t))

	hv.hang.Store(true)
	defer close(hv.released)
	id := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Q3"})
	r.pass()
	countLedgerNow(r.c)
	for deadline := time.Now().Add(5 * time.Second); hv.calls.Load() == 0; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no count reached the vault")
		}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = r.c.Load()
		_ = logSeq(r.c, "acme")
		if res := r.workerOp(w.ID, "op_unpause", "setPaused", switchArgs{On: false}); !res.OK {
			t.Errorf("setPaused off: %+v", res)
		}
		waitJob(t, r.c, mailJobID(id))
		id2 := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Q4"})
		r.pass()
		waitJob(t, r.c, mailJobID(id2))
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a hanging vault held up the coordinator")
	}

	r.c.mu.Lock()
	counting := r.c.counting
	r.c.mu.Unlock()
	if !counting {
		t.Fatal("the count isn't in flight")
	}
	hv.released <- struct{}{}
	waitCounted(t, r.c)
	b := r.c.BackupStatus()
	if b.CountingFailingSince == nil || b.CountRetryAt == nil || !b.CountRetryAt.After(time.Now().Add(countBackoffMin/2-time.Second)) {
		t.Fatalf("a failed count shows as %+v", b)
	}
	calls := hv.calls.Load()
	countLedgerNow(r.c)
	waitCounted(t, r.c)
	if hv.calls.Load() != calls {
		t.Fatal("a count was tried again at once after a failure")
	}
	if !r.c.CountingFailing(time.Now()).IsZero() || r.c.CountingFailing(time.Now().Add(CountUnhealthyAfter)).IsZero() {
		t.Fatalf("unhealthy before %s, or not after", CountUnhealthyAfter)
	}

	hv.hang.Store(false)
	if err := r.c.countOff(t.Context()); err != nil {
		t.Fatal(err)
	}
	if b := r.c.BackupStatus(); b.CountingFailingSince != nil || b.CountError != "" {
		t.Fatalf("a count that worked leaves %+v", b)
	}
}

// countLedgerNow is the mail loop's countLedger once ledgerCountEvery has
// passed since the last count.
func countLedgerNow(c *Coordinator) {
	c.mu.Lock()
	c.lastOwedCount = time.Time{}
	c.mu.Unlock()
	c.countLedger(time.Now())
}

// swapGate holds the first swaps, each until its let is closed.
type swapGate struct {
	StateCounter
	on   atomic.Bool
	n    atomic.Int32
	in   [2]chan struct{}
	let  [2]chan struct{}
	done [2]chan struct{}
}

func newSwapGate(c StateCounter) *swapGate {
	g := &swapGate{StateCounter: c}
	for i := range 2 {
		g.in[i], g.let[i], g.done[i] = make(chan struct{}), make(chan struct{}), make(chan struct{})
	}
	return g
}

func (g *swapGate) CompareAndSwapState(ctx context.Context, generation, prev, next uint64, digest string) error {
	if !g.on.Load() {
		return g.StateCounter.CompareAndSwapState(ctx, generation, prev, next, digest)
	}
	i := int(g.n.Add(1)) - 1
	if i >= 2 {
		return g.StateCounter.CompareAndSwapState(ctx, generation, prev, next, digest)
	}
	close(g.in[i])
	<-g.let[i]
	defer close(g.done[i])
	return g.StateCounter.CompareAndSwapState(ctx, generation, prev, next, digest)
}

// A team's change counted while the ledger's count is in flight, both from
// the same confirmed count, reconciles in either order: the one that lands
// second finds the count moved by its own generation, and is done when the
// count is past it or tried again from it when below. Neither retires the
// coordinator (swapCount).
func TestCountsInFlightTogetherReconcile(t *testing.T) {
	for _, ledgerFirst := range []bool{false, true} {
		r := newMailRig(t, MailConfig{})
		v := newVaultRig(t, r.edge.authority)
		v.key = r.key
		g := newSwapGate(v.vault)
		r.backup = v.backups(v.next())
		r.backup.Counter = g
		r.start()
		_, mb := r.worker()
		id := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Q3"})
		r.c.mu.Lock()
		r.c.lastOwedCount = time.Now().Add(time.Hour)
		r.c.mu.Unlock()
		r.pass()
		waitJob(t, r.c, mailJobID(id))

		g.on.Store(true)
		countLedgerNow(r.c)
		<-g.in[0]
		teamDone := make(chan struct{})
		go func() {
			defer close(teamDone)
			soloTeam(t, r.c, "acme", newTestDevice(t))
		}()
		<-g.in[1]
		if ledgerFirst {
			close(g.let[0])
			<-g.done[0]
			close(g.let[1])
		} else {
			close(g.let[1])
			<-g.done[1]
			close(g.let[0])
		}
		<-teamDone
		waitCounted(t, r.c)
		if r.c.Retired() {
			t.Fatalf("ledger first %v: retired", ledgerFirst)
		}
		r.c.mu.Lock()
		seq, due := r.c.state.SecuritySeq, r.c.countDue()
		r.c.mu.Unlock()
		if got := v.count().Count; got != seq || due || r.c.durable.counted.Load() != seq {
			t.Fatalf("ledger first %v: the vault at %d, the volume at %d, still due %v", ledgerFirst, got, seq, due)
		}
	}
}

// A take-away change whose count failed is counted before its retry is
// acknowledged, though the tree has it already (2026-11-25 re-check, R3-4).
func TestARetriedTakeAwayIsCountedBeforeItIsAcknowledged(t *testing.T) {
	r := newCountedRig(t)
	w, _ := r.worker()
	failing := errors.New("the vault is restarting")
	r.v.vault.FailSwap = func(uint64, uint64, uint64) error { return failing }
	pause := func(op string) error {
		raw, _ := json.Marshal(switchArgs{On: true})
		_, err := r.c.applyWorkerOp(anyDevice, w.ID, workerOpEnvelope{OpID: op, Kind: "setPaused", Args: raw})
		return err
	}
	if err := pause("op_pause"); !errors.Is(err, ErrNotDurable) {
		t.Fatalf("pausing with the vault down: %v", err)
	}
	before := r.v.count().Count
	if err := pause("op_pause_again"); !errors.Is(err, ErrNotDurable) {
		t.Fatalf("the retry was acknowledged uncounted: %v", err)
	}
	r.v.vault.FailSwap = nil
	if err := pause("op_pause_third"); err != nil {
		t.Fatal(err)
	}
	if got := r.v.count().Count; got <= before {
		t.Fatalf("the retry left the vault at %d", got)
	}
	r.c.mu.Lock()
	owed := r.c.awayOwed(w.ID)
	r.c.mu.Unlock()
	if owed {
		t.Fatal("the counted take-away is still owed")
	}
}

// rootBlocker is a bucket whose root fetches fail while block is set, as a
// host that drops them would make them.
type rootBlocker struct {
	BackupBucket
	block atomic.Bool
}

func (b *rootBlocker) Get(ctx context.Context, key string) ([]byte, error) {
	if b.block.Load() && strings.HasPrefix(key, backupRootPrefix) {
		return nil, errors.New("connection reset")
	}
	return b.BackupBucket.Get(ctx, key)
}

// A replayed volume whose newest backup can't be fetched doesn't boot as
// current: the boot fails with ErrBackupUnreachable, to be tried again, and
// once the root comes it runs as a restore. A newer root that was fetched
// and doesn't open is passed over (2026-11-25 re-check, R3-3).
func TestAReplayedVolumeDoesntBootWhileItsBackupsCantBeFetched(t *testing.T) {
	r := newCountedRig(t)
	w, _ := r.worker()
	snap := r.snapshot()
	if err := r.c.PutFile(w.ID, "files/after.md", []byte("a plain change")); err != nil {
		t.Fatal(err)
	}
	if newest, err := r.c.Backup(t.Context()); err != nil || newest == "" {
		t.Fatalf("backup: %q %v", newest, err)
	}
	// Junk under a higher root name, as a bucket writer could plant.
	junk := rootKey(1<<40, 1, time.Now())
	if err := r.v.bucket.Put(t.Context(), junk, []byte(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}

	r.cancel()
	r.c.running.Wait()
	r.cancel = nil
	for _, sub := range []string{"state", "objects"} {
		if err := os.RemoveAll(filepath.Join(r.dir, sub)); err != nil {
			t.Fatal(err)
		}
		if err := os.CopyFS(filepath.Join(r.dir, sub), os.DirFS(filepath.Join(snap, sub))); err != nil {
			t.Fatal(err)
		}
	}
	blocker := &rootBlocker{BackupBucket: r.v.bucket}
	blocker.block.Store(true)
	r.backup = r.v.backups(r.v.next())
	r.backup.Bucket = blocker
	if err := r.startErr(); !errors.Is(err, ErrBackupUnreachable) {
		t.Fatalf("a replayed volume whose roots didn't come booted: %v", err)
	}
	blocker.block.Store(false)
	r.backup = r.v.backups(r.v.next())
	r.backup.Bucket = blocker
	if err := r.startErr(); err != nil {
		t.Fatal(err)
	}
	r.c.mu.Lock()
	mark := r.c.state.Restored
	r.c.mu.Unlock()
	if mark == nil || mark.Root == junk {
		t.Fatalf("the replayed volume is marked %+v", mark)
	}
}

// lostAnswer is a vault whose next swap lands and then answers as if the
// connection dropped.
type lostAnswer struct {
	StateCounter
	lose atomic.Bool
}

func (v *lostAnswer) CompareAndSwapState(ctx context.Context, generation, prev, next uint64, digest string) error {
	err := v.StateCounter.CompareAndSwapState(ctx, generation, prev, next, digest)
	if err == nil && v.lose.CompareAndSwap(true, false) {
		return errors.New("connection reset")
	}
	return err
}

// The round-4 check's P1: a team change whose swap landed but whose answer
// was lost is put back in memory, and a plain save then writes the volume
// at the vault's count without it. The next count must not take the
// vault's count as this volume's: it counts again, so a reboot isn't
// refused as a fork (R4-1).
func TestALostSwapAnswerIsCountedAgain(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	v := newVaultRig(t, r.edge.authority)
	v.key = r.key
	la := &lostAnswer{StateCounter: v.vault}
	r.backup = v.backups(v.next())
	r.backup.Counter = la
	r.start()
	w, _ := r.worker()

	la.lose.Store(true)
	if err := soloTeamErr(t, r.c, "acme", newTestDevice(t)); !errors.Is(err, ErrNotDurable) {
		t.Fatalf("a team change whose answer was lost: %v", err)
	}
	if err := r.c.PutFile(w.ID, "files/after.md", []byte("a plain save")); err != nil {
		t.Fatal(err)
	}
	if err := r.c.countOff(t.Context()); err != nil {
		t.Fatal(err)
	}
	r.c.mu.Lock()
	seq, digest := r.c.state.SecuritySeq, securityDigest(r.c.state)
	r.c.mu.Unlock()
	if got := v.count(); got.Count != seq || got.Digest != digest {
		t.Fatalf("the vault counted %d %.8s, the volume is %d %.8s", got.Count, got.Digest, seq, digest)
	}
	r.backup = v.backups(v.next())
	if err := r.startErr(); err != nil {
		t.Fatalf("a reboot after a lost answer: %v", err)
	}
}

// The round-5 check's probe A: a team change whose answer was lost, then a
// plain save, then a reboot before any count. The rollback took a fresh
// sequence, so the volume is ahead of the vault's count, not at it with
// another state: the boot counts it, as after any crash before a count
// (R5-1).
func TestARebootAfterALostSwapAnswerAndASaveIsNotAFork(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	v := newVaultRig(t, r.edge.authority)
	v.key = r.key
	la := &lostAnswer{StateCounter: v.vault}
	r.backup = v.backups(v.next())
	r.backup.Counter = la
	r.start()
	w, _ := r.worker()

	la.lose.Store(true)
	if err := soloTeamErr(t, r.c, "acme", newTestDevice(t)); !errors.Is(err, ErrNotDurable) {
		t.Fatalf("a team change whose answer was lost: %v", err)
	}
	if err := r.c.PutFile(w.ID, "files/after.md", []byte("a plain save")); err != nil {
		t.Fatal(err)
	}
	r.c.mu.Lock()
	seq, digest := r.c.state.SecuritySeq, securityDigest(r.c.state)
	r.c.mu.Unlock()
	if got := v.count(); got.Count >= seq {
		t.Fatalf("the volume is at %d, not ahead of the vault's count %d", seq, got.Count)
	}
	r.backup = v.backups(v.next())
	if err := r.startErr(); err != nil {
		t.Fatalf("a reboot after a lost answer and a save: %v", err)
	}
	if got := v.count(); got.Count != seq || got.Digest != digest {
		t.Fatalf("the boot counted %d %.8s, the volume is %d %.8s", got.Count, got.Digest, seq, digest)
	}
}

// deadlineBucket records how long each call was given.
type deadlineBucket struct {
	BackupBucket
	given map[string]time.Duration
}

func (b *deadlineBucket) note(ctx context.Context, call string) {
	deadline, ok := ctx.Deadline()
	if !ok {
		b.given[call] = -1
		return
	}
	b.given[call] = time.Until(deadline)
}

func (b *deadlineBucket) Put(ctx context.Context, key string, data []byte) error {
	b.note(ctx, "put "+key)
	return nil
}

func (b *deadlineBucket) Get(ctx context.Context, key string) ([]byte, error) {
	b.note(ctx, "get "+key)
	return nil, ErrNotFound
}

func (b *deadlineBucket) List(ctx context.Context, prefix string) ([]string, error) {
	b.note(ctx, "list "+prefix)
	return nil, nil
}

func (b *deadlineBucket) Delete(ctx context.Context, key string) error {
	b.note(ctx, "delete "+key)
	return nil
}

// A tree object's Put or Get is given time for its size, up to the largest
// a file can be, at bucketFloorRate on top of the minute; a root, a List
// and a Delete get the minute (round-5 check R5-2).
func TestABucketCallsDeadlineScalesWithATreeObjectsSize(t *testing.T) {
	db := &deadlineBucket{given: map[string]time.Duration{}}
	b := boundedBucket{db}
	ctx := t.Context()
	obj := backupObjectPrefix + "w1/o1"
	root := rootKey(1, 1, time.Now())
	_ = b.Put(ctx, obj, make([]byte, 64<<20))
	_ = b.Put(ctx, obj+"small", []byte("x"))
	_ = b.Put(ctx, root, make([]byte, 64<<20))
	_, _ = b.Get(ctx, obj)
	_, _ = b.Get(ctx, root)
	_, _ = b.List(ctx, backupObjectPrefix)
	_ = b.Delete(ctx, obj)
	const slack = 5 * time.Second
	for call, want := range map[string]time.Duration{
		"put " + obj:                 bucketCallTimeout + 16*time.Second,
		"put " + obj + "small":       bucketCallTimeout,
		"put " + root:                bucketCallTimeout,
		"get " + obj:                 bucketCallTimeout + 128*time.Second,
		"get " + root:                bucketCallTimeout,
		"list " + backupObjectPrefix: bucketCallTimeout,
		"delete " + obj:              bucketCallTimeout,
	} {
		got, ok := db.given[call]
		if !ok || got > want || got < want-slack {
			t.Errorf("%s was given %v, want %v", call, got, want)
		}
	}
}

// hungBucket is a bucket whose calls, while hang is set, wait for their
// ctx.
type hungBucket struct {
	BackupBucket
	hang atomic.Bool
}

func (b *hungBucket) wait(ctx context.Context) error {
	if !b.hang.Load() {
		return nil
	}
	<-ctx.Done()
	return ctx.Err()
}

func (b *hungBucket) Put(ctx context.Context, key string, data []byte) error {
	if err := b.wait(ctx); err != nil {
		return err
	}
	return b.BackupBucket.Put(ctx, key, data)
}

func (b *hungBucket) List(ctx context.Context, prefix string) ([]string, error) {
	if err := b.wait(ctx); err != nil {
		return nil, err
	}
	return b.BackupBucket.List(ctx, prefix)
}

// The backup loop's Backup and retention pass run with no deadline of their
// own; a hung bucket call ends by bucketCallTimeout and gives the backups'
// lock back, so a team's change that counts doesn't wait on it (round-4
// check R4-2).
func TestAHungBucketCallGivesTheBackupsLockBack(t *testing.T) {
	was := bucketCallTimeout
	bucketCallTimeout = 200 * time.Millisecond
	t.Cleanup(func() { bucketCallTimeout = was })
	r := newMailRig(t, MailConfig{})
	v := newVaultRig(t, r.edge.authority)
	v.key = r.key
	hung := &hungBucket{BackupBucket: v.bucket}
	r.backup = v.backups(v.next())
	r.backup.Bucket = hung
	r.start()
	w, _ := r.worker()
	if err := r.c.PutFile(w.ID, "files/after.md", []byte("a change")); err != nil {
		t.Fatal(err)
	}

	hung.hang.Store(true)
	done := make(chan error, 2)
	go func() {
		_, err := r.c.Backup(context.Background())
		done <- err
	}()
	go func() { done <- r.c.pruneBackups(context.Background(), time.Now()) }()
	for range 2 {
		select {
		case err := <-done:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("a hung bucket call: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("a hung bucket call held the backups' lock")
		}
	}
	hung.hang.Store(false)
	if err := soloTeamErr(t, r.c, "acme", newTestDevice(t)); err != nil {
		t.Fatalf("a team change after the hang: %v", err)
	}
}

// crowdedVault lands another count of the same generation just before each
// of the next n swaps, as counts in flight beside it would.
type crowdedVault struct {
	StateCounter
	n atomic.Int32
}

func (v *crowdedVault) CompareAndSwapState(ctx context.Context, generation, prev, next uint64, digest string) error {
	if v.n.Add(-1) >= 0 {
		count, err := v.StateCounter.Load(ctx)
		if err != nil {
			return err
		}
		if err := v.StateCounter.CompareAndSwapState(ctx, generation, count.Count, count.Count+1, "beside"); err != nil {
			return err
		}
	}
	return v.StateCounter.CompareAndSwapState(ctx, generation, prev, next, digest)
}

// A count with more counts landing under it than a fixed number of tries
// waits them out instead of failing as not durable (round-4 check R4-3).
func TestACountOutlastsManyCountsInFlight(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	v := newVaultRig(t, r.edge.authority)
	v.key = r.key
	crowd := &crowdedVault{StateCounter: v.vault}
	r.backup = v.backups(v.next())
	r.backup.Counter = crowd
	r.start()
	prev := r.c.durable.counted.Load()
	crowd.n.Store(7)
	if err := r.c.swapCount(t.Context(), prev, prev+10, "mine"); err != nil {
		t.Fatalf("a count with 7 landing under it: %v", err)
	}
	if got := v.count(); got.Count != prev+10 || got.Digest != "mine" {
		t.Fatalf("the vault counted %d %q", got.Count, got.Digest)
	}
	if r.c.Retired() {
		t.Fatal("retired")
	}
}
