package coordinator

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fount-labs/fount-broker/internal/mail"
)

// Backups (launch-plan.md "Durable storage", decisions 15 to 18). The volume
// holds state.json and the store holds each worker's tree. A backup is one
// consistent cut of both, in a bucket:
//
//	objects/<worker>/<object>   a tree object, copied once: objects are
//	                            immutable under fresh ids and already sealed
//	                            under the worker's DEK
//	roots/<gen>-<seq>-<unix>    a root: state.json and each worker's sealed
//	                            manifest and object list, sealed under a key
//	                            derived from the wrapping key
//
// The cut: state.json is taken under c.mu, then each worker's manifest is
// read from the store. A tree commits its manifest before state.json records
// its version, so each manifest read is at or after the version state.json
// names, and each tree is whole: the cut is what a crash at that moment would
// leave on the volume. Deletes in the store are held from before the cut
// until the root is written, so no object a manifest names goes missing
// before it is copied.
//
// A root is written every BackupConfig.Interval when anything changed, and
// synchronously by every change to security state (commitSecurity), before
// the vault counts it. Roots are kept for a day, then one a day up to the
// retention, which must stay under the edge's 90 days of sent records.

// BackupConfig turns backups and the security counter on (Config.Backup).
type BackupConfig struct {
	Bucket  BackupBucket
	Counter VaultCounter
	// Generations is this process's generation from the vault, the same
	// source as MailConfig.Generations: one per coordinator boot.
	Generations mail.GenerationSource
	// Interval is how often a changed volume is backed up. Default 5 min.
	Interval time.Duration
	// Retention is how long roots are kept. Default 30 days; at most
	// MaxBackupRetention.
	Retention time.Duration
	// DeleteMail deletes mail from the edge once every restorable backup
	// has its ledger entry. Off, the edge keeps it.
	DeleteMail bool
}

const (
	// SentRecordWindow is how long the edge keeps a send record after its
	// last write (edge DESIGN.md §8, SENT_RETENTION_DAYS).
	SentRecordWindow = 90 * 24 * time.Hour
	// MaxRestoreAge is the oldest backup a restore takes, with ten days'
	// margin under SentRecordWindow, so every send it could redo is still
	// one the edge can answer "was this sent?" for.
	MaxRestoreAge = SentRecordWindow - 10*24*time.Hour
	// MaxBackupRetention caps BackupConfig.Retention at what a restore takes.
	MaxBackupRetention     = MaxRestoreAge
	DefaultBackupRetention = 30 * 24 * time.Hour
	DefaultBackupInterval  = 5 * time.Minute

	// recentRoots are kept whole; older roots are thinned to one a day.
	recentRoots = 24 * time.Hour
	// pruneEvery spaces out retention passes.
	pruneEvery = time.Hour
	// durableTimeout bounds each count of a change: the vault's counter,
	// the root and the compare-and-swap, under c.mu or not.
	durableTimeout = 30 * time.Second

	backupRootPrefix   = "roots/"
	backupObjectPrefix = "objects/"
	backupRootVersion  = 1
	backupRootInfo     = "fount-coordinator/backup-root/v1"
)

var (
	// ErrStaleCoordinator is a coordinator a newer generation replaced: it
	// serves nothing, fetches and sends no mail, and changes nothing.
	ErrStaleCoordinator = errors.New("a newer coordinator generation has taken over; this one serves nothing")
	// ErrNotDurable is a change to security state that couldn't be backed
	// up or counted, so it wasn't acknowledged.
	ErrNotDurable = errors.New("the change couldn't be made durable")
	// ErrVolumeRolledBack is a volume older than the vault's counter.
	ErrVolumeRolledBack = errors.New("the volume is older than the vault's security counter; restore from a backup")
)

// durability is the coordinator's backups and its place in the vault's
// counter.
type durability struct {
	cfg   BackupConfig
	store *backupStore
	key   [KeySize]byte
	gen   uint64

	// sem serializes backups: writing a root and pruning. It is a channel,
	// not a mutex, so that commitSecurity, which waits for it under c.mu,
	// waits at most its context's time for a root another count or the
	// backup loop is uploading (2026-11-25 re-check, R3-2). Taken after
	// c.mu, never before.
	sem chan struct{}
	// counted is the count the vault last confirmed, which only rises.
	counted atomic.Uint64
	// seq is the last root's number in this generation, and last the cut
	// it was written from: a cut older than it isn't written after it, so
	// the newest root is always the newest cut (writeRoot). Under sem.
	seq  uint64
	last cutMark
	// uploaded are the object keys the bucket has.
	uploaded map[string]bool
	// lastState is the hash of the last root's state.json, so an unchanged
	// volume isn't backed up again.
	lastState [32]byte
	lastPrune time.Time

	status backupStatus
}

// openDurability wraps the store, takes the generation, checks the volume
// against the vault's counter and takes a first backup. A volume older than
// the counter is refused; one newer by an append the vault never counted (a
// crash between the state write and the counter) is backed up and counted
// now. Called from New, before anything is served.
func (c *Coordinator) openDurability() error {
	if c.cfg.Backup == nil {
		return nil
	}
	b := *c.cfg.Backup
	switch {
	case b.Bucket == nil || b.Counter == nil || b.Generations == nil:
		return errors.New("coordinator config: backups need the bucket, the vault's counter and the generation")
	case b.Retention > MaxBackupRetention:
		return fmt.Errorf("coordinator config: backups are kept at most %s, under the edge's sent records", MaxBackupRetention)
	}
	if b.Retention <= 0 {
		b.Retention = DefaultBackupRetention
	}
	if b.Interval <= 0 {
		b.Interval = DefaultBackupInterval
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	g, err := b.Generations.Generation(ctx)
	if err != nil {
		return fmt.Errorf("the vault's generation: %w", err)
	}
	count, err := b.Counter.Load(ctx)
	if err != nil {
		return fmt.Errorf("the vault's counter: %w", err)
	}
	if count.Generation != g.Number {
		return fmt.Errorf("%w: the vault is at generation %d and this coordinator has %d", ErrStaleCoordinator, count.Generation, g.Number)
	}
	store := &backupStore{Store: c.cfg.Store}
	c.cfg.Store = store
	d := &durability{cfg: b, store: store, key: backupKey(&c.cfg.Key), gen: g.Number, uploaded: map[string]bool{}, sem: make(chan struct{}, 1)}
	d.counted.Store(count.Count)
	objects, err := b.Bucket.List(ctx, backupObjectPrefix)
	if err != nil {
		return fmt.Errorf("listing the backups: %w", err)
	}
	for _, k := range objects {
		d.uploaded[k] = true
	}
	roots, err := listRoots(ctx, b.Bucket)
	if err != nil {
		return err
	}
	for _, r := range roots {
		if r.gen == d.gen {
			d.seq = max(d.seq, r.seq)
		}
	}
	c.durable = d

	c.mu.Lock()
	defer c.mu.Unlock()
	switch seq := c.state.SecuritySeq; {
	case seq < count.Count:
		return fmt.Errorf("%w: it has %d and the vault counted %d", ErrVolumeRolledBack, seq, count.Count)
	case seq == count.Count && !sameState(count, c.state):
		return fmt.Errorf("%w: it is at the vault's count %d with another security state than generation %d counted; it is a fork", ErrVolumeRolledBack, seq, count.Writer)
	case seq > count.Count && count.Writer != 0 && c.state.SecurityGen < count.Writer:
		return fmt.Errorf("%w: its uncounted change %d is generation %d's, older than generation %d, which counted %d", ErrVolumeRolledBack, seq, c.state.SecurityGen, count.Writer, count.Count)
	}
	// A volume behind the newest backup of it was replayed to an earlier
	// point, or lost writes: what it lost may have run (broker review M1).
	if root, err := c.replayedVolume(ctx, roots); err != nil {
		return err
	} else if root != nil {
		if err := c.treatAsRestored(root); err != nil {
			return err
		}
	}
	switch seq := c.state.SecuritySeq; {
	case seq > count.Count:
		log.Printf("backup: security change %d was saved and never counted; counting it now", seq)
		if _, err := c.backupLocked(ctx); err != nil {
			return err
		}
		if err := countState(ctx, b.Counter, d.gen, count.Count, c.state); err != nil {
			return fmt.Errorf("counting security change %d: %w", seq, err)
		}
		d.noteCounted(seq)
		return nil
	}
	_, err = c.backupLocked(ctx)
	return err
}

// backupKey seals roots: derived from the wrapping key, so any attested
// coordinator the vault releases it to can open a backup.
func backupKey(w *WrappingKey) [KeySize]byte {
	raw, err := hkdf.Key(sha256.New, w[:], nil, backupRootInfo, KeySize)
	if err != nil {
		panic("hkdf: " + err.Error())
	}
	var k [KeySize]byte
	copy(k[:], raw)
	clear(raw)
	return k
}

// backupStore is the coordinator's store with deletes held while a backup
// copies: an object a commit makes garbage after the cut may be one the cut's
// manifest names.
type backupStore struct {
	Store
	mu       sync.Mutex
	holds    int
	deferred [][2]string
}

func (s *backupStore) Delete(workerID, objectID string) error {
	s.mu.Lock()
	if s.holds > 0 {
		s.deferred = append(s.deferred, [2]string{workerID, objectID})
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	return s.Store.Delete(workerID, objectID)
}

func (s *backupStore) hold() {
	s.mu.Lock()
	s.holds++
	s.mu.Unlock()
}

func (s *backupStore) release() {
	s.mu.Lock()
	s.holds--
	var due [][2]string
	if s.holds == 0 {
		due, s.deferred = s.deferred, nil
	}
	s.mu.Unlock()
	for _, d := range due {
		// An object left behind costs storage, not correctness.
		_ = s.Store.Delete(d[0], d[1])
	}
}

// rootRef is a root's key, read from its name.
type rootRef struct {
	key      string
	gen, seq uint64
	taken    time.Time
}

func rootKey(gen, seq uint64, taken time.Time) string {
	return fmt.Sprintf("%s%020d-%020d-%020d", backupRootPrefix, gen, seq, taken.Unix())
}

func parseRootKey(key string) (rootRef, bool) {
	parts := strings.Split(strings.TrimPrefix(key, backupRootPrefix), "-")
	if !strings.HasPrefix(key, backupRootPrefix) || len(parts) != 3 {
		return rootRef{}, false
	}
	var n [3]uint64
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 10, 64)
		if err != nil || len(p) != 20 {
			return rootRef{}, false
		}
		n[i] = v
	}
	return rootRef{key: key, gen: n[0], seq: n[1], taken: time.Unix(int64(n[2]), 0)}, true
}

// listRoots is the bucket's roots, oldest generation and number first.
func listRoots(ctx context.Context, b BackupBucket) ([]rootRef, error) {
	keys, err := b.List(ctx, backupRootPrefix)
	if err != nil {
		return nil, fmt.Errorf("listing the backups: %w", err)
	}
	var out []rootRef
	for _, k := range keys {
		if r, ok := parseRootKey(k); ok {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b rootRef) int {
		if a.gen != b.gen {
			return cmpUint(a.gen, b.gen)
		}
		return cmpUint(a.seq, b.seq)
	})
	return out, nil
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// rootFile is a root as stored: its header in the clear, its body sealed
// with the header as associated data.
type rootFile struct {
	V           int    `json:"v"`
	Generation  uint64 `json:"generation"`
	Seq         uint64 `json:"seq"`
	SecuritySeq uint64 `json:"securitySeq"`
	TakenAt     int64  `json:"takenAt"`
	Body        []byte `json:"body"`
}

func (r rootFile) aad() []byte {
	return fmt.Appendf(nil, "%s\x00%d\x00%d\x00%d\x00%d\x00%d", backupRootInfo, r.V, r.Generation, r.Seq, r.SecuritySeq, r.TakenAt)
}

// rootBody is what a root seals: state.json as saved, and each worker's tree.
type rootBody struct {
	State   json.RawMessage       `json:"state"`
	Workers map[string]backedTree `json:"workers"`
}

// backedTree is one worker's tree in a root: its manifest as the store held
// it, sealed under the DEK, and the objects that manifest names.
type backedTree struct {
	Version  uint64   `json:"version"`
	Manifest []byte   `json:"manifest,omitempty"`
	Objects  []string `json:"objects"`
}

// backupRoot is an opened root.
type backupRoot struct {
	ref         rootRef
	securitySeq uint64
	taken       time.Time
	body        rootBody
}

func openRoot(ctx context.Context, b BackupBucket, key [KeySize]byte, ref rootRef) (*backupRoot, error) {
	data, err := b.Get(ctx, ref.key)
	if err != nil {
		return nil, fmt.Errorf("backup %s: %w", ref.key, err)
	}
	var f rootFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("backup %s: %w", ref.key, err)
	}
	if f.V != backupRootVersion || f.Generation != ref.gen || f.Seq != ref.seq {
		return nil, fmt.Errorf("backup %s: its header isn't its name's", ref.key)
	}
	plain, err := open(key[:], f.Body, f.aad())
	if err != nil {
		return nil, fmt.Errorf("backup %s: %w", ref.key, err)
	}
	r := &backupRoot{ref: ref, securitySeq: f.SecuritySeq, taken: time.UnixMilli(f.TakenAt)}
	if err := json.Unmarshal(plain, &r.body); err != nil {
		return nil, fmt.Errorf("backup %s: %w", ref.key, err)
	}
	return r, nil
}

// lock takes sem, or fails when ctx ends first.
func (d *durability) lock(ctx context.Context) error {
	select {
	case d.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("waiting for the backup in progress: %w", ctx.Err())
	}
}

func (d *durability) unlock() { <-d.sem }

// noteCounted records that the vault confirmed count n.
func (d *durability) noteCounted(n uint64) {
	for {
		was := d.counted.Load()
		if n <= was || d.counted.CompareAndSwap(was, n) {
			return
		}
	}
}

// volumeCut is the volume as a backup takes it, under c.mu.
type volumeCut struct {
	state   []byte
	mark    cutMark
	workers []Worker
}

// cutMark orders cuts: by security sequence, then by saves.
type cutMark struct {
	securitySeq, saves uint64
}

func (m cutMark) after(o cutMark) bool {
	return m.securitySeq > o.securitySeq || m.securitySeq == o.securitySeq && m.saves > o.saves
}

// takeCut is the volume now. Called with c.mu held.
func (c *Coordinator) takeCut() (volumeCut, error) {
	data, err := json.Marshal(c.state)
	if err != nil {
		return volumeCut{}, err
	}
	k := volumeCut{state: data, mark: cutMark{c.state.SecuritySeq, c.state.Saves}}
	for _, id := range slices.Sorted(maps.Keys(c.state.Workers)) {
		if w := c.state.Workers[id]; w.WrappedDEK != nil {
			k.workers = append(k.workers, *w)
		}
	}
	return k, nil
}

// backupLocked writes a root of the volume now. Called with c.mu held, as
// commitSecurity is: it waits for a backup in progress at most until ctx
// ends.
func (c *Coordinator) backupLocked(ctx context.Context) (string, error) {
	d := c.durable
	if err := d.lock(ctx); err != nil {
		return "", err
	}
	defer d.unlock()
	d.store.hold()
	defer d.store.release()
	d.status.noteAttempt()
	k, err := c.takeCut()
	if err != nil {
		d.status.noteError("", err)
		return "", err
	}
	return c.writeRoot(ctx, k)
}

// Backup writes a root of the volume now, when it changed since the last.
// It holds c.mu only to take state.json, and never waits under it for a
// backup in progress.
func (c *Coordinator) Backup(ctx context.Context) (string, error) {
	d := c.durable
	if d == nil {
		return "", errors.New("backups are off")
	}
	if c.Retired() {
		return "", ErrStaleCoordinator
	}
	c.mu.Lock()
	d.store.hold()
	k, err := c.takeCut()
	c.mu.Unlock()
	defer d.store.release()
	if err != nil {
		d.status.noteError("", err)
		return "", err
	}
	return c.writeCut(ctx, k)
}

// writeCut writes a root of k, taken with the store's deletes held, unless
// it is the last root's or older.
func (c *Coordinator) writeCut(ctx context.Context, k volumeCut) (string, error) {
	d := c.durable
	if err := d.lock(ctx); err != nil {
		d.status.noteError("", err)
		return "", err
	}
	defer d.unlock()
	d.status.noteAttempt()
	if sha256.Sum256(k.state) == d.lastState {
		d.status.noteUnchanged()
		return "", nil
	}
	return c.writeRoot(ctx, k)
}

// writeRoot copies the cut's trees and writes its root. A cut no newer than
// the last root's, taken before a newer one was written, is passed over:
// the newer root holds all it has. Called with sem held and the store's
// deletes held.
func (c *Coordinator) writeRoot(ctx context.Context, k volumeCut) (key string, err error) {
	d := c.durable
	if d.last != (cutMark{}) && !k.mark.after(d.last) {
		d.status.noteUnchanged()
		return "", nil
	}
	var run BackupRun
	defer func() {
		if err != nil {
			d.status.noteError("", err)
		} else {
			d.status.noteRoot(key, run)
		}
	}()
	body := rootBody{State: k.state, Workers: map[string]backedTree{}}
	for _, w := range k.workers {
		bt, err := c.backupTree(ctx, w, &run)
		if err != nil {
			return "", fmt.Errorf("backing up worker %s: %w", w.ID, err)
		}
		body.Workers[w.ID] = bt
	}
	plain, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	now := time.Now()
	f := rootFile{V: backupRootVersion, Generation: d.gen, Seq: d.seq + 1, SecuritySeq: k.mark.securitySeq, TakenAt: now.UnixMilli()}
	if f.Body, err = seal(d.key[:], plain, f.aad()); err != nil {
		return "", err
	}
	data, err := json.Marshal(f)
	if err != nil {
		return "", err
	}
	key = rootKey(f.Generation, f.Seq, now)
	if err := d.cfg.Bucket.Put(ctx, key, data); err != nil {
		return "", fmt.Errorf("writing backup %s: %w", key, err)
	}
	run.Bytes += int64(len(data))
	d.seq, d.last, d.lastState = f.Seq, k.mark, sha256.Sum256(k.state)
	return key, nil
}

// backupTree copies what w's manifest names that the bucket hasn't yet. The
// manifest is read once and opened here, so the objects copied are the ones
// the kept bytes name. What it copies is counted in run.
func (c *Coordinator) backupTree(ctx context.Context, w Worker, run *BackupRun) (backedTree, error) {
	d := c.durable
	sealed, err := d.store.Store.Get(w.ID, manifestObject)
	if errors.Is(err, ErrNotFound) && w.Version == 0 {
		return backedTree{Objects: []string{}}, nil
	}
	if err != nil {
		return backedTree{}, err
	}
	ring, err := c.cfg.Key.Keyring(&w)
	if err != nil {
		return backedTree{}, err
	}
	plain, _, err := openManifest(ring, w.ID, sealed)
	ring.Clear()
	if err != nil {
		return backedTree{}, err
	}
	var m manifest
	if err := json.Unmarshal(plain, &m); err != nil {
		return backedTree{}, fmt.Errorf("manifest: %w", err)
	}
	if m.Version < w.Version {
		return backedTree{}, fmt.Errorf("%w (version %d, expected %d)", ErrRolledBack, m.Version, w.Version)
	}
	bt := backedTree{Version: m.Version, Manifest: sealed, Objects: []string{}}
	for _, p := range slices.Sorted(maps.Keys(m.Entries)) {
		obj := m.Entries[p].Object
		bt.Objects = append(bt.Objects, obj)
		key := backupObjectPrefix + w.ID + "/" + obj
		if d.uploaded[key] {
			continue
		}
		data, err := d.store.Store.Get(w.ID, obj)
		if err != nil {
			return backedTree{}, fmt.Errorf("object %s: %w", obj, err)
		}
		if err := d.cfg.Bucket.Put(ctx, key, data); err != nil {
			return backedTree{}, err
		}
		d.uploaded[key] = true
		run.Objects++
		run.Bytes += int64(len(data))
	}
	return bt, nil
}

// RunBackups backs the volume up every Interval while it changes, keeps
// within the retention, deletes mail from the edge that every restorable
// backup has acted on, and stops this coordinator once the vault has moved
// to a newer generation. It returns when ctx ends, or at once without
// backups.
func (c *Coordinator) RunBackups(ctx context.Context) {
	d := c.durable
	if d == nil {
		return
	}
	tick := time.NewTicker(d.cfg.Interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if !c.backupPass(ctx, time.Now()) {
			return
		}
	}
}

// backupPass is one round of RunBackups. It reports false once this
// coordinator is retired.
func (c *Coordinator) backupPass(ctx context.Context, now time.Time) bool {
	d := c.durable
	if c.Retired() {
		return false
	}
	loadCtx, cancel := context.WithTimeout(ctx, durableTimeout)
	count, err := d.cfg.Counter.Load(loadCtx)
	cancel()
	if err != nil {
		log.Printf("backup: the vault's counter: %v", err)
		d.status.noteError("the vault's counter: ", err)
	} else if count.Generation != d.gen {
		c.retire(fmt.Errorf("%w: the vault is at generation %d", ErrVaultGeneration, count.Generation))
		return false
	}
	c.countLedger(now)
	if key, err := c.Backup(ctx); err != nil {
		log.Printf("backup: %v", err)
	} else if key != "" {
		log.Printf("backup: wrote %s", key)
	}
	if now.Sub(d.lastPrune) >= pruneEvery {
		if err := c.pruneBackups(ctx, now); err != nil {
			log.Printf("backup: keeping to the retention: %v", err)
			d.status.noteError("keeping to the retention: ", err)
		} else {
			d.lastPrune = now
		}
	}
	if d.cfg.DeleteMail {
		if err := c.deleteBackedUpMail(ctx, now); err != nil {
			log.Printf("backup: deleting backed-up mail from the edge: %v", err)
		}
	}
	return true
}

// keptRoots says which roots retention keeps: the newest, every one from the
// last day, and the first of each day after that up to the retention.
func keptRoots(roots []rootRef, retention time.Duration, now time.Time) map[string]bool {
	keep := map[string]bool{}
	if len(roots) == 0 {
		return keep
	}
	keep[roots[len(roots)-1].key] = true
	days := map[string]bool{}
	byTime := slices.Clone(roots)
	slices.SortStableFunc(byTime, func(a, b rootRef) int { return a.taken.Compare(b.taken) })
	for _, r := range byTime {
		age := now.Sub(r.taken)
		switch {
		case age <= recentRoots:
			keep[r.key] = true
		case age <= retention:
			day := r.taken.UTC().Format(time.DateOnly)
			if !days[day] {
				days[day], keep[r.key] = true, true
			}
		}
	}
	return keep
}

// pruneBackups deletes roots retention doesn't keep, then the objects no
// kept root names.
func (c *Coordinator) pruneBackups(ctx context.Context, now time.Time) error {
	d := c.durable
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()
	roots, err := listRoots(ctx, d.cfg.Bucket)
	if err != nil {
		return err
	}
	keep := keptRoots(roots, d.cfg.Retention, now)
	named := map[string]bool{}
	for _, r := range roots {
		if !keep[r.key] {
			continue
		}
		root, err := openRoot(ctx, d.cfg.Bucket, d.key, r)
		if err != nil {
			// A root that doesn't open protects nothing it names; the
			// objects of the roots that do are kept.
			log.Printf("backup: %v", err)
			continue
		}
		for id, bt := range root.body.Workers {
			for _, obj := range bt.Objects {
				named[backupObjectPrefix+id+"/"+obj] = true
			}
		}
	}
	for _, r := range roots {
		if !keep[r.key] {
			if err := d.cfg.Bucket.Delete(ctx, r.key); err != nil {
				return err
			}
		}
	}
	objects, err := d.cfg.Bucket.List(ctx, backupObjectPrefix)
	if err != nil {
		return err
	}
	for _, k := range objects {
		if named[k] {
			continue
		}
		if err := d.cfg.Bucket.Delete(ctx, k); err != nil {
			return err
		}
		delete(d.uploaded, k)
	}
	return nil
}

// restorableFloor is the oldest root a restore could take now: within
// MaxRestoreAge and at or above the vault's counter. Mail one of its ledgers
// has acted on is in every restorable backup.
func (c *Coordinator) restorableFloor(ctx context.Context, now time.Time) (*backupRoot, error) {
	d := c.durable
	counted := d.counted.Load()
	roots, err := listRoots(ctx, d.cfg.Bucket)
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(roots, func(a, b rootRef) int { return a.taken.Compare(b.taken) })
	for _, r := range roots {
		if now.Sub(r.taken) > MaxRestoreAge {
			continue
		}
		root, err := openRoot(ctx, d.cfg.Bucket, d.key, r)
		if err != nil {
			// A root that doesn't open can't be restored, so it doesn't
			// hold mail back; but it can't vouch for any either.
			return nil, err
		}
		if root.securitySeq >= counted {
			return root, nil
		}
	}
	return nil, nil
}

// deleteBackedUpMail deletes from the edge the messages the oldest
// restorable backup's ledger has acted on (decision 15, "Durable storage"
// step 3): a restore to any backup the coordinator would take still has their
// ledger entries, so none is lost and none is fetched again.
func (c *Coordinator) deleteBackedUpMail(ctx context.Context, now time.Time) error {
	if c.mail == nil || c.Retired() {
		return nil
	}
	floor, err := c.restorableFloor(ctx, now)
	if err != nil || floor == nil {
		return err
	}
	var st State
	if err := json.Unmarshal(floor.body.State, &st); err != nil {
		return err
	}
	current := c.mailWorkers()
	var errs []error
	for _, id := range slices.Sorted(maps.Keys(floor.body.Workers)) {
		was := st.Workers[id]
		if was == nil || was.Mailbox == "" {
			continue
		}
		cur, ok := current[was.Mailbox]
		if !ok || cur.ID != id || !c.mail.service.HasKeys(was.Mailbox) {
			continue
		}
		acted, err := c.backedUpActed(ctx, floor, was)
		if err != nil {
			errs = append(errs, fmt.Errorf("worker %s: %w", id, err))
			continue
		}
		listing, err := c.mail.service.List(ctx, was.Mailbox)
		if err != nil {
			errs = append(errs, fmt.Errorf("worker %s: %w", id, err))
			continue
		}
		for _, l := range listing.Messages {
			if !acted[l.ID] {
				continue
			}
			if _, err := c.mail.service.Handle(ctx, mail.OpDelete, was.Mailbox, l.ID, nil); err != nil && !errors.Is(err, mail.ErrNotFound) {
				c.fenced(ctx, was.Mailbox, err)
				errs = append(errs, fmt.Errorf("worker %s: deleting mail %s: %w", id, l.ID, err))
			}
		}
	}
	return errors.Join(errs...)
}

// backedUpActed is the messages w's ledger in root has acted on.
func (c *Coordinator) backedUpActed(ctx context.Context, root *backupRoot, w *Worker) (map[string]bool, error) {
	t, err := c.backedUpTree(ctx, c.durable.cfg.Bucket, root, w)
	if err != nil {
		return nil, err
	}
	l, err := loadMailLedger(t)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for id := range l.Acted {
		out[id] = true
	}
	return out, nil
}

// backedUpTree opens w's tree as root has it, from the bucket.
func (c *Coordinator) backedUpTree(ctx context.Context, b BackupBucket, root *backupRoot, w *Worker) (*Tree, error) {
	bt, ok := root.body.Workers[w.ID]
	if !ok {
		return nil, ErrNoWorker
	}
	ring, err := c.cfg.Key.Keyring(w)
	if err != nil {
		return nil, err
	}
	defer ring.Clear()
	t, err := LoadTreeKeys(bucketTree{ctx: ctx, bucket: b, workerID: w.ID, manifest: bt.Manifest}, w.ID, ring, 0)
	if t != nil {
		t.secret = c.treeSecret(w.ID)
	}
	return t, err
}

// bucketTree is one worker's tree in a backup, read-only, as a Store.
type bucketTree struct {
	ctx      context.Context
	bucket   BackupBucket
	workerID string
	manifest []byte
}

func (b bucketTree) Get(workerID, objectID string) ([]byte, error) {
	if workerID != b.workerID {
		return nil, ErrNotFound
	}
	if objectID == manifestObject {
		if b.manifest == nil {
			return nil, ErrNotFound
		}
		return b.manifest, nil
	}
	data, err := b.bucket.Get(b.ctx, backupObjectPrefix+workerID+"/"+objectID)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNotFound
	}
	return data, err
}

func (bucketTree) Put(string, string, []byte) error { return errors.New("a backup is read-only") }
func (bucketTree) Delete(string, string) error      { return errors.New("a backup is read-only") }
