package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"maps"
	"os"
	"slices"
	"time"

	"github.com/fount-labs/fount-broker/internal/mail"
)

// Restore puts a backup onto an empty volume and store ("Durable storage"
// step 2): a fresh enclave, or one whose volume was lost. Run it before New,
// in the process that then serves, with the same GenerationSource: the
// vault released this process a new generation, and the restored
// coordinator runs under it, so the one it replaces is fenced at the edge and
// at the vault (decision 18).
//
// It refuses a backup below the vault's counter, which would roll back
// security state (decision 17), and one older than MaxRestoreAge, past which
// the edge may have forgotten what was sent. It doesn't redo what may have
// happened after the backup:
//   - jobs queued or running at the backup, and turns mail had owed, are
//     failed with restoredJobError, since they may have run since;
//   - mail the restored ledgers don't have, received before the restore, is
//     held for a person (restoredReason), since it may have run too;
//   - a send in flight resumes from the send journal, which asks the edge
//     before posting, so it goes out once (decision 14);
//   - the mail cursor isn't restored, so every mailbox is listed again.

// RestoreOptions says what to restore, and where.
type RestoreOptions struct {
	Bucket      BackupBucket
	Counter     VaultCounter
	Generations mail.GenerationSource
	// Key is the wrapping key from the vault: the one the backup was taken
	// under.
	Key WrappingKey
	// StateDir and Store are the new coordinator's, empty.
	StateDir string
	Store    Store
	// Root is the backup to restore, a key under roots/; empty is the
	// newest.
	Root string
	// DryRun checks the backup as a restore would, opening every worker's
	// tree and reading every file from the bucket, and writes nothing: no
	// volume, no store, no count. It doesn't ask Generations, which would
	// move the vault's generation on and stop the coordinator running now,
	// so StateDir, Store and Generations may be empty.
	DryRun bool
}

// RestoreResult is what Restore put back.
type RestoreResult struct {
	Root        string    `json:"root"`
	TakenAt     time.Time `json:"takenAt"`
	SecuritySeq uint64    `json:"securitySeq"`
	Generation  uint64    `json:"generation"`
	Workers     int       `json:"workers"`
	Objects     int       `json:"objects"`
	// StoppedJobs are the jobs failed instead of run again.
	StoppedJobs int  `json:"stoppedJobs"`
	DryRun      bool `json:"dryRun,omitempty"`
}

// RestoreMark is kept in state.json once a backup is restored onto it.
type RestoreMark struct {
	At      time.Time `json:"at"`
	Root    string    `json:"root"`
	TakenAt time.Time `json:"takenAt"`
}

const (
	restoredReason   = "Fount was restored from a backup, and this email may have been worked on before"
	restoredJobError = "Fount was restored from a backup, and this job may have run before; run it again if it should"
)

var (
	// ErrBackupRolledBack is a backup older than the vault's counter.
	ErrBackupRolledBack = errors.New("the backup is older than the vault's security counter, so restoring it would roll back security state")
	// ErrBackupTooOld is a backup past MaxRestoreAge.
	ErrBackupTooOld = errors.New("the backup is older than a restore may reach")
	// ErrRestoreOverVolume is a restore onto a volume that has state.
	ErrRestoreOverVolume = errors.New("the volume already has a coordinator's state; restore onto an empty one")
	// ErrNoBackup is a bucket without the backup asked for.
	ErrNoBackup = errors.New("no such backup")
)

// Restore restores a backup; see the comment above.
func Restore(ctx context.Context, o RestoreOptions) (RestoreResult, error) {
	switch {
	case o.DryRun && (o.Bucket == nil || o.Counter == nil):
		return RestoreResult{}, errors.New("restore: a dry run needs the bucket and the vault's counter")
	case o.DryRun:
		o.Store = &dryStore{ctx: ctx, bucket: o.Bucket, manifests: map[string][]byte{}}
	case o.Bucket == nil || o.Counter == nil || o.Generations == nil || o.Store == nil || o.StateDir == "":
		return RestoreResult{}, errors.New("restore: the bucket, the vault's counter and generation, the volume and the store are required")
	default:
		if _, err := os.Stat(statePath(o.StateDir)); err == nil {
			return RestoreResult{}, ErrRestoreOverVolume
		} else if !errors.Is(err, fs.ErrNotExist) {
			return RestoreResult{}, err
		}
	}
	var g mail.Generation
	if !o.DryRun {
		var err error
		if g, err = o.Generations.Generation(ctx); err != nil {
			return RestoreResult{}, fmt.Errorf("the vault's generation: %w", err)
		}
	}
	count, err := o.Counter.Load(ctx)
	if err != nil {
		return RestoreResult{}, fmt.Errorf("the vault's counter: %w", err)
	}
	if !o.DryRun && count.Generation != g.Number {
		return RestoreResult{}, fmt.Errorf("%w: the vault is at generation %d and this coordinator has %d", ErrStaleCoordinator, count.Generation, g.Number)
	}
	roots, err := listRoots(ctx, o.Bucket)
	if err != nil {
		return RestoreResult{}, err
	}
	var ref rootRef
	switch {
	case len(roots) == 0:
		return RestoreResult{}, ErrNoBackup
	case o.Root == "":
		ref = roots[len(roots)-1]
	default:
		i := slices.IndexFunc(roots, func(r rootRef) bool { return r.key == o.Root })
		if i < 0 {
			return RestoreResult{}, fmt.Errorf("%w: %.80q", ErrNoBackup, o.Root)
		}
		ref = roots[i]
	}
	root, err := openRoot(ctx, o.Bucket, backupKey(&o.Key), ref)
	if err != nil {
		return RestoreResult{}, err
	}
	now := time.Now().UTC()
	if age := now.Sub(root.taken); age > MaxRestoreAge {
		return RestoreResult{}, fmt.Errorf("%w: %s was taken %s ago, and the most is %s", ErrBackupTooOld, ref.key, age.Round(time.Hour), MaxRestoreAge)
	}
	if root.securitySeq < count.Count {
		return RestoreResult{}, fmt.Errorf("%w: %s has security change %d, and the vault counted %d", ErrBackupRolledBack, ref.key, root.securitySeq, count.Count)
	}
	st, err := rootState(root)
	if err != nil {
		return RestoreResult{}, err
	}
	if root.securitySeq == count.Count && !sameState(count, st) {
		return RestoreResult{}, fmt.Errorf("%w: %s is at the vault's count %d with another security state than generation %d counted; it is a fork's", ErrBackupRolledBack, ref.key, count.Count, count.Writer)
	}
	res := RestoreResult{Root: ref.key, TakenAt: root.taken, SecuritySeq: root.securitySeq, Generation: g.Number, DryRun: o.DryRun}

	// The trees first and state.json last: a restore cut short leaves no
	// state.json, and can be run again.
	owed := map[string]pendingMail{}
	owedBy := map[string]string{}
	for _, id := range slices.Sorted(maps.Keys(st.Workers)) {
		w := st.Workers[id]
		if w.WrappedDEK == nil {
			continue
		}
		bt, ok := root.body.Workers[id]
		if !ok {
			return RestoreResult{}, fmt.Errorf("restore: %s has worker %s in its state and not its trees", ref.key, id)
		}
		n, pending, err := restoreTree(ctx, o, w, bt)
		if err != nil {
			return RestoreResult{}, fmt.Errorf("restore: worker %s: %w", id, err)
		}
		res.Workers++
		res.Objects += n
		for _, p := range pending {
			owed[p.JobID], owedBy[p.JobID] = p, id
		}
	}
	for _, j := range st.Jobs {
		if j.State == JobQueued || j.State == JobRunning {
			j.State, j.Spec, j.Error, j.Ended = JobFailed, nil, restoredJobError, now
			res.StoppedJobs++
		}
	}
	for _, jobID := range slices.Sorted(maps.Keys(owed)) {
		if _, ok := st.Jobs[jobID]; ok {
			continue
		}
		st.Seq++
		st.Jobs[jobID] = &Job{ID: jobID, WorkerID: owedBy[jobID], Seq: st.Seq, State: JobFailed, ThreadID: owed[jobID].ThreadID,
			Error: restoredJobError, Queued: now, Ended: now}
		res.StoppedJobs++
	}
	if o.DryRun {
		log.Printf("restore dry run: %s, taken %s, opens whole: %d workers, %d objects; a restore would stop %d jobs",
			ref.key, root.taken.UTC().Format(time.RFC3339), res.Workers, res.Objects, res.StoppedJobs)
		return res, nil
	}
	st.Restored = &RestoreMark{At: now, Root: ref.key, TakenAt: root.taken.UTC()}
	// Every restore moves the count one past both the vault's and the
	// root's, so no other disk or root at the old count, from this lineage
	// or a fenced one, passes afterwards (broker review H2). A change the
	// backup saved and never counted is counted with it.
	st.SecuritySeq, st.SecurityGen = max(count.Count, root.securitySeq)+1, g.Number
	res.SecuritySeq = st.SecuritySeq
	if err := os.MkdirAll(o.StateDir, 0o700); err != nil {
		return RestoreResult{}, err
	}
	if err := st.Save(o.StateDir); err != nil {
		return RestoreResult{}, err
	}
	if err := countState(ctx, o.Counter, g.Number, count.Count, st); err != nil {
		return RestoreResult{}, fmt.Errorf("counting the restore as security change %d: %w", st.SecuritySeq, err)
	}
	log.Printf("restore: %s, taken %s, onto a new volume under generation %d: %d workers, %d objects, %d jobs stopped",
		ref.key, root.taken.UTC().Format(time.RFC3339), g.Number, res.Workers, res.Objects, res.StoppedJobs)
	return res, nil
}

// rootState is the state.json a root holds, as LoadState would read it.
func rootState(root *backupRoot) (*State, error) {
	st := &State{}
	if err := json.Unmarshal(root.body.State, st); err != nil {
		return nil, fmt.Errorf("backup %s: state: %w", root.ref.key, err)
	}
	if st.Workers == nil {
		st.Workers = map[string]*Worker{}
	}
	if st.Jobs == nil {
		st.Jobs = map[string]*Job{}
	}
	if st.Teams == nil {
		st.Teams = map[string]*Team{}
	}
	if st.TeamMints == nil {
		st.TeamMints = map[string]string{}
	}
	return st, nil
}

// restoreTree copies w's objects and manifest into the store, opens the tree
// to check it whole, and returns what its mail still owed.
func restoreTree(ctx context.Context, o RestoreOptions, w *Worker, bt backedTree) (int, []pendingMail, error) {
	ring, err := o.Key.Keyring(w)
	if err != nil {
		return 0, nil, err
	}
	defer ring.Clear()
	for _, obj := range bt.Objects {
		data, err := o.Bucket.Get(ctx, backupObjectPrefix+w.ID+"/"+obj)
		if err != nil {
			return 0, nil, fmt.Errorf("object %s: %w", obj, err)
		}
		if err := o.Store.Put(w.ID, obj, data); err != nil {
			return 0, nil, err
		}
	}
	if bt.Manifest == nil {
		if w.Version != 0 {
			return 0, nil, fmt.Errorf("the backup has no manifest for version %d", w.Version)
		}
		return 0, nil, nil
	}
	if err := o.Store.Put(w.ID, manifestObject, bt.Manifest); err != nil {
		return 0, nil, err
	}
	t, err := LoadTreeKeys(o.Store, w.ID, ring, w.Version)
	if err != nil {
		return 0, nil, err
	}
	for p := range t.manifest.Entries {
		if _, err := t.Read(p); err != nil {
			return 0, nil, err
		}
	}
	pending, err := loadPending(t)
	if err != nil {
		return 0, nil, err
	}
	var jobs []pendingMail
	for _, p := range pending {
		if p.Kind == pendingJob && p.JobID != "" {
			jobs = append(jobs, p)
		}
	}
	return len(bt.Objects), jobs, nil
}

// restoredPause holds mail the restored ledger doesn't have that arrived
// before the restore: the lost coordinator may have run it.
func (c *Coordinator) restoredPause(msg *mail.Message, p pause) pause {
	if p == pauseLapsed {
		return p
	}
	c.mu.Lock()
	r := c.state.Restored
	c.mu.Unlock()
	if r != nil && msg.ReceivedAt < r.At.UnixMilli() {
		return pauseRestored
	}
	return p
}

// dryStore is a dry run's store: it keeps each manifest a restore would
// write, discards the objects, and reads them back from the bucket.
type dryStore struct {
	ctx       context.Context
	bucket    BackupBucket
	manifests map[string][]byte
}

func (d *dryStore) Put(workerID, objectID string, data []byte) error {
	if objectID == manifestObject {
		d.manifests[workerID] = data
	}
	return nil
}

func (d *dryStore) Get(workerID, objectID string) ([]byte, error) {
	if objectID == manifestObject {
		if m, ok := d.manifests[workerID]; ok {
			return m, nil
		}
		return nil, ErrNotFound
	}
	data, err := d.bucket.Get(d.ctx, backupObjectPrefix+workerID+"/"+objectID)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNotFound
	}
	return data, err
}

func (*dryStore) Delete(string, string) error { return errors.New("a dry run writes nothing") }
