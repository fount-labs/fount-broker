// Package coordinator is Fount Cloud's coordinator (m4-cloud-runners.md, in the
// Fount repo's docs/features/fount-fleet). It holds each Cloud worker's data key
// and files, queues jobs, and hands each to a runner in a folder it prepares,
// then keeps what the job may change. It never parses user content: files and
// runner output are opaque bytes to it, and a JobSpec is the only request body
// it reads.
//
// This is the P2 skeleton. It runs on a laptop with a local folder for storage
// and a command per runner. Its wrapping key comes from the caller: a dev file,
// or the Cloud vault pair (package vaultkey). Clients reach it over the
// attested client channel (package channel), one account and device per
// channel, and move workers in with a DEK grant their device keys sign
// (grant.go). Each worker's threads are records in its tree, changed only by
// operations (thread.go, threadops.go). Not built yet: the buckets sidecar,
// mail intake and the inference relay.
package coordinator

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fount-labs/fount-broker/internal/jobwire"
)

type Config struct {
	// StateDir is the encrypted volume: the queue and the workers' wrapped
	// keys.
	StateDir string
	// WorkDir holds each running job's folders. In an enclave it is tmpfs.
	WorkDir string
	Store   Store
	Key     WrappingKey
	Pool    *Pool
	Runner  Runner
	// Intake runs intake on received mail (intake.go). Nil refuses it.
	Intake IntakeRunner
	// Credentials are a job's credentials, by the broker's names: in the pool,
	// minted for that one job (package jobcred). Nil gives jobs none.
	Credentials func(account, workerID, jobID string) (map[string]string, error)
	// Audience is the name grants and inclusions must give the coordinator
	// (grant.go): its origin over the client channel. Empty takes none.
	Audience string
	// AccountJobs caps an account's running jobs, so its jobs together stay
	// under the model rate limit of its one inference key. Jobs past it wait
	// in the queue. 0 is no cap.
	AccountJobs int
	// JobConfig is the model settings of every job a thread operation
	// starts, passed to the runner unread. Empty refuses those operations
	// with NO_MODEL.
	JobConfig json.RawMessage
	// Mail runs each Cloud worker's mail loop (mailloop.go, RunMail). Zero
	// runs none.
	Mail MailConfig
	// Backup backs the volume up and counts security changes in the vault
	// (backup.go, RunBackups). Nil does neither.
	Backup *BackupConfig
	// TeamBilling signs firm teams' billing statements and asks fount-infra
	// for their subscriptions (teambilling.go, RunTeamBilling). Nil does
	// neither.
	TeamBilling TeamBiller
}

type Coordinator struct {
	cfg Config

	mu    sync.Mutex
	state *State
	// busy is the workers with a running job: a worker runs one job at a time
	// (fount-mail.md decision 51).
	busy map[string]bool
	// accountJobs counts each account's running jobs, for Config.AccountJobs.
	accountJobs map[string]int
	// locks serialize changes to each worker's tree.
	locks map[string]*sync.Mutex
	// cancels stops each running job.
	cancels map[string]context.CancelFunc
	// queued is why each queued job didn't start in the last schedule pass
	// (queuedBusy or queuedWaiting), which its turn shows.
	queued map[string]string
	wake   chan struct{}
	// running counts jobs started and not yet ended, for Wait.
	running sync.WaitGroup
	// mail is the mail loop's, nil without Config.Mail.
	mail *mailLoop
	// sender is the send journal's way to the edge, nil when sending is off.
	sender MailSender
	// durable is the backups', nil without Config.Backup; fence is set once
	// a newer generation takes over (backupcommit.go).
	durable *durability
	fence   fence
	// Not kept: a restart drops them, and the device asks again.
	// passkeyChallenges are passkey joins' challenges (passkeyjoin.go), by
	// nonce; not kept either.
	passkeyChallenges map[string]*passkeyChallenge
	// intakeWaits are workers' intakes waiting for a runner slot, which
	// TeamRunners counts as queued.
	intakeWaits map[string]intakeWait
	// clock is the team log's time, time.Now unless a test sets it.
	clock func() time.Time
	// billing is the team billing loop's (teambilling.go).
	billing teamBillingLoop
}

// now is the team log's time: lists' age, records' at and recoveries' wait.
func (c *Coordinator) now() time.Time {
	if c.clock != nil {
		return c.clock()
	}
	return time.Now()
}

func New(cfg Config) (*Coordinator, error) {
	if cfg.StateDir == "" || cfg.WorkDir == "" || cfg.Store == nil || cfg.Pool == nil || cfg.Runner == nil {
		return nil, errors.New("coordinator config: StateDir, WorkDir, Store, Pool and Runner are required")
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.WorkDir, 0o700); err != nil {
		return nil, err
	}
	state, err := LoadState(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	if err := checkKey(cfg.Key, state); err != nil {
		return nil, err
	}
	if len(cfg.JobConfig) > 0 && (cfg.JobConfig[0] != '{' || len(cfg.JobConfig) > maxConfigBytes || !json.Valid(cfg.JobConfig)) {
		return nil, fmt.Errorf("coordinator config: JobConfig must be a JSON object of at most %d bytes", maxConfigBytes)
	}
	if cfg.Mail.Service != nil && cfg.Intake == nil {
		return nil, errors.New("coordinator config: the mail loop needs an intake runner")
	}
	if cfg.Mail.Send && cfg.Mail.Service == nil {
		return nil, errors.New("coordinator config: sending mail needs the mail loop's Service")
	}
	c := &Coordinator{cfg: cfg, state: state, busy: map[string]bool{}, accountJobs: map[string]int{}, locks: map[string]*sync.Mutex{}, cancels: map[string]context.CancelFunc{}, queued: map[string]string{}, wake: make(chan struct{}, 1), passkeyChallenges: map[string]*passkeyChallenge{}}
	if cfg.Mail.Send {
		c.sender = serviceSender{service: cfg.Mail.Service}
		if c.cfg.Mail.Ack == nil {
			c.cfg.Mail.Ack = c
		}
		if c.cfg.Mail.Notices == nil {
			c.cfg.Mail.Notices = ownerNotices{c}
		}
	}
	c.mail = newMailLoop(c.cfg.Mail)
	if err := c.openDurability(); err != nil {
		return nil, err
	}
	if err := c.state.Save(cfg.StateDir); err != nil {
		return nil, err
	}
	return c, nil
}

// checkKey fails at boot when the wrapping key doesn't open every worker's DEK
// on the volume: a volume made under another key (the dev one, say) would
// otherwise fail only when each worker's next job starts.
func checkKey(key WrappingKey, state *State) error {
	for _, id := range slices.Sorted(maps.Keys(state.Workers)) {
		if state.Workers[id].WrappedDEK == nil {
			continue
		}
		ring, err := key.Keyring(state.Workers[id])
		ring.Clear()
		if err != nil {
			return fmt.Errorf("the wrapping key doesn't fit this volume: %w", err)
		}
	}
	return nil
}

var (
	ErrNoWorker = errors.New("no such worker")
	ErrNoJob    = errors.New("no such job")
	// ErrWriteOnce is a write over a thread file: what was received never
	// changes, so a citation always opens the same bytes (§5.5).
	ErrWriteOnce = errors.New("thread files are written once")
	ErrReserved  = errors.New("the path is reserved")
)

// CreateWorker takes a worker into the coordinator for the dev API. dek is a
// key to keep its files under; nil makes a new one. Over the client channel a
// worker comes from CreateWorkerFor, and its DEK from a grant.
func (c *Coordinator) CreateWorker(account string, dek *DEK) (Worker, error) {
	key := DEK{}
	defer clear(key[:])
	if dek != nil {
		key = *dek
	} else {
		var err error
		if key, err = NewDEK(); err != nil {
			return Worker{}, err
		}
	}
	id, err := newID("w")
	if err != nil {
		return Worker{}, err
	}
	wrapped, err := c.cfg.Key.Wrap(id, key)
	if err != nil {
		return Worker{}, err
	}
	return c.add(&Worker{ID: id, Account: account, WrappedDEK: wrapped, Created: time.Now().UTC()})
}

func (c *Coordinator) add(w *Worker) (Worker, error) {
	if err := checkID("account", w.Account); err != nil {
		return Worker{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state.Workers[w.ID] = w
	if err := c.state.Save(c.cfg.StateDir); err != nil {
		delete(c.state.Workers, w.ID)
		return Worker{}, err
	}
	return *w, nil
}

func (c *Coordinator) Worker(id string) (Worker, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	w, ok := c.state.Workers[id]
	if !ok {
		return Worker{}, ErrNoWorker
	}
	return *w, nil
}

// Workers are an account's workers, oldest first.
func (c *Coordinator) Workers(account string) []Worker {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Worker
	for _, w := range c.state.Workers {
		if w.Account == account {
			out = append(out, *w)
		}
	}
	slices.SortFunc(out, func(a, b Worker) int { return cmp.Or(a.Created.Compare(b.Created), strings.Compare(a.ID, b.ID)) })
	return out
}

// PutFile writes a file into a worker's root: instructions, memory, a file the
// user sends, or (until intake runners exist) a thread's message.
func (c *Coordinator) PutFile(workerID, path string, data []byte) error {
	return c.putFile(anyDevice, workerID, path, data)
}

// anyDevice is the device of the dev API and the coordinator's own jobs,
// which no device list limits.
const anyDevice = ""

func (c *Coordinator) putFile(device, workerID, path string, data []byte) error {
	if err := checkPath(path); err != nil {
		return err
	}
	if path == fountDir || strings.HasPrefix(path, fountDir+"/") {
		return fmt.Errorf("%s: %w", path, ErrReserved)
	}
	return c.change(workerID, device, func(t *Tree) error {
		if strings.HasPrefix(path, "threads/") && t.Has(prefixRoot+path) {
			return fmt.Errorf("%s: %w", path, ErrWriteOnce)
		}
		return t.Write(prefixRoot+path, data)
	})
}

// ReadFile reads a path from a worker's whole tree, "root/…" included.
func (c *Coordinator) ReadFile(workerID, path string) ([]byte, error) {
	return c.readFile(anyDevice, workerID, path)
}

func (c *Coordinator) readFile(device, workerID, path string) ([]byte, error) {
	var data []byte
	err := c.view(workerID, device, func(t *Tree) (err error) {
		data, err = t.Read(path)
		return err
	})
	return data, err
}

func (c *Coordinator) ListFiles(workerID, prefix string) ([]string, error) {
	return c.listFiles(anyDevice, workerID, prefix)
}

func (c *Coordinator) listFiles(device, workerID, prefix string) ([]string, error) {
	var paths []string
	err := c.view(workerID, device, func(t *Tree) error {
		paths = t.List(prefix)
		return nil
	})
	return paths, err
}

// Enqueue queues a job on a worker's thread.
func (c *Coordinator) Enqueue(workerID string, spec JobSpec) (Job, error) {
	return c.enqueue(anyDevice, workerID, spec)
}

func (c *Coordinator) enqueue(device, workerID string, spec JobSpec) (Job, error) {
	id, err := newID("j")
	if err != nil {
		return Job{}, err
	}
	j, err := c.enqueueAs(device, workerID, id, spec)
	if err == nil {
		c.poke()
	}
	return j, err
}

// enqueueAs queues spec as job id without waking the scheduler: a thread
// operation names its job in the thread before it queues it.
func (c *Coordinator) enqueueAs(device, workerID, id string, spec JobSpec) (Job, error) {
	if err := spec.check(); err != nil {
		return Job{}, err
	}
	c.mu.Lock()
	if w, ok := c.state.Workers[workerID]; !ok || !w.mayAct(device) {
		c.mu.Unlock()
		return Job{}, ErrNoWorker
	} else if w.WrappedDEK == nil {
		c.mu.Unlock()
		return Job{}, ErrNotGranted
	}
	c.state.Seq++
	j := &Job{ID: id, WorkerID: workerID, Seq: c.state.Seq, State: JobQueued, Spec: &spec, ThreadID: spec.ThreadID, Queued: time.Now().UTC()}
	c.state.Jobs[id] = j
	if err := c.state.Save(c.cfg.StateDir); err != nil {
		delete(c.state.Jobs, id)
		c.mu.Unlock()
		return Job{}, err
	}
	out := *j
	out.Spec = nil
	c.mu.Unlock()
	return out, nil
}

// cancel stops a queued or running job. A running one ends as its runner
// stops, and its worker stays busy until then; what it leaves is thrown
// away. It reports whether the job was still unfinished.
func (c *Coordinator) cancel(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	j, ok := c.state.Jobs[id]
	if !ok {
		return false
	}
	switch j.State {
	case JobQueued:
		j.Spec, j.Ended = nil, time.Now().UTC()
	case JobRunning:
		if stop := c.cancels[id]; stop != nil {
			stop()
		}
	default:
		return false
	}
	j.State = JobCancelled
	if err := c.state.Save(c.cfg.StateDir); err != nil {
		log.Printf("save state: %v", err)
	}
	return true
}

func (c *Coordinator) cancelled(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	j := c.state.Jobs[id]
	return j != nil && j.State == JobCancelled
}

func (c *Coordinator) Job(id string) (Job, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	j, ok := c.state.Jobs[id]
	if !ok {
		return Job{}, ErrNoJob
	}
	out := *j
	out.Spec = nil
	return out, nil
}

func (c *Coordinator) poke() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// Run schedules jobs until ctx ends, then waits for the running ones.
func (c *Coordinator) Run(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		c.schedule(ctx)
		select {
		case <-ctx.Done():
			c.running.Wait()
			return
		case <-c.wake:
		case <-tick.C:
			c.ExpireUngranted()
		}
	}
}

// schedule starts every queued job that can start: its worker has no running
// job, its team pays if it is a firm team's, its account is under
// Config.AccountJobs and can get a runner slot. Each
// slot goes to the account with the fewest jobs running, then the oldest job,
// so an account with a long queue takes turns with the others.
func (c *Coordinator) schedule(ctx context.Context) {
	if c.Retired() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var queued []*Job
	for _, j := range c.state.Jobs {
		if j.State == JobQueued {
			queued = append(queued, j)
		}
	}
	slices.SortFunc(queued, func(a, b *Job) int { return cmp.Compare(a.Seq, b.Seq) })
	// noSlot is the accounts the pool had no slot for in this pass.
	noSlot := map[string]bool{}
	var noRunner []*Job
	for {
		i := c.next(queued, noSlot)
		if i < 0 {
			c.whyQueued(append(queued, noRunner...), noSlot)
			return
		}
		j := queued[i]
		queued = slices.Delete(queued, i, i+1)
		w := c.state.Workers[j.WorkerID]
		runner, ok := c.cfg.Pool.Acquire(w.Account)
		if !ok {
			noSlot[w.Account] = true
			noRunner = append(noRunner, j)
			continue
		}
		spec := *j.Spec
		j.Spec, j.State, j.Runner, j.Started = nil, JobRunning, runner, time.Now().UTC()
		if err := c.state.Save(c.cfg.StateDir); err != nil {
			log.Printf("save state: %v", err)
		}
		c.busy[j.WorkerID] = true
		c.accountJobs[w.Account]++
		c.running.Add(1)
		jobCtx, stop := context.WithCancel(ctx)
		c.cancels[j.ID] = stop
		go c.execute(jobCtx, *j, *w, spec)
	}
}

// Why a queued job hasn't started, as its agent-turn's queued shows it:
// queuedBusy when the runner pool is at capacity, queuedWaiting when the job
// waits on its own account (its cap, or its worker's running job).
const (
	queuedBusy    = "busy"
	queuedWaiting = "waiting"
)

// whyQueued records why each job left queued didn't start, and has the
// threads of those whose reason changed follow it. It holds c.mu.
func (c *Coordinator) whyQueued(queued []*Job, noSlot map[string]bool) {
	why := make(map[string]string, len(queued))
	for _, j := range queued {
		account := c.state.Workers[j.WorkerID].Account
		why[j.ID] = queuedWaiting
		if noSlot[account] {
			why[j.ID] = queuedBusy
		}
		if c.queued[j.ID] != why[j.ID] && j.ThreadID != "" {
			c.running.Add(1)
			go func(workerID, threadID string) {
				defer c.running.Done()
				c.followJob(workerID, threadID)
			}(j.WorkerID, j.ThreadID)
		}
	}
	c.queued = why
}

// next is the index of the queued job to start next, or -1 for none. queued is
// oldest first. A firm team's job waits while the team doesn't pay
// (admission.go), as for a runner that isn't there: its model calls would be
// refused mid-turn.
func (c *Coordinator) next(queued []*Job, noSlot map[string]bool) int {
	best, bestRunning := -1, 0
	now := c.now()
	for i, j := range queued {
		w := c.state.Workers[j.WorkerID]
		account := w.Account
		running := c.accountJobs[account]
		switch {
		case c.busy[j.WorkerID], noSlot[account]:
		case !c.teamRunsJobs(w.Team, now):
		case c.cfg.AccountJobs > 0 && running >= c.cfg.AccountJobs:
		case best < 0 || running < bestRunning:
			best, bestRunning = i, running
		}
	}
	return best
}

// Load is the queue by account: what /status shows. It names no account.
type Load struct {
	// AccountJobs is Config.AccountJobs, 0 for no cap.
	AccountJobs int           `json:"account_jobs"`
	Running     int           `json:"running"`
	Queued      int           `json:"queued"`
	Accounts    []AccountLoad `json:"accounts"`
}

type AccountLoad struct {
	Running int `json:"running"`
	Queued  int `json:"queued"`
}

// Load counts the running and queued jobs of each account with either, the
// busiest first.
func (c *Coordinator) Load() Load {
	c.mu.Lock()
	defer c.mu.Unlock()
	by := map[string]*AccountLoad{}
	l := Load{AccountJobs: c.cfg.AccountJobs, Accounts: []AccountLoad{}}
	for _, j := range c.state.Jobs {
		if j.State != JobQueued && j.State != JobRunning {
			continue
		}
		w := c.state.Workers[j.WorkerID]
		if w == nil {
			continue
		}
		a := by[w.Account]
		if a == nil {
			a = &AccountLoad{}
			by[w.Account] = a
		}
		if j.State == JobRunning {
			a.Running++
			l.Running++
		} else {
			a.Queued++
			l.Queued++
		}
	}
	for _, a := range by {
		l.Accounts = append(l.Accounts, *a)
	}
	slices.SortFunc(l.Accounts, func(a, b AccountLoad) int {
		return cmp.Or(cmp.Compare(b.Running, a.Running), cmp.Compare(b.Queued, a.Queued))
	})
	return l
}

func (c *Coordinator) execute(ctx context.Context, job Job, w Worker, spec JobSpec) {
	defer c.running.Done()
	c.followJob(w.ID, job.ThreadID)
	kept, dropped, err := c.runJob(ctx, job, w, spec)
	if err != nil {
		// The error goes on the volume, outside the DEK, so it says what failed
		// and never quotes the job.
		log.Printf("job %s on worker %s: %v", job.ID, w.ID, err)
	}
	if rerr := c.releaseRunner(job.Runner); rerr != nil {
		log.Printf("job %s: %v", job.ID, rerr)
	}
	c.mu.Lock()
	j := c.state.Jobs[job.ID]
	j.Ended, j.Kept, j.Dropped = time.Now().UTC(), kept, dropped
	switch {
	case j.State == JobCancelled:
	case err != nil:
		j.State, j.Error = JobFailed, err.Error()
	case j.State == JobRunning:
		j.State = JobFinished
	}
	delete(c.busy, w.ID)
	if stop := c.cancels[job.ID]; stop != nil {
		stop()
		delete(c.cancels, job.ID)
	}
	if c.accountJobs[w.Account]--; c.accountJobs[w.Account] <= 0 {
		delete(c.accountJobs, w.Account)
	}
	if serr := c.state.Save(c.cfg.StateDir); serr != nil {
		log.Printf("save state: %v", serr)
	}
	c.mu.Unlock()
	c.followJob(w.ID, job.ThreadID)
	c.poke()
}

// errRunnerFailed is a job the runner ran and failed (exit 1), or couldn't start
// (exit 2). Its events and stderr are kept with the worker for the app to show.
var errRunnerFailed = errors.New("the runner failed the job")

func (c *Coordinator) runJob(ctx context.Context, job Job, w Worker, spec JobSpec) (kept, dropped int, err error) {
	// A job whose index is out of date still runs: its runner indexes what
	// changed in a copy of its own.
	if err := c.refreshIndex(ctx, job, w); err != nil {
		log.Printf("job %s: the index step: %v", job.ID, err)
	}
	root, err := os.MkdirTemp(c.cfg.WorkDir, job.ID+"-")
	if err != nil {
		return 0, 0, err
	}
	defer os.RemoveAll(root)
	dirs := JobDirs{
		Workspace: filepath.Join(root, "workspace"),
		Index:     filepath.Join(root, "index"),
		Data:      filepath.Join(root, "data"),
		JobFile:   filepath.Join(root, "job.json"),
	}
	var given map[string]string
	if err := c.view(w.ID, anyDevice, func(t *Tree) (err error) {
		if given, err = materialize(t, dirs); err != nil {
			return err
		}
		return writeListings(t, dirs.Workspace, given)
	}); err != nil {
		// The detail names the worker's files, which the volume mustn't hold.
		return 0, 0, errors.New("couldn't prepare the job's folder")
	}
	runnerJob, err := spec.runnerJob()
	if err != nil {
		return 0, 0, err
	}
	if dirs.Credentials, err = c.credentials(w, job); err != nil {
		return 0, 0, err
	}
	if err := os.WriteFile(dirs.JobFile, runnerJob, fileMode); err != nil {
		return 0, 0, err
	}

	result, runErr := c.cfg.Runner.Run(ctx, job.Runner, w.Account, dirs)
	c.recordStep(job.ID, jobwire.ModeAgent, result)
	results, collectErr := collect(dirs, given, job.ID)
	if collectErr != nil {
		results = &Results{Writes: map[string][]byte{
			prefixJobs + job.ID + "/collect-error.txt": []byte(collectErr.Error()),
		}}
	}
	if c.cancelled(job.ID) {
		// A cancelled job's outputs and proposals are dropped; its logs are
		// kept.
		results = &Results{Writes: map[string][]byte{}}
	}
	results.Writes[prefixJobs+job.ID+"/events.jsonl"] = result.Events
	if result.Enclave != nil {
		if data, err := json.Marshal(result.Enclave); err == nil {
			results.Writes[prefixJobs+job.ID+"/"+enclaveFile] = data
		}
	}
	if len(result.Stderr) > 0 {
		results.Writes[prefixJobs+job.ID+"/stderr.txt"] = result.Stderr
	}
	// The error isn't logged: it can name the worker's files.
	if err := c.change(w.ID, anyDevice, func(t *Tree) error { return apply(t, results) }); err != nil {
		return 0, 0, errors.New("couldn't keep the job's results")
	}
	kept, dropped = len(results.Writes), len(results.Dropped)
	switch {
	case c.cancelled(job.ID):
		return kept, dropped, nil
	case runErr != nil:
		return kept, dropped, runErr
	case collectErr != nil:
		return kept, dropped, errors.New("couldn't read back the job's results; the reason is kept with the worker")
	case result.ExitCode != 0:
		return kept, dropped, fmt.Errorf("%w (exit %d)", errRunnerFailed, result.ExitCode)
	}
	return kept, dropped, nil
}

// refreshIndex runs the index step (§5.5) in a sandbox of its own when the
// worker's files changed since its kept index was built. It is the only job
// that writes the kept index; the agent's job gets it read-only.
func (c *Coordinator) refreshIndex(ctx context.Context, job Job, w Worker) error {
	root, err := os.MkdirTemp(c.cfg.WorkDir, job.ID+"-index-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	dirs := JobDirs{
		Mode:      jobwire.ModeIndex,
		Workspace: filepath.Join(root, "workspace"),
		Index:     filepath.Join(root, "index"),
		Data:      filepath.Join(root, "data"),
		JobFile:   filepath.Join(root, "job.json"),
	}
	var digest string
	current := false
	if err := c.view(w.ID, anyDevice, func(t *Tree) error {
		digest = rootDigest(t)
		if indexed, err := t.Read(pathIndexed); err == nil && string(indexed) == digest {
			current = true
			return nil
		}
		_, err := materialize(t, dirs)
		return err
	}); err != nil {
		return errors.New("couldn't prepare its folder")
	}
	if current {
		return nil
	}
	if err := os.WriteFile(dirs.JobFile, []byte("{}"), fileMode); err != nil {
		return err
	}
	if dirs.Credentials, err = c.credentials(w, job); err != nil {
		return err
	}
	result, err := c.cfg.Runner.Run(ctx, job.Runner, w.Account, dirs)
	c.recordStep(job.ID, jobwire.ModeIndex, result)
	logs := map[string][]byte{prefixJobs + job.ID + "/index-events.jsonl": result.Events}
	if len(result.Stderr) > 0 {
		logs[prefixJobs+job.ID+"/index-stderr.txt"] = result.Stderr
	}
	results := &Results{Writes: logs}
	switch {
	case err != nil:
	case result.ExitCode != 0:
		err = fmt.Errorf("%w (exit %d)", errRunnerFailed, result.ExitCode)
	default:
		if results, err = collectIndex(dirs); err != nil {
			results, err = &Results{Writes: logs}, errors.New("couldn't read back the index")
			break
		}
		maps.Copy(results.Writes, logs)
		results.Writes[pathIndexed] = []byte(digest)
	}
	if cerr := c.change(w.ID, anyDevice, func(t *Tree) error { return apply(t, results) }); cerr != nil && err == nil {
		err = errors.New("couldn't keep the index")
	}
	return err
}

// recordStep keeps a sandbox's usage on its job; it is metadata, never the
// job's content.
func (c *Coordinator) recordStep(jobID string, mode jobwire.Mode, r RunResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if j := c.state.Jobs[jobID]; j != nil {
		j.Steps = append(j.Steps, StepUsage{Mode: cmp.Or(string(mode), "agent"), Exit: r.ExitCode, Seconds: r.Seconds, PeakMiB: r.PeakBytes >> 20, OOMKills: r.OOMKills})
	}
}

func (c *Coordinator) credentials(w Worker, job Job) (map[string]string, error) {
	if c.cfg.Credentials == nil {
		return nil, nil
	}
	creds, err := c.cfg.Credentials(w.Account, w.ID, job.ID)
	if err != nil {
		return nil, fmt.Errorf("the job's credentials: %w", err)
	}
	return creds, nil
}

// apply stages a job's results. Only the index step's carry an index.
func apply(t *Tree, r *Results) error {
	for p, data := range r.Writes {
		if err := t.Write(p, data); err != nil {
			return err
		}
	}
	if r.Index == nil {
		return nil
	}
	for _, p := range t.List(prefixIndex) {
		if _, ok := r.Index[strings.TrimPrefix(p, prefixIndex)]; !ok {
			t.Remove(p)
		}
	}
	for rel, data := range r.Index {
		if err := t.Write(prefixIndex+rel, data); err != nil {
			return err
		}
	}
	return nil
}

// view opens a worker's tree to read, under its lock so no commit removes an
// object while it is read.
func (c *Coordinator) view(workerID, device string, fn func(*Tree) error) error {
	lock, w, err := c.workerLock(workerID)
	if err != nil {
		return err
	}
	lock.Lock()
	defer lock.Unlock()
	t, err := c.loadTree(w, device)
	if err != nil {
		return err
	}
	return fn(t)
}

// change opens the latest version of a worker's tree, lets fn stage changes,
// commits them and records the new version on the volume. A job's results are
// applied this way, on top of whatever changed while it ran.
func (c *Coordinator) change(workerID, device string, fn func(*Tree) error) error {
	return c.changeThen(workerID, device, fn, nil)
}

// changeThen is change, then runs then once the change is committed, still
// under the tree's lock: a thread operation queues or cancels its jobs there,
// so nothing reads the thread between the two. then must not take the lock.
func (c *Coordinator) changeThen(workerID, device string, fn func(*Tree) error, then func()) error {
	lock, w, err := c.workerLock(workerID)
	if err != nil {
		return err
	}
	lock.Lock()
	defer lock.Unlock()
	t, err := c.loadTree(w, device)
	if err != nil {
		return err
	}
	if err := fn(t); err != nil {
		return err
	}
	version, err := t.Commit()
	if err != nil {
		return err
	}
	c.mu.Lock()
	held, ok := c.state.Workers[workerID]
	switch {
	case !ok:
		err = ErrNoWorker
	case held.Version != version || held.ManifestEpoch != t.ManifestEpoch():
		held.Version, held.ManifestEpoch = version, t.ManifestEpoch()
		err = c.state.Save(c.cfg.StateDir)
	}
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if then != nil {
		then()
	}
	return nil
}

func (c *Coordinator) workerLock(workerID string) (*sync.Mutex, Worker, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	w, ok := c.state.Workers[workerID]
	if !ok {
		return nil, Worker{}, ErrNoWorker
	}
	lock, ok := c.locks[workerID]
	if !ok {
		lock = &sync.Mutex{}
		c.locks[workerID] = lock
	}
	return lock, *w, nil
}

// loadTree takes the worker's version from the volume afresh: the copy in w may
// predate a commit made while its caller waited for the lock. It checks that
// device may still act for the worker, under the tree's lock, which a grant
// takes too: a request that raced a grant removing its device fails here.
func (c *Coordinator) loadTree(w Worker, device string) (*Tree, error) {
	c.mu.Lock()
	held, ok := c.state.Workers[w.ID]
	var version uint64
	var cur Worker
	if ok {
		ok = held.mayAct(device)
		version, cur = held.Version, *held
	}
	c.mu.Unlock()
	switch {
	case !ok:
		// Revoked, or its device removed, while its caller waited for the
		// lock.
		return nil, ErrNoWorker
	case cur.WrappedDEK == nil:
		return nil, ErrNotGranted
	}
	ring, err := c.cfg.Key.Keyring(&cur)
	if err != nil {
		return nil, err
	}
	defer ring.Clear()
	t, err := LoadTreeKeys(c.cfg.Store, w.ID, ring, version)
	if t != nil {
		t.secret = c.treeSecret(w.ID)
	}
	return t, err
}

func newID(prefix string) (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(b[:]), nil
}
