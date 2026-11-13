// Package coordinator is Fount Cloud's coordinator (m4-cloud-runners.md, in the
// Fount repo's docs/features/fount-fleet). It holds each Cloud worker's data key
// and files, queues jobs, and hands each to a runner in a folder it prepares,
// then keeps what the job may change. It never parses user content: files and
// runner output are opaque bytes to it, and a JobSpec is the only request body
// it reads.
//
// This is the P2 skeleton. It runs on a laptop with a local folder for storage
// and a command per runner. Not built yet: attestation and the client channel,
// the vault-held wrapping key, the buckets sidecar, mail intake, runner enclaves
// and their IPC, inference relay, and the thread record.
package coordinator

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
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
}

type Coordinator struct {
	cfg Config

	mu    sync.Mutex
	state *State
	// busy is the workers with a running job: a worker runs one job at a time
	// (fount-mail.md decision 51).
	busy map[string]bool
	// locks serialize changes to each worker's tree.
	locks map[string]*sync.Mutex
	wake  chan struct{}
	// running counts jobs started and not yet ended, for Wait.
	running sync.WaitGroup
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
	c := &Coordinator{cfg: cfg, state: state, busy: map[string]bool{}, locks: map[string]*sync.Mutex{}, wake: make(chan struct{}, 1)}
	if err := c.state.Save(cfg.StateDir); err != nil {
		return nil, err
	}
	return c, nil
}

var (
	ErrNoWorker = errors.New("no such worker")
	ErrNoJob    = errors.New("no such job")
	// ErrWriteOnce is a write over a thread file: what was received never
	// changes, so a citation always opens the same bytes (§5.5).
	ErrWriteOnce = errors.New("thread files are written once")
	ErrReserved  = errors.New("the path is reserved")
)

// CreateWorker takes a worker into the coordinator. dek is the key Desktop sends
// when it moves a worker (§3.1, step 4); nil makes a new one.
func (c *Coordinator) CreateWorker(account string, dek *DEK) (Worker, error) {
	if err := checkID("account", account); err != nil {
		return Worker{}, err
	}
	key := DEK{}
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
	w := &Worker{ID: id, Account: account, WrappedDEK: wrapped, Created: time.Now().UTC()}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state.Workers[id] = w
	if err := c.state.Save(c.cfg.StateDir); err != nil {
		delete(c.state.Workers, id)
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

// PutFile writes a file into a worker's root: instructions, memory, a file the
// user sends, or (until intake runners exist) a thread's message.
func (c *Coordinator) PutFile(workerID, path string, data []byte) error {
	if err := checkPath(path); err != nil {
		return err
	}
	if path == fountDir || strings.HasPrefix(path, fountDir+"/") {
		return fmt.Errorf("%s: %w", path, ErrReserved)
	}
	return c.change(workerID, func(t *Tree) error {
		if strings.HasPrefix(path, "threads/") && t.Has(prefixRoot+path) {
			return fmt.Errorf("%s: %w", path, ErrWriteOnce)
		}
		return t.Write(prefixRoot+path, data)
	})
}

// ReadFile reads a path from a worker's whole tree, "root/…" included.
func (c *Coordinator) ReadFile(workerID, path string) ([]byte, error) {
	var data []byte
	err := c.view(workerID, func(t *Tree) (err error) {
		data, err = t.Read(path)
		return err
	})
	return data, err
}

func (c *Coordinator) ListFiles(workerID, prefix string) ([]string, error) {
	var paths []string
	err := c.view(workerID, func(t *Tree) error {
		paths = t.List(prefix)
		return nil
	})
	return paths, err
}

// Enqueue queues a job on a worker's thread.
func (c *Coordinator) Enqueue(workerID string, spec JobSpec) (Job, error) {
	if err := spec.check(); err != nil {
		return Job{}, err
	}
	id, err := newID("j")
	if err != nil {
		return Job{}, err
	}
	c.mu.Lock()
	if _, ok := c.state.Workers[workerID]; !ok {
		c.mu.Unlock()
		return Job{}, ErrNoWorker
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
	c.poke()
	return out, nil
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
		}
	}
}

// schedule starts every queued job that can start, oldest first: its worker has
// no running job and its account can get a runner slot.
func (c *Coordinator) schedule(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var queued []*Job
	for _, j := range c.state.Jobs {
		if j.State == JobQueued {
			queued = append(queued, j)
		}
	}
	slices.SortFunc(queued, func(a, b *Job) int { return cmp.Compare(a.Seq, b.Seq) })
	for _, j := range queued {
		w := c.state.Workers[j.WorkerID]
		if c.busy[j.WorkerID] {
			continue
		}
		runner, ok := c.cfg.Pool.Acquire(w.Account)
		if !ok {
			continue
		}
		spec := *j.Spec
		j.Spec, j.State, j.Runner, j.Started = nil, JobRunning, runner, time.Now().UTC()
		if err := c.state.Save(c.cfg.StateDir); err != nil {
			log.Printf("save state: %v", err)
		}
		c.busy[j.WorkerID] = true
		c.running.Add(1)
		go c.execute(ctx, *j, *w, spec)
	}
}

func (c *Coordinator) execute(ctx context.Context, job Job, w Worker, spec JobSpec) {
	defer c.running.Done()
	kept, dropped, err := c.runJob(ctx, job, w, spec)
	if err != nil {
		// The error goes on the volume, outside the DEK, so it says what failed
		// and never quotes the job.
		log.Printf("job %s on worker %s: %v", job.ID, w.ID, err)
	}
	if rerr := c.cfg.Pool.Release(job.Runner); rerr != nil {
		log.Printf("job %s: %v", job.ID, rerr)
	}
	c.mu.Lock()
	j := c.state.Jobs[job.ID]
	j.Ended, j.Kept, j.Dropped = time.Now().UTC(), kept, dropped
	switch {
	case err != nil:
		j.State, j.Error = JobFailed, err.Error()
	case j.State == JobRunning:
		j.State = JobFinished
	}
	delete(c.busy, w.ID)
	if serr := c.state.Save(c.cfg.StateDir); serr != nil {
		log.Printf("save state: %v", serr)
	}
	c.mu.Unlock()
	c.poke()
}

// errRunnerFailed is a job the runner ran and failed (exit 1), or couldn't start
// (exit 2). Its events and stderr are kept with the worker for the app to show.
var errRunnerFailed = errors.New("the runner failed the job")

func (c *Coordinator) runJob(ctx context.Context, job Job, w Worker, spec JobSpec) (kept, dropped int, err error) {
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
	if err := c.view(w.ID, func(t *Tree) (err error) {
		given, err = materialize(t, dirs)
		return err
	}); err != nil {
		// The detail names the worker's files, which the volume mustn't hold.
		return 0, 0, errors.New("couldn't prepare the job's folder")
	}
	// The empty folder is how the job learns where its outputs go.
	if err := os.MkdirAll(filepath.Join(dirs.Workspace, "threads", job.ThreadID, "outputs", job.ID), dirMode); err != nil {
		return 0, 0, err
	}
	runnerJob, err := spec.runnerJob()
	if err != nil {
		return 0, 0, err
	}
	if err := os.WriteFile(dirs.JobFile, runnerJob, fileMode); err != nil {
		return 0, 0, err
	}

	result, runErr := c.cfg.Runner.Run(ctx, job.Runner, dirs)
	results, collectErr := collect(dirs, given, job.ThreadID, job.ID)
	if collectErr != nil {
		results = &Results{Writes: map[string][]byte{
			prefixJobs + job.ID + "/collect-error.txt": []byte(collectErr.Error()),
		}}
	}
	results.Writes[prefixJobs+job.ID+"/events.jsonl"] = result.Events
	if len(result.Stderr) > 0 {
		results.Writes[prefixJobs+job.ID+"/stderr.txt"] = result.Stderr
	}
	// The error isn't logged: it can name the worker's files.
	if err := c.change(w.ID, func(t *Tree) error { return apply(t, results) }); err != nil {
		return 0, 0, errors.New("couldn't keep the job's results")
	}
	kept, dropped = len(results.Writes), len(results.Dropped)
	switch {
	case runErr != nil:
		return kept, dropped, runErr
	case collectErr != nil:
		return kept, dropped, errors.New("couldn't read back the job's results; the reason is kept with the worker")
	case result.ExitCode != 0:
		return kept, dropped, fmt.Errorf("%w (exit %d)", errRunnerFailed, result.ExitCode)
	}
	return kept, dropped, nil
}

// apply stages a job's results. A collect that failed keeps no index, so the
// kept one stays.
func apply(t *Tree, r *Results) error {
	for p, data := range r.Writes {
		if err := t.Write(p, data); err != nil {
			return err
		}
	}
	if len(r.Index) == 0 {
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
func (c *Coordinator) view(workerID string, fn func(*Tree) error) error {
	lock, w, err := c.workerLock(workerID)
	if err != nil {
		return err
	}
	lock.Lock()
	defer lock.Unlock()
	t, err := c.loadTree(w)
	if err != nil {
		return err
	}
	return fn(t)
}

// change opens the latest version of a worker's tree, lets fn stage changes,
// commits them and records the new version on the volume. A job's results are
// applied this way, on top of whatever changed while it ran.
func (c *Coordinator) change(workerID string, fn func(*Tree) error) error {
	lock, w, err := c.workerLock(workerID)
	if err != nil {
		return err
	}
	lock.Lock()
	defer lock.Unlock()
	t, err := c.loadTree(w)
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
	defer c.mu.Unlock()
	c.state.Workers[workerID].Version = version
	return c.state.Save(c.cfg.StateDir)
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
// predate a commit made while its caller waited for the lock.
func (c *Coordinator) loadTree(w Worker) (*Tree, error) {
	c.mu.Lock()
	version := c.state.Workers[w.ID].Version
	c.mu.Unlock()
	dek, err := c.cfg.Key.Unwrap(w.ID, w.WrappedDEK)
	if err != nil {
		return nil, err
	}
	return LoadTree(c.cfg.Store, w.ID, dek, version)
}

func newID(prefix string) (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(b[:]), nil
}
