package coordinator

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// State is what the coordinator keeps on its encrypted volume: which workers it
// holds, their wrapped DEKs, the last manifest version committed for each, and
// the job queue (fount-cloud-agents.md §4.2). It holds no user content: job
// specs are kept only until the job starts.
//
// One JSON file, rewritten whole on each change, is enough for a skeleton. It
// moves to SQLite on the volume when the queue grows.
type State struct {
	Workers map[string]*Worker `json:"workers"`
	Jobs    map[string]*Job    `json:"jobs"`
	// Seq orders jobs, so the queue is first in, first out.
	Seq uint64 `json:"seq"`
}

type Worker struct {
	ID         string    `json:"id"`
	Account    string    `json:"account"`
	WrappedDEK []byte    `json:"wrappedDek"`
	Version    uint64    `json:"version"`
	Created    time.Time `json:"created"`
}

type JobState string

const (
	JobQueued  JobState = "queued"
	JobRunning JobState = "running"
	// JobFinished is a runner that exited 0: ready for review or waiting for an
	// answer. Telling those apart means reading the runner's events, which the
	// coordinator keeps but doesn't parse yet.
	JobFinished JobState = "finished"
	JobFailed   JobState = "failed"
)

type Job struct {
	ID       string   `json:"id"`
	WorkerID string   `json:"workerId"`
	Seq      uint64   `json:"seq"`
	State    JobState `json:"state"`
	// Spec is dropped once the job starts; the instruction is user content.
	Spec     *JobSpec  `json:"spec,omitempty"`
	ThreadID string    `json:"threadId"`
	Runner   string    `json:"runner,omitempty"`
	Error    string    `json:"error,omitempty"`
	Queued   time.Time `json:"queued"`
	Started  time.Time `json:"started,omitzero"`
	Ended    time.Time `json:"ended,omitzero"`
	// Kept counts what the job's results added to the worker's tree, and
	// Dropped what the runner wrote where a job may not.
	Kept    int `json:"kept,omitempty"`
	Dropped int `json:"dropped,omitempty"`
}

func statePath(dir string) string { return filepath.Join(dir, "state.json") }

// LoadState reads the volume's state, or starts empty. A job that was running
// when the coordinator stopped is failed, not run again: it may have sent mail.
func LoadState(dir string) (*State, error) {
	s := &State{Workers: map[string]*Worker{}, Jobs: map[string]*Job{}}
	data, err := os.ReadFile(statePath(dir))
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("%s: %w", statePath(dir), err)
	}
	if s.Workers == nil {
		s.Workers = map[string]*Worker{}
	}
	if s.Jobs == nil {
		s.Jobs = map[string]*Job{}
	}
	for _, j := range s.Jobs {
		if j.State == JobRunning {
			j.State = JobFailed
			j.Error = "the coordinator restarted while this job ran"
			j.Ended = time.Now().UTC()
		}
	}
	return s, nil
}

func (s *State) Save(dir string) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return writeFileAtomic(statePath(dir), data)
}
