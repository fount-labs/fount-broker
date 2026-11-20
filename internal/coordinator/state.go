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
	// Teams are the teams' membership logs (teamlog.go), and SecuritySeq
	// counts the changes to them (commitSecurity).
	Teams       map[string]*Team `json:"teams,omitempty"`
	SecuritySeq uint64           `json:"securitySeq,omitempty"`
	// TeamMints are firm teams' ids the coordinator made (MintTeam) whose
	// first list hasn't been appended yet, each with the account it was made
	// for: one at a time per account.
	TeamMints map[string]string `json:"teamMints,omitempty"`
	// Releases are deleted workers' edge mailboxes (hex) still to remove
	// at the edge (release.go).
	Releases []string `json:"releases,omitempty"`
	// Restored is set on a volume a backup was restored onto (restore.go).
	Restored *RestoreMark `json:"restored,omitempty"`
}

type Worker struct {
	ID      string `json:"id"`
	Account string `json:"account"`
	// WrappedDEK is nil for a worker made over the client channel until its
	// DEK is granted (grant.go).
	WrappedDEK []byte    `json:"wrappedDek"`
	Version    uint64    `json:"version"`
	Created    time.Time `json:"created"`
	// Team is the team whose log decides who may act for the worker, empty
	// until a list adds it; a team worker's Account is its team. Devices may
	// act for it over the client channel, derived from that log (members.go),
	// and DEKCommitment is the one the list signed, which a device opening
	// its wrap checks. A worker the dev API made has none.
	Team          string   `json:"team,omitempty"`
	Devices       []Device `json:"devices,omitempty"`
	DEKCommitment string   `json:"dekCommitment,omitempty"`
	// Mailbox is the worker's mailbox id at the edge, once it has an
	// address, so the mail loop knows to read it (mailbox.go). Its keys are
	// in the worker's tree.
	Mailbox string `json:"mailbox,omitempty"`
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
	// JobCancelled is a job a thread operation stopped. A running one keeps
	// its worker busy until its runner stops.
	JobCancelled JobState = "cancelled"
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
	// Steps is what each sandbox the job ran took: the index step, if it ran,
	// then the agent. It sizes the pool (m4-cloud-runners.md §5.2a).
	Steps []StepUsage `json:"steps,omitempty"`
}

// StepUsage is one sandbox's run, as its runner reported it.
type StepUsage struct {
	Mode     string  `json:"mode"`
	Exit     int     `json:"exit"`
	Seconds  float64 `json:"seconds"`
	PeakMiB  int64   `json:"peakMiB"`
	OOMKills int64   `json:"oomKills,omitempty"`
}

func statePath(dir string) string { return filepath.Join(dir, "state.json") }

// LoadState reads the volume's state, or starts empty. A job that was running
// when the coordinator stopped is failed, not run again: it may have sent mail.
func LoadState(dir string) (*State, error) {
	s := &State{Workers: map[string]*Worker{}, Jobs: map[string]*Job{}, Teams: map[string]*Team{}, TeamMints: map[string]string{}}
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
	if s.Teams == nil {
		s.Teams = map[string]*Team{}
	}
	if s.TeamMints == nil {
		s.TeamMints = map[string]string{}
	}
	for _, j := range s.Jobs {
		switch {
		case j.State == JobRunning:
			j.State = JobFailed
			j.Error = "the coordinator restarted while this job ran"
			j.Ended = time.Now().UTC()
		case j.State == JobCancelled && j.Ended.IsZero():
			// Cancelled while it ran, and never seen to stop.
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
