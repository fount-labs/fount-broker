package coordinator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// A JobSpec asks for one job on one worker's thread. It is one of the
// coordinator's few parse surfaces (fount-cloud-agents.md §4.2): it comes from a
// client or an intake runner, is bounded, and is refused whole if anything in it
// is unknown or out of range.
type JobSpec struct {
	ThreadID  string `json:"threadId"`
	SessionID string `json:"sessionId"`
	// Instruction is the turn's instruction: the owner's note or the worker's
	// standing instructions. Mail is never pasted in here; the runner reads it
	// from the thread's folder as data (m4-cloud-runners.md §5.5).
	Instruction string `json:"instruction"`
	// Config is the model settings, passed to the runner unread.
	Config json.RawMessage `json:"config"`
	// Script stands in for the model in scripted jobs, which only debug and
	// release-scripted runners accept. Passed to the runner unread.
	Script json.RawMessage `json:"script,omitempty"`
}

const (
	MaxJobSpecBytes = 256 << 10
	maxInstruction  = 64 << 10
	maxConfigBytes  = 16 << 10
	maxScriptBytes  = 160 << 10
)

// ParseJobSpec reads and checks a JobSpec, failing closed.
func ParseJobSpec(r io.Reader) (JobSpec, error) {
	var spec JobSpec
	body, err := io.ReadAll(io.LimitReader(r, MaxJobSpecBytes+1))
	if err != nil {
		return spec, err
	}
	if len(body) > MaxJobSpecBytes {
		return spec, fmt.Errorf("job spec is over %d bytes", MaxJobSpecBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		return spec, fmt.Errorf("job spec: %w", err)
	}
	if dec.More() {
		return spec, errors.New("job spec: trailing data after the object")
	}
	return spec, spec.check()
}

func (s JobSpec) check() error {
	if err := checkID("thread", s.ThreadID); err != nil {
		return err
	}
	if err := checkID("session", s.SessionID); err != nil {
		return err
	}
	if s.Instruction == "" || len(s.Instruction) > maxInstruction {
		return fmt.Errorf("%w: instruction must be 1 to %d bytes", ErrInvalid, maxInstruction)
	}
	if len(s.Config) == 0 || s.Config[0] != '{' || len(s.Config) > maxConfigBytes {
		return fmt.Errorf("%w: config must be an object of at most %d bytes", ErrInvalid, maxConfigBytes)
	}
	if len(s.Script) > 0 && (s.Script[0] != '[' || len(s.Script) > maxScriptBytes) {
		return fmt.Errorf("%w: script must be an array of at most %d bytes", ErrInvalid, maxScriptBytes)
	}
	return nil
}

// runnerJob is the job file fount-runner reads (its JobSpec in main.rs). The
// workspace is given on its command line, never here.
type runnerJob struct {
	SessionID string          `json:"sessionId"`
	Prompt    string          `json:"prompt"`
	Config    json.RawMessage `json:"config"`
	Script    json.RawMessage `json:"script,omitempty"`
}

func (s JobSpec) runnerJob() ([]byte, error) {
	return json.Marshal(runnerJob{SessionID: s.SessionID, Prompt: s.Instruction, Config: s.Config, Script: s.Script})
}
