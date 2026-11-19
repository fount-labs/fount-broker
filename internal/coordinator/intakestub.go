package coordinator

// This file stands in for lane C's intake API (fount-broker fleet/C-result,
// 20f943a, internal/coordinator/intake.go), with the same names and
// signatures, so the mail loop is written against it. Delete this file when
// the two branches merge, and keep C's Config.Intake line.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// An IntakeRunner runs fount-runner --mode intake for account on dir. The
// runner leaves its output in dir/out.
type IntakeRunner interface {
	RunIntake(ctx context.Context, account, dir string) (RunResult, error)
}

// IntakeRequest is what intake needs beside the email.
type IntakeRequest struct {
	ReplyHandle string
	ReplyFolder string
}

// IntakeResult is one email's intake, checked.
type IntakeResult struct {
	Spec           IntakeSpec
	Files          map[string][]byte
	Events, Stderr []byte
}

// IntakeSpec is fount-runner's jobspec.json.
type IntakeSpec struct {
	Version           int                `json:"version"`
	ParserVersion     int                `json:"parserVersion"`
	Message           string             `json:"message"`
	Instruction       string             `json:"instruction"`
	InstructionSource string             `json:"instructionSource"`
	Note              string             `json:"note"`
	Reply             bool               `json:"reply"`
	Automatic         string             `json:"automatic,omitempty"`
	Attachments       []IntakeAttachment `json:"attachments"`
	Flags             []string           `json:"flags"`
}

type IntakeAttachment struct {
	Path        string `json:"path"`
	ContentType string `json:"contentType"`
	Size        int64  `json:"size"`
	Inline      bool   `json:"inline"`
}

// ErrIntake is an email intake refused or couldn't read.
var ErrIntake = errors.New("coordinator: intake")

// Intake, in this stand-in, runs the runner on an empty folder and reads only
// out/jobspec.json's instruction and automatic, loosely; the files are the
// raw email alone. C's reads and checks everything intake writes.
func (c *Coordinator) Intake(ctx context.Context, workerID string, m *Mail, req IntakeRequest) (IntakeResult, error) {
	if c.cfg.Intake == nil {
		return IntakeResult{}, fmt.Errorf("%w: no intake runner", ErrIntake)
	}
	w, err := c.Worker(workerID)
	if err != nil {
		return IntakeResult{}, err
	}
	dir, err := os.MkdirTemp(c.cfg.WorkDir, "intake-")
	if err != nil {
		return IntakeResult{}, err
	}
	defer os.RemoveAll(dir)
	run, err := c.cfg.Intake.RunIntake(ctx, w.Account, dir)
	r := IntakeResult{Events: run.Events, Stderr: run.Stderr}
	switch {
	case err != nil:
		return r, err
	case run.ExitCode != 0:
		return r, fmt.Errorf("%w: the runner failed it (exit %d)", ErrIntake, run.ExitCode)
	}
	r.Spec = IntakeSpec{Version: 1, Message: m.EdgeID, Instruction: "Handle the email in this turn's message folder as your instructions say."}
	if data, err := os.ReadFile(filepath.Join(dir, "out", "jobspec.json")); err == nil {
		if err := json.Unmarshal(data, &r.Spec); err != nil {
			return r, fmt.Errorf("%w: %v", ErrIntake, err)
		}
	}
	r.Files = map[string][]byte{"message.eml": m.Raw}
	return r, nil
}

// MessageFolder is an email's folder name in its thread: the day it arrived
// (UTC) and its edge ID.
func MessageFolder(m *Mail) string {
	return time.UnixMilli(m.ReceivedAt).UTC().Format("2006-01-02") + "-" + m.EdgeID
}

// JobSpec is the job for the email on threadID, its folder there folder. C's
// sets JobSpec.Message, which this branch's JobSpec doesn't have, so this one
// names the folder in the instruction.
func (s IntakeSpec) JobSpec(threadID, sessionID, folder string, config json.RawMessage) (JobSpec, error) {
	spec := JobSpec{ThreadID: threadID, SessionID: sessionID, Config: config,
		Instruction: s.Instruction + "\n\nThe email is in threads/" + threadID + "/" + folder + "."}
	return spec, spec.check()
}

// RunIntake runs the command with --mode intake --workspace dir.
func (l LocalRunner) RunIntake(ctx context.Context, _, dir string) (RunResult, error) {
	if len(l.Command) == 0 {
		return RunResult{}, errors.New("no runner command")
	}
	args := append(l.Command[1:len(l.Command):len(l.Command)], "--mode", "intake", "--workspace", dir)
	cmd := exec.CommandContext(ctx, l.Command[0], args...)
	out, err := cmd.Output()
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		return RunResult{Events: out, ExitCode: exit.ExitCode()}, nil
	case err != nil:
		return RunResult{}, fmt.Errorf("start the intake runner: %w", err)
	}
	return RunResult{Events: out}, nil
}

var _ IntakeRunner = LocalRunner{}
