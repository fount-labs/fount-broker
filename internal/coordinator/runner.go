package coordinator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/fount-labs/fount-broker/internal/jobwire"
)

// A Runner runs one job, for account, in folders the coordinator prepared and
// reads back after (m4-cloud-runners.md §5.1). Everything it leaves there is
// treated as hostile.
type Runner interface {
	Run(ctx context.Context, runnerID, account string, job JobDirs) (RunResult, error)
}

// JobDirs are the folders of one job, in fount-runner's terms.
type JobDirs struct {
	// Mode is an agent job or the index step (jobwire.Mode).
	Mode jobwire.Mode
	// Workspace is the worker root (§5.5): --workspace.
	Workspace string
	// Index is the worker's kept index: --index-read-only for an agent job,
	// which never hands it back, and --index for the index step, the only one
	// that writes it.
	Index string
	// Data is the runner's own scratch state: --data. Nothing in it is kept.
	Data string
	// JobFile is the runner's job spec: --job.
	JobFile string
	// Credentials are the job's, for a runner enclave's broker to hold. They
	// are never written to the job's folders.
	Credentials map[string]string
}

type RunResult struct {
	// ExitCode is fount-runner's: 0 for ready for review or waiting for an
	// answer, 1 for a failed job, 2 for a runner that couldn't start it.
	ExitCode int
	// Events is the runner's stdout, JSON lines, kept unread.
	Events []byte
	Stderr []byte
	// Seconds, PeakBytes and OOMKills are the sandbox's, as a runner enclave's
	// supervisor reports them; a local runner leaves them zero.
	Seconds   float64
	PeakBytes int64
	OOMKills  int64
	// Enclave is where a runner enclave that dialled in ran it; nil for a
	// local runner or one the coordinator dialled.
	Enclave *RunnerEnclave
}

const (
	maxEventBytes  = 8 << 20
	maxStderrBytes = 1 << 20
)

// LocalRunner runs a command per job, with fount-runner's folder flags added:
// fount-runner itself, or a script that starts the runner image in Docker. It
// has no pool of enclaves, so it holds nothing between jobs.
type LocalRunner struct {
	Command []string
	Timeout time.Duration
}

func (l LocalRunner) Run(ctx context.Context, _, _ string, job JobDirs) (RunResult, error) {
	if len(l.Command) == 0 {
		return RunResult{}, errors.New("no runner command")
	}
	if l.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, l.Timeout)
		defer cancel()
	}
	args := append(l.Command[1:len(l.Command):len(l.Command)], "--workspace", job.Workspace, "--data", job.Data)
	if job.Mode == jobwire.ModeIndex {
		args = append(args, "--mode", "index", "--index", job.Index)
	} else {
		args = append(args, "--job", job.JobFile, "--index-read-only", job.Index)
	}
	cmd := exec.CommandContext(ctx, l.Command[0], args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	stdout := &capped{max: maxEventBytes}
	stderr := &capped{max: maxStderrBytes}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	result := RunResult{Events: stdout.Bytes(), Stderr: stderr.Bytes()}
	var exit *exec.ExitError
	switch {
	case err == nil:
	case ctx.Err() != nil:
		return result, fmt.Errorf("runner stopped: %w", ctx.Err())
	case errors.As(err, &exit):
		result.ExitCode = exit.ExitCode()
	default:
		return result, fmt.Errorf("start the runner: %w", err)
	}
	return result, nil
}

// capped keeps the first max bytes written and drops the rest, so a runner
// can't fill the coordinator's memory through its output.
type capped struct {
	bytes.Buffer
	max       int
	truncated bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.Len(); room < len(p) {
		c.truncated = true
		if room > 0 {
			c.Buffer.Write(p[:room])
		}
		return len(p), nil
	}
	return c.Buffer.Write(p)
}

func (c *capped) Bytes() []byte {
	if c.truncated {
		return append(c.Buffer.Bytes(), []byte("\n(truncated)\n")...)
	}
	return c.Buffer.Bytes()
}

var _ io.Writer = (*capped)(nil)
