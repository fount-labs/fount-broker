package coordinator

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/fount-labs/fount-broker/internal/filetree"
	"github.com/fount-labs/fount-broker/internal/frame"
	"github.com/fount-labs/fount-broker/internal/jobwire"
	"github.com/fount-labs/fount-broker/internal/link"
)

// RemoteRunner sends each job to a runner enclave's broker, which relays it to
// the supervisor's sandbox and keeps the job's credentials for its broker socket
// (m4-cloud-runners.md §5.1c). The job's workspace and index travel with it and
// come back once its sandbox is gone; the data folder stays behind.
//
// The connection is the attested link (package link): the runner proves its
// release before the job is sent, and the coordinator proves its own.
type RemoteRunner struct {
	// Addr is the runner broker's job listener.
	Addr string
	// Link is the coordinator's end. Nil dials plain TCP: tests only.
	Link    *link.Side
	Timeout time.Duration
	Limits  filetree.Limits
}

func (r RemoteRunner) Run(ctx context.Context, _, account string, job JobDirs) (RunResult, error) {
	if r.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", r.Addr)
	if err != nil {
		return RunResult{}, fmt.Errorf("reach the runner: %w", err)
	}
	defer conn.Close()
	if r.Link != nil {
		tc, err := r.Link.Client(ctx, conn)
		if err != nil {
			return RunResult{}, fmt.Errorf("the runner's link: %w", err)
		}
		conn = tc
	}
	// Closing the connection is how a job is cancelled.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	result, err := r.exchange(conn, account, job)
	if ctx.Err() != nil {
		return result, fmt.Errorf("runner stopped: %w", ctx.Err())
	}
	return result, err
}

func (r RemoteRunner) exchange(conn net.Conn, account string, job JobDirs) (result RunResult, err error) {
	w := frame.NewWriter(conn)
	jobFile, err := os.ReadFile(job.JobFile)
	if err != nil {
		return result, err
	}
	sendErr := func() error {
		if err := jobwire.Send(w, jobwire.Job{Kind: jobwire.KindJob, Mode: job.Mode, Account: account, Credentials: job.Credentials}, jobFile); err != nil {
			return err
		}
		for _, t := range []struct {
			dir  string
			kind jobwire.Kind
		}{{job.Workspace, jobwire.KindWorkspace}, {job.Index, jobwire.KindIndex}} {
			out := jobwire.Chunks{W: w, Kind: t.kind}
			if err := filetree.Pack(t.dir, out, r.Limits); err != nil {
				return err
			}
			if err := out.Close(); err != nil {
				return err
			}
		}
		return nil
	}()
	// A runner that refused the job may have closed before reading it all; its
	// reason is in the first frame back.

	stdout := &capped{max: maxEventBytes}
	stderr := &capped{max: maxStderrBytes}
	defer func() { result.Events, result.Stderr = stdout.Bytes(), stderr.Bytes() }()
	for {
		f, err := frame.Read(conn)
		if err != nil {
			if sendErr != nil {
				return result, fmt.Errorf("send the job: %w", sendErr)
			}
			return result, fmt.Errorf("the runner's reply: %w", err)
		}
		reply, err := jobwire.DecodeReply(f.Header)
		if err != nil {
			return result, err
		}
		switch reply.Kind {
		case jobwire.KindStdout:
			stdout.Write(f.Body)
		case jobwire.KindStderr:
			stderr.Write(f.Body)
		case jobwire.KindError:
			return result, fmt.Errorf("runner: %w", reply.Err())
		case jobwire.KindExit:
			result.ExitCode = reply.ExitCode
			// The tree the job hands back replaces what the coordinator put
			// there, so a file the job deleted stays deleted.
			kind, dir := job.Mode.Returns(), job.Workspace
			if job.Mode == jobwire.ModeIndex {
				dir = job.Index
			}
			if err := emptyDir(dir); err != nil {
				return result, err
			}
			in := &jobwire.Stream{R: conn, Kind: kind}
			if _, err := filetree.Extract(in, dir, r.Limits, nil); err != nil {
				return result, fmt.Errorf("the job's %s: %w", kind, err)
			}
			if err := in.Drain(); err != nil {
				return result, fmt.Errorf("the job's %s: %w", kind, err)
			}
		case jobwire.KindEnd:
			return result, nil
		default:
			return result, fmt.Errorf("runner sent %q out of turn", reply.Kind)
		}
	}
}

func emptyDir(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	return os.Mkdir(dir, dirMode)
}

var _ Runner = RemoteRunner{}
