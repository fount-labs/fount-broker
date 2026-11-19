package coordinator

import (
	"cmp"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
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
	// Addr is the runner broker's origin, https://<domain> for an enclave,
	// where the link is an upgrade on link.Path. A bare host:port is a plain
	// TCP listener: tests only.
	Addr string
	// Link is the coordinator's end. Nil dials plain TCP: tests only.
	Link    *link.Side
	Timeout time.Duration
	Limits  filetree.Limits
}

func (r RemoteRunner) Run(ctx context.Context, _, account string, job JobDirs) (RunResult, error) {
	jobFile, err := os.ReadFile(job.JobFile)
	if err != nil {
		return RunResult{}, err
	}
	// The tree the job hands back replaces what the coordinator put there, so
	// a file the job deleted stays deleted.
	back := job.Workspace
	if job.Mode == jobwire.ModeIndex {
		back = job.Index
	}
	return r.run(ctx, wireJob{
		header:  jobwire.Job{Kind: jobwire.KindJob, Mode: job.Mode, Account: account, Credentials: job.Credentials},
		jobFile: jobFile,
		send:    map[jobwire.Kind]string{jobwire.KindWorkspace: job.Workspace, jobwire.KindIndex: job.Index},
		back:    back,
	})
}

// RunIntake sends the intake folder dir to a runner enclave as an intake job,
// which holds no credentials and no index, and puts what comes back in
// dir/out. The tree back is held to intake's own caps, and ReadIntake checks
// it after.
func (r RemoteRunner) RunIntake(ctx context.Context, account, dir string) (RunResult, error) {
	out := filepath.Join(dir, intakeOut)
	if _, err := os.Lstat(out); err == nil {
		return RunResult{}, fmt.Errorf("%w: %s is there before intake ran", ErrIntake, intakeOut)
	}
	return r.run(ctx, wireJob{
		header: jobwire.Job{Kind: jobwire.KindJob, Mode: jobwire.ModeIntake, Account: account},
		send:   map[jobwire.Kind]string{jobwire.KindWorkspace: dir},
		back:   out,
		backLimits: tighter(r.Limits, filetree.Limits{
			MaxBytes:     maxIntakeTotalBytes,
			MaxFileBytes: maxIntakeTotalBytes,
			// The files ReadIntake allows, and the attachments/ folder.
			MaxEntries: maxIntakeAttachments + 4,
		}),
		strict: true,
	})
}

// tighter is the smaller of each of a's and b's caps; a zero takes the other.
func tighter(a, b filetree.Limits) *filetree.Limits {
	pick := func(x, y int64) int64 {
		if x == 0 || (y != 0 && y < x) {
			return y
		}
		return x
	}
	return &filetree.Limits{
		MaxBytes:     pick(a.MaxBytes, b.MaxBytes),
		MaxFileBytes: pick(a.MaxFileBytes, b.MaxFileBytes),
		MaxEntries:   int(pick(int64(a.MaxEntries), int64(b.MaxEntries))),
	}
}

// wireJob is one job as it crosses the wire.
type wireJob struct {
	header  jobwire.Job
	jobFile []byte
	// send is the folder of each tree the mode streams in.
	send map[jobwire.Kind]string
	// back is emptied and filled with the tree the job hands back.
	back string
	// backLimits, if set, caps the tree back in place of RemoteRunner.Limits.
	backLimits *filetree.Limits
	// strict refuses a tree back with anything but folders and files in it.
	strict bool
}

func (r RemoteRunner) run(ctx context.Context, job wireJob) (RunResult, error) {
	if r.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
	}
	var conn net.Conn
	var err error
	if strings.Contains(r.Addr, "://") {
		conn, err = link.Dial(ctx, r.Addr)
	} else {
		var d net.Dialer
		conn, err = d.DialContext(ctx, "tcp", r.Addr)
	}
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

	result, err := r.exchange(conn, job)
	if ctx.Err() != nil {
		return result, fmt.Errorf("runner stopped: %w", ctx.Err())
	}
	return result, err
}

func (r RemoteRunner) exchange(conn net.Conn, job wireJob) (result RunResult, err error) {
	w := frame.NewWriter(conn)
	mode := job.header.Mode
	sendErr := func() error {
		if err := jobwire.Send(w, job.header, job.jobFile); err != nil {
			return err
		}
		for _, kind := range mode.Sends() {
			out := jobwire.Chunks{W: w, Kind: kind}
			if err := filetree.Pack(job.send[kind], out, r.Limits); err != nil {
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
			result.Seconds, result.PeakBytes, result.OOMKills = reply.Seconds, reply.PeakBytes, reply.OOMKills
			log.Printf("runner: %s job for %s: exit %d in %.1fs, peak %d MiB, %d OOM kills",
				cmp.Or(string(mode), "agent"), job.header.Account, reply.ExitCode, reply.Seconds, reply.PeakBytes>>20, reply.OOMKills)
			kind := mode.Returns()
			if err := emptyDir(job.back); err != nil {
				return result, err
			}
			lim := r.Limits
			if job.backLimits != nil {
				lim = *job.backLimits
			}
			in := &jobwire.Stream{R: conn, Kind: kind}
			skipped, err := filetree.Extract(in, job.back, lim, nil)
			if err == nil && job.strict && skipped > 0 {
				err = fmt.Errorf("it holds %d links or other non-files", skipped)
			}
			if err != nil {
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

var (
	_ Runner       = RemoteRunner{}
	_ IntakeRunner = RemoteRunner{}
)
