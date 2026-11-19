package supervisor

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fount-labs/fount-broker/internal/filetree"
	"github.com/fount-labs/fount-broker/internal/frame"
	"github.com/fount-labs/fount-broker/internal/jobwire"
)

// Sandboxes runs one job; *Supervisor is the real one.
type Sandboxes interface {
	Run(ctx context.Context, job Job, stdout, stderr io.Writer) (Result, error)
}

// Server takes jobs from the runner enclave's broker on a Unix socket, one per
// connection (package jobwire). Each job's folders are made from the streams it
// arrives with, shared into its sandbox, sent back once the sandbox is gone, and
// removed.
type Server struct {
	Sandboxes Sandboxes
	// JobsDir is tmpfs. Each job's folders are made in JobsDir/<id>.
	JobsDir string
	// Sockets is the volume shared with the broker. A job's broker socket is
	// in Sockets/<id>/, which the broker makes before it relays the job.
	Sockets string
	// Account, when set, is a dedicated runner's account, from the measured
	// config: any other account's job is refused.
	Account string
	MaxJobs int
	// Timeout is the longest a job's sandbox may run.
	Timeout time.Duration
	// Limits caps each tree in both directions.
	Limits filetree.Limits
	// Owner is the sandbox's user, who owns each job's folders. Nil leaves them
	// to the supervisor's own user.
	Owner *filetree.Owner

	once  sync.Once
	slots chan struct{}
}

// How long the broker has to hand over a job's first frame, and then its
// folders.
const (
	headerTimeout = 30 * time.Second
	uploadTimeout = 10 * time.Minute
)

// Serve takes jobs from l until ctx ends, then waits for those running.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	s.once.Do(func() { s.slots = make(chan struct{}, max(s.MaxJobs, 1)) })
	var wg sync.WaitGroup
	defer wg.Wait()
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Go(func() {
			defer conn.Close()
			s.handle(ctx, conn)
		})
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	w := frame.NewWriter(conn)
	fail := func(err error) {
		jobwire.Send(w, jobwire.Reply{Kind: jobwire.KindError, Message: err.Error()}, nil)
	}
	conn.SetReadDeadline(time.Now().Add(headerTimeout))
	first, err := frame.Read(conn)
	if err != nil {
		return
	}
	job, err := jobwire.DecodeJob(first, jobwire.FromBroker)
	if err != nil {
		fail(err)
		return
	}
	if s.Account != "" && job.Account != s.Account {
		fail(errors.New("this runner serves one account, and it isn't this job's"))
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		fail(fmt.Errorf("the runner is running its %d jobs", cap(s.slots)))
		return
	}

	dirs, err := s.prepare(conn, job, first.Body)
	defer os.RemoveAll(filepath.Join(s.JobsDir, job.ID))
	if err != nil {
		fail(err)
		return
	}

	// The broker sends nothing more, so a read that returns is the connection
	// closing: the coordinator cancelled the job.
	runCtx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	go func() {
		conn.Read(make([]byte, 1))
		cancel()
	}()
	res, runErr := s.Sandboxes.Run(runCtx, dirs,
		jobwire.Chunks{W: w, Kind: jobwire.KindStdout}, jobwire.Chunks{W: w, Kind: jobwire.KindStderr})
	log.Printf("job %s: exit %d in %.1fs, peak %d MiB, %d OOM kills, err %v",
		job.ID, res.ExitCode, res.Duration.Seconds(), res.PeakBytes>>20, res.OOMKills, runErr)
	if err := jobwire.Send(w, jobwire.Reply{Kind: jobwire.KindExit, ExitCode: res.ExitCode,
		Seconds: res.Duration.Seconds(), PeakBytes: res.PeakBytes, OOMKills: res.OOMKills}, nil); err != nil {
		return
	}
	// The job's tree goes back even when it failed or was stopped, as a local
	// runner's would, so its transcript isn't lost. An agent job's index never
	// does.
	back := jobwire.Chunks{W: w, Kind: job.Mode.Returns()}
	if err := s.sendBack(dirs, back); err != nil {
		fail(fmt.Errorf("send back the job's %s: %w", back.Kind, err))
		return
	}
	if err := back.Close(); err != nil {
		return
	}
	if runErr != nil {
		fail(runErr)
		return
	}
	jobwire.Send(w, jobwire.Reply{Kind: jobwire.KindEnd}, nil)
}

// sendBack packs the tree the job's mode returns: an agent job's workspace,
// the index step's index, or intake's out/ folder.
func (s *Server) sendBack(dirs Job, back io.Writer) error {
	switch dirs.Mode {
	case jobwire.ModeIndex:
		return filetree.Pack(dirs.Index, back, s.Limits)
	case jobwire.ModeIntake:
		// The sandbox is gone, so out/ can't change under this check. A link
		// there would have Pack read the supervisor's own files.
		out := filepath.Join(dirs.Workspace, IntakeOut)
		info, err := os.Lstat(out)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			// Intake that failed before writing anything hands back an empty
			// tree; its events say why.
			return tar.NewWriter(back).Close()
		case err != nil:
			return err
		case !info.IsDir():
			return fmt.Errorf("intake's %s isn't a folder", IntakeOut)
		}
		return filetree.Pack(out, back, s.Limits)
	default:
		return filetree.Pack(dirs.Workspace, back, s.Limits)
	}
}

// IntakeOut is the folder intake writes in its workspace, and the only one
// that comes back.
const IntakeOut = "out"

// intakeInputs are the files an intake job's workspace may hold, as the
// coordinator lays them out. message.eml is required.
var intakeInputs = map[string]bool{"message.eml": true, "check.json": true, "request.json": true, "instructions.md": true}

// prepare makes the job's folders from its first frame and the streams after
// it.
func (s *Server) prepare(conn net.Conn, job jobwire.Job, jobFile []byte) (Job, error) {
	dir := filepath.Join(s.JobsDir, job.ID)
	if err := os.Mkdir(dir, 0o755); err != nil {
		return Job{}, fmt.Errorf("job folder: %w", err)
	}
	dirs := Job{ID: job.ID, Mode: job.Mode, Workspace: filepath.Join(dir, "work")}
	made := []string{dirs.Workspace}
	if job.Mode != jobwire.ModeIntake {
		dirs.Data = filepath.Join(dir, "data")
		dirs.Index = filepath.Join(dir, "index")
		dirs.JobFile = filepath.Join(dir, "job.json")
		dirs.SocketDir = filepath.Join(s.Sockets, job.ID)
		made = append(made, dirs.Data, dirs.Index)
	}
	for _, d := range made {
		if err := os.Mkdir(d, 0o755); err != nil {
			return Job{}, err
		}
		if s.Owner != nil {
			if err := os.Chown(d, s.Owner.UID, s.Owner.GID); err != nil {
				return Job{}, err
			}
		}
	}
	if dirs.JobFile != "" {
		if err := os.WriteFile(dirs.JobFile, jobFile, 0o644); err != nil {
			return Job{}, err
		}
	}
	conn.SetReadDeadline(time.Now().Add(uploadTimeout))
	for _, kind := range job.Mode.Sends() {
		target := dirs.Workspace
		if kind == jobwire.KindIndex {
			target = dirs.Index
		}
		in := &jobwire.Stream{R: conn, Kind: kind}
		if _, err := filetree.Extract(in, target, s.Limits, s.Owner); err != nil {
			return Job{}, fmt.Errorf("the job's %s: %w", kind, err)
		}
		if err := in.Drain(); err != nil {
			return Job{}, fmt.Errorf("the job's %s: %w", kind, err)
		}
	}
	conn.SetReadDeadline(time.Time{})
	if job.Mode == jobwire.ModeIntake {
		return dirs, checkIntakeInput(dirs.Workspace)
	}
	if info, err := os.Lstat(dirs.SocketDir); err != nil || !info.IsDir() {
		return Job{}, fmt.Errorf("the broker hasn't opened job %s's socket", job.ID)
	}
	return dirs, nil
}

// checkIntakeInput allows only the intake files, as regular files, and
// requires message.eml.
func checkIntakeInput(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	seen := false
	for _, e := range entries {
		if !intakeInputs[e.Name()] || !e.Type().IsRegular() {
			return fmt.Errorf("intake's input holds %q", e.Name())
		}
		seen = seen || e.Name() == "message.eml"
	}
	if !seen {
		return errors.New("intake's input has no message.eml")
	}
	return nil
}
