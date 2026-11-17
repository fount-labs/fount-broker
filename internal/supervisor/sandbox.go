package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fount-labs/fount-broker/internal/jobwire"
)

// Supervisor runs jobs, each in a fresh runsc sandbox whose root is the
// unpacked harness, read-only.
type Supervisor struct {
	// Runsc is the runsc binary; its gvisor-bin sidecars sit beside it.
	Runsc string
	// RootFS is the unpacked harness tree, and Image its config.
	RootFS string
	Image  *Image
	// StateDir holds runsc's state and each job's bundle, while it runs.
	StateDir string
	// Platform is runsc's: systrap in an enclave, which has no /dev/kvm.
	Platform string
	// UID and GID run the job. Never 0.
	UID, GID uint32
	Limits   Limits
	// Confinement is passed to fount-runner's --script-confinement. Under
	// gVisor there is no Landlock, so `required` fails every script.
	Confinement string
	// Cgroups is the cgroup v2 mount and CgroupParent the group every job's
	// group sits under.
	Cgroups      string
	CgroupParent string
}

// Job is one job's folders, prepared by the caller and read back after. They
// are fount-runner's --workspace, --data, --index (or --index-read-only) and
// --job.
type Job struct {
	ID string
	// Mode is jobwire's: an agent job sees Index read-only; the index step
	// writes it and runs no agent.
	Mode      jobwire.Mode
	Workspace string
	Data      string
	Index     string
	JobFile   string
	// SocketDir, if set, is shared in at /run/broker and holds only this
	// job's broker socket.
	SocketDir string
}

type Result struct {
	// ExitCode is fount-runner's, or runsc's if the sandbox didn't start.
	ExitCode int
	Duration time.Duration
	// PeakBytes is the job's cgroup memory.peak, gVisor's Sentry included; -1
	// if it couldn't be read.
	PeakBytes int64
	// OOMKills counts processes the cgroup's memory cap killed.
	OOMKills int64
}

var jobIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Run starts the job and waits for it. stdout gets the runner's events,
// stderr runsc's and the runner's logs. When ctx ends, the sandbox is killed.
// Whatever happens, the sandbox and its cgroup are gone when Run returns.
func (s *Supervisor) Run(ctx context.Context, job Job, stdout, stderr io.Writer) (Result, error) {
	if err := s.check(job); err != nil {
		return Result{}, err
	}
	group := filepath.Join(s.Cgroups, s.CgroupParent, job.ID)
	if err := os.Mkdir(group, 0o755); err != nil {
		return Result{}, fmt.Errorf("job cgroup: %w", err)
	}
	defer os.Remove(group)
	// runsc makes the sandbox's group below this one. This one outlives it, so
	// its memory.peak can be read after the run.
	if err := os.WriteFile(filepath.Join(group, "cgroup.subtree_control"), []byte("+memory +pids +cpu"), 0); err != nil {
		return Result{}, fmt.Errorf("job cgroup controllers: %w", err)
	}
	sandboxGroup := filepath.Join(group, "sandbox")
	defer os.Remove(sandboxGroup)

	bundle := filepath.Join(s.StateDir, "bundles", job.ID)
	if err := os.MkdirAll(bundle, 0o700); err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(bundle)
	args := append(append([]string{}, s.Image.Entrypoint...), "--workspace", sandboxWork)
	if job.Mode == jobwire.ModeIndex {
		args = append(args, "--mode", "index", "--index", sandboxIndex)
	} else {
		args = append(args, "--job", sandboxJob, "--index-read-only", sandboxIndex,
			"--script-confinement", s.Confinement)
	}
	if job.SocketDir != "" {
		args = append(args, "--broker-socket", sandboxBroker+"/"+jobSocket)
	}
	if s.Limits.Threads > 0 {
		args = append(args, "--threads", strconv.Itoa(s.Limits.Threads))
	}
	cgroupsPath := "/" + filepath.Join(s.CgroupParent, job.ID, "sandbox")
	spec, err := jobSpec(s.RootFS, s.Image, s.UID, s.GID, s.Limits, job, args, cgroupsPath)
	if err != nil {
		return Result{}, err
	}
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), spec, 0o600); err != nil {
		return Result{}, err
	}

	runscRoot := filepath.Join(s.StateDir, "runsc")
	global := []string{"--root=" + runscRoot, "--platform=" + s.Platform, "--network=none"}
	if job.SocketDir != "" {
		global = append(global, "--host-uds=open")
	}
	// Without it gVisor shows the job every core, whatever its CPU cap, and
	// anything sizing itself by the core count oversubscribes.
	if s.Limits.CPUs > 0 {
		global = append(global, "--cpu-num-from-quota")
	}
	cmd := exec.Command(s.Runsc, append(global, "run", "--bundle", bundle, job.ID)...)
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	defer s.runsc(runscRoot, "delete", "--force", job.ID)

	started := time.Now()
	if err := cmd.Start(); err != nil {
		return Result{}, fmt.Errorf("start runsc: %w", err)
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	var runErr error
	select {
	case runErr = <-waited:
	case <-ctx.Done():
		// Killing runsc's own process can leave the sandbox running, so the
		// sandbox is killed through runsc.
		s.runsc(runscRoot, "kill", "--all", job.ID, "KILL")
		select {
		case <-waited:
		case <-time.After(10 * time.Second):
			cmd.Process.Kill()
			<-waited
		}
		return s.result(group, started, -1), fmt.Errorf("job stopped: %w", ctx.Err())
	}
	code := 0
	var exit *exec.ExitError
	switch {
	case runErr == nil:
	case errors.As(runErr, &exit):
		code = exit.ExitCode()
	default:
		return Result{}, fmt.Errorf("runsc: %w", runErr)
	}
	return s.result(group, started, code), nil
}

func (s *Supervisor) check(job Job) error {
	if !jobIDPattern.MatchString(job.ID) {
		return fmt.Errorf("job id %q isn't [a-z0-9-], up to 63 characters", job.ID)
	}
	if s.UID == 0 || s.GID == 0 {
		return errors.New("jobs never run as root")
	}
	if s.Limits.MemoryBytes <= 0 || s.Limits.Pids <= 0 || s.Limits.TmpBytes <= 0 {
		return errors.New("every sandbox needs memory, pids and /tmp caps")
	}
	for name, dir := range map[string]string{"workspace": job.Workspace, "data": job.Data, "index": job.Index} {
		if err := isDir(dir); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if job.SocketDir != "" {
		if err := isDir(job.SocketDir); err != nil {
			return fmt.Errorf("socket dir: %w", err)
		}
	}
	if !filepath.IsAbs(job.JobFile) {
		return fmt.Errorf("job file %q isn't absolute", job.JobFile)
	}
	fi, err := os.Lstat(job.JobFile)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("job file %s isn't a regular file", job.JobFile)
	}
	return nil
}

func isDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%q isn't absolute", dir)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s isn't a directory", dir)
	}
	return nil
}

func (s *Supervisor) result(group string, started time.Time, code int) Result {
	r := Result{ExitCode: code, Duration: time.Since(started), PeakBytes: -1}
	if data, err := os.ReadFile(filepath.Join(group, "memory.peak")); err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil {
			r.PeakBytes = n
		}
	}
	if data, err := os.ReadFile(filepath.Join(group, "memory.events")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if v, ok := strings.CutPrefix(line, "oom_kill "); ok {
				r.OOMKills, _ = strconv.ParseInt(v, 10, 64)
			}
		}
	}
	return r
}

func (s *Supervisor) runsc(root string, args ...string) {
	exec.Command(s.Runsc, append([]string{"--root=" + root}, args...)...).Run()
}

// PrepareCgroups makes the cgroup tree able to hold per-job groups, once at
// start. cgroup v2 lets a group hand its controllers to children only when it
// holds no processes itself, so the supervisor's own processes move to
// <cgroups>/init first.
func PrepareCgroups(cgroups, parent string) error {
	const controllers = "+memory +pids +cpu"
	if _, err := os.Stat(filepath.Join(cgroups, "cgroup.controllers")); err != nil {
		return fmt.Errorf("%s isn't a cgroup v2 mount: %w", cgroups, err)
	}
	enabled, err := os.ReadFile(filepath.Join(cgroups, "cgroup.subtree_control"))
	if err != nil {
		return err
	}
	if !hasControllers(string(enabled)) {
		init := filepath.Join(cgroups, "init")
		if err := os.MkdirAll(init, 0o755); err != nil {
			return err
		}
		procs, err := os.ReadFile(filepath.Join(cgroups, "cgroup.procs"))
		if err != nil {
			return err
		}
		for _, pid := range strings.Fields(string(procs)) {
			// A process may have exited since the list was read.
			os.WriteFile(filepath.Join(init, "cgroup.procs"), []byte(pid), 0)
		}
		if err := os.WriteFile(filepath.Join(cgroups, "cgroup.subtree_control"), []byte(controllers), 0); err != nil {
			return fmt.Errorf("enable %s: %w", controllers, err)
		}
	}
	jobs := filepath.Join(cgroups, parent)
	if err := os.MkdirAll(jobs, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(jobs, "cgroup.subtree_control"), []byte(controllers), 0)
}

func hasControllers(enabled string) bool {
	have := map[string]bool{}
	for _, c := range strings.Fields(enabled) {
		have[c] = true
	}
	return have["memory"] && have["pids"] && have["cpu"]
}
