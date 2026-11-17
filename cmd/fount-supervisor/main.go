// Command fount-supervisor runs Fount Cloud jobs, each in its own gVisor
// sandbox (m4-cloud-runners.md §5.1c).
//
//	fount-supervisor serve --image sha256:<manifest> [--blobs /harness-blobs]
//	  [--harness /harness] [--sockets /sockets] [--jobs /jobs] [--account <id>] [limits]
//	fount-supervisor unpack --blobs <oci layout> --image sha256:<manifest> --out <dir>
//	fount-supervisor run --harness <dir> --state <dir> [limits] \
//	  --workspace <dir> --job <file> --data <dir> --index <dir>
//
// serve is the runner enclave's: it unpacks the harness once the broker has
// pulled it, then takes jobs from the broker (package supervisor's Server). run
// takes one job as fount-runner's folder flags, so the dev coordinator can use
// it as its runner command.
//
// unpack checks the pinned image and every blob it names, then writes the tree
// to <dir>/rootfs and its config to <dir>/image.json. run starts one job on
// that tree, prints the runner's events on stdout, and ends with a JSON line on
// stderr: {"supervisor": <id>, "exit_code", "seconds", "peak_mib", "oom_kills"}.
// Its exit code is the runner's.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/fount-labs/fount-broker/internal/filetree"
	"github.com/fount-labs/fount-broker/internal/supervisor"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("fount-supervisor: ")
	if len(os.Args) < 2 {
		log.Fatal("usage: fount-supervisor unpack|run|serve [flags]")
	}
	var err error
	code := 0
	switch os.Args[1] {
	case "unpack":
		err = unpack(os.Args[2:])
	case "run":
		code, err = run(os.Args[2:])
	case "serve":
		err = serve(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		log.Print(err)
		if code == 0 {
			code = 2
		}
	}
	os.Exit(code)
}

func unpack(args []string) error {
	fs := flag.NewFlagSet("unpack", flag.ExitOnError)
	blobs := fs.String("blobs", "", "OCI image layout holding the blobs, as the broker fetched them")
	image := fs.String("image", "", "pinned manifest or index digest, sha256:<hex>")
	out := fs.String("out", "", "new folder for rootfs/ and image.json")
	fs.Parse(args)
	if *blobs == "" || *image == "" || *out == "" {
		return errors.New("unpack needs --blobs, --image and --out")
	}
	return unpackTo(*blobs, *image, *out)
}

func unpackTo(blobs, image, out string) error {
	if err := os.Mkdir(out, 0o755); err != nil {
		return err
	}
	rootfs := filepath.Join(out, "rootfs")
	img, err := supervisor.Unpack(supervisor.Blobs{Dir: blobs}, image, rootfs,
		supervisor.UnpackOptions{KeepOwners: os.Geteuid() == 0})
	if err != nil {
		os.RemoveAll(out)
		return err
	}
	data, err := json.MarshalIndent(img, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, "image.json"), data, 0o644)
}

// sandboxFlags registers the sandbox policy's flags on fs, and returns a
// function making the Supervisor once fs is parsed.
func sandboxFlags(fs *flag.FlagSet) func(harness string) (*supervisor.Supervisor, error) {
	state := fs.String("state", "/run/fount-supervisor", "folder for runsc's state and job bundles")
	runsc := fs.String("runsc", "/usr/local/bin/runsc", "runsc binary")
	platform := fs.String("platform", "systrap", "runsc platform")
	memory := fs.Int64("memory-mib", 2048, "sandbox memory cap, MiB")
	pids := fs.Int64("pids", 1024, "sandbox process and thread cap")
	cpus := fs.Float64("cpus", 0, "sandbox CPU cap in cores; 0 is uncapped")
	tmp := fs.Int64("tmp-mib", 2048, "sandbox /tmp size, MiB")
	confinement := fs.String("confinement", "gvisor", "fount-runner --script-confinement")
	return func(harness string) (*supervisor.Supervisor, error) {
		var img supervisor.Image
		data, err := os.ReadFile(filepath.Join(harness, "image.json"))
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, &img); err != nil {
			return nil, fmt.Errorf("image.json: %w", err)
		}
		s := &supervisor.Supervisor{
			Runsc:        *runsc,
			RootFS:       filepath.Join(harness, "rootfs"),
			Image:        &img,
			StateDir:     *state,
			Platform:     *platform,
			UID:          sandboxUID,
			GID:          sandboxUID,
			Confinement:  *confinement,
			Cgroups:      "/sys/fs/cgroup",
			CgroupParent: "fount-jobs",
			Limits: supervisor.Limits{
				MemoryBytes: *memory << 20,
				Pids:        *pids,
				CPUs:        *cpus,
				TmpBytes:    *tmp << 20,
			},
		}
		return s, supervisor.PrepareCgroups(s.Cgroups, s.CgroupParent)
	}
}

const sandboxUID = 10001

func run(args []string) (int, error) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	harness := fs.String("harness", "", "folder unpack wrote")
	newSupervisor := sandboxFlags(fs)
	socketDir := fs.String("socket-dir", "", "folder shared in at /run/broker, holding this job's broker socket")
	id := fs.String("id", "", "job id, [a-z0-9-]; random if empty")
	var job supervisor.Job
	fs.StringVar(&job.Workspace, "workspace", "", "fount-runner --workspace")
	fs.StringVar(&job.JobFile, "job", "", "fount-runner --job")
	fs.StringVar(&job.Data, "data", "", "fount-runner --data")
	fs.StringVar(&job.Index, "index", "", "fount-runner --index")
	fs.Parse(args)
	if *harness == "" {
		return 2, errors.New("run needs --harness")
	}
	job.ID = *id
	if job.ID == "" {
		b := make([]byte, 6)
		rand.Read(b)
		job.ID = "job-" + hex.EncodeToString(b)
	}
	job.SocketDir = *socketDir
	var err error
	for _, p := range []*string{&job.Workspace, &job.JobFile, &job.Data, &job.Index, &job.SocketDir} {
		if *p != "" {
			if *p, err = filepath.Abs(*p); err != nil {
				return 2, err
			}
		}
	}
	s, err := newSupervisor(*harness)
	if err != nil {
		return 2, err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := s.Run(ctx, job, os.Stdout, os.Stderr)
	line, _ := json.Marshal(map[string]any{
		"supervisor": job.ID,
		"exit_code":  result.ExitCode,
		"seconds":    result.Duration.Seconds(),
		"peak_mib":   result.PeakBytes >> 20,
		"oom_kills":  result.OOMKills,
	})
	fmt.Fprintln(os.Stderr, string(line))
	if err != nil {
		return 2, err
	}
	return result.ExitCode, nil
}

// serve is the supervisor in a runner enclave: it waits for the broker's pull
// of the pinned harness, checks and unpacks it, deletes the blobs, and takes
// jobs from the broker on <sockets>/supervisor.sock.
func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	image := fs.String("image", os.Getenv("HARNESS_DIGEST"), "pinned manifest or index digest, sha256:<hex>, from the measured config")
	blobs := fs.String("blobs", "/harness-blobs", "volume the broker pulls the harness into")
	keepBlobs := fs.Bool("keep-blobs", false, "keep the blobs after unpacking (dev)")
	harness := fs.String("harness", "/harness", "new tmpfs folder for the unpacked harness")
	sockets := fs.String("sockets", "/sockets", "volume shared with the broker")
	jobs := fs.String("jobs", "/jobs", "tmpfs folder for each job's folders")
	account := fs.String("account", os.Getenv("DEDICATED_ACCOUNT"), "a dedicated runner's account; empty serves any")
	maxJobs := fs.Int("max-jobs", 8, "jobs at once")
	timeout := fs.Duration("job-timeout", 30*time.Minute, "longest a job's sandbox may run")
	wait := fs.Duration("wait", 30*time.Minute, "how long to wait for the broker's pull")
	newSupervisor := sandboxFlags(fs)
	fs.Parse(args)
	if *image == "" {
		return errors.New("serve needs --image or HARNESS_DIGEST")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The broker writes index.json last. What it names doesn't matter: the
	// pinned digest is what gets checked.
	deadline := time.Now().Add(*wait)
	for {
		if _, err := os.Stat(filepath.Join(*blobs, "index.json")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the broker didn't pull the harness within %s", *wait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	start := time.Now()
	if err := unpackTo(*blobs, *image, *harness); err != nil {
		return err
	}
	log.Printf("checked and unpacked %s in %.0fs", *image, time.Since(start).Seconds())
	if !*keepBlobs {
		for _, name := range []string{"index.json", "oci-layout", "blobs"} {
			if err := os.RemoveAll(filepath.Join(*blobs, name)); err != nil {
				return err
			}
		}
	}
	s, err := newSupervisor(*harness)
	if err != nil {
		return err
	}

	path := filepath.Join(*sockets, "supervisor.sock")
	os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	srv := &supervisor.Server{
		Sandboxes: s,
		JobsDir:   *jobs,
		Sockets:   *sockets,
		Account:   *account,
		MaxJobs:   *maxJobs,
		Timeout:   *timeout,
		Owner:     &filetree.Owner{UID: sandboxUID, GID: sandboxUID},
	}
	log.Printf("taking jobs on %s", path)
	return srv.Serve(ctx, l)
}
