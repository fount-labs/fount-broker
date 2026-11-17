package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fount-labs/fount-broker/internal/broker"
	"github.com/fount-labs/fount-broker/internal/coordinator"
	"github.com/fount-labs/fount-broker/internal/frame"
	"github.com/fount-labs/fount-broker/internal/jobwire"
	"github.com/fount-labs/fount-broker/internal/link"
	"github.com/fount-labs/fount-broker/internal/route"
	"github.com/fount-labs/fount-broker/internal/supervisor"
)

// fakeSandbox stands in for runsc: it checks what the job was given, talks to
// the job's broker socket, and leaves an output.
type fakeSandbox struct {
	t      *testing.T
	sawJob chan supervisor.Job
	block  bool
}

func (f *fakeSandbox) Run(ctx context.Context, job supervisor.Job, stdout, stderr io.Writer) (supervisor.Result, error) {
	f.sawJob <- job
	if f.block {
		<-ctx.Done()
		return supervisor.Result{ExitCode: -1}, ctx.Err()
	}
	in, err := os.ReadFile(filepath.Join(job.Workspace, "files", "in.md"))
	if err != nil {
		return supervisor.Result{}, err
	}
	// The job's socket answers ready, and refuses to change its credentials.
	c, err := net.Dial("unix", filepath.Join(job.SocketDir, JobSocket))
	if err != nil {
		return supervisor.Result{}, err
	}
	defer c.Close()
	ready, err := frame.Read(c)
	if err != nil {
		return supervisor.Result{}, err
	}
	frame.NewWriter(c).Write(frame.Frame{Header: []byte(`{"kind":"credential","id":1,"name":"license"}`), Body: []byte("mine")})
	refused, err := frame.Read(c)
	if err != nil {
		return supervisor.Result{}, err
	}
	fmt.Fprintf(stdout, "%s\n%s\n", ready.Header, refused.Header)
	fmt.Fprint(stderr, "log line")
	os.WriteFile(filepath.Join(job.Workspace, "files", "in.md"), append(in, " edited"...), 0o644)
	os.Remove(filepath.Join(job.Workspace, "files", "gone.md"))
	os.WriteFile(filepath.Join(job.Index, "idx"), []byte(string(job.Mode)), 0o644)
	return supervisor.Result{ExitCode: 0, Duration: time.Second, PeakBytes: 300 << 20}, nil
}

type harness struct {
	addr string
	// linked takes jobs over the link only.
	linked  string
	sockets string
	sandbox *fakeSandbox
	vaults  chan *broker.Vault
}

func start(t *testing.T, account string) *harness {
	t.Helper()
	// Unix socket paths are short on macOS.
	sockets, err := os.MkdirTemp("/tmp", "relay")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockets) })
	ctx, cancel := context.WithCancel(context.Background())
	h := &harness{sockets: sockets, sandbox: &fakeSandbox{t: t, sawJob: make(chan supervisor.Job, 4)}, vaults: make(chan *broker.Vault, 4)}

	supL, err := net.Listen("unix", filepath.Join(sockets, SupervisorSocket))
	if err != nil {
		t.Fatal(err)
	}
	srv := &supervisor.Server{Sandboxes: h.sandbox, JobsDir: t.TempDir(), Sockets: sockets, Account: account, MaxJobs: 2, Timeout: time.Minute}
	supDone := make(chan struct{})
	go func() { srv.Serve(ctx, supL); close(supDone) }()

	jobL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.addr = jobL.Addr().String()
	r := &Relay{Sockets: sockets, NewBroker: func(v *broker.Vault) *broker.Broker {
		h.vaults <- v
		b := broker.New("test", map[string]route.Route{}, v)
		b.Locked = true
		return b
	}}
	relayDone := make(chan struct{})
	go func() { r.Serve(ctx, jobL); close(relayDone) }()
	linkedL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// As in an enclave: HTTP, the link an upgrade on its path.
	h.linked = "http://" + linkedL.Addr().String()
	upgrades := link.NewListener(linkedL.Addr())
	web := &http.Server{Handler: upgrades}
	go web.Serve(linkedL)
	t.Cleanup(func() { web.Close() })
	runnerEnd, err := link.Unattested()
	if err != nil {
		t.Fatal(err)
	}
	linked := *r
	linked.Link = runnerEnd
	linkedDone := make(chan struct{})
	go func() { linked.Serve(ctx, upgrades); close(linkedDone) }()
	t.Cleanup(func() {
		cancel()
		<-supDone
		<-relayDone
		<-linkedDone
	})
	return h
}

func jobDirs(t *testing.T) coordinator.JobDirs {
	t.Helper()
	root := t.TempDir()
	d := coordinator.JobDirs{
		Workspace: filepath.Join(root, "workspace"), Index: filepath.Join(root, "index"),
		Data: filepath.Join(root, "data"), JobFile: filepath.Join(root, "job.json"),
	}
	for _, dir := range []string{filepath.Join(d.Workspace, "files"), d.Index, d.Data} {
		os.MkdirAll(dir, 0o755)
	}
	os.WriteFile(filepath.Join(d.Workspace, "files", "in.md"), []byte("hello"), 0o644)
	os.WriteFile(filepath.Join(d.Workspace, "files", "gone.md"), []byte("bye"), 0o644)
	os.WriteFile(filepath.Join(d.Index, "kept"), []byte("kept"), 0o644)
	os.WriteFile(d.JobFile, []byte(`{"sessionId":"s","prompt":"p","config":{}}`), 0o644)
	return d
}

func TestAJobGoesThroughAndComesBack(t *testing.T) {
	h := start(t, "")
	dirs := jobDirs(t)
	dirs.Credentials = map[string]string{"license": "L-acct1"}
	runner := coordinator.RemoteRunner{Addr: h.addr}
	res, err := runner.Run(context.Background(), "runner-1", "acct1", dirs)
	if err != nil {
		t.Fatalf("%v\nstdout %s\nstderr %s", err, res.Events, res.Stderr)
	}
	job := <-h.sandbox.sawJob
	if !strings.HasPrefix(job.ID, "j-") || job.SocketDir != filepath.Join(h.sockets, job.ID) {
		t.Errorf("job %+v", job)
	}
	lines := strings.Split(strings.TrimSpace(string(res.Events)), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"kind":"ready"`) || !strings.Contains(lines[1], "set by its runner") {
		t.Errorf("events %q", res.Events)
	}
	if string(res.Stderr) != "log line" {
		t.Errorf("stderr %q", res.Stderr)
	}
	vault := <-h.vaults
	if v, _ := vault.Get("license"); v != "L-acct1" {
		t.Errorf("the job's vault holds license %q", v)
	}
	if data, _ := os.ReadFile(filepath.Join(dirs.Workspace, "files", "in.md")); string(data) != "hello edited" {
		t.Errorf("in.md came back %q", data)
	}
	if _, err := os.Stat(filepath.Join(dirs.Workspace, "files", "gone.md")); err == nil {
		t.Error("a file the job deleted came back")
	}
	if job.Mode != jobwire.ModeAgent {
		t.Errorf("mode %q", job.Mode)
	}
	// The index went in and stayed behind.
	if entries, _ := os.ReadDir(dirs.Index); len(entries) != 1 {
		t.Errorf("index came back %v", entries)
	}
	// The job's socket, its folder and its job folder are gone. The relay
	// removes them as it returns, just after the reply reaches the runner.
	var entries []os.DirEntry
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if entries, _ = os.ReadDir(h.sockets); len(entries) == 1 {
			break
		}
	}
	if len(entries) != 1 {
		t.Errorf("sockets volume holds %v", entries)
	}
}

func TestTheIndexStepHandsBackOnlyTheIndex(t *testing.T) {
	h := start(t, "")
	dirs := jobDirs(t)
	dirs.Mode = jobwire.ModeIndex
	if _, err := (coordinator.RemoteRunner{Addr: h.addr}).Run(context.Background(), "r", "acct1", dirs); err != nil {
		t.Fatal(err)
	}
	if job := <-h.sandbox.sawJob; job.Mode != jobwire.ModeIndex {
		t.Errorf("mode %q", job.Mode)
	}
	if data, _ := os.ReadFile(filepath.Join(dirs.Index, "idx")); string(data) != "index" {
		t.Errorf("index came back %q", data)
	}
	if data, _ := os.ReadFile(filepath.Join(dirs.Index, "kept")); string(data) != "kept" {
		t.Errorf("the kept index wasn't given to the step: %q", data)
	}
	if data, _ := os.ReadFile(filepath.Join(dirs.Workspace, "files", "in.md")); string(data) != "hello" {
		t.Errorf("the index step's workspace came back: %q", data)
	}
}

func TestJobsCrossTheLink(t *testing.T) {
	h := start(t, "")
	coordinatorEnd, err := link.Unattested()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (coordinator.RemoteRunner{Addr: h.linked, Link: coordinatorEnd}).Run(context.Background(), "r", "acct1", jobDirs(t)); err != nil {
		t.Fatal(err)
	}
	<-h.sandbox.sawJob
	// A coordinator that won't do the handshake gets nothing back, not even
	// an error frame.
	if _, err := (coordinator.RemoteRunner{Addr: h.linked}).Run(context.Background(), "r", "acct1", jobDirs(t)); err == nil {
		t.Fatal("a plain connection ran a job")
	}
	select {
	case <-h.sandbox.sawJob:
		t.Fatal("a plain connection's job reached the supervisor")
	default:
	}
}

func TestTheSupervisorNeverSeesCredentials(t *testing.T) {
	sockets, _ := os.MkdirTemp("/tmp", "relay")
	defer os.RemoveAll(sockets)
	supL, err := net.Listen("unix", filepath.Join(sockets, SupervisorSocket))
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan []byte, 1)
	go func() {
		c, err := supL.Accept()
		if err != nil {
			return
		}
		f, _ := frame.Read(c)
		got <- f.Header
		c.Close()
	}()
	jobL, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &Relay{Sockets: sockets, NewBroker: func(v *broker.Vault) *broker.Broker { return nil }}
	go r.Serve(ctx, jobL)
	dirs := jobDirs(t)
	dirs.Credentials = map[string]string{"license": "SECRET"}
	coordinator.RemoteRunner{Addr: jobL.Addr().String()}.Run(context.Background(), "r", "acct1", dirs)
	header := <-got
	var j map[string]any
	json.Unmarshal(header, &j)
	if strings.Contains(string(header), "SECRET") || j["credentials"] != nil || j["account"] != "acct1" {
		t.Errorf("supervisor got %s", header)
	}
}

func TestDedicatedRunnerRefusesOtherAccounts(t *testing.T) {
	h := start(t, "acct1")
	_, err := coordinator.RemoteRunner{Addr: h.addr}.Run(context.Background(), "r", "acct2", jobDirs(t))
	if err == nil || !strings.Contains(err.Error(), "serves one account") {
		t.Fatalf("%v", err)
	}
}

func TestCancellingStopsTheSandbox(t *testing.T) {
	h := start(t, "")
	h.sandbox.block = true
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := coordinator.RemoteRunner{Addr: h.addr}.Run(ctx, "r", "acct1", jobDirs(t))
		errc <- err
	}()
	<-h.sandbox.sawJob
	cancel()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("a cancelled job succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancel didn't end the job")
	}
	// The sandbox saw its context end, so the supervisor freed the slot and
	// the relay removed the job's socket.
	deadline := time.Now().Add(5 * time.Second)
	for {
		entries, _ := os.ReadDir(h.sockets)
		if len(entries) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sockets volume still holds %v", entries)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestUnlockedBrokersAreRefused(t *testing.T) {
	sockets, _ := os.MkdirTemp("/tmp", "relay")
	defer os.RemoveAll(sockets)
	l, _ := net.Listen("unix", filepath.Join(sockets, "j.sock"))
	ctx, cancel := context.WithCancel(context.Background())
	r := &Relay{NewBroker: func(v *broker.Vault) *broker.Broker { return broker.New("t", nil, v) }}
	done := make(chan struct{})
	go func() { r.serveJob(ctx, l, broker.NewVault()); close(done) }()
	c, err := net.Dial("unix", filepath.Join(sockets, "j.sock"))
	if err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := frame.Read(c); err == nil {
		t.Error("an unlocked broker answered")
	}
	cancel()
	<-done
}
