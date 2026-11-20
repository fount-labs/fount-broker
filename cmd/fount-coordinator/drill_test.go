package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/fount-labs/fount-broker/internal/s3bucket/s3buckettest"
)

// drillMainEnv makes the test binary run main, so the drill runs the
// coordinator as docs/backups.md does, flags and all.
const drillMainEnv = "FOUNT_COORDINATOR_DRILL_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(drillMainEnv) == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// drillProc is one coordinator process and its log.
type drillProc struct {
	t    *testing.T
	cmd  *exec.Cmd
	mu   sync.Mutex
	log  bytes.Buffer
	done chan struct{}
	err  error
}

func (p *drillProc) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.log.Write(b)
}

func (p *drillProc) logged() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.log.String()
}

func startCoordinator(t *testing.T, args ...string) *drillProc {
	t.Helper()
	p := &drillProc{t: t, cmd: exec.Command(os.Args[0], args...), done: make(chan struct{})}
	p.cmd.Env = append(os.Environ(), drillMainEnv+"=1", "AWS_ACCESS_KEY_ID=AKIDTEST", "AWS_SECRET_ACCESS_KEY=secret")
	p.cmd.Stdout, p.cmd.Stderr = p, p
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		p.err = p.cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(func() { p.stop() })
	return p
}

// waitLog waits for the log to have want, failing if the process ends
// first.
func (p *drillProc) waitLog(want string) {
	p.t.Helper()
	deadline := time.After(30 * time.Second)
	for !strings.Contains(p.logged(), want) {
		select {
		case <-p.done:
			if strings.Contains(p.logged(), want) {
				return
			}
			p.t.Fatalf("the coordinator exited (%v) before logging %q:\n%s", p.err, want, p.logged())
		case <-deadline:
			p.t.Fatalf("no %q in the log:\n%s", want, p.logged())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// exited waits for the process to end by itself.
func (p *drillProc) exited() error {
	p.t.Helper()
	select {
	case <-p.done:
		return p.err
	case <-time.After(30 * time.Second):
		p.t.Fatalf("the coordinator didn't exit:\n%s", p.logged())
		return nil
	}
}

// stop ends the process as a deploy does, and checks it exits cleanly.
func (p *drillProc) stop() {
	p.t.Helper()
	select {
	case <-p.done:
		return
	default:
	}
	p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
		if p.err != nil {
			p.t.Errorf("the coordinator exited with %v:\n%s", p.err, p.logged())
		}
	case <-time.After(30 * time.Second):
		p.cmd.Process.Kill()
		p.t.Errorf("the coordinator didn't stop on SIGTERM:\n%s", p.logged())
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func drillCall(t *testing.T, method, url, body string, want int) []byte {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("%s %s: %d %s, want %d", method, url, resp.StatusCode, out, want)
	}
	return out
}

func roots(f *s3buckettest.Fake) []string {
	return slices.DeleteFunc(f.Keys(), func(k string) bool { return !strings.HasPrefix(k, "roots/") })
}

// The restore drill as docs/backups.md has it for --wrapping-key dev, on
// the coordinator binary against an S3 bucket over HTTP: a coordinator backs
// a worker's file and job up on its interval; the volume is lost, keeping
// the dev key and the dev vault; a dry run checks the newest backup and
// moves nothing; the restore brings the worker back under a new generation;
// a restart with --restore still set serves it; and --restore over a volume
// nothing was restored onto is refused.
func TestTheRestoreRunbookOnTheBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the coordinator binary")
	}
	fake, srv := s3buckettest.Start(t, "AKIDTEST")
	vault := filepath.Join(t.TempDir(), "dev-vault.json")
	flags := func(dir, listen string, more ...string) []string {
		args := []string{"--dir", dir, "--listen", listen, "--wrapping-key", "dev", "--dev-vault", vault,
			"--backup-bucket", srv.URL, "--backup-region", "us-east-1", "--backup-interval", "100ms"}
		return append(append(args, more...), "--", "true")
	}
	readVault := func() string {
		data, err := os.ReadFile(vault)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}

	c1 := t.TempDir()
	addr := freeAddr(t)
	api := "http://" + addr + "/v0"
	p := startCoordinator(t, flags(c1, addr)...)
	p.waitLog("dev API on")
	var w struct {
		ID string `json:"id"`
	}
	json.Unmarshal(drillCall(t, "POST", api+"/workers", `{"account":"acme"}`, http.StatusCreated), &w)
	const memo = "Q3 close: the accruals are in the shared drive."
	drillCall(t, "PUT", api+"/workers/"+w.ID+"/root/files/memo.md", memo, http.StatusNoContent)
	var job struct {
		ID    string `json:"id"`
		State string `json:"state"`
	}
	json.Unmarshal(drillCall(t, "POST", api+"/workers/"+w.ID+"/jobs", `{"threadId":"t1","sessionId":"s1","instruction":"file Q3","config":{}}`, http.StatusAccepted), &job)
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		json.Unmarshal(drillCall(t, "GET", api+"/jobs/"+job.ID, "", http.StatusOK), &job)
		if job.State != "queued" && job.State != "running" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %s is still %s", job.ID, job.State)
		}
	}
	files := string(drillCall(t, "GET", api+"/workers/"+w.ID+"/files", "", http.StatusOK))
	// The interval backs the volume up while it changes: once it has
	// written nothing new for ten intervals, the newest root has it all.
	for last, quiet := len(roots(fake)), 0; quiet < 10; time.Sleep(100 * time.Millisecond) {
		if n := len(roots(fake)); n != last {
			last, quiet = n, 0
		} else {
			quiet++
		}
	}
	newest := roots(fake)[len(roots(fake))-1]

	// --restore over a volume nothing was restored onto is refused, before
	// it takes a generation that would fence the coordinator running on it.
	live := readVault()
	refused := startCoordinator(t, flags(c1, freeAddr(t), "--restore", "latest")...)
	if err := refused.exited(); err == nil || !strings.Contains(refused.logged(), "never restored onto") {
		t.Fatalf("--restore over the live volume: %v\n%s", err, refused.logged())
	}
	if readVault() != live {
		t.Fatalf("a refused --restore moved the vault from %s to %s", live, readVault())
	}
	time.Sleep(300 * time.Millisecond)
	drillCall(t, "GET", api+"/workers/"+w.ID, "", http.StatusOK)
	p.stop()

	// The volume is lost; the dev key and the dev vault are kept.
	key, err := os.ReadFile(filepath.Join(c1, "wrapping.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(c1); err != nil {
		t.Fatal(err)
	}
	c2 := t.TempDir()
	// Without the key, --restore refuses to start.
	p = startCoordinator(t, flags(c2, freeAddr(t), "--restore", "latest")...)
	if err := p.exited(); err == nil || !strings.Contains(p.logged(), "wrapping.key") {
		t.Fatalf("--restore without the dev key: %v\n%s", err, p.logged())
	}
	if err := os.WriteFile(filepath.Join(c2, "wrapping.key"), key, 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. The dry run names the newest backup, writes nothing and moves the
	// vault nowhere, then serves nothing until stopped.
	before := readVault()
	p = startCoordinator(t, flags(c2, freeAddr(t), "--restore", "latest", "--restore-dry-run")...)
	p.waitLog("restore dry run done")
	if !strings.Contains(p.logged(), `"root":"`+newest+`"`) || !strings.Contains(p.logged(), `"workers":1`) {
		t.Fatalf("the dry run didn't name %s:\n%s", newest, p.logged())
	}
	p.stop()
	if ents, _ := os.ReadDir(c2); len(ents) != 1 {
		t.Fatalf("the dry run wrote the volume: %v", ents)
	}
	if readVault() != before {
		t.Fatalf("the dry run moved the vault from %s to %s", before, readVault())
	}

	// 2. The restore, then serving.
	addr = freeAddr(t)
	api = "http://" + addr + "/v0"
	p = startCoordinator(t, flags(c2, addr, "--restore", newest)...)
	p.waitLog("dev API on")
	if !strings.Contains(p.logged(), `"root":"`+newest+`"`) {
		t.Fatalf("the restore didn't take %s:\n%s", newest, p.logged())
	}
	if got := string(drillCall(t, "GET", api+"/workers/"+w.ID+"/files/root/files/memo.md", "", http.StatusOK)); got != memo {
		t.Fatalf("the memo after the restore: %q", got)
	}
	if got := string(drillCall(t, "GET", api+"/workers/"+w.ID+"/files", "", http.StatusOK)); got != files {
		t.Fatalf("the files after the restore:\n%s\nwant\n%s", got, files)
	}
	var restored struct {
		State string `json:"state"`
	}
	json.Unmarshal(drillCall(t, "GET", api+"/jobs/"+job.ID, "", http.StatusOK), &restored)
	if restored.State != job.State {
		t.Fatalf("job %s is %s after the restore, was %s", job.ID, restored.State, job.State)
	}
	p.stop()

	// 3. A restart with --restore still set serves the restored volume.
	addr = freeAddr(t)
	p = startCoordinator(t, flags(c2, addr, "--restore", "latest")...)
	p.waitLog("dev API on")
	if !strings.Contains(p.logged(), "the volume was restored from "+newest) {
		t.Fatalf("the restart with --restore:\n%s", p.logged())
	}
	if got := string(drillCall(t, "GET", "http://"+addr+"/v0/workers/"+w.ID+"/files/root/files/memo.md", "", http.StatusOK)); got != memo {
		t.Fatalf("the memo after the restart: %q", got)
	}
	p.stop()
}
