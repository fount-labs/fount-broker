package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fount-labs/fount-broker/internal/broker"
	"github.com/fount-labs/fount-broker/internal/coordinator"
	"github.com/fount-labs/fount-broker/internal/filetree"
	"github.com/fount-labs/fount-broker/internal/frame"
	"github.com/fount-labs/fount-broker/internal/jobwire"
	"github.com/fount-labs/fount-broker/internal/supervisor"
)

const intakeEdgeID = "e41c"

func intakeMail() *coordinator.Mail {
	return &coordinator.Mail{
		EdgeID: intakeEdgeID, ReceivedAt: time.Date(2026, 11, 18, 23, 30, 0, 0, time.UTC).UnixMilli(),
		CheckJSON: json.RawMessage(`{"v":1,"from":{"address":"owner@example.com"}}`),
		Raw:       []byte("From: owner@example.com\r\n\r\nPlease reconcile.\r\n"),
	}
}

// writeIntakeOut writes out/ as fount-runner --mode intake does.
func writeIntakeOut(work string) error {
	out := filepath.Join(work, supervisor.IntakeOut)
	if err := os.MkdirAll(filepath.Join(out, "attachments"), 0o755); err != nil {
		return err
	}
	spec := `{"version":1,"parserVersion":2,"message":"` + intakeEdgeID + `","instruction":"Reconcile vendor statements.",` +
		`"instructionSource":"worker","note":"none","reply":false,` +
		`"attachments":[{"path":"attachments/01-statement.csv","contentType":"text/csv","size":5,"inline":false}],"flags":[]}`
	for name, data := range map[string]string{
		"message.md": "md", "intake.json": "{}", "jobspec.json": spec, "attachments/01-statement.csv": "a,b\n1",
	} {
		if err := os.WriteFile(filepath.Join(out, name), []byte(data), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func intakeCoordinator(t *testing.T, runner coordinator.IntakeRunner) (*coordinator.Coordinator, coordinator.Worker) {
	t.Helper()
	key, _ := coordinator.NewWrappingKey()
	dir := t.TempDir()
	c, err := coordinator.New(coordinator.Config{
		StateDir: filepath.Join(dir, "state"), WorkDir: filepath.Join(dir, "work"),
		Store: coordinator.DirStore{Root: filepath.Join(dir, "objects")}, Key: key, Pool: coordinator.NewPool(1, 1, nil),
		Runner: coordinator.LocalRunner{Command: []string{"false"}}, Intake: runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	w, err := c.CreateWorker("acme", nil)
	if err != nil {
		t.Fatal(err)
	}
	return c, w
}

func TestIntakeRunsOnThePoolAndComesBack(t *testing.T) {
	h := start(t, "")
	h.sandbox.intake = func(job supervisor.Job, stdout io.Writer) (supervisor.Result, error) {
		if job.Mode != jobwire.ModeIntake {
			return supervisor.Result{}, fmt.Errorf("mode %q", job.Mode)
		}
		// Nothing but the email's folder: no data, index, job file or broker.
		if job.Data != "" || job.Index != "" || job.JobFile != "" || job.SocketDir != "" {
			return supervisor.Result{}, fmt.Errorf("intake was given %+v", job)
		}
		if entries, _ := os.ReadDir(h.sockets); len(entries) != 1 {
			return supervisor.Result{}, fmt.Errorf("the relay opened a socket for intake: %v", entries)
		}
		var names []string
		entries, _ := os.ReadDir(job.Workspace)
		for _, e := range entries {
			names = append(names, e.Name())
		}
		if !slices.Equal(names, []string{"check.json", "instructions.md", "message.eml", "request.json"}) {
			return supervisor.Result{}, fmt.Errorf("workspace %v", names)
		}
		if err := writeIntakeOut(job.Workspace); err != nil {
			return supervisor.Result{}, err
		}
		fmt.Fprintln(stdout, `{"event":"intake-finished"}`)
		return supervisor.Result{Duration: time.Second}, nil
	}
	c, w := intakeCoordinator(t, coordinator.RemoteRunner{Addr: h.addr})
	if err := c.PutFile(w.ID, "instructions.md", []byte("Reconcile vendor statements.")); err != nil {
		t.Fatal(err)
	}
	m := intakeMail()
	r, err := c.Intake(context.Background(), w.ID, m, coordinator.IntakeRequest{})
	if err != nil {
		t.Fatalf("%v\nevents %s\nstderr %s", err, r.Events, r.Stderr)
	}
	if r.Spec.Instruction != "Reconcile vendor statements." || len(r.Files) != 4 ||
		string(r.Files["attachments/01-statement.csv"]) != "a,b\n1" || string(r.Files["message.eml"]) != string(m.Raw) {
		t.Fatalf("result %+v", r)
	}
	if !strings.Contains(string(r.Events), "intake-finished") {
		t.Errorf("events %s", r.Events)
	}
	select {
	case <-h.vaults:
		t.Error("intake got a broker")
	default:
	}
}

func TestIntakeCarriesNoCredentials(t *testing.T) {
	sockets, _ := os.MkdirTemp("/tmp", "relay")
	defer os.RemoveAll(sockets)
	supL, err := net.Listen("unix", filepath.Join(sockets, SupervisorSocket))
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan frame.Frame, 1)
	go func() {
		c, err := supL.Accept()
		if err != nil {
			return
		}
		f, _ := frame.Read(c)
		got <- f
		c.Close()
	}()
	jobL, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vaults := make(chan *broker.Vault, 1)
	r := &Relay{Sockets: sockets, NewBroker: func(v *broker.Vault) *broker.Broker { vaults <- v; return nil }}
	go r.Serve(ctx, jobL)

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "message.eml"), []byte("x"), 0o644)
	coordinator.RemoteRunner{Addr: jobL.Addr().String()}.RunIntake(context.Background(), "runner-1", "acct1", dir)
	f := <-got
	job, err := jobwire.DecodeJob(f, jobwire.FromBroker)
	if err != nil || job.Mode != jobwire.ModeIntake || job.Credentials != nil || len(f.Body) != 0 {
		t.Errorf("supervisor got %s, body %d bytes: %v", f.Header, len(f.Body), err)
	}
	if entries, _ := os.ReadDir(sockets); len(entries) != 1 {
		t.Errorf("the relay made a job socket for intake: %v", entries)
	}

	// A coordinator that sends credentials with intake is refused before the
	// supervisor hears of it.
	conn, err := net.Dial("tcp", jobL.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	jobwire.Send(frame.NewWriter(conn), jobwire.Job{Kind: jobwire.KindJob, Mode: jobwire.ModeIntake, Account: "a",
		Credentials: map[string]string{"license": "L"}}, nil)
	reply, err := frame.Read(conn)
	if err != nil || !strings.Contains(string(reply.Header), "intake takes no credentials") {
		t.Errorf("reply %s: %v", reply.Header, err)
	}
	select {
	case <-vaults:
		t.Error("intake got a broker")
	default:
	}
}

func TestAHostileIntakeOutIsRefused(t *testing.T) {
	for _, c := range []struct {
		name   string
		limits filetree.Limits
		out    func(work string) error
		want   string
	}{
		{"out is a link", filetree.Limits{}, func(work string) error {
			elsewhere := filepath.Join(filepath.Dir(work), "elsewhere")
			os.Mkdir(elsewhere, 0o755)
			os.WriteFile(filepath.Join(elsewhere, "secret"), []byte("s"), 0o644)
			return os.Symlink(elsewhere, filepath.Join(work, supervisor.IntakeOut))
		}, "isn't a folder"},
		{"out is a file", filetree.Limits{}, func(work string) error {
			return os.WriteFile(filepath.Join(work, supervisor.IntakeOut), []byte("x"), 0o644)
		}, "isn't a folder"},
		{"too many files", filetree.Limits{}, func(work string) error {
			dir := filepath.Join(work, supervisor.IntakeOut, "attachments")
			os.MkdirAll(dir, 0o755)
			for i := range 600 {
				os.WriteFile(filepath.Join(dir, fmt.Sprint(i)), nil, 0o644)
			}
			return nil
		}, "over its limit"},
		{"over the runner's cap", filetree.Limits{MaxBytes: 1 << 10}, func(work string) error {
			os.Mkdir(filepath.Join(work, supervisor.IntakeOut), 0o755)
			return os.WriteFile(filepath.Join(work, supervisor.IntakeOut, "message.md"), make([]byte, 2<<10), 0o644)
		}, "over its limit"},
	} {
		h := start(t, "")
		h.sandbox.intake = func(job supervisor.Job, _ io.Writer) (supervisor.Result, error) {
			return supervisor.Result{}, c.out(job.Workspace)
		}
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "message.eml"), []byte("x"), 0o644)
		_, err := coordinator.RemoteRunner{Addr: h.addr, Limits: c.limits}.RunIntake(context.Background(), "runner-1", "acct1", dir)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
		if entries, _ := os.ReadDir(filepath.Join(dir, "out")); len(entries) > 1 {
			t.Errorf("%s: out holds %d entries", c.name, len(entries))
		}
	}
}

func TestAFailedIntakeHandsBackNothing(t *testing.T) {
	h := start(t, "")
	h.sandbox.intake = func(job supervisor.Job, stdout io.Writer) (supervisor.Result, error) {
		fmt.Fprintln(stdout, `{"event":"intake-failed"}`)
		return supervisor.Result{ExitCode: 1}, nil
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "message.eml"), []byte("x"), 0o644)
	res, err := coordinator.RemoteRunner{Addr: h.addr}.RunIntake(context.Background(), "runner-1", "acct1", dir)
	if err != nil || res.ExitCode != 1 || !strings.Contains(string(res.Events), "intake-failed") {
		t.Fatalf("%+v: %v", res, err)
	}
	if entries, err := os.ReadDir(filepath.Join(dir, "out")); err != nil || len(entries) != 0 {
		t.Errorf("out %v: %v", entries, err)
	}
	// Coordinator.Intake refuses it on the exit code.
	c, w := intakeCoordinator(t, coordinator.RemoteRunner{Addr: h.addr})
	if _, err := c.Intake(context.Background(), w.ID, intakeMail(), coordinator.IntakeRequest{}); !errors.Is(err, coordinator.ErrIntake) {
		t.Errorf("intake: %v", err)
	}
}

func TestIntakeInputIsOnlyTheEmail(t *testing.T) {
	h := start(t, "")
	h.sandbox.intake = func(supervisor.Job, io.Writer) (supervisor.Result, error) {
		return supervisor.Result{}, errors.New("sandbox reached")
	}
	for name, files := range map[string][]string{
		"an extra file":   {"message.eml", "run.sh"},
		"no message":      {"check.json"},
		"a folder":        {"message.eml", "out/x"},
		"a prepared spec": {"message.eml", "jobspec.json"},
	} {
		dir := t.TempDir()
		for _, f := range files {
			os.MkdirAll(filepath.Join(dir, filepath.Dir(f)), 0o755)
			os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644)
		}
		_, err := coordinator.RemoteRunner{Addr: h.addr}.RunIntake(context.Background(), "runner-1", "acct1", dir)
		if err == nil || strings.Contains(err.Error(), "sandbox reached") {
			t.Errorf("%s: %v", name, err)
		}
	}
	select {
	case job := <-h.sandbox.sawJob:
		t.Errorf("a refused intake reached the sandbox: %+v", job)
	default:
	}
}
