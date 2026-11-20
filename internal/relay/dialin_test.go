package relay

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fount-labs/fount-broker/internal/broker"
	"github.com/fount-labs/fount-broker/internal/coordinator"
	"github.com/fount-labs/fount-broker/internal/link"
	"github.com/fount-labs/fount-broker/internal/route"
	"github.com/fount-labs/fount-broker/internal/supervisor"
)

// dialIn is a runner that dials a coordinator's RunnerHub, as in an enclave:
// the hub behind HTTP, the link an upgrade on its path.
type dialIn struct {
	hub     *coordinator.RunnerHub
	sandbox *fakeSandbox
	// dials counts the links the runner opened.
	changed atomic.Int32
	mu      sync.Mutex
	dials   int
	conns   []net.Conn
}

// dropAll closes, from the runner's side, every link it has open.
func (d *dialIn) dropAll() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range d.conns {
		c.Close()
	}
	d.conns = nil
}

func (d *dialIn) dialled() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials
}

func startDialIn(t *testing.T, hubSide, runnerSide *link.Side, parkFor time.Duration) *dialIn {
	t.Helper()
	sockets, err := os.MkdirTemp("/tmp", "relay")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockets) })
	ctx, cancel := context.WithCancel(context.Background())
	d := &dialIn{hub: coordinator.NewRunnerHub(hubSide), sandbox: &fakeSandbox{t: t, sawJob: make(chan supervisor.Job, 8)}}
	d.hub.TakeWait = 5 * time.Second
	d.hub.Changed = func() { d.changed.Add(1) }

	supL, err := net.Listen("unix", filepath.Join(sockets, SupervisorSocket))
	if err != nil {
		t.Fatal(err)
	}
	srv := &supervisor.Server{Sandboxes: d.sandbox, JobsDir: t.TempDir(), Sockets: sockets, MaxJobs: 4, Timeout: time.Minute}
	supDone := make(chan struct{})
	go func() { srv.Serve(ctx, supL); close(supDone) }()

	web := httptest.NewServer(d.hub)
	r := &Relay{Sockets: sockets, Link: runnerSide, NewBroker: func(v *broker.Vault) *broker.Broker {
		b := broker.New("test", map[string]route.Route{}, v)
		b.Locked = true
		return b
	}}
	header := http.Header{link.NameHeader: {"runner-t.example"}}
	relayDone := make(chan struct{})
	go func() {
		r.ServeDialIn(ctx, DialIn{
			Dial: func(ctx context.Context) (net.Conn, error) {
				c, err := link.DialUpgradeHeader(ctx, web.URL, link.Path, link.DialInProtocol, header)
				if err == nil {
					d.mu.Lock()
					d.dials++
					d.conns = append(d.conns, c)
					d.mu.Unlock()
				}
				return c, err
			},
			Spare: 2, Max: 4, ParkFor: parkFor,
		})
		close(relayDone)
	}()
	t.Cleanup(func() {
		cancel()
		d.hub.Close()
		web.Close()
		<-relayDone
		<-supDone
	})
	return d
}

func unattested(t *testing.T) *link.Side {
	t.Helper()
	s, err := link.Unattested()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !ok(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func parked(h *coordinator.RunnerHub) int {
	n := 0
	for _, r := range h.Runners() {
		n += r.Parked
	}
	return n
}

func TestARunnerDialsInAndTakesJobs(t *testing.T) {
	d := startDialIn(t, unattested(t), unattested(t), link.ParkFor)
	waitFor(t, "two parked links", func() bool { return parked(d.hub) == 2 })
	if runners := d.hub.Runners(); len(runners) != 1 || runners[0].Name != "runner-t.example" {
		t.Fatalf("runners %+v", runners)
	}
	if d.changed.Load() != 1 {
		t.Errorf("the first link called Changed %d times", d.changed.Load())
	}
	runner := coordinator.RemoteRunner{Hub: d.hub}
	for i := range 3 {
		dirs := jobDirs(t)
		dirs.Credentials = map[string]string{"license": "L"}
		res, err := runner.Run(context.Background(), "runner-1", "acct1", dirs)
		if err != nil {
			t.Fatalf("job %d: %v\nstderr %s", i, err, res.Stderr)
		}
		<-d.sandbox.sawJob
		if data, _ := os.ReadFile(filepath.Join(dirs.Workspace, "files", "in.md")); string(data) != "hello edited" {
			t.Errorf("job %d: in.md came back %q", i, data)
		}
	}
	// Each job took a parked link, and the runner dialled one in its place.
	waitFor(t, "the spares again", func() bool { return parked(d.hub) == 2 })
	if n := d.dialled(); n != 5 {
		t.Errorf("the runner dialled %d links for 3 jobs and 2 spares", n)
	}
	waitFor(t, "no busy links", func() bool { return d.hub.Runners()[0].Busy == 0 })
}

func TestJobsRunAtOnceOverDialledLinks(t *testing.T) {
	d := startDialIn(t, unattested(t), unattested(t), link.ParkFor)
	d.sandbox.block = true
	waitFor(t, "a parked link", d.hub.Ready)
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 3)
	for range 3 {
		go func() {
			_, err := coordinator.RemoteRunner{Hub: d.hub}.Run(ctx, "r", "acct1", jobDirs(t))
			errs <- err
		}()
	}
	for range 3 {
		select {
		case <-d.sandbox.sawJob:
		case <-time.After(10 * time.Second):
			t.Fatal("three jobs didn't all start with two spares")
		}
	}
	// Cancelling closes each job's link, which ends its sandbox.
	cancel()
	for range 3 {
		if err := <-errs; err == nil {
			t.Error("a cancelled job succeeded")
		}
	}
}

func TestACoordinatorRefusesARunnerItCantCheck(t *testing.T) {
	refuse := unattested(t)
	refuse.Check = func([]byte, []byte) (ed25519.PublicKey, error) { return nil, errors.New("built from another repo") }
	d := startDialIn(t, refuse, unattested(t), link.ParkFor)
	waitFor(t, "the runner to try", func() bool { return d.dialled() >= 2 })
	if d.hub.Ready() || len(d.hub.Runners()) != 0 {
		t.Fatalf("a runner that failed its check parked: %+v", d.hub.Runners())
	}
	d.hub.TakeWait = 100 * time.Millisecond
	if _, err := (coordinator.RemoteRunner{Hub: d.hub}).Run(context.Background(), "r", "acct1", jobDirs(t)); !errors.Is(err, coordinator.ErrNoRunnerLink) {
		t.Fatalf("%v", err)
	}
	select {
	case <-d.sandbox.sawJob:
		t.Fatal("a job reached the supervisor")
	default:
	}
}

func TestARunnerRefusesACoordinatorItCantCheck(t *testing.T) {
	refuse := unattested(t)
	refuse.Check = func([]byte, []byte) (ed25519.PublicKey, error) { return nil, errors.New("built from another repo") }
	d := startDialIn(t, unattested(t), refuse, link.ParkFor)
	waitFor(t, "the runner to try", func() bool { return d.dialled() >= 2 })
	// The coordinator's end may finish its half before the runner refuses;
	// the runner closes, so nothing stays parked to take a job.
	time.Sleep(100 * time.Millisecond)
	d.hub.TakeWait = 200 * time.Millisecond
	if _, err := (coordinator.RemoteRunner{Hub: d.hub}).Run(context.Background(), "r", "acct1", jobDirs(t)); err == nil {
		t.Fatal("a job ran on a runner that refused its coordinator")
	}
	select {
	case <-d.sandbox.sawJob:
		t.Fatal("a job reached the supervisor")
	default:
	}
}

func TestARunnerDialsAgainWhenItsLinksDrop(t *testing.T) {
	d := startDialIn(t, unattested(t), unattested(t), link.ParkFor)
	waitFor(t, "two parked links", func() bool { return parked(d.hub) == 2 })
	d.dropAll()
	waitFor(t, "the hub to drop them", func() bool { return d.dialled() > 2 || !d.hub.Ready() })
	waitFor(t, "two links again", func() bool { return parked(d.hub) == 2 && d.dialled() >= 4 })
	if _, err := (coordinator.RemoteRunner{Hub: d.hub}).Run(context.Background(), "r", "acct1", jobDirs(t)); err != nil {
		t.Fatal(err)
	}
	<-d.sandbox.sawJob
}

func TestAParkedLinkWithNoJobIsDialledAgain(t *testing.T) {
	d := startDialIn(t, unattested(t), unattested(t), 200*time.Millisecond)
	waitFor(t, "links parked out and dialled again", func() bool { return d.dialled() >= 6 })
	if n := parked(d.hub); n > 2 {
		t.Errorf("%d links parked with 2 spares", n)
	}
	waitFor(t, "a parked link", d.hub.Ready)
	if _, err := (coordinator.RemoteRunner{Hub: d.hub}).Run(context.Background(), "r", "acct1", jobDirs(t)); err != nil {
		t.Fatal(err)
	}
	<-d.sandbox.sawJob
}

func TestALinkPastItsFreshnessIsntHandedOut(t *testing.T) {
	stale := unattested(t)
	stale.Endorse = func(doc, nonce []byte) (link.Endorsement, error) {
		e, err := link.CheckUnattestedKey(doc, nonce)
		e.Fresh = time.Now().Add(-time.Second)
		return e, err
	}
	d := startDialIn(t, stale, unattested(t), link.ParkFor)
	waitFor(t, "a parked link", d.hub.Ready)
	d.hub.TakeWait = 300 * time.Millisecond
	if _, err := (coordinator.RemoteRunner{Hub: d.hub}).Run(context.Background(), "r", "acct1", jobDirs(t)); !errors.Is(err, coordinator.ErrNoRunnerLink) {
		t.Fatalf("%v", err)
	}
	select {
	case <-d.sandbox.sawJob:
		t.Fatal("a job went over a stale link")
	default:
	}
}
