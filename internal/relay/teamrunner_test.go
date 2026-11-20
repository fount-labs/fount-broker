package relay

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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

const (
	team      = "tm_0123456789abcdef01234567"
	teamName  = "runner-dev-tm-0123456789abcdef01234567"
	otherTeam = "tm_ffffffffffffffffffffffff"
)

var testRelease = link.Release{Repo: "fount-labs/fount-cloud-runner", Tag: "v0.4.0", Digest: "5f2c"}

// teamHub is a coordinator's RunnerHub with team runners on, behind HTTP.
type teamHub struct {
	hub *coordinator.RunnerHub
	url string
}

func startTeamHub(t *testing.T) *teamHub {
	t.Helper()
	side := unattested(t)
	// As a Tinfoil checker would, the hub's end says what release it verified.
	side.Endorse = func(doc, nonce []byte) (link.Endorsement, error) {
		e, err := link.CheckUnattestedKey(doc, nonce)
		e.Release = testRelease
		return e, err
	}
	h := coordinator.NewRunnerHub(side)
	h.TeamStage = "dev"
	h.TakeWait = 5 * time.Second
	web := httptest.NewServer(h)
	t.Cleanup(func() { h.Close(); web.Close() })
	return &teamHub{hub: h, url: web.URL}
}

// teamEnd is one runner enclave, with its own link key, dialling a hub.
type teamEnd struct {
	relay   *Relay
	sandbox *fakeSandbox
	mu      sync.Mutex
	name    string
	dials   atomic.Int32
}

func (e *teamEnd) rename(name string) {
	e.mu.Lock()
	e.name = name
	e.mu.Unlock()
}

func startRunner(t *testing.T, h *teamHub, name string, parkFor time.Duration) *teamEnd {
	t.Helper()
	sockets, err := os.MkdirTemp("/tmp", "relay")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockets) })
	ctx, cancel := context.WithCancel(context.Background())
	e := &teamEnd{name: name, sandbox: &fakeSandbox{t: t, sawJob: make(chan supervisor.Job, 8)}}
	supL, err := net.Listen("unix", filepath.Join(sockets, SupervisorSocket))
	if err != nil {
		t.Fatal(err)
	}
	srv := &supervisor.Server{Sandboxes: e.sandbox, JobsDir: t.TempDir(), Sockets: sockets, MaxJobs: 4, Timeout: time.Minute}
	supDone := make(chan struct{})
	go func() { srv.Serve(ctx, supL); close(supDone) }()
	e.relay = &Relay{Sockets: sockets, Link: unattested(t), NewBroker: func(v *broker.Vault) *broker.Broker {
		b := broker.New("test", map[string]route.Route{}, v)
		b.Locked = true
		return b
	}}
	done := make(chan struct{})
	go func() {
		e.relay.ServeDialIn(ctx, DialIn{
			Dial: func(ctx context.Context) (net.Conn, error) {
				e.mu.Lock()
				header := http.Header{link.NameHeader: {e.name}}
				e.mu.Unlock()
				e.dials.Add(1)
				return link.DialUpgradeHeader(ctx, h.url, link.Path, link.DialInProtocol, header)
			},
			Spare: 2, Max: 4, ParkFor: parkFor,
		})
		close(done)
	}()
	t.Cleanup(func() { cancel(); <-done; <-supDone })
	return e
}

func TestATeamRunnerIsBoundToItsTeamByItsName(t *testing.T) {
	h := startTeamHub(t)
	e := startRunner(t, h, teamName, link.ParkFor)
	waitFor(t, "the team's runner", func() bool { return h.hub.ReadyFor(team) })
	waitFor(t, "the runner to bind", func() bool { return e.relay.Bound() == team })
	if h.hub.ReadyFor("acct1") || h.hub.ReadyFor(otherTeam) {
		t.Fatal("a team's runner is ready for another account")
	}
	runners := h.hub.Runners()
	if len(runners) != 1 || !runners[0].Team || runners[0].Name != "" {
		t.Fatalf("/status shows %+v", runners)
	}
	l := h.hub.TeamLinks()[team]
	if !l.Connected || l.Last.IsZero() {
		t.Fatalf("team link %+v", l)
	}
}

func TestJobsGoOnlyToTheRunnerTheyArePlacedOn(t *testing.T) {
	h := startTeamHub(t)
	pool := startRunner(t, h, "runner-a", link.ParkFor)
	mine := startRunner(t, h, teamName, link.ParkFor)
	waitFor(t, "both runners", func() bool { return h.hub.ReadyFor(team) && h.hub.ReadyFor("acct1") })
	runner := coordinator.RemoteRunner{Hub: h.hub}
	ranOn := func(r coordinator.RunResult, kind string) {
		t.Helper()
		want := coordinator.RunnerEnclave{Kind: kind, Repo: testRelease.Repo, Tag: testRelease.Tag, Digest: testRelease.Digest}
		if r.Enclave == nil || *r.Enclave != want {
			t.Fatalf("the job ran on %+v, want %+v", r.Enclave, want)
		}
	}
	for range 3 {
		result, err := runner.Run(context.Background(), "r", team, jobDirs(t))
		if err != nil {
			t.Fatal(err)
		}
		ranOn(result, "team")
		select {
		case <-mine.sandbox.sawJob:
		case <-pool.sandbox.sawJob:
			t.Fatal("a team's job ran on the pool")
		}
		result, err = runner.Run(context.Background(), "r", "acct1", jobDirs(t))
		if err != nil {
			t.Fatal(err)
		}
		ranOn(result, "pool")
		select {
		case <-pool.sandbox.sawJob:
		case <-mine.sandbox.sawJob:
			t.Fatal("a solo job ran on a team's runner")
		}
	}
	if pool.relay.Bound() != "" {
		t.Fatal("the pool runner bound")
	}
	if h.hub.TeamLinks()[team].Last.IsZero() {
		t.Fatal("no activity")
	}
}

func TestATeamsJobWaitsPastTakeWaitForItsRunner(t *testing.T) {
	h := startTeamHub(t)
	h.hub.TakeWait = 100 * time.Millisecond
	pool := startRunner(t, h, "runner-a", link.ParkFor)
	waitFor(t, "the pool runner", func() bool { return h.hub.ReadyFor("acct1") })
	done := make(chan error, 1)
	go func() {
		_, err := coordinator.RemoteRunner{Hub: h.hub, Timeout: 30 * time.Second}.Run(context.Background(), "r", team, jobDirs(t))
		done <- err
	}()
	time.Sleep(500 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("a team's job gave up while its runner was stopped: %v", err)
	default:
	}
	mine := startRunner(t, h, teamName, link.ParkFor)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-mine.sandbox.sawJob:
	case <-pool.sandbox.sawJob:
		t.Fatal("it ran on the pool")
	}
}

func TestATeamRunnerRefusesAnotherAccountsJob(t *testing.T) {
	h := startTeamHub(t)
	e := startRunner(t, h, teamName, link.ParkFor)
	waitFor(t, "the runner to bind", func() bool { return e.relay.Bound() == team })
	// As a coordinator that got placement wrong would: a team's link, another
	// account's job.
	conn, err := h.hub.Take(context.Background(), team)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := jobwire.Send(frame.NewWriter(conn), jobwire.Job{Kind: jobwire.KindJob, Account: "acct1"}, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	f, err := frame.Read(conn)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := jobwire.DecodeReply(f.Header)
	if err != nil || reply.Kind != jobwire.KindError || !strings.Contains(reply.Message, "serves one team") {
		t.Fatalf("%+v %v", reply, err)
	}
	select {
	case <-e.sandbox.sawJob:
		t.Fatal("the job reached the sandbox")
	default:
	}
	// Nor does it take a bind to another team.
	if err := e.relay.bind(otherTeam); err == nil || e.relay.Bound() != team {
		t.Fatalf("rebound: %v", err)
	}
}

func TestARunnerThatChangesItsNameIsRefused(t *testing.T) {
	h := startTeamHub(t)
	e := startRunner(t, h, teamName, 300*time.Millisecond)
	waitFor(t, "the team's runner", func() bool { return h.hub.ReadyFor(team) })
	// The host renames it: its key's links under the new name are refused,
	// and the old ones park out.
	e.rename("runner-a")
	before := e.dials.Load()
	waitFor(t, "renamed links refused", func() bool { return e.dials.Load() > before+4 && len(h.hub.Runners()) == 0 })
	if h.hub.ReadyFor("acct1") {
		t.Fatal("a team's runner became a pool runner")
	}
	e.rename(teamName)
	waitFor(t, "the team's runner again", func() bool { return h.hub.ReadyFor(team) })
}
