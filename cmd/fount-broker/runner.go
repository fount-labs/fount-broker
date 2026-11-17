package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/fount-labs/fount-broker/internal/broker"
	"github.com/fount-labs/fount-broker/internal/link"
	"github.com/fount-labs/fount-broker/internal/policy"
	"github.com/fount-labs/fount-broker/internal/registry"
	"github.com/fount-labs/fount-broker/internal/relay"
)

// runner is a Cloud runner enclave's broker (m4-cloud-runners.md §5.1c):
//
//	fount-broker runner --image host/repo@sha256:… --coordinator-repo owner/repo
//	  [--blobs /harness-blobs] [--sockets /sockets] [--listen 127.0.0.1:7400]
//
// It pulls the harness image the supervisor's measured config pins into the
// blobs volume, unless a finished pull is there, then takes jobs from the
// coordinator and relays each to the supervisor (package relay).
// FOUNT_BROKER_REGISTRY_TOKEN is a read-only registry token; without it the
// pull is anonymous.
//
// The job listener is HTTP, behind the enclave's shim: each job is a
// connection upgraded on link.Path (shim paths: /fount-link, /health,
// /status), and
// that connection is the attested link (package link):
// the coordinator must prove it runs a release of --coordinator-repo, and this
// enclave proves itself back with its attested fount-link key. Dev builds also
// take --coordinator-repo unattested, a link no hardware vouches for.
func runner(args []string) error {
	fs := flag.NewFlagSet("runner", flag.ExitOnError)
	image := fs.String("image", os.Getenv("FOUNT_HARNESS_IMAGE"), "harness image, host/repository@sha256:<hex>")
	blobs := fs.String("blobs", "/harness-blobs", "volume the supervisor unpacks the harness from")
	sockets := fs.String("sockets", "/sockets", "volume shared with the supervisor")
	listen := fs.String("listen", "127.0.0.1:7400", "the coordinator's job listener")
	coordinatorRepo := fs.String("coordinator-repo", os.Getenv("FOUNT_COORDINATOR_REPO"), "GitHub repository whose releases the coordinator must run")
	fs.Parse(args)
	side, err := linkSide(*coordinatorRepo)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ref, err := registry.ParseRef(*image)
	if err != nil {
		return err
	}
	base, err := policy.HarnessRegistryBase(ref.Host)
	if err != nil {
		return err
	}
	// The listener comes up before the pull, which takes minutes: the enclave's
	// boot gate needs /health within about a minute, and /status is the only
	// way to see from outside how the pull is going.
	tl, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	status := &pullStatus{State: "pulling", Since: time.Now(),
		supervisor: filepath.Join(*sockets, relay.SupervisorSocket)}
	l := link.NewListener(tl.Addr())
	mux := http.NewServeMux()
	mux.HandleFunc(link.Path, func(w http.ResponseWriter, r *http.Request) {
		if !status.ready() {
			http.Error(w, "the runner isn't ready; see /status", http.StatusServiceUnavailable)
			return
		}
		l.ServeHTTP(w, r)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("/status", status.serve)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(tl)
	defer srv.Close()

	if registry.Complete(*blobs, ref.Digest) {
		log.Printf("%s is already pulled", ref)
		status.done(0)
	} else {
		p := &registry.Puller{
			Base:   base,
			Client: registry.Client(append([]string{ref.Host}, policy.HarnessRegistryRedirectHosts...)...),
			Token:  os.Getenv("FOUNT_BROKER_REGISTRY_TOKEN"),
		}
		for {
			start := time.Now()
			err := p.Pull(ctx, ref, *blobs)
			if err == nil {
				log.Printf("pulled %s in %.0fs", ref, time.Since(start).Seconds())
				status.done(time.Since(start))
				break
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Printf("pull %s: %v; retrying in %s", ref, err, pullRetry)
			status.failed(err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(pullRetry):
			}
		}
	}
	log.Printf("taking jobs on http://%s%s", tl.Addr(), link.Path)
	r := &relay.Relay{Sockets: *sockets, Link: side, NewBroker: func(vault *broker.Vault) *broker.Broker {
		b := broker.New(version, newRoutes(vault), vault)
		b.Locked = true
		return b
	}}
	return r.Serve(ctx, l)
}

const pullRetry = 30 * time.Second

// health is the runner container's healthcheck, so its image needs no HTTP
// client:
//
//	fount-broker health [http://127.0.0.1:7400/health]
//
// It reaches only loopback.
func health(args []string) error {
	url := "http://127.0.0.1:7400/health"
	if len(args) > 0 {
		url = args[0]
	}
	u, err := neturl.Parse(url)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(u.Hostname()); u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("health checks only http://127.0.0.1, not %s", url)
	}
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	return nil
}

// pullStatus is /status: how the harness pull is going, and whether the
// supervisor is taking jobs. It holds nothing secret; a failed pull's error
// names the registry and the image.
//
// The supervisor's socket appears only once it has unpacked the pulled
// harness, so a pulled runner isn't ready until the socket takes a connection.
// The supervisor drops one that sends nothing.
type pullStatus struct {
	mu          sync.Mutex
	State       string    `json:"state"` // pulling, starting (the supervisor isn't up), ready
	Since       time.Time `json:"since"`
	PullSeconds float64   `json:"pullSeconds,omitempty"`
	Failures    int       `json:"failures,omitempty"`
	LastError   string    `json:"lastError,omitempty"`
	Supervisor  string    `json:"supervisor,omitempty"` // why it isn't taking jobs

	pulled     bool
	supervisor string
}

// check updates State from the pull and a dial of the supervisor's socket.
func (s *pullStatus) check() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.pulled {
		return
	}
	c, err := net.DialTimeout("unix", s.supervisor, time.Second)
	if err != nil {
		s.State, s.Supervisor = "starting", err.Error()
		return
	}
	c.Close()
	s.State, s.Supervisor = "ready", ""
}

func (s *pullStatus) ready() bool {
	s.check()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.State == "ready"
}

func (s *pullStatus) done(took time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pulled, s.State, s.PullSeconds = true, "starting", took.Seconds()
}

func (s *pullStatus) failed(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Failures++
	s.LastError = err.Error()
}

func (s *pullStatus) serve(w http.ResponseWriter, _ *http.Request) {
	s.check()
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s)
}
