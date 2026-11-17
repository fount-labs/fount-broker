package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
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
// connection upgraded on link.Path (shim paths: /fount-link, /health), and
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
	if registry.Complete(*blobs, ref.Digest) {
		log.Printf("%s is already pulled", ref)
	} else {
		p := &registry.Puller{
			Base:   base,
			Client: registry.Client(append([]string{ref.Host}, policy.HarnessRegistryRedirectHosts...)...),
			Token:  os.Getenv("FOUNT_BROKER_REGISTRY_TOKEN"),
		}
		start := time.Now()
		if err := p.Pull(ctx, ref, *blobs); err != nil {
			return err
		}
		log.Printf("pulled %s in %.0fs", ref, time.Since(start).Seconds())
	}

	tl, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	l := link.NewListener(tl.Addr())
	mux := http.NewServeMux()
	mux.Handle(link.Path, l)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(tl)
	defer srv.Close()
	log.Printf("taking jobs on http://%s%s", tl.Addr(), link.Path)
	r := &relay.Relay{Sockets: *sockets, Link: side, NewBroker: func(vault *broker.Vault) *broker.Broker {
		b := broker.New(version, newRoutes(vault), vault)
		b.Locked = true
		return b
	}}
	return r.Serve(ctx, l)
}
