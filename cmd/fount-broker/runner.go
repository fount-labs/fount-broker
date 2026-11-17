package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fount-labs/fount-broker/internal/broker"
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
// Every connection to the job listener is the attested link (package link):
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

	l, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	log.Printf("taking jobs on %s", l.Addr())
	r := &relay.Relay{Sockets: *sockets, Link: side, NewBroker: func(vault *broker.Vault) *broker.Broker {
		b := broker.New(version, newRoutes(vault), vault)
		b.Locked = true
		return b
	}}
	return r.Serve(ctx, l)
}
