// Package relay is the runner enclave's broker side of a Cloud job
// (m4-cloud-runners.md §5.1c). It takes each job from the coordinator, keeps
// the job's credentials and serves them on the job's own broker socket, and
// relays the rest of the job to the supervisor unread.
//
// The supervisor and the broker share one volume, Sockets. The supervisor
// listens on Sockets/supervisor.sock. Each job's socket is
// Sockets/<id>/job.sock, and its sandbox sees only Sockets/<id>, at
// /run/broker. The socket answers in the app's broker protocol, with a vault
// holding only that job's credentials, which the job can't change.
package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fount-labs/fount-broker/internal/broker"
	"github.com/fount-labs/fount-broker/internal/frame"
	"github.com/fount-labs/fount-broker/internal/jobwire"
	"github.com/fount-labs/fount-broker/internal/link"
	"github.com/fount-labs/fount-broker/internal/policy"
)

const (
	SupervisorSocket = "supervisor.sock"
	JobSocket        = "job.sock"
)

type Relay struct {
	Sockets string
	// Link proves each connection's coordinator, and this enclave to it,
	// before a job is read (package link). Nil takes plain connections: tests
	// only.
	Link *link.Side
	// NewBroker makes the broker for one connection on a job's socket. It
	// must set Locked, and give it no mail and no package tunnel.
	NewBroker func(vault *broker.Vault) *broker.Broker
}

const headerTimeout = 30 * time.Second

// Serve takes jobs from the coordinator on l until ctx ends, then waits for
// those running.
func (r *Relay) Serve(ctx context.Context, l net.Listener) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Go(func() {
			defer conn.Close()
			if r.Link != nil {
				tc, err := r.Link.Server(ctx, conn)
				if err != nil {
					log.Printf("link from %s: %v", conn.RemoteAddr(), err)
					return
				}
				defer tc.Close()
				conn = tc
			}
			if err := r.handle(ctx, conn); err != nil {
				log.Printf("job: %v", err)
				w := frame.NewWriter(conn)
				jobwire.Send(w, jobwire.Reply{Kind: jobwire.KindError, Message: err.Error()}, nil)
			}
		})
	}
}

func (r *Relay) handle(ctx context.Context, conn net.Conn) error {
	conn.SetReadDeadline(time.Now().Add(headerTimeout))
	first, err := frame.Read(conn)
	if err != nil {
		return err
	}
	conn.SetReadDeadline(time.Time{})
	job, err := jobwire.DecodeJob(first, jobwire.FromCoordinator)
	if err != nil {
		return err
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	id := "j-" + hex.EncodeToString(b[:])
	vault := broker.NewVault()
	for name, value := range job.Credentials {
		vault.Set(policy.Credential(name), value)
	}

	dir := filepath.Join(r.Sockets, id)
	if err := os.Mkdir(dir, 0o755); err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, JobSocket)
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	// The sandbox's user isn't the broker's.
	if err := os.Chmod(path, 0o666); err != nil {
		l.Close()
		return err
	}
	jobCtx, cancel := context.WithCancel(ctx)
	served := make(chan struct{})
	go func() {
		defer close(served)
		r.serveJob(jobCtx, l, vault)
	}()
	defer func() {
		cancel()
		<-served
	}()

	var d net.Dialer
	sup, err := d.DialContext(ctx, "unix", filepath.Join(r.Sockets, SupervisorSocket))
	if err != nil {
		return fmt.Errorf("the supervisor isn't taking jobs: %w", err)
	}
	defer sup.Close()
	if err := jobwire.Send(frame.NewWriter(sup), jobwire.Job{Kind: jobwire.KindJob, Mode: job.Mode, ID: id, Account: job.Account}, first.Body); err != nil {
		return err
	}
	log.Printf("job %s: relaying", id)
	start := time.Now()
	// Either side closing ends the job: the coordinator's is a cancel, which
	// the supervisor sees as its side closing.
	done := make(chan struct{}, 2)
	go func() { io.Copy(sup, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, sup); done <- struct{}{} }()
	select {
	case <-done:
	case <-ctx.Done():
	}
	conn.Close()
	sup.Close()
	<-done
	log.Printf("job %s: ended after %.1fs", id, time.Since(start).Seconds())
	return nil
}

// serveJob answers on a job's socket until ctx ends, one broker per
// connection, all holding the job's vault.
func (r *Relay) serveJob(ctx context.Context, l net.Listener, vault *broker.Vault) {
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := l.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("job socket: %v", err)
			}
			return
		}
		wg.Go(func() {
			defer c.Close()
			stop := context.AfterFunc(ctx, func() { c.Close() })
			defer stop()
			b := r.NewBroker(vault)
			if !b.Locked || b.Mail != nil || b.ProxyURL != "" {
				log.Printf("job socket: refusing a broker that isn't locked down")
				return
			}
			b.Serve(ctx, c, c)
		})
	}
}
