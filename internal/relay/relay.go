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
	// Handshakes bounds the links Serve is setting up, whose peers haven't
	// proved their release yet (link.Gate).
	Handshakes link.Gate

	mu sync.Mutex
	// bound is the account a coordinator's bind frame gave this runner for
	// its boot (dialin.go), empty for a pool runner.
	bound string
}

// errOtherAccount is a job or bind for an account this runner isn't bound to.
var errOtherAccount = errors.New("this runner serves one team this boot, and it isn't this one")

// bind locks the runner to account for the rest of the process, which is the
// boot: the broker isn't restarted alone in an enclave, and if it were, the
// coordinator still holds the binding for this enclave's link key.
func (r *Relay) bind(account string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.bound != "" && r.bound != account {
		return errOtherAccount
	}
	if r.bound == "" {
		log.Printf("bound to a team for this boot")
	}
	r.bound = account
	return nil
}

// Bound is the account the runner is bound to, or empty.
func (r *Relay) Bound() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bound
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
				// The shim is every peer's source here: only the total counts.
				pass, ok := r.Handshakes.Admit("", func() { conn.Close() })
				if !ok {
					log.Printf("link from %s: too many links being set up", conn.RemoteAddr())
					return
				}
				tc, _, err := r.Link.ServerGated(ctx, conn, pass)
				pass.Done()
				if err != nil {
					log.Printf("link from %s: %v", conn.RemoteAddr(), err)
					return
				}
				defer tc.Close()
				conn = tc
			}
			if err := r.handle(ctx, conn, headerTimeout, nil); err != nil {
				log.Printf("job: %v", err)
				w := frame.NewWriter(conn)
				jobwire.Send(w, jobwire.Reply{Kind: jobwire.KindError, Message: err.Error()}, nil)
			}
		})
	}
}

// handle runs the job conn carries, whose first frame comes within wait.
// started, if set, is called once it has.
func (r *Relay) handle(ctx context.Context, conn net.Conn, wait time.Duration, started func()) error {
	conn.SetReadDeadline(time.Now().Add(wait))
	first, err := frame.Read(conn)
	if err != nil {
		return err
	}
	conn.SetReadDeadline(time.Time{})
	if started != nil {
		started()
	}
	return r.run(ctx, conn, first)
}

// run runs the job whose first frame is first.
func (r *Relay) run(ctx context.Context, conn net.Conn, first frame.Frame) error {
	job, err := jobwire.DecodeJob(first, jobwire.FromCoordinator)
	if err != nil {
		return err
	}
	bound := r.Bound()
	if bound != "" && job.Account != bound {
		return errOtherAccount
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	id := "j-" + hex.EncodeToString(b[:])
	// Intake has no broker socket: it holds no credentials and reaches
	// nothing.
	if job.Mode != jobwire.ModeIntake {
		stop, err := r.openSocket(ctx, id, job.Credentials)
		if err != nil {
			return err
		}
		defer stop()
	}

	var d net.Dialer
	sup, err := d.DialContext(ctx, "unix", filepath.Join(r.Sockets, SupervisorSocket))
	if err != nil {
		return fmt.Errorf("the supervisor isn't taking jobs: %w", err)
	}
	defer sup.Close()
	if err := jobwire.Send(frame.NewWriter(sup), jobwire.Job{Kind: jobwire.KindJob, Mode: job.Mode, ID: id, Account: job.Account, Bound: bound != ""}, first.Body); err != nil {
		return err
	}
	log.Printf("job %s: relaying", id)
	start := time.Now()
	// The job ends when the supervisor's replies do. The coordinator closing
	// is a cancel, which the supervisor sees as its side closing. The
	// supervisor refusing a job stops it reading mid-upload; the rest of the
	// upload is drained, so its reason still reaches the coordinator rather
	// than a reset.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		io.Copy(sup, conn)
		sup.(*net.UnixConn).CloseWrite()
		io.Copy(io.Discard, conn)
	}()
	replied := make(chan struct{})
	go func() { defer close(replied); io.Copy(conn, sup) }()
	select {
	case <-replied:
	case <-ctx.Done():
	}
	conn.Close()
	sup.Close()
	<-replied
	<-drained
	log.Printf("job %s: ended after %.1fs", id, time.Since(start).Seconds())
	return nil
}

// openSocket makes job id's socket folder and serves its broker on it, with a
// vault of the job's credentials, until stop.
func (r *Relay) openSocket(ctx context.Context, id string, credentials map[string]string) (stop func(), err error) {
	vault := broker.NewVault()
	for name, value := range credentials {
		vault.Set(policy.Credential(name), value)
	}
	dir := filepath.Join(r.Sockets, id)
	if err := os.Mkdir(dir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, JobSocket)
	l, err := net.Listen("unix", path)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	// The sandbox's user isn't the broker's.
	if err := os.Chmod(path, 0o666); err != nil {
		l.Close()
		os.RemoveAll(dir)
		return nil, err
	}
	jobCtx, cancel := context.WithCancel(ctx)
	served := make(chan struct{})
	go func() {
		defer close(served)
		r.serveJob(jobCtx, l, vault)
	}()
	return func() {
		cancel()
		<-served
		os.RemoveAll(dir)
	}, nil
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
