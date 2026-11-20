package relay

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/fount-labs/fount-broker/internal/frame"
	"github.com/fount-labs/fount-broker/internal/jobwire"
	"github.com/fount-labs/fount-broker/internal/link"
)

// DialIn is how a runner takes jobs when it dials the coordinator (launch
// plan work R): the coordinator's measured allowlist can't name a runner that
// may be stopped, so the runner opens each link. It keeps Spare links parked,
// each waiting for one job, and dials another whenever a job takes one, up to
// Max links at once. A link with no job for link.ParkFor is closed and
// dialled again, so the coordinator's check of this enclave is never old.
type DialIn struct {
	// Dial opens a connection to the coordinator's link endpoint, ready for
	// the handshake: link.DialUpgradeHeader with link.DialInProtocol.
	Dial func(ctx context.Context) (net.Conn, error)
	// Ready reports whether this runner can take a job: it dials only then.
	// Nil is always.
	Ready func() bool
	// Spare is the links kept parked; Max caps links at once, parked and
	// busy. Zero is DefaultSpare and DefaultMax.
	Spare, Max int
	// ParkFor is link.ParkFor; tests shorten it.
	ParkFor time.Duration
}

const (
	DefaultSpare = 2
	// DefaultMax is the supervisor's --max-jobs in the runner's config.
	DefaultMax = 16
)

const (
	dialBackoffMin = time.Second
	dialBackoffMax = 30 * time.Second
	readyPoll      = 2 * time.Second
)

// errParkedOut is a parked link that waited ParkFor with no job.
var errParkedOut = errors.New("no job came on the parked link")

// ServeDialIn takes jobs over links it dials until ctx ends, then waits for
// those running. Each link is checked both ways (Relay.Link) before a job
// is read.
func (r *Relay) ServeDialIn(ctx context.Context, d DialIn) error {
	if d.Spare == 0 {
		d.Spare = DefaultSpare
	}
	if d.Max == 0 {
		d.Max = DefaultMax
	}
	if d.ParkFor == 0 {
		d.ParkFor = link.ParkFor
	}
	var (
		mu          sync.Mutex
		idle, total int
		changed     = make(chan struct{}, 1)
		wg          sync.WaitGroup
	)
	notify := func() {
		select {
		case changed <- struct{}{}:
		default:
		}
	}
	defer wg.Wait()
	for {
		mu.Lock()
		for idle < d.Spare && total < d.Max {
			idle++
			total++
			wg.Go(func() {
				started := func() {
					mu.Lock()
					idle--
					mu.Unlock()
					notify()
				}
				r.dialLoop(ctx, d, started)
				mu.Lock()
				total--
				mu.Unlock()
				notify()
			})
		}
		mu.Unlock()
		select {
		case <-ctx.Done():
			return nil
		case <-changed:
		}
	}
}

// dialLoop keeps one link parked until a job comes on it, then runs the job
// and returns. A link that fails or parks out is dialled again, with backoff
// after failures.
func (r *Relay) dialLoop(ctx context.Context, d DialIn, started func()) {
	backoff := dialBackoffMin
	for ctx.Err() == nil {
		if d.Ready != nil && !d.Ready() {
			sleep(ctx, readyPoll)
			continue
		}
		ran, err := r.dialOne(ctx, d, started)
		if ran {
			if err != nil {
				log.Printf("job: %v", err)
			}
			return
		}
		switch {
		case ctx.Err() != nil:
			return
		case errors.Is(err, errParkedOut):
			backoff = dialBackoffMin
			continue
		}
		log.Printf("link to the coordinator: %v; again in %s", err, backoff)
		sleep(ctx, backoff)
		backoff = min(backoff*2, dialBackoffMax)
	}
}

// dialOne dials, parks and, if a job comes, runs it. ran reports a job came.
func (r *Relay) dialOne(ctx context.Context, d DialIn, started func()) (ran bool, err error) {
	conn, err := d.Dial(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	if r.Link != nil {
		tc, err := r.Link.Client(ctx, conn)
		if err != nil {
			return false, err
		}
		defer tc.Close()
		conn = tc
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	err = r.handle(ctx, conn, d.ParkFor, func() { ran = true; started() })
	if !ran {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return false, errParkedOut
		}
		return false, err
	}
	if err != nil {
		jobwire.Send(frame.NewWriter(conn), jobwire.Reply{Kind: jobwire.KindError, Message: err.Error()}, nil)
	}
	return true, err
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
