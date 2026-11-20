package coordinator

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/fount-labs/fount-broker/internal/link"
)

// RunnerHub holds the links runner enclaves dialled in to the coordinator
// (launch plan work R): a runner can't be on the coordinator's measured
// egress allowlist when it may be stopped or not made yet, so it opens the
// link, and the coordinator sends a job over it as it would over one it
// dialled. Each link carries one job; a runner keeps a few parked, waiting,
// and dials another for each one a job takes.
//
// Both ends check each other as on a dialled link: the hub's Side checks the
// runner's document against the runner repo, and the runner checks the
// coordinator's. A parked link is handed out only within link.ParkFor less a
// minute of its handshake, and before its verification's freshness deadline.
//
// The hub answers on link.Path for link.DialInProtocol, on the listener the
// enclave's shim exposes. While nothing is parked the Pool hands out no slot
// (Ready), so jobs and intake wait in the queue.
type RunnerHub struct {
	Side *link.Side
	// Changed, if set, is called when a runner's first link parks, so queued
	// jobs and waiting intake get another look.
	Changed func()
	// TakeWait bounds how long Take waits for a parked link. Zero is
	// DefaultTakeWait.
	TakeWait time.Duration

	mu      sync.Mutex
	parked  []*parkedLink
	busy    int
	runners map[string]*hubRunner
	arrived chan struct{} // closed and replaced when a link parks
	closed  bool
	ctx     context.Context
	cancel  context.CancelFunc
}

// DefaultTakeWait is long enough for a runner to dial a new link when a job
// took its last parked one.
const DefaultTakeWait = 2 * time.Minute

// parkedLink is a link with no job yet. watch reads it until it's taken: a
// runner sends nothing on a parked link, so anything it reads ends it.
type parkedLink struct {
	conn    net.Conn
	runner  string // the hubRunner key
	expires time.Time
	taken   bool
	watched chan error // the watch's end
}

// hubRunner is one runner boot, by its attested link key.
type hubRunner struct {
	Name   string    `json:"name,omitempty"` // its own claim, unattested
	Key    string    `json:"key"`            // the attested link key's first bytes, hex
	Since  time.Time `json:"since"`
	Parked int       `json:"parked"`
	Busy   int       `json:"busy"`
}

func NewRunnerHub(side *link.Side) *RunnerHub {
	ctx, cancel := context.WithCancel(context.Background())
	return &RunnerHub{Side: side, runners: map[string]*hubRunner{}, arrived: make(chan struct{}), ctx: ctx, cancel: cancel}
}

var ErrNoRunnerLink = errors.New("no runner enclave has a link to the coordinator")

func (h *RunnerHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != link.Path {
		http.NotFound(w, r)
		return
	}
	name := r.Header.Get(link.NameHeader)
	if len(name) > 253 {
		name = name[:253]
	}
	conn, ok := link.Upgrade(w, r, link.DialInProtocol)
	if !ok {
		return
	}
	go h.admit(conn, name)
}

// admit runs the handshake on a runner's connection and parks it.
func (h *RunnerHub) admit(raw net.Conn, name string) {
	start := time.Now()
	conn, e, err := h.Side.ServerEndorsed(h.ctx, raw)
	if err != nil {
		raw.Close()
		log.Printf("runner link from %s (%q): %v", raw.RemoteAddr(), name, err)
		return
	}
	expires := start.Add(link.ParkFor - time.Minute)
	if !e.Fresh.IsZero() && e.Fresh.Before(expires) {
		expires = e.Fresh
	}
	key := hex.EncodeToString(e.Key[:8])
	p := &parkedLink{conn: conn, runner: key, expires: expires, watched: make(chan error, 1)}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		conn.Close()
		return
	}
	first := len(h.parked) == 0 && h.busy == 0
	r := h.runners[key]
	if r == nil {
		r = &hubRunner{Name: name, Key: key, Since: time.Now().UTC()}
		h.runners[key] = r
		log.Printf("runner %s (%q) linked in", key, name)
	}
	r.Parked++
	h.parked = append(h.parked, p)
	close(h.arrived)
	h.arrived = make(chan struct{})
	h.mu.Unlock()
	go h.watch(p)
	if first && h.Changed != nil {
		h.Changed()
	}
}

// watch reads a parked link until Take interrupts it. Anything else that
// ends the read, the runner closing, a dead link or bytes it shouldn't send,
// drops the link.
func (h *RunnerHub) watch(p *parkedLink) {
	var b [1]byte
	_, err := p.conn.Read(b[:])
	if err == nil {
		err = errors.New("the runner sent on a parked link")
	}
	h.mu.Lock()
	taken := p.taken
	if !taken {
		h.unpark(p, false)
	}
	h.mu.Unlock()
	if !taken {
		p.conn.Close()
	}
	p.watched <- err
}

// unpark removes p from the parked links, and counts it busy if it's taken
// for a job. It holds h.mu.
func (h *RunnerHub) unpark(p *parkedLink, busy bool) {
	i := slices.Index(h.parked, p)
	if i < 0 {
		return
	}
	h.parked = slices.Delete(h.parked, i, i+1)
	if busy {
		h.busy++
		h.forget(p.runner, -1, 1)
		return
	}
	h.forget(p.runner, -1, 0)
}

// forget changes a runner's counts and drops it once it has no links. It
// holds h.mu.
func (h *RunnerHub) forget(key string, parked, busy int) {
	r := h.runners[key]
	if r == nil {
		return
	}
	r.Parked += parked
	r.Busy += busy
	if r.Parked == 0 && r.Busy == 0 {
		delete(h.runners, key)
		log.Printf("runner %s (%q) has no links left", key, r.Name)
	}
}

// Ready reports whether any runner has a link, parked or carrying a job: the
// Pool's gate.
func (h *RunnerHub) Ready() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.parked) > 0 || h.busy > 0
}

// Take hands out a parked link for one job, waiting up to TakeWait for one.
// Closing it ends the job's link.
func (h *RunnerHub) Take(ctx context.Context) (net.Conn, error) {
	wait := h.TakeWait
	if wait == 0 {
		wait = DefaultTakeWait
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		h.mu.Lock()
		if h.closed {
			h.mu.Unlock()
			return nil, ErrNoRunnerLink
		}
		now := time.Now()
		var p *parkedLink
		for len(h.parked) > 0 {
			// The newest has the most time left.
			p = h.parked[len(h.parked)-1]
			if now.Before(p.expires) {
				break
			}
			h.unpark(p, false)
			p.taken = true
			p.conn.Close()
			p = nil
		}
		if p != nil {
			p.taken = true
			h.unpark(p, true)
		}
		arrived := h.arrived
		h.mu.Unlock()
		if p != nil {
			conn, err := h.claim(p)
			if err == nil {
				return conn, nil
			}
			log.Printf("runner %s: a parked link was gone: %v", p.runner, err)
			continue
		}
		select {
		case <-arrived:
		case <-timer.C:
			return nil, fmt.Errorf("%w for %s", ErrNoRunnerLink, wait)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// claim stops p's watch and gives its link to a job, unless the watch had
// already seen it end.
func (h *RunnerHub) claim(p *parkedLink) (net.Conn, error) {
	p.conn.SetReadDeadline(time.Now())
	err := <-p.watched
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		p.conn.Close()
		h.done(p.runner)
		return nil, err
	}
	p.conn.SetReadDeadline(time.Time{})
	return &busyLink{Conn: p.conn, done: func() { h.done(p.runner) }}, nil
}

func (h *RunnerHub) done(key string) {
	h.mu.Lock()
	h.busy--
	h.forget(key, 0, -1)
	h.mu.Unlock()
}

// busyLink is a taken link; closing it counts its job's end once.
type busyLink struct {
	net.Conn
	once sync.Once
	done func()
}

func (b *busyLink) Close() error {
	err := b.Conn.Close()
	b.once.Do(b.done)
	return err
}

// RunnerStatus is one linked runner, as /status shows it.
type RunnerStatus = hubRunner

// Runners are the runners with links, oldest first.
func (h *RunnerHub) Runners() []RunnerStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]RunnerStatus, 0, len(h.runners))
	for _, r := range h.runners {
		out = append(out, *r)
	}
	slices.SortFunc(out, func(a, b RunnerStatus) int { return a.Since.Compare(b.Since) })
	return out
}

// Close drops every parked link and refuses new ones. Links carrying jobs
// end with their jobs.
func (h *RunnerHub) Close() {
	h.mu.Lock()
	h.closed = true
	parked := slices.Clone(h.parked)
	h.mu.Unlock()
	h.cancel()
	for _, p := range parked {
		p.conn.Close()
	}
}
