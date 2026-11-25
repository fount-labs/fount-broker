package link

import (
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// The accepting end of a link takes anyone with a key until their document
// checks. A Gate bounds how many of them it holds at once: MaxHandshakes in
// all, MaxHandshakesPerSource from one source. With frame's buffers growing
// only as bytes come and MaxAttestation, that bounds what unproven peers make
// it hold, and the accepting end's deadlines (link.go) how long.
//
// So that peers holding places can't keep a runner out (2026-11-25
// re-review, N1), a full Gate gives a newcomer the place of the oldest
// handshake whose peer hasn't begun its document EvictAfter after it came:
// TLS and an attestation from a warm socket take far less. To keep every
// place from a runner a peer must then begin a new handshake every
// EvictAfter/MaxHandshakes (16 a second), or stream documents at
// MinAttestationRate into every place (8 MiB/s), not just hold them.
const (
	MaxHandshakes          = 32
	MaxHandshakesPerSource = 4
	EvictAfter             = 2 * time.Second
)

// A Gate counts handshakes in flight. The zero Gate is MaxHandshakes and
// MaxHandshakesPerSource.
type Gate struct {
	// Max and PerSource replace MaxHandshakes and MaxHandshakesPerSource
	// when set.
	Max, PerSource int

	mu       sync.Mutex
	total    int
	bySource map[string]int
	passes   map[*Pass]struct{}
	now      func() time.Time
}

// A Pass is one handshake's place in a Gate.
type Pass struct {
	g       *Gate
	source  string
	at      time.Time
	evict   func()
	began   atomic.Bool
	release sync.Once
}

// Enter takes a place for a handshake from source, "" when it can't be told,
// which counts only toward Max. It reports false when there is none; done
// gives the place back. Its place is never given to a newcomer.
func (g *Gate) Enter(source string) (done func(), ok bool) {
	p, ok := g.Admit(source, nil)
	if !ok {
		return nil, false
	}
	return p.Done, true
}

// Admit is Enter for a handshake evict stops: when the Gate is full, a
// newcomer takes the place of the oldest one whose peer hasn't begun its
// document (Pass.Begin) EvictAfter after it came, and evict is called.
func (g *Gate) Admit(source string, evict func()) (*Pass, bool) {
	g.mu.Lock()
	max, per := g.Max, g.PerSource
	if max <= 0 {
		max = MaxHandshakes
	}
	if per <= 0 {
		per = MaxHandshakesPerSource
	}
	now := time.Now()
	if g.now != nil {
		now = g.now()
	}
	if source != "" && g.bySource[source] >= per {
		g.mu.Unlock()
		return nil, false
	}
	var victim *Pass
	if g.total >= max {
		for p := range g.passes {
			if p.evict == nil || p.began.Load() || now.Sub(p.at) < EvictAfter {
				continue
			}
			if victim == nil || p.at.Before(victim.at) {
				victim = p
			}
		}
		if victim == nil {
			g.mu.Unlock()
			return nil, false
		}
		victim.release.Do(func() { g.leave(victim) })
	}
	if g.bySource == nil {
		g.bySource = map[string]int{}
		g.passes = map[*Pass]struct{}{}
	}
	p := &Pass{g: g, source: source, at: now, evict: evict}
	g.total++
	g.passes[p] = struct{}{}
	if source != "" {
		g.bySource[source]++
	}
	g.mu.Unlock()
	if victim != nil {
		victim.evict()
	}
	return p, true
}

// leave gives p's place back. Called with g.mu held, once.
func (g *Gate) leave(p *Pass) {
	g.total--
	delete(g.passes, p)
	if p.source != "" {
		if g.bySource[p.source]--; g.bySource[p.source] <= 0 {
			delete(g.bySource, p.source)
		}
	}
}

// Begin says the peer has begun its document: its place is no longer given
// to a newcomer. Safe on a nil Pass.
func (p *Pass) Begin() {
	if p != nil {
		p.began.Store(true)
	}
}

// Done gives the place back; later calls do nothing.
func (p *Pass) Done() {
	p.release.Do(func() {
		p.g.mu.Lock()
		defer p.g.mu.Unlock()
		p.g.leave(p)
	})
}

// Evictable is a connection a Pass's evict closes, which may come only after
// the Pass: Set closes it at once when the Pass was evicted before.
type Evictable struct {
	mu      sync.Mutex
	conn    net.Conn
	evicted bool
}

// Evict closes the connection, now or once it is Set.
func (e *Evictable) Evict() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.evicted = true
	if e.conn != nil {
		e.conn.Close()
	}
}

// Set is the connection to close. It reports false, having closed it, when
// the Pass was already evicted.
func (e *Evictable) Set(c net.Conn) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.conn = c
	if e.evicted {
		c.Close()
		return false
	}
	return true
}

// Source is where r came from, for a Gate: r's own peer when it is a public
// address, by its /64 for IPv6, and "" otherwise, which counts only toward
// the total. A request through the shim comes from shim-net, a private
// address, and the shim's X-Forwarded-For isn't trusted: Tinfoil doesn't
// document whether the shim sets it or passes a client's own on, so a
// client could name any source and take every source's share.
func Source(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	switch {
	case ip == nil, ip.IsLoopback(), ip.IsPrivate(), ip.IsLinkLocalUnicast(), ip.IsUnspecified():
		return ""
	case ip.To4() != nil:
		return ip.To4().String()
	}
	return (&net.IPNet{IP: ip.Mask(net.CIDRMask(64, 128)), Mask: net.CIDRMask(64, 128)}).String()
}
