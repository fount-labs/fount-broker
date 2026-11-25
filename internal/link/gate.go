package link

import (
	"net"
	"net/http"
	"strings"
	"sync"
)

// The accepting end of a link takes anyone with a key until their document
// checks. A Gate bounds how many of them it holds at once: MaxHandshakes in
// all, MaxHandshakesPerSource from one source. With frame's buffers growing
// only as bytes come and MaxAttestation, that bounds what unproven peers make
// it hold, and PeerTimeout how long.
const (
	MaxHandshakes          = 32
	MaxHandshakesPerSource = 4
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
}

// Enter takes a place for a handshake from source, "" when it can't be told,
// which counts only toward Max. It reports false when there is none; done
// gives the place back.
func (g *Gate) Enter(source string) (done func(), ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	max, per := g.Max, g.PerSource
	if max <= 0 {
		max = MaxHandshakes
	}
	if per <= 0 {
		per = MaxHandshakesPerSource
	}
	if g.total >= max || source != "" && g.bySource[source] >= per {
		return nil, false
	}
	if g.bySource == nil {
		g.bySource = map[string]int{}
	}
	g.total++
	if source != "" {
		g.bySource[source]++
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			g.total--
			if source != "" {
				if g.bySource[source]--; g.bySource[source] <= 0 {
					delete(g.bySource, source)
				}
			}
		})
	}, true
}

// Source is where r came from, for a Gate: the address the nearest proxy
// says it took r from, the last X-Forwarded-For entry, when r came through
// one on this host, as the shim's do; otherwise r's own peer. It is "" for a
// proxy that says nothing, whose peers can't be told apart.
func Source(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() && !ip.IsPrivate() {
		return host
	}
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return ""
	}
	entries := strings.Split(values[len(values)-1], ",")
	last := strings.TrimSpace(entries[len(entries)-1])
	if net.ParseIP(last) == nil {
		return ""
	}
	return last
}
