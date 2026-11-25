package link

import (
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAGateBoundsTheTotalAndEachSource(t *testing.T) {
	g := &Gate{Max: 3, PerSource: 2}
	a1, ok1 := g.Enter("a")
	_, ok2 := g.Enter("a")
	if _, ok := g.Enter("a"); !ok1 || !ok2 || ok {
		t.Fatalf("a source past its share: %v %v %v", ok1, ok2, ok)
	}
	_, ok := g.Enter("")
	if !ok {
		t.Fatal("an untold source under the total")
	}
	if _, ok := g.Enter("b"); ok {
		t.Fatal("past the total")
	}
	a1()
	a1()
	if _, ok := g.Enter("b"); !ok {
		t.Fatal("a place given back isn't taken again")
	}
	if _, ok := g.Enter("c"); ok {
		t.Fatal("done twice gave back two places")
	}
}

// The shim's X-Forwarded-For isn't trusted (2026-11-25 re-review, N1): a
// peer through it counts only toward the total; a public peer is its own
// address, an IPv6 one its /64.
func TestSourceTrustsNoForwardedHeader(t *testing.T) {
	for _, c := range []struct{ remote, xff, want string }{
		{"203.0.113.7:4000", "198.51.100.1", "203.0.113.7"},
		{"127.0.0.1:4000", "198.51.100.1, 203.0.113.7", ""},
		{"10.0.0.2:4000", "203.0.113.8", ""},
		{"127.0.0.1:4000", "", ""},
		{"[2001:db8:1:2:3:4:5:6]:4000", "", "2001:db8:1:2::/64"},
		{"[2001:db8:1:2:ffff::9]:4000", "", "2001:db8:1:2::/64"},
		{"[::ffff:203.0.113.9]:4000", "", "203.0.113.9"},
	} {
		r := &http.Request{RemoteAddr: c.remote, Header: http.Header{}}
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := Source(r); got != c.want {
			t.Errorf("%s via %q: %q, want %q", c.remote, c.xff, got, c.want)
		}
	}
}

// A full gate gives a newcomer the place of the oldest handshake whose peer
// hasn't begun its document EvictAfter after it came, never one that began,
// a younger one, or one taken with Enter.
func TestAFullGateEvictsTheOldestStalledHandshake(t *testing.T) {
	now := time.Unix(1000, 0)
	g := &Gate{Max: 3, now: func() time.Time { return now }}
	evicted := map[string]int{}
	ev := func(name string) func() { return func() { evicted[name]++ } }
	held, _ := g.Enter("")
	a, _ := g.Admit("", ev("a"))
	now = now.Add(time.Second)
	b, _ := g.Admit("", ev("b"))
	if _, ok := g.Admit("", ev("c")); ok {
		t.Fatal("a full gate took a newcomer before any handshake stalled")
	}
	now = now.Add(EvictAfter)
	a.Begin()
	c, ok := g.Admit("", ev("c"))
	if !ok || evicted["b"] != 1 || evicted["a"] != 0 {
		t.Fatalf("the newcomer: %v, evicted %v", ok, evicted)
	}
	b.Done()
	if _, ok := g.Admit("", ev("d")); ok {
		t.Fatal("an evicted handshake's Done gave back a second place")
	}
	held()
	c.Done()
	a.Done()
	if g.total != 0 || len(g.passes) != 0 {
		t.Fatalf("%d places left", g.total)
	}
}

// Done racing an Admit that evicts the same handshake gave the place back
// under a sync.Once each took in the other's order around g.mu, and every
// later Admit hung (2026-11-25 re-check, R3-1). Every handshake here is
// stalled, so a full gate always evicts, while the evicted ones end at once.
func TestDoneRacingAnEvictionNeverDeadlocks(t *testing.T) {
	var ticks atomic.Int64
	g := &Gate{Max: 4, now: func() time.Time {
		return time.Unix(0, 0).Add(time.Duration(ticks.Add(1)) * EvictAfter)
	}}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() {
				for range 2000 {
					gone := make(chan struct{})
					p, ok := g.Admit("", func() { close(gone) })
					if !ok {
						continue
					}
					select {
					case <-gone:
					default:
					}
					p.Done()
				}
			})
		}
		wg.Wait()
	}()
	select {
	case <-finished:
	case <-time.After(20 * time.Second):
		t.Fatal("the gate deadlocked: Done and an eviction hold each other")
	}
	if g.total != 0 || len(g.passes) != 0 {
		t.Fatalf("%d places left, %d passes", g.total, len(g.passes))
	}
}
