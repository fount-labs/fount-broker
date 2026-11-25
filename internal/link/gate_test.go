package link

import (
	"net/http"
	"testing"
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

func TestSourceTrustsOnlyANearbyProxy(t *testing.T) {
	for _, c := range []struct{ remote, xff, want string }{
		{"203.0.113.7:4000", "198.51.100.1", "203.0.113.7"},
		{"127.0.0.1:4000", "198.51.100.1, 203.0.113.7", "203.0.113.7"},
		{"10.0.0.2:4000", "203.0.113.8", "203.0.113.8"},
		{"127.0.0.1:4000", "", ""},
		{"127.0.0.1:4000", "not an address", ""},
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
