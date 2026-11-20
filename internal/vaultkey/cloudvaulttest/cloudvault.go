// Package cloudvaulttest is the Cloud vault pair's generation and counter
// over HTTP, for tests: the real wire formats, checks and signatures
// (github.com/fount-labs/fount-mail-vault/wire), with one register standing
// for both vaults. fount-mail-vault tests the replication itself; this pair
// keeps its rule that every call needs both vaults.
package cloudvaulttest

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-vault/wire"
)

// Pair is two vault origins over one register.
type Pair struct {
	Authority ed25519.PrivateKey
	// LoseSwap, when set, makes the next cas take effect and answer 502, as
	// a lost answer would.
	LoseSwap atomic.Bool

	servers [2]*httptest.Server
	down    [2]atomic.Bool

	mu    sync.Mutex
	gen   uint64
	count uint64
	key   ed25519.PublicKey
	last  *[3]uint64
}

// Start serves both vaults until the test ends.
func Start(t testing.TB) *Pair {
	_, authority, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p := &Pair{Authority: authority}
	for i := range p.servers {
		mux := http.NewServeMux()
		mux.HandleFunc("POST "+wire.CounterPath, func(w http.ResponseWriter, r *http.Request) { p.counter(i, w, r) })
		p.servers[i] = httptest.NewServer(mux)
		t.Cleanup(p.servers[i].Close)
	}
	return p
}

// Vaults are both origins.
func (p *Pair) Vaults() []string { return []string{p.servers[0].URL, p.servers[1].URL} }

// AuthorityKey is GENERATION_AUTHORITY_KEY.
func (p *Pair) AuthorityKey() ed25519.PublicKey { return p.Authority.Public().(ed25519.PublicKey) }

// Down takes vault i down, or brings it back.
func (p *Pair) Down(i int, down bool) { p.down[i].Store(down) }

var errOneDown = errors.New("the register needs both vaults, and one didn't answer")

func (p *Pair) bothUp() bool { return !p.down[0].Load() && !p.down[1].Load() }

// Boot moves the generation on for key and certifies it, as a coordinator's
// keyset pull with coordinator_key does.
func (p *Pair) Boot(key ed25519.PublicKey) (string, uint64, error) {
	if !p.bothUp() {
		return "", 0, errOneDown
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	cert, err := wire.SignGenerationCertificate(p.Authority, wire.GenerationCertificate{Generation: p.gen + 1, CoordinatorKey: key, IssuedAt: time.Now().Unix()})
	if err != nil {
		return "", 0, err
	}
	p.gen++
	p.key = key
	return cert, p.gen, nil
}

// State is the register's generation and count.
func (p *Pair) State() wire.CounterState {
	p.mu.Lock()
	defer p.mu.Unlock()
	return wire.CounterState{Generation: p.gen, Count: p.count}
}

func (p *Pair) counter(i int, w http.ResponseWriter, r *http.Request) {
	if p.down[i].Load() {
		http.Error(w, "down", http.StatusBadGateway)
		return
	}
	if !p.bothUp() {
		http.Error(w, errOneDown.Error(), http.StatusServiceUnavailable)
		return
	}
	var req wire.CounterRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, wire.MaxCounterBody)).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	nonce, err := req.Validate()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	result := wire.CounterOK
	if req.Op == wire.CounterCAS {
		swap := [3]uint64{req.Generation, req.Prev, req.Next}
		switch {
		case req.Generation != p.gen:
			result = wire.CounterStaleGeneration
		case p.key == nil:
			result = wire.CounterNoGeneration
		case !ed25519.Verify(p.key, wire.CASMessage(nonce, req.Generation, req.Prev, req.Next), req.Signature):
			result = wire.CounterBadSignature
		case p.count == req.Next && p.last != nil && *p.last == swap:
		case p.count != req.Prev || req.Next <= req.Prev:
			result = wire.CounterCountMismatch
		default:
			p.count, p.last = req.Next, &swap
		}
	}
	st := wire.CounterState{Generation: p.gen, Count: p.count}
	p.mu.Unlock()
	if req.Op == wire.CounterCAS && p.LoseSwap.CompareAndSwap(true, false) {
		http.Error(w, "the answer was lost", http.StatusBadGateway)
		return
	}
	status := http.StatusOK
	if result != wire.CounterOK {
		status = http.StatusConflict
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(wire.AnswerCounter(p.Authority, &req, result, st))
}
