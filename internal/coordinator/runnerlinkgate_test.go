package coordinator

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fount-labs/fount-broker/internal/frame"
	"github.com/fount-labs/fount-broker/internal/link"
)

// countingAttester counts the documents this end was asked for.
type countingAttester struct {
	link.Attester
	n atomic.Int32
}

func (a *countingAttester) Attest(ctx context.Context, nonce []byte) ([]byte, error) {
	a.n.Add(1)
	return a.Attester.Attest(ctx, nonce)
}

// junkPeer finishes TLS on /fount-link with a throwaway key, then declares
// an attestation of size bytes and sends none of it.
func junkPeer(t *testing.T, base string, header http.Header, size uint32) (net.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := link.DialUpgradeHeader(ctx, base, link.Path, link.DialInProtocol, header)
	if err != nil {
		return nil, err
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	cert, err := link.Certificate(key)
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true})
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		t.Fatalf("TLS: %v", err)
	}
	h := []byte(`{"kind":"attestation"}`)
	b := binary.BigEndian.AppendUint32(nil, uint32(len(h)))
	b = append(b, h...)
	b = binary.BigEndian.AppendUint32(b, size)
	if _, err := tc.Write(b); err != nil {
		t.Fatal(err)
	}
	return tc, nil
}

func heapNow() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// The 11-24 review's H4 probe, flipped: a peer that finishes TLS with any key
// and declares a 64 MiB attestation is dropped at once. Peers that declare
// link.MaxAttestation and stall hold the coordinator to a bound before they
// proved anything, take no document from its attestation socket, and past
// link.MaxHandshakes are turned away; once they go, a runner links.
func TestUnprovenLinkPeersHoldTheCoordinatorToABound(t *testing.T) {
	side, err := link.Unattested()
	if err != nil {
		t.Fatal(err)
	}
	attester := &countingAttester{Attester: side.Attester}
	side.Attester = attester
	h := NewRunnerHub(side)
	defer h.Close()
	web := httptest.NewServer(h)
	defer web.Close()

	big, err := junkPeer(t, web.URL, nil, frame.MaxBody)
	if err != nil {
		t.Fatal(err)
	}
	big.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := big.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a peer that declared a 64 MiB attestation is still held: %v", err)
	}
	big.Close()

	const peers = 40
	before := heapNow()
	var held []net.Conn
	refused := 0
	for range peers {
		c, err := junkPeer(t, web.URL, nil, link.MaxAttestation)
		if err != nil {
			if !strings.Contains(err.Error(), "503") {
				t.Fatalf("a peer past the limit: %v", err)
			}
			refused++
			continue
		}
		held = append(held, c)
	}
	time.Sleep(200 * time.Millisecond)
	grew := int64(heapNow()) - int64(before)
	t.Logf("%d unproven peers held, the heap grew %d KiB", len(held), grew>>10)
	if len(held) != link.MaxHandshakes || refused != peers-link.MaxHandshakes {
		t.Fatalf("%d held, %d refused; want %d held", len(held), refused, link.MaxHandshakes)
	}
	// Each held peer costs its TLS state and a first chunk, not its 64 MiB.
	if bound := int64(link.MaxHandshakes) << 20; grew > bound {
		t.Fatalf("%d unproven peers grew the heap by %d bytes, over %d", len(held), grew, bound)
	}
	if n := attester.n.Load(); n != 0 {
		t.Fatalf("the coordinator asked its attestation socket %d times for unproven peers", n)
	}
	for _, c := range held {
		c.Close()
	}

	runner, err := link.Unattested()
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); !h.Ready(); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no runner linked once the junk peers went")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		raw, err := link.DialUpgradeHeader(ctx, web.URL, link.Path, link.DialInProtocol, nil)
		if err == nil {
			if _, err := runner.Client(ctx, raw); err != nil {
				raw.Close()
			}
		}
		cancel()
	}
}

// stalledPeer finishes TLS on /fount-link with a throwaway key and sends
// nothing.
func stalledPeer(t *testing.T, base string) (net.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := link.DialUpgradeHeader(ctx, base, link.Path, link.DialInProtocol, nil)
	if err != nil {
		return nil, err
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	cert, err := link.Certificate(key)
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true})
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return tc, nil
}

// closedWithin is whether the coordinator closes c within d.
func closedWithin(c net.Conn, d time.Duration) bool {
	c.SetReadDeadline(time.Now().Add(d))
	_, err := c.Read(make([]byte, 1))
	return err != nil && !errors.Is(err, os.ErrDeadlineExceeded)
}

// The 2026-11-25 re-review's N1 probe, flipped: link.MaxHandshakes peers
// that finish TLS and stall, the whole gate, no longer keep a runner out. A
// newcomer takes a stalled one's place once it is link.EvictAfter old, and
// a stalled peer is dropped by link.PeerFirstBytes anyway.
func TestStalledLinkHandshakesDontKeepARunnerOut(t *testing.T) {
	side, err := link.Unattested()
	if err != nil {
		t.Fatal(err)
	}
	h := NewRunnerHub(side)
	defer h.Close()
	web := httptest.NewServer(h)
	defer web.Close()

	var held []net.Conn
	for range link.MaxHandshakes {
		c, err := stalledPeer(t, web.URL)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	if _, err := stalledPeer(t, web.URL); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("a newcomer before any handshake is %s old: %v", link.EvictAfter, err)
	}
	time.Sleep(link.EvictAfter + 100*time.Millisecond)

	runner, err := link.Unattested()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := link.DialUpgradeHeader(ctx, web.URL, link.Path, link.DialInProtocol, nil)
	if err != nil {
		t.Fatalf("a runner against a gate full of stalled peers: %v", err)
	}
	if _, err := runner.Client(ctx, raw); err != nil {
		t.Fatalf("the runner's handshake: %v", err)
	}
	for deadline := time.Now().Add(5 * time.Second); !h.Ready(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the runner didn't park")
		}
	}
	// The one whose place it took was closed; the rest go by
	// link.PeerFirstBytes after their TLS.
	closed := 0
	for _, c := range held {
		if closedWithin(c, link.PeerFirstBytes+time.Second) {
			closed++
		}
	}
	if closed != len(held) {
		t.Fatalf("%d of %d stalled peers were closed", closed, len(held))
	}
}

// A peer that sends its document slower than link.MinAttestationRate is
// dropped after link.PeerRateGrace, well before link.PeerTimeout.
func TestATricklingLinkPeerIsDropped(t *testing.T) {
	side, err := link.Unattested()
	if err != nil {
		t.Fatal(err)
	}
	h := NewRunnerHub(side)
	defer h.Close()
	web := httptest.NewServer(h)
	defer web.Close()
	c, err := junkPeer(t, web.URL, nil, link.MaxAttestation)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	go func() {
		for range 20 {
			if _, err := c.Write(make([]byte, 1024)); err != nil {
				return
			}
			time.Sleep(time.Second)
		}
	}()
	if !closedWithin(c, link.PeerRateGrace+3*time.Second) {
		t.Fatal("a peer at 1 KiB/s is still held")
	}
	if took := time.Since(start); took > link.PeerRateGrace+2*time.Second {
		t.Fatalf("it was dropped after %s", took)
	}
}
