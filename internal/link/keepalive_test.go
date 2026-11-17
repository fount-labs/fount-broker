package link

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestAQuietButLiveLinkStaysUp(t *testing.T) {
	a, b := net.Pipe()
	ca := keepalive(a, 10*time.Millisecond, 100*time.Millisecond)
	cb := keepalive(b, 10*time.Millisecond, 100*time.Millisecond)
	defer ca.Close()
	defer cb.Close()

	// Nothing but pings for several idle timeouts, then the data.
	go func() {
		time.Sleep(400 * time.Millisecond)
		ca.Write(bytes.Repeat([]byte("x"), 3*maxRecord+7))
	}()
	got := make([]byte, 3*maxRecord+7)
	if _, err := io.ReadFull(cb, got); err != nil {
		t.Fatalf("the pings didn't keep the link up: %v", err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte("x"), len(got))) {
		t.Fatal("the data came back garbled")
	}
}

func TestASilentPeerFailsTheLink(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	// b's peer is a bare pipe end: it reads but never pings.
	go io.Copy(io.Discard, a)
	cb := keepalive(b, 10*time.Millisecond, 100*time.Millisecond)
	defer cb.Close()
	start := time.Now()
	_, err := cb.Read(make([]byte, 1))
	if !errors.Is(err, ErrQuiet) {
		t.Fatalf("got %v, want ErrQuiet", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("took %s to notice", d)
	}
}

func TestTheCallersOwnDeadlineStillHolds(t *testing.T) {
	a, b := net.Pipe()
	ca := keepalive(a, 10*time.Millisecond, time.Minute)
	cb := keepalive(b, 10*time.Millisecond, time.Minute)
	defer ca.Close()
	defer cb.Close()
	cb.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, err := cb.Read(make([]byte, 1))
	if !errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, ErrQuiet) {
		t.Fatalf("got %v, want the caller's own timeout", err)
	}
	// Cleared, the link reads again.
	cb.SetReadDeadline(time.Time{})
	go ca.Write([]byte("y"))
	if _, err := io.ReadFull(cb, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
}
