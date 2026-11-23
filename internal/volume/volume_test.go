package volume

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

// fakeVolume answers like Tinfoil's control socket: it holds the key a disk
// was initialized under, none for a blank disk.
type fakeVolume struct {
	key     []byte
	blankOp string // the reply to u on a blank disk
	seen    []string
}

func (f *fakeVolume) dial(ctx context.Context, path string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		buf := make([]byte, 64<<10)
		n, err := server.Read(buf)
		if err != nil || n < 2 || buf[0] != formatArgon2id {
			server.Write([]byte("failed"))
			return
		}
		op, key := buf[1], append([]byte(nil), buf[2:n]...)
		f.seen = append(f.seen, string(op))
		switch {
		case op == 'u' && f.key == nil:
			server.Write([]byte(f.blankOp))
		case op == 'u' && bytes.Equal(key, f.key):
			server.Write([]byte("ok"))
		case op == 'u':
			server.Write([]byte("rejected"))
		case op == 'i' && f.key == nil:
			f.key = key
			server.Write([]byte("ok\n"))
		default:
			server.Write([]byte("rejected"))
		}
	}()
	return client, nil
}

func TestOpenInitializesABlankDiskThenUnlocksIt(t *testing.T) {
	for _, blank := range []string{"rejected", "failed"} {
		f := &fakeVolume{blankOp: blank}
		s := Socket{Path: "x", Dial: f.dial}
		key := bytes.Repeat([]byte{7}, 32)
		got, err := s.Open(context.Background(), key)
		if err != nil || got != Initialized {
			t.Fatalf("blank (%s): %v %v", blank, got, err)
		}
		if got, err = s.Open(context.Background(), key); err != nil || got != Unlocked {
			t.Fatalf("second boot: %v %v", got, err)
		}
		if got := strings.Join(f.seen, ""); got != "uiu" {
			t.Fatalf("ops %s, want uiu", got)
		}
	}
}

func TestOpenNeverTakesADiskUnderAnotherKey(t *testing.T) {
	f := &fakeVolume{key: bytes.Repeat([]byte{1}, 32)}
	_, err := Socket{Path: "x", Dial: f.dial}.Open(context.Background(), bytes.Repeat([]byte{2}, 32))
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("got %v, want ErrRefused", err)
	}
	if !bytes.Equal(f.key, bytes.Repeat([]byte{1}, 32)) {
		t.Fatal("the disk's key changed")
	}
}

func TestOpenRefusesAShortKey(t *testing.T) {
	f := &fakeVolume{}
	if _, err := (Socket{Path: "x", Dial: f.dial}).Open(context.Background(), make([]byte, 15)); err == nil || len(f.seen) != 0 {
		t.Fatalf("got %v after %v", err, f.seen)
	}
}

func TestOpenWithNoSocketIsAnErrorToRetry(t *testing.T) {
	_, err := Socket{Path: t.TempDir() + "/control.sock"}.Open(context.Background(), make([]byte, 32))
	if err == nil || errors.Is(err, ErrRefused) {
		t.Fatalf("got %v", err)
	}
}
