// Package volume opens a Tinfoil encrypted volume from inside the enclave,
// over its runtime control socket (Tinfoil's "Unlock at runtime"): one
// SOCK_SEQPACKET packet of the format byte 0x02 (Argon2id), an operation, u
// to unlock or i to initialize a blank disk, and the raw key; the reply is
// ok, rejected or failed. Until then the mount is read-only.
//
// The key never leaves the enclave: the coordinator derives it from the key
// the Cloud vaults release to it after attestation, so no keyserver, and no
// one at Fount, holds a key to the disk (verifiable-privacy.md).
package volume

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// MinKeySize is the shortest key Tinfoil takes.
const MinKeySize = 16

const formatArgon2id = 0x02

// SocketPath is the control socket of the mount named name in
// tinfoil-config.yml's top-level volumes.
func SocketPath(name string) string { return "/run/tinfoil/volumes/" + name + "/control.sock" }

// Opened says how Open opened the volume.
type Opened string

const (
	// Unlocked is a disk this key initialized before.
	Unlocked Opened = "unlocked"
	// Initialized is a blank disk, now under this key: the first boot on it.
	Initialized Opened = "initialized"
)

// ErrRefused is a volume that took neither operation: a disk initialized
// under another key. Trying again won't change it.
var ErrRefused = errors.New("the volume refused the key: it holds a disk initialized under another key")

// Socket is one volume's control socket.
type Socket struct {
	Path string
	// Dial connects to Path; nil is a SOCK_SEQPACKET Unix socket.
	Dial func(ctx context.Context, path string) (net.Conn, error)
}

// Open unlocks the volume with key, or, when unlocking fails, initializes it
// with key: Tinfoil initializes only a blank disk, so a disk with data on it
// is never formatted, it refuses. Its error is ErrRefused when both
// operations were refused; any other error may pass on a retry.
func (s Socket) Open(ctx context.Context, key []byte) (Opened, error) {
	if len(key) < MinKeySize {
		return "", fmt.Errorf("a volume key is at least %d bytes, not %d", MinKeySize, len(key))
	}
	unlock, err := s.request(ctx, 'u', key)
	if err != nil {
		return "", err
	}
	if unlock == "ok" {
		return Unlocked, nil
	}
	init, err := s.request(ctx, 'i', key)
	switch {
	case err != nil:
		return "", err
	case init == "ok":
		return Initialized, nil
	case unlock == "rejected" && init == "rejected":
		return "", ErrRefused
	}
	return "", fmt.Errorf("the volume answered %q to unlock and %q to initialize", unlock, init)
}

// request sends one operation and returns the reply: ok, rejected or failed.
func (s Socket) request(ctx context.Context, op byte, key []byte) (string, error) {
	dial := s.Dial
	if dial == nil {
		dial = dialPacket
	}
	conn, err := dial(ctx, s.Path)
	if err != nil {
		return "", fmt.Errorf("the volume's control socket: %w", err)
	}
	defer conn.Close()
	// Argon2id takes 256 MiB and a few seconds; the disk check more.
	deadline := time.Now().Add(5 * time.Minute)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()

	packet := make([]byte, 0, 2+len(key))
	packet = append(append(packet, formatArgon2id, op), key...)
	defer clear(packet)
	if _, err := conn.Write(packet); err != nil {
		return "", fmt.Errorf("the volume's control socket: %w", err)
	}
	reply := make([]byte, 64)
	n, err := conn.Read(reply)
	if err != nil {
		return "", fmt.Errorf("the volume's control socket: %w", err)
	}
	switch got := strings.TrimSpace(string(reply[:n])); got {
	case "ok", "rejected", "failed":
		return got, nil
	default:
		return "", fmt.Errorf("the volume's control socket answered %q", got)
	}
}

func dialPacket(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unixpacket", path)
}
