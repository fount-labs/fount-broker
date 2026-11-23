package volume

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"testing"
)

// The real dial: a SOCK_SEQPACKET socket, one packet each way.
func TestOpenOverASeqpacketSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	ln, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	key := bytes.Repeat([]byte{9}, 32)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 64<<10)
			n, _ := conn.Read(buf)
			if n == 2+len(key) && buf[0] == formatArgon2id && buf[1] == 'u' && bytes.Equal(buf[2:n], key) {
				conn.Write([]byte("ok"))
			} else {
				conn.Write([]byte("rejected"))
			}
			conn.Close()
		}
	}()
	if got, err := (Socket{Path: path}).Open(context.Background(), key); err != nil || got != Unlocked {
		t.Fatalf("%v %v", got, err)
	}
}
