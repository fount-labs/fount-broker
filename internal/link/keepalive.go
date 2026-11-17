package link

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// A job can go quiet for minutes, waiting on a model with nothing to print.
// The shim between the enclaves may drop a connection that idle, and a peer
// that vanishes without closing would otherwise go unnoticed until the job's
// own timeout. So once the handshake is done, each end sends a ping every
// PingInterval, and a read that sees nothing for IdleTimeout fails the link.
//
// The pings are below package jobwire: after the handshake, the bytes travel
// as records, [u8 kind][u32 length][payload], and a ping is an empty record
// that Read skips.
const (
	PingInterval = 15 * time.Second
	IdleTimeout  = time.Minute
)

const (
	recordData byte = 0
	recordPing byte = 1
	// maxRecord bounds one record, so a ping can go out between the pieces of
	// a large write.
	maxRecord = 64 << 10
)

// ErrQuiet is a link whose peer sent nothing, not even a ping, for its idle
// timeout.
var ErrQuiet = errors.New("the link's peer went quiet")

type keepaliveConn struct {
	net.Conn
	idle time.Duration

	wmu  sync.Mutex
	rmu  sync.Mutex
	left int // unread bytes of the current data record

	dmu      sync.Mutex
	deadline time.Time // the caller's read deadline, if it set one

	stop     chan struct{}
	stopOnce sync.Once
}

func keepalive(conn net.Conn, interval, idle time.Duration) net.Conn {
	c := &keepaliveConn{Conn: conn, idle: idle, stop: make(chan struct{})}
	go c.ping(interval)
	return c
}

func (c *keepaliveConn) ping(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if c.writeRecord(recordPing, nil) != nil {
				return
			}
		case <-c.stop:
			return
		}
	}
}

func (c *keepaliveConn) writeRecord(kind byte, p []byte) error {
	var h [5]byte
	h[0] = kind
	binary.BigEndian.PutUint32(h[1:], uint32(len(p)))
	c.wmu.Lock()
	defer c.wmu.Unlock()
	// A peer that stopped reading is as gone as one that went quiet.
	c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	if _, err := c.Conn.Write(append(h[:], p...)); err != nil {
		return err
	}
	return nil
}

func (c *keepaliveConn) Write(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		end := min(n+maxRecord, len(p))
		if err := c.writeRecord(recordData, p[n:end]); err != nil {
			return n, err
		}
		n = end
	}
	return n, nil
}

func (c *keepaliveConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for c.left == 0 {
		var h [5]byte
		if err := c.readFull(h[:]); err != nil {
			return 0, err
		}
		n := binary.BigEndian.Uint32(h[1:])
		switch {
		case h[0] == recordPing && n == 0:
		case h[0] == recordData && n <= maxRecord:
			c.left = int(n)
		default:
			return 0, fmt.Errorf("%w: a record of kind %d and %d bytes", ErrPeer, h[0], n)
		}
	}
	if err := c.arm(); err != nil {
		return 0, err
	}
	n, err := c.Conn.Read(p[:min(len(p), c.left)])
	c.left -= n
	return n, c.quiet(err)
}

func (c *keepaliveConn) readFull(p []byte) error {
	for got := 0; got < len(p); {
		if err := c.arm(); err != nil {
			return err
		}
		n, err := c.Conn.Read(p[got:])
		got += n
		if err != nil {
			if got > 0 && errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return c.quiet(err)
		}
	}
	return nil
}

// arm sets the read deadline to the idle timeout from now, or the caller's
// own deadline if that's sooner.
func (c *keepaliveConn) arm() error {
	d := time.Now().Add(c.idle)
	c.dmu.Lock()
	if !c.deadline.IsZero() && c.deadline.Before(d) {
		d = c.deadline
	}
	c.dmu.Unlock()
	return c.Conn.SetReadDeadline(d)
}

// quiet names a timeout the idle timeout caused, rather than the caller's.
func (c *keepaliveConn) quiet(err error) error {
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}
	c.dmu.Lock()
	mine := !c.deadline.IsZero() && !time.Now().Before(c.deadline)
	c.dmu.Unlock()
	if mine {
		return err
	}
	return fmt.Errorf("%w for %s", ErrQuiet, c.idle)
}

func (c *keepaliveConn) SetReadDeadline(t time.Time) error {
	c.dmu.Lock()
	c.deadline = t
	c.dmu.Unlock()
	return c.Conn.SetReadDeadline(t)
}

func (c *keepaliveConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.Conn.SetWriteDeadline(t)
}

func (c *keepaliveConn) Close() error {
	c.stopOnce.Do(func() { close(c.stop) })
	return c.Conn.Close()
}
