package link

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// A Tinfoil enclave takes only HTTPS, through its shim, on the paths its config
// lists. So the link travels inside an HTTP/1.1 upgrade on Path: the shim's TLS
// carries it between enclaves, and the link's own handshake runs inside.

// Path is the runner broker's link endpoint, listed in its shim paths.
const Path = "/fount-link"

// Protocol is the Upgrade token. 2 added the keepalive's records.
const Protocol = "fount-link/2"

// roots are the system's, but in tests.
var roots *x509.CertPool

// Dial opens a connection to the link endpoint at base, an https:// URL (http://
// in dev and tests), ready for Side.Client.
func Dial(ctx context.Context, base string) (net.Conn, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	if u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.User != nil {
		return nil, fmt.Errorf("%s: name only the runner's origin", base)
	}
	host := u.Host
	var conn net.Conn
	switch u.Scheme {
	case "https":
		if u.Port() == "" {
			host = net.JoinHostPort(u.Hostname(), "443")
		}
		d := tls.Dialer{Config: &tls.Config{ServerName: u.Hostname(), RootCAs: roots, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}}
		conn, err = d.DialContext(ctx, "tcp", host)
	case "http":
		if u.Port() == "" {
			host = net.JoinHostPort(u.Hostname(), "80")
		}
		var d net.Dialer
		conn, err = d.DialContext(ctx, "tcp", host)
	default:
		return nil, fmt.Errorf("%s: the runner is an http(s) URL", base)
	}
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	req := &http.Request{
		Method:     http.MethodGet,
		URL:        &url.URL{Scheme: u.Scheme, Host: u.Host, Path: Path},
		Host:       u.Host,
		Header:     http.Header{"Connection": {"Upgrade"}, "Upgrade": {Protocol}},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("the runner's answer to the upgrade: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols || !strings.EqualFold(resp.Header.Get("Upgrade"), Protocol) {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		conn.Close()
		return nil, fmt.Errorf("the runner refused the upgrade: %s %q", resp.Status, body)
	}
	if ctx.Err() != nil {
		conn.Close()
		return nil, ctx.Err()
	}
	return &bufferedConn{Conn: conn, r: br}, nil
}

// Listener is the runner broker's end: an http.Handler for Path whose
// upgraded connections Accept returns, ready for Side.Server.
type Listener struct {
	addr  net.Addr
	conns chan net.Conn
	once  sync.Once
	done  chan struct{}
}

func NewListener(addr net.Addr) *Listener {
	return &Listener{addr: addr, conns: make(chan net.Conn), done: make(chan struct{})}
}

var ErrClosed = errors.New("the link listener is closed")

func (l *Listener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != Path {
		http.NotFound(w, r)
		return
	}
	if !headerHas(r.Header, "Connection", "upgrade") || !strings.EqualFold(r.Header.Get("Upgrade"), Protocol) {
		w.Header().Set("Upgrade", Protocol)
		http.Error(w, "this endpoint takes only an upgrade to "+Protocol, http.StatusUpgradeRequired)
		return
	}
	rc := http.NewResponseController(w)
	conn, brw, err := rc.Hijack()
	if err != nil {
		http.Error(w, "can't take the connection over", http.StatusInternalServerError)
		return
	}
	conn.SetDeadline(time.Time{})
	if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: "+Protocol+"\r\n\r\n"); err != nil {
		conn.Close()
		return
	}
	var c net.Conn = conn
	if brw.Reader.Buffered() > 0 {
		c = &bufferedConn{Conn: conn, r: brw.Reader}
	}
	select {
	case l.conns <- c:
	case <-l.done:
		conn.Close()
	}
}

func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, ErrClosed
	}
}

func (l *Listener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *Listener) Addr() net.Addr { return l.addr }

func headerHas(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for t := range strings.SplitSeq(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// bufferedConn reads first what the HTTP exchange read ahead.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
