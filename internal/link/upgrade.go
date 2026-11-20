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

// Path is the link endpoint, listed in the shim paths of the end that
// accepts: the runner broker's, or the coordinator's when runners dial in.
const Path = "/fount-link"

// Protocol is the Upgrade token. 2 added the keepalive's records.
const Protocol = "fount-link/2"

// DialInProtocol is the Upgrade token of a link a runner opens to the
// coordinator. The job protocol over it is Protocol's, but the runner waits
// up to ParkFor for its job, and the coordinator holds it until it has one.
const DialInProtocol = "fount-link-in/1"

// ParkFor is how long a runner keeps a dialled link that has no job before it
// closes it and dials another, so no link is used long after its peer was
// checked. The coordinator stops handing it out a minute sooner.
const ParkFor = 10 * time.Minute

// NameHeader is the runner's name for itself on a dialled link, its enclave's
// hostname: a label for logs and status. Nothing attests it.
const NameHeader = "Fount-Runner"

// roots are the system's, but in tests.
var roots *x509.CertPool

// Dial opens a connection to the link endpoint at base, an https:// URL (http://
// in dev and tests), ready for Side.Client.
func Dial(ctx context.Context, base string) (net.Conn, error) {
	return DialUpgrade(ctx, base, Path, Protocol)
}

// DialUpgrade opens a connection upgraded to protocol on path at base: the
// link's endpoint, or another that crosses the shim the same way (package
// channel).
func DialUpgrade(ctx context.Context, base, path, protocol string) (net.Conn, error) {
	return DialUpgradeHeader(ctx, base, path, protocol, nil)
}

// DialUpgradeHeader is DialUpgrade with extra request headers.
func DialUpgradeHeader(ctx context.Context, base, path, protocol string, extra http.Header) (net.Conn, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	if u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.User != nil {
		return nil, fmt.Errorf("%s: name only the peer's origin", base)
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
		return nil, fmt.Errorf("%s: the peer is an http(s) URL", base)
	}
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	req := &http.Request{
		Method:     http.MethodGet,
		URL:        &url.URL{Scheme: u.Scheme, Host: u.Host, Path: path},
		Host:       u.Host,
		Header:     http.Header{"Connection": {"Upgrade"}, "Upgrade": {protocol}},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	for k, v := range extra {
		req.Header[k] = v
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("the peer's answer to the upgrade: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols || !strings.EqualFold(resp.Header.Get("Upgrade"), protocol) {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		conn.Close()
		return nil, fmt.Errorf("the peer refused the upgrade: %s %q", resp.Status, body)
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
	addr           net.Addr
	path, protocol string
	conns          chan net.Conn
	once           sync.Once
	done           chan struct{}
}

func NewListener(addr net.Addr) *Listener {
	return NewUpgradeListener(addr, Path, Protocol)
}

// NewUpgradeListener is a Listener for another endpoint: path, upgraded to
// protocol.
func NewUpgradeListener(addr net.Addr, path, protocol string) *Listener {
	return &Listener{addr: addr, path: path, protocol: protocol, conns: make(chan net.Conn), done: make(chan struct{})}
}

var ErrClosed = errors.New("the link listener is closed")

func (l *Listener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != l.path {
		http.NotFound(w, r)
		return
	}
	c, ok := Upgrade(w, r, l.protocol)
	if !ok {
		return
	}
	select {
	case l.conns <- c:
	case <-l.done:
		c.Close()
	}
}

// Upgrade answers r with a switch to protocol and takes its connection over.
// It reports false once it has answered with an error instead.
func Upgrade(w http.ResponseWriter, r *http.Request, protocol string) (net.Conn, bool) {
	if !headerHas(r.Header, "Connection", "upgrade") || !strings.EqualFold(r.Header.Get("Upgrade"), protocol) {
		w.Header().Set("Upgrade", protocol)
		http.Error(w, "this endpoint takes only an upgrade to "+protocol, http.StatusUpgradeRequired)
		return nil, false
	}
	rc := http.NewResponseController(w)
	conn, brw, err := rc.Hijack()
	if err != nil {
		http.Error(w, "can't take the connection over", http.StatusInternalServerError)
		return nil, false
	}
	conn.SetDeadline(time.Time{})
	if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: "+protocol+"\r\n\r\n"); err != nil {
		conn.Close()
		return nil, false
	}
	if brw.Reader.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: brw.Reader}, true
	}
	return conn, true
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
