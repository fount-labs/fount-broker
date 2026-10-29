package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
)

type dials struct {
	mu    sync.Mutex
	addrs []string
}

func (d *dials) String() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return strings.Join(d.addrs, ",")
}

// serve starts a proxy whose tunnels all reach one echo server, whatever host
// they name, and returns the proxy and the addresses it was asked to dial.
func serve(t *testing.T) (*Proxy, *dials) {
	t.Helper()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(c, c)
				c.Close()
			}()
		}
	}()

	p, err := Listen([]string{"pypi.org"})
	if err != nil {
		t.Fatal(err)
	}
	dialed := &dials{}
	p.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed.mu.Lock()
		dialed.addrs = append(dialed.addrs, addr)
		dialed.mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, network, echo.Addr().String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go p.Serve(ctx)
	return p, dialed
}

// connect sends one request line to the proxy with auth and returns the
// connection and the status code of the reply.
func connect(t *testing.T, p *Proxy, method, target, auth string) (net.Conn, *bufio.Reader, int) {
	t.Helper()
	u, _ := url.Parse(p.URL())
	c, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	host := target
	if abs, err := url.Parse(target); err == nil && abs.Host != "" {
		host = abs.Host
	}
	req := method + " " + target + " HTTP/1.1\r\nHost: " + host + "\r\n"
	if auth != "" {
		req += "Proxy-Authorization: " + auth + "\r\n"
	}
	if _, err := io.WriteString(c, req+"\r\n"); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	resp, err := http.ReadResponse(r, &http.Request{Method: method})
	if err != nil {
		t.Fatal(err)
	}
	return c, r, resp.StatusCode
}

func TestListensOnLoopbackWithAPassword(t *testing.T) {
	p, _ := serve(t)
	u, err := url.Parse(p.URL())
	if err != nil {
		t.Fatal(err)
	}
	if host, _, _ := net.SplitHostPort(u.Host); host != "127.0.0.1" {
		t.Errorf("listening on %s, want loopback", u.Host)
	}
	if pw, ok := u.User.Password(); !ok || len(pw) < 32 {
		t.Errorf("URL %q has no strong password", p.URL())
	}
}

func TestTunnelsToAnAllowedHost(t *testing.T) {
	p, dialed := serve(t)
	c, r, status := connect(t, p, "CONNECT", "pypi.org:443", p.auth)
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200", status)
	}
	if _, err := io.WriteString(c, "hello\n"); err != nil {
		t.Fatal(err)
	}
	line, err := r.ReadString('\n')
	if err != nil || line != "hello\n" {
		t.Fatalf("echo: %q, %v", line, err)
	}
	if got := dialed.String(); got != "pypi.org:443" {
		t.Errorf("dialed %s", got)
	}
}

func TestRefusals(t *testing.T) {
	p, _ := serve(t)
	wrong := "Basic " + strings.Repeat("A", len(p.auth)-6)
	for _, tc := range []struct {
		name, method, target, auth string
		want                       int
	}{
		{"no password", "CONNECT", "pypi.org:443", "", http.StatusProxyAuthRequired},
		{"wrong password", "CONNECT", "pypi.org:443", wrong, http.StatusProxyAuthRequired},
		{"plain HTTP proxying", "GET", "http://pypi.org/simple/", p.auth, http.StatusMethodNotAllowed},
		{"another host", "CONNECT", "example.com:443", p.auth, http.StatusForbidden},
		{"a subdomain", "CONNECT", "evil.pypi.org:443", p.auth, http.StatusForbidden},
		{"another port", "CONNECT", "pypi.org:22", p.auth, http.StatusForbidden},
		{"an IP address", "CONNECT", "151.101.0.223:443", p.auth, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, status := connect(t, p, tc.method, tc.target, tc.auth)
			if status != tc.want {
				t.Errorf("status %d, want %d", status, tc.want)
			}
		})
	}
}

func TestHostNamesAreMatchedWithoutCase(t *testing.T) {
	p, dialed := serve(t)
	if _, _, status := connect(t, p, "CONNECT", "PyPI.org:443", p.auth); status != http.StatusOK {
		t.Fatalf("status %d, want 200", status)
	}
	if got := dialed.String(); got != "pypi.org:443" {
		t.Errorf("dialed %s", got)
	}
}
