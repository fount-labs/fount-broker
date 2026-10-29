// Package proxy is the broker's tunnel for Python's package manager. uv
// can't speak the frame protocol, so the broker also listens on loopback as
// an HTTPS proxy. It opens CONNECT tunnels to a fixed list of hosts on port
// 443 and refuses everything else. TLS runs end to end between uv and the
// host: the broker sees the host name and the byte counts, nothing more.
//
// A per-launch password, handed to the app in the ready frame, keeps other
// local processes, such as the code an agent runs, from using the tunnel.
package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	user        = "fount"
	dialTimeout = 15 * time.Second
)

type Proxy struct {
	ln    net.Listener
	auth  string
	url   string
	hosts []string
	dial  func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Listen opens the proxy on a free loopback port. It tunnels to hosts only.
func Listen(hosts []string) (*Proxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		ln.Close()
		return nil, err
	}
	password := hex.EncodeToString(secret)
	u := url.URL{Scheme: "http", User: url.UserPassword(user, password), Host: ln.Addr().String()}
	d := &net.Dialer{Timeout: dialTimeout}
	return &Proxy{
		ln:    ln,
		auth:  "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password)),
		url:   u.String(),
		hosts: hosts,
		dial:  d.DialContext,
	}, nil
}

// URL is the proxy's address with its password, for HTTPS_PROXY.
func (p *Proxy) URL() string { return p.url }

// Serve answers connections until ctx ends.
func (p *Proxy) Serve(ctx context.Context) error {
	srv := &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	if err := srv.Serve(p.ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Proxy-Authorization")), []byte(p.auth)) != 1 {
		w.Header().Set("Proxy-Authenticate", `Basic realm="fount-broker"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	if r.Method != http.MethodConnect {
		http.Error(w, "only CONNECT tunnels are offered", http.StatusMethodNotAllowed)
		return
	}
	host, port, err := net.SplitHostPort(r.Host)
	host = strings.ToLower(host)
	if err != nil || port != "443" || !slices.Contains(p.hosts, host) {
		log.Printf("proxy: refused a tunnel to %q", r.Host)
		http.Error(w, fmt.Sprintf("the broker doesn't tunnel to %s", r.Host), http.StatusForbidden)
		return
	}
	upstream, err := p.dial(r.Context(), "tcp", net.JoinHostPort(host, port))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "can't tunnel over this connection", http.StatusInternalServerError)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		client.Close()
		upstream.Close()
		return
	}
	up, down := pipe(client, buf.Reader, upstream)
	log.Printf("proxy: %s: %d bytes up, %d down", host, up, down)
}

// pipe copies both ways until each side has finished sending, then closes
// both. from holds what the client sent after its CONNECT request.
func pipe(client net.Conn, from *bufio.Reader, upstream net.Conn) (up, down int64) {
	var wg sync.WaitGroup
	wg.Go(func() {
		up, _ = io.Copy(upstream, from)
		closeWrite(upstream)
	})
	down, _ = io.Copy(client, upstream)
	closeWrite(client)
	wg.Wait()
	client.Close()
	upstream.Close()
	return up, down
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(interface{ CloseWrite() error }); ok {
		tc.CloseWrite()
		return
	}
	c.Close()
}
