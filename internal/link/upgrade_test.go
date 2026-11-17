package link

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
)

// shim stands in for a Tinfoil enclave's: TLS outside, plain HTTP to the
// container, only the listed path through.
func shim(t *testing.T, upstream string) *httptest.Server {
	t.Helper()
	target, _ := url.Parse(upstream)
	proxy := httputil.NewSingleHostReverseProxy(target)
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != Path {
			http.NotFound(w, r)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(s.Close)
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	roots = pool
	t.Cleanup(func() { roots = nil })
	return s
}

func TestTheLinkCrossesTheShim(t *testing.T) {
	backend := httptest.NewUnstartedServer(nil)
	l := NewListener(backend.Listener.Addr())
	backend.Config.Handler = l
	backend.Start()
	defer backend.Close()
	defer l.Close()
	front := shim(t, backend.URL)

	runner, coordinator := plain(t), plain(t)
	got := make(chan string, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			got <- err.Error()
			return
		}
		defer conn.Close()
		tc, err := runner.Server(context.Background(), conn)
		if err != nil {
			got <- err.Error()
			return
		}
		buf := make([]byte, 5)
		io.ReadFull(tc, buf)
		tc.Write([]byte("world"))
		got <- string(buf)
	}()
	conn, err := Dial(context.Background(), front.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tc, err := coordinator.Client(context.Background(), conn)
	if err != nil {
		t.Fatal(err)
	}
	tc.Write([]byte("hello"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(tc, buf); err != nil || string(buf) != "world" {
		t.Fatalf("%q %v", buf, err)
	}
	if s := <-got; s != "hello" {
		t.Fatal(s)
	}
}

func TestAPlainRequestIsToldToUpgrade(t *testing.T) {
	l := NewListener(nil)
	defer l.Close()
	s := httptest.NewServer(l)
	defer s.Close()
	resp, err := http.Get(s.URL + Path)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("%s", resp.Status)
	}
	if _, err := Dial(context.Background(), s.URL+"/elsewhere"); err == nil || !strings.Contains(err.Error(), "origin") {
		t.Fatalf("a URL with a path: %v", err)
	}
}

func TestARefusedUpgradeSaysWhy(t *testing.T) {
	s := httptest.NewServer(http.NotFoundHandler())
	defer s.Close()
	_, err := Dial(context.Background(), s.URL)
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("%v", err)
	}
}
