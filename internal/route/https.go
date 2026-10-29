package route

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// HTTPS sends requests to a fixed base URL over ordinary TLS. It verifies
// nothing beyond the server's certificate, so it carries destinations whose
// server is trusted with what they send.
//
// It doesn't follow redirects unless they are to a host in redirectHosts;
// any other redirect reaches the app as the 3xx response it is.
type HTTPS struct {
	base   string
	client *http.Client
	// status is what Status reports, such as the catalogue of model files.
	status func() any
}

func NewHTTPS(base string, status func() any, redirectHosts ...string) *HTTPS {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 2 * time.Minute
	client := &http.Client{Transport: transport, CheckRedirect: redirectPolicy(redirectHosts)}
	return &HTTPS{base: base, client: client, status: status}
}

const maxRedirects = 5

// redirectPolicy follows a GET's redirects within hosts over HTTPS. A request
// with a body is never redirected, so a body only reaches the URL its
// destination names.
func redirectPolicy(hosts []string) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		switch {
		case len(hosts) == 0:
			return http.ErrUseLastResponse
		case via[0].Method != http.MethodGet || req.Method != http.MethodGet:
			return http.ErrUseLastResponse
		case len(via) >= maxRedirects:
			return errors.New("too many redirects")
		case req.URL.Scheme != "https" || !hostAllowed(hosts, req.URL.Hostname()):
			return fmt.Errorf("redirect to %s is not allowed", req.URL.Host)
		}
		return nil
	}
}

func (h *HTTPS) Do(ctx context.Context, r Request) (*http.Response, error) {
	if escapes(r.Dest.Path) {
		return nil, fmt.Errorf("destination path %q escapes the base URL", r.Dest.Path)
	}
	req, err := http.NewRequestWithContext(ctx, r.Dest.Method, h.base+r.Dest.Path, bytes.NewReader(r.Body))
	if err != nil {
		return nil, err
	}
	if len(r.Body) > 0 {
		req.Header.Set("Content-Type", r.Dest.ContentType)
	}
	if r.Accept != "" {
		req.Header.Set("Accept", r.Accept)
	}
	if r.Credential != "" {
		req.Header.Set("Authorization", "Bearer "+r.Credential)
	}
	for k, v := range r.Dest.Headers {
		req.Header.Set(k, v)
	}
	if r.Dest.IdempotencyKey {
		req.Header.Set("Idempotency-Key", rand.Text())
	}
	return h.client.Do(req)
}

func (h *HTTPS) Status(context.Context) (any, error) {
	if h.status == nil {
		return map[string]string{"base": h.base}, nil
	}
	return h.status(), nil
}

// hostAllowed matches host against hosts, where an entry starting with "."
// matches any subdomain of it.
func hostAllowed(hosts []string, host string) bool {
	for _, h := range hosts {
		if host == h || strings.HasPrefix(h, ".") && strings.HasSuffix(host, h) {
			return true
		}
	}
	return false
}

func escapes(path string) bool {
	return strings.Contains(path, "..") || strings.HasPrefix(path, "/") || strings.Contains(path, "://")
}
