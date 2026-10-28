package route

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// HTTPS sends requests to a fixed base URL over ordinary TLS. It verifies
// nothing beyond the server's certificate, so it carries destinations whose
// server is trusted with what they send.
type HTTPS struct {
	base   string
	client *http.Client
	// status is what Status reports, such as the catalogue of model files.
	status func() any
}

func NewHTTPS(base string, status func() any) *HTTPS {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 2 * time.Minute
	return &HTTPS{base: base, client: &http.Client{Transport: transport}, status: status}
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

func escapes(path string) bool {
	return strings.Contains(path, "..") || strings.HasPrefix(path, "/") || strings.Contains(path, "://")
}
