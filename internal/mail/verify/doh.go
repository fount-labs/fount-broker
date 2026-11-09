package verify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// DoH asks every resolver the same question over DNS over HTTPS (RFC 8484) and
// returns their responses unread. The verifier parses them and checks that
// they agree, so the broker never parses a DNS answer.
type DoH struct {
	Client *http.Client
	URLs   []string
}

const maxDNSResponse = 64 << 10

func NewDoH(urls []string) *DoH {
	return &DoH{Client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, URLs: urls}
}

func (d *DoH) Ask(ctx context.Context, qtype, name string) ([][]byte, error) {
	q, err := BuildQuery(qtype, name)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, len(d.URLs))
	errs := make([]error, len(d.URLs))
	var wg sync.WaitGroup
	for i, u := range d.URLs {
		wg.Go(func() { out[i], errs[i] = d.one(ctx, u, q) })
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return out, nil
}

func (d *DoH) one(ctx context.Context, url string, q []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(q))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/dns-message" {
		return nil, fmt.Errorf("%s answered %d %s", req.URL.Host, resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSResponse+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxDNSResponse {
		return nil, fmt.Errorf("%s answered more than %d bytes", req.URL.Host, maxDNSResponse)
	}
	return b, nil
}
