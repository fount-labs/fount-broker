// Package s3bucket is the coordinator's backup bucket (coordinator.BackupBucket)
// on S3: a stdlib-only client for Put, Get, List and Delete, signed with
// Signature Version 4 (sign.go), as the mail edge's is.
//
// A key is written once. Put sends If-None-Match: *, so S3 writes the object
// whole or not at all and never replaces one: roots and tree objects are
// named fresh, and a backup that met an existing key with other bytes is a
// bug or another writer, not something to overwrite. A Put whose first answer
// was lost meets its own object on the retry, reads it back, and succeeds when
// the bytes match.
//
// The bucket is addressed virtual-hosted style (the endpoint's host names the
// bucket), so it has one hostname, and in a Tinfoil enclave one forwarder
// route: S3's addresses change too fast for Tinfoil's allowlist, so its TCP
// connections go to a forwarder container on an open network, while TLS still
// runs to S3 and verifies its certificate (Config.Forwarder).
package s3bucket

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/fount-labs/fount-broker/internal/coordinator"
)

const service = "s3"

// ErrExists is a Put to a key the bucket already holds with other bytes.
var ErrExists = errors.New("s3: the key already holds another object")

// Config is one bucket.
type Config struct {
	// Endpoint is the bucket's root, which names it:
	// https://<bucket>.s3.<region>.amazonaws.com.
	Endpoint string
	Region   string

	AccessKeyID     string
	SecretAccessKey string
	// SessionToken is set for temporary (STS) credentials.
	SessionToken string

	// Forwarder, host:port, is where every TCP connection to the bucket
	// goes instead of S3's own addresses: the S3 forwarder container in an
	// enclave (fount-mail-edge internal/egress). TLS still runs to
	// Endpoint's host.
	Forwarder string
	// HTTPClient replaces the client New builds; Forwarder is then unused.
	HTTPClient *http.Client
}

// Bucket is a coordinator.BackupBucket on S3. It is safe for concurrent use.
type Bucket struct {
	httpc *http.Client
	base  *url.URL
	host  string
	reg   string
	creds creds
	token string
	now   func() time.Time
	// retries are the waits before each retry of a request S3 answered
	// with a 5xx, or that didn't reach it.
	retries  []time.Duration
	maxPages int
}

var _ coordinator.BackupBucket = (*Bucket)(nil)

const (
	maxKey          = 1024
	requestTimeout  = 2 * time.Minute
	forwarderDial   = 3 * time.Second
	defaultMaxPages = 100_000
)

// New checks the config and makes the bucket's client. It makes no request.
func New(cfg Config) (*Bucket, error) {
	if cfg.Endpoint == "" || cfg.Region == "" {
		return nil, errors.New("s3: the bucket's endpoint and region are required")
	}
	if cfg.AccessKeyID == "" || cfg.SecretAccessKey == "" {
		return nil, errors.New("s3: credentials are required")
	}
	base, err := url.Parse(strings.TrimRight(cfg.Endpoint, "/"))
	if err != nil {
		return nil, fmt.Errorf("s3: endpoint: %w", err)
	}
	if base.Scheme != "https" && base.Scheme != "http" || base.Host == "" || base.Path != "" || base.RawQuery != "" || base.User != nil {
		return nil, fmt.Errorf("s3: endpoint %q: the bucket's root, https://<bucket>.s3.<region>.amazonaws.com", cfg.Endpoint)
	}
	httpc := cfg.HTTPClient
	if httpc == nil {
		httpc = newHTTPClient(base, cfg.Forwarder)
	} else if cfg.Forwarder != "" {
		return nil, errors.New("s3: a forwarder needs the client New builds")
	}
	return &Bucket{
		httpc:    httpc,
		base:     base,
		host:     base.Host,
		reg:      cfg.Region,
		creds:    creds{cfg.AccessKeyID, cfg.SecretAccessKey},
		token:    cfg.SessionToken,
		now:      time.Now,
		retries:  []time.Duration{200 * time.Millisecond, time.Second, 3 * time.Second},
		maxPages: defaultMaxPages,
	}, nil
}

// newHTTPClient is the bucket's client: through the forwarder when one is
// named, and only ever to the endpoint's host.
func newHTTPClient(base *url.URL, forwarder string) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConnsPerHost = 16
	// The forwarder ends idle connections after two minutes.
	t.IdleConnTimeout = time.Minute
	if forwarder != "" {
		port := base.Port()
		if port == "" {
			port = map[string]string{"https": "443", "http": "80"}[base.Scheme]
		}
		want := net.JoinHostPort(base.Hostname(), port)
		d := net.Dialer{Timeout: forwarderDial}
		t.Proxy = nil
		t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != want {
				return nil, fmt.Errorf("s3: no forwarder route to %s", addr)
			}
			// The containers start together, and the forwarder may be
			// restarting.
			var err error
			for _, wait := range []time.Duration{0, 250 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second} {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(wait):
				}
				var c net.Conn
				if c, err = d.DialContext(ctx, network, forwarder); err == nil {
					return c, nil
				}
			}
			return nil, fmt.Errorf("s3: the forwarder %s: %w", forwarder, err)
		}
	}
	return &http.Client{Timeout: requestTimeout, Transport: t}
}

// Put writes data at key, once: see the package comment.
func (b *Bucket) Put(ctx context.Context, key string, data []byte) error {
	if err := checkKey(key); err != nil {
		return err
	}
	for range 3 {
		resp, err := b.do(ctx, http.MethodPut, key, nil, data, http.Header{"If-None-Match": {"*"}})
		if err != nil {
			return err
		}
		status := resp.StatusCode
		if status == http.StatusOK {
			drain(resp)
			return nil
		}
		if status != http.StatusPreconditionFailed && status != http.StatusConflict {
			return b.httpErr("put", key, resp)
		}
		drain(resp)
		// 412: the key is there. 409: another conditional write to it was
		// in flight; read what won.
		have, err := b.Get(ctx, key)
		switch {
		case errors.Is(err, coordinator.ErrNotFound):
			// Deleted since, or the racing write failed: try again.
			continue
		case err != nil:
			return err
		case bytes.Equal(have, data):
			return nil
		default:
			return fmt.Errorf("%w: %q", ErrExists, key)
		}
	}
	return fmt.Errorf("s3: put %q: the key kept changing under a conditional write", key)
}

// Get reads key, or coordinator.ErrNotFound.
func (b *Bucket) Get(ctx context.Context, key string) ([]byte, error) {
	if err := checkKey(key); err != nil {
		return nil, err
	}
	resp, err := b.do(ctx, http.MethodGet, key, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		if err := b.missing("get", key, resp); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%s: %w", key, coordinator.ErrNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, b.httpErr("get", key, resp)
	}
	defer drain(resp)
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("s3: get %q: %w", key, err)
	}
	if resp.ContentLength >= 0 && int64(len(data)) != resp.ContentLength {
		return nil, fmt.Errorf("s3: get %q: read %d of %d bytes", key, len(data), resp.ContentLength)
	}
	return data, nil
}

type listResult struct {
	XMLName     xml.Name `xml:"ListBucketResult"`
	IsTruncated bool     `xml:"IsTruncated"`
	NextToken   string   `xml:"NextContinuationToken"`
	Contents    []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
}

// List is every key under prefix, sorted, across every page.
func (b *Bucket) List(ctx context.Context, prefix string) ([]string, error) {
	out := []string{}
	token := ""
	for range b.maxPages {
		q := url.Values{"list-type": {"2"}}
		if prefix != "" {
			q.Set("prefix", prefix)
		}
		if token != "" {
			q.Set("continuation-token", token)
		}
		resp, err := b.do(ctx, http.MethodGet, "", q, nil, nil)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, b.httpErr("list", prefix, resp)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		drain(resp)
		if err != nil {
			return nil, fmt.Errorf("s3: list %q: %w", prefix, err)
		}
		var lr listResult
		if err := xml.Unmarshal(body, &lr); err != nil {
			return nil, fmt.Errorf("s3: list %q: %w", prefix, err)
		}
		for _, o := range lr.Contents {
			if !strings.HasPrefix(o.Key, prefix) {
				return nil, fmt.Errorf("s3: list %q answered %q", prefix, o.Key)
			}
			out = append(out, o.Key)
		}
		if !lr.IsTruncated {
			slices.Sort(out)
			return slices.Compact(out), nil
		}
		if lr.NextToken == "" || lr.NextToken == token {
			return nil, fmt.Errorf("s3: list %q: a truncated page with no new continuation token", prefix)
		}
		token = lr.NextToken
	}
	return nil, fmt.Errorf("s3: list %q: over %d pages", prefix, b.maxPages)
}

// Delete removes key; a missing key is no error. With versioning on, S3 keeps
// the bytes as a noncurrent version until the bucket's lifecycle expires it.
func (b *Bucket) Delete(ctx context.Context, key string) error {
	if err := checkKey(key); err != nil {
		return err
	}
	resp, err := b.do(ctx, http.MethodDelete, key, nil, nil, nil)
	if err != nil {
		return err
	}
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		drain(resp)
		return nil
	case http.StatusNotFound:
		return b.missing("delete", key, resp)
	}
	return b.httpErr("delete", key, resp)
}

func checkKey(key string) error {
	if key == "" || len(key) > maxKey || strings.HasPrefix(key, "/") {
		return fmt.Errorf("s3: key %.80q: 1 to %d bytes, not starting with /", key, maxKey)
	}
	return nil
}

// do sends one signed request, again after a 5xx or a request that didn't
// reach S3, up to len(b.retries) times. Every request here is safe to repeat:
// Put is conditional, and the rest don't change or only delete.
func (b *Bucket) do(ctx context.Context, method, key string, query url.Values, body []byte, header http.Header) (*http.Response, error) {
	var lastErr error
	for i := 0; ; i++ {
		resp, err := b.once(ctx, method, key, query, body, header)
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}
		if err == nil {
			lastErr = b.httpErr(strings.ToLower(method), key, resp)
		} else {
			lastErr = err
		}
		if i == len(b.retries) || ctx.Err() != nil {
			return nil, lastErr
		}
		select {
		case <-ctx.Done():
			return nil, lastErr
		case <-time.After(b.retries[i]):
		}
	}
}

func (b *Bucket) once(ctx context.Context, method, key string, query url.Values, body []byte, header http.Header) (*http.Response, error) {
	u := *b.base
	u.Path = "/" + key
	if query != nil {
		u.RawQuery = query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Host = b.host
	for k, v := range header {
		req.Header[k] = v
	}
	payloadHash := emptyPayloadHash
	if len(body) > 0 {
		payloadHash = hexSHA256(body)
	}
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if method == http.MethodPut {
		// S3 checks the body against it, so a write is whole or refused.
		sum := sha256.Sum256(body)
		req.Header.Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(sum[:]))
	}
	if b.token != "" {
		req.Header.Set("X-Amz-Security-Token", b.token)
	}
	req.ContentLength = int64(len(body))
	sign(req, payloadHash, b.reg, service, b.creds, b.now())
	return b.httpc.Do(req)
}

type s3Error struct {
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

// httpErr reads S3's error and closes the response.
func (b *Bucket) httpErr(op, key string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	drain(resp)
	var e s3Error
	if xml.Unmarshal(body, &e) == nil && e.Code != "" {
		return fmt.Errorf("s3: %s %.120q: %s: %s: %.200s", op, key, resp.Status, e.Code, e.Message)
	}
	return fmt.Errorf("s3: %s %.120q: %s: %.200s", op, key, resp.Status, strings.TrimSpace(string(body)))
}

// missing reads a 404 and closes it: nil for a missing key, an error for a
// missing bucket, which must never read as an empty one.
func (b *Bucket) missing(op, key string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	drain(resp)
	var e s3Error
	if xml.Unmarshal(body, &e) == nil && e.Code == "NoSuchBucket" {
		return fmt.Errorf("s3: %s %.120q: %s: NoSuchBucket: %.200s", op, key, resp.Status, e.Message)
	}
	return nil
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
}
