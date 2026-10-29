package route

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	tinfoil "github.com/tinfoilsh/tinfoil-go"
	"github.com/tinfoilsh/tinfoil-go/verify"

	"github.com/fount-labs/fount-broker/internal/policy"
)

// Tinfoil seals each request to an attested Tinfoil enclave and sends it
// through Fount's proxy. The proxy sees the method, path and headers, never
// the body.
type Tinfoil struct {
	base string
	// discover returns a client bound to a verified enclave.
	discover func(ctx context.Context) (enclave, error)

	mu     sync.Mutex
	client enclave
}

// enclave is the part of *tinfoil.EnclaveHTTPClient the route uses.
type enclave interface {
	Do(*http.Request) (*http.Response, error)
	Enclave() string
	EnsureVerified(context.Context) (*verify.Verification, error)
}

// NewTinfoil returns a route through the proxy at base. cacheSecret is read
// at each discovery and scopes Tinfoil's prompt cache to this user.
func NewTinfoil(base string, cacheSecret func() string) *Tinfoil {
	return &Tinfoil{
		base: base,
		discover: func(ctx context.Context) (enclave, error) {
			return tinfoil.DiscoverRouter(ctx, &tinfoil.EnclaveOptions{
				TransportMode:     tinfoil.TransportModeEHBP,
				BaseURL:           base,
				UserCacheSecret:   cacheSecret(),
				VerificationCheck: checkRepo(policy.TinfoilRouterRepo),
			})
		},
	}
}

// NewTinfoilEnclave returns a route to the one enclave at host, which must be
// built from repo, through the proxy at base.
func NewTinfoilEnclave(host, repo, base string) *Tinfoil {
	return &Tinfoil{
		base: base,
		discover: func(context.Context) (enclave, error) {
			return tinfoil.NewEnclaveHTTPClient(host, repo, &tinfoil.EnclaveOptions{
				TransportMode:     tinfoil.TransportModeEHBP,
				BaseURL:           base,
				VerificationCheck: checkRepo(repo),
			})
		},
	}
}

// checkRepo restates a pin here so the policy file shows it. tinfoil-go
// already verifies against the same repository.
func checkRepo(want string) func(*verify.Verification) error {
	return func(v *verify.Verification) error {
		if repo := v.ConfigRepo(); repo != want {
			return fmt.Errorf("enclave is built from %q, want %q", repo, want)
		}
		return nil
	}
}

func (t *Tinfoil) current(ctx context.Context) (enclave, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client != nil {
		return t.client, nil
	}
	c, err := t.discover(ctx)
	if err != nil {
		return nil, classify(err)
	}
	t.client = c
	return c, nil
}

// forget drops c so the next request discovers again, unless another request
// already replaced it.
func (t *Tinfoil) forget(c enclave) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client == c {
		t.client = nil
	}
}

// Reset drops the current router, for example after the cache secret changes.
func (t *Tinfoil) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.client = nil
}

// Do sends r, and when the router can't be reached, discovers again and
// retries once. The body is held in memory, so the retry resends it exactly.
func (t *Tinfoil) Do(ctx context.Context, r Request) (*http.Response, error) {
	if escapes(r.Dest.Path) {
		return nil, fmt.Errorf("destination path %q escapes the base URL", r.Dest.Path)
	}
	c, err := t.current(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := t.send(ctx, c, r)
	if err == nil || ctx.Err() != nil || errors.Is(err, ErrAttestation) {
		return resp, err
	}
	t.forget(c)
	if c, err = t.current(ctx); err != nil {
		return nil, err
	}
	return t.send(ctx, c, r)
}

func (t *Tinfoil) send(ctx context.Context, c enclave, r Request) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, r.Dest.Method, t.base+r.Dest.Path, bytes.NewReader(r.Body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", r.Dest.ContentType)
	if r.Accept != "" {
		req.Header.Set("Accept", r.Accept)
	}
	if r.Credential != "" {
		req.Header.Set("Authorization", "Bearer "+r.Credential)
	}
	for k, v := range r.Dest.Headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, classify(err)
	}
	return resp, nil
}

func classify(err error) error {
	var attestation *tinfoil.AttestationError
	if errors.As(err, &attestation) {
		return fmt.Errorf("%w: %v", ErrAttestation, err)
	}
	return err
}

// TinfoilStatus is what the app shows as proof of the enclave it talks to.
type TinfoilStatus struct {
	Enclave            string    `json:"enclave"`
	Repo               string    `json:"repo"`
	CodeDigest         string    `json:"codeDigest"`
	CodeTag            string    `json:"codeTag"`
	Measurement        string    `json:"measurement"`
	HPKEPublicKey      string    `json:"hpkePublicKey"`
	TLSPublicKeyFP     string    `json:"tlsPublicKeyFingerprint"`
	FreshnessExpiresAt time.Time `json:"freshnessExpiresAt"`
	VerifiedAt         time.Time `json:"verifiedAt"`
}

// Status verifies the router if needed and reports what was verified.
func (t *Tinfoil) Status(ctx context.Context) (any, error) {
	c, err := t.current(ctx)
	if err != nil {
		return nil, err
	}
	v, err := c.EnsureVerified(ctx)
	if err != nil {
		t.forget(c)
		return nil, classify(err)
	}
	hpke, _ := v.HPKEPublicKey()
	tlsFP, _ := v.TLSPublicKeyFP()
	return TinfoilStatus{
		Enclave:            c.Enclave(),
		Repo:               v.ConfigRepo(),
		CodeDigest:         v.CodeDigest(),
		CodeTag:            v.CodeTag(),
		Measurement:        fmt.Sprint(v.EnclaveMeasurement()),
		HPKEPublicKey:      hpke,
		TLSPublicKeyFP:     tlsFP,
		FreshnessExpiresAt: v.FreshnessExpiresAt(),
		VerifiedAt:         v.Metadata().VerifiedAt,
	}, nil
}
