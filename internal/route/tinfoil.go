package route

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
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

	// memory, when set, is shared with other routes: it holds the router
	// discovery last chose, and forgetting a client forgets that router.
	memory *RouterMemory

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
			return tinfoil.NewRouterHTTPClient(ctx, &tinfoil.RouterOptions{
				TransportMode:     tinfoil.TransportModeEHBP,
				BaseURL:           base,
				UserCacheSecret:   cacheSecret(),
				VerificationCheck: checkRepo(policy.TinfoilRouterRepo),
			})
		},
	}
}

// RouterMemory is the router that discovery last chose, for routes that each
// start with no client: a runner makes one route per job. Only the router's
// host is shared; each route verifies it again and keeps its own client and
// cache secret.
type RouterMemory struct {
	mu   sync.Mutex
	host string
}

func (m *RouterMemory) get() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.host
}

func (m *RouterMemory) set(host string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.host = host
}

// forget drops host, unless another route already chose a different one.
func (m *RouterMemory) forget(host string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.host == host {
		m.host = ""
	}
}

// NewTinfoilRemembering is NewTinfoil for one of many routes that share m.
// The route goes straight to the router m holds, and discovers only when m
// holds none or that router fails, so a slow or unreachable router list costs
// once per process rather than once per route.
func NewTinfoilRemembering(base string, cacheSecret func() string, m *RouterMemory) *Tinfoil {
	t := NewTinfoil(base, cacheSecret)
	t.memory = m
	t.discover = m.discoverWith(t.discover, func(ctx context.Context, host string) (enclave, error) {
		return tinfoil.NewEnclaveHTTPClient(ctx, host, tinfoil.Pin{Repo: policy.TinfoilRouterRepo}, &tinfoil.EnclaveOptions{
			TransportMode:     tinfoil.TransportModeEHBP,
			BaseURL:           base,
			UserCacheSecret:   orProcessSecret(cacheSecret()),
			VerificationCheck: checkRepo(policy.TinfoilRouterRepo),
		})
	})
	return t
}

// discoverWith tries the remembered router with known, and otherwise
// discovers with fresh and remembers what it chose.
func (m *RouterMemory) discoverWith(fresh func(context.Context) (enclave, error), known func(context.Context, string) (enclave, error)) func(context.Context) (enclave, error) {
	return func(ctx context.Context) (enclave, error) {
		if host := m.get(); host != "" {
			c, err := known(ctx, host)
			if err == nil {
				return c, nil
			}
			if ctx.Err() != nil {
				return nil, err
			}
			m.forget(host)
		}
		c, err := fresh(ctx)
		if err != nil {
			return nil, err
		}
		m.set(c.Enclave())
		return c, nil
	}
}

var (
	processSecretOnce sync.Once
	processSecret     string
)

// orProcessSecret is tinfoil-go's rule for a router client without a cache
// secret, which a client for a named enclave doesn't apply: a random secret
// made once per process.
func orProcessSecret(s string) string {
	if s != "" {
		return s
	}
	processSecretOnce.Do(func() {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			panic(err)
		}
		processSecret = hex.EncodeToString(b)
	})
	return processSecret
}

// NewTinfoilEnclave returns a route to the one enclave at host, which must be
// built from repo, through the proxy at base.
func NewTinfoilEnclave(host, repo, base string) *Tinfoil {
	return &Tinfoil{
		base: base,
		discover: func(ctx context.Context) (enclave, error) {
			return tinfoil.NewEnclaveHTTPClient(ctx, host, tinfoil.Pin{Repo: repo}, &tinfoil.EnclaveOptions{
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
	if t.memory != nil {
		t.memory.forget(c.Enclave())
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
	if errors.Is(err, tinfoil.ErrAttestation) {
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
