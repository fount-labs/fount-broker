package route

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"

	tinfoil "github.com/tinfoilsh/tinfoil-go"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"

	"github.com/fount-labs/fount-broker/internal/policy"
)

// MailEdge is the Device API transport: TLS pinned to the key the edge's
// Tinfoil attestation endorses, verified against policy.MailEdgeRepo. It also
// reports the message-signing key that attestation endorses, which is how the
// broker knows a boot's key came from the enclave and not from storage.
type MailEdge struct {
	host, repo string

	mu     sync.Mutex
	client *tinfoil.EnclaveHTTPClient
}

func NewMailEdge() *MailEdge {
	return &MailEdge{host: policy.MailEdgeHost, repo: policy.MailEdgeRepo}
}

func (m *MailEdge) current() (*tinfoil.EnclaveHTTPClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.client != nil {
		return m.client, nil
	}
	c, err := tinfoil.NewEnclaveHTTPClient(m.host, m.repo, &tinfoil.EnclaveOptions{
		TransportMode:     tinfoil.TransportModeTLS,
		VerificationCheck: checkRepo(m.repo),
	})
	if err != nil {
		return nil, classify(err)
	}
	c.Timeout = 2 * time.Minute
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	m.client = c
	return c, nil
}

func (m *MailEdge) Base() string { return "https://" + m.host + "/" }

func (m *MailEdge) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	c, err := m.current()
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req.WithContext(ctx))
	if err != nil {
		return nil, classify(err)
	}
	return resp, nil
}

// AttestedSigningKey verifies the edge, if its last verification has lapsed,
// and returns the mail-sign key its attestation endorses.
func (m *MailEdge) AttestedSigningKey(ctx context.Context) (ed25519.PublicKey, error) {
	c, err := m.current()
	if err != nil {
		return nil, err
	}
	v, err := c.EnsureVerified(ctx)
	if err != nil {
		return nil, classify(err)
	}
	return endorsedEd25519(v, policy.MailSignKeyID)
}

// endorsedEd25519 reads an attested Ed25519 key, a hex SPKI, from v.
func endorsedEd25519(v *verify.Verification, id string) (ed25519.PublicKey, error) {
	data, ok := v.CryptoMaterialData(id, document.KeySPKIV1Format)
	if !ok {
		return nil, fmt.Errorf("%w: the edge's attestation endorses no %q key", ErrAttestation, id)
	}
	der, err := hex.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %q key: %v", ErrAttestation, id, err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %q key: %v", ErrAttestation, id, err)
	}
	k, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: %q key isn't Ed25519", ErrAttestation, id)
	}
	return k, nil
}
