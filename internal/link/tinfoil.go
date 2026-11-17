package link

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

// AttestationSocket is where a Tinfoil container with `attestation: true`
// asks for its enclave's documents.
const AttestationSocket = "/tinfoil/attestation.sock"

// KeyDir is where Tinfoil puts the private halves of a container's attested
// keys.
const KeyDir = "/run/tinfoil/keys"

// LoadKey reads the attested link key from dir.
func LoadKey(dir string) (ed25519.PrivateKey, error) {
	path := filepath.Join(dir, KeyID, "private_key.pem")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s holds no PEM", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s isn't an Ed25519 key", path)
	}
	return key, nil
}

// SocketAttester asks the enclave's attestation socket for documents.
type SocketAttester struct{ client *http.Client }

func NewSocketAttester(path string) *SocketAttester {
	return &SocketAttester{client: &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", path)
			},
		},
	}}
}

const maxDocument = 32 << 20

// Attest retries a 503, which the socket answers until it's ready and while
// the release has no current freshness witness.
func (a *SocketAttester) Attest(ctx context.Context, nonce []byte) ([]byte, error) {
	url := "http://localhost/.well-known/tinfoil-attestation?nonce=" + hex.EncodeToString(nonce)
	var last error
	for range 10 {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := a.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("attestation socket: %w", err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocument))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		switch resp.StatusCode {
		case http.StatusOK:
			return body, nil
		case http.StatusServiceUnavailable:
			last = fmt.Errorf("attestation socket answered 503: %.200s", body)
		default:
			return nil, fmt.Errorf("attestation socket answered %d: %.200s", resp.StatusCode, body)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return nil, last
}

// TinfoilChecker checks the peer's document against repo, the GitHub
// repository whose releases the peer must run: hardware, provenance,
// freshness and the nonce.
func TinfoilChecker(repo string) (Checker, error) {
	v, err := verify.NewVerifier()
	if err != nil {
		return nil, err
	}
	if err := v.CheckRepoVerifiability(repo); err != nil {
		return nil, fmt.Errorf("pin %q: %w", repo, err)
	}
	return func(doc, nonce []byte) (ed25519.PublicKey, error) {
		verified, err := v.VerifyV3(doc, nonce, repo)
		if err != nil {
			return nil, err
		}
		spki, ok := verified.CryptoMaterialData(KeyID, document.KeySPKIV1Format)
		if !ok {
			return nil, fmt.Errorf("the attestation endorses no %q key", KeyID)
		}
		der, err := hex.DecodeString(spki)
		if err != nil {
			return nil, err
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, err
		}
		key, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("the endorsed link key isn't Ed25519")
		}
		return key, nil
	}, nil
}

// Tinfoil is this end of the link in a Tinfoil enclave, checking a peer that
// runs repo's releases.
func Tinfoil(repo string) (*Side, error) {
	key, err := LoadKey(KeyDir)
	if err != nil {
		return nil, fmt.Errorf("the attested link key: %w", err)
	}
	check, err := TinfoilChecker(repo)
	if err != nil {
		return nil, err
	}
	return &Side{Key: key, Attester: NewSocketAttester(AttestationSocket), Check: check}, nil
}
