package link

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/fount-labs/fount-broker/internal/attested"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

// AttestationSocket is where a Tinfoil container with `attestation: true`
// asks for its enclave's documents.
const AttestationSocket = "/tinfoil/attestation.sock"

// KeyDir is where Tinfoil puts the private halves of a container's attested
// keys.
const KeyDir = attested.Dir

// LoadKey reads the attested link key from dir.
func LoadKey(dir string) (ed25519.PrivateKey, error) { return attested.LoadEd25519(dir, KeyID) }

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
//
// It keeps nothing: each link verifies afresh and carries one job. VerifyV3
// already refuses a document whose freshness proofs have lapsed. A link held
// before its job (one a runner dialled in) is used only within ParkFor and
// before the verification's FreshnessExpiresAt (Side.Endorse); caching a
// peer's key across links would have to honour that deadline too.
func TinfoilChecker(repo string) (Checker, error) {
	check, err := TinfoilKeyChecker(repo, KeyID)
	if err != nil {
		return nil, err
	}
	return func(doc, nonce []byte) (ed25519.PublicKey, error) {
		e, err := check(doc, nonce)
		return e.Key, err
	}, nil
}

// TinfoilKeyChecker is TinfoilChecker for the peer's attested key id, and
// says when the verification stops being fresh, for a connection that
// outlives one request.
func TinfoilKeyChecker(repo, id string) (KeyChecker, error) {
	v, err := verify.NewVerifier()
	if err != nil {
		return nil, err
	}
	if err := v.CheckPinVerifiability(verify.Pin{Repo: repo}); err != nil {
		return nil, fmt.Errorf("pin %q: %w", repo, err)
	}
	return func(doc, nonce []byte) (Endorsement, error) {
		verified, err := v.VerifyV3(doc, nonce, verify.Pin{Repo: repo})
		if err != nil {
			return Endorsement{}, err
		}
		spki, ok := verified.CryptoMaterialData(id, document.KeySPKIV1Format)
		if !ok {
			return Endorsement{}, fmt.Errorf("the attestation endorses no %q key", id)
		}
		der, err := hex.DecodeString(spki)
		if err != nil {
			return Endorsement{}, err
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return Endorsement{}, err
		}
		key, ok := pub.(ed25519.PublicKey)
		if !ok {
			return Endorsement{}, fmt.Errorf("the endorsed %q key isn't Ed25519", id)
		}
		fresh := verified.FreshnessExpiresAt()
		if fresh.IsZero() {
			// tinfoil-go sets it for every V3 document; one without would
			// otherwise be trusted for as long as a connection lasts.
			return Endorsement{}, errors.New("the verification has no freshness deadline")
		}
		release := Release{Repo: repo, Tag: verified.CodeTag(), Digest: verified.CodeDigest()}
		return Endorsement{Key: key, Fresh: fresh, Release: release}, nil
	}, nil
}

// Tinfoil is this end of the link in a Tinfoil enclave, checking a peer that
// runs repo's releases.
func Tinfoil(repo string) (*Side, error) {
	key, err := LoadKey(KeyDir)
	if err != nil {
		return nil, fmt.Errorf("the attested link key: %w", err)
	}
	endorse, err := TinfoilKeyChecker(repo, KeyID)
	if err != nil {
		return nil, err
	}
	check := func(doc, nonce []byte) (ed25519.PublicKey, error) {
		e, err := endorse(doc, nonce)
		return e.Key, err
	}
	return &Side{Key: key, Attester: NewSocketAttester(AttestationSocket), Check: check, Endorse: endorse}, nil
}
