// Package vaultkey fetches the coordinator's wrapping key from Fount Cloud's
// vault pair (m4-cloud-runners.md §4), so the key outlives every coordinator
// update without touching a disk.
//
// The vaults are Fount Mail's vault code, unchanged, run as a separate pair
// from their own public config repo. To them the coordinator is what the edge
// is to the mail vaults: their EDGE_REPO is the coordinator's config repo, so
// a coordinator release at or above their EDGE_MIN_TAG gets the keyset, sealed
// to its attested `transfer` key, over the vault's own pull protocol
// (github.com/fount-labs/fount-mail-vault/wire). The coordinator checks the
// keyset against the commitment in its own measured config, and the vault's
// document against the vault repo, then derives the wrapping key from it. It
// never generates a keyset, and never serves one: it's a leaf, not a peer.
package vaultkey

import (
	"context"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/fount-labs/fount-mail-vault/wire"

	"github.com/fount-labs/fount-broker/internal/coordinator"
)

// wrappingInfo separates the wrapping key from anything else derived from the
// same keyset, and from the mail keyset's own uses of its fields.
const wrappingInfo = "fount-coordinator/wrapping-key/v1"

// Source is where a coordinator gets its wrapping key.
type Source struct {
	// Vaults are the vaults' origins, https://<host>, tried in order.
	Vaults []string
	// Commitment is the Cloud keyset's KEYSET_COMMITMENT, from this release's
	// config. Only that keyset is taken, whichever vault serves it.
	Commitment string
	// Transfer is this enclave's attested `transfer` key, which the vaults
	// seal to.
	Transfer *ecdh.PrivateKey
	Attester wire.Attester
	// Check verifies a vault's document and returns the key it endorses.
	Check  wire.HolderCheck
	Client *http.Client
}

// Fetched is a wrapping key and where it came from.
type Fetched struct {
	Key        coordinator.WrappingKey
	Commitment string
	Vault      string
	Elapsed    time.Duration
}

// Fetch asks each vault once, in order, and returns the first keyset that
// verifies.
func (s *Source) Fetch(ctx context.Context) (*Fetched, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	var errs []error
	for _, vault := range s.Vaults {
		got, err := wire.Pull(ctx, s.Client, vault, s.Transfer, s.Attester, s.Check, s.Commitment)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", vault, err))
			continue
		}
		commitment := got.Keyset.Commitment()
		key, err := Derive(got.Keyset)
		if err != nil {
			return nil, err
		}
		return &Fetched{Key: key, Commitment: commitment, Vault: vault, Elapsed: got.Elapsed}, nil
	}
	return nil, errors.Join(errs...)
}

// Backoff is how long Wait waits between rounds: first, doubling to most.
type Backoff struct{ First, Most time.Duration }

// DefaultBackoff is the vaults' own restore schedule.
var DefaultBackoff = Backoff{First: 5 * time.Second, Most: 2 * time.Minute}

// Wait fetches until a vault answers or ctx ends. A coordinator can't do
// anything without the key, so with both vaults down it waits for them; a
// running coordinator keeps the key it has.
func (s *Source) Wait(ctx context.Context, b Backoff, failed func(error)) (*Fetched, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	wait := b.First
	for {
		got, err := s.Fetch(ctx)
		if err == nil {
			return got, nil
		}
		if failed != nil {
			failed(err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
		wait = min(wait*2, b.Most)
	}
}

// check refuses a Source that would take an unauthenticated key.
func (s *Source) check() error {
	switch {
	case len(s.Vaults) == 0:
		return errors.New("no vaults")
	case s.Transfer == nil || s.Attester == nil || s.Client == nil:
		return errors.New("a vault source needs the transfer key, an attester and a client")
	case s.Check == nil:
		return errors.New("a vault source needs a check of the vault's document")
	}
	if err := wire.ValidateCommitment(s.Commitment); err != nil {
		return fmt.Errorf("the keyset commitment: %w", err)
	}
	return nil
}

// Derive is the wrapping key from a Cloud keyset. Both of its random 32-byte
// keys go in; its ACME key, which only the mail edge uses, doesn't. The
// keyset's fields are cleared after.
func Derive(k *wire.Keyset) (coordinator.WrappingKey, error) {
	secret := make([]byte, 0, 2*len(k.AddressMACKey))
	secret = append(secret, k.AddressMACKey[:]...)
	secret = append(secret, k.RoutingDataKey[:]...)
	raw, err := hkdf.Key(sha256.New, secret, nil, wrappingInfo, coordinator.KeySize)
	clear(secret)
	clear(k.AddressMACKey[:])
	clear(k.RoutingDataKey[:])
	clear(k.ACMEAccountKey)
	var key coordinator.WrappingKey
	if err != nil {
		return key, err
	}
	copy(key[:], raw)
	clear(raw)
	return key, nil
}

// KeyID names a wrapping key without revealing it, so /status can show that
// two coordinators hold the same one.
func KeyID(key *coordinator.WrappingKey) string {
	m := hmac.New(sha256.New, key[:])
	m.Write([]byte("fount-coordinator/key-id/v1"))
	return hex.EncodeToString(m.Sum(nil)[:8])
}

// ParseVaults reads a comma-separated list of bare vault hostnames into
// origins.
func ParseVaults(list string) ([]string, error) {
	var out []string
	for _, h := range strings.Split(list, ",") {
		if h = strings.TrimSpace(h); h == "" {
			continue
		}
		if strings.ContainsAny(h, "/?#@: ") {
			return nil, fmt.Errorf("vault %q must be a bare hostname", h)
		}
		out = append(out, "https://"+h)
	}
	if len(out) == 0 {
		return nil, errors.New("no vaults named")
	}
	return out, nil
}
