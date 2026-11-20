package vaultkey

import (
	"crypto/ed25519"
	"errors"
	"net/http"
	"time"

	"github.com/fount-labs/fount-mail-vault/wire"

	"github.com/fount-labs/fount-broker/internal/coordinator"
)

// NewCounter is the Cloud vaults' counter, at vaults (origins, as
// ParseVaults gives them) in order, for gen's process; gen is nil in a
// restore dry run.
func NewCounter(vaults []string, authority ed25519.PublicKey, gen *coordinator.FixedGeneration) (*coordinator.WireCounter, error) {
	if len(vaults) == 0 || len(authority) != ed25519.PublicKeySize {
		return nil, errors.New("the vault counter needs the vaults and the generation authority's key")
	}
	return &coordinator.WireCounter{
		Client: &wire.CounterClient{Vaults: vaults, Authority: authority, Client: &http.Client{Timeout: 30 * time.Second}},
		Gen:    gen,
	}, nil
}
