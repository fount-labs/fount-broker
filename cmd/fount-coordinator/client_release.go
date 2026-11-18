//go:build !dev

package main

import (
	"crypto/ed25519"
	"fmt"

	"github.com/fount-labs/fount-broker/internal/link"
)

// clientAttestation is the channel's key and attester: the enclave's attested
// fount-link key, the one its runner link uses, and its attestation socket.
func clientAttestation(mode string) (ed25519.PrivateKey, link.Attester, error) {
	if mode != attestTinfoil {
		return nil, nil, fmt.Errorf("--client-attestation %q: release builds attest with tinfoil only", mode)
	}
	key, err := link.LoadKey(link.KeyDir)
	if err != nil {
		return nil, nil, fmt.Errorf("the attested link key: %w", err)
	}
	return key, link.NewSocketAttester(link.AttestationSocket), nil
}
