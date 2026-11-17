//go:build !dev

package main

import (
	"crypto/ed25519"
	"crypto/rand"

	"github.com/fount-labs/fount-broker/internal/attested"
	"github.com/fount-labs/fount-broker/internal/jobcred"
)

// jobKeys are the enclave's attested job-signing key, which the proxy learns
// from this enclave's attestation, and a cache secret drawn for this boot.
// Neither outlives the boot, so nothing holds them in between: a reboot costs
// the accounts' prompt caches, and credentials already minted stay good under
// the old key until they expire.
func jobKeys(string) (ed25519.PrivateKey, []byte, error) {
	key, err := attested.LoadEd25519(attested.Dir, jobcred.AttestedKeyID)
	if err != nil {
		return nil, nil, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, nil, err
	}
	return key, secret, nil
}
