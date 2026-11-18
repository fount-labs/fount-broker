//go:build dev

package main

import (
	"crypto/ed25519"
	"fmt"
	"log"

	"github.com/fount-labs/fount-broker/internal/link"
)

// clientAttestation is the channel's key and attester: the enclave's attested
// fount-client key and its attestation socket, or with unattested, a fresh key
// and a document no hardware vouches for, for a dev build's broker.
func clientAttestation(mode string) (ed25519.PrivateKey, link.Attester, error) {
	switch mode {
	case attestTinfoil:
		key, err := loadClientKey()
		if err != nil {
			return nil, nil, err
		}
		return key, link.NewSocketAttester(link.AttestationSocket), nil
	case attestUnattested:
		log.Printf("the client channel is unattested: nothing vouches for this coordinator")
		side, err := link.Unattested()
		if err != nil {
			return nil, nil, err
		}
		return side.Key, side.Attester, nil
	}
	return nil, nil, fmt.Errorf("--client-attestation %q: tinfoil or unattested", mode)
}
