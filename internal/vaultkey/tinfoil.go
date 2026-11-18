package vaultkey

import (
	"crypto/ecdh"
	"fmt"
	"net/http"
	"time"

	"github.com/fount-labs/fount-mail-vault/wire"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

// transferKeyID is the attested key a vault seals to and endorses its own
// side with: the mail vault's name for it, which its verifier reads.
const transferKeyID = "transfer"

// TinfoilCheck verifies a vault's document against repo, the vault pair's
// public config repo: hardware, provenance, freshness and the nonce, offline.
// It returns the `transfer` key the document endorses, which wire.Pull
// compares with the key the vault sealed with.
func TinfoilCheck(repo string) (wire.HolderCheck, error) {
	v, err := verify.NewVerifier()
	if err != nil {
		return nil, err
	}
	if err := v.CheckPinVerifiability(verify.Pin{Repo: repo}); err != nil {
		return nil, fmt.Errorf("vault pin %q: %w", repo, err)
	}
	return func(doc, nonce []byte) (*ecdh.PublicKey, error) {
		verified, err := v.VerifyV3(doc, nonce, verify.Pin{Repo: repo})
		if err != nil {
			return nil, err
		}
		spki, ok := verified.CryptoMaterialData(transferKeyID, document.KeySPKIV1Format)
		if !ok {
			return nil, fmt.Errorf("the vault's attestation endorses no %q key", transferKeyID)
		}
		return wire.ParseEndorsedKey(spki)
	}, nil
}

// Tinfoil is a Source in a Tinfoil enclave: its attested `transfer` key, its
// attestation socket, and vaults that must run releases of repo.
func Tinfoil(vaults []string, repo, commitment string) (*Source, error) {
	transfer, err := wire.LoadTransferKey(wire.TransferKeyPath)
	if err != nil {
		return nil, fmt.Errorf("the attested %q key: %w", transferKeyID, err)
	}
	check, err := TinfoilCheck(repo)
	if err != nil {
		return nil, err
	}
	return &Source{
		Vaults:     vaults,
		Commitment: commitment,
		Transfer:   transfer,
		Attester:   wire.NewSocketAttester(wire.AttestationSocket),
		Check:      check,
		Client:     &http.Client{Timeout: 90 * time.Second},
	}, nil
}
