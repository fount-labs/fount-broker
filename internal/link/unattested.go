package link

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
)

// Unattested is an end with a fresh key and a document anyone could write:
// it names the key and echoes the nonce, and no hardware vouches for it. The
// handshake runs as in an enclave, so dev builds and tests exercise it, but it
// proves nothing; only dev builds offer it.
func Unattested() (*Side, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Side{Key: key, Attester: unattested{key.Public().(ed25519.PublicKey)}, Check: checkUnattested}, nil
}

type unattested struct{ key ed25519.PublicKey }

type unattestedDoc struct {
	Unattested bool   `json:"unattested"`
	Key        []byte `json:"key"`
	Nonce      []byte `json:"nonce"`
}

func (u unattested) Attest(_ context.Context, nonce []byte) ([]byte, error) {
	return json.Marshal(unattestedDoc{Unattested: true, Key: u.key, Nonce: nonce})
}

func checkUnattested(doc, nonce []byte) (ed25519.PublicKey, error) {
	var d unattestedDoc
	if err := json.Unmarshal(doc, &d); err != nil || !d.Unattested || len(d.Key) != ed25519.PublicKeySize {
		return nil, errors.New("not an unattested document")
	}
	if !bytes.Equal(d.Nonce, nonce) {
		return nil, errors.New("the document is for another session")
	}
	return ed25519.PublicKey(d.Key), nil
}

// CheckUnattestedKey is the KeyChecker for an unattested document, which has
// no freshness deadline.
func CheckUnattestedKey(doc, nonce []byte) (Endorsement, error) {
	key, err := checkUnattested(doc, nonce)
	return Endorsement{Key: key}, err
}
