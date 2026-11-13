package coordinator

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// KeySize is the size of every symmetric key here: the wrapping key and each
// worker's DEK are AES-256 keys.
const KeySize = 32

// A DEK is one worker's data key (m4-cloud-runners.md §4). It exists unwrapped
// only in coordinator memory; at rest it is wrapped by the WrappingKey.
type DEK [KeySize]byte

// A WrappingKey wraps every worker's DEK on the volume. In an enclave it lives
// only in memory and is restored from peers after an update (§4, the vault
// pattern). The dev coordinator reads it from a file.
type WrappingKey [KeySize]byte

func NewDEK() (DEK, error) {
	var k DEK
	_, err := rand.Read(k[:])
	return k, err
}

func NewWrappingKey() (WrappingKey, error) {
	var k WrappingKey
	_, err := rand.Read(k[:])
	return k, err
}

// Each sealed thing is bound to what it is and whose it is, so a ciphertext
// moved to another worker or another slot fails to open.
const (
	purposeDEK      = "fount-coordinator/dek/v1"
	purposeManifest = "fount-coordinator/manifest/v1"
	purposeBlob     = "fount-coordinator/blob/v1"
)

func aad(purpose, workerID, name string) []byte {
	return []byte(purpose + "\x00" + workerID + "\x00" + name)
}

// Wrap seals a worker's DEK for the volume.
func (w *WrappingKey) Wrap(workerID string, dek DEK) ([]byte, error) {
	return seal(w[:], dek[:], aad(purposeDEK, workerID, ""))
}

// Unwrap opens a DEK sealed by Wrap for the same worker.
func (w *WrappingKey) Unwrap(workerID string, wrapped []byte) (DEK, error) {
	var k DEK
	plain, err := open(w[:], wrapped, aad(purposeDEK, workerID, ""))
	if err != nil {
		return k, fmt.Errorf("unwrap the DEK of worker %s: %w", workerID, err)
	}
	if len(plain) != KeySize {
		return k, fmt.Errorf("worker %s: wrapped DEK is %d bytes", workerID, len(plain))
	}
	copy(k[:], plain)
	return k, nil
}

var errOpen = errors.New("ciphertext doesn't open: wrong key, or it was changed or moved")

// seal is AES-256-GCM with a random nonce, stored as nonce || ciphertext.
func seal(key, plain, ad []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plain)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, ad), nil
}

func open(key, sealed, ad []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < aead.NonceSize()+aead.Overhead() {
		return nil, errOpen
	}
	plain, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], ad)
	if err != nil {
		return nil, errOpen
	}
	return plain, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
