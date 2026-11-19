package coordinator

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

// Each device has two keys: the Ed25519 key it signs with, whose hash is its
// id, and an X25519 key a worker's DEK is wrapped to. A device is listed in a
// team only on its own inclusion (teamlist.go), which binds the two.
//
// A wrap is the DEK sealed to one device's X25519 key with HPKE (RFC 9180,
// base mode): DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305,
// info WrapInfo, one Seal with the AAD wrapAAD makes. It is enc (32 bytes)
// followed by the sealed DEK (48), WrapSize in all. The coordinator seals
// one for each device that reaches a worker (members.go), from the DEK it
// holds, so a device can open the worker's files without another device at
// hand.
const (
	WrapInfo = "fount-worker-dek-wrap-v1"
	// WrapSize is enc, the DEK and the AEAD tag.
	WrapSize = 32 + KeySize + 16

	wrapAADContext = "fount-worker-dek-wrap-aad-v1\x00"
)

var wrapSuite = struct {
	kem  hpke.KEM
	kdf  hpke.KDF
	aead hpke.AEAD
}{hpke.DHKEM(ecdh.X25519()), hpke.HKDFSHA256(), hpke.ChaCha20Poly1305()}

// x25519Probe is a fixed scalar for checkX25519.
var x25519Probe = sha256.Sum256([]byte("fount-worker-device-x25519-probe"))

// checkX25519 refuses a low-order X25519 public key, the all-zero one among
// them: a DEK wrapped to it is sealed under a shared secret anyone can
// compute. Every low-order point gives the all-zero output whatever the
// scalar, which crypto/ecdh refuses.
func checkX25519(enc []byte) error {
	pub, err := ecdh.X25519().NewPublicKey(enc)
	if err != nil {
		return err
	}
	priv, err := ecdh.X25519().NewPrivateKey(x25519Probe[:])
	if err != nil {
		return err
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return errors.New("it is a low-order point")
	}
	if subtle.ConstantTimeCompare(shared, make([]byte, len(shared))) == 1 {
		return errors.New("it is a low-order point")
	}
	return nil
}

// lengthPrefixed is context, then each field as a 2-byte big-endian length
// and its bytes.
func lengthPrefixed(context string, fields ...[]byte) ([]byte, error) {
	out := []byte(context)
	for _, f := range fields {
		if len(f) > 0xffff {
			return nil, errors.New("a field is over 65535 bytes")
		}
		out = binary.BigEndian.AppendUint16(out, uint16(len(f)))
		out = append(out, f...)
	}
	return out, nil
}

// wrapAAD is a wrap's AAD: wrapAADContext, then the account, worker id,
// device id and DEK commitment, length-prefixed.
func wrapAAD(account, workerID, device, commitment string) ([]byte, error) {
	return lengthPrefixed(wrapAADContext, []byte(account), []byte(workerID), []byte(device), []byte(commitment))
}

func hpkeSender(pk hpke.PublicKey) ([]byte, *hpke.Sender, error) {
	return hpke.NewSender(pk, wrapSuite.kdf, wrapSuite.aead, []byte(WrapInfo))
}

// SealWrap wraps dek to a device's X25519 public key enc, for the account
// (the worker's team), worker and device id it is kept under.
func SealWrap(enc []byte, account, workerID, device string, dek DEK) ([]byte, error) {
	pk, err := wrapSuite.kem.NewPublicKey(enc)
	if err != nil {
		return nil, err
	}
	aad, err := wrapAAD(account, workerID, device, DEKCommitment(workerID, dek))
	if err != nil {
		return nil, err
	}
	e, sender, err := hpkeSender(pk)
	if err != nil {
		return nil, err
	}
	ct, err := sender.Seal(aad, dek[:])
	if err != nil {
		return nil, err
	}
	return append(e, ct...), nil
}

// OpenWrap is the device's: its X25519 private key opens a wrap of the
// worker's DEK, which must match the commitment its team's list signed.
func OpenWrap(priv []byte, account, workerID, device, commitment string, wrap []byte) (DEK, error) {
	if len(wrap) != WrapSize {
		return DEK{}, fmt.Errorf("a wrap is %d bytes", WrapSize)
	}
	sk, err := wrapSuite.kem.NewPrivateKey(priv)
	if err != nil {
		return DEK{}, err
	}
	aad, err := wrapAAD(account, workerID, device, commitment)
	if err != nil {
		return DEK{}, err
	}
	r, err := hpke.NewRecipient(wrap[:32], sk, wrapSuite.kdf, wrapSuite.aead, []byte(WrapInfo))
	if err != nil {
		return DEK{}, err
	}
	pt, err := r.Open(aad, wrap[32:])
	if err != nil {
		return DEK{}, errors.New("the wrap doesn't open: another device, worker or DEK")
	}
	var dek DEK
	copy(dek[:], pt)
	clear(pt)
	if subtle.ConstantTimeCompare([]byte(DEKCommitment(workerID, dek)), []byte(commitment)) != 1 {
		clear(dek[:])
		return DEK{}, errors.New("the wrap holds another DEK than the commitment")
	}
	return dek, nil
}
