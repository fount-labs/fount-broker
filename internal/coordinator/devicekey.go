package coordinator

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Each device has two keys: the Ed25519 key it signs with, whose hash is its
// id, and an X25519 key the worker's DEK is wrapped to. A grant names devices
// by their Ed25519 keys, but the granting device's word alone doesn't add one:
// each device on the list signs its own inclusion, which binds its X25519 key
// to its Ed25519 key, the coordinator, the account, the worker and the DEK,
// and says from which grant on it is listed. So neither a compromised
// granting device nor whoever controls fount-infra's device registry can list
// a device whose key they don't hold.
//
// An inclusion is sent like a grant: base64url(claims) "." base64url(sig),
// the device's Ed25519 signature over InclusionContext followed by the
// claims bytes. Its Seq is the grant that first lists the device. A device
// stays listed on that inclusion through later grants; once a grant drops it,
// coming back takes a new inclusion numbered for the grant that brings it
// back, so a removed device's old inclusion doesn't let anyone re-add it.
//
// A wrap is the DEK sealed to one device's X25519 key with HPKE (RFC 9180,
// base mode): DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305,
// info WrapInfo, one Seal with the AAD wrapAAD makes. It is enc (32 bytes)
// followed by the sealed DEK (48), WrapSize in all. The coordinator checks
// each listed device has one, that the grant signed them all (WrapsDigest),
// and keeps them; it never opens one.
const (
	InclusionVersion = 1
	InclusionType    = "fount-worker-device"
	InclusionContext = "fount-worker-device-v1\n"

	WrapInfo = "fount-worker-dek-wrap-v1"
	// WrapSize is enc, the DEK and the AEAD tag.
	WrapSize = 32 + KeySize + 16

	wrapAADContext = "fount-worker-dek-wrap-aad-v1\x00"
	wrapsContext   = "fount-worker-wraps-v1\x00"
)

// InclusionClaims are what a device signs to be listed for a worker.
type InclusionClaims struct {
	V   int    `json:"v"`
	Typ string `json:"typ"`
	// Aud is the coordinator's audience (Config.Audience), as in a grant.
	Aud  string `json:"aud"`
	Acct string `json:"acct"`
	// Worker is the worker's id, and DEK is DEKCommitment of its DEK: the
	// inclusion is good for this worker alone.
	Worker string `json:"worker"`
	DEK    string `json:"dek"`
	// Dev is the device's id; Key its Ed25519 public key and Enc its X25519
	// public key, raw, base64url.
	Dev string `json:"dev"`
	Key string `json:"key"`
	Enc string `json:"enc"`
	// Seq is the grant that first lists the device.
	Seq uint64 `json:"seq"`
}

var wrapSuite = struct {
	kem  hpke.KEM
	kdf  hpke.KDF
	aead hpke.AEAD
}{hpke.DHKEM(ecdh.X25519()), hpke.HKDFSHA256(), hpke.ChaCha20Poly1305()}

// SignInclusion is Desktop's half, on the device to be listed: its Ed25519
// key signs claims, filling in their version, type, id and key; enc is its
// X25519 public key. Like SignGrant, this is the reference for Desktop's Rust.
func SignInclusion(device ed25519.PrivateKey, enc []byte, c InclusionClaims) (string, error) {
	if len(enc) != 32 {
		return "", errors.New("an X25519 public key is 32 bytes")
	}
	pub := device.Public().(ed25519.PublicKey)
	c.V, c.Typ, c.Dev, c.Key, c.Enc = InclusionVersion, InclusionType, deviceID(pub), b64.EncodeToString(pub), b64.EncodeToString(enc)
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(device, append([]byte(InclusionContext), payload...))
	return b64.EncodeToString(payload) + "." + b64.EncodeToString(sig), nil
}

// parseInclusion checks an inclusion's signature by the key it names and
// that it is for this coordinator, account, worker and DEK.
func parseInclusion(token, aud, account, workerID, commitment string) (InclusionClaims, ed25519.PublicKey, []byte, error) {
	p, s, ok := strings.Cut(token, ".")
	if !ok || strings.Contains(s, ".") {
		return InclusionClaims{}, nil, nil, errors.New("an inclusion is malformed")
	}
	payload, err := b64.DecodeString(p)
	if err != nil || len(payload) == 0 {
		return InclusionClaims{}, nil, nil, errors.New("an inclusion is malformed")
	}
	sig, err := b64.DecodeString(s)
	if err != nil {
		return InclusionClaims{}, nil, nil, errors.New("an inclusion is malformed")
	}
	var c InclusionClaims
	if err := json.Unmarshal(payload, &c); err != nil || c.V != InclusionVersion || c.Typ != InclusionType {
		return InclusionClaims{}, nil, nil, errors.New("an inclusion is malformed")
	}
	key, err := b64.DecodeString(c.Key)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return InclusionClaims{}, nil, nil, errors.New("an inclusion's key isn't 32 bytes of base64url")
	}
	enc, err := b64.DecodeString(c.Enc)
	if err != nil || len(enc) != 32 {
		return InclusionClaims{}, nil, nil, errors.New("an inclusion's X25519 key isn't 32 bytes of base64url")
	}
	if err := checkX25519(enc); err != nil {
		return InclusionClaims{}, nil, nil, fmt.Errorf("an inclusion's X25519 key: %w", err)
	}
	switch {
	case !ed25519.Verify(key, append([]byte(InclusionContext), payload...), sig):
		return InclusionClaims{}, nil, nil, errors.New("an inclusion isn't signed by the key it names")
	case c.Dev != deviceID(key):
		return InclusionClaims{}, nil, nil, errors.New("an inclusion names another device than its key's")
	case c.Aud != aud:
		return InclusionClaims{}, nil, nil, errors.New("an inclusion is for another coordinator")
	case c.Acct != account:
		return InclusionClaims{}, nil, nil, errors.New("an inclusion is for another account")
	case c.Worker != workerID:
		return InclusionClaims{}, nil, nil, errors.New("an inclusion is for another worker")
	case subtle.ConstantTimeCompare([]byte(c.DEK), []byte(commitment)) != 1:
		return InclusionClaims{}, nil, nil, errors.New("an inclusion is for another DEK")
	}
	return c, key, enc, nil
}

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

// WrapsDigest is what a grant signs for its wraps (GrantClaims.Wraps):
// base64url SHA-256 of wrapsContext and, for each device in the order the
// grant lists them (devices, their ids), its id and wrap, length-prefixed.
// A device with no wrap is an error.
func WrapsDigest(devices []string, wraps map[string][]byte) (string, error) {
	var fields [][]byte
	for _, id := range devices {
		wrap, ok := wraps[id]
		if !ok {
			return "", fmt.Errorf("device %.40q has no wrap", id)
		}
		fields = append(fields, []byte(id), wrap)
	}
	b, err := lengthPrefixed(wrapsContext, fields...)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return b64.EncodeToString(sum[:]), nil
}

func hpkeSender(pk hpke.PublicKey) ([]byte, *hpke.Sender, error) {
	return hpke.NewSender(pk, wrapSuite.kdf, wrapSuite.aead, []byte(WrapInfo))
}

// SealWrap wraps dek to a device's X25519 public key enc, for the account,
// worker and device id it is kept under. Desktop's, like SignGrant.
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
// worker's DEK, which must match the commitment the worker's grant signed.
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

// withInclusions gives each device a grant names its X25519 key and the
// inclusion it signed, and checks there is exactly one per device. Whether
// each inclusion's number fits the worker's list is checked against the
// worker (sinceFits).
func withInclusions(devices []Device, inclusions []string, c GrantClaims) error {
	got := map[string]bool{}
	for _, token := range inclusions {
		ic, key, enc, err := parseInclusion(token, c.Aud, c.Acct, c.Worker, c.DEK)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrGrantRefused, err)
		}
		i := -1
		for j := range devices {
			if devices[j].ID == ic.Dev {
				i = j
			}
		}
		switch {
		case i < 0:
			return fmt.Errorf("%w: an inclusion of device %.40q, which it doesn't name", ErrGrantRefused, ic.Dev)
		case subtle.ConstantTimeCompare(devices[i].Key, key) != 1:
			return fmt.Errorf("%w: device %s's inclusion has another key than the grant", ErrGrantRefused, ic.Dev)
		case got[ic.Dev]:
			return fmt.Errorf("%w: device %s has two inclusions", ErrGrantRefused, ic.Dev)
		case ic.Seq == 0 || ic.Seq > c.Seq:
			return fmt.Errorf("%w: device %s's inclusion is for grant %d", ErrGrantRefused, ic.Dev, ic.Seq)
		}
		got[ic.Dev] = true
		devices[i].Enc, devices[i].Since, devices[i].Inclusion = enc, ic.Seq, token
	}
	for _, d := range devices {
		if !got[d.ID] {
			return fmt.Errorf("%w: device %s has no inclusion", ErrGrantRefused, d.ID)
		}
	}
	return nil
}

// sinceFits checks each device's inclusion against the worker's list before
// the grant: a device already listed keeps the inclusion it was listed on,
// and any other must sign one for this grant.
func sinceFits(prior []Device, devices []Device, seq uint64) error {
	for _, d := range devices {
		want := seq
		for _, p := range prior {
			if p.ID == d.ID && p.Since != 0 {
				want = p.Since
			}
		}
		if d.Since != want {
			return fmt.Errorf("%w: device %s's inclusion is for grant %d, and it must be for %d", ErrGrantRefused, d.ID, d.Since, want)
		}
	}
	return nil
}
