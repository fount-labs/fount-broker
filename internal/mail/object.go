package mail

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// The stored-message object (design §9, edge internal/store/message.go):
//
//	magic "FME1" | version 1 | suite(6) | edge id(16) | mailbox id(32) |
//	pubkey hash(32) | received_at(8, unix ms) | sequence(8) | boot id(16) |
//	encLen(2) enc | ctLen(4) ct | ed25519 signature(64) over everything before it
//
// The header up to the boot id is the HPKE AAD. The plaintext is
// senderLen(2) sender | recipientLen(2) recipient | raw message.
const (
	objMagic   = "FME1"
	objVersion = 1
	hpkeInfo   = "fount-mail-edge/v1/stored-message"
	headerLen  = 4 + 1 + 6 + 16 + 32 + 32 + 8 + 8 + 16
	// MaxObject bounds a fetched object: a 25 MB message with its envelope and
	// framing, rounded up.
	MaxObject = 32 << 20
)

// suite is DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
var suite = []byte{0x00, 0x20, 0x00, 0x01, 0x00, 0x01}

// Object is a parsed stored message. Nothing in it is trusted until Verify
// succeeds with the right boot's key.
type Object struct {
	EdgeID     []byte
	MailboxID  []byte
	PubKeyHash []byte
	ReceivedAt time.Time
	Sequence   uint64
	BootID     []byte
	Enc, Ct    []byte

	header []byte // the AAD
	signed []byte
	sig    []byte
}

var ErrMalformed = errors.New("mail: malformed message object")

// ParseObject decodes the framing. It checks lengths, magic, version and suite,
// not the signature.
func ParseObject(b []byte) (*Object, error) {
	if len(b) < headerLen+2+4+ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: %d bytes is too short", ErrMalformed, len(b))
	}
	if len(b) > MaxObject {
		return nil, fmt.Errorf("%w: %d bytes is too long", ErrMalformed, len(b))
	}
	if string(b[:4]) != objMagic {
		return nil, fmt.Errorf("%w: bad magic", ErrMalformed)
	}
	if b[4] != objVersion {
		return nil, fmt.Errorf("%w: version %d", ErrMalformed, b[4])
	}
	if !bytes.Equal(b[5:11], suite) {
		return nil, fmt.Errorf("%w: suite %x", ErrMalformed, b[5:11])
	}
	o := &Object{header: b[:headerLen]}
	off := 11
	take := func(n int) []byte {
		v := b[off : off+n]
		off += n
		return v
	}
	o.EdgeID = take(16)
	o.MailboxID = take(32)
	o.PubKeyHash = take(32)
	o.ReceivedAt = time.UnixMilli(int64(binary.BigEndian.Uint64(take(8))))
	o.Sequence = binary.BigEndian.Uint64(take(8))
	o.BootID = take(16)

	encLen := int(binary.BigEndian.Uint16(take(2)))
	if len(b)-off < encLen+4+ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: enc overruns the object", ErrMalformed)
	}
	o.Enc = take(encLen)
	ctLen := int(binary.BigEndian.Uint32(take(4)))
	if len(b)-off != ctLen+ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: ciphertext length %d doesn't match the object", ErrMalformed, ctLen)
	}
	o.Ct = take(ctLen)
	o.signed = b[:off]
	o.sig = b[off:]
	return o, nil
}

var ErrSignature = errors.New("mail: message signature does not verify against its boot's key")

// Verify checks the edge's signature with the signing key of the boot the
// object names.
func (o *Object) Verify(bootKey ed25519.PublicKey) error {
	if len(bootKey) != ed25519.PublicKeySize || !ed25519.Verify(bootKey, o.signed, o.sig) {
		return ErrSignature
	}
	return nil
}

// Envelope is what the edge sealed besides the message: the SMTP envelope.
type Envelope struct {
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
}

var (
	ErrWrongMailbox = errors.New("mail: message is for another mailbox")
	ErrWrongKey     = errors.New("mail: message is sealed to a public key this device doesn't hold")
	ErrDecrypt      = errors.New("mail: message does not decrypt")
)

// Open decrypts a verified object with the address's keys.
func (o *Object) Open(k *Keys) (Envelope, []byte, error) {
	if !bytes.Equal(o.MailboxID, k.MailboxID) {
		return Envelope{}, nil, ErrWrongMailbox
	}
	sum := sha256.Sum256(k.Decryption.PublicKey().Bytes())
	if !bytes.Equal(o.PubKeyHash, sum[:]) {
		return Envelope{}, nil, ErrWrongKey
	}
	priv, err := hpke.NewDHKEMPrivateKey(k.Decryption)
	if err != nil {
		return Envelope{}, nil, err
	}
	r, err := hpke.NewRecipient(o.Enc, priv, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte(hpkeInfo))
	if err != nil {
		return Envelope{}, nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	pt, err := r.Open(o.header, o.Ct)
	if err != nil {
		return Envelope{}, nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	env, raw, err := unframe(pt)
	if err != nil {
		return Envelope{}, nil, err
	}
	return env, raw, nil
}

func unframe(p []byte) (Envelope, []byte, error) {
	field := func() (string, bool) {
		if len(p) < 2 {
			return "", false
		}
		n := int(binary.BigEndian.Uint16(p))
		if len(p) < 2+n {
			return "", false
		}
		v := string(p[2 : 2+n])
		p = p[2+n:]
		return v, true
	}
	sender, ok1 := field()
	recipient, ok2 := field()
	if !ok1 || !ok2 {
		return Envelope{}, nil, fmt.Errorf("%w: bad envelope framing", ErrMalformed)
	}
	return Envelope{Sender: sender, Recipient: recipient}, p, nil
}
