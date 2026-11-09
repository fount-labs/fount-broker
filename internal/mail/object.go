package mail

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// The stored-message object (design §9, edge internal/store/message.go):
//
//	magic "FME1" | version(1) | suite(6) | edge id(16) | mailbox id(32) |
//	pubkey hash(32) | received_at(8, unix ms) | sequence(8) | boot id(16) |
//	encLen(2) enc | ctLen(4) ct | ed25519 signature(64) over everything before it
//
// The header up to the boot id is the HPKE AAD, so the version is signed and
// bound to the ciphertext. The version names the plaintext framing, big-endian
// lengths:
//
//	1: senderLen(2) sender | recipientLen(2) recipient | raw message
//	2: senderLen(2) sender | recipientLen(2) recipient |
//	   clientIPFrom(1) | clientIPLen(1) clientIP | heloLen(1) helo | raw message
const (
	objMagic  = "FME1"
	objV1     = 1
	objV2     = 2
	hpkeInfo  = "fount-mail-edge/v1/stored-message"
	headerLen = 4 + 1 + 6 + 16 + 32 + 32 + 8 + 8 + 16
	// MaxObject bounds a fetched object: a 25 MB message with its envelope and
	// framing, rounded up.
	MaxObject = 32 << 20
)

// suite is DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
var suite = []byte{0x00, 0x20, 0x00, 0x01, 0x00, 0x01}

// Object is a parsed stored message. Nothing in it is trusted until Verify
// succeeds with the right boot's key.
type Object struct {
	Version    byte
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
	if b[4] != objV1 && b[4] != objV2 {
		return nil, fmt.Errorf("%w: version %d", ErrMalformed, b[4])
	}
	if !bytes.Equal(b[5:11], suite) {
		return nil, fmt.Errorf("%w: suite %x", ErrMalformed, b[5:11])
	}
	o := &Object{Version: b[4], header: b[:headerLen]}
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

// Envelope is what the edge sealed besides the message: the SMTP envelope and,
// from version 2, the sending server's address and HELO name. All of it is what
// the sender or the gateway said; nothing here is verified.
type Envelope struct {
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	// ClientIP is the sending server's address in netip's canonical form, or
	// empty. ClientIPSource says where the edge got it.
	ClientIP       string `json:"client_ip,omitempty"`
	ClientIPSource string `json:"client_ip_source,omitempty"`
	// HELO is the session's last EHLO or HELO name, or empty.
	HELO string `json:"helo,omitempty"`
}

// ClientIPSource values. Empty means the edge recorded no address (all
// version 1 objects, and version 2 with source byte 0).
const (
	// ClientIPGatewayProxy: the source address in the PROXY v1 header the
	// gateway writes inside its mutual TLS to the edge (edge design §7).
	// Nothing attests the gateway, so the address, and any SPF result computed
	// from it, is only as honest as the gateway.
	ClientIPGatewayProxy = "gateway_proxy"
)

// The edge's limits on the version 2 fields, and its source bytes.
const (
	maxClientIP = 45
	maxHELO     = 255
	ipFromNone  = 0
	ipFromProxy = 1
)

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
	env, raw, err := unframe(o.Version, pt)
	if err != nil {
		return Envelope{}, nil, err
	}
	return env, raw, nil
}

// unframe splits a decrypted plaintext of the given version into its envelope
// and raw message, refusing anything the edge would not have written.
func unframe(version byte, p []byte) (Envelope, []byte, error) {
	bad := func(why string) (Envelope, []byte, error) {
		return Envelope{}, nil, fmt.Errorf("%w: bad envelope framing: %s", ErrMalformed, why)
	}
	str16 := func() (string, bool) {
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
	str8 := func(limit int) (string, bool) {
		if len(p) < 1 {
			return "", false
		}
		n := int(p[0])
		if n > limit || len(p) < 1+n {
			return "", false
		}
		v := string(p[1 : 1+n])
		p = p[1+n:]
		return v, true
	}
	var env Envelope
	var ok bool
	if env.Sender, ok = str16(); !ok {
		return bad("sender")
	}
	if env.Recipient, ok = str16(); !ok {
		return bad("recipient")
	}
	switch version {
	case objV1:
		return env, p, nil
	case objV2:
	default:
		return bad(fmt.Sprintf("version %d", version))
	}
	if len(p) < 1 {
		return bad("client IP source")
	}
	from := p[0]
	p = p[1:]
	ip, ok := str8(maxClientIP)
	if !ok {
		return bad("client IP")
	}
	switch from {
	case ipFromNone:
		if ip != "" {
			return bad("client IP with no source")
		}
	case ipFromProxy:
		a, err := netip.ParseAddr(ip)
		if err != nil || a.Zone() != "" || a.String() != ip {
			return bad(fmt.Sprintf("client IP %q", ip))
		}
		env.ClientIP, env.ClientIPSource = ip, ClientIPGatewayProxy
	default:
		return bad(fmt.Sprintf("client IP source %d", from))
	}
	if env.HELO, ok = str8(maxHELO); !ok {
		return bad("HELO")
	}
	return env, p, nil
}
