// Package mailtest builds stored-message objects the way the edge does, for
// tests of the readers. Nothing outside tests imports it.
package mailtest

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"time"
)

// Object is what an edge would seal into a version 3 object.
type Object struct {
	EdgeID     []byte // 16 bytes
	MailboxID  []byte // 32 bytes
	ReceivedAt time.Time
	Sequence   uint64
	BootID     []byte // 16 bytes

	Sender, Recipient string
	ClientIP          string // empty, or an address from the gateway's PROXY header
	HELO              string
	Check             []byte
	Raw               []byte
}

// SealV3 seals o to the address's public key and signs it with the boot's key,
// in the layout of the edge's internal/store/message.go at format version 3.
func SealV3(o Object, to *ecdh.PublicKey, boot ed25519.PrivateKey) ([]byte, error) {
	suite := []byte{0x00, 0x20, 0x00, 0x01, 0x00, 0x01}
	keyHash := sha256.Sum256(to.Bytes())
	h := append([]byte("FME1"), 3)
	h = append(h, suite...)
	h = append(h, o.EdgeID...)
	h = append(h, o.MailboxID...)
	h = append(h, keyHash[:]...)
	h = binary.BigEndian.AppendUint64(h, uint64(o.ReceivedAt.UnixMilli()))
	h = binary.BigEndian.AppendUint64(h, o.Sequence)
	h = append(h, o.BootID...)

	var pt []byte
	pt = binary.BigEndian.AppendUint16(pt, uint16(len(o.Sender)))
	pt = append(pt, o.Sender...)
	pt = binary.BigEndian.AppendUint16(pt, uint16(len(o.Recipient)))
	pt = append(pt, o.Recipient...)
	if o.ClientIP == "" {
		pt = append(pt, 0, 0)
	} else {
		pt = append(pt, 1, byte(len(o.ClientIP)))
		pt = append(pt, o.ClientIP...)
	}
	pt = append(pt, byte(len(o.HELO)))
	pt = append(pt, o.HELO...)
	pt = binary.BigEndian.AppendUint32(pt, uint32(len(o.Check)))
	pt = append(pt, o.Check...)
	pt = append(pt, o.Raw...)

	pk, err := hpke.NewDHKEMPublicKey(to)
	if err != nil {
		return nil, err
	}
	enc, s, err := hpke.NewSender(pk, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte("fount-mail-edge/v1/stored-message"))
	if err != nil {
		return nil, err
	}
	ct, err := s.Seal(h, pt)
	if err != nil {
		return nil, err
	}
	b := binary.BigEndian.AppendUint16(h, uint16(len(enc)))
	b = append(b, enc...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(ct)))
	b = append(b, ct...)
	return append(b, ed25519.Sign(boot, b)...), nil
}

// Check is a passing edge check for a message from "from" to "to", made over raw.
func Check(from, to string, raw []byte) []byte {
	domain := after(from)
	sum := sha256.Sum256(raw)
	b, _ := json.Marshal(map[string]any{
		"v": 1, "checked_by": "edge",
		"from": map[string]any{"address": from, "domain": domain},
		"dkim": []any{map[string]any{"domain": domain, "selector": "s", "algorithm": "ed25519-sha256", "result": "pass",
			"key_bits": 256, "headers": []string{"from", "to", "date", "subject"}, "body_length": false, "testing": false,
			"covers": true, "hash": "ab12", "aligned": true}},
		"aligned": true, "recipient_signed": true, "date_skew_seconds": -30,
		"headers":    map[string]any{"to": []string{to}, "subject": "Q3"},
		"raw_sha256": hex.EncodeToString(sum[:]),
	})
	return b
}

func after(addr string) string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == '@' {
			return addr[i+1:]
		}
	}
	return ""
}
