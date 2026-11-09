package mail

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// GapRecord accounts for a sequence number with no message (edge
// internal/store.ExpiryRecord). "expired" means the edge's 30-day sweep deleted
// an unfetched message; "void" means the number was spent but nothing was
// stored and the sender was told to retry.
type GapRecord struct {
	MailboxID   string `json:"mailbox_id"`
	EdgeID      string `json:"edge_id"`
	Sequence    uint64 `json:"sequence"`
	ReceivedAt  int64  `json:"received_at"`
	ExpiredAt   int64  `json:"expired_at"`
	BootID      string `json:"boot_id"`
	MessageBoot string `json:"message_boot"`
	Reason      string `json:"reason"`
}

const (
	ReasonExpired = "expired"
	ReasonVoid    = "void"
	maxRecord     = 4 << 10
)

var ErrRecord = errors.New("mail: bad gap record")

// RecordBoot reads the boot a record claims signed it. It is unverified until
// ParseRecord succeeds with that boot's key.
func RecordBoot(token string) (string, error) {
	rec, _, _, err := splitRecord(token)
	if err != nil {
		return "", err
	}
	return rec.BootID, nil
}

// ParseRecord verifies a record, b64url(json).b64url(sig), against bootKey.
func ParseRecord(token string, bootKey ed25519.PublicKey) (GapRecord, error) {
	rec, payload, sig, err := splitRecord(token)
	if err != nil {
		return GapRecord{}, err
	}
	if len(bootKey) != ed25519.PublicKeySize || !ed25519.Verify(bootKey, payload, sig) {
		return GapRecord{}, fmt.Errorf("%w: signature does not verify against boot %s", ErrRecord, rec.BootID)
	}
	return rec, nil
}

func splitRecord(token string) (GapRecord, []byte, []byte, error) {
	if len(token) > maxRecord {
		return GapRecord{}, nil, nil, fmt.Errorf("%w: too long", ErrRecord)
	}
	p, s, ok := strings.Cut(token, ".")
	if !ok || strings.Contains(s, ".") {
		return GapRecord{}, nil, nil, fmt.Errorf("%w: not two parts", ErrRecord)
	}
	enc := base64.RawURLEncoding.Strict()
	payload, err := enc.DecodeString(p)
	if err != nil {
		return GapRecord{}, nil, nil, fmt.Errorf("%w: payload: %v", ErrRecord, err)
	}
	sig, err := enc.DecodeString(s)
	if err != nil {
		return GapRecord{}, nil, nil, fmt.Errorf("%w: signature: %v", ErrRecord, err)
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	var rec GapRecord
	if err := dec.Decode(&rec); err != nil || dec.More() {
		return GapRecord{}, nil, nil, fmt.Errorf("%w: payload is not a record", ErrRecord)
	}
	if rec.Reason != ReasonExpired && rec.Reason != ReasonVoid {
		return GapRecord{}, nil, nil, fmt.Errorf("%w: reason %q", ErrRecord, rec.Reason)
	}
	if rec.Sequence == 0 || !validHex(rec.BootID, 16) || !validHex(rec.MessageBoot, 16) || !validHex(rec.MailboxID, 32) || !validHex(rec.EdgeID, 16) {
		return GapRecord{}, nil, nil, fmt.Errorf("%w: bad field", ErrRecord)
	}
	return rec, payload, sig, nil
}
