package mail

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// EdgeCheck is the sender check the edge makes when a message arrives and seals
// into a version 3 object. Its fields match the local verifier's Verdict
// (package verify), without SPF and DMARC, so the app reads either the same way.
type EdgeCheck struct {
	V         int    `json:"v"`
	CheckedBy string `json:"checked_by"`
	// Error is set when the check couldn't run; then nothing else is trusted.
	Error           string           `json:"error,omitempty"`
	From            EdgeFrom         `json:"from"`
	DKIM            []EdgeSignature  `json:"dkim"`
	Aligned         bool             `json:"aligned"`
	RecipientSigned bool             `json:"recipient_signed"`
	DateSkewSeconds *int64           `json:"date_skew_seconds,omitempty"`
	Headers         EdgeCheckHeaders `json:"headers"`
	RawSHA256       string           `json:"raw_sha256"`
}

type EdgeFrom struct {
	Address string `json:"address,omitempty"`
	Domain  string `json:"domain,omitempty"`
	Name    string `json:"name,omitempty"`
	Error   string `json:"error,omitempty"`
}

type EdgeSignature struct {
	Domain     string   `json:"domain"`
	Selector   string   `json:"selector"`
	Algorithm  string   `json:"algorithm"`
	Result     string   `json:"result"`
	Error      string   `json:"error,omitempty"`
	KeyBits    int      `json:"key_bits,omitempty"`
	Headers    []string `json:"headers"`
	BodyLength bool     `json:"body_length"`
	Testing    bool     `json:"testing"`
	Covers     bool     `json:"covers"`
	Unsigned   []string `json:"unsigned,omitempty"`
	Hash       string   `json:"hash"`
	Aligned    bool     `json:"aligned"`
}

type EdgeCheckHeaders struct {
	MessageID  string   `json:"message_id,omitempty"`
	InReplyTo  string   `json:"in_reply_to,omitempty"`
	References string   `json:"references,omitempty"`
	Subject    string   `json:"subject,omitempty"`
	Date       string   `json:"date,omitempty"`
	To         []string `json:"to,omitempty"`
	Cc         []string `json:"cc,omitempty"`
	ReplyTo    []string `json:"reply_to,omitempty"`
	Duplicated []string `json:"duplicated,omitempty"`
}

// The errors are generic on purpose: they reach the app and logs, and must
// never carry the message's content.
var (
	ErrEdgeCheckFailed    = errors.New("mail: the edge couldn't check the sender")
	ErrEdgeCheckMalformed = errors.New("mail: the edge's sender check is malformed")
)

// DecodeEdgeCheck reads a version 3 object's check strictly and confirms it was
// made over raw.
func DecodeEdgeCheck(b, raw []byte) (*EdgeCheck, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c EdgeCheck
	if err := dec.Decode(&c); err != nil || dec.More() {
		return nil, ErrEdgeCheckMalformed
	}
	if c.V != 1 || c.CheckedBy != "edge" {
		return nil, ErrEdgeCheckMalformed
	}
	if c.Error != "" {
		return nil, ErrEdgeCheckFailed
	}
	sum := sha256.Sum256(raw)
	if c.RawSHA256 != hex.EncodeToString(sum[:]) {
		return nil, ErrEdgeCheckMalformed
	}
	return &c, nil
}
