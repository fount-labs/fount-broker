package coordinator

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/fount-labs/fount-broker/internal/mail"
	"github.com/fount-labs/fount-broker/internal/mail/decide"
)

// ErrNoEdgeCheck is a stored message from before the edge checked senders
// (format version 1 or 2). Cloud has no local verifier, so it refuses them.
var ErrNoEdgeCheck = errors.New("coordinator: the message has no edge sender check")

// Mail is one received message, opened. Raw is the email itself, opaque here:
// the coordinator parses no user content, and hands Raw to an intake runner.
// Who sent it comes only from Check, which the edge made on arrival and sealed
// under its signature (m4-cloud-runners.md §3.2).
type Mail struct {
	EdgeID       string
	Sequence     uint64
	ReceivedAt   int64 // unix ms, the edge's clock
	BootAttested bool
	Envelope     mail.Envelope
	// Check is the edge's check, or nil with CheckError set when the edge
	// couldn't check the sender or the check doesn't hold. Such mail is held.
	Check      *mail.EdgeCheck
	CheckJSON  json.RawMessage
	CheckError string
	Raw        []byte
}

// OpenMail verifies a stored message object against its boot's signing key and
// opens it with the address's keys. bootAttested says whether that key is the
// attested edge's.
func OpenMail(object []byte, bootKey ed25519.PublicKey, bootAttested bool, keys *mail.Keys) (*Mail, error) {
	o, err := mail.ParseObject(object)
	if err != nil {
		return nil, err
	}
	if err := o.Verify(bootKey); err != nil {
		return nil, err
	}
	if o.Version < 3 {
		return nil, ErrNoEdgeCheck
	}
	opened, err := o.Open(keys)
	if err != nil {
		return nil, err
	}
	m := &Mail{
		EdgeID: hex.EncodeToString(o.EdgeID), Sequence: o.Sequence, ReceivedAt: o.ReceivedAt.UnixMilli(),
		BootAttested: bootAttested, Envelope: opened.Envelope, Raw: opened.Raw,
	}
	if c, err := mail.DecodeEdgeCheck(opened.Check, opened.Raw); err != nil {
		m.CheckError = err.Error()
	} else {
		m.Check, m.CheckJSON = c, json.RawMessage(opened.Check)
	}
	return m, nil
}

// Received is what decide.Decide reads about this message. The coordinator's
// ledger, not built yet, will supply reuse.
func (m *Mail) Received() decide.Received {
	return decide.Received{
		ID: m.EdgeID, Sequence: m.Sequence, ReceivedAt: m.ReceivedAt, BootAttested: m.BootAttested,
		EnvelopeSender: m.Envelope.Sender, SenderCheck: m.CheckJSON, SenderCheckError: m.CheckError,
	}
}
