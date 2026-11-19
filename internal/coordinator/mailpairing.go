package coordinator

import (
	"slices"
	"strings"
	"time"

	"github.com/fount-labs/fount-broker/internal/mail"
)

// Pairing connects a requester by email, as Desktop's pairing.rs does: the
// edge emails the requester from the worker's address (POST /connect) with a
// Message-ID only it can make, and the requester's reply carries that id back
// in In-Reply-To or References. The DKIM result decides whether their jobs run
// by themselves.
//
// POST /connect is signed with the address's owner-change key, which is never
// granted to Cloud (fount-mail-design.md), so a device sends it and then
// tells the coordinator with pairingStart. The coordinator looks at each
// message while the pairing is open, and the proof it finds waits in
// MailSettings.Proofs for that device's next PUT /routing.
type Pairing struct {
	Requester string    `json:"requester"`
	StartedAt time.Time `json:"startedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	// Seen is the messages already looked at, so each counts once.
	Seen      []string     `json:"seen"`
	Untokened []Untokened  `json:"untokened"`
	Paired    *PairedOwner `json:"paired,omitempty"`
	// MessageID is the connect email's Message-ID the reply named.
	MessageID string `json:"messageId,omitempty"`
}

// Untokened is an email that arrived during the pairing and isn't a reply to
// the connect email. Someone can say in the app it's the requester's
// (pairingConfirm).
type Untokened struct {
	Message    string `json:"message"`
	Address    string `json:"address"`
	ReceivedAt int64  `json:"receivedAt"`
}

type PairedOwner struct {
	Address    string `json:"address"`
	DKIMDomain string `json:"dkimDomain,omitempty"`
	AutoRun    bool   `json:"autoRun"`
	Reason     string `json:"reason,omitempty"`
	// Message is the reply's edge id; empty when confirmed in the app.
	Message string `json:"message,omitempty"`
}

// connectLifetime is how long the edge's connect email can be replied to.
const connectLifetime = 24 * time.Hour

func (p *Pairing) open(now time.Time) bool {
	return p.Paired == nil && !now.After(p.ExpiresAt)
}

func (p *PairedOwner) requester(now time.Time) Requester {
	by := "reply"
	if p.Message == "" {
		by = "confirmed"
	}
	return Requester{Address: p.Address, DKIMDomain: p.DKIMDomain, AutoRun: p.AutoRun, PairedBy: by, AddedAt: now, Reason: p.Reason}
}

type pairingFound struct {
	paired    *PairedOwner
	messageID string
	untokened *Untokened
}

// examinePairing is pairing.rs examine: what one message means to the
// pairing. Intake can't say yet whether the email looks automatic, so every
// message counts as ordinary.
func examinePairing(p *Pairing, workerAddress string, msg *mail.Message, check *mail.EdgeCheck) pairingFound {
	at := time.UnixMilli(msg.ReceivedAt)
	if at.Before(p.StartedAt) || at.After(p.ExpiresAt) || slices.Contains(p.Seen, msg.ID) {
		return pairingFound{}
	}
	if msg.Reused || msg.SenderCheckError != "" || msg.Quarantined || check == nil {
		return pairingFound{}
	}
	address := strings.ToLower(strings.TrimSpace(check.From.Address))
	mailDomain := "@" + domainOf(workerAddress)
	if check.From.Error != "" || address == "" || !strings.Contains(address, "@") || strings.HasSuffix(address, mailDomain) {
		return pairingFound{}
	}
	id := connectIDIn(check.Headers.InReplyTo, mailDomain)
	if id == "" {
		id = connectIDIn(check.Headers.References, mailDomain)
	}
	if id == "" || address != p.Requester {
		return pairingFound{untokened: &Untokened{Message: msg.ID, Address: address, ReceivedAt: msg.ReceivedAt}}
	}
	aligned := ""
	for _, s := range check.DKIM {
		if s.Aligned && strings.EqualFold(s.Domain, check.From.Domain) {
			aligned = strings.ToLower(s.Domain)
			break
		}
	}
	inTo := slices.ContainsFunc(check.Headers.To, func(a string) bool { return strings.EqualFold(strings.TrimSpace(a), workerAddress) })
	var reason string
	switch {
	case aligned == "":
		reason = "The reply wasn't signed by " + check.From.Domain + ", so each job from this address needs confirming until its mail is."
	case !msg.BootAttested:
		reason = "The mail edge that received the reply wasn't attested."
	case !check.RecipientSigned || !inTo:
		reason = "The worker's address wasn't in the reply's signed To."
	}
	return pairingFound{
		paired:    &PairedOwner{Address: address, DKIMDomain: aligned, AutoRun: reason == "", Reason: reason, Message: msg.ID},
		messageID: id,
	}
}

// isConnectID is whether id is shaped like a connect email's Message-ID,
// c.<issued at>.<mac>@<mail domain>. Only the edge can tell whether the mac
// is right.
func isConnectID(id, mailDomain string) bool {
	id = strings.TrimSpace(id)
	id = strings.TrimSuffix(strings.TrimPrefix(id, "<"), ">")
	at := strings.LastIndexByte(id, '@')
	if at < 0 || !strings.EqualFold(id[at:], mailDomain) {
		return false
	}
	parts := strings.Split(id[:at], ".")
	if len(parts) != 3 || parts[0] != "c" || parts[1] == "" || parts[2] == "" {
		return false
	}
	digits := strings.Trim(parts[1], "0123456789") == ""
	alnum := strings.IndexFunc(parts[2], func(r rune) bool {
		return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z')
	}) < 0
	return digits && alnum
}

// connectIDIn is the first connect id among a header's msg-ids, as <…>.
func connectIDIn(header, mailDomain string) string {
	var ids []string
	for _, part := range strings.Split(header, "<")[1:] {
		if id, _, ok := strings.Cut(part, ">"); ok {
			ids = append(ids, id)
		}
	}
	for _, w := range strings.Fields(header) {
		if !strings.ContainsAny(w, "<>") {
			ids = append(ids, w)
		}
	}
	for _, id := range ids {
		if isConnectID(id, mailDomain) {
			return "<" + strings.TrimSpace(id) + ">"
		}
	}
	return ""
}
