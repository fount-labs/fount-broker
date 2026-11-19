package coordinator

import (
	"time"

	"github.com/fount-labs/fount-broker/internal/mail"
)

// mailLedger is what the coordinator has acted on in a worker's mail
// (decision 15). It is staged in the same tree change as the thread
// operation a message causes, so both commit in one manifest version or
// neither does: a crash before the commit leaves the message unacted on, and
// the next sync does it again; a crash after leaves it acted on, and the next
// sync skips it. Nothing is acted on twice and nothing is lost.
//
// Sequences is the mailbox's sequence accounting (internal/mail's Ledger),
// kept here too so a restart restores it into the Service.
type mailLedger struct {
	Sequences *mail.Ledger `json:"sequences"`
	// Acted is each message acted on, by edge id.
	Acted map[string]actedMail `json:"acted"`
	// Signers maps each aligned DKIM signature's hash to the first message
	// that carried it, for decide's replay check.
	Signers map[string]string `json:"signers"`
}

// actedMail is what became of one message: Desktop's MailDecision.
type actedMail struct {
	At         time.Time `json:"at"`
	ReceivedAt int64     `json:"receivedAt"`
	Sequence   uint64    `json:"sequence"`
	Sender     string    `json:"sender,omitempty"`
	Verdict    string    `json:"verdict"`
	// Outcome is "job" (it started a turn), "held" (it waits on Thread),
	// "context" (it joined Thread, nothing to run), "ignored" or "paired"
	// (it answered a pairing).
	Outcome string `json:"outcome"`
	Reason  string `json:"reason,omitempty"`
	Thread  string `json:"thread,omitempty"`
	Entry   string `json:"entry,omitempty"`
}

const (
	outcomeJob     = "job"
	outcomeHeld    = "held"
	outcomeContext = "context"
	outcomeIgnored = "ignored"
	outcomePaired  = "paired"
)

func loadMailLedger(t *Tree) (*mailLedger, error) {
	l := &mailLedger{}
	if _, err := readJSON(t, mailLedgerPath, l); err != nil {
		return nil, err
	}
	if l.Sequences == nil {
		l.Sequences = &mail.Ledger{}
	}
	if l.Sequences.Delivered == nil {
		l.Sequences.Delivered = map[uint64]string{}
	}
	if l.Sequences.Accounted == nil {
		l.Sequences.Accounted = map[uint64]mail.Accounted{}
	}
	if l.Acted == nil {
		l.Acted = map[string]actedMail{}
	}
	if l.Signers == nil {
		l.Signers = map[string]string{}
	}
	return l, nil
}

// jobsSince counts the jobs mail started by itself after since, all of them
// or sender's.
func (l *mailLedger) jobsSince(since time.Time, sender string) int {
	n := 0
	for _, a := range l.Acted {
		if a.Outcome == outcomeJob && a.At.After(since) && (sender == "" || a.Sender == sender) {
			n++
		}
	}
	return n
}
