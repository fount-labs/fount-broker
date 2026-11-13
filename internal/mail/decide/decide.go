// Package decide says what a received email may do (fount docs
// fount-mail-design.md §11, "Verdicts"), from the edge's sender check and the
// worker's requesters. It is a port of Desktop's src-tauri/src/workers/verdict.rs
// for the coordinator, which must decide without parsing the email: every input
// here is the edge's signed check or state the coordinator already holds. Keep
// the two in step: same rules, same order, same reasons.
package decide

import (
	"cmp"
	"encoding/json"
	"slices"
	"strings"
)

// How far the signed Date may be behind the edge's received_at. Mail normally
// arrives within minutes, so two days allows for slow relays and still refuses
// old signed mail resent later.
const MaxDateAgeSecs = 2 * 24 * 60 * 60

// How far the signed Date may be ahead of it, for a sender's clock running fast.
const MaxDateAheadSecs = 60 * 60

type Verdict string

const (
	Request           Verdict = "request"
	Context           Verdict = "context"
	NeedsConfirmation Verdict = "needs_confirmation"
	Held              Verdict = "held"
	Ignored           Verdict = "ignored"
)

type Decision struct {
	Verdict Verdict
	// Reason is why, for the user. Empty for a request.
	Reason string
	// SignatureHash is the aligned signature's hash, for the replay check, or
	// empty.
	SignatureHash string
}

// Requester is someone whose mail can start a job. DKIMDomain is the d= stored
// at pairing, or empty.
type Requester struct {
	Address    string
	DKIMDomain string
	AutoRun    bool
}

type Worker struct {
	Address    string
	Requesters []Requester
}

// Received is one message as the coordinator holds it.
type Received struct {
	ID             string
	Sequence       uint64
	ReceivedAt     int64
	BootAttested   bool
	Reused         bool
	Quarantined    bool
	EnvelopeSender string
	// SenderCheck is the edge's check; SenderCheckError says it couldn't be
	// had. Either way an unreadable check holds the message.
	SenderCheck      json.RawMessage
	SenderCheckError string
}

// check is the parts of the edge's check this reads.
type check struct {
	From struct {
		Address string `json:"address"`
		Domain  string `json:"domain"`
		Error   string `json:"error"`
	} `json:"from"`
	DKIM            []signature `json:"dkim"`
	RecipientSigned bool        `json:"recipient_signed"`
	DateSkewSeconds *int64      `json:"date_skew_seconds"`
	Headers         struct {
		To []string `json:"to"`
		Cc []string `json:"cc"`
	} `json:"headers"`
}

type signature struct {
	Domain  string `json:"domain"`
	Result  string `json:"result"`
	Hash    string `json:"hash"`
	Aligned bool   `json:"aligned"`
}

func parse(raw json.RawMessage) (*check, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	var c check
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, false
	}
	return &c, true
}

// alignedSignature is the signature a message's request would rest on: a
// passing, aligned one for the From domain. It returns -1 when there's none.
func alignedSignature(c *check) int {
	return slices.IndexFunc(c.DKIM, func(s signature) bool {
		return s.Aligned && s.Result == "pass" && s.Hash != "" && strings.EqualFold(s.Domain, c.From.Domain)
	})
}

// FirstSigners maps each aligned signature's hash to the first message, by
// arrival, carrying it. A later message with the same signature is a replay:
// someone who received the requester's signed mail sent it again, or an SMTP
// retry delivered it twice (design §11, "Replay").
func FirstSigners(messages []Received) map[string]string {
	sorted := slices.Clone(messages)
	slices.SortStableFunc(sorted, func(a, b Received) int {
		return cmp.Or(cmp.Compare(a.ReceivedAt, b.ReceivedAt), cmp.Compare(a.Sequence, b.Sequence), cmp.Compare(a.ID, b.ID))
	})
	first := map[string]string{}
	for _, m := range sorted {
		c, ok := parse(m.SenderCheck)
		if !ok {
			continue
		}
		if i := alignedSignature(c); i >= 0 {
			if _, seen := first[c.DKIM[i].Hash]; !seen {
				first[c.DKIM[i].Hash] = m.ID
			}
		}
	}
	return first
}

func listed(list []string, address string) bool {
	return slices.ContainsFunc(list, func(a string) bool { return strings.EqualFold(strings.TrimSpace(a), address) })
}

// Decide decides one message. automatic is intake's reason the email looks
// automatic, or empty, and firstSigners is FirstSigners over every message the
// worker has.
func Decide(w Worker, r Received, automatic string, firstSigners map[string]string) Decision {
	c, ok := parse(r.SenderCheck)
	if !ok || r.SenderCheckError != "" || r.Quarantined {
		return Decision{Verdict: Held, Reason: "Fount couldn't check the sender"}
	}
	if r.Reused {
		return Decision{Verdict: Held, Reason: "the edge reused this message's number"}
	}
	if strings.TrimSpace(r.EnvelopeSender) == "" {
		return Decision{Verdict: Ignored, Reason: "a bounce (no envelope sender)"}
	}
	if automatic != "" {
		return Decision{Verdict: Ignored, Reason: "sent automatically (" + automatic + ")"}
	}
	if c.From.Error != "" || c.From.Address == "" {
		return Decision{Verdict: Held, Reason: "it has no single sender address"}
	}
	ri := slices.IndexFunc(w.Requesters, func(q Requester) bool { return strings.EqualFold(q.Address, c.From.Address) })
	if ri < 0 {
		return Decision{Verdict: Held, Reason: "not from an owner"}
	}
	requester := w.Requesters[ri]
	si := alignedSignature(c)
	if si < 0 {
		return Decision{Verdict: NeedsConfirmation, Reason: "no DKIM signature from the sender's domain"}
	}
	sig := c.DKIM[si]
	with := func(v Verdict, reason string) Decision {
		return Decision{Verdict: v, Reason: reason, SignatureHash: sig.Hash}
	}
	if first, ok := firstSigners[sig.Hash]; ok && first != r.ID {
		return with(Ignored, "a replay of an email already received")
	}
	if requester.DKIMDomain == "" || !strings.EqualFold(requester.DKIMDomain, sig.Domain) {
		return with(NeedsConfirmation, "signed by "+sig.Domain+", not the domain recorded at pairing")
	}
	switch skew := c.DateSkewSeconds; {
	case skew == nil:
		return with(NeedsConfirmation, "it has no single signed date")
	case *skew < -MaxDateAgeSecs || *skew > MaxDateAheadSecs:
		return with(NeedsConfirmation, "its signed date is too far from when it arrived")
	}
	if !r.BootAttested {
		return with(NeedsConfirmation, "the mail edge that received it wasn't attested")
	}
	inTo := listed(c.Headers.To, w.Address)
	inCc := listed(c.Headers.Cc, w.Address)
	if !c.RecipientSigned || !(inTo || inCc) {
		return with(NeedsConfirmation, "the worker's address isn't in a signed To or Cc (Bcc)")
	}
	if !inTo {
		return with(Context, "the worker was only copied (Cc)")
	}
	if !requester.AutoRun {
		return with(NeedsConfirmation, "this owner's pairing needs each job confirmed")
	}
	return with(Request, "")
}
