package coordinator

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/fount-labs/fount-broker/internal/mail"
)

// Approval by email (m4-cloud-runners.md §3.3, fount-mail-design §14). When
// the owner is on Full, a draft's notice is the draft itself: its exact
// recipients, files and text. Its Message-ID's random part is a one-time
// approval token, an HMAC under a key from the wrapping key, which only the
// coordinator holds (decision 25), over the worker, thread, draft, draft_rev,
// the binding hash of the recipients, files and bytes, the owner's address and
// the expiry. A reply approves the draft when:
//
//   - it answers that Message-ID in an In-Reply-To or References a DKIM
//     signature aligned with its From covers;
//   - it is from the owner the approval email went to, whose own mode is Full;
//   - intake read the owner's words above the quote as "yes" (or the like);
//   - the token wasn't used, hasn't expired, and the draft is still pending at
//     that draft_rev with the same binding.
//
// The coordinator parses no email: the edge's check gives the signed headers
// and DKIM, and intake (C) the owner's reply text. A reply that matches a
// token but fails a check sends nothing and says why on the thread. A reply
// that answers it with something other than yes is an ordinary reply.
//
// Whose mode allows it is open (launch-plan "Open questions"). Built here: the
// approver's own mode must be Full, whatever the recipients' modes, which is
// what "Full for me, Notify for others" needs.

const (
	approvalLifetime = 7 * 24 * time.Hour
	verdictApproval  = "approval"
)

// approvalAsk is the approval email sent for one draft_rev.
type approvalAsk struct {
	DraftRev  int       `json:"draftRev"`
	Binding   string    `json:"binding"`
	To        string    `json:"to"`
	ExpiresAt time.Time `json:"expiresAt"`
	SendID    string    `json:"sendId"`
	// UsedBy is the edge id of the reply that used it.
	UsedBy string `json:"usedBy,omitempty"`
}

func (c *Coordinator) approvalToken(workerID, threadID, draftID string, a *approvalAsk) string {
	return c.derivedPart(approvalIDInfo, workerID, threadID, draftID, fmt.Sprint(a.DraftRev), a.Binding, a.To, fmt.Sprint(a.ExpiresAt.Unix()))
}

// askApproval sends the owner the draft with an approval token.
func (c *Coordinator) askApproval(t *Tree, th *threadRecord, mb *Mailbox, rs *replySettings, id, draftID string, d *draftEntry, now time.Time) error {
	keys, err := mb.keys()
	if err != nil {
		return err
	}
	handle, err := threadHandle(t, th)
	if err != nil {
		return err
	}
	token, err := mail.MintReplyToken(keys, handle)
	if err != nil {
		return err
	}
	ask := &approvalAsk{DraftRev: d.DraftRev, Binding: d.Binding, To: strings.ToLower(rs.Owner), ExpiresAt: now.Add(approvalLifetime).Truncate(time.Second), SendID: id}
	var names []string
	for _, p := range d.Files {
		names = append(names, path.Base(p))
	}
	firm := rs.firm(mb)
	var b strings.Builder
	fmt.Fprintf(&b, "A draft reply is ready in %s.\n\n", firm)
	b.WriteString("To: " + strings.Join(d.To, ", ") + "\n")
	b.WriteString("Subject: " + d.Subject + "\n")
	if len(names) > 0 {
		b.WriteString("Attached: " + strings.Join(names, ", ") + "\n")
	}
	b.WriteString("\n----- The reply, as it will be sent -----\n\n")
	b.WriteString(renderBody(d.Text, names, footer(firm, true)))
	b.WriteString("\n----- End of the reply -----\n\n")
	fmt.Fprintf(&b, "To send it exactly as it is, reply to this email with \"yes\". That works once, until %s.\n", ask.ExpiresAt.Format("2 Jan 2006 15:04 MST"))
	b.WriteString("Anything else you write back goes to the worker as a note.\n\n")
	b.WriteString("Open it in Fount: " + fountLink(th.WorkerID, th.ID) + "\n\n" + footer(firm, false) + "\n")
	r := &sendRecord{
		ID: id, Kind: sendKindNotice, ThreadID: th.ID, Attempt: 1, State: sendSending, To: []string{ask.To},
		MessageID: messageID(c.approvalToken(th.WorkerID, th.ID, draftID, ask), token, domainOf(mb.Address)),
	}
	raw, err := c.buildOut(t, th, mb, r, nil, "Approve: "+d.Subject, "", nil, b.String(), nil, now)
	if err != nil {
		return err
	}
	if _, err := c.stageSend(t, th.WorkerID, r, raw); err != nil {
		return err
	}
	d.Ask = ask
	return nil
}

// approvalIDs are the random parts of the worker's Message-IDs a reply
// answers, fm.<26>.<token>@<domain>.
func approvalIDs(check *mail.EdgeCheck, domain string) []string {
	var out []string
	for _, value := range []string{check.Headers.InReplyTo, check.Headers.References} {
		for rest := value; ; {
			_, after, ok := strings.Cut(rest, "<")
			if !ok {
				break
			}
			id, next, ok := strings.Cut(after, ">")
			if !ok {
				break
			}
			rest = next
			local, d, ok := cutLast(id, "@")
			parts := strings.Split(local, ".")
			if ok && strings.EqualFold(d, domain) && len(parts) == 3 && parts[0] == "fm" && len(parts[1]) == 26 {
				out = append(out, strings.ToLower(parts[1]))
			}
		}
	}
	return out
}

// threadHeadersCovered says an aligned DKIM signature covers In-Reply-To and
// References (internal/mail threadHeadersSigned).
func threadHeadersCovered(check *mail.EdgeCheck) bool {
	if !check.Aligned {
		return false
	}
	for _, s := range check.DKIM {
		if s.Aligned && s.Result == "pass" && !slices.Contains(s.Unsigned, "in-reply-to") && !slices.Contains(s.Unsigned, "references") {
			return true
		}
	}
	return false
}

var approvalWords = []string{"yes", "y", "approve", "approved", "send", "send it", "yes send it", "yes, send it", "ok", "okay", "go ahead"}

// saysYes is an owner's reply intake read, certain of the split, as an
// approval.
func saysYes(spec IntakeSpec) bool {
	if spec.InstructionSource != "owner" {
		return false
	}
	w := strings.Trim(strings.ToLower(firstLine(spec.Instruction)), " .!")
	return slices.Contains(approvalWords, w)
}

// emailApproval looks at a received email for an approval of one of th's
// drafts. It reports whether the email was one, approved or refused: either
// way it starts no turn. An approval is applied to th at its next revision,
// which the caller finishes.
func (c *Coordinator) emailApproval(t *Tree, th *threadRecord, mb *Mailbox, s *MailSettings, msg *mail.Message, check *mail.EdgeCheck, in intook, now time.Time) (bool, error) {
	if check == nil || !in.ran || in.unread != nil || !saysYes(in.r.Spec) {
		return false, nil
	}
	ids := approvalIDs(check, domainOf(mb.Address))
	if len(ids) == 0 {
		return false, nil
	}
	sender := strings.ToLower(strings.TrimSpace(check.From.Address))
	rev := th.Revision + 1
	for i := range th.Entries {
		e := &th.Entries[i]
		if e.Kind != entryDraft || e.Draft.Ask == nil || !slices.Contains(ids, c.approvalToken(th.WorkerID, th.ID, e.ID, e.Draft.Ask)) {
			continue
		}
		ask := e.Draft.Ask
		if sender != ask.To {
			// Someone else answered the approval email: an ordinary email.
			return false, th.event(rev, now, "approval_refused", map[string]string{"draftId": e.ID, "reason": "it isn't from " + ask.To})
		}
		rs, err := loadReplySettings(t)
		if err != nil {
			return false, err
		}
		why := emailApprovalRefused(e.Draft, ask, rs, s, sender, check, in, now)
		if why != "" {
			return true, th.event(rev, now, "approval_refused", map[string]string{"draftId": e.ID, "reason": why})
		}
		ask.UsedBy = msg.ID
		a := approval{By: sender, Via: viaEmail, DKIM: alignedDomain(check), Email: msg.ID}
		if err := c.approve(t, th, e, a, rev, now); err != nil {
			if isRefusal(err) {
				return true, th.event(rev, now, "approval_refused", map[string]string{"draftId": e.ID, "reason": "the draft was already sent or discarded"})
			}
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// emailApprovalRefused is why a matching approval reply doesn't count, or
// empty when it does.
func emailApprovalRefused(d *draftEntry, ask *approvalAsk, rs *replySettings, s *MailSettings, sender string, check *mail.EdgeCheck, in intook, now time.Time) string {
	dkim := alignedDomain(check)
	switch {
	case ask.UsedBy != "":
		return "this approval was already used"
	case !now.Before(ask.ExpiresAt):
		return "this approval expired"
	case dkim == "" || !strings.EqualFold(dkim, domainOf(sender)) || !threadHeadersCovered(check):
		return "the reply isn't signed by its sender's domain"
	case rs.modeOf(sender) != modeFull:
		return "approval by email needs Full"
	case d.State != draftPending:
		return "the draft was already sent or discarded"
	case d.DraftRev != ask.DraftRev || d.Binding != ask.Binding:
		return "the draft changed since the approval email"
	case !in.r.Spec.Reply:
		return "intake didn't read it as a reply"
	}
	for _, to := range d.To {
		if s.requester(to) == nil {
			return to + " can't send this worker work"
		}
	}
	return ""
}

// approve moves a pending draft's record to sending with a, at rev.
func (c *Coordinator) approve(t *Tree, th *threadRecord, e *threadEntry, a approval, rev uint64, now time.Time) error {
	d := e.Draft
	r, err := loadSend(t, d.SendID)
	if errors.Is(err, ErrNotFound) {
		return refusal{code: CodeNotFound}
	}
	if err != nil {
		return err
	}
	if r.State != sendDraft {
		return refusal{code: CodeAlreadySent}
	}
	a.At, a.Hash = now, r.Hash
	a.AgentTextHash, a.SentTextHash = sha256Hex([]byte(d.AgentText)), sha256Hex([]byte(d.Text))
	r.Approval = &a
	if err := c.startSending(t, th.WorkerID, r, now); err != nil {
		return err
	}
	if err := writeSignoff(t, th, e, r, a); err != nil {
		return err
	}
	d.State, d.Approval, d.Send, e.Rev = draftSent, &a, r.view(), rev
	return nil
}
