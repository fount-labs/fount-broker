package coordinator

import (
	"cmp"
	"crypto/subtle"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/fount-labs/fount-broker/internal/mail"
)

// Approval by email (m4-cloud-runners.md §3.3, fount-mail-design §14). When
// a reviewer is on Full, the draft's notice to them is the draft itself: its exact
// recipients, files and text. Its Message-ID's random part is a one-time
// approval token, an HMAC under a key from the wrapping key, which only the
// coordinator holds (decision 25), over the worker, thread, draft, draft_rev,
// the binding hash of the recipients, files and bytes, the owner's address and
// the expiry. A reply approves the draft when:
//
//   - it answers that Message-ID directly, in its In-Reply-To, or, with no
//     In-Reply-To, in References that name no other live approval email of
//     the thread's (answeredAsk), and a DKIM signature aligned with its From
//     covers both;
//   - the thread's mode now is no lower than when the approval email went
//     (Notify on a Full-for-the-owner thread with others on it): lowering
//     it stops the email from sending;
//   - it is from the reviewer the approval email went to, whose own mode is
//     Full, and who still reviews the worker: the owner, or a member of its
//     team who reaches it (reviewers.go), as a device's approval must be;
//   - intake read the owner's words above the quote as "yes" (or the like);
//   - the token wasn't used, hasn't expired, and the draft is still pending at
//     that draft_rev with the same binding, with no newer draft, no email
//     from the thread's people and no change of them since the email went.
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
	// Since is the thread's revision before the email went: an email or
	// change of people on it after that refuses a reply to this one, as
	// NEW_MAIL_SINCE and PARTICIPANTS_CHANGED refuse a device's approval.
	// Zero, from before it was kept, is before everything.
	Since uint64 `json:"since,omitempty"`
	// ThreadMode is the thread's reply mode when the email went. Empty, from
	// before it was kept, is Full.
	ThreadMode string `json:"threadMode,omitempty"`
	// UsedBy is the edge id of the reply that used it.
	UsedBy string `json:"usedBy,omitempty"`
}

func (c *Coordinator) approvalToken(workerID, threadID, draftID string, a *approvalAsk) string {
	return c.derivedPart(approvalIDInfo, workerID, threadID, draftID, fmt.Sprint(a.DraftRev), a.Binding, a.To, fmt.Sprint(a.ExpiresAt.Unix()))
}

// askApproval sends a reviewer on Full, to, the draft with an approval
// token: the owner's is the draft's Ask, every other reviewer's one of its
// Asks. requester says to's other replies start work; a member who isn't
// one is told theirs wait.
//
// It reads as a person's reply would: text/plain, in the reviewer's own
// conversation when they wrote on the thread (In-Reply-To and References to
// their newest email, its subject), the draft quoted as it will be sent, and
// no link: a fount:// link in a message body is what a spam filter sees as a
// lure, and there is no https form of a thread's link yet. The token is only
// in the Message-ID, as before.
func (c *Coordinator) askApproval(t *Tree, th *threadRecord, mb *Mailbox, rs *replySettings, id, draftID string, d *draftEntry, to string, requester bool, now time.Time) error {
	keys, err := c.mailKeys(mb)
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
	ask := &approvalAsk{DraftRev: d.DraftRev, Binding: d.Binding, To: strings.ToLower(to), ExpiresAt: now.Add(approvalLifetime).Truncate(time.Second), SendID: id, Since: th.Revision, ThreadMode: th.replyMode()}
	var names []string
	for _, p := range d.Files {
		names = append(names, path.Base(p))
	}
	text := approvalText(d, names, rs.firm(mb), ask.To, requester, ask.ExpiresAt)
	subject, inReplyTo, refs := approvalSubject(d.Subject), "", []string(nil)
	if m := th.newestMailFrom(ask.To); m != nil {
		subject, inReplyTo, refs = replySubject(cmp.Or(m.Subject, th.Subject)), m.MessageID, m.references()
	}
	r := &sendRecord{
		ID: id, Kind: sendKindNotice, ThreadID: th.ID, Attempt: 1, State: sendSending, To: []string{ask.To},
		MessageID: messageID(c.approvalToken(th.WorkerID, th.ID, draftID, ask), token, domainOf(mb.Address)),
	}
	raw, err := c.buildOut(t, th, mb, r, nil, subject, inReplyTo, refs, text, nil, now)
	if err != nil {
		return err
	}
	if _, err := c.stageSend(t, th.WorkerID, r, raw); err != nil {
		return err
	}
	if ask.To == strings.ToLower(rs.Owner) {
		d.Ask = ask
	} else {
		d.Asks = append(d.Asks, *ask)
	}
	return nil
}

// approvalText is the approval email's body: who the reply is for, the reply
// quoted exactly as it will be sent, how to send it, and the footer. The
// reviewer is "you" among the recipients.
func approvalText(d *draftEntry, names []string, firm, reviewer string, requester bool, expires time.Time) string {
	var to []string
	for _, a := range d.To {
		if strings.EqualFold(a, reviewer) {
			a = "you"
		}
		to = append(to, a)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "The email agent drafted a reply to %s, with the subject \"%s\".", strings.Join(to, ", "), d.Subject)
	if len(names) > 0 {
		fmt.Fprintf(&b, "\nIt attaches %s, which aren't in this email: \"yes\" sends them as they are now. To look at them first, open Fount.", strings.Join(names, ", "))
	}
	b.WriteString("\nHere it is, exactly as it will be sent:\n\n")
	for line := range strings.SplitSeq(strings.TrimRight(renderBody(d.Text, names, footer(firm, true)), "\n"), "\n") {
		b.WriteString(strings.TrimRight("> "+line, " ") + "\n")
	}
	fmt.Fprintf(&b, "\nReply \"yes\" to send it as it is.\nThat works once, until %s.\n", expires.Format("2 Jan 2006 15:04 MST"))
	if requester {
		b.WriteString("Anything else you write back goes to the email agent as a note.\n")
	} else {
		b.WriteString("Anything else you write back waits in Fount until someone runs it.\n")
	}
	b.WriteString("To change it first, open Fount.\n\n" + footer(firm, false) + "\n")
	return b.String()
}

// approvalSubject is the subject of an approval email that starts its own
// conversation, for a reviewer who hasn't written on the thread.
func approvalSubject(draftSubject string) string {
	subject := strings.Join(strings.Fields(draftSubject), " ")
	if len(subject) >= 3 && strings.EqualFold(subject[:3], "re:") {
		subject = strings.TrimSpace(subject[3:])
	}
	return "Draft reply: " + subject
}

// newestMailFrom is the newest email on th from address, signed by its
// domain, which an approval email to address answers, or nil. An unsigned
// one may be anyone's, whose Subject and References the approval email
// would otherwise carry.
func (th *threadRecord) newestMailFrom(address string) *mailEntry {
	for _, e := range slices.Backward(th.Entries) {
		if e.Kind == entryMail && e.Mail != nil && e.Mail.MessageID != "" && strings.EqualFold(strings.TrimSpace(e.Mail.Sender), address) &&
			e.Mail.Signed != "" && strings.EqualFold(e.Mail.Signed, domainOf(address)) {
			return e.Mail
		}
	}
	return nil
}

// asks are the approval emails out for d's draft_rev: the owner's, then the
// other reviewers'.
func (d *draftEntry) asks() []*approvalAsk {
	var out []*approvalAsk
	if d.Ask != nil {
		out = append(out, d.Ask)
	}
	for i := range d.Asks {
		out = append(out, &d.Asks[i])
	}
	return out
}

// approvalIDs are the random parts of the worker's Message-IDs a header
// value names, fm.<26>.<token>@<domain>.
func approvalIDs(value, domain string) []string {
	var out []string
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
	return out
}

// tokenIn says ids has token, comparing in constant time.
func tokenIn(ids []string, token string) bool {
	found := 0
	for _, id := range ids {
		found |= subtle.ConstantTimeCompare([]byte(id), []byte(token))
	}
	return found == 1
}

// askOnThread is an approval email out for one of th's drafts.
type askOnThread struct {
	e   *threadEntry
	ask *approvalAsk
}

// asksNamed are the approval emails out for th's drafts whose tokens ids
// has, oldest draft first.
func (c *Coordinator) asksNamed(th *threadRecord, ids []string) []askOnThread {
	var out []askOnThread
	for i := range th.Entries {
		e := &th.Entries[i]
		if e.Kind != entryDraft {
			continue
		}
		for _, a := range e.Draft.asks() {
			if tokenIn(ids, c.approvalToken(th.WorkerID, th.ID, e.ID, a)) {
				out = append(out, askOnThread{e, a})
			}
		}
	}
	return out
}

// live says a's approval email could still approve its draft for sender:
// it went to sender, is unused and unexpired, and the draft is pending as
// it was.
func (a askOnThread) live(sender string, now time.Time) bool {
	d := a.e.Draft
	return a.ask.To == sender && a.ask.UsedBy == "" && now.Before(a.ask.ExpiresAt) &&
		d.State == draftPending && d.DraftRev == a.ask.DraftRev && d.Binding == a.ask.Binding
}

// answeredAsk is the approval email a reply answers. It is the one its
// In-Reply-To names, the email it answers directly, whatever state that one
// is in. A reply with no In-Reply-To may answer one its References name, but
// only the one still live there for sender: References carry every older
// message of the conversation, spent approval emails and other drafts' too.
// Two live there answer neither, which ambiguous says. With none named, it
// is no answer.
func (c *Coordinator) answeredAsk(th *threadRecord, check *mail.EdgeCheck, domain, sender string, now time.Time) (a askOnThread, ambiguous, ok bool) {
	if strings.TrimSpace(check.Headers.InReplyTo) != "" {
		named := c.asksNamed(th, approvalIDs(check.Headers.InReplyTo, domain))
		if len(named) == 0 {
			return askOnThread{}, false, false
		}
		return named[len(named)-1], false, true
	}
	named := c.asksNamed(th, approvalIDs(check.Headers.References, domain))
	var live []askOnThread
	for _, a := range named {
		if a.live(sender, now) {
			live = append(live, a)
		}
	}
	switch {
	case len(live) == 1:
		return live[0], false, true
	case len(live) > 1:
		return live[len(live)-1], true, true
	case len(named) > 0:
		// None live: the newest says why.
		return named[len(named)-1], false, true
	}
	return askOnThread{}, false, false
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
	sender := strings.ToLower(strings.TrimSpace(check.From.Address))
	found, ambiguous, ok := c.answeredAsk(th, check, domainOf(mb.Address), sender, now)
	if !ok {
		return false, nil
	}
	e, ask := found.e, found.ask
	rev := th.Revision + 1
	if ambiguous {
		return true, th.event(rev, now, "approval_refused", map[string]string{"draftId": e.ID, "reason": "the reply answers more than one approval email; reply to the newest, or approve in Fount"})
	}
	if sender != ask.To {
		// Someone else answered the approval email: an ordinary email.
		return false, th.event(rev, now, "approval_refused", map[string]string{"draftId": e.ID, "reason": "it isn't from " + ask.To})
	}
	rs, err := loadReplySettings(t)
	if err != nil {
		return false, err
	}
	why := ""
	if !slices.Contains(c.reviewers(th.WorkerID, rs, s), sender) {
		why = sender + " no longer reviews this email agent"
	} else {
		why = emailApprovalRefused(th, e, ask, rs, s, sender, check, in, now)
	}
	if why != "" {
		return true, th.event(rev, now, "approval_refused", map[string]string{"draftId": e.ID, "reason": why})
	}
	ask.UsedBy = msg.ID
	a := approval{By: sender, Via: viaEmail, DKIM: alignedDomain(check), Email: msg.ID, Member: c.memberID(th.WorkerID, sender)}
	if err := c.approve(t, th, e, a, rev, now); err != nil {
		if isRefusal(err) {
			return true, th.event(rev, now, "approval_refused", map[string]string{"draftId": e.ID, "reason": "the draft was already sent or discarded"})
		}
		return false, err
	}
	return true, nil
}

// emailApprovalRefused is why a matching approval reply doesn't count, or
// empty when it does.
func emailApprovalRefused(th *threadRecord, e *threadEntry, ask *approvalAsk, rs *replySettings, s *MailSettings, sender string, check *mail.EdgeCheck, in intook, now time.Time) string {
	d, dkim := e.Draft, alignedDomain(check)
	switch {
	case ask.UsedBy != "":
		return "this approval was already used"
	case !now.Before(ask.ExpiresAt):
		return "this approval expired"
	case dkim == "" || !strings.EqualFold(dkim, domainOf(sender)) || !threadHeadersCovered(check):
		return "the reply isn't signed by its sender's domain"
	case modeRank(th.replyMode()) < modeRank(cmp.Or(ask.ThreadMode, modeFull)):
		return "the thread's reply mode was lowered since the approval email"
	case rs.modeOf(sender) != modeFull:
		return "approval by email needs Full"
	case d.State != draftPending:
		return "the draft was already sent or discarded"
	case d.DraftRev != ask.DraftRev || d.Binding != ask.Binding:
		return "the draft changed since the approval email"
	case editingElsewhere(d, "", now) != nil:
		return d.Claim.By + " is editing one of its attachments in Fount"
	case !in.r.Spec.Reply:
		return "intake didn't read it as a reply"
	case th.newerDraft(e):
		return "a newer draft is waiting on this thread"
	case th.participantMailSince(ask.Since):
		return "an email came on the thread after the approval email; approve in Fount"
	case th.peopleSince(ask.Since):
		return "the thread's people or mode changed after the approval email; approve in Fount"
	}
	for _, to := range d.To {
		if s.requester(to) == nil {
			return to + " can't send this email agent work"
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
	return writeReplyFolder(t, th, d, now)
}

// newerDraft says a draft made after e's is waiting on th: the conversation
// moved on from e's, which an approval email for it shouldn't send.
func (th *threadRecord) newerDraft(e *threadEntry) bool {
	after := false
	for i := range th.Entries {
		o := &th.Entries[i]
		switch {
		case o == e:
			after = true
		case after && o.Kind == entryDraft && o.Draft.State == draftPending:
			return true
		}
	}
	return false
}

// participantMailSince says one of th's participants wrote on it after
// base, other than to answer an approval email: what the owner's "yes" didn't
// see, such as a client's "wait, the amounts changed".
func (th *threadRecord) participantMailSince(base uint64) bool {
	return slices.ContainsFunc(th.Entries, func(e threadEntry) bool {
		return e.Kind == entryMail && e.Rev > base && e.Mail != nil && e.Mail.Verdict != verdictApproval && th.hasParticipant(e.Mail.Sender)
	})
}
