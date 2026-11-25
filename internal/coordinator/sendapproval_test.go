package coordinator

import (
	"bytes"
	"context"
	"io"
	"mime/quotedprintable"
	"net/mail"
	"slices"
	"strings"
	"testing"
	"time"
)

// approvalsTo is the Message-IDs of the approval emails delivered to
// address.
func (f *fakeSendEdge) approvalsTo(address string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for id, raw := range f.raw {
		m, err := mail.ReadMessage(bytes.NewReader(raw))
		if err != nil || !strings.Contains(m.Header.Get("To"), address) {
			continue
		}
		if body := decodedBody(f.t, m); strings.Contains(body, `Reply "yes" to send it`) {
			out = append(out, id)
		}
	}
	return out
}

func decodedBody(t *testing.T, m *mail.Message) string {
	t.Helper()
	var r io.Reader = m.Body
	if strings.EqualFold(m.Header.Get("Content-Transfer-Encoding"), "quoted-printable") {
		r = quotedprintable.NewReader(m.Body)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(data), "\r\n", "\n")
}

func (f *fakeSendEdge) message(t *testing.T, id string) (*mail.Message, string) {
	t.Helper()
	f.mu.Lock()
	raw := f.raw[id]
	f.mu.Unlock()
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return m, decodedBody(t, m)
}

// quietPass is a pass that sweeps nothing: it reads only the mailboxes the
// changes feed or a kick named.
func (r *mailRig) quietPass() {
	r.t.Helper()
	r.c.mail.mu.Lock()
	r.c.mail.lastSweep = time.Now()
	r.c.mail.mu.Unlock()
	r.c.mailPass(context.Background(), time.Now())
}

// The approval email reads as a reply in the owner's own conversation: their
// request's subject, In-Reply-To and References, text/plain, the draft
// quoted as it will be sent, no link, and none of the words a filter or an
// owner trips on. The token is the Message-ID's, as before.
func TestTheApprovalEmailIsAPlainReplyInTheOwnersThread(t *testing.T) {
	r := newSendRig(t, modeFull)
	const requestID = "<q3-close@example.com>"
	id := r.edge.deliver(r.mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Q3 close", messageID: requestID})
	r.pass()
	waitJob(t, r.c, mailJobID(id))
	th := r.waitStatus(r.w.ID, onlyThread(t, r.threads(r.w.ID)).ID, StatusReview)
	e := draftOn(t, th)
	r.pass()
	asks := r.send.approvalsTo("dana@example.com")
	if len(asks) != 1 {
		t.Fatalf("the approval email: %v", asks)
	}
	m, body := r.send.message(t, asks[0])
	request := th.newestMailFrom("dana@example.com")
	if request == nil || request.MessageID != requestID {
		t.Fatalf("the request's Message-ID isn't on the thread: %+v", request)
	}
	h := m.Header
	if h.Get("Content-Transfer-Encoding") != "7bit" {
		t.Errorf("a short draft's approval email isn't plain 7-bit text: %q", h.Get("Content-Transfer-Encoding"))
	}
	if h.Get("Subject") != "Re: Q3 close" || h.Get("In-Reply-To") != request.MessageID || !slices.Contains(strings.Fields(h.Get("References")), request.MessageID) {
		t.Fatalf("not threaded: subject %q, in-reply-to %q, references %q (request %s)", h.Get("Subject"), h.Get("In-Reply-To"), h.Get("References"), request.MessageID)
	}
	if h.Get("From") != testWorkerAddr || h.Get("To") != "dana@example.com" || !strings.HasPrefix(h.Get("Content-Type"), "text/plain") {
		t.Fatalf("headers %v", h)
	}
	for _, name := range []string{"Reply-To", "Auto-Submitted", "Precedence", "List-Unsubscribe", "List-Id"} {
		if h.Get(name) != "" {
			t.Errorf("a %s header: %q", name, h.Get(name))
		}
	}
	d := r.draft(th.ID, e.ID)
	ids := approvalIDs(h.Get("Message-Id"), domainOf(testWorkerAddr))
	if d.Ask == nil || len(ids) != 1 || ids[0] != r.c.approvalToken(r.w.ID, th.ID, e.ID, d.Ask) {
		t.Fatalf("the Message-ID %s doesn't carry the approval token: %v", h.Get("Message-Id"), ids)
	}
	for _, want := range []string{
		`The email agent drafted a reply to you, with the subject "Re: Q3 close".`,
		"> The ledger is reconciled. See [1].",
		"> [1] the Q3 statement (q3.pdf), page 4",
		"> Drafted by an AI assistant and reviewed by a person before it was sent.",
		"Reply \"yes\" to send it as it is.\nThat works once, until " + d.Ask.ExpiresAt.Format("2 Jan 2006 15:04 MST") + ".",
		"Here it is, exactly as it will be sent:\n\n> The ledger",
		"Anything else you write back goes to the email agent as a note.",
		"To change it first, open Fount.",
		"Written by Fount automatically, without a person reviewing it.",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the body has no %q:\n%s", want, body)
		}
	}
	lower := strings.ToLower(body)
	for _, never := range []string{"fount://", "worker", "firm", "approve", "-----"} {
		if strings.Contains(lower, never) {
			t.Errorf("the body says %q:\n%s", never, body)
		}
	}
}

// A draft's notice and approval email go on the next pass, not the next sweep:
// they're made when the job ends, outside any pass over the worker's mail.
func TestADraftsEmailGoesOnTheNextPass(t *testing.T) {
	for _, mode := range []string{modeFull, modeNotify} {
		t.Run(mode, func(t *testing.T) {
			r := newSendRig(t, mode)
			r.drafted()
			sent := func() int {
				if mode == modeFull {
					return len(r.send.approvalsTo("dana@example.com"))
				}
				return len(r.send.sentTo("dana@example.com", "A draft reply is ready"))
			}
			if n := sent(); n != 0 {
				t.Fatalf("sent before a pass: %d", n)
			}
			r.quietPass()
			if n := sent(); n != 1 {
				t.Fatalf("after a pass that sweeps nothing, %d sent", n)
			}
		})
	}
}

// askMessageID is the Message-ID of the approval email the owner got for
// draft e on th.
func (r *sendRig) askMessageID(th *threadRecord, e *threadEntry) string {
	r.t.Helper()
	d := r.draft(th.ID, e.ID)
	if d.Ask == nil {
		r.t.Fatalf("draft %s has no approval email", e.ID)
	}
	token := r.c.approvalToken(r.w.ID, th.ID, e.ID, d.Ask)
	for _, id := range r.send.approvalsTo("dana@example.com") {
		if ids := approvalIDs(id, domainOf(testWorkerAddr)); len(ids) == 1 && ids[0] == token {
			return id
		}
	}
	r.t.Fatalf("no approval email for draft %s was sent", e.ID)
	return ""
}

// drafts are th's drafts, oldest first, once there are n.
func (r *sendRig) drafts(threadID string, n int) (*threadRecord, []*threadEntry) {
	r.t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		r.pass()
		th, err := r.c.thread(anyDevice, r.w.ID, threadID)
		if err != nil {
			r.t.Fatal(err)
		}
		var out []*threadEntry
		for i := range th.Entries {
			if th.Entries[i].Kind == entryDraft {
				out = append(out, &th.Entries[i])
			}
		}
		if len(out) >= n {
			return th, out
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("%d drafts on the thread, want %d", len(out), n)
		}
	}
}

// refusals are the reasons th's email approvals were refused.
func (r *sendRig) refusals(threadID string) []string {
	r.t.Helper()
	th, err := r.c.thread(anyDevice, r.w.ID, threadID)
	if err != nil {
		r.t.Fatal(err)
	}
	var out []string
	for _, e := range th.Entries {
		if e.Kind == entryEvent && e.Code == "approval_refused" {
			out = append(out, e.Args["reason"])
		}
	}
	return out
}

// twoDrafts is the 11-24 review's H5 setup: draft 1's approval email A1 is
// out, the owner answers it with a note, and the turn that note starts makes
// draft 2, whose approval email A2 threads under the note, so its References
// carry A1.
func twoDrafts(t *testing.T) (r *sendRig, th *threadRecord, d1, d2 *threadEntry, a1, a2 string) {
	r = newSendRig(t, modeFull)
	const request = "<q3-close@example.com>"
	id := r.edge.deliver(r.mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Q3 close", messageID: request})
	r.pass()
	waitJob(t, r.c, mailJobID(id))
	th = r.waitStatus(r.w.ID, onlyThread(t, r.threads(r.w.ID)).ID, StatusReview)
	d1 = draftOn(t, th)
	r.pass()
	a1 = r.askMessageID(th, d1)

	r.intake.set(func(f *fakeIntake) { f.instruction, f.source, f.reply = "Also attach the invoice.", "owner", true })
	r.edge.deliver(r.mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Re: Q3 close",
		messageID: "<note@example.com>", inReplyTo: a1, references: request + " " + a1})
	th, ds := r.drafts(th.ID, 2)
	d1, d2 = ds[0], ds[1]
	r.pass()
	a2 = r.askMessageID(th, d2)
	m, _ := r.send.message(t, a2)
	if refs := m.Header.Get("References"); !strings.Contains(refs, a1) {
		t.Fatalf("A2's References don't carry A1: %q", refs)
	}
	r.intake.set(func(f *fakeIntake) { f.instruction, f.source, f.reply = "Yes.", "owner", true })
	return r, th, d1, d2, a1, a2
}

// The 11-24 review's H5 probe, flipped: a "yes" to the newer approval email,
// whose client's References carry the older one too, sends the draft it
// names, never the older one.
func TestAYesToTheNewerApprovalSendsOnlyItsDraft(t *testing.T) {
	r, th, d1, d2, a1, a2 := twoDrafts(t)
	r.edge.deliver(r.mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Re: Q3 close",
		inReplyTo: a2, references: "<q3-close@example.com> " + a1 + " <note@example.com> " + a2})
	r.pass()
	if d := r.draft(th.ID, d1.ID); d.State != draftPending {
		t.Fatalf("the older draft is %s", d.State)
	}
	if d := r.draft(th.ID, d2.ID); d.State != draftSent || d.Approval.Via != viaEmail {
		t.Fatalf("the draft the yes answered is %s: %v", d.State, r.refusals(th.ID))
	}
}

// A reply with no In-Reply-To whose References name two live approval
// emails approves neither, and says why.
func TestAYesThatNamesTwoLiveApprovalsSendsNeither(t *testing.T) {
	r, th, d1, d2, a1, a2 := twoDrafts(t)
	r.edge.deliver(r.mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Re: Q3 close",
		references: "<q3-close@example.com> " + a1 + " <note@example.com> " + a2})
	r.pass()
	for _, e := range []*threadEntry{d1, d2} {
		if d := r.draft(th.ID, e.ID); d.State != draftPending {
			t.Fatalf("draft %s is %s", e.ID, d.State)
		}
	}
	if why := r.refusals(th.ID); len(why) != 1 || !strings.Contains(why[0], "more than one approval email") {
		t.Fatalf("refusals %v", why)
	}
}

// A "yes" straight to the older approval email, once a newer draft is
// waiting, sends nothing: the conversation moved on from it.
func TestAYesToAnOlderApprovalWithANewerDraftSendsNothing(t *testing.T) {
	r, th, d1, d2, a1, _ := twoDrafts(t)
	r.edge.deliver(r.mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Re: Q3 close",
		inReplyTo: a1, references: "<q3-close@example.com> " + a1})
	r.pass()
	for _, e := range []*threadEntry{d1, d2} {
		if d := r.draft(th.ID, e.ID); d.State != draftPending {
			t.Fatalf("draft %s is %s", e.ID, d.State)
		}
	}
	if why := r.refusals(th.ID); len(why) != 1 || why[0] != "a newer draft is waiting on this thread" {
		t.Fatalf("refusals %v", why)
	}
}
