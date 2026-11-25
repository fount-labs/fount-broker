package coordinator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

// The 11-24 review's M2 probe, flipped: once A1 approved draft 1, a later
// approval email A2 on the conversation carries A1 in its References, and
// the owner's yes to A2 sends draft 2, whether its In-Reply-To names A2 or
// it has only References.
func TestASpentApprovalInReferencesDoesntBlockALaterOne(t *testing.T) {
	for _, direct := range []bool{true, false} {
		t.Run(fmt.Sprintf("in-reply-to %v", direct), func(t *testing.T) {
			r := newSendRig(t, modeFull)
			const request = "<q3-close@example.com>"
			id := r.edge.deliver(r.mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Q3 close", messageID: request})
			r.pass()
			waitJob(t, r.c, mailJobID(id))
			th := r.waitStatus(r.w.ID, onlyThread(t, r.threads(r.w.ID)).ID, StatusReview)
			d1 := draftOn(t, th)
			r.pass()
			a1 := r.askMessageID(th, d1)
			r.intake.set(func(f *fakeIntake) { f.instruction, f.source, f.reply = "Yes.", "owner", true })
			r.edge.deliver(r.mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Re: Q3 close",
				messageID: "<yes1@example.com>", inReplyTo: a1, references: request + " " + a1})
			r.pass()
			if d := r.draft(th.ID, d1.ID); d.State != draftSent {
				t.Fatalf("draft 1 is %s: %v", d.State, r.refusals(th.ID))
			}

			r.intake.set(func(f *fakeIntake) { f.instruction, f.source, f.reply = "Now do Q4.", "owner", true })
			r.edge.deliver(r.mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Re: Q3 close",
				messageID: "<q4@example.com>", inReplyTo: "<yes1@example.com>", references: request + " " + a1 + " <yes1@example.com>"})
			th, ds := r.drafts(th.ID, 2)
			d2 := ds[1]
			r.pass()
			a2 := r.askMessageID(th, d2)
			r.intake.set(func(f *fakeIntake) { f.instruction, f.source, f.reply = "Yes.", "owner", true })
			yes := email{from: "dana@example.com", to: testWorkerAddr, subject: "Re: Q3 close",
				references: request + " " + a1 + " <yes1@example.com> <q4@example.com> " + a2}
			if direct {
				yes.inReplyTo = a2
			}
			r.edge.deliver(r.mb, yes)
			r.pass()
			if d := r.draft(th.ID, d2.ID); d.State != draftSent || d.Approval.Via != viaEmail {
				t.Fatalf("draft 2 is %s: %v", d.State, r.refusals(th.ID))
			}
			if why := r.refusals(th.ID); len(why) != 0 {
				t.Fatalf("refusals %v", why)
			}
		})
	}
}

// The 11-24 review's M5 probe, flipped: a thread lowered to Notify or Off
// after its approval email went refuses that email's "yes". The mode is the
// thread's at the reply, not when the email went.
func TestALoweredThreadRefusesItsApprovalEmail(t *testing.T) {
	for _, mode := range []string{modeNotify, modeOff} {
		t.Run(mode, func(t *testing.T) {
			r := newSendRig(t, modeFull)
			th, e := r.drafted()
			r.pass()
			a1 := r.askMessageID(th, e)
			th, _ = r.c.thread(anyDevice, r.w.ID, th.ID)
			raw, _ := json.Marshal(map[string]string{"mode": mode})
			res, err := r.c.applyThreadOp(anyDevice, r.w.ID, th.ID, opEnvelope{OpID: "op_lower", ThreadID: th.ID, BaseRevision: th.Revision, Kind: "setThreadReplyMode", Args: raw})
			if err != nil || !res.OK {
				t.Fatalf("lowering: %+v %v", res, err)
			}
			r.intake.set(func(f *fakeIntake) { f.instruction, f.source, f.reply = "Yes.", "owner", true })
			r.edge.deliver(r.mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Re: Q3 close", inReplyTo: a1})
			r.pass()
			if d := r.draft(th.ID, e.ID); d.State != draftPending {
				t.Fatalf("the draft is %s", d.State)
			}
			if why := r.refusals(th.ID); len(why) != 1 || why[0] != "the thread's reply mode was lowered since the approval email" {
				t.Fatalf("refusals %v", why)
			}
		})
	}
}

// On Full for the owner, a client's thread is on Notify and the owner's
// approval email still sends its draft; lowered to Off, it doesn't.
func TestAFullForTheOwnerThreadApprovesByEmailUntilLowered(t *testing.T) {
	for _, lower := range []bool{false, true} {
		t.Run(fmt.Sprintf("lowered %v", lower), func(t *testing.T) {
			r := newSendRig(t, modeFullOwner)
			if err := r.c.SetMailbox(r.w.ID, r.mb, []Requester{{Address: "carol@example.com", DKIMDomain: "example.com", AutoRun: true}}); err != nil {
				t.Fatal(err)
			}
			id := r.edge.deliver(r.mb, email{from: "carol@example.com", to: testWorkerAddr, subject: "Q3 close"})
			r.pass()
			waitJob(t, r.c, mailJobID(id))
			th := r.waitStatus(r.w.ID, onlyThread(t, r.threads(r.w.ID)).ID, StatusReview)
			e := draftOn(t, th)
			r.pass()
			if th.replyMode() != modeNotify {
				t.Fatalf("the client's thread is on %s", th.replyMode())
			}
			a1 := r.askMessageID(th, e)
			if lower {
				th, _ = r.c.thread(anyDevice, r.w.ID, th.ID)
				raw, _ := json.Marshal(map[string]string{"mode": modeOff})
				res, err := r.c.applyThreadOp(anyDevice, r.w.ID, th.ID, opEnvelope{OpID: "op_lower", ThreadID: th.ID, BaseRevision: th.Revision, Kind: "setThreadReplyMode", Args: raw})
				if err != nil || !res.OK {
					t.Fatalf("lowering: %+v %v", res, err)
				}
			}
			r.intake.set(func(f *fakeIntake) { f.instruction, f.source, f.reply = "Yes.", "owner", true })
			r.edge.deliver(r.mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Re: Q3 close", inReplyTo: a1})
			r.pass()
			want := draftSent
			if lower {
				want = draftPending
			}
			if d := r.draft(th.ID, e.ID); d.State != want {
				t.Fatalf("the draft is %s, want %s: %v", d.State, want, r.refusals(th.ID))
			}
		})
	}
}

// The 11-24 review's L9 probe, flipped: an email from the thread's people
// after the approval email went refuses its "yes", as NEW_MAIL_SINCE refuses
// a device's approval; the owner's refused replies to approval emails, and
// a stranger's email, don't.
func TestAnEmailAfterTheApprovalEmailRefusesItsYes(t *testing.T) {
	r := newSendRig(t, modeFull)
	th, e := r.drafted()
	r.pass()
	a1 := r.askMessageID(th, e)
	r.intake.set(func(f *fakeIntake) { f.instruction, f.source, f.reply = "Yes.", "owner", true })
	r.edge.deliver(r.mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Re: Q3 close", inReplyTo: a1, unsigned: true})
	r.edge.deliver(r.mb, email{from: "eve@else.example", to: testWorkerAddr, subject: "Re: Q3 close", inReplyTo: a1})
	r.pass()
	// With automatic runs off, it waits on the thread instead of starting a
	// turn, whose draft would be newer.
	if res := r.workerOp(r.w.ID, "op_auto_off", "setAutoRun", switchArgs{On: false, BaseRevision: r.settings(r.w.ID).AutoRunRev}); !res.OK {
		t.Fatalf("setAutoRun: %+v", res)
	}
	r.intake.set(func(f *fakeIntake) { f.instruction = "Wait, the amounts changed." })
	r.edge.deliver(r.mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Re: Q3 close", inReplyTo: a1})
	r.pass()
	r.intake.set(func(f *fakeIntake) { f.instruction = "Yes." })
	r.edge.deliver(r.mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Re: Q3 close", inReplyTo: a1})
	r.pass()
	if d := r.draft(th.ID, e.ID); d.State != draftPending {
		t.Fatalf("the draft is %s", d.State)
	}
	why := r.refusals(th.ID)
	if len(why) == 0 || !strings.HasPrefix(why[len(why)-1], "an email came on the thread after the approval email") {
		t.Fatalf("refusals %v", why)
	}
}

// The 11-24 review's L11: the approval email threads only under the
// reviewer's own signed email, never one that merely says it is from them.
func TestTheApprovalEmailThreadsOnlyUnderSignedMail(t *testing.T) {
	th := &threadRecord{Entries: []threadEntry{
		{Kind: entryMail, Mail: &mailEntry{Sender: "dana@example.com", Signed: "example.com", MessageID: "<real@example.com>"}},
		{Kind: entryMail, Mail: &mailEntry{Sender: "dana@example.com", MessageID: "<spoof@else.example>", Subject: "Invoice overdue"}},
		{Kind: entryMail, Mail: &mailEntry{Sender: "dana@example.com", Signed: "else.example", MessageID: "<other@else.example>"}},
	}}
	if m := th.newestMailFrom("dana@example.com"); m == nil || m.MessageID != "<real@example.com>" {
		t.Fatalf("threads under %+v", m)
	}
}

// The 11-24 review's L12: an approval email for a draft with files says
// they aren't in it, and that "yes" sends them unseen.
func TestAnApprovalEmailSaysItsFilesArentInIt(t *testing.T) {
	d := &draftEntry{To: []string{"carol@example.com"}, Subject: "Re: Q3 close", Text: "Attached."}
	text := approvalText(d, []string{"q3.pdf"}, "Acme", "dana@example.com", true, time.Now())
	if !strings.Contains(text, "It attaches q3.pdf, which aren't in this email") || !strings.Contains(text, "To look at them first, open Fount.") {
		t.Fatalf("the email:\n%s", text)
	}
	if strings.Contains(strings.ToLower(text), "approve") {
		t.Fatalf("the email says approve:\n%s", text)
	}
}

// The 11-24 broker review's L10: a client's reply threads under none of the
// owner's approval emails, nor under the owner's "yes", which answered an
// email the client never got. The replies the worker sent stay in its
// References.
func TestAClientsReplyDoesntThreadUnderAnApproval(t *testing.T) {
	domain := domainOf(testWorkerAddr)
	approval := "<fm." + strings.Repeat("a", 26) + ".tok@" + domain + ">"
	sent := "<fm." + strings.Repeat("b", 26) + ".tok@" + domain + ">"
	th := &threadRecord{Subject: "Q3 close", Participants: []string{"dana@example.com", "lee@client.com"}, Entries: []threadEntry{
		{Kind: entryMail, Mail: &mailEntry{Sender: "lee@client.com", MessageID: "<q3@client.com>"}},
		{Kind: entryDraft, Draft: &draftEntry{State: draftSent, MessageID: sent}},
		{Kind: entryMail, Mail: &mailEntry{Sender: "dana@example.com", MessageID: "<note@example.com>", Subject: "Re: Q3 close",
			References: "<q3@client.com> " + sent + " " + approval}},
		{Kind: entryMail, Mail: &mailEntry{Sender: "dana@example.com", MessageID: "<yes@example.com>", Verdict: verdictApproval,
			References: "<q3@client.com> " + approval}},
	}}
	d := &draftEntry{}
	th.replyTo(d, domain)
	if d.InReplyTo != "<note@example.com>" {
		t.Fatalf("the reply answers %s, not the newest mail but the yes", d.InReplyTo)
	}
	if want := []string{"<q3@client.com>", sent, "<note@example.com>"}; !slices.Equal(d.References, want) {
		t.Fatalf("References %v, want %v", d.References, want)
	}
	if d.Subject != "Re: Q3 close" {
		t.Fatalf("subject %q", d.Subject)
	}
}

// End to end: once the owner's yes sent draft 1 and their next note made
// draft 2, draft 2 carries none of the approval emails' Message-IDs.
func TestADraftCarriesNoApprovalMessageID(t *testing.T) {
	r := newSendRig(t, modeFull)
	const request = "<q3-close@example.com>"
	id := r.edge.deliver(r.mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Q3 close", messageID: request})
	r.pass()
	waitJob(t, r.c, mailJobID(id))
	th := r.waitStatus(r.w.ID, onlyThread(t, r.threads(r.w.ID)).ID, StatusReview)
	d1 := draftOn(t, th)
	r.pass()
	a1 := r.askMessageID(th, d1)
	r.intake.set(func(f *fakeIntake) { f.instruction, f.source, f.reply = "Yes.", "owner", true })
	r.edge.deliver(r.mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Re: Q3 close",
		messageID: "<yes1@example.com>", inReplyTo: a1, references: request + " " + a1})
	r.pass()
	r.intake.set(func(f *fakeIntake) { f.instruction, f.source, f.reply = "Now do Q4.", "owner", true })
	r.edge.deliver(r.mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Re: Q3 close",
		messageID: "<q4@example.com>", inReplyTo: "<yes1@example.com>", references: request + " " + a1 + " <yes1@example.com>"})
	_, ds := r.drafts(th.ID, 2)
	d2 := r.draft(th.ID, ds[1].ID)
	if d2.InReplyTo != "<q4@example.com>" || slices.Contains(d2.References, a1) {
		t.Fatalf("draft 2 answers %s with References %v; A1 is %s", d2.InReplyTo, d2.References, a1)
	}
}
