package coordinator

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSendEdge is the edge's POST /send and POST /sent/query, served by
// fakeMailEdge after its signature check and generation fence, with the
// edge's dedupe: a repeat of the same bytes under one Message-ID answers the
// first send's results and delivers nothing, other bytes are 409, and an ID
// marked in doubt answers send_in_doubt and is never delivered.
type fakeSendEdge struct {
	t         *testing.T
	mu        sync.Mutex
	records   map[string]*SentRecord
	delivered map[string]int // Message-ID -> deliveries
	posts     map[string]int // Message-ID -> POST /send calls
	raw       map[string][]byte
	inDoubt   map[string]bool
	// doubtNext marks the next reply posted (fm.… with "Re: ") in doubt.
	doubtNext bool
}

func newFakeSendEdge(t *testing.T) *fakeSendEdge {
	return &fakeSendEdge{t: t, records: map[string]*SentRecord{},
		delivered: map[string]int{}, posts: map[string]int{}, raw: map[string][]byte{}, inDoubt: map[string]bool{}}
}

func (f *fakeSendEdge) serve(w http.ResponseWriter, r *http.Request, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/send":
		var req struct {
			Message []byte `json:"message"`
		}
		json.Unmarshal(body, &req)
		h, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(req.Message))).ReadMIMEHeader()
		if err != nil {
			http.Error(w, `{"error":"bad message"}`, 400)
			return
		}
		id, hash := h.Get("Message-Id"), sha256Hex(req.Message)
		f.posts[id]++
		if f.doubtNext && strings.HasPrefix(h.Get("Subject"), "Re: ") {
			f.doubtNext, f.inDoubt[id] = false, true
		}
		if f.inDoubt[id] {
			f.records[id] = &SentRecord{MessageID: id, State: sentInDoubt, SHA256: hash}
			w.WriteHeader(409)
			w.Write([]byte(`{"error":"an earlier send of this Message-ID may have been delivered","code":"send_in_doubt"}`))
			return
		}
		if prev := f.records[id]; prev != nil {
			if prev.SHA256 != hash {
				http.Error(w, `{"error":"this Message-ID was already sent with different content"}`, 409)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"results": prev.Results})
			return
		}
		var results []RecipientResult
		for _, to := range strings.Split(h.Get("To"), ",") {
			results = append(results, RecipientResult{Recipient: strings.TrimSpace(to), Status: resultSent})
		}
		f.delivered[id]++
		f.raw[id] = req.Message
		f.records[id] = &SentRecord{MessageID: id, State: sentDone, SHA256: hash, Results: results}
		json.NewEncoder(w).Encode(map[string]any{"results": results})
	case "/sent/query":
		var q struct {
			IDs []string `json:"message_ids"`
		}
		json.Unmarshal(body, &q)
		out := []SentRecord{}
		for _, id := range q.IDs {
			if rec := f.records[id]; rec != nil {
				out = append(out, *rec)
			} else {
				out = append(out, SentRecord{MessageID: id, State: sentNone})
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"records": out})
	default:
		http.Error(w, `{"error":"not found"}`, 404)
	}
}

func (f *fakeSendEdge) count(m map[string]int, id string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return m[id]
}

// sentTo is the Message-IDs delivered to address whose subject starts with
// prefix.
func (f *fakeSendEdge) sentTo(address, prefix string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for id, raw := range f.raw {
		h, _ := textproto.NewReader(bufio.NewReader(bytes.NewReader(raw))).ReadMIMEHeader()
		if strings.Contains(h.Get("To"), address) && strings.HasPrefix(h.Get("Subject"), prefix) {
			out = append(out, id)
		}
	}
	return out
}

const agentAnswer = "The ledger is reconciled. See [[statements/q3.pdf?page=4|the Q3 statement]]."

// sendRig is a mail rig whose agent jobs answer agentAnswer, with a sending
// edge, and a worker on mode whose owner is dana@example.com.
type sendRig struct {
	*mailRig
	send *fakeSendEdge
	w    Worker
	mb   Mailbox
}

func newSendRig(t *testing.T, mode string) *sendRig {
	t.Helper()
	return sendRigOn(t, newMailRig(t, MailConfig{Send: true}), mode)
}

// sendRigOn makes r, whose coordinator sends, a send rig.
func sendRigOn(t *testing.T, r *mailRig, mode string) *sendRig {
	t.Helper()
	old := sendBackoff
	sendBackoff = func(int) time.Duration { return 0 }
	t.Cleanup(func() { sendBackoff = old })
	se := newFakeSendEdge(t)
	r.edge.mu.Lock()
	r.edge.send = se
	r.edge.mu.Unlock()
	r.runner.events = eventsWith(summaryWith(t, func(p map[string]any) {
		p["state"], p["text"], p["steps"] = "ready_for_review", agentAnswer, []any{}
		delete(p, "question")
	}))
	w, mb := r.worker()
	if res := r.workerOp(w.ID, "op_mode", "setDefaultMode", defaultModeArgs{Mode: mode, Owner: "dana@example.com", Firm: "Acme"}); !res.OK {
		t.Fatalf("setDefaultMode: %+v", res)
	}
	return &sendRig{mailRig: r, send: se, w: w, mb: mb}
}

// drafted delivers a request from dana and waits for its draft.
func (r *sendRig) drafted() (*threadRecord, *threadEntry) {
	r.t.Helper()
	id := r.edge.deliver(r.mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Q3 close"})
	r.pass()
	waitJob(r.t, r.c, mailJobID(id))
	th := onlyThread(r.t, r.threads(r.w.ID))
	th = r.waitStatus(r.w.ID, th.ID, StatusReview)
	return th, draftOn(r.t, th)
}

func draftOn(t *testing.T, th *threadRecord) *threadEntry {
	t.Helper()
	for i := range th.Entries {
		if th.Entries[i].Kind == entryDraft {
			return &th.Entries[i]
		}
	}
	t.Fatalf("no draft on the thread: %+v", th.Entries)
	return nil
}

func (r *sendRig) approve(th *threadRecord, d *threadEntry, opID string, rev int) OpResult {
	r.t.Helper()
	raw, _ := json.Marshal(map[string]any{"draftId": d.ID, "draftRev": rev})
	res, err := r.c.applyThreadOp(anyDevice, r.w.ID, th.ID, opEnvelope{OpID: opID, ThreadID: th.ID, BaseRevision: th.Revision, Kind: "approveDraft", Args: raw})
	if err != nil {
		r.t.Fatal(err)
	}
	return res
}

func (r *sendRig) draft(threadID, draftID string) *draftEntry {
	r.t.Helper()
	th, err := r.c.thread(anyDevice, r.w.ID, threadID)
	if err != nil {
		r.t.Fatal(err)
	}
	return th.entry(draftID).Draft
}

func TestAJobsAnswerBecomesADraftWithItsBytes(t *testing.T) {
	r := newSendRig(t, modeNotify)
	th, e := r.drafted()
	d := e.Draft
	if d.State != draftPending || d.DraftRev != 1 || !slices.Equal(d.To, []string{"dana@example.com"}) || d.Subject != "Re: Q3 close" {
		t.Fatalf("draft %+v", d)
	}
	if !strings.HasPrefix(d.MessageID, "<fm.") || !strings.HasSuffix(d.MessageID, "@fountbox.com>") || d.Hash == "" {
		t.Fatalf("message id %q hash %q", d.MessageID, d.Hash)
	}
	var raw []byte
	r.c.view(r.w.ID, anyDevice, func(t *Tree) (err error) {
		raw, err = t.Read(sendBytes(d.SendID))
		return err
	})
	text := string(raw)
	for _, want := range []string{"Message-ID: " + d.MessageID, "Subject: Re: Q3 close", "See [1].", "[1] the Q3 statement (q3.pdf), page 4",
		"Sent by Acme with Fount.", "reviewed by a person", privacyLink} {
		if !strings.Contains(text, want) {
			t.Errorf("the bytes lack %q:\n%s", want, text)
		}
	}
	if sha256Hex(raw) != d.Hash {
		t.Error("the hash isn't the bytes'")
	}
	// The thread's view: Desktop's draft entry, the reply mode in force.
	view := th.view()
	if view.Status != StatusReview || view.ReplyMode != modeNotify {
		t.Fatalf("header %+v", view.ThreadHeader)
	}
	data, _ := json.Marshal(view.Entries)
	if !strings.Contains(string(data), `"kind":"draft","content":"result","state":"pending","draftRev":1,"to":["dana@example.com"]`) {
		t.Fatalf("the draft's view: %s", data)
	}
	// Under Notify the owner hears there's a draft, without its content.
	r.pass()
	notices := r.send.sentTo("dana@example.com", "A draft reply is ready in Acme")
	if len(notices) != 1 || strings.Contains(string(r.send.raw[notices[0]]), "reconciled") {
		t.Fatalf("notices %v", notices)
	}
}

// A crash after the post and before "sent" was written: the restarted
// coordinator asks the edge, finds the send, and doesn't send again.
func TestAnApprovedReplyIsSentOnceAcrossACrash(t *testing.T) {
	r := newSendRig(t, modeNotify)
	th, e := r.drafted()
	r.pass()
	th, _ = r.c.thread(anyDevice, r.w.ID, th.ID)
	if res := r.approve(th, e, "op_ok", 1); !res.OK {
		t.Fatalf("approve: %+v", res)
	}
	d := r.draft(th.ID, e.ID)
	if d.State != draftSent || d.Send == nil || d.Send.State != sendSending || d.Approval.Via != viaApp || d.Approval.Hash != d.Hash {
		t.Fatalf("approved: %+v", d)
	}
	r.store.arm()
	r.pass()
	if n := r.send.count(r.send.delivered, d.MessageID); n != 1 {
		t.Fatalf("delivered %d times before the crash", n)
	}
	r.start()
	r.pass()
	r.pass()
	if n := r.send.count(r.send.delivered, d.MessageID); n != 1 {
		t.Fatalf("delivered %d times, want once", n)
	}
	if n := r.send.count(r.send.posts, d.MessageID); n != 1 {
		t.Fatalf("posted %d times: the restart should have asked first", n)
	}
	d = r.draft(th.ID, e.ID)
	if d.Send.State != sendSent || len(d.Send.Delivery) != 1 || d.Send.Delivery[0].Status != deliverySent {
		t.Fatalf("after the restart: %+v", d.Send)
	}
	if th, _ := r.c.thread(anyDevice, r.w.ID, th.ID); th.Status != StatusIdle {
		t.Fatalf("status %s", th.Status)
	}
}

func TestAnInDoubtSendIsNeverResentUnderItsID(t *testing.T) {
	r := newSendRig(t, modeNotify)
	th, e := r.drafted()
	r.send.mu.Lock()
	r.send.doubtNext = true
	r.send.mu.Unlock()
	if res := r.approve(th, e, "op_ok", 1); !res.OK {
		t.Fatalf("approve: %+v", res)
	}
	first := r.draft(th.ID, e.ID).MessageID
	r.pass()
	r.pass()
	r.pass()
	d := r.draft(th.ID, e.ID)
	if d.Send.State != sendMaybe || d.Send.Code != CodeMaybeSent {
		t.Fatalf("send %+v", d.Send)
	}
	if n := r.send.count(r.send.posts, first); n != 1 {
		t.Fatalf("posted %d times; an in-doubt ID is never posted again", n)
	}
	if len(r.send.sentTo("dana@example.com", "An email from Acme wasn't delivered")) != 1 {
		t.Error("the owner wasn't told")
	}
	th, _ = r.c.thread(anyDevice, r.w.ID, th.ID)
	raw, _ := json.Marshal(sendAgainArgs{SentID: d.SendID})
	res, err := r.c.applyThreadOp(anyDevice, r.w.ID, th.ID, opEnvelope{OpID: "op_again", ThreadID: th.ID, BaseRevision: th.Revision, Kind: "sendAgain", Args: raw})
	if err != nil || res.OK || res.Code != CodeMaybeSent {
		t.Fatalf("sendAgain without duplicateOk: %+v %v", res, err)
	}
	raw, _ = json.Marshal(sendAgainArgs{SentID: d.SendID, DuplicateOK: true})
	res, err = r.c.applyThreadOp(anyDevice, r.w.ID, th.ID, opEnvelope{OpID: "op_again2", ThreadID: th.ID, BaseRevision: th.Revision, Kind: "sendAgain", Args: raw})
	if err != nil || !res.OK {
		t.Fatalf("sendAgain with duplicateOk: %+v %v", res, err)
	}
	r.pass()
	d = r.draft(th.ID, e.ID)
	if d.MessageID == first || d.Send.State != sendSent || r.send.count(r.send.delivered, d.MessageID) != 1 {
		t.Fatalf("the new attempt: %s %+v", d.MessageID, d.Send)
	}
	if n := r.send.count(r.send.posts, first); n != 1 {
		t.Fatalf("the in-doubt ID was posted %d times", n)
	}
}

func TestAStaleApprovalIsRefused(t *testing.T) {
	r := newSendRig(t, modeNotify)
	th, e := r.drafted()
	if res := r.approve(th, e, "op_stale", 2); res.OK || res.Code != CodeDraftChanged {
		t.Fatalf("draftRev 2: %+v", res)
	}
	raw, _ := json.Marshal(map[string]any{"draftId": e.ID, "draftRev": 1, "hash": strings.Repeat("0", 64)})
	res, _ := r.c.applyThreadOp(anyDevice, r.w.ID, th.ID, opEnvelope{OpID: "op_hash", ThreadID: th.ID, BaseRevision: th.Revision, Kind: "approveDraft", Args: raw})
	if res.OK || res.Code != CodeDraftChanged {
		t.Fatalf("another hash: %+v", res)
	}
	// An approval from before a new email arrived is refused.
	old := th.Revision
	r.edge.deliver(r.mb, email{from: "dana@example.com", to: testWorkerAddr, inReplyTo: e.Draft.MessageID, subject: "Re: Q3 close"})
	r.pass()
	th, _ = r.c.thread(anyDevice, r.w.ID, th.ID)
	th.Revision = old
	if res := r.approve(th, e, "op_old", 1); res.OK || res.Code != CodeNewMailSince {
		t.Fatalf("after new mail: %+v", res)
	}
	if d := r.draft(th.ID, e.ID); d.State != draftPending {
		t.Fatalf("a refused approval changed the draft: %+v", d)
	}
	// An edited text is approved as the next draft_rev, with its own bytes.
	th, _ = r.c.thread(anyDevice, r.w.ID, th.ID)
	raw, _ = json.Marshal(map[string]any{"draftId": e.ID, "draftRev": 1, "text": "Reconciled, with one fix."})
	res, _ = r.c.applyThreadOp(anyDevice, r.w.ID, th.ID, opEnvelope{OpID: "op_edit", ThreadID: th.ID, BaseRevision: th.Revision, Kind: "approveDraft", Args: raw})
	d := r.draft(th.ID, e.ID)
	if !res.OK || d.DraftRev != 2 || d.MessageID == e.Draft.MessageID || d.Approval.AgentTextHash == d.Approval.SentTextHash {
		t.Fatalf("an edit: %+v %+v", res, d)
	}
}

func TestAReviewerApprovesAndANonMemberCant(t *testing.T) {
	f := newTeamFixture(t)
	mb := newMailbox(t, testWorkerAddr)
	if err := f.c.SetMailbox(f.w1.ID, mb, []Requester{{Address: "dana@example.com"}}); err != nil {
		t.Fatal(err)
	}
	var threadID string
	err := f.c.change(f.w1.ID, anyDevice, func(t *Tree) error {
		now := time.Now().UTC()
		th, err := newMailThread(f.w1.ID, "Q3", now)
		if err != nil {
			return err
		}
		th.Participants = []string{"dana@example.com"}
		th.Jobs = []threadJob{{ID: "j_done", State: JobFinished, Rev: 1}}
		if _, err := th.push(1, now, threadEntry{Kind: entryTurn, JobID: "j_done", State: turnDone, Text: "Done."}); err != nil {
			return err
		}
		th.finish(1, now)
		threadID = th.ID
		return saveThread(t, th)
	})
	if err != nil {
		t.Fatal(err)
	}
	reviewer := f.api(t, f.reviewer, "maria")
	base := "/v1/workers/" + f.w1.ID + "/threads/" + threadID
	code, view := do(t, reviewer, "GET", base, "")
	if code != 200 || view["status"] != string(StatusReview) {
		t.Fatalf("the thread: %d %v", code, view)
	}
	var draftID string
	for _, e := range view["entries"].([]any) {
		if e := e.(map[string]any); e["kind"] == "draft" {
			draftID = e["id"].(string)
		}
	}
	th0, _ := f.c.thread(anyDevice, f.w1.ID, threadID)
	d0 := th0.entry(draftID).Draft
	claims := ApprovalClaims{Aud: testAudience, Worker: f.w1.ID, Thread: threadID, Draft: draftID, DraftRev: 1, To: d0.To, Subject: d0.Subject, Text: sha256Hex([]byte(d0.Text)), Iat: time.Now().Unix()}
	sign := func(d testDevice, a ApprovalClaims) string {
		token, err := SignApproval(d.key, a)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	body := func(op, token string) string {
		approval := ""
		if token != "" {
			approval = `,"approval":"` + token + `"`
		}
		return `{"opId":"` + op + `","threadId":"` + threadID + `","baseRevision":` + strconv.Itoa(int(view["revision"].(float64))) +
			`,"kind":"approveDraft","args":{"draftId":"` + draftID + `","draftRev":1` + approval + `}}`
	}
	stranger := newTestDevice(t)
	outsider := httptest.NewServer(f.c.AccountHandler(stranger.caller("eve")))
	t.Cleanup(outsider.Close)
	if code, out := do(t, outsider, "POST", base+"/ops", body("op_eve", sign(stranger, claims))); code != 404 {
		t.Fatalf("a non-member: %d %v", code, out)
	}
	// A device's approval is its signature over exactly what is sent.
	other := claims
	other.Text = sha256Hex([]byte("something else"))
	late := claims
	late.Iat = time.Now().Add(-2 * time.Hour).Unix()
	for i, token := range []string{"", sign(f.owner, claims), sign(f.reviewer, other), sign(f.reviewer, late), sign(f.reviewer, claims) + "x"} {
		if code, out := do(t, reviewer, "POST", base+"/ops", body("op_bad"+strconv.Itoa(i), token)); code != 200 || out["code"] != string(CodeApprovalUnsigned) {
			t.Fatalf("approval %d: %d %v", i, code, out)
		}
	}
	token := sign(f.reviewer, claims)
	if code, out := do(t, reviewer, "POST", base+"/ops", body("op_maria", token)); code != 200 || out["ok"] != true {
		t.Fatalf("the reviewer: %d %v", code, out)
	}
	th, _ := f.c.thread(anyDevice, f.w1.ID, threadID)
	d := th.entry(draftID).Draft
	if d.State != draftSent || d.Approval.Device != f.reviewer.id() || d.Send.State != sendSending {
		t.Fatalf("approved: %+v %+v", d, d.Approval)
	}
	if d.Approval.Token != token || d.Approval.Member == "" {
		t.Errorf("the approval keeps no signature: %+v", d.Approval)
	}
	// The sign-off record: who asked, who approved, what, signed.
	var so signoff
	err = f.c.view(f.w1.ID, anyDevice, func(tr *Tree) error {
		_, err := readJSON(tr, signoffDir+d.SendID+".json", &so)
		return err
	})
	if err != nil || so.Signature != token || so.Reviewer.Device != f.reviewer.id() || !slices.Equal(so.Requesters, []string{"dana@example.com"}) || so.Text != claims.Text || so.Files == nil {
		t.Fatalf("the sign-off: %v %+v", err, so)
	}
	payload, sig, _ := splitToken(so.Signature)
	if !ed25519.Verify(f.reviewer.pub(), append([]byte(ApprovalContext), payload...), sig) {
		t.Error("the sign-off's signature doesn't verify")
	}
}

// Approval by email: the owner on Full answers the approval email with
// "yes". A wrong token, a reply that isn't aligned, someone else, or the same
// approval again sends nothing.
func TestApprovalByEmail(t *testing.T) {
	r := newSendRig(t, modeFull)
	r.intake.set(func(f *fakeIntake) { f.instruction, f.source, f.reply = "Yes.", "owner", true })
	th, e := r.drafted()
	r.pass()
	asks := r.send.sentTo("dana@example.com", "Approve: Re: Q3 close")
	if len(asks) != 1 || !strings.Contains(string(r.send.raw[asks[0]]), "reconciled") {
		t.Fatalf("the approval email: %v", asks)
	}
	ask := asks[0]
	reply := func(e email) {
		e.from, e.to, e.subject = cmpOrStr(e.from, "dana@example.com"), testWorkerAddr, "Re: Approve: Re: Q3 close"
		r.edge.deliver(r.mb, e)
		r.pass()
	}
	pending := func(why string) {
		t.Helper()
		if d := r.draft(th.ID, e.ID); d.State != draftPending {
			t.Fatalf("%s: the draft is %s", why, d.State)
		}
	}
	// The thread's reply token is right, the approval token isn't.
	parts := strings.Split(strings.Trim(ask, "<>"), ".")
	wrong := "<fm." + strings.Repeat("a", 26) + "." + parts[2] + "." + strings.Join(parts[3:], ".") + ">"
	reply(email{inReplyTo: wrong})
	pending("a wrong token")
	reply(email{inReplyTo: ask, unsigned: true})
	pending("an unsigned reply")
	reply(email{from: "eve@else.example", inReplyTo: ask})
	pending("someone else")

	reply(email{inReplyTo: ask})
	d := r.draft(th.ID, e.ID)
	if d.State != draftSent || d.Approval.Via != viaEmail || d.Approval.By != "dana@example.com" || d.Approval.DKIM != "example.com" {
		t.Fatalf("approved by email: %+v", d.Approval)
	}
	r.pass()
	if n := r.send.count(r.send.delivered, d.MessageID); n != 1 {
		t.Fatalf("the reply was delivered %d times", n)
	}
	reply(email{inReplyTo: ask})
	r.pass()
	if n := r.send.count(r.send.delivered, d.MessageID); n != 1 {
		t.Fatalf("a replayed approval: delivered %d times", n)
	}
	th, _ = r.c.thread(anyDevice, r.w.ID, th.ID)
	var reasons []string
	for _, e := range th.Entries {
		if e.Kind == entryEvent && e.Code == "approval_refused" {
			reasons = append(reasons, e.Args["reason"])
		}
	}
	if !slices.Contains(reasons, "this approval was already used") || !slices.Contains(reasons, "it isn't from dana@example.com") {
		t.Fatalf("refusals %v", reasons)
	}
}

func TestTheAcknowledgementGoesOnceByEdgeID(t *testing.T) {
	r := newSendRig(t, modeNotify)
	if res := r.workerOp(r.w.ID, "op_ack", "setAcknowledge", switchArgs{On: true}); !res.OK {
		t.Fatalf("setAcknowledge: %+v", res)
	}
	id := r.edge.deliver(r.mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Q3 close"})
	r.pass()
	th := onlyThread(t, r.threads(r.w.ID))
	if err := r.c.Acknowledge(context.Background(), AckRequest{WorkerID: r.w.ID, ThreadID: th.ID, EdgeID: id, To: "dana@example.com"}); err != nil {
		t.Fatal(err)
	}
	r.pass()
	acks := r.send.sentTo("dana@example.com", "Re: Q3 close")
	if len(acks) != 1 || !strings.Contains(string(r.send.raw[acks[0]]), "Received. We'll reply after review.") {
		t.Fatalf("acks %v", acks)
	}
}

func TestSetThreadReplyModeOnlyLowers(t *testing.T) {
	r := newSendRig(t, modeNotify)
	th, _ := r.drafted()
	op := func(id, mode string) OpResult {
		raw, _ := json.Marshal(map[string]string{"mode": mode})
		th, _ = r.c.thread(anyDevice, r.w.ID, th.ID)
		res, err := r.c.applyThreadOp(anyDevice, r.w.ID, th.ID, opEnvelope{OpID: id, ThreadID: th.ID, BaseRevision: th.Revision, Kind: "setThreadReplyMode", Args: raw})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if res := op("op_up", modeFull); res.OK || res.Code != CodeModeAbove {
		t.Fatalf("raising: %+v", res)
	}
	if res := op("op_down", modeOff); !res.OK {
		t.Fatalf("lowering: %+v", res)
	}
	if th, _ := r.c.thread(anyDevice, r.w.ID, th.ID); th.header().ReplyMode != modeOff {
		t.Fatalf("mode %s", th.header().ReplyMode)
	}
}

func TestAnAccountNoticeGoesOncePerKey(t *testing.T) {
	r := newSendRig(t, modeNotify)
	ctx := context.Background()
	// The mail loop's notices (lapse.go) are NotifyOwner's.
	notices := r.c.mail.cfg.Notices
	if notices == nil {
		t.Fatal("a sending coordinator has no owner notices")
	}
	for range 2 {
		if err := notices.Notify(ctx, OwnerNotice{Key: "acct/lapsed/1", Kind: NoticeLapsed, Account: r.w.Account, WorkerID: r.w.ID, Until: time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := notices.Notify(ctx, OwnerNotice{Key: "acct/lapsed/1", Kind: NoticeLapsed, Account: r.w.Account, WorkerID: "w_other"}); err != nil {
		t.Fatal(err)
	}
	r.pass()
	got := r.send.sentTo("dana@example.com", "Acme is paused")
	if len(got) != 1 || !strings.Contains(string(r.send.raw[got[0]]), "1 Dec 2026. Renew") {
		t.Fatalf("notices %v\n%s", got, r.send.raw[got[0]])
	}
}

func TestAForwardedQuestionIsADraft(t *testing.T) {
	r := newSendRig(t, modeNotify)
	th, _ := r.drafted()
	var draftID string
	err := r.c.change(r.w.ID, anyDevice, func(tr *Tree) error {
		th, err := loadThread(tr, th.ID)
		if err != nil {
			return err
		}
		rev := th.Revision + 1
		qid, err := th.push(rev, time.Now(), threadEntry{Kind: entryQuestion, JobID: "j_q", Text: "Which quarter?"})
		if err != nil {
			return err
		}
		if draftID, err = r.c.questionDraft(tr, th, th.entry(qid), "dana@example.com", rev, time.Now()); err != nil {
			return err
		}
		th.finish(rev, time.Now())
		return saveThread(tr, th)
	})
	if err != nil {
		t.Fatal(err)
	}
	d := r.draft(th.ID, draftID)
	if d.Content != draftContentQuestion || d.Text != "Which quarter?" || d.QuestionID == "" || d.Hash == "" {
		t.Fatalf("draft %+v", d)
	}
}

// Sends go through the mail loop's Service: under a generation they name it,
// and the edge's fence lets them through.
func TestASendNamesTheGeneration(t *testing.T) {
	r := sendRigOn(t, genRig(t, MailConfig{Send: true}), modeNotify)
	th, e := r.drafted()
	if res := r.approve(th, e, "op_ok", 1); !res.OK {
		t.Fatalf("approve: %+v", res)
	}
	r.pass()
	if !r.edge.coord.Mailbox(r.mb.MailboxID).Enrolled {
		t.Fatal("the mailbox wasn't enrolled")
	}
	d := r.draft(th.ID, e.ID)
	if n := r.send.count(r.send.delivered, d.MessageID); n != 1 || d.Send.State != sendSent {
		t.Fatalf("delivered %d times, send %+v", n, d.Send)
	}
	for _, c := range r.edge.coord.Calls() {
		if strings.HasPrefix(c, "fenced") {
			t.Errorf("the fence refused %s", c)
		}
	}
}

// A coordinator that names no generation can't send for a mailbox another
// one enrolled: the fence holds the send's query, and nothing is posted.
func TestAnEnrolledMailboxRefusesASendWithoutTheGeneration(t *testing.T) {
	r := newSendRig(t, modeNotify)
	th, e := r.drafted()
	pub, _, _ := ed25519.GenerateKey(nil)
	r.edge.coord.Advance(3, pub)
	if err := r.edge.coord.Enroll(r.mb.MailboxID); err != nil {
		t.Fatal(err)
	}
	if res := r.approve(th, e, "op_ok", 1); !res.OK {
		t.Fatalf("approve: %+v", res)
	}
	if err := r.c.runSends(context.Background(), r.w.ID); err != nil {
		t.Fatal(err)
	}
	d := r.draft(th.ID, e.ID)
	if n := r.send.count(r.send.posts, d.MessageID); n != 0 || d.Send.State != sendSending {
		t.Fatalf("posted %d times, send %+v", n, d.Send)
	}
	if !slices.Contains(r.edge.coord.Calls(), "fenced POST /sent/query: generation_required") {
		t.Fatalf("calls %v", r.edge.coord.Calls())
	}
}
