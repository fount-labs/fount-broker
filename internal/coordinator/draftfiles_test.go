package coordinator

import (
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// draftFileRig is a team worker with a mailbox and a pending draft whose
// job wrote two files, one nested.
type draftFileRig struct {
	f                   teamFixture
	threadID, draftID   string
	report, data        string
	reviewer, admin     *httptest.Server
	reviewerID, adminID string
}

func newDraftFileRig(t *testing.T, mode string) *draftFileRig {
	t.Helper()
	f := newTeamFixture(t)
	f.tt.update("m_owner", func(m *ListMember) { m.Email = "dana@example.com" })
	f.tt.update("m_reviewer", func(m *ListMember) { m.Email = "maria@example.com" })
	f.tt.update("m_admin", func(m *ListMember) { m.Email = "dev@firm.example" })
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	mb := newMailbox(t, testWorkerAddr)
	if err := f.c.SetMailbox(f.w1.ID, mb, []Requester{{Address: "dana@example.com"}, {Address: "maria@example.com"}}); err != nil {
		t.Fatal(err)
	}
	if mode != "" {
		raw, _ := json.Marshal(defaultModeArgs{Mode: mode, Owner: "dana@example.com", Firm: "Acme"})
		if res, err := f.c.applyWorkerOp(anyDevice, f.w1.ID, workerOpEnvelope{OpID: "op_mode", Kind: "setDefaultMode", Args: raw}); err != nil || !res.OK {
			t.Fatalf("setDefaultMode: %+v %v", res, err)
		}
	}
	r := &draftFileRig{f: f, reviewer: f.api(t, f.reviewer, "maria"), admin: f.api(t, f.admin, "dev"), reviewerID: f.reviewer.id(), adminID: f.admin.id()}
	err := f.c.change(f.w1.ID, anyDevice, func(t *Tree) error {
		now := time.Now().UTC()
		th, err := newMailThread(f.w1.ID, "Q3", now)
		if err != nil {
			return err
		}
		r.threadID = th.ID
		r.report = "threads/" + th.ID + "/outputs/j_done/report.md"
		r.data = "threads/" + th.ID + "/outputs/j_done/tables/data.csv"
		for p, body := range map[string]string{r.report: "Q3 report", r.data: "a,b\n1,2\n"} {
			if err := t.Write(prefixRoot+p, []byte(body)); err != nil {
				return err
			}
		}
		th.Participants = []string{"dana@example.com"}
		th.Jobs = []threadJob{{ID: "j_done", State: JobFinished, Rev: 1}}
		if _, err := th.push(1, now, threadEntry{Kind: entryTurn, JobID: "j_done", State: turnDone, Text: "Done.", Outputs: []string{r.report, r.data}}); err != nil {
			return err
		}
		th.finish(1, now)
		return saveThread(t, th)
	})
	if err != nil {
		t.Fatal(err)
	}
	code, view := do(t, r.reviewer, "GET", r.base(), "")
	if code != 200 {
		t.Fatalf("the thread: %d %v", code, view)
	}
	for _, e := range view["entries"].([]any) {
		if e := e.(map[string]any); e["kind"] == "draft" {
			r.draftID = e["id"].(string)
		}
	}
	if r.draftID == "" {
		t.Fatalf("no draft: %v", view)
	}
	return r
}

func (r *draftFileRig) base() string { return "/v1/workers/" + r.f.w1.ID + "/threads/" + r.threadID }

func (r *draftFileRig) draft(t *testing.T) *draftEntry {
	t.Helper()
	th, err := r.f.c.thread(anyDevice, r.f.w1.ID, r.threadID)
	if err != nil {
		t.Fatal(err)
	}
	return th.entry(r.draftID).Draft
}

func (r *draftFileRig) save(t *testing.T, srv *httptest.Server, file string, rev int, body string) map[string]any {
	t.Helper()
	code, out := do(t, srv, "PUT", r.base()+"/drafts/"+r.draftID+"/files/"+file+"?rev="+strconv.Itoa(rev), body)
	if code != 200 {
		t.Fatalf("save %s: %d %v", file, code, out)
	}
	return out
}

func (r *draftFileRig) op(t *testing.T, srv *httptest.Server, opID, kind string, args map[string]any) map[string]any {
	t.Helper()
	th, err := r.f.c.thread(anyDevice, r.f.w1.ID, r.threadID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"opId": opID, "threadId": r.threadID, "baseRevision": th.Revision, "kind": kind, "args": args})
	code, out := do(t, srv, "POST", r.base()+"/ops", string(raw))
	if code != 200 {
		t.Fatalf("%s: %d %v", kind, code, out)
	}
	return out
}

// approval is d's signed approval of the draft as it stands, by dev.
func (r *draftFileRig) approval(t *testing.T, d testDevice, rev int, hashes map[string]string) string {
	t.Helper()
	dr := r.draft(t)
	files := []ApprovedFile{}
	for _, p := range dr.Files {
		files = append(files, ApprovedFile{Path: p, SHA256: hashes[p]})
	}
	token, err := SignApproval(d.key, ApprovalClaims{Aud: testAudience, Worker: r.f.w1.ID, Thread: r.threadID, Draft: r.draftID, DraftRev: rev,
		To: dr.To, Subject: dr.Subject, Text: sha256Hex([]byte(dr.Text)), Files: files, Iat: time.Now().Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// The view names every file by its path, nested ones too, so each opens.
func TestADraftsFilesShowTheirPaths(t *testing.T) {
	r := newDraftFileRig(t, "")
	_, view := do(t, r.reviewer, "GET", r.base(), "")
	var turnFiles, draftFiles []any
	for _, e := range view["entries"].([]any) {
		switch e := e.(map[string]any); e["kind"] {
		case "agent-turn":
			turnFiles = e["files"].([]any)
		case "draft":
			draftFiles = e["files"].([]any)
		}
	}
	for _, files := range [][]any{turnFiles, draftFiles} {
		if len(files) != 2 || files[1].(map[string]any)["path"] != r.data || files[1].(map[string]any)["name"] != "data.csv" {
			t.Fatalf("files %v", files)
		}
	}
}

// A save is the next draft_rev, with new bytes at a new path; the old version
// stays, an approval of the old draft_rev is refused, and a signed approval
// must name the new file's hash.
func TestASaveMakesTheNextDraftRev(t *testing.T) {
	r := newDraftFileRig(t, "")
	before := r.draft(t)
	oldHash := before.Hash
	if out := r.op(t, r.reviewer, "op_edit", "claimDraft", map[string]any{"draftId": r.draftID, "editing": r.report}); out["ok"] != true {
		t.Fatalf("claim: %v", out)
	}
	out := r.save(t, r.reviewer, r.report, 1, "Q3 report, edited")
	next := "threads/" + r.threadID + "/drafts/" + r.draftID + "/2/report.md"
	detail, _ := out["detail"].(map[string]any)
	if out["ok"] != true || detail["draftRev"] != "2" || detail["path"] != next {
		t.Fatalf("the save: %v", out)
	}
	d := r.draft(t)
	if d.DraftRev != 2 || d.Files[0] != next || d.Files[1] != r.data || d.Hash == oldHash || d.FileHashes[next] != sha256Hex([]byte("Q3 report, edited")) {
		t.Fatalf("the draft after the save: %+v", d)
	}
	if len(d.Edits) != 1 || d.Edits[0].By != "maria@example.com" || d.Edits[0].From != r.report || d.Edits[0].Member != "m_reviewer" {
		t.Fatalf("the edit record: %+v", d.Edits)
	}
	if d.Claim == nil || d.Claim.Editing != "" {
		t.Fatalf("the save didn't clear the editing mark: %+v", d.Claim)
	}
	for p, want := range map[string]string{r.report: "Q3 report", next: "Q3 report, edited"} {
		if data, err := r.f.c.ReadFile(r.f.w1.ID, prefixRoot+p); err != nil || string(data) != want {
			t.Fatalf("%s: %q %v", p, data, err)
		}
	}
	if code, _ := do(t, r.reviewer, "GET", "/v1/workers/"+r.f.w1.ID+"/files/root/"+next, ""); code != 200 {
		t.Fatalf("the new version doesn't open: %d", code)
	}
	// A retry of the same save answers as the first did.
	if again := r.save(t, r.reviewer, r.report, 1, "Q3 report, edited"); again["ok"] != true || r.draft(t).DraftRev != 2 {
		t.Fatalf("a retried save: %v", again)
	}
	// Someone who opened draft_rev 1 can't overwrite it.
	stale := r.save(t, r.admin, r.report, 1, "Other edit")
	if stale["code"] != string(CodeDraftChanged) || stale["detail"].(map[string]any)["draftRev"] != "2" {
		t.Fatalf("a stale save: %v", stale)
	}
	if missing := r.save(t, r.admin, r.report, 2, "x"); missing["code"] != string(CodeAttachmentMissing) {
		t.Fatalf("a file no longer on the draft: %v", missing)
	}
	// Approving: draft_rev 1 is refused, a signature over the old hash too.
	hashes := map[string]string{next: before.FileHashes[r.report], r.data: before.FileHashes[r.data]}
	if out := r.op(t, r.admin, "op_old", "approveDraft", map[string]any{"draftId": r.draftID, "draftRev": 1, "approval": r.approval(t, r.f.admin, 1, hashes)}); out["code"] != string(CodeDraftChanged) {
		t.Fatalf("approving draft_rev 1: %v", out)
	}
	if out := r.op(t, r.admin, "op_oldhash", "approveDraft", map[string]any{"draftId": r.draftID, "draftRev": 2, "approval": r.approval(t, r.f.admin, 2, hashes)}); out["code"] != string(CodeApprovalUnsigned) {
		t.Fatalf("a signature over the old file: %v", out)
	}
	if out := r.op(t, r.admin, "op_ok", "approveDraft", map[string]any{"draftId": r.draftID, "draftRev": 2, "approval": r.approval(t, r.f.admin, 2, d.FileHashes)}); out["ok"] != true {
		t.Fatalf("approving the saved draft: %v", out)
	}
	if sent := r.save(t, r.reviewer, next, 2, "late"); sent["code"] != string(CodeAlreadySent) {
		t.Fatalf("a save after the send: %v", sent)
	}
}

// A save too large to send is refused and changes nothing.
func TestARefusedSaveChangesNothing(t *testing.T) {
	r := newDraftFileRig(t, "")
	before := r.draft(t)
	out := r.save(t, r.reviewer, r.report, 1, strings.Repeat("x", maxAttachmentBytes+1))
	if out["code"] != string(CodeAttachmentsTooLarge) {
		t.Fatalf("a save too large: %v", out)
	}
	d := r.draft(t)
	if d.DraftRev != 1 || d.Hash != before.Hash || d.Files[0] != r.report || len(d.Edits) != 0 {
		t.Fatalf("the refused save changed the draft: %+v", d)
	}
	if rec, err := r.f.c.ReadFile(r.f.w1.ID, sendPath(d.SendID)); err != nil || !strings.Contains(string(rec), `"state":"draft"`) {
		t.Fatalf("the draft's bytes were dropped: %s %v", rec, err)
	}
	if paths, _ := r.f.c.ListFiles(r.f.w1.ID, prefixRoot+"threads/"+r.threadID+"/drafts/"); len(paths) != 0 {
		t.Fatalf("the refused save left files: %v", paths)
	}
}

// While a reviewer has unsaved edits, another's approval asks first, and a
// claim doesn't take the mark over.
func TestAnEditingMarkHoldsOffOtherApprovals(t *testing.T) {
	r := newDraftFileRig(t, "")
	if out := r.op(t, r.reviewer, "op_edit", "claimDraft", map[string]any{"draftId": r.draftID, "editing": r.data}); out["ok"] != true {
		t.Fatalf("claim: %v", out)
	}
	_, view := do(t, r.admin, "GET", r.base(), "")
	for _, e := range view["entries"].([]any) {
		if e := e.(map[string]any); e["kind"] == "draft" && e["claim"].(map[string]any)["editing"] != r.data {
			t.Fatalf("the view's claim: %v", e["claim"])
		}
	}
	if out := r.op(t, r.admin, "op_claim", "claimDraft", map[string]any{"draftId": r.draftID}); out["code"] != string(CodeDraftBeingEdited) {
		t.Fatalf("a claim over an editor's mark: %v", out)
	}
	if out := r.op(t, r.admin, "op_nope", "claimDraft", map[string]any{"draftId": r.draftID, "editing": "threads/x/other.md"}); out["code"] != string(CodeDraftBeingEdited) {
		t.Fatalf("a second editor: %v", out)
	}
	hashes := r.draft(t).FileHashes
	out := r.op(t, r.admin, "op_a1", "approveDraft", map[string]any{"draftId": r.draftID, "draftRev": 1, "approval": r.approval(t, r.f.admin, 1, hashes)})
	if out["code"] != string(CodeDraftBeingEdited) || out["detail"].(map[string]any)["path"] != r.data {
		t.Fatalf("approving while someone edits: %v", out)
	}
	// The editor themself may approve; so may anyone who says so.
	out = r.op(t, r.admin, "op_a2", "approveDraft", map[string]any{"draftId": r.draftID, "draftRev": 1, "editingOk": true, "approval": r.approval(t, r.f.admin, 1, hashes)})
	if out["ok"] != true {
		t.Fatalf("approving anyway: %v", out)
	}
}

// Every reviewer the edge can mail hears of a draft, once, in their own mode:
// the approval email on Full, each with its own token.
func TestEveryReviewerIsNotifiedOfADraft(t *testing.T) {
	r := newDraftFileRig(t, modeFull)
	d := r.draft(t)
	if d.Ask == nil || d.Ask.To != "dana@example.com" || len(d.Asks) != 1 || d.Asks[0].To != "maria@example.com" {
		t.Fatalf("the asks: %+v %+v", d.Ask, d.Asks)
	}
	tokens := map[string]bool{}
	for _, a := range d.asks() {
		tokens[r.f.c.approvalToken(r.f.w1.ID, r.threadID, r.draftID, a)] = true
	}
	if len(tokens) != 2 {
		t.Fatal("two reviewers share a token")
	}
	var to []string
	_ = r.f.c.view(r.f.w1.ID, anyDevice, func(tr *Tree) error {
		for _, p := range tr.List(sendsDir) {
			if !strings.HasSuffix(p, ".json") {
				continue
			}
			var rec sendRecord
			if _, err := readJSON(tr, p, &rec); err == nil && rec.Kind == sendKindNotice {
				to = append(to, rec.To...)
			}
		}
		return nil
	})
	if len(to) != 2 || !strings.Contains(strings.Join(to, ","), "maria@example.com") || strings.Contains(strings.Join(to, ","), "dev@firm.example") {
		t.Fatalf("notices went to %v", to)
	}
	// A save makes a new draft_rev and no new notices: the approval emails of
	// the old one stop working.
	r.save(t, r.reviewer, r.report, 1, "edited")
	if d := r.draft(t); d.Ask != nil || len(d.Asks) != 0 {
		t.Fatalf("asks after a save: %+v %+v", d.Ask, d.Asks)
	}
}

// Under Notify, a reviewer's notice has no content.
func TestAReviewersNoticeUnderNotifyHasNoContent(t *testing.T) {
	r := newDraftFileRig(t, modeNotify)
	var bodies []string
	_ = r.f.c.view(r.f.w1.ID, anyDevice, func(tr *Tree) error {
		for _, p := range tr.List(sendsDir) {
			if strings.HasSuffix(p, ".eml") {
				data, _ := tr.Read(p)
				bodies = append(bodies, string(data))
			}
		}
		return nil
	})
	notices := 0
	for _, b := range bodies {
		if strings.Contains(b, "Subject: A draft reply is ready") {
			if !strings.Contains(b, "To: maria@example.com") && !strings.Contains(b, "To: dana@example.com") {
				t.Fatalf("a notice to someone else:\n%s", b)
			}
			notices++
			if strings.Contains(b, "Done.") || strings.Contains(b, "report.md") {
				t.Fatalf("a Notify notice has content:\n%s", b)
			}
		}
	}
	if notices != 2 {
		t.Fatalf("%d notices in %d emails", notices, len(bodies))
	}
}

// An approval by email waits while someone has unsaved edits in the app.
func TestAnEmailApprovalIsRefusedWhileSomeoneEdits(t *testing.T) {
	r := newSendRig(t, modeFull)
	r.intake.set(func(f *fakeIntake) { f.instruction, f.source, f.reply = "Yes.", "owner", true })
	th, e := r.drafted()
	r.pass()
	asks := r.send.sentTo("dana@example.com", "Approve: Re: Q3 close")
	if len(asks) != 1 {
		t.Fatalf("the approval email: %v", asks)
	}
	err := r.c.change(r.w.ID, anyDevice, func(tr *Tree) error {
		cur, err := loadThread(tr, th.ID)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		cur.entry(e.ID).Draft.Claim = &draftClaim{By: "Maria", Device: "d_maria", At: now, ExpiresAt: now.Add(10 * time.Minute), Editing: "threads/x/report.md"}
		return saveThread(tr, cur)
	})
	if err != nil {
		t.Fatal(err)
	}
	r.edge.deliver(r.mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Re: Approve: Re: Q3 close", inReplyTo: asks[0]})
	r.pass()
	if d := r.draft(th.ID, e.ID); d.State != draftPending {
		t.Fatalf("approved while someone edits: %s", d.State)
	}
	cur, _ := r.c.thread(anyDevice, r.w.ID, th.ID)
	found := false
	for _, en := range cur.Entries {
		if en.Kind == entryEvent && en.Code == "approval_refused" && strings.Contains(en.Args["reason"], "Maria is editing") {
			found = true
		}
	}
	if !found {
		t.Fatal("the thread doesn't say why")
	}
}
