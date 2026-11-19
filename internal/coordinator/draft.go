package coordinator

import (
	"cmp"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"
)

// Drafts (launch-plan D). A job's final answer on a mail thread becomes a
// draft reply, by Desktop's rules (thread/home.rs draft_created): to the
// thread's participants who are still requesters, the turn's text, once per
// job; no recipient or no text is no draft. Its exact bytes are built then
// (decision 14) and kept in the send journal as a "draft" record, under a
// Message-ID derived from the draft id, its draft_rev and the attempt, with the
// footer (decision 13). Approving sends exactly those bytes.
//
// Reply modes (decision 7) are the worker's: Notify, Full, or Full for the
// owner and Notify for everyone else. A participant's mode is the worker's
// for them, a thread's the lowest of its participants', and setThreadReplyMode
// lowers one thread. Notices (decision 8) follow the mode: under Notify the
// owner hears what's waiting without content; when the owner is on Full they
// get the draft itself, which they can approve by replying (sendapproval.go).

const (
	entryDraft = "draft"

	draftPending   = "pending"
	draftSent      = "sent"
	draftDiscarded = "discarded"

	draftContentResult = "result"

	modeOff       = "off"
	modeNotify    = "notify"
	modeFull      = "full"
	modeFullOwner = "full_owner"

	replySettingsPath = prefixMailRecord + "reply.json"
)

// draftEntry is a draft reply on its thread entry, kind "draft".
type draftEntry struct {
	Content string `json:"content"`
	// QuestionID is the question a "question" draft forwards.
	QuestionID string   `json:"questionId,omitempty"`
	DraftRev   int      `json:"draftRev"`
	State      string   `json:"state"`
	To         []string `json:"to"`
	Subject    string   `json:"subject"`
	// AgentText is what the job wrote; Text is what the bytes carry, the
	// approver's edit if they made one.
	AgentText string `json:"agentText"`
	Text      string `json:"text"`
	// Files are the files the email carries, by path in the worker root,
	// and FileHashes each one's SHA-256, hex, which a signed approval names.
	Files      []string          `json:"files,omitempty"`
	FileHashes map[string]string `json:"fileHashes,omitempty"`
	InReplyTo  string            `json:"inReplyTo,omitempty"`
	References []string          `json:"references,omitempty"`
	// SendID is the journal record of the current bytes; MessageID and Hash
	// are its. Binding is the hash an email approval is bound to: the
	// recipients, the files and the bytes.
	SendID    string `json:"sendId"`
	MessageID string `json:"messageId"`
	Hash      string `json:"hash"`
	Binding   string `json:"binding"`
	// Approval is who approved it; Discarded who discarded it.
	Approval  *approval  `json:"approval,omitempty"`
	Discarded *decidedBy `json:"discarded,omitempty"`
	// Ask is the approval email the owner was sent for this draft_rev.
	Ask *approvalAsk `json:"ask,omitempty"`
	// Claim is who said they're reviewing it, until when (claim.go).
	Claim *draftClaim `json:"claim,omitempty"`
	// Send mirrors the journal record once it is sending.
	Send *sendView `json:"send,omitempty"`
}

type decidedBy struct {
	By  string    `json:"by"`
	At  time.Time `json:"at"`
	Via string    `json:"via"`
}

// replySettings are the worker's reply mode (decision 7), the owner's
// address, which notices go to and approval emails come from, and the firm's
// name for the footer. Revision is setDefaultMode's base.
type replySettings struct {
	Mode     string `json:"mode"`
	Owner    string `json:"owner,omitempty"`
	Firm     string `json:"firm,omitempty"`
	Revision uint64 `json:"revision"`
}

func loadReplySettings(t *Tree) (*replySettings, error) {
	rs := &replySettings{}
	_, err := readJSON(t, replySettingsPath, rs)
	return rs, err
}

// modeOf is address's reply mode. A worker whose mode was never chosen is on
// Notify: nothing leaves with content until someone chooses.
func (rs *replySettings) modeOf(address string) string {
	switch rs.Mode {
	case modeFull:
		return modeFull
	case modeFullOwner:
		if rs.Owner != "" && strings.EqualFold(address, rs.Owner) {
			return modeFull
		}
	}
	return modeNotify
}

func (rs *replySettings) firm(mb *Mailbox) string {
	return cmp.Or(rs.Firm, mb.Address)
}

func modeRank(mode string) int {
	switch mode {
	case modeNotify:
		return 1
	case modeFull:
		return 2
	}
	return 0
}

func lowerMode(a, b string) string {
	if modeRank(a) <= modeRank(b) {
		return a
	}
	return b
}

// derivedMode is the lowest participant's mode, off with none.
func (rs *replySettings) derivedMode(th *threadRecord) string {
	if len(th.Participants) == 0 {
		return modeOff
	}
	mode := modeFull
	for _, p := range th.Participants {
		mode = lowerMode(mode, rs.modeOf(p))
	}
	return mode
}

// modeInForce is the derived mode, lowered by setThreadReplyMode.
func (rs *replySettings) modeInForce(th *threadRecord) string {
	mode := rs.derivedMode(th)
	if th.ModeSet != "" {
		mode = lowerMode(mode, th.ModeSet)
	}
	return mode
}

func (th *threadRecord) pendingDraft() bool {
	return slices.ContainsFunc(th.Entries, func(e threadEntry) bool {
		return e.Kind == entryDraft && e.Draft.State == draftPending
	})
}

// draftFor is the draft a job's turn made, or nil.
func (th *threadRecord) draftFor(jobID string) *threadEntry {
	for i := range th.Entries {
		if e := &th.Entries[i]; e.Kind == entryDraft && e.JobID == jobID {
			return e
		}
	}
	return nil
}

// newestMail is the newest received email on th from one of its
// participants, which a reply answers.
func (th *threadRecord) newestMail() *mailEntry {
	for _, e := range slices.Backward(th.Entries) {
		if e.Kind == entryMail && th.hasParticipant(e.Mail.Sender) {
			return e.Mail
		}
	}
	return nil
}

// afterFollow is what the coordinator does once a thread is up to its jobs:
// keep its reply mode, make a draft of each turn that ended with an answer,
// and tell the owner of a failed job. It changes th at one new revision, or
// not at all.
func (c *Coordinator) afterFollow(t *Tree, th *threadRecord, now time.Time) (bool, error) {
	if len(th.Participants) == 0 && !slices.ContainsFunc(th.Jobs, func(j threadJob) bool { return j.State == JobFailed }) {
		return false, nil
	}
	mb, err := loadMailbox(t)
	if errors.Is(err, ErrNoMailbox) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	rs, err := loadReplySettings(t)
	if err != nil {
		return false, err
	}
	s, err := loadMailSettings(t)
	if err != nil {
		return false, err
	}
	rev, changed := th.Revision+1, false
	if mode := rs.modeInForce(th); mode != cmp.Or(th.ReplyMode, modeOff) {
		if th.ReplyMode != "" && modeRank(mode) < modeRank(th.ReplyMode) {
			if err := th.event(rev, now, "mode_dropped", map[string]string{"from": th.ReplyMode, "to": mode}); err != nil {
				return false, err
			}
		}
		th.ReplyMode, changed = mode, true
	}
	for i := 0; i < len(th.Entries); i++ {
		e := th.Entries[i]
		if e.Kind != entryTurn || e.State != turnDone || strings.TrimSpace(e.Text) == "" || th.draftFor(e.JobID) != nil || th.asked(e.JobID) {
			continue
		}
		made, err := c.makeDraft(t, th, mb, rs, s, e, rev, now)
		if err != nil {
			return false, err
		}
		changed = changed || made
	}
	for _, j := range th.Jobs {
		if j.State == JobFailed {
			if err := c.problemNotice(t, th.WorkerID, th.ID, noticeJobFailed, j.ID, now); err != nil {
				return false, err
			}
		}
	}
	if changed {
		th.finish(rev, now)
	}
	return changed, nil
}

func isRefusal(err error) bool {
	var r refusal
	return errors.As(err, &r)
}

// asked says a job's turn ended on a question, which isn't a reply, or that
// its answer couldn't be made a draft.
func (th *threadRecord) asked(jobID string) bool {
	return slices.ContainsFunc(th.Entries, func(e threadEntry) bool {
		return (e.Kind == entryQuestion && e.JobID == jobID) || (e.Kind == entryEvent && e.Code == "draft_failed" && e.Args["jobId"] == jobID)
	})
}

// makeDraft makes the draft of a turn's answer, and its notice.
func (c *Coordinator) makeDraft(t *Tree, th *threadRecord, mb *Mailbox, rs *replySettings, s *MailSettings, turn threadEntry, rev uint64, now time.Time) (bool, error) {
	var to []string
	for _, p := range th.Participants {
		if s.requester(p) != nil {
			to = append(to, strings.ToLower(p))
		}
	}
	if len(to) == 0 {
		return false, nil
	}
	d := &draftEntry{
		Content: draftContentResult, DraftRev: 1, State: draftPending, To: to, Subject: replySubject(th.Subject),
		AgentText: strings.TrimSpace(turn.Text), Text: strings.TrimSpace(turn.Text),
	}
	if m := th.newestMail(); m != nil {
		d.Subject = replySubject(cmp.Or(m.Subject, th.Subject))
		d.InReplyTo, d.References = m.MessageID, m.references()
	}
	for _, p := range turn.Outputs {
		d.Files = append(d.Files, p)
	}
	id, err := th.push(rev, now, threadEntry{Kind: entryDraft, JobID: turn.JobID, Draft: d})
	if err != nil {
		return false, err
	}
	err = c.buildDraft(t, th, mb, rs, id, d, 1, now)
	if isRefusal(err) && len(d.Files) > 0 {
		// Files that can't go with it stay in the thread, unattached.
		d.Files = nil
		err = c.buildDraft(t, th, mb, rs, id, d, 1, now)
	}
	if isRefusal(err) || errors.Is(err, ErrInvalid) {
		// No email can be made of it: the turn's answer stays on the
		// thread, and the thread says why there's no draft.
		th.Entries, th.Seq = th.Entries[:len(th.Entries)-1], th.Seq-1
		return true, th.event(rev, now, "draft_failed", map[string]string{"jobId": turn.JobID})
	}
	if err != nil {
		return false, err
	}
	if th.ReplyMode == modeOff {
		return true, nil
	}
	return true, c.draftNotice(t, th, mb, rs, id, d, now)
}

// buildDraft builds d's bytes at its draft_rev and attempt, and stages the
// journal record for them, "draft" until approved.
func (c *Coordinator) buildDraft(t *Tree, th *threadRecord, mb *Mailbox, rs *replySettings, draftID string, d *draftEntry, attempt int, now time.Time) error {
	var files []outFile
	var names []string
	for _, p := range d.Files {
		data, err := t.Read(prefixRoot + p)
		if errors.Is(err, ErrNotFound) {
			return refusal{code: CodeAttachmentMissing, detail: map[string]string{"path": p}}
		}
		if err != nil {
			return err
		}
		files = append(files, outFile{Name: path.Base(p), Data: data})
		names = append(names, path.Base(p))
	}
	d.FileHashes = nil
	if len(files) > 0 {
		d.FileHashes = map[string]string{}
		for i, p := range d.Files {
			d.FileHashes[p] = sha256Hex(files[i].Data)
		}
	}
	parts := []string{sendKindReply, draftID, fmt.Sprint(d.DraftRev), fmt.Sprint(attempt)}
	r := &sendRecord{
		ID: c.sendID(th.WorkerID, parts...), Kind: sendKindReply, ThreadID: th.ID, DraftID: draftID,
		DraftRev: d.DraftRev, Attempt: attempt, State: sendDraft, To: d.To,
	}
	text := renderBody(d.Text, names, footer(rs.firm(mb), true))
	raw, err := c.buildOut(t, th, mb, r, parts, d.Subject, d.InReplyTo, d.References, text, files, now)
	if err != nil {
		return err
	}
	if _, err := c.stageSend(t, th.WorkerID, r, raw); err != nil {
		return err
	}
	d.To, d.SendID, d.MessageID, d.Hash = r.To, r.ID, r.MessageID, r.Hash
	d.Binding = binding(r.To, d.Files, files, r.Hash)
	return nil
}

// binding is the hash an email approval is bound to (m4 §3.3): the
// recipients, each file by name and content, and the bytes.
func binding(to, paths []string, files []outFile, hash string) string {
	var b strings.Builder
	for _, a := range slices.Sorted(slices.Values(to)) {
		b.WriteString("to " + a + "\n")
	}
	for i, f := range files {
		b.WriteString("file " + paths[i] + " " + sha256Hex(f.Data) + "\n")
	}
	b.WriteString("bytes " + hash + "\n")
	return sha256Hex([]byte(b.String()))
}

// The notices (decisions 8 and 10). Each is a journal record sent at once to
// the owner, without content except the approval email to an owner on Full,
// with an id from what it is about, so each goes once.
const (
	noticeDraft     = "draft_ready"
	noticeJobFailed = "job_failed"
	noticeHeld      = "mail_held"
	noticeBounced   = "send_failed"
)

var noticeText = map[string][2]string{
	noticeDraft:     {"A draft reply is ready in %s", "A draft reply is waiting for review in %s. Nothing is sent until someone approves it in Fount."},
	noticeJobFailed: {"A job failed in %s", "A job failed in %s. Nothing was sent."},
	noticeHeld:      {"An email is waiting in %s", "An email to %s is held until someone decides what to do with it."},
	noticeBounced:   {"An email from %s wasn't delivered", "An email from %s didn't reach everyone it was for."},
}

// problemNotice tells the owner about kind on a thread, once per ref.
func (c *Coordinator) problemNotice(t *Tree, workerID, threadID, kind, ref string, now time.Time) error {
	id := c.sendID(workerID, sendKindNotice, kind, ref)
	if t.Has(sendPath(id)) {
		return nil
	}
	rs, err := loadReplySettings(t)
	if err != nil || rs.Owner == "" {
		return err
	}
	mb, err := loadMailbox(t)
	if errors.Is(err, ErrNoMailbox) {
		return nil
	}
	if err != nil {
		return err
	}
	th, err := loadThread(t, threadID)
	if errors.Is(err, ErrNoThread) {
		return nil
	}
	if err != nil {
		return err
	}
	return c.sendNotice(t, th, mb, rs, id, []string{sendKindNotice, kind, ref}, kind, now)
}

func (c *Coordinator) sendNotice(t *Tree, th *threadRecord, mb *Mailbox, rs *replySettings, id string, parts []string, kind string, now time.Time) error {
	words, firm := noticeText[kind], rs.firm(mb)
	text := fmt.Sprintf(words[1], firm) + "\n\nOpen it in Fount: " + fountLink(th.WorkerID, th.ID) + "\n\n" + footer(firm, false) + "\n"
	r := &sendRecord{ID: id, Kind: sendKindNotice, ThreadID: th.ID, Attempt: 1, State: sendSending, To: []string{rs.Owner}}
	raw, err := c.buildOut(t, th, mb, r, parts, fmt.Sprintf(words[0], firm), "", nil, text, nil, now)
	if err != nil {
		return err
	}
	_, err = c.stageSend(t, th.WorkerID, r, raw)
	return err
}

// draftNotice tells the owner a draft is waiting: the approval email when
// they are on Full, otherwise a notice without content.
func (c *Coordinator) draftNotice(t *Tree, th *threadRecord, mb *Mailbox, rs *replySettings, draftID string, d *draftEntry, now time.Time) error {
	if rs.Owner == "" {
		return nil
	}
	parts := []string{sendKindNotice, noticeDraft, draftID, fmt.Sprint(d.DraftRev)}
	id := c.sendID(th.WorkerID, parts...)
	if t.Has(sendPath(id)) {
		return nil
	}
	if rs.modeOf(rs.Owner) != modeFull {
		return c.sendNotice(t, th, mb, rs, id, parts, noticeDraft, now)
	}
	return c.askApproval(t, th, mb, rs, id, draftID, d, now)
}

// The display form: Desktop's Draft, Approval and MailOut entries (view.rs).
// A decided draft shows as the draft, then its approval and the email, which
// share its seq and come after it.

type draftView struct {
	entryHead
	Content  string           `json:"content"`
	State    string           `json:"state"`
	DraftRev int              `json:"draftRev"`
	To       []string         `json:"to"`
	Subject  string           `json:"subject"`
	Text     string           `json:"text"`
	Files    []attachmentView `json:"files,omitempty"`
	JobID    string           `json:"jobId,omitempty"`
	// QuestionID is the question a forwarded question's draft asks.
	QuestionID string `json:"questionId,omitempty"`
	// Hash is the SHA-256 of the bytes approving sends, which approveDraft
	// may name; MessageID is theirs.
	Hash      string `json:"hash"`
	MessageID string `json:"messageId"`
}

type approvalView struct {
	entryHead
	By      string `json:"by"`
	Via     string `json:"via"`
	DraftID string `json:"draftId"`
	Outcome string `json:"outcome"`
}

type mailOutView struct {
	entryHead
	To     []string         `json:"to"`
	Text   string           `json:"text"`
	Files  []attachmentView `json:"files,omitempty"`
	SentID string           `json:"sentId,omitempty"`
	Send   *sendView        `json:"send,omitempty"`
}

func draftViews(head entryHead, e threadEntry) []DisplayEntry {
	d := e.Draft
	head.Kind = "draft"
	v := draftView{
		entryHead: head, Content: d.Content, State: d.State, DraftRev: d.DraftRev, To: d.To, Subject: d.Subject,
		Text: d.Text, JobID: e.JobID, QuestionID: d.QuestionID, Hash: d.Hash, MessageID: d.MessageID,
	}
	var files []attachmentView
	for _, p := range d.Files {
		files = append(files, attachmentView{Name: path.Base(p)})
	}
	v.Files = files
	out := []DisplayEntry{v}
	switch {
	case d.Approval != nil:
		a := head
		a.ID, a.Kind = e.ID+"-approval", "approval"
		out = append(out, approvalView{entryHead: a, By: d.Approval.By, Via: d.Approval.Via, DraftID: e.ID, Outcome: "sent"})
		m := head
		m.ID, m.Kind = e.ID+"-sent", "mail-out"
		out = append(out, mailOutView{entryHead: m, To: d.To, Text: d.Text, Files: files, SentID: d.SendID, Send: d.Send})
	case d.Discarded != nil:
		a := head
		a.ID, a.Kind = e.ID+"-approval", "approval"
		out = append(out, approvalView{entryHead: a, By: d.Discarded.By, Via: d.Discarded.Via, DraftID: e.ID, Outcome: "discarded"})
	}
	return out
}
