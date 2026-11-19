package coordinator

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
)

// The draft and sending operations (thread-operations.md §5, §4.3), and the
// worker's reply mode. Roles are opRoles' (members.go): approveDraft,
// discardDraft and sendAgain are a reviewer's; setThreadReplyMode and
// setDefaultMode an admin's.
//
//	approveDraft        {draftId, draftRev, text?, attachments?, changes?, hash?, editingOk?}
//	discardDraft        {draftId}
//	sendAgain           {sentId, duplicateOk?}
//	setThreadReplyMode  {mode}
//	setDefaultMode      {mode, owner?, firm?, baseRevision}   a worker operation
//
// approveDraft names the draft_rev it approves (decision 5): a stale one is
// DRAFT_CHANGED. With text or attachments that differ from the draft's, the
// draft moves to the next draft_rev with new bytes, and those are what is
// approved; hash, when given, must be the bytes' the client showed.

const (
	CodeDraftChanged        OpCode = "DRAFT_CHANGED"
	CodeNewMailSince        OpCode = "NEW_MAIL_SINCE"
	CodeParticipantsChanged OpCode = "PARTICIPANTS_CHANGED"
	CodeAlreadySent         OpCode = "ALREADY_SENT"
	CodeAlreadyDiscarded    OpCode = "ALREADY_DISCARDED"
	CodeModeAbove           OpCode = "MODE_ABOVE_PARTICIPANTS"
	CodeMaybeSent           OpCode = "MAYBE_SENT"
	CodeSending             OpCode = "SENDING"
	CodeSendFailed          OpCode = "SEND_FAILED"
	CodeSendLimit           OpCode = "SEND_LIMIT"
	CodeInviteLimit         OpCode = "INVITE_LIMIT"
	CodeBadMessage          OpCode = "BAD_MESSAGE"
	CodeMailLapsed          OpCode = "MAIL_LAPSED"
	CodeSendingOff          OpCode = "SENDING_OFF"
	CodeWorkerPaused        OpCode = "WORKER_PAUSED"
	CodeAttachmentsTooLarge OpCode = "ATTACHMENTS_TOO_LARGE"
	CodeAttachmentMissing   OpCode = "ATTACHMENT_MISSING"
	CodeApprovalUnsigned    OpCode = "APPROVAL_UNSIGNED"
)

func init() {
	maps.Copy(opMessages, map[OpCode]string{
		CodeDraftChanged:        "The agent updated this draft. Check the new version.",
		CodeNewMailSince:        "A new email arrived on this thread. Read it, then send again.",
		CodeParticipantsChanged: "Who's on this thread changed. Check the recipients and send again.",
		CodeAlreadySent:         "This was already sent.",
		CodeAlreadyDiscarded:    "This draft was already discarded.",
		CodeModeAbove:           "A thread can't be on a higher reply mode than the people on it.",
		CodeMaybeSent:           "Fount lost Fount Mail's answer, so this may have been sent. Check with the recipients before sending again.",
		CodeSending:             "This email is still being sent.",
		CodeSendFailed:          "Fount Mail didn't send this email.",
		CodeSendLimit:           "This worker has reached its sending limit for today. It can send again tomorrow.",
		CodeInviteLimit:         "This worker has sent its most invites for today. Copy the invite link and send it yourself, or email it again tomorrow.",
		CodeBadMessage:          "Fount couldn't build this email. Nothing was sent.",
		CodeMailLapsed:          "This worker's Fount Mail has lapsed. Renew it, then send again.",
		CodeSendingOff:          "Fount Mail isn't sending email yet. Nothing was sent.",
		CodeWorkerPaused:        "This worker is paused. Resume it first.",
		CodeAttachmentsTooLarge: "The attached files are too large for one email. Untick some and send again.",
		CodeAttachmentMissing:   "An attached file is gone from the workspace. Untick it and send again.",
		CodeApprovalUnsigned:    "Fount couldn't check this device's signature on the approval. Nothing was sent. Open the draft again and approve it.",
	})
}

// maybeDuplicate is what a maybe_sent email's sendAgain says until the user
// accepts it (Desktop's MAYBE_DUPLICATE).
const maybeDuplicate = "This email may already have arrived. Sending it again could deliver it twice, so check with the recipients first."

type approveArgs struct {
	DraftID     string    `json:"draftId"`
	DraftRev    int       `json:"draftRev"`
	Text        *string   `json:"text,omitempty"`
	Changes     *[]string `json:"changes,omitempty"`
	Attachments *[]string `json:"attachments,omitempty"`
	Hash        string    `json:"hash,omitempty"`
	// Approval is the approving device's signed approval (approvalsig.go),
	// which a device's approval must carry.
	Approval string `json:"approval,omitempty"`
	// EditingOK is the approver's choice to approve while another reviewer
	// has unsaved edits to one of its files (DRAFT_BEING_EDITED).
	EditingOK bool `json:"editingOk,omitempty"`
	base      uint64
}

type discardArgs struct {
	DraftID string `json:"draftId"`
}

type sendAgainArgs struct {
	SentID      string `json:"sentId"`
	DuplicateOK bool   `json:"duplicateOk,omitempty"`
}

type threadModeArgs struct {
	Mode string `json:"mode"`
	base uint64
}

// draftOp is an operation of this file, applied to its thread at rev.
type draftOp interface {
	applyDraft(c *Coordinator, t *Tree, th *threadRecord, device string, rev uint64, now time.Time) ([]string, effects, error)
}

// parseDraftThreadOp decodes this file's thread operations, or reports the
// kind isn't one.
func parseDraftThreadOp(env opEnvelope) (any, bool, error) {
	switch env.Kind {
	case "approveDraft":
		var a approveArgs
		if err := decodeArgs(env.Args, &a); err != nil {
			return nil, true, err
		}
		a.base = env.BaseRevision
		if a.Attachments != nil {
			for _, p := range *a.Attachments {
				if err := checkPath(p); err != nil {
					return nil, true, err
				}
			}
		}
		return a, true, checkID("draft", a.DraftID)
	case "discardDraft":
		var a discardArgs
		if err := decodeArgs(env.Args, &a); err != nil {
			return nil, true, err
		}
		return a, true, checkID("draft", a.DraftID)
	case "sendAgain":
		var a sendAgainArgs
		if err := decodeArgs(env.Args, &a); err != nil {
			return nil, true, err
		}
		return a, true, checkID("sent", a.SentID)
	case "setThreadReplyMode":
		var a threadModeArgs
		if err := decodeArgs(env.Args, &a); err != nil {
			return nil, true, err
		}
		a.base = env.BaseRevision
		if a.Mode != modeOff && a.Mode != modeNotify && a.Mode != modeFull {
			return nil, true, fmt.Errorf("%w: mode is off, notify or full", ErrInvalid)
		}
		return a, true, nil
	}
	return parseClaimOp(env)
}

// pendingDraftEntry is the draft id names, if it is still pending.
func pendingDraftEntry(th *threadRecord, id string) (*threadEntry, error) {
	e := th.entry(id)
	if e == nil || e.Kind != entryDraft {
		return nil, refusal{code: CodeNotFound}
	}
	d := e.Draft
	switch d.State {
	case draftSent:
		return nil, refusal{code: CodeAlreadySent, detail: map[string]string{"by": d.Approval.By, "via": d.Approval.Via, "at": d.Approval.At.Format(time.RFC3339)}}
	case draftDiscarded:
		return nil, refusal{code: CodeAlreadyDiscarded, detail: map[string]string{"by": d.Discarded.By, "at": d.Discarded.At.Format(time.RFC3339)}}
	}
	return e, nil
}

// mailSince says an email joined or changed on th after base.
func (th *threadRecord) mailSince(base uint64) bool {
	return slices.ContainsFunc(th.Entries, func(e threadEntry) bool { return e.Kind == entryMail && e.Rev > base })
}

// peopleSince says th's participants or reply mode changed after base.
func (th *threadRecord) peopleSince(base uint64) bool {
	return slices.ContainsFunc(th.Entries, func(e threadEntry) bool {
		return e.Kind == entryEvent && e.Rev > base && (e.Code == "requester_added" || e.Code == "mode_dropped" || e.Code == "mode_changed")
	})
}

// approverName is who a device acts for: its member's email on a team
// worker, the device otherwise.
func (c *Coordinator) approverName(workerID, device string) string {
	if device == anyDevice {
		return "Fount Cloud"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if w, ok := c.state.Workers[workerID]; ok && w.Team != "" {
		if st, err := c.teamState(w.Team); err == nil {
			if _, m := st.device(device); m != nil && m.Email != "" {
				return m.Email
			}
		}
	}
	return device
}

func (a approveArgs) applyDraft(c *Coordinator, t *Tree, th *threadRecord, device string, rev uint64, now time.Time) ([]string, effects, error) {
	e, err := pendingDraftEntry(th, a.DraftID)
	if err != nil {
		return nil, effects{}, err
	}
	d := e.Draft
	switch {
	case d.DraftRev != a.DraftRev, a.Hash != "" && !strings.EqualFold(a.Hash, d.Hash):
		return nil, effects{}, refusal{code: CodeDraftChanged, detail: map[string]string{"draftRev": fmt.Sprint(d.DraftRev)}}
	case th.mailSince(a.base):
		return nil, effects{}, refusal{code: CodeNewMailSince, detail: map[string]string{"since": fmt.Sprint(a.base)}}
	case th.peopleSince(a.base):
		return nil, effects{}, refusal{code: CodeParticipantsChanged}
	}
	if cl := editingElsewhere(d, device, now); cl != nil && !a.EditingOK {
		return nil, effects{}, beingEdited(cl)
	}
	mb, err := loadMailbox(t)
	if errors.Is(err, ErrNoMailbox) {
		return nil, effects{}, refusal{code: CodeNoMailbox}
	}
	if err != nil {
		return nil, effects{}, err
	}
	s, err := loadMailSettings(t)
	if err != nil {
		return nil, effects{}, err
	}
	for _, to := range d.To {
		if s.requester(to) == nil {
			return nil, effects{}, refusal{code: CodeRecipientNotAllowed, detail: map[string]string{"address": to}}
		}
	}
	text, files := d.Text, d.Files
	if a.Text != nil {
		if text, err = noteText(*a.Text); err != nil {
			return nil, effects{}, err
		}
	}
	if a.Attachments != nil {
		files = *a.Attachments
		for _, p := range files {
			if !slices.Contains(d.Files, p) {
				return nil, effects{}, fmt.Errorf("%w: %s isn't one of the draft's files", ErrInvalid, p)
			}
		}
	}
	var member *Member
	var approved []ApprovedFile
	if device != anyDevice {
		if a.Approval == "" {
			return nil, effects{}, refusal{code: CodeApprovalUnsigned}
		}
		key, err := c.deviceKey(th.WorkerID, device)
		if err != nil {
			return nil, effects{}, err
		}
		hashes := d.FileHashes
		if hashes == nil {
			if hashes, err = fileHashes(t, files); err != nil {
				return nil, effects{}, err
			}
		}
		approved = []ApprovedFile{}
		for _, p := range files {
			approved = append(approved, ApprovedFile{Path: p, SHA256: hashes[p]})
		}
		want := approvedAs{worker: th.WorkerID, thread: th.ID, draft: e.ID, draftRev: a.DraftRev, to: d.To, subject: d.Subject, text: sha256Hex([]byte(text)), files: approved}
		if err := verifyApproval(a.Approval, key, device, c.cfg.Audience, want, now); err != nil {
			return nil, effects{}, refusal{code: CodeApprovalUnsigned, detail: map[string]string{"reason": err.Error()}}
		}
		member = c.memberOf(th.WorkerID, device)
	}
	if text != d.Text || !slices.Equal(files, d.Files) {
		// The approver's edit is the next draft_rev, with its own bytes.
		rs, err := loadReplySettings(t)
		if err != nil {
			return nil, effects{}, err
		}
		if err := c.dropDraftBytes(t, d.SendID, now); err != nil {
			return nil, effects{}, err
		}
		d.DraftRev++
		d.Text, d.Files, d.Ask, d.Asks = text, files, nil, nil
		if err := c.buildDraft(t, th, mb, rs, e.ID, d, 1, now); err != nil {
			return nil, effects{}, err
		}
	}
	// The rebuild read the files from the tree again: what it sends must be
	// what the device signed, or nothing is sent (the change is undone).
	if p := unsigned(d, approved); device != anyDevice && p != "" {
		return nil, effects{}, refusal{code: CodeDraftChanged, detail: map[string]string{"draftRev": fmt.Sprint(a.DraftRev), "path": p}}
	}
	ap := approval{By: c.approverName(th.WorkerID, device), Device: device, Via: viaApp, Token: a.Approval}
	if member != nil {
		ap.Member = member.ID
	}
	if err := c.approve(t, th, e, ap, rev, now); err != nil {
		return nil, effects{}, err
	}
	return []string{e.ID}, effects{mail: true}, nil
}

// dropDraftBytes discards a record that was never sent, and its bytes.
func (c *Coordinator) dropDraftBytes(t *Tree, id string, now time.Time) error {
	r, err := loadSend(t, id)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil || r.State != sendDraft {
		return err
	}
	r.State, r.Updated = sendDiscarded, now
	t.Remove(sendBytes(id))
	return c.saveSend(t, r)
}

func (a discardArgs) applyDraft(c *Coordinator, t *Tree, th *threadRecord, device string, rev uint64, now time.Time) ([]string, effects, error) {
	e, err := pendingDraftEntry(th, a.DraftID)
	if err != nil {
		return nil, effects{}, err
	}
	if err := c.dropDraftBytes(t, e.Draft.SendID, now); err != nil {
		return nil, effects{}, err
	}
	e.Draft.State, e.Rev = draftDiscarded, rev
	e.Draft.Discarded = &decidedBy{By: c.approverName(th.WorkerID, device), At: now, Via: viaApp}
	return []string{e.ID}, effects{}, nil
}

// sendAgain is §5.3 step 6 on the journal: a failed reply posts its bytes
// again under its Message-ID. A maybe_sent one never goes again under that
// ID, which the edge refuses for good: with duplicateOk, the user's explicit
// choice, the draft gets a new attempt with a new Message-ID.
func (a sendAgainArgs) applyDraft(c *Coordinator, t *Tree, th *threadRecord, device string, rev uint64, now time.Time) ([]string, effects, error) {
	r, err := loadSend(t, a.SentID)
	if errors.Is(err, ErrNotFound) {
		return nil, effects{}, refusal{code: CodeNotFound}
	}
	if err != nil {
		return nil, effects{}, err
	}
	e := th.entry(r.DraftID)
	if r.ThreadID != th.ID || r.Kind != sendKindReply || e == nil || e.Kind != entryDraft || e.Draft.SendID != r.ID {
		return nil, effects{}, refusal{code: CodeNotFound}
	}
	switch r.State {
	case sendFailed:
		if err := c.startSending(t, th.WorkerID, r, now); err != nil {
			return nil, effects{}, err
		}
	case sendMaybe:
		if !a.DuplicateOK {
			return nil, effects{}, refusal{code: CodeMaybeSent, detail: map[string]string{"message": maybeDuplicate}}
		}
		mb, err := loadMailbox(t)
		if err != nil {
			return nil, effects{}, err
		}
		rs, err := loadReplySettings(t)
		if err != nil {
			return nil, effects{}, err
		}
		d := e.Draft
		was := sealedFiles(d)
		if err := c.buildDraft(t, th, mb, rs, e.ID, d, r.Attempt+1, now); err != nil {
			return nil, effects{}, err
		}
		// A new attempt is new bytes under a new Message-ID. It goes only if
		// its text and every file are the ones approved; the approval stays
		// the approver's, and the resend is recorded as whoever asked.
		if p := unsigned(d, was); p != "" || sha256Hex([]byte(d.Text)) != r.Approval.SentTextHash {
			return nil, effects{}, refusal{code: CodeFilesChanged, detail: map[string]string{"path": p}}
		}
		next, err := loadSend(t, d.SendID)
		if err != nil {
			return nil, effects{}, err
		}
		ap := *r.Approval
		ap.Hash = next.Hash
		ap.Resent = &resend{By: c.approverName(th.WorkerID, device), Device: device, At: now, From: r.ID}
		next.Approval = &ap
		if err := c.startSending(t, th.WorkerID, next, now); err != nil {
			return nil, effects{}, err
		}
		if err := writeSignoff(t, th, e, next, ap); err != nil {
			return nil, effects{}, err
		}
		d.Approval, r = &ap, next
	case sendSending:
		return nil, effects{}, refusal{code: CodeSending}
	default:
		return nil, effects{}, refusal{code: CodeAlreadySent}
	}
	e.Draft.Send, e.Rev = r.view(), rev
	was := map[string]string{"sentId": a.SentID, "was": "failed"}
	if r.ID != a.SentID {
		was["was"], was["newSentId"] = "maybe_sent", r.ID
	}
	if err := th.event(rev, now, "send_again", was); err != nil {
		return nil, effects{}, err
	}
	return []string{e.ID}, effects{mail: true}, nil
}

// setThreadReplyMode is §5.10's lowering of one thread: below the mode its
// participants derive, or back to it, never above it.
func (a threadModeArgs) applyDraft(c *Coordinator, t *Tree, th *threadRecord, _ string, rev uint64, now time.Time) ([]string, effects, error) {
	if th.peopleSince(a.base) {
		return nil, effects{}, refusal{code: CodeParticipantsChanged}
	}
	rs, err := loadReplySettings(t)
	if err != nil {
		return nil, effects{}, err
	}
	derived := rs.derivedMode(th)
	if modeRank(a.Mode) > modeRank(derived) {
		return nil, effects{}, refusal{code: CodeModeAbove, detail: map[string]string{"mode": derived}}
	}
	from := cmp.Or(th.ReplyMode, modeOff)
	th.ModeSet = a.Mode
	if a.Mode == derived {
		th.ModeSet = ""
	}
	th.ReplyMode = rs.modeInForce(th)
	if th.ReplyMode != from {
		if err := th.event(rev, now, "mode_changed", map[string]string{"from": from, "to": th.ReplyMode}); err != nil {
			return nil, effects{}, err
		}
	}
	return nil, effects{}, nil
}

// The worker's reply mode: setDefaultMode.

type defaultModeArgs struct {
	Mode         string `json:"mode"`
	Owner        string `json:"owner,omitempty"`
	Firm         string `json:"firm,omitempty"`
	BaseRevision uint64 `json:"baseRevision"`
}

const maxFirmChars = 120

// applyDefaultMode is setDefaultMode: the mode chosen when the worker is made
// (decision 7), the owner whose address notices go to, and the firm the
// footer names. The owner must be a requester: the edge sends only to them.
func (c *Coordinator) applyDefaultMode(device, workerID string, env workerOpEnvelope) (OpResult, error) {
	if err := checkID("op", env.OpID); err != nil {
		return OpResult{}, err
	}
	var a defaultModeArgs
	if err := decodeArgs(env.Args, &a); err != nil {
		return OpResult{}, err
	}
	if a.Mode != modeNotify && a.Mode != modeFull && a.Mode != modeFullOwner {
		return OpResult{}, fmt.Errorf("%w: mode is notify, full or full_owner", ErrInvalid)
	}
	a.Firm = strings.Join(strings.Fields(a.Firm), " ")
	if len([]rune(a.Firm)) > maxFirmChars {
		return OpResult{}, fmt.Errorf("%w: firm is at most %d characters", ErrInvalid, maxFirmChars)
	}
	hash := argsHash("", env.Kind, a)
	var result OpResult
	err := c.change(workerID, device, func(t *Tree) error {
		ops, err := loadOpLog(t, workerOps)
		if err != nil {
			return err
		}
		if r, ok := retried(ops, env.OpID, hash, 0); ok {
			result = r
			return nil
		}
		rs, err := loadReplySettings(t)
		if err != nil {
			return err
		}
		if err := stale(a.BaseRevision, rs.Revision); err != nil {
			result = refused(rs.Revision, CodeWorkerChanged)
			result.Detail = err.(refusal).detail
			return nil
		}
		owner := ""
		if a.Owner != "" {
			s, err := loadMailSettings(t)
			if err != nil {
				return err
			}
			if owner, err = mailAddress(a.Owner); err != nil {
				return err
			}
			if s.requester(owner) == nil {
				result = refused(rs.Revision, CodeRecipientNotAllowed)
				result.Detail = map[string]string{"address": owner}
				return nil
			}
		}
		if a.Mode == modeFullOwner && owner == "" {
			return fmt.Errorf("%w: full_owner needs the owner's address", ErrInvalid)
		}
		rs.Mode, rs.Owner, rs.Firm = a.Mode, owner, a.Firm
		rs.Revision++
		result = OpResult{OK: true, Revision: rs.Revision}
		ops[env.OpID] = loggedOp{ArgsHash: hash, Revision: rs.Revision, Result: result, At: time.Now().UTC()}
		if err := writeJSON(t, replySettingsPath, rs); err != nil {
			return err
		}
		return saveOpLog(t, workerOps, ops)
	})
	return result, err
}

// sealedFiles is the files a draft's bytes were built from, with their hashes.
func sealedFiles(d *draftEntry) []ApprovedFile {
	files := make([]ApprovedFile, 0, len(d.Files))
	for _, p := range d.Files {
		files = append(files, ApprovedFile{Path: p, SHA256: d.FileHashes[p]})
	}
	return files
}

// unsigned is the first file the draft's bytes now hold that isn't as
// approved: a path or hash that differs, or a file added or dropped.
func unsigned(d *draftEntry, approved []ApprovedFile) string {
	for i, f := range approved {
		if i >= len(d.Files) || d.Files[i] != f.Path || !strings.EqualFold(d.FileHashes[f.Path], f.SHA256) {
			return f.Path
		}
	}
	if len(d.Files) > len(approved) {
		return d.Files[len(approved)]
	}
	return ""
}
