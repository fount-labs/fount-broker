package coordinator

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"path"
	"slices"
	"strconv"
	"time"
)

// Editing a draft's attachments (launch-plan W, "Editing files"). A reviewer
// opens a draft's file on the desktop, edits it there, and saves it
// explicitly: the whole file, with the draft_rev it was opened at.
//
//	PUT /v1/workers/{id}/threads/{tid}/drafts/{draft}/files/{path...}?rev=N
//	body: the file's new bytes
//
// path is the file's path in the worker's tree as the draft names it (a
// draft view's files[].path). The save is applied under the tree's lock only if the
// draft is still pending at draft_rev N, else DRAFT_CHANGED with the current
// draftRev; nothing is overwritten and nobody merges. It writes the bytes to
// a new path, jobs/<job id>/drafts/<draft>/<N+1>/<name>, beside the job's
// outbox and out of every job's sight, so every version stays; moves the draft to draft_rev N+1 with new message bytes, so an
// approval of N, by app or email, is refused; and records who saved it. The
// answer is an OpResult whose detail names the new draftRev and path.
//
// A retry of a save that went through (the same file, draft_rev and bytes,
// from the same device) answers as the first did, so the route needs no opId.
//
// While a reviewer has unsaved edits, Desktop marks the draft with a claim
// naming the file (claimDraft{editing}, claim.go). Another reviewer's
// approval is then refused with DRAFT_BEING_EDITED unless they confirm
// (approveDraft{editingOk}), and an approval by email is refused, so nobody
// sends a draft someone is half-way through changing without knowing.

const (
	CodeDraftBeingEdited OpCode = "DRAFT_BEING_EDITED"

	saveDraftFileKind = "saveDraftFile"
)

func init() {
	maps.Copy(opMessages, map[OpCode]string{
		CodeDraftBeingEdited: "Someone is editing an attachment of this draft and hasn't saved it yet. Approve anyway to send it as it is now.",
	})
}

// draftEdit is one member's save of a draft's file: the draft_rev it made,
// the path it replaced and the new one, and who saved it.
type draftEdit struct {
	DraftRev int       `json:"draftRev"`
	From     string    `json:"from"`
	Path     string    `json:"path"`
	SHA256   string    `json:"sha256"`
	By       string    `json:"by"`
	Member   string    `json:"member,omitempty"`
	Device   string    `json:"device"`
	At       time.Time `json:"at"`
}

// editView is a save as the draft view shows it.
type editView struct {
	Path     string `json:"path"`
	Name     string `json:"name"`
	DraftRev int    `json:"draftRev"`
	By       string `json:"by"`
	Member   string `json:"member,omitempty"`
	At       string `json:"at"`
}

// draftFilePath is where a save's bytes go in the worker's tree.
func draftFilePath(jobID, draftID string, rev int, name string) string {
	return prefixJobs + jobID + "/drafts/" + draftID + "/" + strconv.Itoa(rev) + "/" + name
}

// errAbort undoes a save refused after the tree was written to: the change
// isn't committed and the refusal is the answer.
var errAbort = errors.New("aborted")

// SaveDraftFile saves new bytes for one of a pending draft's files, opened at
// draftRev, as device. A refusal is an OpResult.
func (c *Coordinator) SaveDraftFile(device, workerID, threadID, draftID, file string, draftRev int, data []byte) (OpResult, error) {
	if err := checkID("draft", draftID); err != nil {
		return OpResult{}, err
	}
	if err := checkPath(file); err != nil {
		return OpResult{}, err
	}
	if draftRev < 1 {
		return OpResult{}, fmt.Errorf("%w: rev is the draft_rev the file was opened at", ErrInvalid)
	}
	sum := sha256Hex(data)
	var result OpResult
	err := c.change(workerID, device, func(t *Tree) error {
		th, err := loadThread(t, threadID)
		if errors.Is(err, ErrNoThread) {
			result = refused(0, CodeNotFound)
			return errAbort
		}
		if err != nil {
			return err
		}
		if _, err := c.follow(t, th); err != nil {
			return err
		}
		now, rev := time.Now().UTC(), th.Revision+1
		e, err := pendingDraftEntry(th, draftID)
		if err == nil {
			if done := savedAlready(e.Draft, file, draftRev, sum, device); done != nil {
				result = OpResult{OK: true, Revision: th.Revision, EntryIDs: []string{e.ID}, Detail: saveDetail(done)}
				return errAbort
			}
			err = c.saveDraftFile(t, th, e, device, file, draftRev, data, sum, rev, now)
		}
		var r refusal
		if errors.As(err, &r) {
			result = refused(th.Revision, r.code)
			result.Detail = r.detail
			return errAbort
		}
		if err != nil {
			return err
		}
		th.finish(rev, now)
		result = OpResult{OK: true, Revision: rev, EntryIDs: []string{e.ID}, Detail: saveDetail(&e.Draft.Edits[len(e.Draft.Edits)-1])}
		if err := markReadAt(t, th.ID, device, rev, now); err != nil {
			return err
		}
		return saveThread(t, th)
	})
	if errors.Is(err, errAbort) {
		return result, nil
	}
	return result, err
}

func saveDetail(ed *draftEdit) map[string]string {
	return map[string]string{"draftRev": strconv.Itoa(ed.DraftRev), "path": ed.Path}
}

// savedAlready is the save a retry repeats: the draft's latest, of file at
// draftRev with the same bytes, by device.
func savedAlready(d *draftEntry, file string, draftRev int, sum, device string) *draftEdit {
	if len(d.Edits) == 0 {
		return nil
	}
	ed := &d.Edits[len(d.Edits)-1]
	if ed.DraftRev == draftRev+1 && ed.DraftRev == d.DraftRev && ed.From == file && ed.SHA256 == sum && ed.Device == device {
		return ed
	}
	return nil
}

// saveDraftFile writes a save into the tree and moves the draft to its next
// draft_rev, with new bytes. Any refusal comes back as one, for the caller to
// abort the change.
func (c *Coordinator) saveDraftFile(t *Tree, th *threadRecord, e *threadEntry, device, file string, draftRev int, data []byte, sum string, rev uint64, now time.Time) error {
	d := e.Draft
	if d.DraftRev != draftRev {
		return refusal{code: CodeDraftChanged, detail: map[string]string{"draftRev": strconv.Itoa(d.DraftRev)}}
	}
	i := slices.Index(d.Files, file)
	if i < 0 {
		return refusal{code: CodeAttachmentMissing, detail: map[string]string{"path": file}}
	}
	mb, err := loadMailbox(t)
	if errors.Is(err, ErrNoMailbox) {
		return refusal{code: CodeNoMailbox}
	}
	if err != nil {
		return err
	}
	rs, err := loadReplySettings(t)
	if err != nil {
		return err
	}
	if checkID("job", e.JobID) != nil {
		return refusal{code: CodeAttachmentMissing, detail: map[string]string{"path": file}}
	}
	next := draftFilePath(e.JobID, e.ID, d.DraftRev+1, path.Base(file))
	if err := t.Write(next, data); err != nil {
		return err
	}
	if err := c.dropDraftBytes(t, d.SendID, now); err != nil {
		return err
	}
	d.Files = slices.Clone(d.Files)
	d.Files[i] = next
	d.DraftRev++
	dropAsks(t, d)
	if err := c.buildDraft(t, th, mb, rs, e.ID, d, 1, now); err != nil {
		return err
	}
	ed := draftEdit{DraftRev: d.DraftRev, From: file, Path: next, SHA256: sum, By: c.approverName(th.WorkerID, device), Device: device, At: now}
	if m := c.memberOf(th.WorkerID, device); m != nil {
		ed.Member = m.ID
	}
	d.Edits = append(d.Edits, ed)
	if d.Claim != nil && d.Claim.Device == device {
		d.Claim.Editing = ""
	}
	e.Rev = rev
	return th.event(rev, now, "draft_file_saved", map[string]string{"draftId": e.ID, "path": next, "by": ed.By, "draftRev": strconv.Itoa(d.DraftRev)})
}

// saveDraftFile is the route: PUT …/threads/{tid}/drafts/{draft}/files/{path...}?rev=N.
func (a *api) saveDraftFile(rw http.ResponseWriter, r *http.Request) {
	if _, err := a.worker(r); err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	rev, err := strconv.Atoi(r.URL.Query().Get("rev"))
	if err != nil {
		fail(rw, http.StatusBadRequest, fmt.Errorf("%w: rev is the draft_rev the file was opened at", ErrInvalid))
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxFileBody+1))
	if err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	if len(data) > maxFileBody {
		fail(rw, http.StatusRequestEntityTooLarge, fmt.Errorf("files are at most %d bytes here", maxFileBody))
		return
	}
	result, err := a.c.SaveDraftFile(a.device(), r.PathValue("id"), r.PathValue("tid"), r.PathValue("draft"), r.PathValue("path"), rev, data)
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusOK, result)
}

// editingElsewhere is a claim in force by another device than device that
// says it is editing one of the draft's files.
func editingElsewhere(d *draftEntry, device string, now time.Time) *draftClaim {
	if cl := d.Claim; cl.active(now) && cl.Editing != "" && cl.Device != device {
		return cl
	}
	return nil
}

func beingEdited(cl *draftClaim) refusal {
	return refusal{code: CodeDraftBeingEdited, detail: map[string]string{
		"by": cl.By, "path": cl.Editing, "until": cl.ExpiresAt.UTC().Format(time.RFC3339),
	}}
}
