package coordinator

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"
)

// Operations are how a client changes a thread (thread-operations.md §4, §5):
// an envelope naming the operation, the thread revision the user saw and an
// opId the client reuses for every retry of one action. The coordinator
// checks and applies each under the worker's tree lock, so a worker's
// operations and job changes are applied one at a time, in order. A refused
// operation changes nothing and answers with a §6 code; the actor is the
// channel's device, never a field of the body.
//
// Built: startThread (a worker operation), sendNote, cancelJob, and
// acceptProposal and discardProposal, Cloud's own, and the mail operations
// (mailops.go): runHeldMail and addRequester on a thread, and the worker's
// mail settings. Every other
// operation Desktop knows is ErrUnsupported, by name, so a client can tell
// "not here yet" from a bad request.

// ErrUnsupported is an operation this home doesn't apply yet.
var ErrUnsupported = errors.New("not supported by Fount Cloud yet")

const (
	// maxOpBody bounds an operation's body: a 64 KiB note, escaped.
	maxOpBody = 512 << 10
	// maxNoteText is Desktop's MAX_TEXT.
	maxNoteText  = 64 << 10
	maxNoteFiles = 64
)

// opEnvelope is a thread operation, §4.1: kind and args beside the opId,
// thread and base revision.
type opEnvelope struct {
	OpID         string          `json:"opId"`
	ThreadID     string          `json:"threadId"`
	BaseRevision uint64          `json:"baseRevision"`
	Kind         string          `json:"kind"`
	Args         json.RawMessage `json:"args"`
}

// workerOpEnvelope is a worker operation: no thread, and no base revision, as
// startThread has nothing to be stale against.
type workerOpEnvelope struct {
	OpID string          `json:"opId"`
	Kind string          `json:"kind"`
	Args json.RawMessage `json:"args"`
}

// OpResult is §4.1's answer, Desktop's ops.rs OpResult. A refusal carries the
// thread's revision, which it didn't move.
type OpResult struct {
	OK       bool              `json:"ok"`
	Revision uint64            `json:"revision"`
	EntryIDs []string          `json:"entryIds,omitempty"`
	Code     OpCode            `json:"code,omitempty"`
	Message  string            `json:"message,omitempty"`
	Detail   map[string]string `json:"detail,omitempty"`
	// ThreadID is the thread a worker operation made or acted on.
	ThreadID string `json:"threadId,omitempty"`
}

// OpCode is a §6 refusal code.
type OpCode string

const (
	CodeNotFound        OpCode = "NOT_FOUND"
	CodeEmptyText       OpCode = "EMPTY_TEXT"
	CodeTextTooLong     OpCode = "TEXT_TOO_LONG"
	CodeOpIDReused      OpCode = "OP_ID_REUSED"
	CodeNoModel         OpCode = "NO_MODEL"
	CodeThreadCap       OpCode = "THREAD_CAP"
	CodeJobFinished     OpCode = "JOB_FINISHED"
	CodeFilesChanged    OpCode = "FILES_CHANGED"
	CodeProposalDecided OpCode = "PROPOSAL_DECIDED"
)

// opMessages are §6's messages, as Desktop's Code::message words them.
var opMessages = map[OpCode]string{
	CodeNotFound:        "This thread is gone.",
	CodeEmptyText:       "Write something first.",
	CodeTextTooLong:     "That's too long to send. Attach it as a file instead.",
	CodeOpIDReused:      "Fount sent this action twice with different content. Try again.",
	CodeNoModel:         "Choose a model for this worker's jobs first.",
	CodeThreadCap:       fmt.Sprintf("This thread has reached its limit of %d jobs.", maxThreadJobs),
	CodeJobFinished:     "That job already finished.",
	CodeFilesChanged:    "This file changed since the agent's change was made. Discard the change, or ask for it again.",
	CodeProposalDecided: "This change was already accepted or discarded.",
}

func refused(rev uint64, code OpCode) OpResult {
	return OpResult{Revision: rev, Code: code, Message: opMessages[code]}
}

// refusal is an operation the coordinator turns down with a code.
type refusal struct {
	code   OpCode
	detail map[string]string
}

func (r refusal) Error() string { return string(r.code) }

// unsupportedThreadOps are the thread operations Desktop's Op has that Cloud
// doesn't apply yet, and what each waits on.
var unsupportedThreadOps = map[string]string{
	"answerQuestion":  "questions: the runner reporting an ask, and resuming its wait",
	"dismissQuestion": "questions: the runner reporting an ask, and resuming its wait",
	"forwardQuestion": "questions and sending mail from Cloud",
	"keepFileAsCopy":  "drafts from a job's final answer",
	"redoOnLatest":    "drafts from a job's final answer",
	"markRead":        "read state per device",
}

var unsupportedWorkerOps = map[string]string{
	"removeRequester":  "the worker's requesters, moved in with worker.json",
	"setRequesterMode": "the worker's requesters, moved in with worker.json",
}

// noteArgs are sendNote's and startThread's. files is accepted and, as on
// Desktop, unused.
type noteArgs struct {
	Text  string   `json:"text"`
	Files []string `json:"files,omitempty"`
}

type cancelArgs struct {
	JobID string `json:"jobId"`
}

// proposalArgs are acceptProposal's and discardProposal's: a job's proposal,
// by the path it would have in the worker root.
type proposalArgs struct {
	JobID  string `json:"jobId"`
	Path   string `json:"path"`
	accept bool
}

func decodeArgs(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		return fmt.Errorf("%w: the operation has no args", ErrInvalid)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: args: %v", ErrInvalid, err)
	}
	return nil
}

func (a noteArgs) check() error {
	if len(a.Files) > maxNoteFiles {
		return fmt.Errorf("%w: at most %d files", ErrInvalid, maxNoteFiles)
	}
	for _, f := range a.Files {
		if err := checkPath(f); err != nil {
			return err
		}
	}
	return nil
}

// parseThreadOp checks an envelope for the thread at threadID and decodes its
// args: a noteArgs, cancelArgs or proposalArgs. It returns the hash a retry must match
// (§4.4): the thread, kind and args, not the base revision.
func parseThreadOp(env opEnvelope, threadID string) (args any, hash string, err error) {
	if err := checkID("op", env.OpID); err != nil {
		return nil, "", err
	}
	if env.ThreadID != threadID {
		return nil, "", fmt.Errorf("%w: the envelope's threadId isn't the path's", ErrInvalid)
	}
	switch env.Kind {
	case "sendNote":
		var a noteArgs
		if err := decodeArgs(env.Args, &a); err != nil {
			return nil, "", err
		}
		args, err = a, a.check()
	case "cancelJob":
		var a cancelArgs
		if err := decodeArgs(env.Args, &a); err != nil {
			return nil, "", err
		}
		args, err = a, checkID("job", a.JobID)
	case "acceptProposal", "discardProposal":
		var a proposalArgs
		if err := decodeArgs(env.Args, &a); err != nil {
			return nil, "", err
		}
		a.accept = env.Kind == "acceptProposal"
		args, err = a, cmp.Or(checkID("job", a.JobID), checkPath(a.Path))
	default:
		var mailOp bool
		if args, mailOp, err = parseMailThreadOp(env); mailOp {
			break
		}
		if args, mailOp, err = parseDraftThreadOp(env); mailOp {
			break
		}
		if needs, ok := unsupportedThreadOps[env.Kind]; ok {
			return nil, "", fmt.Errorf("%s: %w; it needs %s", env.Kind, ErrUnsupported, needs)
		}
		return nil, "", fmt.Errorf("%w: no thread operation %q", ErrInvalid, env.Kind)
	}
	if err != nil {
		return nil, "", err
	}
	return args, argsHash(threadID, env.Kind, args), nil
}

func parseWorkerOp(env workerOpEnvelope) (noteArgs, string, error) {
	if err := checkID("op", env.OpID); err != nil {
		return noteArgs{}, "", err
	}
	if env.Kind != "startThread" {
		if needs, ok := unsupportedWorkerOps[env.Kind]; ok {
			return noteArgs{}, "", fmt.Errorf("%s: %w; it needs %s", env.Kind, ErrUnsupported, needs)
		}
		return noteArgs{}, "", fmt.Errorf("%w: no worker operation %q", ErrInvalid, env.Kind)
	}
	var a noteArgs
	if err := decodeArgs(env.Args, &a); err != nil {
		return noteArgs{}, "", err
	}
	if err := a.check(); err != nil {
		return noteArgs{}, "", err
	}
	return a, argsHash("", env.Kind, a), nil
}

func argsHash(threadID, kind string, args any) string {
	data, _ := json.Marshal(struct {
		Thread string `json:"thread"`
		Kind   string `json:"kind"`
		Args   any    `json:"args"`
	}{threadID, kind, args})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// loggedOp is an applied client operation (§4.4). The log is in the worker's
// tree, under its DEK, so the opIds need no MAC.
type loggedOp struct {
	ArgsHash string    `json:"argsHash"`
	Revision uint64    `json:"revision"`
	Result   OpResult  `json:"result"`
	At       time.Time `json:"at"`
}

func loadOpLog(t *Tree, path string) (map[string]loggedOp, error) {
	ops := map[string]loggedOp{}
	data, err := t.Read(path)
	if errors.Is(err, ErrNotFound) {
		return ops, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &ops); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return ops, nil
}

func saveOpLog(t *Tree, path string, ops map[string]loggedOp) error {
	data, err := json.Marshal(ops)
	if err != nil {
		return err
	}
	return t.Write(path, data)
}

// retried is the answer to an opId already applied: its first result if the
// args match, else OP_ID_REUSED.
func retried(ops map[string]loggedOp, opID, hash string, rev uint64) (OpResult, bool) {
	logged, ok := ops[opID]
	switch {
	case !ok:
		return OpResult{}, false
	case logged.ArgsHash == hash:
		return logged.Result, true
	default:
		return refused(rev, CodeOpIDReused), true
	}
}

// noteText trims a note and checks it isn't empty or over the cap.
func noteText(text string) (string, error) {
	text = strings.TrimSpace(text)
	switch {
	case text == "":
		return "", refusal{code: CodeEmptyText}
	case len(text) > maxNoteText:
		return "", refusal{code: CodeTextTooLong}
	}
	return text, nil
}

// replacedNote opens a note's instruction when the note stopped the thread's
// unfinished job, as Desktop's NOTE_REPLACED_NOTE does.
const replacedNote = "The user wrote you a note while you were working, so that work was stopped and dropped, " +
	"and its file changes undone. Work from the note.\n\n"

// noteJob is the job a note starts on th: the JobSpec the coordinator builds
// from the thread, with the coordinator's model settings.
func (c *Coordinator) noteJob(th *threadRecord, text string, replacing bool) (string, JobSpec, error) {
	if len(c.cfg.JobConfig) == 0 {
		return "", JobSpec{}, refusal{code: CodeNoModel}
	}
	if len(th.Jobs) >= maxThreadJobs {
		return "", JobSpec{}, refusal{code: CodeThreadCap}
	}
	instruction := text
	if replacing {
		instruction = replacedNote + text
	}
	if len(instruction) > maxInstruction {
		return "", JobSpec{}, refusal{code: CodeTextTooLong}
	}
	id, err := newID("j")
	if err != nil {
		return "", JobSpec{}, err
	}
	return id, JobSpec{ThreadID: th.ID, SessionID: th.SessionID, Instruction: instruction, Config: c.cfg.JobConfig}, nil
}

// effects are what an applied operation does once the thread is committed:
// jobs to cancel, then a job to queue.
type effects struct {
	cancel []string
	jobID  string
	spec   JobSpec
	// mail is set when the operation left its worker's mail owing something
	// (mailintake.go), for the mail loop to do now.
	mail bool
}

func (c *Coordinator) runEffects(device, workerID string, e effects) {
	for _, id := range e.cancel {
		c.cancel(id)
	}
	if e.mail && c.mail != nil {
		c.mail.kick(workerID)
	}
	if e.jobID == "" {
		return
	}
	// A job that can't be queued is failed on the thread the next time it
	// is read, as one the queue has lost.
	if _, err := c.enqueueAs(device, workerID, e.jobID, e.spec); err != nil {
		log.Printf("worker %s: couldn't queue job %s: %v", workerID, e.jobID, err)
	}
	c.poke()
}

// applyThreadOp checks and applies a thread operation. A refusal is an
// OpResult; an error is a request the API refuses (ErrInvalid,
// ErrUnsupported) or a failure.
func (c *Coordinator) applyThreadOp(device, workerID, threadID string, env opEnvelope) (OpResult, error) {
	args, hash, err := parseThreadOp(env, threadID)
	if err != nil {
		return OpResult{}, err
	}
	var result OpResult
	var fx effects
	err = c.changeThen(workerID, device, func(t *Tree) error {
		th, err := loadThread(t, threadID)
		if errors.Is(err, ErrNoThread) {
			result = refused(0, CodeNotFound)
			return nil
		}
		if err != nil {
			return err
		}
		// The thread is brought up to its jobs first, so the checks see
		// what the queue knows.
		if _, err := c.follow(t, th); err != nil {
			return err
		}
		ops, err := loadOpLog(t, threadOpsPath(th.ID))
		if err != nil {
			return err
		}
		if r, ok := retried(ops, env.OpID, hash, th.Revision); ok {
			result = r
			return nil
		}
		now, rev := time.Now().UTC(), th.Revision+1
		var ids []string
		switch a := args.(type) {
		case noteArgs:
			ids, fx, err = c.sendNote(th, device, a, rev, now)
		case cancelArgs:
			fx, err = cancelJob(th, a, rev)
		case proposalArgs:
			err = decideProposal(t, th, a, rev)
		case heldMailArgs:
			fx, err = c.runHeldMail(t, th, a, rev)
		case mailRequesterArgs:
			err = c.addRequesterFromMail(t, th, a, rev, now)
		case draftOp:
			ids, fx, err = a.applyDraft(c, t, th, device, rev, now)
		}
		var r refusal
		if errors.As(err, &r) {
			result = refused(th.Revision, r.code)
			result.Detail = r.detail
			return nil
		}
		if err != nil {
			return err
		}
		th.finish(rev, now)
		result = OpResult{OK: true, Revision: rev, EntryIDs: ids}
		ops[env.OpID] = loggedOp{ArgsHash: hash, Revision: rev, Result: result, At: now}
		if err := saveThread(t, th); err != nil {
			return err
		}
		return saveOpLog(t, threadOpsPath(th.ID), ops)
	}, func() { c.runEffects(device, workerID, fx) })
	return result, err
}

// sendNote is §5.1: a note entry and a job on the thread with the note as its
// instruction. Like a reply, a note takes over open work: a queued or running
// job is cancelled (job_replaced) and the note's job starts after it stops.
// A Cloud thread has no questions yet, so no note is held.
func (c *Coordinator) sendNote(th *threadRecord, device string, a noteArgs, rev uint64, now time.Time) ([]string, effects, error) {
	text, err := noteText(a.Text)
	if err != nil {
		return nil, effects{}, err
	}
	var open []string
	for _, j := range th.Jobs {
		if j.unfinished() {
			open = append(open, j.ID)
		}
	}
	jobID, spec, err := c.noteJob(th, text, len(open) > 0)
	if err != nil {
		return nil, effects{}, err
	}
	note, err := th.push(rev, now, threadEntry{Kind: entryNote, Device: device, Text: text, JobID: jobID})
	if err != nil {
		return nil, effects{}, err
	}
	for _, id := range open {
		th.stopJob(id, rev)
		if err := th.event(rev, now, "job_replaced", map[string]string{"jobId": id, "note": "true"}); err != nil {
			return nil, effects{}, err
		}
	}
	th.Jobs = append(th.Jobs, threadJob{ID: jobID, State: JobQueued, Rev: rev})
	return []string{note}, effects{cancel: open, jobID: jobID, spec: spec}, nil
}

// cancelJob is §5.11: the job must be queued or running. Its live turn is
// cancelled now; a running job's runner stops after.
func cancelJob(th *threadRecord, a cancelArgs, rev uint64) (effects, error) {
	j := th.job(a.JobID)
	if j == nil || !j.unfinished() {
		return effects{}, refusal{code: CodeJobFinished}
	}
	th.stopJob(a.JobID, rev)
	return effects{cancel: []string{a.JobID}}, nil
}

// decideProposal accepts or discards one of a finished job's proposals
// (cloud-in-home.md §5). Accept makes it the worker's file, if the file is
// still the version the job was given: a file someone changed since, or one
// made since a job proposed a new file of that name, is FILES_CHANGED and
// changes nothing. Either way the proposal goes, and its turn says what became
// of it.
func decideProposal(t *Tree, th *threadRecord, a proposalArgs, rev uint64) error {
	turn := th.proposalTurn(a.JobID, a.Path)
	if turn == nil {
		return fmt.Errorf("%w: job %s proposed no %s on this thread", ErrInvalid, a.JobID, a.Path)
	}
	if turn.Decided[a.Path] != "" {
		return refusal{code: CodeProposalDecided}
	}
	proposed := prefixJobs + a.JobID + "/proposed/" + a.Path
	decided := proposalDiscarded
	if a.accept {
		bases, err := loadBases(t, a.JobID)
		if err != nil {
			return err
		}
		base, known := bases[a.Path]
		current, exists := t.Hash(prefixRoot + a.Path)
		if !known || current != base || exists != (base != "") {
			return refusal{code: CodeFilesChanged, detail: map[string]string{"path": a.Path}}
		}
		data, err := t.Read(proposed)
		if err != nil {
			return err
		}
		if err := t.Write(prefixRoot+a.Path, data); err != nil {
			return err
		}
		decided = proposalAccepted
	}
	t.Remove(proposed)
	if turn.Decided == nil {
		turn.Decided = map[string]string{}
	}
	turn.Decided[a.Path], turn.Rev = decided, rev
	return nil
}

// loadBases is a job's bases.json. A job collected before bases were kept
// has none, so none of its proposals can be accepted, only discarded.
func loadBases(t *Tree, jobID string) (map[string]string, error) {
	bases := map[string]string{}
	data, err := t.Read(basesPath(jobID))
	if errors.Is(err, ErrNotFound) {
		return bases, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &bases); err != nil {
		return nil, fmt.Errorf("%s: %w", basesPath(jobID), err)
	}
	return bases, nil
}

// applyWorkerOp checks and applies a worker operation: startThread, a new
// thread with the note as its first entry and a job working from it.
func (c *Coordinator) applyWorkerOp(device, workerID string, env workerOpEnvelope) (OpResult, error) {
	if isMailWorkerOp(env.Kind) {
		return c.applyMailWorkerOp(device, workerID, env)
	}
	if env.Kind == "setDefaultMode" {
		return c.applyDefaultMode(device, workerID, env)
	}
	args, hash, err := parseWorkerOp(env)
	if err != nil {
		return OpResult{}, err
	}
	var result OpResult
	var fx effects
	err = c.changeThen(workerID, device, func(t *Tree) error {
		ops, err := loadOpLog(t, workerOps)
		if err != nil {
			return err
		}
		if r, ok := retried(ops, env.OpID, hash, 0); ok {
			result = r
			return nil
		}
		th, ids, e, err := c.startThread(workerID, device, args)
		var r refusal
		if errors.As(err, &r) {
			result = refused(0, r.code)
			return nil
		}
		if err != nil {
			return err
		}
		fx = e
		result = OpResult{OK: true, Revision: th.Revision, EntryIDs: ids, ThreadID: th.ID}
		ops[env.OpID] = loggedOp{ArgsHash: hash, Revision: th.Revision, Result: result, At: th.CreatedAt}
		if err := saveThread(t, th); err != nil {
			return err
		}
		return saveOpLog(t, workerOps, ops)
	}, func() { c.runEffects(device, workerID, fx) })
	return result, err
}

func (c *Coordinator) startThread(workerID, device string, a noteArgs) (*threadRecord, []string, effects, error) {
	text, err := noteText(a.Text)
	if err != nil {
		return nil, nil, effects{}, err
	}
	id, err := newID("thr")
	if err != nil {
		return nil, nil, effects{}, err
	}
	session, err := newID("ses")
	if err != nil {
		return nil, nil, effects{}, err
	}
	now := time.Now().UTC()
	th := &threadRecord{
		Schema: threadSchema, ID: id, WorkerID: workerID, Origin: "app", SessionID: session,
		Subject: firstLine(text), CreatedAt: now, Status: StatusIdle, Entries: []threadEntry{}, Jobs: []threadJob{},
	}
	jobID, spec, err := c.noteJob(th, text, false)
	if err != nil {
		return nil, nil, effects{}, err
	}
	const rev = 1
	note, err := th.push(rev, now, threadEntry{Kind: entryNote, Device: device, Text: text, JobID: jobID})
	if err != nil {
		return nil, nil, effects{}, err
	}
	th.Jobs = append(th.Jobs, threadJob{ID: jobID, State: JobQueued, Rev: rev})
	th.finish(rev, now)
	return th, []string{note}, effects{jobID: jobID, spec: spec}, nil
}

// threads is the worker's threads, newest first, each brought up to its jobs.
func (c *Coordinator) threads(device, workerID string) ([]ThreadSummary, error) {
	out := []ThreadSummary{}
	err := c.change(workerID, device, func(t *Tree) error {
		out = out[:0]
		for _, id := range threadIDs(t) {
			th, err := loadThread(t, id)
			if err != nil {
				return err
			}
			if _, err := c.follow(t, th); err != nil {
				return err
			}
			out = append(out, th.summary())
		}
		return nil
	})
	slices.SortFunc(out, func(a, b ThreadSummary) int {
		return cmp.Or(cmp.Compare(b.UpdatedAt, a.UpdatedAt), strings.Compare(a.ID, b.ID))
	})
	return out, err
}

// thread is one thread, brought up to its jobs.
func (c *Coordinator) thread(device, workerID, threadID string) (*threadRecord, error) {
	var th *threadRecord
	err := c.change(workerID, device, func(t *Tree) (err error) {
		if th, err = loadThread(t, threadID); err != nil {
			return err
		}
		_, err = c.follow(t, th)
		return err
	})
	return th, err
}
