package coordinator

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// A worker's threads are records in its tree, under its DEK: a thread's
// subject and notes are the user's words, which the volume mustn't hold
// (thread-operations.md §2, in the Fount repo's docs/features/fount-fleet).
// The coordinator is each Cloud thread's only writer. Client operations
// (threadops.go) and its own job changes each move a thread's revision on by
// one, and every entry keeps the revision it last changed at, so a client
// that saw revision N asks for what changed since N.
//
// The record is the coordinator's, not Desktop's schema 2: it has notes,
// turns and events, the entries a thread started in the app has before mail,
// questions and drafts reach Cloud. The reads give Desktop's display form
// (src-tauri/src/workers/thread/view.rs), so a client draws either home's
// threads the same way.
const (
	prefixRecord = "record/"
	// threadsDir holds each thread's record, <id>.json, and the operations
	// applied to it, <id>.ops.json.
	threadsDir = prefixRecord + "threads/"
	// workerOps is the worker operations applied, for retries.
	workerOps = prefixRecord + "ops.json"

	threadSchema = 1
	// maxThreadJobs is Desktop's default limits.jobsPerThread.
	maxThreadJobs = 20
	previewChars  = 160
)

// ErrNoThread is a thread the worker doesn't have.
var ErrNoThread = errors.New("no such thread")

// ThreadStatus is thread-operations.md §3's, first match wins. A Cloud thread
// has no questions, drafts or held mail yet, so it is working or idle.
type ThreadStatus string

const (
	StatusWorking ThreadStatus = "working"
	StatusWaiting ThreadStatus = "waiting"
	StatusReview  ThreadStatus = "review"
	StatusHeld    ThreadStatus = "held"
	StatusIdle    ThreadStatus = "idle"
)

type threadRecord struct {
	Schema   int    `json:"schema"`
	ID       string `json:"id"`
	WorkerID string `json:"workerId"`
	// Origin is "app": a thread started by startThread. Mail threads come
	// with intake.
	Origin string `json:"origin"`
	// SessionID is the runner's session for every job on the thread, so
	// each turn continues the last.
	SessionID string       `json:"sessionId"`
	Subject   string       `json:"subject"`
	Revision  uint64       `json:"revision"`
	Status    ThreadStatus `json:"status"`
	StatusAt  uint64       `json:"statusAt"`
	CreatedAt time.Time    `json:"createdAt"`
	UpdatedAt time.Time    `json:"updatedAt"`
	// Seq is the last seq given to an entry: entries are ordered by it.
	Seq     uint64        `json:"seq"`
	Entries []threadEntry `json:"entries"`
	// Jobs is every job run on the thread, with the last state the thread
	// followed. The job queue is the authority on a job (followJobs).
	Jobs []threadJob `json:"jobs"`
}

const (
	entryNote  = "note"
	entryTurn  = "turn"
	entryEvent = "event"
)

const (
	turnLive      = "live"
	turnDone      = "done"
	turnFailed    = "failed"
	turnCancelled = "cancelled"
)

// threadEntry is one work entry. Entries are never removed, only changed, so
// "changed since" needs no tombstones.
type threadEntry struct {
	ID   string    `json:"id"`
	Seq  uint64    `json:"seq"`
	Rev  uint64    `json:"rev"`
	At   time.Time `json:"at"`
	Kind string    `json:"kind"`
	// A note's author and text, and the job it started.
	Device string `json:"device,omitempty"`
	Text   string `json:"text,omitempty"`
	// A turn's job, its state and, once it ends, the files it left in the
	// thread's outputs/<job id>/, by path in the worker root. A note names
	// its job here too.
	JobID   string   `json:"jobId,omitempty"`
	State   string   `json:"state,omitempty"`
	Outputs []string `json:"outputs,omitempty"`
	// An event's code and arguments: fixed text, filled in when shown.
	Code string            `json:"code,omitempty"`
	Args map[string]string `json:"args,omitempty"`
}

type threadJob struct {
	ID    string   `json:"id"`
	State JobState `json:"state"`
	Rev   uint64   `json:"rev"`
}

func (j threadJob) unfinished() bool { return j.State == JobQueued || j.State == JobRunning }

func threadPath(id string) string    { return threadsDir + id + ".json" }
func threadOpsPath(id string) string { return threadsDir + id + ".ops.json" }

func loadThread(t *Tree, id string) (*threadRecord, error) {
	if checkID("thread", id) != nil {
		return nil, ErrNoThread
	}
	data, err := t.Read(threadPath(id))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNoThread
	}
	if err != nil {
		return nil, err
	}
	th := &threadRecord{}
	if err := json.Unmarshal(data, th); err != nil {
		return nil, fmt.Errorf("thread %s: %w", id, err)
	}
	if th.Schema != threadSchema {
		return nil, fmt.Errorf("thread %s: schema %d, want %d", id, th.Schema, threadSchema)
	}
	return th, nil
}

func saveThread(t *Tree, th *threadRecord) error {
	data, err := json.Marshal(th)
	if err != nil {
		return err
	}
	return t.Write(threadPath(th.ID), data)
}

// threadIDs lists the worker's threads.
func threadIDs(t *Tree) []string {
	var ids []string
	for _, p := range t.List(threadsDir) {
		name := strings.TrimPrefix(p, threadsDir)
		if id, ok := strings.CutSuffix(name, ".json"); ok && !strings.HasSuffix(id, ".ops") {
			ids = append(ids, id)
		}
	}
	return ids
}

func (th *threadRecord) push(rev uint64, at time.Time, e threadEntry) (string, error) {
	id, err := newID("ent")
	if err != nil {
		return "", err
	}
	th.Seq++
	e.ID, e.Seq, e.Rev, e.At = id, th.Seq, rev, at
	th.Entries = append(th.Entries, e)
	return id, nil
}

func (th *threadRecord) event(rev uint64, at time.Time, code string, args map[string]string) error {
	_, err := th.push(rev, at, threadEntry{Kind: entryEvent, Code: code, Args: args})
	return err
}

// finish moves the thread to rev after a change.
func (th *threadRecord) finish(rev uint64, now time.Time) {
	th.Revision, th.UpdatedAt = rev, now
	if s := th.status(); s != th.Status {
		th.Status, th.StatusAt = s, rev
	}
}

func (th *threadRecord) status() ThreadStatus {
	if slices.ContainsFunc(th.Jobs, threadJob.unfinished) {
		return StatusWorking
	}
	return StatusIdle
}

func (th *threadRecord) job(id string) *threadJob {
	for i := range th.Jobs {
		if th.Jobs[i].ID == id {
			return &th.Jobs[i]
		}
	}
	return nil
}

func (th *threadRecord) liveTurn(jobID string) *threadEntry {
	for i := range th.Entries {
		if e := &th.Entries[i]; e.Kind == entryTurn && e.JobID == jobID && e.State == turnLive {
			return e
		}
	}
	return nil
}

// stopJob marks an unfinished job cancelled at rev, and its live turn.
func (th *threadRecord) stopJob(id string, rev uint64) {
	if j := th.job(id); j != nil {
		j.State, j.Rev = JobCancelled, rev
	}
	if turn := th.liveTurn(id); turn != nil {
		turn.State, turn.Rev = turnCancelled, rev
	}
}

// jobView is what followJobs reads of a job in the queue.
type jobView struct {
	State JobState
	Error string
}

// followJobs brings the thread's jobs up to the queue's, one revision per
// job that changed, as Desktop's jobState does (home.rs turn_follows): a turn
// opens, live, when its job runs, and ends done when the job finishes or
// failed when it fails. A job the thread already saw end is never changed
// again: a cancel the thread recorded stands even if the job finished first.
// outputs lists a finished job's outputs. It reports whether anything changed.
func (th *threadRecord) followJobs(jobs map[string]jobView, outputs func(jobID string) []string, now time.Time) (bool, error) {
	changed := false
	for i := range th.Jobs {
		j := &th.Jobs[i]
		if !j.unfinished() {
			continue
		}
		cur, ok := jobs[j.ID]
		if !ok {
			cur = jobView{State: JobFailed, Error: "the job is gone"}
		}
		if cur.State == j.State {
			continue
		}
		rev := th.Revision + 1
		live := th.liveTurn(j.ID)
		switch {
		case cur.State == JobRunning && live == nil:
			if _, err := th.push(rev, now, threadEntry{Kind: entryTurn, JobID: j.ID, State: turnLive}); err != nil {
				return changed, err
			}
		case cur.State == JobFinished && live == nil:
			// It ran between two reads, so it was never seen running.
			if _, err := th.push(rev, th.UpdatedAt, threadEntry{Kind: entryTurn, JobID: j.ID, State: turnDone, Outputs: outputs(j.ID)}); err != nil {
				return changed, err
			}
		case live != nil && cur.State != JobRunning:
			live.Rev = rev
			switch cur.State {
			case JobFinished:
				live.State, live.Outputs = turnDone, outputs(j.ID)
			case JobFailed:
				live.State = turnFailed
			case JobCancelled:
				live.State = turnCancelled
			}
		}
		if cur.State == JobFailed {
			args := map[string]string{"jobId": j.ID}
			if cur.Error != "" {
				args["error"] = cur.Error
			}
			if err := th.event(rev, now, "job_failed", args); err != nil {
				return changed, err
			}
		}
		j.State, j.Rev = cur.State, rev
		th.finish(rev, now)
		changed = true
	}
	return changed, nil
}

// followJob brings a thread up to its jobs' states, after one changed. A job
// queued with no thread record (the JobSpec API's) changes nothing.
func (c *Coordinator) followJob(workerID, threadID string) {
	err := c.change(workerID, anyDevice, func(t *Tree) error {
		th, err := loadThread(t, threadID)
		if errors.Is(err, ErrNoThread) {
			return nil
		}
		if err != nil {
			return err
		}
		_, err = c.follow(t, th)
		return err
	})
	if err != nil && !errors.Is(err, ErrNoWorker) {
		// The error isn't logged: it can name the worker's files.
		log.Printf("worker %s: couldn't bring a thread up to its jobs", workerID)
	}
}

// follow brings th up to the queue and stages it if it changed.
func (c *Coordinator) follow(t *Tree, th *threadRecord) (bool, error) {
	jobs := map[string]jobView{}
	c.mu.Lock()
	for _, j := range th.Jobs {
		if held, ok := c.state.Jobs[j.ID]; ok {
			jobs[j.ID] = jobView{State: held.State, Error: held.Error}
		}
	}
	c.mu.Unlock()
	outputs := func(jobID string) []string {
		var out []string
		for _, p := range t.List(prefixRoot + "threads/" + th.ID + "/outputs/" + jobID + "/") {
			out = append(out, strings.TrimPrefix(p, prefixRoot))
		}
		return out
	}
	changed, err := th.followJobs(jobs, outputs, time.Now().UTC())
	if err != nil || !changed {
		return changed, err
	}
	return true, saveThread(t, th)
}

// The display form: Desktop's view.rs types, field for field.

type ThreadSummary struct {
	ID       string       `json:"id"`
	Worker   string       `json:"worker"`
	Revision uint64       `json:"revision"`
	Status   ThreadStatus `json:"status"`
	Subject  string       `json:"subject"`
	Preview  *string      `json:"preview"`
	// UpdatedAt is epoch milliseconds.
	UpdatedAt int64 `json:"updatedAt"`
	// Unread is always false: read state is per device and not kept yet.
	Unread bool `json:"unread"`
	// SessionID is always null: the session is the coordinator's, not on
	// the client's device.
	SessionID *string `json:"sessionId"`
}

type ThreadHeader struct {
	ID       string       `json:"id"`
	Revision uint64       `json:"revision"`
	Worker   WorkerName   `json:"worker"`
	Subject  string       `json:"subject"`
	Status   ThreadStatus `json:"status"`
	// ReplyMode is "off": a thread started in the app has no email side.
	ReplyMode    string   `json:"replyMode"`
	Participants []any    `json:"participants"`
	Viewers      []string `json:"viewers"`
	SessionID    *string  `json:"sessionId"`
}

// WorkerName is empty: the worker's name and address are in its worker.json,
// which the client has.
type WorkerName struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

type ThreadView struct {
	ThreadHeader
	Entries []DisplayEntry `json:"entries"`
}

type ThreadChanges struct {
	Full     bool           `json:"full"`
	Revision uint64         `json:"revision"`
	Header   *ThreadHeader  `json:"header"`
	Entries  []DisplayEntry `json:"entries"`
}

// DisplayEntry is one drawn item: an entryHead and the fields of its kind,
// flat beside it.
type DisplayEntry any

type entryHead struct {
	ID   string `json:"id"`
	Seq  uint64 `json:"seq"`
	Rev  uint64 `json:"rev"`
	At   string `json:"at"`
	Kind string `json:"kind"`
}

type noteView struct {
	entryHead
	Author string `json:"author"`
	Text   string `json:"text"`
}

// turnView is an agent turn. Its steps and final text are in the runner's
// events, which the coordinator doesn't read, so a turn shows its state and
// outputs only.
type turnView struct {
	entryHead
	JobID string           `json:"jobId"`
	Steps []struct{}       `json:"steps"`
	Files []attachmentView `json:"files,omitempty"`
	Live  bool             `json:"live,omitempty"`
}

type attachmentView struct {
	Name string `json:"name"`
}

type eventView struct {
	entryHead
	Code string `json:"code,omitempty"`
	Text string `json:"text"`
}

func (th *threadRecord) summary() ThreadSummary {
	return ThreadSummary{
		ID: th.ID, Worker: th.WorkerID, Revision: th.Revision, Status: th.Status, Subject: th.Subject,
		Preview: th.preview(), UpdatedAt: th.UpdatedAt.UnixMilli(),
	}
}

func (th *threadRecord) header() ThreadHeader {
	return ThreadHeader{
		ID: th.ID, Revision: th.Revision, Subject: th.Subject, Status: th.Status,
		ReplyMode: "off", Participants: []any{}, Viewers: []string{},
	}
}

func (th *threadRecord) view() ThreadView {
	return ThreadView{ThreadHeader: th.header(), Entries: th.display(0)}
}

// changes is thread-operations.md §7.2's getChanges: everything when since is
// 0 or newer than the thread, as a client that must replace its copy;
// otherwise the header if the thread moved, and the entries changed after
// since.
func (th *threadRecord) changes(since uint64) ThreadChanges {
	full := since == 0 || since > th.Revision
	out := ThreadChanges{Full: full, Revision: th.Revision, Entries: th.display(since)}
	if full {
		out.Entries = th.display(0)
	}
	if full || th.Revision > since {
		h := th.header()
		out.Header = &h
	}
	return out
}

// display is the entries changed after since, in seq order.
func (th *threadRecord) display(since uint64) []DisplayEntry {
	out := []DisplayEntry{}
	for _, e := range th.Entries {
		if e.Rev <= since {
			continue
		}
		head := entryHead{ID: e.ID, Seq: e.Seq, Rev: e.Rev, At: e.At.UTC().Format(time.RFC3339)}
		switch e.Kind {
		case entryNote:
			head.Kind = "note"
			out = append(out, noteView{entryHead: head, Author: "You", Text: e.Text})
		case entryTurn:
			head.Kind = "agent-turn"
			v := turnView{entryHead: head, JobID: e.JobID, Steps: []struct{}{}, Live: e.State == turnLive}
			for _, p := range e.Outputs {
				v.Files = append(v.Files, attachmentView{Name: path.Base(p)})
			}
			out = append(out, v)
		case entryEvent:
			head.Kind = "event"
			out = append(out, eventView{entryHead: head, Code: e.Code, Text: eventText(e.Code, e.Args)})
		}
	}
	return out
}

// eventText is the fixed English for each event, as Desktop's assemble.rs
// event_text words it.
func eventText(code string, args map[string]string) string {
	switch code {
	case "job_replaced":
		return "Your note replaced the job, so it was stopped and restarted with your note."
	case "job_failed":
		if args["error"] != "" {
			return "The job failed: " + args["error"]
		}
		return "The job failed."
	}
	return strings.ReplaceAll(code, "_", " ")
}

// preview is the latest note's first line.
func (th *threadRecord) preview() *string {
	for _, e := range slices.Backward(th.Entries) {
		if e.Kind == entryNote {
			if line := firstLine(e.Text); line != "" {
				line = cut(line, previewChars)
				return &line
			}
		}
	}
	return nil
}

func firstLine(text string) string {
	for line := range strings.Lines(text) {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	return ""
}

func cut(text string, max int) string {
	if utf8.RuneCountInString(text) <= max {
		return text
	}
	return strings.TrimRight(string([]rune(text)[:max]), " \t") + "…"
}
