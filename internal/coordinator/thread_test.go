package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fount-labs/fount-broker/internal/jobwire"
)

// threadRunner holds each agent job until the test releases it or the job is
// cancelled, and keeps each job's prompt. A job leaves out.md in its outputs
// and report.md, naming its prompt, at the top of the worker's files.
type threadRunner struct {
	mu      sync.Mutex
	prompts []string
	release chan struct{}
	stopped chan struct{}
}

func (r *threadRunner) Run(ctx context.Context, _, _ string, job JobDirs) (RunResult, error) {
	if job.Mode == jobwire.ModeIndex {
		return RunResult{}, os.MkdirAll(job.Index, dirMode)
	}
	data, err := os.ReadFile(job.JobFile)
	if err != nil {
		return RunResult{}, err
	}
	var rj runnerJob
	json.Unmarshal(data, &rj)
	r.mu.Lock()
	r.prompts = append(r.prompts, rj.Prompt)
	r.mu.Unlock()
	outputs, _ := filepath.Glob(filepath.Join(job.Workspace, "threads", "*", "outputs", "*"))
	for _, out := range outputs {
		os.WriteFile(filepath.Join(out, "out.md"), []byte("done"), fileMode)
	}
	os.WriteFile(filepath.Join(job.Workspace, "report.md"), []byte("report: "+rj.Prompt), fileMode)
	select {
	case <-r.release:
		return RunResult{}, nil
	case <-ctx.Done():
		r.stopped <- struct{}{}
		return RunResult{}, ctx.Err()
	}
}

func (r *threadRunner) started() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.prompts)
}

func (r *threadRunner) prompt(i int) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.prompts[i]
}

func newThreadCoordinator(t *testing.T, jobConfig string) (*Coordinator, *threadRunner, Worker) {
	t.Helper()
	key, _ := NewWrappingKey()
	dir := t.TempDir()
	r := &threadRunner{release: make(chan struct{}), stopped: make(chan struct{}, 8)}
	c, err := New(Config{
		StateDir:  filepath.Join(dir, "state"),
		WorkDir:   filepath.Join(dir, "work"),
		Store:     DirStore{Root: filepath.Join(dir, "objects")},
		Key:       key,
		Pool:      NewPool(1, 2, nil),
		Runner:    r,
		Audience:  testAudience,
		JobConfig: json.RawMessage(jobConfig),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()
	// Run returns once its jobs have, so none writes into a removed folder.
	t.Cleanup(func() {
		cancel()
		<-done
	})
	w, err := c.CreateWorker("acme", nil)
	if err != nil {
		t.Fatal(err)
	}
	return c, r, w
}

func startThread(t *testing.T, c *Coordinator, w Worker, opID, text string) OpResult {
	t.Helper()
	res, err := c.applyWorkerOp(anyDevice, w.ID, workerOpEnvelope{OpID: opID, Kind: "startThread", Args: noteJSON(text)})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func noteJSON(text string) json.RawMessage {
	data, _ := json.Marshal(noteArgs{Text: text})
	return data
}

func threadOp(t *testing.T, c *Coordinator, w Worker, tid, opID string, base uint64, kind string, args any) OpResult {
	t.Helper()
	raw, _ := json.Marshal(args)
	res, err := c.applyThreadOp(anyDevice, w.ID, tid, opEnvelope{OpID: opID, ThreadID: tid, BaseRevision: base, Kind: kind, Args: raw})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func readThread(t *testing.T, c *Coordinator, w Worker, tid string) *threadRecord {
	t.Helper()
	th, err := c.thread(anyDevice, w.ID, tid)
	if err != nil {
		t.Fatal(err)
	}
	return th
}

// waitThread reads the thread until ok holds.
func waitThread(t *testing.T, c *Coordinator, w Worker, tid, what string, ok func(*threadRecord) bool) *threadRecord {
	t.Helper()
	var th *threadRecord
	eventually(t, what, func() bool {
		th = readThread(t, c, w, tid)
		return ok(th)
	})
	return th
}

func kinds(th *threadRecord) string {
	var out []string
	for _, e := range th.Entries {
		k := e.Kind
		if e.State != "" {
			k += ":" + e.State
		}
		if e.Code != "" {
			k += ":" + e.Code
		}
		out = append(out, k)
	}
	return strings.Join(out, " ")
}

func TestChangesSinceARevision(t *testing.T) {
	at := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	th := &threadRecord{Schema: threadSchema, ID: "thr_1", Subject: "Close Acme", Status: StatusIdle}
	th.push(1, at, threadEntry{Kind: entryNote, Text: "Close Acme\nby Friday", JobID: "j_1"})
	th.Jobs = []threadJob{{ID: "j_1", State: JobQueued, Rev: 1}}
	th.finish(1, at)
	th.push(2, at, threadEntry{Kind: entryTurn, JobID: "j_1", State: turnLive})
	th.Jobs[0].State, th.Jobs[0].Rev = JobRunning, 2
	th.finish(2, at)
	// The turn ends at 3: it changes, and keeps its seq.
	th.Entries[1].State, th.Entries[1].Rev, th.Entries[1].Outputs = turnDone, 3, []string{"threads/thr_1/outputs/j_1/memo.md"}
	th.Jobs[0].State, th.Jobs[0].Rev = JobFinished, 3
	th.finish(3, at)

	if th.Status != StatusIdle || th.StatusAt != 3 {
		t.Fatalf("status %s at %d", th.Status, th.StatusAt)
	}
	for _, tc := range []struct {
		since   uint64
		full    bool
		header  bool
		entries int
	}{
		{0, true, true, 2},
		{1, false, true, 1},
		{2, false, true, 1},
		{3, false, false, 0},
		{9, true, true, 2},
	} {
		ch := th.changes(tc.since)
		if ch.Full != tc.full || (ch.Header != nil) != tc.header || len(ch.Entries) != tc.entries || ch.Revision != 3 {
			t.Errorf("since %d: full %v, header %v, %d entries, revision %d", tc.since, ch.Full, ch.Header != nil, len(ch.Entries), ch.Revision)
		}
	}
	got, _ := json.Marshal(th.changes(2))
	want := `{"full":false,"revision":3,"header":{"id":"thr_1","revision":3,"worker":{"name":"","address":""},"subject":"Close Acme","status":"idle","replyMode":"off","participants":[],"viewers":[],"sessionId":null},` +
		`"entries":[{"id":"` + th.Entries[1].ID + `","seq":2,"rev":3,"at":"2026-11-18T09:00:00Z","kind":"agent-turn","jobId":"j_1","steps":[],"files":[{"name":"memo.md"}]}]}`
	if string(got) != want {
		t.Errorf("changes:\n got %s\nwant %s", got, want)
	}
	got, _ = json.Marshal(th.view().Entries[0])
	if want := `{"id":"` + th.Entries[0].ID + `","seq":1,"rev":1,"at":"2026-11-18T09:00:00Z","kind":"note","author":"You","text":"Close Acme\nby Friday"}`; string(got) != want {
		t.Errorf("note:\n got %s\nwant %s", got, want)
	}
	if s := th.summary(); *s.Preview != "Close Acme" || s.UpdatedAt != at.UnixMilli() || s.SessionID != nil {
		t.Errorf("summary %+v", s)
	}
}

func TestAThreadFollowsItsJobs(t *testing.T) {
	at := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	newThread := func(ids ...string) *threadRecord {
		th := &threadRecord{Schema: threadSchema, ID: "thr_1", Status: StatusIdle}
		for _, id := range ids {
			th.Jobs = append(th.Jobs, threadJob{ID: id, State: JobQueued, Rev: 1})
		}
		th.finish(1, at)
		return th
	}
	none := func(string) jobFiles { return jobFiles{} }
	follow := func(th *threadRecord, jobs map[string]jobView) bool {
		t.Helper()
		changed, err := th.followJobs(jobs, none, at)
		if err != nil {
			t.Fatal(err)
		}
		return changed
	}

	th := newThread("j_1")
	if follow(th, map[string]jobView{"j_1": {State: JobQueued}}) || th.Revision != 1 || th.Status != StatusWorking {
		t.Fatalf("a queued job moved the thread: rev %d, %s", th.Revision, th.Status)
	}
	follow(th, map[string]jobView{"j_1": {State: JobRunning}})
	if th.Revision != 2 || kinds(th) != "turn:live" || th.Entries[0].Rev != 2 {
		t.Fatalf("running: rev %d, %s", th.Revision, kinds(th))
	}
	follow(th, map[string]jobView{"j_1": {State: JobFailed, Error: "the runner failed the job (exit 1)"}})
	if th.Revision != 3 || kinds(th) != "turn:failed event:job_failed" || th.Status != StatusIdle || th.StatusAt != 3 {
		t.Fatalf("failed: rev %d, %s, %s", th.Revision, kinds(th), th.Status)
	}
	if text := eventText("job_failed", th.Entries[1].Args); text != "The job failed: the runner failed the job (exit 1)" {
		t.Errorf("event text %q", text)
	}
	// An ended job is never followed again.
	if follow(th, map[string]jobView{"j_1": {State: JobFinished}}) {
		t.Error("an ended job changed again")
	}

	// Two jobs that ended between two reads: one revision each. The one never
	// seen running gets a done turn; the one the queue lost fails.
	th = newThread("j_1", "j_2")
	follow(th, map[string]jobView{"j_1": {State: JobFinished}})
	if th.Revision != 3 || kinds(th) != "turn:done event:job_failed" || th.Jobs[0].Rev != 2 || th.Jobs[1].Rev != 3 {
		t.Fatalf("rev %d, %s, jobs %+v", th.Revision, kinds(th), th.Jobs)
	}
	if th.Entries[1].Args["error"] != "the job is gone" {
		t.Errorf("args %v", th.Entries[1].Args)
	}

	// A cancel the thread recorded stands, even if the job finished first.
	th = newThread("j_1")
	follow(th, map[string]jobView{"j_1": {State: JobRunning}})
	th.stopJob("j_1", 3)
	th.finish(3, at)
	if follow(th, map[string]jobView{"j_1": {State: JobFinished}}) || kinds(th) != "turn:cancelled" {
		t.Fatalf("a cancel was undone: %s", kinds(th))
	}
}

func TestAJobOnAFullThreadIsRefused(t *testing.T) {
	c := &Coordinator{cfg: Config{JobConfig: json.RawMessage(`{}`)}}
	th := &threadRecord{ID: "thr_1", SessionID: "ses_1"}
	for i := range maxThreadJobs {
		th.Jobs = append(th.Jobs, threadJob{ID: "j_" + string(rune('a'+i)), State: JobFinished})
	}
	var r refusal
	if _, _, err := c.noteJob(th, "again", false); !errors.As(err, &r) || r.code != CodeThreadCap {
		t.Fatalf("%v", err)
	}
	if _, _, err := (&Coordinator{}).noteJob(&threadRecord{}, "hi", false); !errors.As(err, &r) || r.code != CodeNoModel {
		t.Fatalf("no model: %v", err)
	}
}

func TestStartThreadRunsTheNoteAndRetriesByOpID(t *testing.T) {
	c, r, w := newThreadCoordinator(t, `{"model":"m"}`)
	res := startThread(t, c, w, "op_1", "  Close the Acme books\nby Friday  ")
	if !res.OK || res.Revision != 1 || res.ThreadID == "" || len(res.EntryIDs) != 1 {
		t.Fatalf("startThread: %+v", res)
	}
	tid := res.ThreadID
	if again := startThread(t, c, w, "op_1", "  Close the Acme books\nby Friday  "); again.ThreadID != tid || !again.OK {
		t.Fatalf("a retry made another thread: %+v", again)
	}
	if reused := startThread(t, c, w, "op_1", "something else"); reused.OK || reused.Code != CodeOpIDReused {
		t.Fatalf("a reused opId: %+v", reused)
	}
	if empty := startThread(t, c, w, "op_2", " \n "); empty.OK || empty.Code != CodeEmptyText {
		t.Fatalf("an empty note: %+v", empty)
	}
	if long := startThread(t, c, w, "op_3", strings.Repeat("x", maxNoteText+1)); long.Code != CodeTextTooLong {
		t.Fatalf("a long note: %+v", long)
	}

	th := waitThread(t, c, w, tid, "the job runs", func(th *threadRecord) bool { return th.Revision == 2 })
	if kinds(th) != "note turn:live" || th.Status != StatusWorking || th.Subject != "Close the Acme books" {
		t.Fatalf("running: %s, %s, %q", kinds(th), th.Status, th.Subject)
	}
	eventually(t, "the runner starts", func() bool { return r.started() == 1 })
	if r.prompt(0) != "Close the Acme books\nby Friday" {
		t.Fatalf("prompts: %q", r.prompts)
	}
	r.release <- struct{}{}
	th = waitThread(t, c, w, tid, "the job ends", func(th *threadRecord) bool { return th.Revision == 3 })
	if kinds(th) != "note turn:done" || th.Status != StatusIdle || th.StatusAt != 3 {
		t.Fatalf("finished: %s, %s at %d", kinds(th), th.Status, th.StatusAt)
	}
	if out := th.Entries[1].Outputs; len(out) != 1 || out[0] != "threads/"+tid+"/outputs/"+th.Jobs[0].ID+"/out.md" {
		t.Errorf("outputs %v", out)
	}
	if proposed := th.Entries[1].Proposed; len(proposed) != 1 || proposed[0] != "report.md" {
		t.Errorf("proposed %v", proposed)
	}
	turn, ok := th.display(0)[1].(turnView)
	if !ok || len(turn.Files) != 2 || turn.Files[0].Name != "out.md" || turn.Files[1].Name != "report.md" {
		t.Errorf("the turn shows %+v", th.display(0)[1])
	}
	list, err := c.threads(anyDevice, w.ID)
	if err != nil || len(list) != 1 || list[0].ID != tid || list[0].Revision != 3 {
		t.Fatalf("list: %v %+v", err, list)
	}
}

func TestANoteReplacesARunningJob(t *testing.T) {
	c, r, w := newThreadCoordinator(t, `{"model":"m"}`)
	tid := startThread(t, c, w, "op_1", "Draft the memo").ThreadID
	waitThread(t, c, w, tid, "the first job runs", func(th *threadRecord) bool { return th.Revision == 2 })

	// Based on revision 1, behind the turn that opened: a note is never stale.
	res := threadOp(t, c, w, tid, "op_2", 1, "sendNote", noteArgs{Text: "Use the 2025 figures"})
	if !res.OK || res.Revision != 3 || len(res.EntryIDs) != 1 {
		t.Fatalf("sendNote: %+v", res)
	}
	if again := threadOp(t, c, w, tid, "op_2", 1, "sendNote", noteArgs{Text: "Use the 2025 figures"}); again.Revision != 3 || again.EntryIDs[0] != res.EntryIDs[0] {
		t.Fatalf("a retry applied again: %+v", again)
	}
	select {
	case <-r.stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("the replaced job kept running")
	}
	th := readThread(t, c, w, tid)
	if !strings.HasPrefix(kinds(th), "note turn:cancelled note event:job_replaced") {
		t.Fatalf("entries: %s", kinds(th))
	}
	if first, _ := c.Job(th.Jobs[0].ID); first.State != JobCancelled {
		t.Errorf("the replaced job is %s", first.State)
	}
	if len(th.Jobs) != 2 {
		t.Fatalf("jobs %+v", th.Jobs)
	}
	eventually(t, "the note's job runs", func() bool { return r.started() == 2 })
	if p := r.prompt(1); p != replacedNote+"Use the 2025 figures" {
		t.Errorf("the note's prompt: %q", p)
	}
	r.release <- struct{}{}
	th = waitThread(t, c, w, tid, "the note's job ends", func(th *threadRecord) bool { return th.Status == StatusIdle })
	if kinds(th) != "note turn:cancelled note event:job_replaced turn:done" {
		t.Fatalf("entries: %s", kinds(th))
	}
	// The cancelled job's outputs were dropped; the note's job's were kept.
	paths, _ := c.ListFiles(w.ID, prefixRoot+"threads/"+tid+"/outputs/")
	if len(paths) != 1 || !strings.Contains(paths[0], th.Jobs[1].ID) {
		t.Errorf("outputs %v", paths)
	}
}

func TestCancelJob(t *testing.T) {
	c, r, w := newThreadCoordinator(t, `{"model":"m"}`)
	tid := startThread(t, c, w, "op_1", "Draft the memo").ThreadID
	th := waitThread(t, c, w, tid, "the job runs", func(th *threadRecord) bool { return th.Revision == 2 })
	job := th.Jobs[0].ID

	res := threadOp(t, c, w, tid, "op_2", 2, "cancelJob", cancelArgs{JobID: job})
	if !res.OK || res.Revision != 3 {
		t.Fatalf("cancelJob: %+v", res)
	}
	<-r.stopped
	th = readThread(t, c, w, tid)
	if kinds(th) != "note turn:cancelled" || th.Status != StatusIdle || th.Revision != 3 {
		t.Fatalf("cancelled: %s, %s, rev %d", kinds(th), th.Status, th.Revision)
	}
	// A retry gets the first answer; a new cancel of the same job is too late.
	if again := threadOp(t, c, w, tid, "op_2", 2, "cancelJob", cancelArgs{JobID: job}); !again.OK || again.Revision != 3 {
		t.Fatalf("a retry: %+v", again)
	}
	if late := threadOp(t, c, w, tid, "op_3", 3, "cancelJob", cancelArgs{JobID: job}); late.OK || late.Code != CodeJobFinished || late.Revision != 3 {
		t.Fatalf("a second cancel: %+v", late)
	}
	if other := threadOp(t, c, w, tid, "op_4", 3, "cancelJob", cancelArgs{JobID: "j_other"}); other.Code != CodeJobFinished {
		t.Fatalf("another thread's job: %+v", other)
	}
	eventually(t, "the job ends", func() bool { j, _ := c.Job(job); return !j.Ended.IsZero() })
	if j, _ := c.Job(job); j.State != JobCancelled {
		t.Errorf("the job is %s", j.State)
	}

	// A queued job is cancelled before it runs: it never opens a turn.
	c2, r2, w2 := newThreadCoordinator(t, `{"model":"m"}`)
	first := startThread(t, c2, w2, "op_1", "one").ThreadID
	waitThread(t, c2, w2, first, "the first job runs", func(th *threadRecord) bool { return th.Revision == 2 })
	second := startThread(t, c2, w2, "op_2", "two").ThreadID
	queued := readThread(t, c2, w2, second).Jobs[0].ID
	if res := threadOp(t, c2, w2, second, "op_3", 1, "cancelJob", cancelArgs{JobID: queued}); !res.OK {
		t.Fatalf("cancel a queued job: %+v", res)
	}
	r2.release <- struct{}{}
	waitThread(t, c2, w2, first, "the first job ends", func(th *threadRecord) bool { return th.Status == StatusIdle })
	time.Sleep(100 * time.Millisecond)
	if th := readThread(t, c2, w2, second); kinds(th) != "note" || th.Status != StatusIdle || r2.started() != 1 {
		t.Fatalf("the cancelled queued job: %s, %s, %d started", kinds(th), th.Status, r2.started())
	}
}

func TestAcceptAndDiscardAProposal(t *testing.T) {
	c, r, w := newThreadCoordinator(t, `{"model":"m"}`)
	tid := startThread(t, c, w, "op_1", "Write the report").ThreadID
	r.release <- struct{}{}
	th := waitThread(t, c, w, tid, "the job ends", func(th *threadRecord) bool { return th.Revision == 3 })
	first := th.Jobs[0].ID
	report := proposalArgs{JobID: first, Path: "report.md"}

	res := threadOp(t, c, w, tid, "op_2", 3, "acceptProposal", report)
	if !res.OK || res.Revision != 4 {
		t.Fatalf("accept: %+v", res)
	}
	if data, _ := c.ReadFile(w.ID, prefixRoot+"report.md"); string(data) != "report: Write the report" {
		t.Fatalf("the accepted file reads %q", data)
	}
	if left, _ := c.ListFiles(w.ID, prefixJobs+first+"/proposed/"); len(left) != 0 {
		t.Errorf("the proposal is still there: %v", left)
	}
	th = readThread(t, c, w, tid)
	turn := th.display(3)[0].(turnView)
	if got := turn.Files[1]; got.Name != "report.md" || got.Note != "Accepted" || got.Proposal != "" || turn.Rev != 4 {
		t.Errorf("the accepted turn shows %+v at %d", got, turn.Rev)
	}
	if again := threadOp(t, c, w, tid, "op_2", 3, "acceptProposal", report); !again.OK || again.Revision != 4 {
		t.Fatalf("a retry: %+v", again)
	}
	if twice := threadOp(t, c, w, tid, "op_3", 4, "discardProposal", report); twice.Code != CodeProposalDecided || twice.Revision != 4 {
		t.Fatalf("discarding an accepted proposal: %+v", twice)
	}

	// The next job changes report.md; someone changes it before it's accepted.
	threadOp(t, c, w, tid, "op_4", 4, "sendNote", noteArgs{Text: "Add the totals"})
	eventually(t, "the second job runs", func() bool { return r.started() == 2 })
	r.release <- struct{}{}
	th = waitThread(t, c, w, tid, "the second job ends", func(th *threadRecord) bool { return th.Status == StatusIdle })
	second := th.Jobs[1].ID
	if th.Entries[len(th.Entries)-1].Proposed[0] != "report.md" {
		t.Fatalf("the second job proposed %v", th.Entries[len(th.Entries)-1].Proposed)
	}
	pending := th.display(0)[len(th.Entries)-1].(turnView).Files[1]
	if pending.Note != "Proposed" || pending.Proposal != "report.md" {
		t.Errorf("a pending proposal shows %+v", pending)
	}
	if err := c.putFile(anyDevice, w.ID, "report.md", []byte("mine")); err != nil {
		t.Fatal(err)
	}
	rev := th.Revision
	moved := threadOp(t, c, w, tid, "op_5", rev, "acceptProposal", proposalArgs{JobID: second, Path: "report.md"})
	if moved.OK || moved.Code != CodeFilesChanged || moved.Detail["path"] != "report.md" || moved.Revision != rev {
		t.Fatalf("accepting over a changed file: %+v", moved)
	}
	res = threadOp(t, c, w, tid, "op_6", rev, "discardProposal", proposalArgs{JobID: second, Path: "report.md"})
	if !res.OK || res.Revision != rev+1 {
		t.Fatalf("discard: %+v", res)
	}
	if data, _ := c.ReadFile(w.ID, prefixRoot+"report.md"); string(data) != "mine" {
		t.Errorf("discarding changed the file: %q", data)
	}
	th = readThread(t, c, w, tid)
	if got := th.display(rev)[0].(turnView).Files[1]; got.Note != "Discarded" || got.Proposal != "" {
		t.Errorf("the discarded turn shows %+v", got)
	}
	if _, err := c.applyThreadOp(anyDevice, w.ID, tid, opEnvelope{OpID: "op_7", ThreadID: tid, Kind: "acceptProposal", Args: json.RawMessage(`{"jobId":"` + second + `","path":"other.md"}`)}); !errors.Is(err, ErrInvalid) {
		t.Errorf("a file the job never proposed: %v", err)
	}
}

func TestOperationsThatArentHereOrArentRight(t *testing.T) {
	c, _, w := newThreadCoordinator(t, ``)
	if res := startThread(t, c, w, "op_1", "hi"); res.Code != CodeNoModel {
		t.Fatalf("no model: %+v", res)
	}
	if res := threadOp(t, c, w, "thr_nope", "op_2", 0, "sendNote", noteArgs{Text: "hi"}); res.OK || res.Code != CodeNotFound {
		t.Fatalf("no thread: %+v", res)
	}
	for _, tc := range []struct {
		env  opEnvelope
		path string
		want error
	}{
		{opEnvelope{OpID: "op_1", ThreadID: "thr_1", Kind: "keepFileAsCopy", Args: json.RawMessage(`{}`)}, "thr_1", ErrUnsupported},
		{opEnvelope{OpID: "op_1", ThreadID: "thr_1", Kind: "approveDraft", Args: json.RawMessage(`{}`)}, "thr_1", ErrInvalid},
		{opEnvelope{OpID: "op_1", ThreadID: "thr_1", Kind: "frobnicate", Args: json.RawMessage(`{}`)}, "thr_1", ErrInvalid},
		{opEnvelope{OpID: "op_1", ThreadID: "thr_2", Kind: "sendNote", Args: noteJSON("hi")}, "thr_1", ErrInvalid},
		{opEnvelope{OpID: "op 1", ThreadID: "thr_1", Kind: "sendNote", Args: noteJSON("hi")}, "thr_1", ErrInvalid},
		{opEnvelope{OpID: "op_1", ThreadID: "thr_1", Kind: "sendNote"}, "thr_1", ErrInvalid},
		{opEnvelope{OpID: "op_1", ThreadID: "thr_1", Kind: "sendNote", Args: json.RawMessage(`{"text":"hi","extra":1}`)}, "thr_1", ErrInvalid},
		{opEnvelope{OpID: "op_1", ThreadID: "thr_1", Kind: "sendNote", Args: json.RawMessage(`{"text":"hi","files":["../x"]}`)}, "thr_1", ErrInvalid},
		{opEnvelope{OpID: "op_1", ThreadID: "thr_1", Kind: "acceptProposal", Args: json.RawMessage(`{"jobId":"j_1","path":"../x"}`)}, "thr_1", ErrInvalid},
	} {
		if _, err := c.applyThreadOp(anyDevice, w.ID, tc.path, tc.env); !errors.Is(err, tc.want) {
			t.Errorf("%s %s: %v, want %v", tc.env.Kind, tc.env.Args, err, tc.want)
		}
	}
	if _, err := c.applyWorkerOp(anyDevice, w.ID, workerOpEnvelope{OpID: "op_1", Kind: "setRequesterMode", Args: json.RawMessage(`{}`)}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("setRequesterMode: %v", err)
	}
	if _, err := c.applyWorkerOp(anyDevice, "w_nope", workerOpEnvelope{OpID: "op_1", Kind: "startThread", Args: noteJSON("hi")}); !errors.Is(err, ErrNoWorker) {
		t.Errorf("no worker: %v", err)
	}
}

func TestThreadsThroughTheAPI(t *testing.T) {
	c, r, _ := newThreadCoordinator(t, `{"model":"m"}`)
	srv := httptest.NewServer(c.Handler())
	defer srv.Close()
	_, w := do(t, srv, "POST", "/v0/workers", `{"account":"acme"}`)
	id := w["id"].(string)
	base := "/v0/workers/" + id

	code, res := do(t, srv, "POST", base+"/ops", `{"opId":"op_1","kind":"startThread","args":{"text":"Close Acme"}}`)
	if code != 200 || res["ok"] != true || res["revision"] != 1.0 {
		t.Fatalf("startThread: %d %v", code, res)
	}
	tid := res["threadId"].(string)
	eventually(t, "the job runs", func() bool { return r.started() == 1 })

	code, list := do(t, srv, "GET", base+"/threads", "")
	rows, _ := list["threads"].([]any)
	if code != 200 || len(rows) != 1 {
		t.Fatalf("list: %d %v", code, list)
	}
	row := rows[0].(map[string]any)
	for k, want := range map[string]any{"id": tid, "worker": id, "status": "working", "subject": "Close Acme", "preview": "Close Acme", "unread": false, "sessionId": nil} {
		if row[k] != want {
			t.Errorf("row %s: %v, want %v", k, row[k], want)
		}
	}

	code, view := do(t, srv, "GET", base+"/threads/"+tid, "")
	entries, _ := view["entries"].([]any)
	if code != 200 || view["id"] != tid || view["replyMode"] != "off" || len(entries) != 2 {
		t.Fatalf("get: %d %v", code, view)
	}
	if e := entries[1].(map[string]any); e["kind"] != "agent-turn" || e["live"] != true {
		t.Errorf("the turn: %v", e)
	}
	rev := view["revision"].(float64)
	code, ch := do(t, srv, "GET", base+"/threads/"+tid+"?since=1", "")
	if code != 200 || ch["full"] != false || ch["revision"] != rev || len(ch["entries"].([]any)) != 1 {
		t.Fatalf("since 1: %d %v", code, ch)
	}
	code, ch = do(t, srv, "GET", base+"/threads/"+tid+"?since=0", "")
	if code != 200 || ch["full"] != true || len(ch["entries"].([]any)) != 2 {
		t.Fatalf("since 0: %d %v", code, ch)
	}

	code, res = do(t, srv, "POST", base+"/threads/"+tid+"/ops", `{"opId":"op_2","threadId":"`+tid+`","baseRevision":2,"kind":"sendNote","args":{"text":"Use 2025"}}`)
	if code != 200 || res["ok"] != true {
		t.Fatalf("sendNote: %d %v", code, res)
	}
	code, res = do(t, srv, "POST", base+"/threads/"+tid+"/ops", `{"opId":"op_3","threadId":"`+tid+`","baseRevision":2,"kind":"cancelJob","args":{"jobId":"j_nope"}}`)
	if code != 200 || res["ok"] != false || res["code"] != "JOB_FINISHED" || res["message"] != "That job already finished." {
		t.Fatalf("cancelJob: %d %v", code, res)
	}
	for _, tc := range []struct {
		method, path, body string
		want               int
	}{
		{"GET", base + "/threads/" + tid + "?since=x", "", 400},
		{"GET", base + "/threads/thr_nope", "", 404},
		{"GET", "/v0/workers/w_nope/threads", "", 404},
		{"POST", base + "/threads/" + tid + "/ops", `{"opId":"op_4","threadId":"` + tid + `","baseRevision":2,"kind":"keepFileAsCopy","args":{}}`, 501},
		{"POST", base + "/threads/" + tid + "/ops", `{"opId":"op_4","threadId":"` + tid + `","baseRevision":2,"kind":"sendNote","args":{"text":"x"},"extra":1}`, 400},
		{"POST", base + "/ops", `{"opId":"op_4","kind":"setRequesterMode","args":{}}`, 501},
		{"POST", "/v0/workers/w_nope/ops", `{"opId":"op_4","kind":"startThread","args":{"text":"x"}}`, 404},
	} {
		if code, out := do(t, srv, tc.method, tc.path, tc.body); code != tc.want {
			t.Errorf("%s %s: %d %v, want %d", tc.method, tc.path, code, out, tc.want)
		}
	}
	code, res = do(t, srv, "POST", base+"/threads/thr_nope/ops", `{"opId":"op_5","threadId":"thr_nope","baseRevision":0,"kind":"sendNote","args":{"text":"x"}}`)
	if code != 200 || res["code"] != "NOT_FOUND" {
		t.Errorf("an op on no thread: %d %v", code, res)
	}
	<-r.stopped
	eventually(t, "the note's job runs", func() bool { return r.started() == 2 })
	r.release <- struct{}{}
}

func TestTheAccountAPIOpensThreadsOnlyToListedDevices(t *testing.T) {
	c, r, _ := newThreadCoordinator(t, `{"model":"m"}`)
	me := newTestDevice(t)
	w := granted(t, c, me, mustDEK(t))
	mine := httptest.NewServer(c.AccountHandler(me.caller("acme")))
	defer mine.Close()
	other := httptest.NewServer(c.AccountHandler(newTestDevice(t).caller("acme")))
	defer other.Close()

	base := "/v1/workers/" + w.ID
	if code, out := do(t, other, "POST", base+"/ops", `{"opId":"op_1","kind":"startThread","args":{"text":"hi"}}`); code != http.StatusNotFound {
		t.Fatalf("an unlisted device started a thread: %d %v", code, out)
	}
	code, res := do(t, mine, "POST", base+"/ops", `{"opId":"op_1","kind":"startThread","args":{"text":"hi"}}`)
	if code != 200 || res["ok"] != true {
		t.Fatalf("startThread: %d %v", code, res)
	}
	tid := res["threadId"].(string)
	th := readThread(t, c, w, tid)
	if th.Entries[0].Device != me.id() {
		t.Errorf("the note's device is %q", th.Entries[0].Device)
	}
	for _, path := range []string{base + "/threads", base + "/threads/" + tid, base + "/threads/" + tid + "?since=1"} {
		if code, out := do(t, other, "GET", path, ""); code != http.StatusNotFound {
			t.Errorf("other: GET %s: %d %v", path, code, out)
		}
		if code, out := do(t, mine, "GET", path, ""); code != http.StatusOK {
			t.Errorf("mine: GET %s: %d %v", path, code, out)
		}
	}
	eventually(t, "the job runs", func() bool { return r.started() == 1 })
	r.release <- struct{}{}
}
