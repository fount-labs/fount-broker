package coordinator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fount-labs/fount-broker/internal/jobwire"
)

const readySummary = `{"event":"turn-summary","payload":{"state":"ready_for_review","text":"Reconciled April.","steps":[]}}`

// questionRunner is an agent job that asks goodSummary's question, or, when
// it resumes a wait, finishes. It keeps each job file it was given.
type questionRunner struct {
	mu   sync.Mutex
	jobs []runnerJob
}

func (r *questionRunner) Run(_ context.Context, _, _ string, job JobDirs) (RunResult, error) {
	if job.Mode == jobwire.ModeIndex {
		return RunResult{}, os.MkdirAll(job.Index, dirMode)
	}
	data, err := os.ReadFile(job.JobFile)
	if err != nil {
		return RunResult{}, err
	}
	var rj runnerJob
	if err := json.Unmarshal(data, &rj); err != nil {
		return RunResult{}, err
	}
	r.mu.Lock()
	r.jobs = append(r.jobs, rj)
	r.mu.Unlock()
	if rj.Resume != nil {
		return RunResult{Events: eventsWith(readySummary)}, nil
	}
	return RunResult{Events: eventsWith(goodSummary)}, nil
}

func (r *questionRunner) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.jobs)
}

func (r *questionRunner) job(i int) runnerJob {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.jobs[i]
}

func newQuestionCoordinator(t *testing.T) (*Coordinator, *questionRunner, Worker) {
	t.Helper()
	key, _ := NewWrappingKey()
	dir := t.TempDir()
	r := &questionRunner{}
	c, err := New(Config{
		StateDir: filepath.Join(dir, "state"), WorkDir: filepath.Join(dir, "work"),
		Store: DirStore{Root: filepath.Join(dir, "objects")}, Key: key, Pool: NewPool(1, 2, nil),
		Runner: r, Audience: testAudience, JobConfig: json.RawMessage(`{"model":"m"}`),
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

// askedThread is a thread whose first job ended waiting on its question.
func askedThread(t *testing.T, c *Coordinator, w Worker) (*threadRecord, threadEntry) {
	t.Helper()
	tid := startThread(t, c, w, "op_start", "Reconcile April").ThreadID
	th := waitThread(t, c, w, tid, "the question", func(th *threadRecord) bool { return th.Status == StatusWaiting })
	q := th.Entries[len(th.Entries)-1]
	if q.Kind != entryQuestion || q.State != questionOpen {
		t.Fatalf("entries %s", kinds(th))
	}
	return th, q
}

func answerArgs(q threadEntry, text string) map[string]any {
	return map[string]any{"questionId": q.ID, "questionRev": q.Rev, "text": text}
}

func TestAnAnswerResumesTheSavedSession(t *testing.T) {
	c, r, w := newQuestionCoordinator(t)
	th, q := askedThread(t, c, w)

	res := threadOp(t, c, w, th.ID, "op_a", th.Revision, "answerQuestion", answerArgs(q, "April"))
	if !res.OK || len(res.EntryIDs) != 1 || res.EntryIDs[0] != q.ID {
		t.Fatalf("answer: %+v", res)
	}
	th = waitThread(t, c, w, th.ID, "the resumed turn", func(th *threadRecord) bool { return th.Status == StatusIdle })
	if got := kinds(th); got != "note turn:done question:answered turn:done" {
		t.Fatalf("entries %s", got)
	}
	resumed := r.job(1)
	if resumed.SessionID != th.SessionID || resumed.SessionID != r.job(0).SessionID || resumed.Prompt != "" || resumed.Message != "" {
		t.Errorf("the resumed job %+v", resumed)
	}
	if resumed.Resume == nil || resumed.Resume.WaitID != "call_7" || string(resumed.Resume.Answer) != `{"answers":{"0":"April"}}` {
		t.Errorf("the resume %+v", resumed.Resume)
	}
	answered := th.entry(q.ID)
	if a := answered.Answer; a == nil || a.Via != viaApp || a.Text != "April" || a.JobID != th.Entries[3].JobID || a.Skipped {
		t.Errorf("the answer %+v", answered.Answer)
	}

	// Drawn as Desktop's Question with its answer.
	view, _ := json.Marshal(th.view())
	var drawn struct {
		Entries []map[string]any `json:"entries"`
	}
	json.Unmarshal(view, &drawn)
	question := drawn.Entries[2]
	answer, _ := question["answer"].(map[string]any)
	if question["state"] != "answered" || answer["by"] != "You" || answer["via"] != "app" || answer["text"] != "April" {
		t.Errorf("drawn %v", question)
	}
}

func TestTheFirstAnswerWins(t *testing.T) {
	c, r, w := newQuestionCoordinator(t)
	th, q := askedThread(t, c, w)
	if res := threadOp(t, c, w, th.ID, "op_a", th.Revision, "answerQuestion", answerArgs(q, "April")); !res.OK {
		t.Fatalf("first: %+v", res)
	}
	// A retry of the first is its first answer.
	if res := threadOp(t, c, w, th.ID, "op_a", th.Revision, "answerQuestion", answerArgs(q, "April")); !res.OK {
		t.Errorf("retry: %+v", res)
	}
	for kind, args := range map[string]any{
		"answerQuestion":  answerArgs(q, "May"),
		"dismissQuestion": map[string]any{"questionId": q.ID, "questionRev": q.Rev},
	} {
		res := threadOp(t, c, w, th.ID, "op_"+kind, th.Revision, kind, args)
		if res.OK || res.Code != CodeAlreadyAnswered || res.Detail["via"] != "app" {
			t.Errorf("%s after an answer: %+v", kind, res)
		}
	}
	waitThread(t, c, w, th.ID, "the resumed turn", func(th *threadRecord) bool { return th.Status == StatusIdle })
	// An emailed answer after it is a reply, not an answer.
	var spec *JobSpec
	err := c.change(w.ID, anyDevice, func(tr *Tree) error {
		th, err := loadThread(tr, th.ID)
		if err != nil {
			return err
		}
		th.Participants = []string{"owner@client.example"}
		spec, err = c.answerByMail(th, "owner@client.example", "May", "jm_e1", th.Revision+1, time.Now())
		return err
	})
	if err != nil || spec != nil {
		t.Errorf("an emailed answer after the app's: %v %+v", err, spec)
	}
	if r.count() != 2 {
		t.Errorf("%d jobs ran, want the question's and one resume", len(r.jobs))
	}
}

func TestAStaleQuestionRevisionIsRefused(t *testing.T) {
	c, _, w := newQuestionCoordinator(t)
	th, q := askedThread(t, c, w)
	stale := answerArgs(q, "April")
	stale["questionRev"] = q.Rev - 1
	res := threadOp(t, c, w, th.ID, "op_a", th.Revision, "answerQuestion", stale)
	if res.OK || res.Code != CodeQuestionChanged || res.Revision != th.Revision {
		t.Errorf("a stale questionRev: %+v", res)
	}
	if got := readThread(t, c, w, th.ID); got.Revision != th.Revision || got.entry(q.ID).State != questionOpen {
		t.Errorf("a refused answer changed the thread: %s", kinds(got))
	}
	// Without one, or with another kind's field, the operation is malformed.
	for _, args := range []string{
		`{"questionId":"` + q.ID + `","text":"April"}`,
		`{"questionId":"` + q.ID + `","questionRev":1,"text":"April","to":"x@y.example"}`,
	} {
		_, err := c.applyThreadOp(anyDevice, w.ID, th.ID, opEnvelope{OpID: "op_b", ThreadID: th.ID, Kind: "answerQuestion", Args: json.RawMessage(args)})
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", args, err)
		}
	}
	if res := threadOp(t, c, w, th.ID, "op_c", th.Revision, "answerQuestion", answerArgs(q, "  ")); res.Code != CodeEmptyText {
		t.Errorf("an empty answer: %+v", res)
	}
	form := answerArgs(q, "April")
	form["answer"] = map[string]any{"answers": map[string]any{}}
	if res := threadOp(t, c, w, th.ID, "op_d", th.Revision, "answerQuestion", form); res.Code != CodeEmptyText {
		t.Errorf("a form that answers nothing: %+v", res)
	}
}

func TestAFormAnswerIsPassedOn(t *testing.T) {
	c, r, w := newQuestionCoordinator(t)
	th, q := askedThread(t, c, w)
	form := answerArgs(q, "April, with a note")
	form["answer"] = map[string]any{"answers": map[string]any{"0": "April"}, "annotations": map[string]any{"0": map[string]any{"notes": "the second one"}}}
	if res := threadOp(t, c, w, th.ID, "op_a", th.Revision, "answerQuestion", form); !res.OK {
		t.Fatalf("answer: %+v", res)
	}
	waitThread(t, c, w, th.ID, "the resumed turn", func(th *threadRecord) bool { return th.Status == StatusIdle })
	if got := string(r.job(1).Resume.Answer); got != `{"annotations":{"0":{"notes":"the second one"}},"answers":{"0":"April"}}` {
		t.Errorf("the resume's answer %s", got)
	}
}

func TestADismissalResumesWithNoAnswers(t *testing.T) {
	c, r, w := newQuestionCoordinator(t)
	th, q := askedThread(t, c, w)
	res := threadOp(t, c, w, th.ID, "op_d", th.Revision, "dismissQuestion", map[string]any{"questionId": q.ID, "questionRev": q.Rev})
	if !res.OK {
		t.Fatalf("dismiss: %+v", res)
	}
	th = waitThread(t, c, w, th.ID, "the resumed turn", func(th *threadRecord) bool { return th.Status == StatusIdle })
	if a := th.entry(q.ID).Answer; a == nil || !a.Skipped {
		t.Errorf("the dismissal %+v", a)
	}
	if rs := r.job(1).Resume; rs == nil || rs.WaitID != "call_7" || string(rs.Answer) != `{"answers":{}}` {
		t.Errorf("the resume %+v", rs)
	}
}

func TestAQuestionIsForwardedToARequesterOnTheThread(t *testing.T) {
	c, _, w := newQuestionCoordinator(t)
	th, q := askedThread(t, c, w)
	forward := map[string]any{"questionId": q.ID, "questionRev": q.Rev, "to": "Lee@Client.example"}

	// Without drafts (lane D) it isn't here yet.
	raw, _ := json.Marshal(forward)
	if _, err := c.applyThreadOp(anyDevice, w.ID, th.ID, opEnvelope{OpID: "op_f", ThreadID: th.ID, Kind: "forwardQuestion", Args: raw}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("forward without drafts: %v", err)
	}

	var drafted []string
	QuestionDraft = func(_ *Tree, th *threadRecord, q *threadEntry, to string, rev uint64, now time.Time) (string, error) {
		drafted = append(drafted, q.ID+" to "+to)
		return th.push(rev, now, threadEntry{Kind: entryEvent, Code: "question_draft"})
	}
	t.Cleanup(func() { QuestionDraft = nil })

	// Lee isn't on the thread, nor a requester.
	if res := threadOp(t, c, w, th.ID, "op_f1", th.Revision, "forwardQuestion", forward); res.Code != CodeRecipientNotAllowed {
		t.Fatalf("forward to a stranger: %+v", res)
	}
	err := c.change(w.ID, anyDevice, func(tr *Tree) error {
		th, err := loadThread(tr, th.ID)
		if err != nil {
			return err
		}
		th.Participants = []string{"lee@client.example"}
		if err := saveThread(tr, th); err != nil {
			return err
		}
		return writeJSON(tr, mailSettingsPath, &MailSettings{Requesters: []Requester{{Address: "lee@client.example"}}})
	})
	if err != nil {
		t.Fatal(err)
	}
	res := threadOp(t, c, w, th.ID, "op_f2", th.Revision, "forwardQuestion", forward)
	if !res.OK || len(drafted) != 1 || drafted[0] != q.ID+" to lee@client.example" {
		t.Fatalf("forward: %+v %v", res, drafted)
	}
	if res := threadOp(t, c, w, th.ID, "op_f3", th.Revision, "forwardQuestion", forward); res.Code != CodeQuestionChanged {
		t.Errorf("forward at the old rev: %+v", res)
	}
	th = readThread(t, c, w, th.ID)
	fq := th.entry(q.ID)
	if fq.State != questionOpen || fq.Forward == nil || fq.Forward.DraftID != res.EntryIDs[0] || th.Status != StatusWaiting {
		t.Fatalf("forwarded question %+v", fq)
	}
	forward["questionRev"] = fq.Rev
	if res := threadOp(t, c, w, th.ID, "op_f4", th.Revision, "forwardQuestion", forward); res.Code != CodeAlreadyForwarded {
		t.Errorf("a second forward: %+v", res)
	}
	// Forwarded, it can still be answered in the app.
	if res := threadOp(t, c, w, th.ID, "op_a", th.Revision, "answerQuestion", answerArgs(*fq, "April")); !res.OK {
		t.Errorf("answer after forwarding: %+v", res)
	}
	view, _ := json.Marshal(readThread(t, c, w, th.ID).view())
	if !bytes.Contains(view, []byte(`"forwarded":"lee@client.example"`)) {
		t.Errorf("view %s", view)
	}
}

func TestAnEmailedAnswerResumesTheSession(t *testing.T) {
	c, r, w := newQuestionCoordinator(t)
	th, q := askedThread(t, c, w)
	var spec *JobSpec
	jobID := mailJobID("e_1")
	err := c.changeThen(w.ID, anyDevice, func(tr *Tree) error {
		th, err := loadThread(tr, th.ID)
		if err != nil {
			return err
		}
		rev, now := th.Revision+1, time.Now().UTC()
		// Someone not on the thread can't answer.
		if s, err := c.answerByMail(th, "eve@else.example", "April", jobID, rev, now); s != nil || err != nil {
			t.Errorf("a stranger's answer: %+v %v", s, err)
		}
		th.Participants = []string{"lee@client.example"}
		if spec, err = c.answerByMail(th, "Lee@client.example", "Reply in threads/x/2026-11-19-e_1/.", jobID, rev, now); err != nil || spec == nil {
			return errors.Join(err, errors.New("no spec"))
		}
		th.Jobs = append(th.Jobs, threadJob{ID: jobID, State: JobQueued, Rev: rev})
		th.finish(rev, now)
		return saveThread(tr, th)
	}, func() {
		if spec != nil {
			c.enqueueAs(anyDevice, w.ID, jobID, *spec)
			c.poke()
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	th = waitThread(t, c, w, th.ID, "the resumed turn", func(th *threadRecord) bool { return th.Status == StatusIdle })
	a := th.entry(q.ID).Answer
	if a == nil || a.Via != viaEmail || a.Requester != "lee@client.example" || a.JobID != jobID {
		t.Fatalf("the emailed answer %+v", a)
	}
	if rs := r.job(1).Resume; rs == nil || rs.WaitID != "call_7" || !strings.Contains(string(rs.Answer), "2026-11-19-e_1") {
		t.Errorf("the resume %+v", rs)
	}
	res := threadOp(t, c, w, th.ID, "op_a", th.Revision, "answerQuestion", answerArgs(*th.entry(q.ID), "May"))
	if res.Code != CodeAlreadyAnswered || res.Detail["via"] != "email" || res.Detail["by"] != "lee@client.example" {
		t.Errorf("an answer in the app after the email's: %+v", res)
	}
}

func TestANoteClosesTheQuestion(t *testing.T) {
	c, r, w := newQuestionCoordinator(t)
	th, q := askedThread(t, c, w)
	if res := threadOp(t, c, w, th.ID, "op_n", th.Revision, "sendNote", noteArgs{Text: "Use May instead"}); !res.OK {
		t.Fatalf("note: %+v", res)
	}
	th = waitThread(t, c, w, th.ID, "the note's turn", func(th *threadRecord) bool { return r.count() == 2 && th.Status != StatusWorking })
	if th.entry(q.ID).State != questionClosed {
		t.Fatalf("entries %s", kinds(th))
	}
	if r.job(1).Resume != nil || r.job(1).Prompt != "Use May instead" {
		t.Errorf("the note's job %+v", r.job(1))
	}
	if res := threadOp(t, c, w, th.ID, "op_a", th.Revision, "answerQuestion", answerArgs(q, "April")); res.Code != CodeQuestionClosed {
		t.Errorf("answering a closed question: %+v", res)
	}
}

func TestAReviewerAnswersAndANonMemberCant(t *testing.T) {
	f := newTeamFixture(t)
	f.c.cfg.JobConfig = json.RawMessage(`{"model":"m"}`)
	f.tt.update("m_reviewer", func(m *ListMember) { m.Workers = []string{f.w1.ID} })
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	stranger := newTestDevice(t)
	const tid = "thr_0123456789abcdef01234567"
	var qid string
	err := f.c.change(f.w1.ID, anyDevice, func(tr *Tree) error {
		now := time.Now().UTC()
		th := &threadRecord{Schema: threadSchema, ID: tid, WorkerID: f.w1.ID, Origin: "app", SessionID: "ses_1", Subject: "Close", Entries: []threadEntry{}, Jobs: []threadJob{}}
		var err error
		if qid, err = th.push(1, now, threadEntry{Kind: entryQuestion, State: questionOpen, WaitID: "call_7", Text: "Which month?"}); err != nil {
			return err
		}
		th.finish(1, now)
		return saveThread(tr, th)
	})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"opId":"op_a","threadId":"` + tid + `","baseRevision":1,"kind":"answerQuestion","args":{"questionId":"` + qid + `","questionRev":1,"text":"April"}}`
	path := "/v1/workers/" + f.w1.ID + "/threads/" + tid + "/ops"
	if code, out := do(t, f.api(t, stranger, "eve"), "POST", path, body); code != 404 {
		t.Errorf("a non-member: %d %v", code, out)
	}
	code, out := do(t, f.api(t, f.reviewer, "maria"), "POST", path, body)
	if code != 200 || out["ok"] != true {
		t.Fatalf("the reviewer: %d %v", code, out)
	}
	th, err := f.c.thread(anyDevice, f.w1.ID, tid)
	if err != nil {
		t.Fatal(err)
	}
	if a := th.entry(qid).Answer; a == nil || a.Device != f.reviewer.id() {
		t.Errorf("the answer %+v", a)
	}
	// The resume runs to its end before the test's folders go.
	eventually(t, "the resumed job's end", func() bool {
		th, err := f.c.thread(anyDevice, f.w1.ID, tid)
		return err == nil && th.Status != StatusWorking
	})
}

func TestAResumeSpecIsChecked(t *testing.T) {
	ok := JobSpec{ThreadID: "thr_1", SessionID: "ses_1", Config: json.RawMessage(`{"model":"m"}`), Resume: &ResumeSpec{WaitID: "call_7", Answer: json.RawMessage(`{"answers":{"0":"April"}}`)}}
	if err := ok.check(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(s *JobSpec){
		"an instruction": func(s *JobSpec) { s.Instruction = "and this" },
		"a message":      func(s *JobSpec) { s.Message = "threads/thr_1/m" },
		"no wait":        func(s *JobSpec) { s.Resume.WaitID = "" },
		"a control wait": func(s *JobSpec) { s.Resume.WaitID = "a\x00b" },
		"a list answer":  func(s *JobSpec) { s.Resume.Answer = json.RawMessage(`["April"]`) },
		"no answer":      func(s *JobSpec) { s.Resume.Answer = nil },
		"a long answer": func(s *JobSpec) {
			s.Resume.Answer = json.RawMessage(`{"a":"` + strings.Repeat("x", maxResumeAnswer) + `"}`)
		},
	} {
		s := ok
		r := *ok.Resume
		s.Resume = &r
		change(&s)
		if err := s.check(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// testdata/resume-job.json is the job file the coordinator writes for a
// resume. fount-runner's tests read the same bytes
// (crates/fount-runner/tests/fixtures/resume-job.json in the Fount repo), so
// the two sides of the field stay one. Regenerate it with
// FOUNT_RESUME_GOLDEN=1.
func TestTheResumeJobFileIsTheRunnersGolden(t *testing.T) {
	spec := JobSpec{
		ThreadID: "thr_golden", SessionID: "ses_golden", Config: json.RawMessage(`{"model":"kimi-k3-1-pro"}`),
		Resume: &ResumeSpec{WaitID: "call_7", Answer: json.RawMessage(`{"answers":{"0":"April"}}`)},
	}
	got, err := spec.runnerJob()
	if err != nil {
		t.Fatal(err)
	}
	const golden = "testdata/resume-job.json"
	if os.Getenv("FOUNT_RESUME_GOLDEN") != "" {
		if err := os.WriteFile(golden, append(got, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(append(got, '\n'), want) {
		t.Errorf("runner job\n%s\nwant\n%s", got, want)
	}
}
