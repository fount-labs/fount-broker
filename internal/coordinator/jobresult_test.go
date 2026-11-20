package coordinator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fount-labs/fount-broker/internal/jobwire"
)

// A turn summary as fount-runner's summary.rs writes it.
const goodSummary = `{"event":"turn-summary","payload":{"state":"waiting_for_you","text":"Which statement?","steps":[{"verb":"Read","target":"01-bank.pdf"},{"verb":"Searched","target":"April"}],"question":{"waitId":"call_7","text":"Which month?\n   A) April\n   B) May","detail":"April: The statement's month"}}}`

func eventsWith(lines ...string) []byte {
	all := append([]string{
		`{"event":"index-built","payload":{"files":2}}`,
		`{"event":"agent-event","payload":{"event":{"type":"text-delta","text":"the \"turn-summary\" is next"}}}`,
	}, lines...)
	all = append(all, `{"event":"job-finished","payload":{"state":"waiting_for_you"}}`)
	return []byte(strings.Join(all, "\n") + "\n")
}

func summaryWith(t *testing.T, change func(p map[string]any)) string {
	t.Helper()
	var line struct {
		Event   string         `json:"event"`
		Payload map[string]any `json:"payload"`
	}
	if err := json.Unmarshal([]byte(goodSummary), &line); err != nil {
		t.Fatal(err)
	}
	change(line.Payload)
	data, _ := json.Marshal(line)
	return string(data)
}

func TestATurnSummaryIsReadFromTheEvents(t *testing.T) {
	s, err := readTurnSummary(eventsWith(goodSummary))
	if err != nil {
		t.Fatal(err)
	}
	if s.State != jobStateWaiting || s.Text != "Which statement?" || len(s.Steps) != 2 || s.Steps[0] != (workStep{"Read", "01-bank.pdf"}) {
		t.Fatalf("summary %+v", s)
	}
	if s.Question == nil || s.Question.WaitID != "call_7" || !strings.HasPrefix(s.Question.Text, "Which month?") {
		t.Fatalf("question %+v", s.Question)
	}
}

func TestATurnSummaryThatBreaksARuleIsRefusedWhole(t *testing.T) {
	long := func(n int) string { return strings.Repeat("x", n) }
	steps := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = map[string]any{"verb": "Read", "target": "f"}
		}
		return out
	}
	cases := map[string][]byte{
		"none":         eventsWith(),
		"two":          eventsWith(goodSummary, goodSummary),
		"unknown":      eventsWith(summaryWith(t, func(p map[string]any) { p["send"] = "x@example.com" })),
		"state":        eventsWith(summaryWith(t, func(p map[string]any) { p["state"] = "sent" })),
		"long text":    eventsWith(summaryWith(t, func(p map[string]any) { p["text"] = long(maxTurnText + 1) })),
		"bad utf8":     eventsWith(strings.Replace(goodSummary, "Which statement?", "Which \xff?", 1)),
		"steps null":   eventsWith(summaryWith(t, func(p map[string]any) { p["steps"] = nil })),
		"many steps":   eventsWith(summaryWith(t, func(p map[string]any) { p["steps"] = steps(maxTurnSteps + 1) })),
		"verb":         eventsWith(summaryWith(t, func(p map[string]any) { p["steps"] = []any{map[string]any{"verb": "Sent", "target": "f"}} })),
		"empty target": eventsWith(summaryWith(t, func(p map[string]any) { p["steps"] = []any{map[string]any{"verb": "Read", "target": ""}} })),
		"ctl target":   eventsWith(summaryWith(t, func(p map[string]any) { p["steps"] = []any{map[string]any{"verb": "Read", "target": "a\nb"}} })),
		"long target": eventsWith(summaryWith(t, func(p map[string]any) {
			p["steps"] = []any{map[string]any{"verb": "Read", "target": long(maxStepTarget + 1)}}
		})),
		"step field": eventsWith(summaryWith(t, func(p map[string]any) {
			p["steps"] = []any{map[string]any{"verb": "Read", "target": "f", "path": "/etc"}}
		})),
		"ready asks":  eventsWith(summaryWith(t, func(p map[string]any) { p["state"] = "ready_for_review" })),
		"wait id":     eventsWith(summaryWith(t, func(p map[string]any) { p["question"].(map[string]any)["waitId"] = long(maxWaitID + 1) })),
		"no question": eventsWith(summaryWith(t, func(p map[string]any) { p["question"].(map[string]any)["text"] = "" })),
		"long detail": eventsWith(summaryWith(t, func(p map[string]any) { p["question"].(map[string]any)["detail"] = long(maxQuestionText + 1) })),
		"array":       eventsWith(`{"event":"turn-summary","payload":[]}`),
		"trailing":    eventsWith(strings.TrimSuffix(goodSummary, "}") + `,"x":1}}`),
		"cut short":   eventsWith(goodSummary[:len(goodSummary)/2]),
		"over a line": eventsWith(summaryWith(t, func(p map[string]any) { p["text"] = long(maxSummaryLine) })),
		"deep":        eventsWith(`{"event":"turn-summary","payload":` + strings.Repeat("[", 100000) + `}`),
	}
	for name, events := range cases {
		if s, err := readTurnSummary(events); err == nil {
			t.Errorf("%s: read %+v", name, s)
		}
	}
	// A summary with no question and no text, ready for review, holds.
	ready := summaryWith(t, func(p map[string]any) {
		p["state"] = "ready_for_review"
		delete(p, "question")
		delete(p, "text")
		p["steps"] = []any{}
	})
	if _, err := readTurnSummary(eventsWith(ready)); err != nil {
		t.Errorf("ready: %v", err)
	}
}

// summaryRunner is an agent job that ends with events.
type summaryRunner struct {
	events  []byte
	enclave *RunnerEnclave
}

func (r summaryRunner) Run(_ context.Context, _, _ string, job JobDirs) (RunResult, error) {
	if job.Mode == jobwire.ModeIndex {
		return RunResult{}, os.MkdirAll(job.Index, dirMode)
	}
	outputs, _ := filepath.Glob(filepath.Join(job.Workspace, "threads", "*", "outputs", "*"))
	for _, out := range outputs {
		os.WriteFile(filepath.Join(out, "recon.xlsx"), []byte("cells"), fileMode)
	}
	return RunResult{Events: r.events, Enclave: r.enclave}, nil
}

func newSummaryCoordinator(t *testing.T, events []byte) (*Coordinator, Worker) {
	t.Helper()
	return newRunnerCoordinator(t, summaryRunner{events: events})
}

func newRunnerCoordinator(t *testing.T, runner Runner) (*Coordinator, Worker) {
	t.Helper()
	key, _ := NewWrappingKey()
	dir := t.TempDir()
	c, err := New(Config{
		StateDir: filepath.Join(dir, "state"), WorkDir: filepath.Join(dir, "work"),
		Store: DirStore{Root: filepath.Join(dir, "objects")}, Key: key, Pool: NewPool(1, 2, nil),
		Runner: runner, Audience: testAudience, JobConfig: json.RawMessage(`{"model":"m"}`),
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
	return c, w
}

func TestACloudTurnShowsItsStepsTextAndQuestion(t *testing.T) {
	c, w := newSummaryCoordinator(t, eventsWith(goodSummary))
	tid := startThread(t, c, w, "op_1", "Reconcile April").ThreadID
	th := waitThread(t, c, w, tid, "the question", func(th *threadRecord) bool { return th.Status == StatusWaiting })
	if got := kinds(th); got != "note turn:done question:open" {
		t.Fatalf("entries %s", got)
	}
	turn, q := th.Entries[1], th.Entries[2]
	if turn.Text != "Which statement?" || len(turn.Steps) != 2 || len(turn.Outputs) != 1 {
		t.Fatalf("turn %+v", turn)
	}
	if q.JobID != turn.JobID || q.WaitID != "call_7" || q.Rev != turn.Rev {
		t.Fatalf("question %+v", q)
	}

	view, _ := json.Marshal(th.view())
	var drawn struct {
		Status  string           `json:"status"`
		Entries []map[string]any `json:"entries"`
	}
	json.Unmarshal(view, &drawn)
	if drawn.Status != "waiting" || len(drawn.Entries) != 3 {
		t.Fatalf("view %s", view)
	}
	agent, question := drawn.Entries[1], drawn.Entries[2]
	if _, ok := agent["enclave"]; ok {
		t.Errorf("a turn whose runner didn't dial in names an enclave: %v", agent)
	}
	if agent["kind"] != "agent-turn" || agent["text"] != "Which statement?" {
		t.Errorf("turn drawn %v", agent)
	}
	if steps := agent["steps"].([]any); len(steps) != 2 || steps[1].(map[string]any)["verb"] != "Searched" {
		t.Errorf("steps drawn %v", agent["steps"])
	}
	if question["kind"] != "question" || question["state"] != "open" || question["waitId"] != "call_7" ||
		question["detail"] != "April: The statement's month" || !strings.HasPrefix(question["question"].(string), "Which month?") {
		t.Errorf("question drawn %v", question)
	}
}

func TestATurnWithAHostileSummaryShowsOnlyItsFiles(t *testing.T) {
	hostile := summaryWith(t, func(p map[string]any) { p["question"].(map[string]any)["waitId"] = "a\x00b" })
	c, w := newSummaryCoordinator(t, eventsWith(hostile))
	tid := startThread(t, c, w, "op_1", "Reconcile April").ThreadID
	th := waitThread(t, c, w, tid, "the turn's end", func(th *threadRecord) bool { return th.Status == StatusIdle })
	if got := kinds(th); got != "note turn:done" {
		t.Fatalf("entries %s", got)
	}
	if turn := th.Entries[1]; turn.Text != "" || turn.Steps != nil || len(turn.Outputs) != 1 {
		t.Fatalf("turn %+v", turn)
	}
	view, _ := json.Marshal(th.view())
	if !strings.Contains(string(view), `"steps":[]`) {
		t.Errorf("a turn without a summary draws no steps list: %s", view)
	}
}

func TestAnEndedTurnSaysWhichEnclaveRanIt(t *testing.T) {
	ran := &RunnerEnclave{Kind: enclaveTeam, Repo: "fount-labs/fount-cloud-runner", Tag: "v0.4.0", Digest: "5f2c"}
	c, w := newRunnerCoordinator(t, summaryRunner{events: eventsWith(goodSummary), enclave: ran})
	tid := startThread(t, c, w, "op_1", "Reconcile April").ThreadID
	th := waitThread(t, c, w, tid, "the question", func(th *threadRecord) bool { return th.Status == StatusWaiting })
	if got := th.Entries[1].Enclave; got == nil || *got != *ran {
		t.Fatalf("the turn's enclave %+v", got)
	}
	view, _ := json.Marshal(th.view())
	want := `"enclave":{"kind":"team","repo":"fount-labs/fount-cloud-runner","tag":"v0.4.0","digest":"5f2c"}`
	if !strings.Contains(string(view), want) {
		t.Errorf("view %s", view)
	}
}

func TestAnEnclaveRecordThatDoesntHoldIsDropped(t *testing.T) {
	for _, data := range []string{`{"kind":"pool"`, `{"kind":"tm_0123456789abcdef01234567"}`, `{"kind":"team","team":"tm_1"}`, `{}`} {
		if e := readEnclave([]byte(data)); e != nil {
			t.Errorf("%s read as %+v", data, e)
		}
	}
	if e := readEnclave([]byte(`{"kind":"pool"}`)); e == nil || e.Kind != enclavePool {
		t.Errorf("a pool record read as %+v", e)
	}
}
