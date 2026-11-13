package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMain doubles as the fake runner: run with FAKE_RUNNER set, the test binary
// acts like fount-runner given the coordinator's folder flags.
func TestMain(m *testing.M) {
	if mode := os.Getenv("FAKE_RUNNER"); mode != "" {
		os.Exit(fakeRunner(mode, os.Args[1:]))
	}
	os.Exit(m.Run())
}

func fakeRunner(mode string, args []string) int {
	flags := map[string]string{}
	for i := 0; i+1 < len(args); i += 2 {
		flags[strings.TrimPrefix(args[i], "--")] = args[i+1]
	}
	ws := flags["workspace"]
	job, _ := os.ReadFile(flags["job"])
	var spec runnerJob
	json.Unmarshal(job, &spec)
	outputs, _ := filepath.Glob(filepath.Join(ws, "threads", "*", "outputs", "*"))
	instructions, _ := os.ReadFile(filepath.Join(ws, "instructions.md"))
	for _, out := range outputs {
		os.WriteFile(filepath.Join(out, "reply.md"), []byte("reply to: "+spec.Prompt+"\ninstructions: "+string(instructions)), 0o644)
		os.Symlink("/etc/hosts", filepath.Join(out, "hosts"))
	}
	os.WriteFile(filepath.Join(ws, "instructions.md"), []byte("rewritten by the runner"), 0o644)
	os.MkdirAll(filepath.Join(ws, ".fount", "conversations"), 0o755)
	os.WriteFile(filepath.Join(ws, ".fount", "conversations", spec.SessionID+".json"), []byte(`{"turns":1}`), 0o644)
	os.WriteFile(filepath.Join(ws, "files", "memo.md"), []byte("memo v2"), 0o644)
	os.MkdirAll(flags["index"], 0o755)
	os.WriteFile(filepath.Join(flags["index"], "manifest.json"), []byte(`{"built":true}`), 0o644)
	fmt.Println(`{"event":"job-finished","payload":{"state":"ready_for_review"}}`)
	switch mode {
	case "fail":
		return 1
	case "hang":
		time.Sleep(time.Minute)
	}
	return 0
}

func newTestCoordinator(t *testing.T, mode string, timeout time.Duration) (*Coordinator, context.CancelFunc) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := NewWrappingKey()
	dir := t.TempDir()
	c, err := New(Config{
		StateDir: filepath.Join(dir, "state"),
		WorkDir:  filepath.Join(dir, "work"),
		Store:    DirStore{Root: filepath.Join(dir, "objects")},
		Key:      key,
		Pool:     NewPool(1, 2, nil),
		Runner:   envRunner{LocalRunner{Command: []string{self}, Timeout: timeout}, mode},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go c.Run(ctx)
	t.Cleanup(cancel)
	return c, cancel
}

// envRunner sets FAKE_RUNNER, which LocalRunner's cleared environment drops.
type envRunner struct {
	LocalRunner
	mode string
}

func (e envRunner) Run(ctx context.Context, id string, job JobDirs) (RunResult, error) {
	l := e.LocalRunner
	l.Command = append([]string{"/usr/bin/env", "FAKE_RUNNER=" + e.mode}, l.Command...)
	return l.Run(ctx, id, job)
}

func waitJob(t *testing.T, c *Coordinator, id string) Job {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		j, err := c.Job(id)
		if err != nil {
			t.Fatal(err)
		}
		if j.State == JobFinished || j.State == JobFailed {
			return j
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("job didn't end")
	return Job{}
}

func spec(thread string) JobSpec {
	return JobSpec{ThreadID: thread, SessionID: "s_" + thread, Instruction: "Answer Ann", Config: json.RawMessage(`{"model":"m"}`)}
}

func TestAJobRunsAndKeepsOnlyItsResults(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	w, err := c.CreateWorker("acme", nil)
	if err != nil {
		t.Fatal(err)
	}
	c.PutFile(w.ID, "instructions.md", []byte("be brief"))
	c.PutFile(w.ID, "files/memo.md", []byte("memo v1"))
	c.PutFile(w.ID, "threads/t1/2026-11-13-e_1/message.md", []byte("From Ann: please send the memo"))

	job, err := c.Enqueue(w.ID, spec("t1"))
	if err != nil {
		t.Fatal(err)
	}
	done := waitJob(t, c, job.ID)
	if done.State != JobFinished {
		t.Fatalf("job %s: %s", done.State, done.Error)
	}

	reply, err := c.ReadFile(w.ID, "root/threads/t1/outputs/"+job.ID+"/reply.md")
	if err != nil || string(reply) != "reply to: Answer Ann\ninstructions: be brief" {
		t.Fatalf("reply: %q %v", reply, err)
	}
	if got, _ := c.ReadFile(w.ID, "root/instructions.md"); string(got) != "be brief" {
		t.Fatalf("the runner changed instructions.md to %q", got)
	}
	if got, _ := c.ReadFile(w.ID, "root/files/memo.md"); string(got) != "memo v1" {
		t.Fatalf("the memo changed without review: %q", got)
	}
	if got, _ := c.ReadFile(w.ID, "jobs/"+job.ID+"/proposed/files/memo.md"); string(got) != "memo v2" {
		t.Fatalf("proposal: %q", got)
	}
	if got, _ := c.ReadFile(w.ID, "fount/conversations/s_t1.json"); string(got) != `{"turns":1}` {
		t.Fatalf("session: %q", got)
	}
	if got, _ := c.ReadFile(w.ID, "index/manifest.json"); string(got) != `{"built":true}` {
		t.Fatalf("index: %q", got)
	}
	if got, _ := c.ReadFile(w.ID, "jobs/"+job.ID+"/events.jsonl"); !strings.Contains(string(got), "job-finished") {
		t.Fatalf("events: %q", got)
	}
	if _, err := c.ReadFile(w.ID, "root/threads/t1/outputs/"+job.ID+"/hosts"); !errors.Is(err, ErrNotFound) {
		t.Fatal("a link the runner left was followed")
	}
	if done.Dropped != 2 {
		t.Fatalf("dropped %d, want 2 (instructions.md and the link)", done.Dropped)
	}

	// The next job is given the kept session and index.
	second, _ := c.Enqueue(w.ID, spec("t1"))
	if j := waitJob(t, c, second.ID); j.State != JobFinished {
		t.Fatalf("second job: %s %s", j.State, j.Error)
	}
	worker, _ := c.Worker(w.ID)
	if worker.Version < 5 {
		t.Fatalf("worker at version %d after 3 puts and 2 jobs", worker.Version)
	}
}

func TestFailedAndTimedOutJobs(t *testing.T) {
	c, _ := newTestCoordinator(t, "fail", 0)
	w, _ := c.CreateWorker("acme", nil)
	j, _ := c.Enqueue(w.ID, spec("t1"))
	done := waitJob(t, c, j.ID)
	if done.State != JobFailed || !strings.Contains(done.Error, "exit 1") {
		t.Fatalf("failed job: %s %q", done.State, done.Error)
	}
	// A failed job's session and events are still kept, for the app to show.
	if _, err := c.ReadFile(w.ID, "fount/conversations/s_t1.json"); err != nil {
		t.Fatal(err)
	}

	slow, _ := newTestCoordinator(t, "hang", 300*time.Millisecond)
	w2, _ := slow.CreateWorker("acme", nil)
	j2, _ := slow.Enqueue(w2.ID, spec("t1"))
	if done := waitJob(t, slow, j2.ID); done.State != JobFailed || !strings.Contains(done.Error, "deadline") {
		t.Fatalf("timed-out job: %s %q", done.State, done.Error)
	}
}

func TestAWorkerRunsOneJobAtATime(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	w, _ := c.CreateWorker("acme", nil)
	var ids []string
	for _, thread := range []string{"t1", "t2", "t3"} {
		j, _ := c.Enqueue(w.ID, spec(thread))
		ids = append(ids, j.ID)
	}
	var prevEnd time.Time
	for _, id := range ids {
		j := waitJob(t, c, id)
		if j.State != JobFinished {
			t.Fatalf("%s: %s %s", id, j.State, j.Error)
		}
		if j.Started.Before(prevEnd) {
			t.Fatalf("%s started before the previous job ended", id)
		}
		prevEnd = j.Ended
	}
}

func TestThreadFilesAreWriteOnce(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	w, _ := c.CreateWorker("acme", nil)
	if err := c.PutFile(w.ID, "threads/t1/e_1/message.md", []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := c.PutFile(w.ID, "threads/t1/e_1/message.md", []byte("b")); !errors.Is(err, ErrWriteOnce) {
		t.Fatalf("overwrote a thread file: %v", err)
	}
	if err := c.PutFile(w.ID, ".fount/conversations/x.json", []byte("{}")); !errors.Is(err, ErrReserved) {
		t.Fatalf("wrote into .fount: %v", err)
	}
	if err := c.PutFile(w.ID, "memory.md", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := c.PutFile(w.ID, "memory.md", []byte("2")); err != nil {
		t.Fatalf("memory.md is not write-once: %v", err)
	}
}

func TestRestartFailsInterruptedJobs(t *testing.T) {
	dir := t.TempDir()
	s := &State{Workers: map[string]*Worker{}, Jobs: map[string]*Job{"j_1": {ID: "j_1", State: JobRunning}, "j_2": {ID: "j_2", State: JobQueued}}}
	if err := s.Save(dir); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Jobs["j_1"].State != JobFailed || loaded.Jobs["j_2"].State != JobQueued {
		t.Fatalf("after restart: running job %s, queued job %s", loaded.Jobs["j_1"].State, loaded.Jobs["j_2"].State)
	}
}

func TestAPI(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	srv := httptest.NewServer(c.Handler())
	defer srv.Close()
	do := func(method, path, body string) (int, map[string]any) {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	code, w := do("POST", "/v0/workers", `{"account":"acme"}`)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, w)
	}
	if _, leaked := w["wrappedDek"]; leaked {
		t.Fatal("the API returned the wrapped DEK")
	}
	id := w["id"].(string)
	for _, tc := range []struct {
		method, path, body string
		want               int
	}{
		{"POST", "/v0/workers", `{"account":"acme","extra":1}`, 400},
		{"POST", "/v0/workers", `{"account":"acme","dek":"c2hvcnQ="}`, 400},
		{"GET", "/v0/workers/w_nope", "", 404},
		{"PUT", "/v0/workers/" + id + "/root/instructions.md", "be brief", 204},
		{"PUT", "/v0/workers/" + id + "/root/a/%2E%2E/b", "x", 400},
		{"GET", "/v0/workers/" + id + "/files/root/missing.md", "", 404},
		{"POST", "/v0/workers/" + id + "/jobs", `{"threadId":"t1"}`, 400},
		{"GET", "/v0/jobs/j_nope", "", 404},
	} {
		if code, out := do(tc.method, tc.path, tc.body); code != tc.want {
			t.Errorf("%s %s: %d %v, want %d", tc.method, tc.path, code, out, tc.want)
		}
	}
	code, j := do("POST", "/v0/workers/"+id+"/jobs", `{"threadId":"t1","sessionId":"s1","instruction":"hi","config":{}}`)
	if code != http.StatusAccepted {
		t.Fatalf("enqueue: %d %v", code, j)
	}
	waitJob(t, c, j["id"].(string))
	code, list := do("GET", "/v0/workers/"+id+"/files?prefix=root/threads/", "")
	if code != 200 || len(list["paths"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, list)
	}
}
