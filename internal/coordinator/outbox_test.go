package coordinator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// A reply carries what the agent put in outbox/ (§5.5, "The outbox"): a file
// it made, and an email's attachment it moved in, which stays where it was and
// names the version it is. Sent, the reply becomes the thread's next message
// folder, with its text and files.
func TestTheOutboxIsTheReplysFiles(t *testing.T) {
	r := newSendRig(t, modeNotify)
	r.runner.mu.Lock()
	r.runner.act = func(ws string) {
		msgs, _ := filepath.Glob(filepath.Join(ws, "threads", "*", "01 *"))
		for _, m := range msgs {
			data, _ := os.ReadFile(filepath.Join(m, intakeAttachment))
			os.WriteFile(filepath.Join(ws, "outbox", "statement.csv"), data, fileMode)
		}
		os.WriteFile(filepath.Join(ws, "outbox", "total.md"), []byte("total: 42"), fileMode)
		os.MkdirAll(filepath.Join(ws, "outbox", "sub"), dirMode)
		os.WriteFile(filepath.Join(ws, "outbox", "sub", "total.md"), []byte("another total"), fileMode)
		os.WriteFile(filepath.Join(ws, "files", "helper.py"), []byte("print(42)"), fileMode)
	}
	r.runner.mu.Unlock()
	th, e := r.drafted()
	if th.Folder != "1 Q3 close" {
		t.Fatalf("the thread's folder is %q", th.Folder)
	}
	msg := mailEntries(th)[0].Folder
	if !strings.HasPrefix(msg, "01 ") || !strings.HasSuffix(msg, " Dana") {
		t.Fatalf("the email's folder is %q", msg)
	}

	// The job saw readable paths, the listings and the empty folders' files.
	r.runner.mu.Lock()
	seen := slices.Clone(r.runner.seen[0])
	r.runner.mu.Unlock()
	for _, want := range []string{"threads/index.md", "threads/1 Q3 close/thread.md", "threads/1 Q3 close/" + msg + "/message.md"} {
		if !slices.Contains(seen, want) {
			t.Errorf("the job didn't see %s: %v", want, seen)
		}
	}
	for _, p := range seen {
		if strings.Contains(p, th.ID) || strings.Contains(p, "jm_") {
			t.Errorf("the job saw an ID in a path: %s", p)
		}
	}

	job := mailEntries(th)[0].JobID
	out := "jobs/" + job + "/outbox/"
	d := e.Draft
	if want := []string{out + "statement.csv", out + "sub/total.md", out + "total.md"}; !slices.Equal(d.Files, want) {
		t.Fatalf("the draft's files %v, want %v", d.Files, want)
	}
	moved := "threads/1 Q3 close/" + msg + "/" + intakeAttachment
	if src := d.Sources[out+"statement.csv"]; src.Path != moved || len(d.Sources) != 1 {
		t.Fatalf("the moved attachment's source: %+v", d.Sources)
	}
	// The move didn't delete: the attachment is still in its email's folder.
	if _, err := r.c.ReadFile(r.w.ID, prefixRoot+moved); err != nil {
		t.Fatalf("the moved attachment left its folder: %v", err)
	}
	// A helper file under files/ is proposed, not sent.
	if turn := th.Entries[len(th.Entries)-2]; turn.Kind != entryTurn || !slices.Equal(turn.Proposed, []string{"files/helper.py"}) {
		t.Fatalf("the turn %+v", turn)
	}
	view, _ := json.Marshal(th.view().Entries)
	if !strings.Contains(string(view), `"path":"`+out+`statement.csv","source":"`+moved+`"`) {
		t.Fatalf("the draft's view: %s", view)
	}

	th, _ = r.c.thread(anyDevice, r.w.ID, th.ID)
	if res := r.approve(th, e, "op_ok", 1); !res.OK {
		t.Fatalf("approve: %+v", res)
	}
	th, _ = r.c.thread(anyDevice, r.w.ID, th.ID)
	sent := th.entry(e.ID).Draft
	reply := "02 " + time.Now().UTC().Format("2006-01-02") + " Reply"
	if sent.Folder != reply || th.Messages != 2 {
		t.Fatalf("the reply's folder %q, %d messages", sent.Folder, th.Messages)
	}
	dir := prefixRoot + "threads/1 Q3 close/" + reply + "/"
	for name, want := range map[string]string{"attachments/total.md": "another total", "attachments/total (2).md": "total: 42", "attachments/statement.csv": ""} {
		got, err := r.c.ReadFile(r.w.ID, dir+name)
		if err != nil || want != "" && string(got) != want {
			t.Errorf("%s: %q %v", name, got, err)
		}
	}
	md, _ := r.c.ReadFile(r.w.ID, dir+"message.md")
	for _, want := range []string{"To: dana@example.com", "Subject: Re: Q3 close", agentAnswer, "`attachments/total (2).md`"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("message.md lacks %q:\n%s", want, md)
		}
	}
	var out2 mailOutView
	for _, v := range th.view().Entries {
		if m, ok := v.(mailOutView); ok {
			out2 = m
		}
	}
	if out2.Folder != dir || len(out2.Files) != 3 || !strings.HasPrefix(out2.Files[0].Path, dir+"attachments/") {
		t.Fatalf("the sent email's view: %+v", out2)
	}
	// The next job's thread.md lists the reply.
	listing := string(threadListings(mustTree(t, r.c, r.w.ID))["threads/1 Q3 close/thread.md"])
	if !strings.Contains(listing, "`"+reply+"/`: reply to dana@example.com") || !strings.Contains(listing, ", 3 attachments") {
		t.Fatalf("thread.md:\n%s", listing)
	}
}

func mustTree(t *testing.T, c *Coordinator, workerID string) *Tree {
	t.Helper()
	var tree *Tree
	if err := c.view(workerID, anyDevice, func(tr *Tree) error { tree = tr; return nil }); err != nil {
		t.Fatal(err)
	}
	return tree
}
