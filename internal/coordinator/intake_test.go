package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testEdgeID = "e41c"

// A spec as fount-runner's intake.rs writes it.
func goodIntakeSpec() map[string]any {
	return map[string]any{
		"version": 1, "parserVersion": 2, "message": testEdgeID,
		"instruction": "Please reconcile the attached statement.", "instructionSource": "owner",
		"note": "certain", "reply": false,
		"attachments": []any{map[string]any{"path": "attachments/01-statement.csv", "contentType": "text/csv", "size": 5, "inline": false}},
		"flags":       []any{"attached_email"},
	}
}

// writeIntakeOut lays out an intake's out folder with spec as its jobspec.json.
func writeIntakeOut(t *testing.T, spec any) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), intakeOut)
	os.MkdirAll(filepath.Join(out, "attachments"), 0o755)
	data, ok := spec.([]byte)
	if !ok {
		data, _ = json.Marshal(spec)
	}
	os.WriteFile(filepath.Join(out, intakeSpecFile), data, 0o644)
	os.WriteFile(filepath.Join(out, "message.md"), []byte("<!-- fount-mail message.md v1 -->\n"), 0o644)
	os.WriteFile(filepath.Join(out, "intake.json"), []byte(`{"version":1}`), 0o644)
	os.WriteFile(filepath.Join(out, "attachments", "01-statement.csv"), []byte("a,b\n1"), 0o644)
	return out
}

func TestIntakeOutputIsReadBack(t *testing.T) {
	spec, files, err := ReadIntake(writeIntakeOut(t, goodIntakeSpec()), testEdgeID)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Instruction != "Please reconcile the attached statement." || spec.InstructionSource != "owner" || len(spec.Attachments) != 1 {
		t.Fatalf("spec %+v", spec)
	}
	if len(files) != 3 || string(files["attachments/01-statement.csv"]) != "a,b\n1" || files[intakeSpecFile] != nil {
		t.Fatalf("files %v", files)
	}
}

// The spec fount-runner wrote for a real email, kept to hold the two repos to
// one format.
func TestTheRunnersSpecParses(t *testing.T) {
	data, err := os.ReadFile("testdata/intake-jobspec.json")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := ParseIntakeSpec(data, "e_41c")
	if err != nil {
		t.Fatal(err)
	}
	if spec.ParserVersion < 1 || spec.Instruction == "" || len(spec.Attachments) != 1 {
		t.Fatalf("spec %+v", spec)
	}
}

func TestAnIntakeThatBreaksARuleIsRefusedWhole(t *testing.T) {
	with := func(change func(s map[string]any)) map[string]any {
		s := goodIntakeSpec()
		change(s)
		return s
	}
	attachment := func(change func(a map[string]any)) func(s map[string]any) {
		return func(s map[string]any) { change(s["attachments"].([]any)[0].(map[string]any)) }
	}
	specs := map[string]any{
		"unknown field":  with(func(s map[string]any) { s["to"] = "x@example.com" }),
		"version":        with(func(s map[string]any) { s["version"] = 2 }),
		"parser version": with(func(s map[string]any) { s["parserVersion"] = 0 }),
		"other message":  with(func(s map[string]any) { s["message"] = "e_other" }),
		"no instruction": with(func(s map[string]any) { s["instruction"] = "" }),
		"long instr":     with(func(s map[string]any) { s["instruction"] = strings.Repeat("x", maxInstruction+1) }),
		"source":         with(func(s map[string]any) { s["instructionSource"] = "sender" }),
		"note":           with(func(s map[string]any) { s["note"] = "sure" }),
		"automatic":      with(func(s map[string]any) { s["automatic"] = strings.Repeat("x", maxAutomaticBytes+1) }),
		"automatic ctl":  with(func(s map[string]any) { s["automatic"] = "a\x1bb" }),
		"no attachments": with(func(s map[string]any) { delete(s, "attachments") }),
		"null flags":     with(func(s map[string]any) { s["flags"] = nil }),
		"flag":           with(func(s map[string]any) { s["flags"] = []any{"approved"} }),
		"twice flag":     with(func(s map[string]any) { s["flags"] = []any{"truncated", "truncated"} }),
		"traversal":      with(attachment(func(a map[string]any) { a["path"] = "attachments/../../instructions.md" })),
		"nested":         with(attachment(func(a map[string]any) { a["path"] = "attachments/a/b.csv" })),
		"outside":        with(attachment(func(a map[string]any) { a["path"] = "message.md" })),
		"bare":           with(attachment(func(a map[string]any) { a["path"] = "attachments/" })),
		"negative":       with(attachment(func(a map[string]any) { a["size"] = -1 })),
		"wrong size":     with(attachment(func(a map[string]any) { a["size"] = 6 })),
		"content type":   with(attachment(func(a map[string]any) { a["contentType"] = "text/csv\r\nX: y" })),
		"attachment key": with(attachment(func(a map[string]any) { a["sha"] = "x" })),
		"listed twice": with(func(s map[string]any) {
			s["attachments"] = append(s["attachments"].([]any), s["attachments"].([]any)[0])
		}),
		"not listed":      with(func(s map[string]any) { s["attachments"] = []any{} }),
		"many":            with(func(s map[string]any) { s["attachments"] = make([]any, maxIntakeAttachments+1) }),
		"trailing":        []byte(`{"version":1} {}`),
		"not json":        []byte(`{"version":`),
		"array":           []byte(`[]`),
		"too big":         []byte(`{"instruction":"` + strings.Repeat("x", maxIntakeSpecBytes) + `"}`),
		"missing message": with(func(s map[string]any) { delete(s, "message") }),
	}
	for name, spec := range specs {
		if s, _, err := ReadIntake(writeIntakeOut(t, spec), testEdgeID); err == nil || !errors.Is(err, ErrIntake) {
			t.Errorf("%s: read %+v, %v", name, s, err)
		}
	}

	layouts := map[string]func(out string){
		"no spec":       func(out string) { os.Remove(filepath.Join(out, intakeSpecFile)) },
		"no message.md": func(out string) { os.Remove(filepath.Join(out, "message.md")) },
		"empty md":      func(out string) { os.WriteFile(filepath.Join(out, "message.md"), nil, 0o644) },
		"no intake":     func(out string) { os.Remove(filepath.Join(out, "intake.json")) },
		"extra file":    func(out string) { os.WriteFile(filepath.Join(out, "run.sh"), []byte("x"), 0o644) },
		"extra nested":  func(out string) { os.WriteFile(filepath.Join(out, "attachments", "02-x"), []byte("x"), 0o644) },
		"link": func(out string) {
			p := filepath.Join(out, "attachments", "01-statement.csv")
			os.Remove(p)
			os.Symlink("/etc/hosts", p)
		},
		"link dir": func(out string) { os.Symlink("/etc", filepath.Join(out, "etc")) },
		"big md": func(out string) {
			os.WriteFile(filepath.Join(out, "message.md"), make([]byte, maxMessageMDBytes+1), 0o644)
		},
		"many files": func(out string) {
			for i := range maxIntakeAttachments + 3 {
				os.WriteFile(filepath.Join(out, "attachments", strings.Repeat("f", 3)+string(rune('a'+i%26))+strings.Repeat("_", i/26)), nil, 0o644)
			}
		},
	}
	for name, change := range layouts {
		out := writeIntakeOut(t, goodIntakeSpec())
		change(out)
		if _, _, err := ReadIntake(out, testEdgeID); err == nil {
			t.Errorf("%s: read", name)
		}
	}
}

func testMail() *Mail {
	return &Mail{
		EdgeID: testEdgeID, ReceivedAt: time.Date(2026, 11, 18, 23, 30, 0, 0, time.UTC).UnixMilli(),
		CheckJSON: json.RawMessage(`{"v":1,"from":{"address":"owner@example.com"},"headers":{"subject":"Reconcile"}}`),
		Raw:       []byte("From: owner@example.com\r\n\r\nPlease reconcile.\r\n"),
	}
}

// intakeScript stands in for fount-runner --mode intake: it checks its
// input and writes out/ as the real one does.
const intakeScript = `
[ "$1" = "--mode" ] && [ "$2" = "intake" ] && [ "$3" = "--workspace" ] && [ $# -eq 4 ] || exit 2
d="$4"
grep -q '"id":"e41c"' "$d/check.json" && grep -q '"handle":"h_1"' "$d/check.json" || exit 3
grep -q '"turn":"request"' "$d/request.json" || exit 4
[ "$(cat "$d/instructions.md")" = "Reconcile vendor statements." ] || exit 5
[ -f "$d/message.eml" ] || exit 6
mkdir -p "$d/out/attachments"
printf 'md' > "$d/out/message.md"
printf '{}' > "$d/out/intake.json"
printf 'a,b\n1' > "$d/out/attachments/01-statement.csv"
cat > "$d/out/jobspec.json" <<'EOF'
{"version":1,"parserVersion":2,"message":"e41c","instruction":"Reconcile vendor statements.","instructionSource":"worker","note":"none","reply":false,"attachments":[{"path":"attachments/01-statement.csv","contentType":"text/csv","size":5,"inline":false}],"flags":[]}
EOF
echo '{"event":"intake-finished"}'
`

func newIntakeCoordinator(t *testing.T, script string) (*Coordinator, Worker) {
	t.Helper()
	key, _ := NewWrappingKey()
	dir := t.TempDir()
	c, err := New(Config{
		StateDir: filepath.Join(dir, "state"), WorkDir: filepath.Join(dir, "work"),
		Store: DirStore{Root: filepath.Join(dir, "objects")}, Key: key, Pool: NewPool(1, 2, nil),
		Runner: summaryRunner{}, Intake: LocalRunner{Command: []string{"/bin/sh", "-c", script, "sh"}, Timeout: 10 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	w, err := c.CreateWorker("acme", nil)
	if err != nil {
		t.Fatal(err)
	}
	return c, w
}

func TestTheCoordinatorRunsIntakeAndMakesTheJob(t *testing.T) {
	c, w := newIntakeCoordinator(t, intakeScript)
	c.PutFile(w.ID, "instructions.md", []byte("Reconcile vendor statements."))
	m := testMail()
	r, err := c.Intake(context.Background(), w.ID, m, IntakeRequest{ReplyHandle: "h_1"})
	if err != nil {
		t.Fatalf("%v: %s", err, r.Stderr)
	}
	if r.Spec.InstructionSource != "worker" || string(r.Files["message.eml"]) != string(m.Raw) || len(r.Files) != 4 {
		t.Fatalf("result %+v", r)
	}
	if !strings.Contains(string(r.Events), "intake-finished") {
		t.Errorf("events %s", r.Events)
	}
	folder := MessageFolder(m)
	if folder != "2026-11-18-"+testEdgeID {
		t.Errorf("folder %s", folder)
	}
	spec, err := r.Spec.JobSpec("t_1", "s_1", folder, json.RawMessage(`{"model":"m"}`))
	if err != nil {
		t.Fatal(err)
	}
	if spec.Message != "threads/t_1/"+folder || spec.Instruction != "Reconcile vendor statements." {
		t.Fatalf("job spec %+v", spec)
	}
	job, _ := spec.runnerJob()
	if !strings.Contains(string(job), `"message":"threads/t_1/`+folder+`"`) {
		t.Errorf("runner job %s", job)
	}
	if entries, _ := os.ReadDir(c.cfg.WorkDir); len(entries) != 0 {
		t.Errorf("intake left %d folders behind", len(entries))
	}
}

func TestAFailedIntakeIsRefused(t *testing.T) {
	for name, script := range map[string]string{
		"exit":       `echo '{"event":"intake-failed"}'; exit 1`,
		"no output":  `exit 0`,
		"extra file": strings.Replace(intakeScript, `echo '{"event":"intake-finished"}'`, `printf x > "$d/out/extra"`, 1),
	} {
		c, w := newIntakeCoordinator(t, script)
		c.PutFile(w.ID, "instructions.md", []byte("Reconcile vendor statements."))
		if _, err := c.Intake(context.Background(), w.ID, testMail(), IntakeRequest{ReplyHandle: "h_1"}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c, w := newIntakeCoordinator(t, intakeScript)
	c.cfg.Intake = nil
	if _, err := c.Intake(context.Background(), w.ID, testMail(), IntakeRequest{}); !errors.Is(err, ErrIntake) {
		t.Errorf("no intake runner: %v", err)
	}
}

func TestAMailJobNamesAFolderOfItsThread(t *testing.T) {
	for _, message := range []string{"threads/t_1/a", "threads/t_1/2026-11-18-e1"} {
		s := spec("t_1")
		s.Message = message
		if err := s.check(); err != nil {
			t.Errorf("%s: %v", message, err)
		}
	}
	for _, message := range []string{"threads/t_2/a", "threads/t_1", "threads/t_1/", "threads/t_1/a/b", "threads/t_1/..", "instructions.md", "threads/t_1/a\x00"} {
		s := spec("t_1")
		s.Message = message
		if err := s.check(); err == nil {
			t.Errorf("%q accepted", message)
		}
	}
}

func TestIntakeInputIsWhatTheRunnerReads(t *testing.T) {
	dir := t.TempDir()
	if err := writeIntakeInput(dir, testMail(), IntakeRequest{ReplyFolder: "threads/t_1/2026-11-17-e9"}, []byte("  ")); err != nil {
		t.Fatal(err)
	}
	var check map[string]any
	data, _ := os.ReadFile(filepath.Join(dir, "check.json"))
	json.Unmarshal(data, &check)
	if check["id"] != testEdgeID || check["senderCheck"].(map[string]any)["from"] == nil || check["replyToken"] != nil {
		t.Errorf("check.json %s", data)
	}
	if request, _ := os.ReadFile(filepath.Join(dir, "request.json")); string(request) != `{"folder":"threads/t_1/2026-11-17-e9","turn":"reply"}` {
		t.Errorf("request.json %s", request)
	}
	if _, err := os.Stat(filepath.Join(dir, "instructions.md")); err == nil {
		t.Error("blank instructions were written")
	}
	if err := writeIntakeInput(t.TempDir(), testMail(), IntakeRequest{ReplyFolder: "../x"}, nil); err == nil {
		t.Error("a bad reply folder was written")
	}
}
