package coordinator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Intake turns one received email into its message folder and a bounded
// JobSpec (launch-plan.md C, m4-cloud-runners.md §3.2). The coordinator parses
// no user content, so an intake runner reads the email: fount-runner --mode
// intake, with fount-mail, the parser Desktop runs, holding no keys and opening
// no connection. What comes back is hostile. ReadIntake takes only the files
// intake writes, and ParseIntakeSpec checks the JobSpec field by field and
// refuses it whole on any error.
//
// The runner's side is src-tauri/crates/fount-runner/src/intake.rs in the
// Fount repo; IntakeSpec is its Spec.

// An IntakeRunner runs fount-runner --mode intake for account on dir, a folder
// writeIntakeInput prepared. The runner leaves its output in dir/out.
type IntakeRunner interface {
	RunIntake(ctx context.Context, account, dir string) (RunResult, error)
}

// IntakeRequest is what intake needs beside the email.
type IntakeRequest struct {
	// ReplyHandle is the reply token's thread handle, when the email came to
	// a thread's reply address: then the owner's text above the quote is a
	// reply, not a note.
	ReplyHandle string
	// ReplyFolder makes the email the owner's reply on a thread: its folder
	// in the worker root. Empty is a new request.
	ReplyFolder string
}

// IntakeResult is one email's intake, checked.
type IntakeResult struct {
	Spec IntakeSpec
	// Files are the email's folder, by path in it: message.eml, message.md,
	// intake.json and attachments/…. They are written once under
	// threads/<thread id>/<MessageFolder>/.
	Files map[string][]byte
	// Events and Stderr are the runner's, for the job's logs.
	Events, Stderr []byte
}

// IntakeSpec is fount-runner's jobspec.json.
type IntakeSpec struct {
	Version       int    `json:"version"`
	ParserVersion int    `json:"parserVersion"`
	Message       string `json:"message"`
	// Instruction is the turn's instruction (message-format.md §2): the
	// owner's note, the worker's standing instructions, or Fount's text.
	Instruction       string             `json:"instruction"`
	InstructionSource string             `json:"instructionSource"`
	Note              string             `json:"note"`
	Reply             bool               `json:"reply"`
	Automatic         string             `json:"automatic,omitempty"`
	Attachments       []IntakeAttachment `json:"attachments"`
	Flags             []string           `json:"flags"`
}

type IntakeAttachment struct {
	// Path is attachments/<name>, in the email's folder.
	Path        string `json:"path"`
	ContentType string `json:"contentType"`
	Size        int64  `json:"size"`
	Inline      bool   `json:"inline"`
}

const (
	intakeSpecVersion   = 1
	maxIntakeSpecBytes  = 256 << 10
	maxParserVersion    = 1 << 16
	maxAutomaticBytes   = 200
	maxContentTypeBytes = 127
	// fount-mail's MAX_ATTACHMENTS.
	maxIntakeAttachments = 500
	// fount-mail's MAX_RENDERED_BYTES, with room for the headers.
	maxMessageMDBytes   = 9 << 20
	maxIntakeJSONBytes  = 2 << 20
	maxIntakeTotalBytes = 256 << 20
	intakeOut           = "out"
	intakeSpecFile      = "jobspec.json"
)

var (
	instructionSources = []string{"owner", "worker", "fount"}
	noteStatuses       = []string{"certain", "uncertain", "none"}
	// fount-mail's §3.6 flags.
	intakeFlags = []string{
		"plain_html_differ", "hidden_html_dropped", "stylesheet_may_hide", "attached_email", "bidi_in_filename",
		"extension_mismatch", "content_mismatch", "bidi_in_text", "signed_or_encrypted", "undecodable_part", "truncated",
	}
)

// ErrIntake is intake that failed or left something the coordinator refuses.
// Its message never quotes the email.
var ErrIntake = errors.New("intake")

// ParseIntakeSpec reads and checks an intake JobSpec for the email edgeID,
// failing closed.
func ParseIntakeSpec(b []byte, edgeID string) (IntakeSpec, error) {
	var s IntakeSpec
	if len(b) > maxIntakeSpecBytes {
		return IntakeSpec{}, fmt.Errorf("%w: the job spec is over %d bytes", ErrIntake, maxIntakeSpecBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return IntakeSpec{}, fmt.Errorf("%w: the job spec: %v", ErrIntake, err)
	}
	if dec.More() {
		return IntakeSpec{}, fmt.Errorf("%w: trailing data after the job spec", ErrIntake)
	}
	if err := s.check(edgeID); err != nil {
		return IntakeSpec{}, fmt.Errorf("%w: the job spec: %v", ErrIntake, err)
	}
	return s, nil
}

func (s IntakeSpec) check(edgeID string) error {
	switch {
	case s.Version != intakeSpecVersion:
		return fmt.Errorf("version %d, want %d", s.Version, intakeSpecVersion)
	case s.ParserVersion < 1 || s.ParserVersion > maxParserVersion:
		return errors.New("parser version out of range")
	case s.Message != edgeID:
		return errors.New("it names another message")
	case s.Instruction == "" || len(s.Instruction) > maxInstruction || !utf8.ValidString(s.Instruction):
		return fmt.Errorf("instruction must be 1 to %d bytes of UTF-8", maxInstruction)
	case !slices.Contains(instructionSources, s.InstructionSource):
		return errors.New("unknown instruction source")
	case !slices.Contains(noteStatuses, s.Note):
		return errors.New("unknown note status")
	case len(s.Automatic) > maxAutomaticBytes || !plainText(s.Automatic):
		return errors.New("automatic reason out of range")
	case s.Attachments == nil || len(s.Attachments) > maxIntakeAttachments:
		return fmt.Errorf("attachments must be a list of at most %d", maxIntakeAttachments)
	case s.Flags == nil || len(s.Flags) > len(intakeFlags):
		return errors.New("flags must be a short list")
	}
	seen := map[string]bool{}
	for _, f := range s.Flags {
		if !slices.Contains(intakeFlags, f) || seen[f] {
			return errors.New("unknown or repeated flag")
		}
		seen[f] = true
	}
	for _, a := range s.Attachments {
		name, ok := strings.CutPrefix(a.Path, "attachments/")
		switch {
		case !ok || name == "" || strings.Contains(name, "/") || checkPath(a.Path) != nil:
			return errors.New("an attachment's path isn't attachments/<name>")
		case seen[a.Path]:
			return errors.New("an attachment is listed twice")
		case a.Size < 0 || a.Size > maxFileBytes:
			return errors.New("an attachment's size is out of range")
		case len(a.ContentType) > maxContentTypeBytes || !plainText(a.ContentType):
			return errors.New("an attachment's content type is out of range")
		}
		seen[a.Path] = true
	}
	return nil
}

// plainText is valid UTF-8 with no control characters.
func plainText(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsFunc(s, unicode.IsControl)
}

// writeIntakeInput lays out what fount-runner --mode intake reads in dir.
func writeIntakeInput(dir string, m *Mail, req IntakeRequest, instructions []byte) error {
	type replyToken struct {
		Handle string `json:"handle"`
	}
	check := struct {
		ID               string          `json:"id"`
		ReceivedAt       int64           `json:"receivedAt"`
		SenderCheck      json.RawMessage `json:"senderCheck,omitempty"`
		SenderCheckError string          `json:"senderCheckError,omitempty"`
		ReplyToken       *replyToken     `json:"replyToken,omitempty"`
	}{ID: m.EdgeID, ReceivedAt: m.ReceivedAt, SenderCheck: m.CheckJSON, SenderCheckError: m.CheckError}
	if req.ReplyHandle != "" {
		check.ReplyToken = &replyToken{Handle: req.ReplyHandle}
	}
	request := map[string]string{"turn": "request"}
	if req.ReplyFolder != "" {
		if err := checkPath(req.ReplyFolder); err != nil {
			return err
		}
		request = map[string]string{"turn": "reply", "folder": req.ReplyFolder}
	}
	checkJSON, err := json.Marshal(check)
	if err != nil {
		return err
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return err
	}
	files := map[string][]byte{"message.eml": m.Raw, "check.json": checkJSON, "request.json": requestJSON}
	if len(bytes.TrimSpace(instructions)) > 0 {
		files["instructions.md"] = instructions
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, fileMode); err != nil {
			return err
		}
	}
	return nil
}

// ReadIntake reads back what intake left in out for the email edgeID: exactly
// message.md, intake.json, jobspec.json and the attachments the spec lists,
// each the size it says. Anything else, missing or over its limits refuses the
// whole intake.
func ReadIntake(out, edgeID string) (IntakeSpec, map[string][]byte, error) {
	// Sized before anything is read, so a runner can't fill the coordinator's
	// memory.
	var count, total int64
	err := filepath.WalkDir(out, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		count, total = count+1, total+info.Size()
		if count > maxIntakeAttachments+3 || total > maxIntakeTotalBytes {
			return fmt.Errorf("over %d files or %d bytes", maxIntakeAttachments+3, maxIntakeTotalBytes)
		}
		return nil
	})
	if err != nil {
		return IntakeSpec{}, nil, fmt.Errorf("%w: its output: %v", ErrIntake, err)
	}
	files := map[string][]byte{}
	var dropped []string
	err = walkFiles(out, &budget{}, func(rel string, data []byte) { files[rel] = data }, &dropped)
	switch {
	case err != nil:
		return IntakeSpec{}, nil, fmt.Errorf("%w: reading its output: %v", ErrIntake, err)
	case len(dropped) > 0:
		return IntakeSpec{}, nil, fmt.Errorf("%w: it left %d links or odd names", ErrIntake, len(dropped))
	}
	spec, err := ParseIntakeSpec(files[intakeSpecFile], edgeID)
	if err != nil {
		return IntakeSpec{}, nil, err
	}
	delete(files, intakeSpecFile)
	md, summary := files["message.md"], files["intake.json"]
	switch {
	case len(md) == 0 || len(md) > maxMessageMDBytes:
		return IntakeSpec{}, nil, fmt.Errorf("%w: message.md is missing or over %d bytes", ErrIntake, maxMessageMDBytes)
	case len(summary) == 0 || len(summary) > maxIntakeJSONBytes:
		return IntakeSpec{}, nil, fmt.Errorf("%w: intake.json is missing or over %d bytes", ErrIntake, maxIntakeJSONBytes)
	case len(files) != 2+len(spec.Attachments):
		return IntakeSpec{}, nil, fmt.Errorf("%w: it left files the job spec doesn't list", ErrIntake)
	}
	for _, a := range spec.Attachments {
		data, ok := files[a.Path]
		if !ok || int64(len(data)) != a.Size {
			return IntakeSpec{}, nil, fmt.Errorf("%w: an attachment is missing or not the size listed", ErrIntake)
		}
	}
	return spec, files, nil
}

// Intake runs intake on one email for a worker. The worker's standing
// instructions come from its instructions.md. Nothing is written to the
// worker's tree: the mail loop puts Files in the thread it picks, with
// MessageFolder, and queues r.Spec.JobSpec.
func (c *Coordinator) Intake(ctx context.Context, workerID string, m *Mail, req IntakeRequest) (IntakeResult, error) {
	if c.cfg.Intake == nil {
		return IntakeResult{}, fmt.Errorf("%w: no intake runner", ErrIntake)
	}
	w, err := c.Worker(workerID)
	if err != nil {
		return IntakeResult{}, err
	}
	var instructions []byte
	err = c.view(workerID, anyDevice, func(t *Tree) error {
		instructions, err = t.Read(prefixRoot + "instructions.md")
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	})
	if err != nil {
		return IntakeResult{}, err
	}
	dir, err := os.MkdirTemp(c.cfg.WorkDir, "intake-")
	if err != nil {
		return IntakeResult{}, err
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, dirMode); err != nil {
		return IntakeResult{}, err
	}
	if err := writeIntakeInput(dir, m, req, instructions); err != nil {
		return IntakeResult{}, err
	}
	run, err := c.cfg.Intake.RunIntake(ctx, w.Account, dir)
	r := IntakeResult{Events: run.Events, Stderr: run.Stderr}
	switch {
	case err != nil:
		return r, err
	case run.ExitCode != 0:
		return r, fmt.Errorf("%w: the runner failed it (exit %d)", ErrIntake, run.ExitCode)
	}
	if r.Spec, r.Files, err = ReadIntake(filepath.Join(dir, intakeOut), m.EdgeID); err != nil {
		return r, err
	}
	r.Files["message.eml"] = m.Raw
	return r, nil
}

// MessageFolder is an email's folder name in its thread: the day it arrived
// (UTC) and its edge ID (m4-cloud-runners.md §5.5).
func MessageFolder(m *Mail) string {
	return time.UnixMilli(m.ReceivedAt).UTC().Format("2006-01-02") + "-" + m.EdgeID
}

// JobSpec is the job for the email on threadID, its folder there folder (a
// MessageFolder), with the model settings config. The result is checked as
// every JobSpec is.
func (s IntakeSpec) JobSpec(threadID, sessionID, folder string, config json.RawMessage) (JobSpec, error) {
	spec := JobSpec{
		ThreadID: threadID, SessionID: sessionID, Instruction: s.Instruction, Config: config,
		Message: "threads/" + threadID + "/" + folder,
	}
	return spec, spec.check()
}

// RunIntake runs the command with --mode intake --workspace dir.
func (l LocalRunner) RunIntake(ctx context.Context, _, dir string) (RunResult, error) {
	if len(l.Command) == 0 {
		return RunResult{}, errors.New("no runner command")
	}
	if l.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, l.Timeout)
		defer cancel()
	}
	args := append(l.Command[1:len(l.Command):len(l.Command)], "--mode", "intake", "--workspace", dir)
	cmd := exec.CommandContext(ctx, l.Command[0], args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	stdout, stderr := &capped{max: maxEventBytes}, &capped{max: maxStderrBytes}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	result := RunResult{Events: stdout.Bytes(), Stderr: stderr.Bytes()}
	var exit *exec.ExitError
	switch {
	case err == nil:
	case ctx.Err() != nil:
		return result, fmt.Errorf("intake stopped: %w", ctx.Err())
	case errors.As(err, &exit):
		result.ExitCode = exit.ExitCode()
	default:
		return result, fmt.Errorf("start the intake runner: %w", err)
	}
	return result, nil
}

var _ IntakeRunner = LocalRunner{}
