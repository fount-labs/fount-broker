package coordinator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
)

// A question is a saved wait (m4-cloud-runners.md §5.4): its job saved the
// session and ended waiting_for_you, and its turn summary put an open
// question on the thread (thread.go endTurn). The first valid answer, from
// the app or by email, settles it and starts a new job that resumes the
// saved session with the answer (JobSpec.Resume). A later one is refused.
//
// The thread operations, Desktop's Op (workers/thread/ops.rs), each naming
// the question and the rev of it the client saw (decision 5):
//
//	answerQuestion  {questionId, questionRev, text, answer?}  answer is the app form's {answers, annotations?}
//	dismissQuestion {questionId, questionRev}                 the ask resolves with no answers; the job goes on
//	forwardQuestion {questionId, questionRev, to}             a draft of the question to a requester on the thread
//
// Answering by email is answerByMail, for the mail path to call.

const (
	CodeAlreadyAnswered  OpCode = "ALREADY_ANSWERED"
	CodeQuestionClosed   OpCode = "QUESTION_CLOSED"
	CodeQuestionChanged  OpCode = "QUESTION_CHANGED"
	CodeAlreadyForwarded OpCode = "ALREADY_FORWARDED"
	CodeNotNotify        OpCode = "NOT_NOTIFY"
)

func init() {
	maps.Copy(opMessages, map[OpCode]string{
		CodeAlreadyAnswered:  "This was already answered.",
		CodeQuestionClosed:   "This question was closed when the job stopped.",
		CodeQuestionChanged:  "This question changed since you saw it. Look again, then try.",
		CodeAlreadyForwarded: "This question is already forwarded. Send or discard that draft.",
		CodeNotNotify:        "This thread is on Full, so the question was already emailed.",
	})
}

// A question's states past open, Desktop's QuestionStateView.
const (
	questionAnswered = "answered"
	questionClosed   = "closed"
)

// How an answer came.
const (
	viaApp   = "app"
	viaEmail = "email"
)

// maxResumeAnswer bounds a resume's answer: a form answer is held to
// maxNoteText, and an emailed one is its turn's instruction and a line.
const maxResumeAnswer = 2 * maxNoteText

// questionAnswer is who settled a question, how and when: Desktop's Answer,
// with the answer's text kept for drawing it.
type questionAnswer struct {
	// Device is the member's device for an answer in the app; Requester
	// the sender of an emailed one.
	Device    string    `json:"device,omitempty"`
	Requester string    `json:"requester,omitempty"`
	Via       string    `json:"via"`
	At        time.Time `json:"at"`
	Text      string    `json:"text,omitempty"`
	// Skipped is a dismissal.
	Skipped bool `json:"skipped,omitempty"`
	// JobID is the job that resumes the session with it.
	JobID string `json:"jobId,omitempty"`
}

// questionForward is a question forwarded to a requester: the draft it is
// sent as, once approved.
type questionForward struct {
	To      string    `json:"to"`
	Device  string    `json:"device"`
	At      time.Time `json:"at"`
	DraftID string    `json:"draftId"`
}

// ResumeSpec makes a job continue its thread's saved session: the wait it
// answers and the answer, as Desktop's answer_wait takes it. fount-runner
// (main.rs JobSpec.resume) answers the saved wait and runs the queued turn,
// with no new prompt.
type ResumeSpec struct {
	WaitID string          `json:"waitId"`
	Answer json.RawMessage `json:"answer"`
}

func (r *ResumeSpec) check() error {
	if r.WaitID == "" || len(r.WaitID) > maxWaitID || !plainText(r.WaitID) {
		return fmt.Errorf("%w: resume's waitId is out of range", ErrInvalid)
	}
	if len(r.Answer) == 0 || r.Answer[0] != '{' || len(r.Answer) > maxResumeAnswer || !json.Valid(r.Answer) {
		return fmt.Errorf("%w: resume's answer must be an object of at most %d bytes", ErrInvalid, maxResumeAnswer)
	}
	return nil
}

// questionArgs are the three operations' args, by kind.
type questionArgs struct {
	Kind        string          `json:"-"`
	QuestionID  string          `json:"questionId"`
	QuestionRev uint64          `json:"questionRev"`
	Text        string          `json:"text,omitempty"`
	Answer      json.RawMessage `json:"answer,omitempty"`
	To          string          `json:"to,omitempty"`
}

// The wire args of each kind, decoded strictly so a field of another kind is
// refused.
type (
	answerQuestionArgs struct {
		QuestionID  string          `json:"questionId"`
		QuestionRev uint64          `json:"questionRev"`
		Text        string          `json:"text"`
		Answer      json.RawMessage `json:"answer,omitempty"`
	}
	dismissQuestionArgs struct {
		QuestionID  string `json:"questionId"`
		QuestionRev uint64 `json:"questionRev"`
	}
	forwardQuestionArgs struct {
		QuestionID  string `json:"questionId"`
		QuestionRev uint64 `json:"questionRev"`
		To          string `json:"to"`
	}
)

// parseQuestionOp decodes a question operation's args, or reports the kind
// isn't one.
func parseQuestionOp(env opEnvelope) (any, bool, error) {
	var a questionArgs
	switch env.Kind {
	case "answerQuestion":
		var w answerQuestionArgs
		if err := decodeArgs(env.Args, &w); err != nil {
			return nil, true, err
		}
		a = questionArgs{QuestionID: w.QuestionID, QuestionRev: w.QuestionRev, Text: w.Text, Answer: w.Answer}
	case "dismissQuestion":
		var w dismissQuestionArgs
		if err := decodeArgs(env.Args, &w); err != nil {
			return nil, true, err
		}
		a = questionArgs{QuestionID: w.QuestionID, QuestionRev: w.QuestionRev}
	case "forwardQuestion":
		var w forwardQuestionArgs
		if err := decodeArgs(env.Args, &w); err != nil {
			return nil, true, err
		}
		a = questionArgs{QuestionID: w.QuestionID, QuestionRev: w.QuestionRev, To: strings.ToLower(strings.TrimSpace(w.To))}
		if a.To == "" {
			return nil, true, fmt.Errorf("%w: forwardQuestion needs to", ErrInvalid)
		}
	default:
		return nil, false, nil
	}
	a.Kind = env.Kind
	if a.QuestionRev == 0 {
		return nil, true, fmt.Errorf("%w: %s needs the questionRev the client saw", ErrInvalid, env.Kind)
	}
	return a, true, checkID("question", a.QuestionID)
}

// openQuestion is the open question id names on th, seen at rev. A question
// settled since is refused with what became of it, whatever rev was seen.
func openQuestion(th *threadRecord, id string, rev uint64) (*threadEntry, error) {
	e := th.entry(id)
	if e == nil || e.Kind != entryQuestion {
		return nil, refusal{code: CodeNotFound}
	}
	switch e.State {
	case questionOpen:
	case questionAnswered:
		return nil, refusal{code: CodeAlreadyAnswered, detail: e.Answer.detail()}
	default:
		return nil, refusal{code: CodeQuestionClosed}
	}
	if e.Rev != rev {
		return nil, refusal{code: CodeQuestionChanged}
	}
	return e, nil
}

// detail says who settled a question, how and when, for the refusal.
func (a *questionAnswer) detail() map[string]string {
	if a == nil {
		return nil
	}
	d := map[string]string{"via": a.Via, "at": a.At.UTC().Format(time.RFC3339)}
	if a.Requester != "" {
		d["by"] = a.Requester
	}
	if a.Skipped {
		d["skipped"] = "true"
	}
	return d
}

// applyQuestion applies one of the three to th as rev.
func (c *Coordinator) applyQuestion(t *Tree, th *threadRecord, device string, a questionArgs, rev uint64, now time.Time) ([]string, effects, error) {
	q, err := openQuestion(th, a.QuestionID, a.QuestionRev)
	if err != nil {
		return nil, effects{}, err
	}
	switch a.Kind {
	case "forwardQuestion":
		ids, err := c.forwardQuestion(t, th, q, device, a.To, rev, now)
		return ids, effects{}, err
	case "dismissQuestion":
		fx, err := c.settleQuestion(th, q, questionAnswer{Device: device, Via: viaApp, At: now, Skipped: true}, json.RawMessage(`{"answers":{}}`), rev)
		return []string{q.ID}, fx, err
	}
	text, err := noteText(a.Text)
	if err != nil {
		return nil, effects{}, err
	}
	payload, err := formAnswer(a.Answer, text)
	if err != nil {
		return nil, effects{}, err
	}
	fx, err := c.settleQuestion(th, q, questionAnswer{Device: device, Via: viaApp, At: now, Text: text}, payload, rev)
	return []string{q.ID}, fx, err
}

// formAnswer is the wait's answer: the app form's {answers, annotations?},
// which must answer something (skipping is dismissQuestion), or else text as
// the first question's answer, as Desktop's answer_question.
func formAnswer(raw json.RawMessage, text string) (json.RawMessage, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return json.Marshal(map[string]any{"answers": map[string]string{"0": text}})
	}
	var form struct {
		Answers     map[string]json.RawMessage `json:"answers"`
		Annotations json.RawMessage            `json:"annotations,omitempty"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&form); err != nil {
		return nil, fmt.Errorf("%w: answer: %v", ErrInvalid, err)
	}
	if len(form.Answers) == 0 {
		return nil, refusal{code: CodeEmptyText}
	}
	if len(raw) > maxNoteText {
		return nil, refusal{code: CodeTextTooLong}
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return nil, fmt.Errorf("%w: answer: %v", ErrInvalid, err)
	}
	return compact.Bytes(), nil
}

// settleQuestion marks q settled by ans and queues the job that resumes its
// session with payload.
func (c *Coordinator) settleQuestion(th *threadRecord, q *threadEntry, ans questionAnswer, payload json.RawMessage, rev uint64) (effects, error) {
	jobID, spec, err := c.resumeJob(th, q, payload)
	if err != nil {
		return effects{}, err
	}
	ans.JobID = jobID
	q.State, q.Rev, q.Answer = questionAnswered, rev, &ans
	th.Jobs = append(th.Jobs, threadJob{ID: jobID, State: JobQueued, Rev: rev})
	return effects{jobID: jobID, spec: spec}, nil
}

// resumeJob is the job that continues th's session from q's wait.
func (c *Coordinator) resumeJob(th *threadRecord, q *threadEntry, payload json.RawMessage) (string, JobSpec, error) {
	if len(c.cfg.JobConfig) == 0 {
		return "", JobSpec{}, refusal{code: CodeNoModel}
	}
	if len(th.Jobs) >= maxThreadJobs {
		return "", JobSpec{}, refusal{code: CodeThreadCap}
	}
	if len(payload) > maxResumeAnswer {
		return "", JobSpec{}, refusal{code: CodeTextTooLong}
	}
	id, err := newID("j")
	if err != nil {
		return "", JobSpec{}, err
	}
	spec := JobSpec{ThreadID: th.ID, SessionID: th.SessionID, Config: c.cfg.JobConfig, Resume: &ResumeSpec{WaitID: q.WaitID, Answer: payload}}
	return id, spec, spec.check()
}

// forwardQuestion is Desktop's forward_question: the question goes to a
// requester on the thread as a draft, which is sent only once approved.
// As Desktop does, it's refused on a thread on Full, where the question was
// already emailed. The draft is questionDraft's (draftquestion.go).
func (c *Coordinator) forwardQuestion(t *Tree, th *threadRecord, q *threadEntry, device, to string, rev uint64, now time.Time) ([]string, error) {
	if q.Forward != nil {
		return nil, refusal{code: CodeAlreadyForwarded}
	}
	allowed := th.hasParticipant(to)
	if allowed {
		s, err := loadMailSettings(t)
		if err != nil {
			return nil, err
		}
		allowed = s.requester(to) != nil
	}
	if !allowed {
		return nil, refusal{code: CodeRecipientNotAllowed, detail: map[string]string{"to": to}}
	}
	if th.replyMode() == modeFull {
		return nil, refusal{code: CodeNotNotify}
	}
	draft, err := c.questionDraft(t, th, q, to, rev, now)
	if err != nil {
		return nil, err
	}
	// The draft's push may have moved th's entries: find q again.
	q = th.entry(q.ID)
	q.Forward, q.Rev = &questionForward{To: to, Device: device, At: now, DraftID: draft}, rev
	return []string{draft}, nil
}

// answerByMail is the hook for an answer by email (§5.4), for the mail path
// to call while it places a requester's reply on th: one carrying a valid
// reply token for th, from sender, a participant, that would otherwise start
// a turn (verdictThreadReply). text is the turn's instruction for the reply,
// naming the email's folder, as Desktop's answer_by_email words it.
//
// If th's job is waiting on an open question, the reply answers it: the
// question is settled at rev, via email, by sender, and the returned spec
// resumes the saved session with the answer, to be queued as jobID the way
// the mail path queues a reply's turn (owe, then settle names it on th).
// Otherwise, as when someone answered first, or with no model settings, it
// returns nil and changes nothing: the reply is a reply, not an answer.
func (c *Coordinator) answerByMail(th *threadRecord, sender, text, jobID string, rev uint64, now time.Time) (*JobSpec, error) {
	sender = strings.ToLower(strings.TrimSpace(sender))
	if !th.hasParticipant(sender) {
		return nil, nil
	}
	q := th.waitingQuestion()
	if q == nil {
		return nil, nil
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, errors.New("an answer by email needs its instruction")
	}
	payload, err := json.Marshal(map[string]any{"answers": map[string]string{"0": text}})
	if err != nil {
		return nil, err
	}
	if len(c.cfg.JobConfig) == 0 {
		return nil, nil
	}
	spec := JobSpec{ThreadID: th.ID, SessionID: th.SessionID, Config: c.cfg.JobConfig, Resume: &ResumeSpec{WaitID: q.WaitID, Answer: payload}}
	if err := spec.check(); err != nil {
		return nil, err
	}
	q.State, q.Rev = questionAnswered, rev
	q.Answer = &questionAnswer{Requester: sender, Via: viaEmail, At: now, JobID: jobID}
	return &spec, nil
}

// waitingQuestion is th's open question whose job ended waiting on it, with
// no job since: the newest, as each turn asks at most one.
func (th *threadRecord) waitingQuestion() *threadEntry {
	if slices.ContainsFunc(th.Jobs, threadJob.unfinished) {
		return nil
	}
	for i := len(th.Entries) - 1; i >= 0; i-- {
		if e := &th.Entries[i]; e.Kind == entryQuestion && e.State == questionOpen {
			return e
		}
	}
	return nil
}

// closeQuestions closes th's open questions at rev: a note took over the
// session, so their waits are never resumed.
func (th *threadRecord) closeQuestions(rev uint64) {
	for i := range th.Entries {
		if e := &th.Entries[i]; e.Kind == entryQuestion && e.State == questionOpen {
			e.State, e.Rev = questionClosed, rev
		}
	}
}

// questionView is Desktop's Question entry: what a job ended waiting on and,
// once settled, the answer.
type questionView struct {
	entryHead
	WaitID   string              `json:"waitId,omitempty"`
	State    string              `json:"state"`
	Question string              `json:"question"`
	Detail   string              `json:"detail,omitempty"`
	Answer   *questionAnswerView `json:"answer,omitempty"`
	// Forwarded is who the question was forwarded to, and DraftID the draft
	// it is sent as. Desktop shows that draft as its own entry.
	Forwarded string `json:"forwarded,omitempty"`
	DraftID   string `json:"draftId,omitempty"`
}

// questionAnswerView is Desktop's QuestionAnswerView. By is "You" for an
// answer in the app, as notes are drawn, and the sender's address for an
// emailed one; ByDevice names the member's device, for a team's Home to put
// a name to.
type questionAnswerView struct {
	By       string `json:"by"`
	ByDevice string `json:"byDevice,omitempty"`
	Via      string `json:"via"`
	At       string `json:"at"`
	Text     string `json:"text"`
	Skipped  bool   `json:"skipped,omitempty"`
	JobID    string `json:"jobId,omitempty"`
}

func questionIn(head entryHead, e threadEntry) questionView {
	v := questionView{entryHead: head, WaitID: e.WaitID, State: e.State, Question: e.Text, Detail: e.Detail}
	if a := e.Answer; a != nil {
		by := "You"
		if a.Via == viaEmail {
			by = a.Requester
		}
		v.Answer = &questionAnswerView{
			By: by, ByDevice: a.Device, Via: a.Via, At: a.At.UTC().Format(time.RFC3339),
			Text: a.Text, Skipped: a.Skipped, JobID: a.JobID,
		}
	}
	if f := e.Forward; f != nil {
		v.Forwarded, v.DraftID = f.To, f.DraftID
	}
	return v
}
