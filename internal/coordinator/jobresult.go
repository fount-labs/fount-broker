package coordinator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"unicode/utf8"
)

// A job's result for its thread comes from the runner's events
// (RunResult.Events, kept as jobs/<job id>/events.jsonl): fount-runner ends a
// job with a turn-summary event (src-tauri/crates/fount-runner/src/summary.rs
// in the Fount repo), what Desktop draws for a turn read from the session's
// transcript: the steps, the final text, and the question when the job ended
// waiting for an answer. The files the turn left come from the job's folder,
// not from the events (thread.go's jobFiles).
//
// The events are a runner's, so hostile: the one event is read with size
// limits and strictly, and an event that breaks any rule is ignored whole. The
// turn then shows its state and files, as before.

const turnSummaryEvent = "turn-summary"

// Limits on the summary, which fount-runner keeps to.
const (
	maxSummaryLine    = 1 << 20
	maxTurnText       = 128 << 10
	maxTurnSteps      = 500
	maxStepTarget     = 512
	maxQuestionText   = 32 << 10
	maxWaitID         = 128
	jobStateReady     = "ready_for_review"
	jobStateWaiting   = "waiting_for_you"
	jobStateRunFailed = "failed"
)

var stepVerbs = []string{"Read", "Searched", "Edited", "Ran", "Created"}

// turnSummary is the turn-summary event's payload.
type turnSummary struct {
	State    string        `json:"state"`
	Text     string        `json:"text,omitempty"`
	Steps    []workStep    `json:"steps"`
	Question *turnQuestion `json:"question,omitempty"`
}

// workStep is Desktop's WorkStep (view.rs): a tool call as "Read memo.docx".
type workStep struct {
	Verb   string `json:"verb"`
	Target string `json:"target"`
}

type turnQuestion struct {
	WaitID string `json:"waitId"`
	Text   string `json:"text"`
	Detail string `json:"detail,omitempty"`
}

var errNoSummary = errors.New("the job's events have no turn summary")

// readTurnSummary finds the turn summary in one job's events. Exactly one is
// taken; none, two, or one that breaks a rule is an error.
func readTurnSummary(events []byte) (*turnSummary, error) {
	var found *turnSummary
	for line := range bytes.SplitSeq(events, []byte("\n")) {
		// The decoder would quietly mend bad UTF-8; a runner never writes it.
		if len(line) > maxSummaryLine || !bytes.Contains(line, []byte(`"`+turnSummaryEvent+`"`)) || !utf8.Valid(line) {
			continue
		}
		var envelope struct {
			Event   string          `json:"event"`
			Payload json.RawMessage `json:"payload"`
		}
		if json.Unmarshal(line, &envelope) != nil || envelope.Event != turnSummaryEvent {
			continue
		}
		if found != nil {
			return nil, errors.New("the job's events have two turn summaries")
		}
		s, err := decodeTurnSummary(envelope.Payload)
		if err != nil {
			return nil, err
		}
		found = s
	}
	if found == nil {
		return nil, errNoSummary
	}
	return found, nil
}

func decodeTurnSummary(payload []byte) (*turnSummary, error) {
	s := &turnSummary{}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(s); err != nil {
		return nil, fmt.Errorf("the turn summary: %w", err)
	}
	if dec.More() {
		return nil, errors.New("the turn summary has trailing data")
	}
	if err := s.check(); err != nil {
		return nil, fmt.Errorf("the turn summary: %w", err)
	}
	return s, nil
}

func (s *turnSummary) check() error {
	switch {
	case s.State != jobStateReady && s.State != jobStateWaiting && s.State != jobStateRunFailed:
		return errors.New("unknown state")
	case len(s.Text) > maxTurnText || !utf8.ValidString(s.Text):
		return fmt.Errorf("text must be at most %d bytes of UTF-8", maxTurnText)
	case s.Steps == nil || len(s.Steps) > maxTurnSteps:
		return fmt.Errorf("steps must be a list of at most %d", maxTurnSteps)
	case s.Question != nil && s.State != jobStateWaiting:
		return errors.New("a question on a job that isn't waiting")
	}
	for _, step := range s.Steps {
		if !slices.Contains(stepVerbs, step.Verb) || step.Target == "" || len(step.Target) > maxStepTarget || !plainText(step.Target) {
			return errors.New("a step is out of range")
		}
	}
	if q := s.Question; q != nil {
		switch {
		case q.WaitID == "" || len(q.WaitID) > maxWaitID || !plainText(q.WaitID):
			return errors.New("the question's wait ID is out of range")
		case q.Text == "" || len(q.Text) > maxQuestionText || !utf8.ValidString(q.Text):
			return errors.New("the question's text is out of range")
		case len(q.Detail) > maxQuestionText || !utf8.ValidString(q.Detail):
			return errors.New("the question's detail is out of range")
		}
	}
	return nil
}
