package coordinator

import (
	"cmp"
	"errors"
	"strings"
	"time"
)

const draftContentQuestion = "question"

// questionDraft is forwardQuestion's draft: the question q, asked of the
// requester to, as a draft on th at rev with its bytes, approved and sent
// like any other. It returns the draft's entry id. The caller checked to is a requester on th.
func (c *Coordinator) questionDraft(t *Tree, th *threadRecord, q *threadEntry, to string, rev uint64, now time.Time) (string, error) {
	mb, err := loadMailbox(t)
	if errors.Is(err, ErrNoMailbox) {
		return "", refusal{code: CodeNoMailbox}
	}
	if err != nil {
		return "", err
	}
	rs, err := loadReplySettings(t)
	if err != nil {
		return "", err
	}
	text := strings.TrimSpace(q.Text)
	if detail := strings.TrimSpace(q.Detail); detail != "" {
		text += "\n\n" + detail
	}
	d := &draftEntry{
		Content: draftContentQuestion, DraftRev: 1, State: draftPending, To: []string{strings.ToLower(to)},
		Subject: replySubject(th.Subject), AgentText: text, Text: text, QuestionID: q.ID,
	}
	th.replyTo(d, domainOf(mb.Address))
	id, err := th.push(rev, now, threadEntry{Kind: entryDraft, JobID: q.JobID, Draft: d})
	if err != nil {
		return "", err
	}
	if err := c.buildDraft(t, th, mb, rs, id, d, 1, now); err != nil {
		return "", err
	}
	return id, nil
}

// replyMode is the reply mode in force on th: off, notify or full.
// A thread with no email side is off.
func (th *threadRecord) replyMode() string {
	return cmp.Or(th.ReplyMode, modeOff)
}
