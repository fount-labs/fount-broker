package coordinator

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"time"
)

// What the coordinator owes a message once it is acted on: the agent job of
// its turn, when it runs, and the fixed acknowledgement, when that is on.
// Each is staged in record/mail/pending.json in the same tree change as the
// thread operation and the ledger, then done after the commit, then dropped
// in a change of its own. A crash between leaves it pending, and the next
// sync does it again: the job is queued under an id made from the message's,
// so it is queued once, and the Acknowledger must be idempotent by edge id.

// Acknowledger sends the fixed acknowledgement (decision 8): a template, no
// model call, from the worker's address to the requester. D builds it on the
// send journal, with a Message-ID derived from EdgeID, so a retry sends it
// once.
type Acknowledger interface {
	Acknowledge(ctx context.Context, req AckRequest) error
}

type AckRequest struct {
	WorkerID string
	ThreadID string
	EdgeID   string
	To       string
}

type pendingMail struct {
	Kind     string `json:"kind"` // "job" or "ack"
	ThreadID string `json:"threadId"`
	EdgeID   string `json:"edgeId"`
	JobID    string `json:"jobId,omitempty"`
	// Spec is the turn's job, from intake's spec (IntakeSpec.JobSpec).
	Spec      *JobSpec `json:"spec,omitempty"`
	Requester string   `json:"requester,omitempty"`
}

const (
	pendingJob = "job"
	pendingAck = "ack"
)

func loadPending(t *Tree) ([]pendingMail, error) {
	var p []pendingMail
	_, err := readJSON(t, mailPendingPath, &p)
	return p, err
}

// owe stages p in the worker's pending list.
func owe(t *Tree, p pendingMail) error {
	list, err := loadPending(t)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(list, func(q pendingMail) bool { return q.Kind == p.Kind && q.EdgeID == p.EdgeID }) {
		return nil
	}
	return writeJSON(t, mailPendingPath, append(list, p))
}

// mailJobID is the job a message's turn runs as: one per message, so a
// retry finds the job it queued.
func mailJobID(edgeID string) string { return "jm_" + edgeID }

// runPending does what workerID's mail still owes, then drops what was done.
func (c *Coordinator) runPending(ctx context.Context, workerID string) error {
	var list []pendingMail
	if err := c.view(workerID, anyDevice, func(t *Tree) (err error) {
		list, err = loadPending(t)
		return err
	}); err != nil || len(list) == 0 {
		return err
	}
	var done []pendingMail
	var errs []error
	for _, p := range list {
		var err error
		switch p.Kind {
		case pendingJob:
			if _, err = c.Job(p.JobID); err == nil {
				break
			}
			if p.Spec == nil {
				err = fmt.Errorf("%w: a pending job has no spec", ErrInvalid)
				break
			}
			_, err = c.enqueueAs(anyDevice, workerID, p.JobID, *p.Spec)
		case pendingAck:
			if ack := c.cfg.Mail.Ack; ack != nil {
				err = ack.Acknowledge(ctx, AckRequest{WorkerID: workerID, ThreadID: p.ThreadID, EdgeID: p.EdgeID, To: p.Requester})
			}
		}
		if err != nil {
			// The error isn't logged: it can name the worker's files.
			log.Printf("worker %s: a message's %s didn't go through; it is retried", workerID, p.Kind)
			errs = append(errs, err)
			continue
		}
		done = append(done, p)
	}
	if len(done) > 0 {
		err := c.changeThen(workerID, anyDevice, func(t *Tree) error { return c.settle(t, done) }, c.poke)
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// settle drops done from the pending list and names each queued job on its
// thread, which follows it from then on. Until then the thread doesn't list
// it, so a thread read before a restart's sync doesn't fail it as lost.
func (c *Coordinator) settle(t *Tree, done []pendingMail) error {
	list, err := loadPending(t)
	if err != nil {
		return err
	}
	list = slices.DeleteFunc(list, func(p pendingMail) bool {
		return slices.ContainsFunc(done, func(d pendingMail) bool { return d.Kind == p.Kind && d.EdgeID == p.EdgeID })
	})
	if err := writeJSON(t, mailPendingPath, list); err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, p := range done {
		if p.Kind != pendingJob {
			continue
		}
		th, err := loadThread(t, p.ThreadID)
		if errors.Is(err, ErrNoThread) {
			continue
		}
		if err != nil {
			return err
		}
		e := th.mailOn(p.EdgeID)
		if e == nil || e.Mail.Intake != intakePending {
			continue
		}
		rev := th.Revision + 1
		e.Mail.Intake, e.Mail.JobID, e.Rev = intakeQueued, p.JobID, rev
		if th.job(p.JobID) == nil {
			th.Jobs = append(th.Jobs, threadJob{ID: p.JobID, State: JobQueued, Rev: rev})
		}
		th.finish(rev, now)
		if _, err := c.follow(t, th); err != nil {
			return err
		}
		if err := saveThread(t, th); err != nil {
			return err
		}
	}
	return nil
}
