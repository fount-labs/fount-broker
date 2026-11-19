package coordinator

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"time"
)

// What the coordinator owes a message once it is acted on: its intake, when
// it runs, and the fixed acknowledgement, when that is on. Each is staged in
// record/mail/pending.json in the same tree change as the thread operation,
// then done after the commit, then dropped in a change of its own. A crash
// between leaves it pending, and the next sync does it again, so each hook
// must be idempotent by the message's edge id.

// Intake turns a stored message into the turn it asks for: lane C's intake
// runner (fount-runner --mode intake), then the agent job its JobSpec
// describes. Queue is called once the thread names the message as run, and
// again after a crash until it returns nil, so it must be idempotent by
// IntakeRequest.EdgeID. It must not wait for the runner.
type Intake interface {
	Queue(ctx context.Context, req IntakeRequest) error
}

// IntakeRequest is one message to run on a thread.
type IntakeRequest struct {
	WorkerID string
	ThreadID string
	EdgeID   string
	// Stored is the message's path in the worker's tree, opaque bytes.
	Stored string
	// JobID is the job the thread names for this message's turn. Intake
	// queues the turn's agent job under it, so the thread follows it.
	JobID string
	// Requester is the checked sender when the mail ran by itself.
	Requester string
	// Instruction is what someone typed running held mail (runHeldMail), or
	// empty for the worker's standing instructions. It is never the email's
	// text (message-format.md §2).
	Instruction string
}

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
	Kind        string `json:"kind"` // "intake" or "ack"
	ThreadID    string `json:"threadId"`
	EdgeID      string `json:"edgeId"`
	JobID       string `json:"jobId,omitempty"`
	Requester   string `json:"requester,omitempty"`
	Instruction string `json:"instruction,omitempty"`
}

const (
	pendingIntake = "intake"
	pendingAck    = "ack"
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
	if slices.Contains(list, p) {
		return nil
	}
	return writeJSON(t, mailPendingPath, append(list, p))
}

// mailJobID is the job a message's turn runs as: one per message, so a
// retried intake finds the job it queued.
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
		case pendingIntake:
			err = c.intake().Queue(ctx, IntakeRequest{
				WorkerID: workerID, ThreadID: p.ThreadID, EdgeID: p.EdgeID, Stored: storedMailPath(p.EdgeID),
				JobID: p.JobID, Requester: p.Requester, Instruction: p.Instruction,
			})
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

// settle drops done from the pending list and names each queued intake's job
// on its thread, which follows it from then on.
func (c *Coordinator) settle(t *Tree, done []pendingMail) error {
	list, err := loadPending(t)
	if err != nil {
		return err
	}
	list = slices.DeleteFunc(list, func(p pendingMail) bool { return slices.Contains(done, p) })
	if err := writeJSON(t, mailPendingPath, list); err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, p := range done {
		if p.Kind != pendingIntake {
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

func (c *Coordinator) intake() Intake {
	if c.cfg.Mail.Intake != nil {
		return c.cfg.Mail.Intake
	}
	return directIntake{c}
}

// directIntake stands in for the intake runner (C) until it lands: it puts
// the message, unparsed, in the thread's folder and queues the turn's agent
// job with a fixed instruction pointing at it. The job reads the raw email;
// with C, it reads message.md and the attachments instead.
type directIntake struct{ c *Coordinator }

func (d directIntake) Queue(_ context.Context, req IntakeRequest) error {
	c := d.c
	if _, err := c.Job(req.JobID); err == nil {
		return nil
	}
	if len(c.cfg.JobConfig) == 0 {
		return refusal{code: CodeNoModel}
	}
	rel := "threads/" + req.ThreadID + "/mail/" + req.EdgeID + "/message.eml"
	var session string
	err := c.change(req.WorkerID, anyDevice, func(t *Tree) error {
		th, err := loadThread(t, req.ThreadID)
		if err != nil {
			return err
		}
		session = th.SessionID
		if t.Has(prefixRoot + rel) {
			return nil
		}
		raw, err := t.Read(req.Stored)
		if err != nil {
			return err
		}
		return t.Write(prefixRoot+rel, raw)
	})
	if err != nil {
		return err
	}
	instruction := fmt.Sprintf("An email for you is at %s. Read it and handle it as your instructions say.", rel)
	if req.Instruction != "" {
		instruction = req.Instruction + "\n\nThe email is at " + rel + "."
	}
	_, err = c.enqueueAs(anyDevice, req.WorkerID, req.JobID, JobSpec{
		ThreadID: req.ThreadID, SessionID: session, Instruction: instruction, Config: c.cfg.JobConfig,
	})
	return err
}
