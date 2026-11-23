package coordinator

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/fount-labs/fount-broker/internal/mail"
)

// One coordinator at a time (decision 18). With MailConfig.Generations the
// mail loop takes this coordinator's generation from the vault, presents it to
// the edge before anything else (POST /coordinator/generation), enrolls each
// Cloud mailbox under it the first time it reads that mailbox in this process
// (PUT /coordinator), and names it on every call after. When the edge says a
// newer generation has spoken, the loop stops for good: another coordinator
// owns the mail, and this one must not fetch or send it.

// generationRetry spaces out tries to get or present the generation.
const generationRetry = 30 * time.Second

// startGeneration gets the generation and presents it, trying again until ctx
// ends. It reports false when the mail loop must not run.
func (c *Coordinator) startGeneration(ctx context.Context) bool {
	m := c.mail
	for {
		err := c.presentGeneration(ctx)
		switch {
		case err == nil:
			log.Printf("mail: coordinator generation %d", m.service.Generation())
			m.notePhase(MailRunning)
			return true
		case errors.Is(err, mail.ErrStaleGeneration), errors.Is(err, mail.ErrGenerationConflict), errors.Is(err, mail.ErrBadCertificate):
			c.stopMail(err)
			return false
		}
		log.Printf("mail: couldn't present the coordinator generation: %v", err)
		m.noteError(fmt.Errorf("presenting generation %d: %w", m.service.Generation(), err))
		select {
		case <-ctx.Done():
			return false
		case <-time.After(generationRetry):
		}
	}
}

func (c *Coordinator) presentGeneration(ctx context.Context) error {
	m := c.mail
	if m.service.Generation() == 0 {
		g, err := m.cfg.Generations.Generation(ctx)
		if err != nil {
			return fmt.Errorf("the vault's generation: %w", err)
		}
		if err := m.service.SetGeneration(g); err != nil {
			return err
		}
	}
	return m.service.AdvanceGeneration(ctx)
}

// stopMail stops the mail loop for good, as a newer coordinator owns the mail.
func (c *Coordinator) stopMail(err error) {
	if c.mail.stale.CompareAndSwap(false, true) {
		c.mail.mu.Lock()
		c.mail.status.phase, c.mail.status.stopped = MailStopped, err.Error()
		c.mail.mu.Unlock()
		log.Printf("mail: STOPPED: %v. Another coordinator generation owns Cloud mail; this one reads and sends none", err)
	}
	if errors.Is(err, mail.ErrStaleGeneration) {
		c.retire(err)
	}
}

// enrollMail enrolls w's mailbox under the generation, once per process.
// Without a generation it does nothing.
func (c *Coordinator) enrollMail(ctx context.Context, w Worker) error {
	m := c.mail
	if m.service.Generation() == 0 {
		return nil
	}
	m.mu.Lock()
	done := m.enrolled[w.Mailbox]
	m.mu.Unlock()
	if done {
		return nil
	}
	if err := m.service.Enroll(ctx, w.Mailbox); err != nil {
		return fmt.Errorf("enrolling the mailbox: %w", err)
	}
	m.mu.Lock()
	m.enrolled[w.Mailbox] = true
	m.mu.Unlock()
	return nil
}

// fenced acts on an edge error about the generation: a newer one stops the
// loop; one the edge hasn't seen is presented again; a mailbox that wants a
// generation is enrolled again. It reports whether err was one.
func (c *Coordinator) fenced(ctx context.Context, mailbox string, err error) bool {
	m := c.mail
	switch {
	case errors.Is(err, mail.ErrStaleGeneration):
		c.stopMail(err)
	case errors.Is(err, mail.ErrUnknownGeneration):
		if m.cfg.Generations != nil {
			if perr := c.presentGeneration(ctx); errors.Is(perr, mail.ErrStaleGeneration) {
				c.stopMail(perr)
			}
		}
	case errors.Is(err, mail.ErrGenerationRequired):
		m.mu.Lock()
		delete(m.enrolled, mailbox)
		m.mu.Unlock()
	default:
		return false
	}
	return true
}

// EdgeChanges is MailChanges over the edge's POST /coordinator/changes,
// signed with the Service's generation. It lists only enrolled mailboxes, so
// a loop using it needs MailConfig.Generations.
type EdgeChanges struct{ Service *mail.Service }

func (e EdgeChanges) Changes(ctx context.Context, cursor string, limit int) (ChangesPage, error) {
	p, err := e.Service.Changes(ctx, cursor, limit)
	if err != nil {
		return ChangesPage{}, err
	}
	out := ChangesPage{Cursor: p.Cursor, More: p.More, Reset: p.Reset}
	for _, c := range p.Changes {
		out.Changes = append(out.Changes, MailboxChange{MailboxID: c.MailboxID, Changed: c.Changed, Sequence: c.Sequence, Paused: c.Paused, Lapsed: c.Lapsed})
	}
	return out, nil
}
