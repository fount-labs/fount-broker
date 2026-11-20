package coordinator

import (
	"context"
	"errors"
	"log"
	"slices"

	"github.com/fount-labs/fount-broker/internal/mail"
)

// Releasing a deleted worker's address at the edge (fount launch-plan X4).
// When a list leaves a worker out, or its team is deleted, commitEntry puts
// its mailbox in State.Releases in the same commit that forgets the worker.
// Each mail pass then asks the edge to remove it (POST /coordinator/remove)
// and takes it off once the edge answers: removed, removed before, or never
// held, enrolled or removable. Any other failure is retried next pass, and a
// restart resumes from the saved list.

// releaseDue removes the addresses of deleted workers at the edge.
func (c *Coordinator) releaseDue(ctx context.Context) {
	if c.mail == nil {
		return
	}
	c.mu.Lock()
	todo := slices.Clone(c.state.Releases)
	c.mu.Unlock()
	for _, mb := range todo {
		if ctx.Err() != nil {
			return
		}
		c.mail.service.DropKeys(mb)
		c.mail.mu.Lock()
		delete(c.mail.enrolled, mb)
		c.mail.mu.Unlock()
		err := c.mail.service.RemoveMailbox(ctx, mb)
		switch {
		case err == nil, errors.Is(err, mail.ErrNotFound):
			c.released(mb)
		case errors.Is(err, mail.ErrNotCoordinated), errors.Is(err, mail.ErrHandleKept):
			log.Printf("mail: a deleted worker's mailbox %s stays at the edge: %v", mb, err)
			c.released(mb)
		default:
			c.fenced(ctx, "", err)
			log.Printf("mail: removing a deleted worker's mailbox %s: %v", mb, err)
		}
	}
}

// releaseLocked queues the mailboxes of removed workers. Called with c.mu
// held, before the commit that forgets them; restore puts it back.
func (c *Coordinator) releaseLocked(removed []Worker) (restore func()) {
	old := c.state.Releases
	for _, w := range removed {
		if w.Mailbox != "" && !slices.Contains(c.state.Releases, w.Mailbox) {
			c.state.Releases = append(slices.Clone(c.state.Releases), w.Mailbox)
		}
	}
	return func() { c.state.Releases = old }
}

// released takes mailbox off the queue.
func (c *Coordinator) released(mailbox string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !slices.Contains(c.state.Releases, mailbox) {
		return
	}
	old := c.state.Releases
	c.state.Releases = slices.DeleteFunc(slices.Clone(old), func(m string) bool { return m == mailbox })
	if len(c.state.Releases) == 0 {
		c.state.Releases = nil
	}
	if err := c.state.Save(c.cfg.StateDir); err != nil {
		c.state.Releases = old
		log.Printf("mail: keeping mailbox %s queued for removal: %v", mailbox, err)
	}
}
