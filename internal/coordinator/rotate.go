package coordinator

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"slices"

	"github.com/fount-labs/fount-broker/internal/mail"
)

// Rotating a team worker's address signing key when the team loses an admin
// (launch-plan decision 25, teams.md §5). An admin's device could have read
// the worker's keys while it was one; once it isn't, the edge must stop
// taking that key. reduceTeam puts every worker of such a team in
// Team.Rotate, and the mail pass rotates each one at the edge:
//
//  1. a new seed is kept in the worker's mailbox record first, so a retry
//     after a lost answer asks for the same key;
//  2. POST /coordinator/signing-key with the new key's proof, signed by the
//     coordinator's generation key (mail.Service.RotateSigningKey); the
//     edge's 409 for the key it already has is the earlier attempt landing;
//  3. the new seed becomes the signing key, the old one is kept as the reply
//     seed (reply tokens are keyed from it, and threads keep theirs), and the
//     Service is given the new keys;
//  4. the worker leaves Team.Rotate.
//
// The decryption key isn't rotated: mail already delivered was sealed to it,
// and the edge holds no copy to re-seal.

// rotateDue rotates the address key of every worker a team marked, and
// drops from the marks those without a mailbox or gone.
func (c *Coordinator) rotateDue(ctx context.Context) {
	if c.mail == nil {
		return
	}
	type due struct{ team, worker string }
	var todo []due
	c.mu.Lock()
	for _, t := range c.state.Teams {
		for _, id := range t.Rotate {
			todo = append(todo, due{t.ID, id})
		}
	}
	c.mu.Unlock()
	for _, d := range todo {
		if ctx.Err() != nil {
			return
		}
		err := c.rotateWorker(ctx, d.worker)
		switch {
		case err == nil, errors.Is(err, ErrNoWorker), errors.Is(err, ErrNoMailbox):
			c.rotated(d.team, d.worker)
		default:
			c.fenced(ctx, "", err)
			log.Printf("worker %s: rotating its address key: %v", d.worker, err)
		}
	}
}

// rotateWorker rotates one worker's address signing key at the edge.
func (c *Coordinator) rotateWorker(ctx context.Context, workerID string) error {
	c.mu.Lock()
	w, ok := c.state.Workers[workerID]
	mailbox := ""
	if ok {
		mailbox = w.Mailbox
	}
	c.mu.Unlock()
	if !ok {
		return ErrNoWorker
	}
	if mailbox == "" {
		return ErrNoMailbox
	}
	var next []byte
	err := c.change(workerID, anyDevice, func(t *Tree) error {
		mb, err := loadMailbox(t)
		if err != nil {
			return err
		}
		if len(mb.NextSigningKey) != ed25519.SeedSize {
			mb.NextSigningKey = make([]byte, ed25519.SeedSize)
			if _, err := rand.Read(mb.NextSigningKey); err != nil {
				return err
			}
			if err := writeJSON(t, mailboxPath, mb); err != nil {
				return err
			}
		}
		next = slices.Clone(mb.NextSigningKey)
		return nil
	})
	if err != nil {
		return err
	}
	if err := c.mail.service.RotateSigningKey(ctx, mailbox, ed25519.NewKeyFromSeed(next)); err != nil && !mail.AlreadyCurrent(err) {
		return err
	}
	var keys *mail.Keys
	err = c.change(workerID, anyDevice, func(t *Tree) error {
		mb, err := loadMailbox(t)
		if err != nil {
			return err
		}
		if mb == nil || !slices.Equal(mb.NextSigningKey, next) {
			return fmt.Errorf("%w: the worker's mailbox changed while its key rotated", ErrInvalid)
		}
		if mb.ReplySeed == nil {
			mb.ReplySeed = mb.SigningKey
		}
		mb.SigningKey, mb.NextSigningKey = next, nil
		if keys, err = mb.keys(); err != nil {
			return err
		}
		return writeJSON(t, mailboxPath, mb)
	})
	if err != nil {
		return err
	}
	c.mail.service.PutKeys(keys)
	return nil
}

// rotated takes workerID off team's marks.
func (c *Coordinator) rotated(team, workerID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.state.Teams[team]
	if t == nil || !slices.Contains(t.Rotate, workerID) {
		return
	}
	old := t.Rotate
	t.Rotate = slices.DeleteFunc(slices.Clone(old), func(id string) bool { return id == workerID })
	if len(t.Rotate) == 0 {
		t.Rotate = nil
	}
	if err := c.commitSecurity(); err != nil {
		t.Rotate = old
		log.Printf("team %s: keeping that worker %s rotated: %v", team, workerID, err)
	}
}
