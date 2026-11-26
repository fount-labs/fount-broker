package coordinator

import (
	"context"
	"crypto/ecdh"
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
//  3. the new seed becomes the signing key and the old one is dropped, and
//     the Service is given the new keys. Reply tokens aren't keyed from any
//     signing seed (Coordinator.mailKeys), so threads keep theirs and nothing
//     of the old key is kept;
//  4. the worker leaves Team.Rotate.
//
// The decryption key is rotated the same way, after the signing key (security
// review 2026-11-19, M1: a removed admin may have read it, and new mail sealed
// to it would be theirs to read from stored ciphertext). Mail the edge sealed
// to an older key before the rotation is still waiting there, so the old key
// is kept (Mailbox.OlderDecryptionKeys) and the Service opens such mail
// with it.

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

// rotateWorker rotates one worker's address signing key at the edge, then
// its decryption key.
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
	// A decryption key kept as next means an earlier pass rotated the
	// signing key and the edge didn't take the decryption key: retry that
	// alone, so an edge without the route doesn't get a new signing key
	// every pass.
	mb, err := c.workerMailbox(workerID)
	if err != nil {
		return err
	}
	if len(mb.NextDecryptionKey) == 0 {
		err := c.rotateKey(workerID, (*Mailbox).signingSlot, newSigningSeed, func(next []byte) error {
			return c.mail.service.RotateSigningKey(ctx, mailbox, ed25519.NewKeyFromSeed(next))
		})
		if err != nil {
			return err
		}
	}
	return c.rotateKey(workerID, (*Mailbox).decryptionSlot, newDecryptionKey, func(next []byte) error {
		k, err := ecdh.X25519().NewPrivateKey(next)
		if err != nil {
			return err
		}
		return c.mail.service.RotateDecryptionKey(ctx, mailbox, k)
	})
}

// keySlot is one of a mailbox's rotated keys: the key, the next one kept
// while it lands, and what to do with the one it replaces.
type keySlot struct {
	cur, next *[]byte
	retire    func(old []byte)
}

func (m *Mailbox) signingSlot() keySlot {
	// Nothing of an old signing seed is kept: reply tokens aren't keyed
	// from it (Coordinator.mailKeys).
	return keySlot{&m.SigningKey, &m.NextSigningKey, func([]byte) {}}
}

// maxOlderDecryptionKeys bounds the decryption keys kept after rotations,
// for mail the edge sealed to them before. The mail loop reads mail within
// seconds, so a key this many rotations old opens nothing still waiting.
const maxOlderDecryptionKeys = 8

func (m *Mailbox) decryptionSlot() keySlot {
	return keySlot{&m.DecryptionKey, &m.NextDecryptionKey, func(old []byte) {
		m.OlderDecryptionKeys = append([][]byte{old}, m.OlderDecryptionKeys...)
		if len(m.OlderDecryptionKeys) > maxOlderDecryptionKeys {
			m.OlderDecryptionKeys = m.OlderDecryptionKeys[:maxOlderDecryptionKeys]
		}
	}}
}

func newSigningSeed() ([]byte, error) {
	seed := make([]byte, ed25519.SeedSize)
	_, err := rand.Read(seed)
	return seed, err
}

func newDecryptionKey() ([]byte, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return k.Bytes(), nil
}

// rotateKey rotates one key of a worker's mailbox at the edge: the new key
// is kept first (so a retry after a lost answer asks for the same one, and
// mail sealed to it meanwhile opens), then the edge is told, then it
// becomes the key and the Service is given it.
func (c *Coordinator) rotateKey(workerID string, slot func(*Mailbox) keySlot, fresh func() ([]byte, error), tell func(next []byte) error) error {
	var next []byte
	err := c.change(workerID, anyDevice, func(t *Tree) error {
		mb, err := loadMailbox(t)
		if err != nil {
			return err
		}
		s := slot(mb)
		if len(*s.next) != 32 {
			if *s.next, err = fresh(); err != nil {
				return err
			}
			if err := writeJSON(t, mailboxPath, mb); err != nil {
				return err
			}
		}
		next = slices.Clone(*s.next)
		return nil
	})
	if err != nil {
		return err
	}
	if c.mail != nil {
		if keys, err := c.workerMailKeys(workerID); err == nil {
			c.mail.service.PutKeys(keys)
		}
	}
	if err := tell(next); err != nil && !mail.AlreadyCurrent(err) {
		return err
	}
	var keys *mail.Keys
	err = c.change(workerID, anyDevice, func(t *Tree) error {
		mb, err := loadMailbox(t)
		if err != nil {
			return err
		}
		s := slot(mb)
		if !slices.Equal(*s.next, next) {
			return fmt.Errorf("%w: the worker's mailbox changed while its key rotated", ErrInvalid)
		}
		s.retire(*s.cur)
		*s.cur, *s.next = next, nil
		if keys, err = c.mailKeys(mb); err != nil {
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

// workerMailbox is a worker's mailbox as its tree holds it now.
func (c *Coordinator) workerMailbox(workerID string) (*Mailbox, error) {
	var mb *Mailbox
	err := c.view(workerID, anyDevice, func(t *Tree) error {
		var err error
		mb, err = loadMailbox(t)
		return err
	})
	return mb, err
}

// workerMailKeys are a worker's mail keys as its tree holds them now.
func (c *Coordinator) workerMailKeys(workerID string) (*mail.Keys, error) {
	mb, err := c.workerMailbox(workerID)
	if err != nil {
		return nil, err
	}
	return c.mailKeys(mb)
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
	if err := c.commitSecurity(func() { t.Rotate = old }); err != nil {
		log.Printf("team %s: keeping that worker %s rotated: %v", team, workerID, err)
	}
}
