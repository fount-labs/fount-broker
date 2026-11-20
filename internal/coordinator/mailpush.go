package coordinator

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/fount-labs/fount-broker/internal/mail"
)

// Since the security review (2026-11-19, H1) the edge takes an enrolled
// worker's owner list and pause only from its coordinator: POST
// /coordinator/routing and POST /coordinator/pause, signed by the current
// generation's key. The device's PUT /routing and passkey POST /pause refuse
// it. So a worker's settings say what the edge hasn't taken yet
// (MailSettings.RoutingUnsent, PauseUnsent), and each mail pass over the
// worker sends it, once the mailbox is enrolled, clearing the flag only once
// the edge has answered and only if nothing changed the part meanwhile.

// maxRoutingTries bounds the versions one pass tries when the edge says a
// version is stale: it holds a newer list than the coordinator knows, as when
// a device wrote one before the worker moved to Cloud. The highest version
// tried is kept, so the next pass goes on from there.
const maxRoutingTries = 8

// sendOwedSettings sends the edge what it hasn't taken of w's pause and
// requester list. It returns the settings as read, for the pass to compare
// the edge's listing with.
func (c *Coordinator) sendOwedSettings(ctx context.Context, w Worker) (*MailSettings, error) {
	var s *MailSettings
	if err := c.view(w.ID, anyDevice, func(t *Tree) (err error) {
		s, err = loadMailSettings(t)
		return err
	}); err != nil {
		return nil, err
	}
	if c.mail.service.Generation() == 0 {
		// Not enrolled: the edge takes these only from a coordinator.
		return s, nil
	}
	var errs []error
	if s.PauseUnsent {
		if err := c.sendPause(ctx, w, s); err != nil {
			errs = append(errs, fmt.Errorf("pause: %w", err))
		}
	}
	if s.RoutingUnsent {
		if err := c.sendRouting(ctx, w, s); err != nil {
			errs = append(errs, fmt.Errorf("requesters: %w", err))
		}
	}
	return s, errors.Join(errs...)
}

func (c *Coordinator) sendPause(ctx context.Context, w Worker, s *MailSettings) error {
	if err := c.mail.service.SetPaused(ctx, w.Mailbox, s.Paused); err != nil {
		return err
	}
	return c.changeMailSettings(w.ID, func(cur *MailSettings) bool {
		if cur.PausedRev != s.PausedRev || !cur.PauseUnsent {
			return false
		}
		cur.PauseUnsent = false
		return true
	})
}

func (c *Coordinator) sendRouting(ctx context.Context, w Worker, s *MailSettings) error {
	owners := make([]string, 0, len(s.Requesters))
	for _, r := range s.Requesters {
		owners = append(owners, r.Address)
	}
	var proofs []mail.RoutingProof
	for _, p := range s.Proofs {
		proofs = append(proofs, mail.RoutingProof{Owner: p.Owner, MessageID: p.MessageID})
	}
	version := s.RoutingVersion + 1
	var err error
	for tries := 0; tries < maxRoutingTries; {
		err = c.mail.service.SetRouting(ctx, w.Mailbox, version, owners, proofs)
		switch {
		case mail.ProofRefused(err) && len(proofs) > 0:
			// An expired or unverifiable reply: the requester stays, only
			// unproved, and the edge mails them a proof request.
			log.Printf("worker %s: the edge didn't take a requester's connect reply; sending the list without it", w.ID)
			proofs = nil
			continue
		case mail.StaleRouting(err):
			version++
			tries++
			continue
		}
		break
	}
	switch {
	case err == nil:
		return c.changeMailSettings(w.ID, func(cur *MailSettings) bool {
			cur.RoutingVersion = max(cur.RoutingVersion, version)
			if cur.RequestersRev == s.RequestersRev {
				cur.RoutingUnsent, cur.Proofs = false, nil
			}
			return true
		})
	case mail.StaleRouting(err):
		// version is one past the last the edge refused.
		refused := version - 1
		if kept := c.changeMailSettings(w.ID, func(cur *MailSettings) bool {
			if cur.RoutingVersion >= refused {
				return false
			}
			cur.RoutingVersion = refused
			return true
		}); kept != nil {
			return errors.Join(err, kept)
		}
	}
	return err
}

// takeEdgePause takes in the edge's pause, as its listing said, when the
// worker owes the edge no pause of its own: a pause from before the worker
// was enrolled, or the edge's own. s is the settings the pass read.
func (c *Coordinator) takeEdgePause(w Worker, s *MailSettings, edge *bool) error {
	if s == nil || edge == nil || s.PauseUnsent || s.Paused == *edge {
		return nil
	}
	return c.changeMailSettings(w.ID, func(cur *MailSettings) bool {
		if cur.PauseUnsent || cur.PausedRev != s.PausedRev || cur.Paused == *edge {
			return false
		}
		cur.Paused = *edge
		cur.PausedRev++
		return true
	})
}

// changeMailSettings applies fn to w's settings and keeps them when it says
// it changed them.
func (c *Coordinator) changeMailSettings(workerID string, fn func(*MailSettings) bool) error {
	return c.change(workerID, anyDevice, func(t *Tree) error {
		s, err := loadMailSettings(t)
		if err != nil {
			return err
		}
		if !fn(s) {
			return nil
		}
		return writeJSON(t, mailSettingsPath, s)
	})
}
