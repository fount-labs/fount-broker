package coordinator

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"

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
// owner list: the requesters, and the team members who hear of its drafts
// (reviewers.go). It returns the settings as read, for the pass to compare
// the edge's listing with.
func (c *Coordinator) sendOwedSettings(ctx context.Context, w Worker) (*MailSettings, error) {
	var s *MailSettings
	var mb *Mailbox
	if err := c.view(w.ID, anyDevice, func(t *Tree) (err error) {
		if s, err = loadMailSettings(t); err != nil {
			return err
		}
		mb, err = loadMailbox(t)
		if errors.Is(err, ErrNoMailbox) {
			mb, err = nil, nil
		}
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
	notice, more := nextNoticeOwners(s.NoticeOwners, c.noticeOwnersWanted(w.ID, mb, s), len(s.Requesters))
	if s.RoutingUnsent || !slices.Equal(notice, s.NoticeOwners) {
		took, err := c.sendRouting(ctx, w, s, notice)
		if err != nil {
			errs = append(errs, fmt.Errorf("owners: %w", err))
		}
		if took && more {
			// The next member waits for the next pass, which is now.
			c.mail.kick(w.ID)
		}
	}
	return s, errors.Join(errs...)
}

// noticeOwnersWanted are the members who should be on w's owner list for
// notices: those who reach it, but aren't requesters already or addresses
// under the worker's own domain, which the edge never mails.
func (c *Coordinator) noticeOwnersWanted(workerID string, mb *Mailbox, s *MailSettings) []string {
	if mb == nil {
		return nil
	}
	var out []string
	for _, a := range c.memberAddresses(workerID) {
		if s.requester(a) == nil && !strings.HasSuffix(a, "@"+domainOf(mb.Address)) {
			out = append(out, a)
		}
	}
	return out
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

// sendRouting writes w's owner list: the requesters, then the notice
// owners notice. It reports whether the edge took a list with notice's new
// member in it.
func (c *Coordinator) sendRouting(ctx context.Context, w Worker, s *MailSettings, notice []string) (bool, error) {
	var proofs []mail.RoutingProof
	for _, p := range s.Proofs {
		proofs = append(proofs, mail.RoutingProof{Owner: p.Owner, MessageID: p.MessageID})
	}
	version := s.RoutingVersion + 1
	added := !isSubset(notice, s.NoticeOwners)
	var err error
	for tries := 0; tries < maxRoutingTries; {
		err = c.mail.service.SetRouting(ctx, w.Mailbox, version, routingOwners(s, notice), proofs)
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
		case mail.OwnerLimit(err) && added:
			// The day's new owners are used up: the member waits for a
			// later pass, and the rest of the list goes now.
			log.Printf("worker %s: the edge's new-owner limit holds a member's notices back for now", w.ID)
			notice = slices.DeleteFunc(slices.Clone(notice), func(a string) bool { return !slices.Contains(s.NoticeOwners, a) })
			added = false
			if !s.RoutingUnsent && slices.Equal(notice, s.NoticeOwners) {
				return false, nil
			}
			continue
		}
		break
	}
	switch {
	case err == nil:
		return added, c.changeMailSettings(w.ID, func(cur *MailSettings) bool {
			cur.RoutingVersion = max(cur.RoutingVersion, version)
			cur.NoticeOwners = notice
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
			return false, errors.Join(err, kept)
		}
	}
	return false, err
}

// routingOwners is the owner list for the edge: s's requesters, then the
// notice owners.
func routingOwners(s *MailSettings, notice []string) []string {
	owners := make([]string, 0, len(s.Requesters)+len(notice))
	for _, r := range s.Requesters {
		owners = append(owners, r.Address)
	}
	return append(owners, notice...)
}

func isSubset(a, b []string) bool {
	for _, v := range a {
		if !slices.Contains(b, v) {
			return false
		}
	}
	return true
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
