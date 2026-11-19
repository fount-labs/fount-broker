package coordinator

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log"
	"maps"
	"time"
)

// Cloud mailboxes renew themselves (decision 12). The edge bounces a mailbox's
// mail once its stored entitlement expiry passes (fount-mail-design.md §5), so
// once a day the coordinator asks fount-infra for a fresh entitlement for each
// Cloud mailbox and presents it to the edge (POST /entitlement), as Desktop's
// renew.rs does for its own, with every laptop closed.

// Entitlements is fount-infra's issuer of Cloud mailbox entitlements. It
// authenticates the coordinator by its attested key and names the account,
// and answers with an entitlement bound to the address's request-signing key,
// which only an account entitled to Cloud mail gets.
type Entitlements interface {
	Issue(ctx context.Context, req EntitlementRequest) (Entitlement, error)
}

type EntitlementRequest struct {
	Account   string
	WorkerID  string
	MailboxID string
	// SigningKey is the address's request-signing public key, which the
	// entitlement must be bound to (Desktop: Entitlement.check_device).
	SigningKey ed25519.PublicKey
}

// Entitlement is the token the edge takes in Fount-Entitlement, and when it
// was issued. GraceEnds is set while the account is past_due: the worker keeps
// working until then (decision 11, lapse.go). Once grace has ended, Issue
// refuses with an error wrapping ErrAccountLapsed.
type Entitlement struct {
	Token     string
	IssuedAt  time.Time
	GraceEnds time.Time
}

// Renewed is a mailbox's last renewal, kept in the worker's tree: when its
// entitlement was issued and the expiry the edge then held, and the last
// failure since, if any.
type Renewed struct {
	IssuedAt  time.Time `json:"issuedAt,omitzero"`
	ExpiresAt time.Time `json:"expiresAt,omitzero"`
	TriedAt   time.Time `json:"triedAt,omitzero"`
	Error     string    `json:"error,omitempty"`
	// GraceEnds is when the account's past_due grace ends, as last issued;
	// the renewal is asked again then. Lapsed is the worker paused for a
	// lapsed payment, and Notices the owner notices sent, by step.
	GraceEnds time.Time             `json:"graceEnds,omitzero"`
	Lapsed    *Lapse                `json:"lapsed,omitempty"`
	Notices   map[NoticeKind]string `json:"notices,omitempty"`
}

const (
	renewedPath = prefixMailRecord + "renewed.json"
	// renewAfter is Desktop's RENEW_AFTER_SECS.
	renewAfter = 24 * time.Hour
	// renewRetry spaces out tries after a failure.
	renewRetry = time.Hour
	// renewWarn is how near the edge's expiry gets before it's logged; the
	// owner's notice of it is D's (decision 10).
	renewWarn = 7 * 24 * time.Hour
)

func (r Renewed) due(now time.Time) bool {
	if r.Error != "" && now.Sub(r.TriedAt) < renewRetry {
		return false
	}
	if r.Lapsed != nil || !r.GraceEnds.IsZero() && !now.Before(r.GraceEnds) {
		return true
	}
	return r.IssuedAt.IsZero() || !now.Before(r.IssuedAt.Add(renewAfter))
}

// renewDue renews w's mailbox if a day has passed since the last renewal.
func (c *Coordinator) renewDue(ctx context.Context, w Worker, now time.Time) {
	m := c.mail
	if m.cfg.Entitlements == nil || !m.service.HasKeys(w.Mailbox) {
		return
	}
	m.mu.Lock()
	r, cached := m.renewed[w.ID]
	m.mu.Unlock()
	if !cached {
		if err := c.view(w.ID, anyDevice, func(t *Tree) error {
			_, err := readJSON(t, renewedPath, &r)
			return err
		}); err != nil {
			return
		}
	}
	r.Notices = maps.Clone(r.Notices)
	if !r.due(now) {
		sent := maps.Clone(r.Notices)
		r = c.holdNotices(ctx, w, r, now)
		if !maps.Equal(sent, r.Notices) {
			if err := c.change(w.ID, anyDevice, func(t *Tree) error { return writeJSON(t, renewedPath, r) }); err != nil {
				log.Printf("worker %s: couldn't keep its mailbox's renewal", w.ID)
			}
		}
		m.mu.Lock()
		m.renewed[w.ID] = r
		m.mu.Unlock()
		return
	}
	next, err := c.renew(ctx, w, r, now)
	if err != nil {
		c.fenced(ctx, w.Mailbox, err)
		log.Printf("worker %s: couldn't renew its mailbox: %v", w.ID, err)
	} else if next.ExpiresAt.Sub(now) < renewWarn {
		log.Printf("worker %s: its mailbox expires %s", w.ID, next.ExpiresAt.Format(time.RFC3339))
	}
	if serr := c.change(w.ID, anyDevice, func(t *Tree) error { return writeJSON(t, renewedPath, next) }); serr != nil {
		log.Printf("worker %s: couldn't keep its mailbox's renewal", w.ID)
	}
	m.mu.Lock()
	m.renewed[w.ID] = next
	m.mu.Unlock()
}

// renew asks for an entitlement and presents it. A failure keeps the last
// success and says why.
func (c *Coordinator) renew(ctx context.Context, w Worker, last Renewed, now time.Time) (Renewed, error) {
	m := c.mail
	var signing ed25519.PublicKey
	if err := c.view(w.ID, anyDevice, func(t *Tree) error {
		mb, err := loadMailbox(t)
		if err != nil {
			return err
		}
		keys, err := mb.keys()
		if err != nil {
			return err
		}
		signing = keys.SigningPublic()
		return nil
	}); err != nil {
		return failed(last, now, err), err
	}
	ent, err := m.cfg.Entitlements.Issue(ctx, EntitlementRequest{Account: w.Account, WorkerID: w.ID, MailboxID: w.Mailbox, SigningKey: signing})
	if errors.Is(err, ErrAccountLapsed) {
		return c.lapsed(ctx, w, last, now, err), err
	}
	if err == nil && ent.Token == "" {
		err = errors.New("fount-infra issued an empty entitlement")
	}
	if err != nil {
		return failed(last, now, err), err
	}
	renewal, err := m.service.RenewEntitlement(ctx, w.Mailbox, ent.Token)
	if err != nil {
		return failed(last, now, err), err
	}
	next := last
	next.IssuedAt, next.ExpiresAt, next.TriedAt, next.Error = ent.IssuedAt.UTC(), renewal.ExpiresAt, now.UTC(), ""
	next.GraceEnds = ent.GraceEnds.UTC()
	if ent.GraceEnds.IsZero() {
		next.GraceEnds = time.Time{}
	}
	next = c.resumed(ctx, w, next, now)
	if !next.GraceEnds.IsZero() {
		c.notice(ctx, w, &next, NoticePastDue, next.GraceEnds, next.GraceEnds)
	}
	return next, nil
}

func failed(last Renewed, now time.Time, err error) Renewed {
	last.TriedAt, last.Error = now.UTC(), err.Error()
	return last
}
