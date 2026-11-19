package coordinator

import (
	"context"
	"errors"
	"log"
	"strconv"
	"time"
)

// Lapsing doesn't bounce mail (decision 11). What decides it is fount-infra's
// entitlement state for the account, as the daily renewal asks it
// (renew.go): during past_due grace Issue still answers, with GraceEnds set,
// and the worker keeps working; once grace ends, Issue refuses with
// ErrAccountLapsed. The renewal is asked again as soon as GraceEnds passes,
// not a day later. Then, for each of the account's workers:
//
//   - the coordinator pauses it: a requester's email is held, not run
//     (whyNotRun), and its mail is still fetched and held on its threads;
//   - it tells the edge (POST /coordinator/lapse), which holds the worker's
//     mail instead of bouncing it, until the entitlement's expiry plus 30
//     days, and refuses its sends;
//   - the owner is emailed at each step: past due, paused, a week before the
//     hold ends, mail bouncing, and resumed.
//
// When Issue answers again, the edge is told the worker resumed, and its
// renewal goes on as before.
//
// Not built: the export-only channel. A lapsed account's client channel
// closes at the end of its paid period (cloud-worker-devices.md §3.2), so
// export needs fount-infra to keep issuing a credential that opens only the
// read routes, and the channel to carry only those for it. Lapsed reports the
// state that channel would check.

// ErrAccountLapsed is fount-infra refusing an entitlement because the
// account's past_due grace has ended. An Entitlements implementation wraps it.
var ErrAccountLapsed = errors.New("the account's payment lapsed")

// OwnerNotices emails a worker's owner about a problem (decision 10):
// content-free, linked with fount://. D's notices implement it. Notify must
// be idempotent by Key: every worker of an account calls it with the same
// Key for the same account-wide step, and a retry repeats a Key.
type OwnerNotices interface {
	Notify(ctx context.Context, n OwnerNotice) error
}

// OwnerNotice is one notice. It names no mail content.
type OwnerNotice struct {
	Key      string
	Kind     NoticeKind
	Account  string
	WorkerID string
	// Until is the step's deadline: when grace ends (past due), or when the
	// edge stops holding mail (paused, hold ending). Zero when none.
	Until time.Time
}

type NoticeKind string

const (
	NoticePastDue    NoticeKind = "past_due"    // payment failed; the worker keeps working until Until
	NoticeLapsed     NoticeKind = "lapsed"      // the worker is paused; mail is held until Until
	NoticeHoldEnding NoticeKind = "hold_ending" // mail starts bouncing at Until
	NoticeBouncing   NoticeKind = "bouncing"    // the hold ended; mail bounces
	NoticeResumed    NoticeKind = "resumed"     // paid again; the worker runs
)

// holdWarning is how long before the hold ends the owner is warned.
const holdWarning = 7 * 24 * time.Hour

// Lapse is a worker paused for a lapsed payment, kept in its Renewed.
type Lapse struct {
	At time.Time `json:"at"`
	// Edge says the edge holds the worker's mail; until then the pause is
	// retried with the renewal, hourly.
	Edge      bool      `json:"edge"`
	HoldUntil time.Time `json:"holdUntil,omitzero"`
}

// lapsed applies fount-infra's refusal: the worker is paused, the edge told,
// and the owner told. It returns the Renewed to keep.
func (c *Coordinator) lapsed(ctx context.Context, w Worker, r Renewed, now time.Time, cause error) Renewed {
	r = failed(r, now, cause)
	if r.Lapsed == nil {
		r.Lapsed = &Lapse{At: now.UTC()}
		log.Printf("worker %s: paused, as its account's payment lapsed", w.ID)
	}
	if !r.Lapsed.Edge {
		st, err := c.mail.service.Lapse(ctx, w.Mailbox, true)
		if err != nil {
			c.fenced(ctx, w.Mailbox, err)
			log.Printf("worker %s: couldn't tell the edge to hold its mail: %v", w.ID, err)
		} else {
			r.Lapsed.Edge, r.Lapsed.HoldUntil = true, st.HoldUntil
		}
	}
	if r.Lapsed.Edge {
		c.notice(ctx, w, &r, NoticeLapsed, r.Lapsed.At, r.Lapsed.HoldUntil)
	}
	return c.holdNotices(ctx, w, r, now)
}

// resumed is the account paying again: the edge stops holding, and the owner
// is told. A failure leaves the worker lapsed, to try again.
func (c *Coordinator) resumed(ctx context.Context, w Worker, r Renewed, now time.Time) Renewed {
	if r.Lapsed == nil {
		return r
	}
	if r.Lapsed.Edge {
		if _, err := c.mail.service.Lapse(ctx, w.Mailbox, false); err != nil {
			c.fenced(ctx, w.Mailbox, err)
			log.Printf("worker %s: couldn't tell the edge it resumed: %v", w.ID, err)
			r.Error = "the account paid, but the edge still holds this worker's mail: " + err.Error()
			return r
		}
	}
	at := r.Lapsed.At
	r.Lapsed = nil
	c.notice(ctx, w, &r, NoticeResumed, at, time.Time{})
	log.Printf("worker %s: resumed, as its account paid", w.ID)
	return r
}

// holdNotices warns the owner a week before the edge's hold ends, and when it
// has, while the worker stays lapsed.
func (c *Coordinator) holdNotices(ctx context.Context, w Worker, r Renewed, now time.Time) Renewed {
	if r.Lapsed == nil || r.Lapsed.HoldUntil.IsZero() {
		return r
	}
	if !now.Before(r.Lapsed.HoldUntil.Add(-holdWarning)) {
		c.notice(ctx, w, &r, NoticeHoldEnding, r.Lapsed.At, r.Lapsed.HoldUntil)
	}
	if !now.Before(r.Lapsed.HoldUntil) {
		c.notice(ctx, w, &r, NoticeBouncing, r.Lapsed.At, r.Lapsed.HoldUntil)
	}
	return r
}

// notice sends one step's notice once: its key is the account, the step and
// when the episode began, so every worker of the account sends the same one.
func (c *Coordinator) notice(ctx context.Context, w Worker, r *Renewed, kind NoticeKind, episode, until time.Time) {
	key := w.Account + "/" + string(kind) + "/" + strconv.FormatInt(episode.Unix(), 10)
	if r.Notices[kind] == key {
		return
	}
	n := c.mail.cfg.Notices
	if n == nil {
		log.Printf("worker %s: no owner notices, so the owner isn't told: %s", w.ID, kind)
	} else if err := n.Notify(ctx, OwnerNotice{Key: key, Kind: kind, Account: w.Account, WorkerID: w.ID, Until: until}); err != nil {
		log.Printf("worker %s: couldn't send the owner's %s notice: %v", w.ID, kind, err)
		return
	}
	if r.Notices == nil {
		r.Notices = map[NoticeKind]string{}
	}
	r.Notices[kind] = key
}

// isLapsed says whether w is paused for a lapsed payment, as last kept.
func (m *mailLoop) isLapsed(workerID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.renewed[workerID]
	return ok && r.Lapsed != nil
}

// Lapsed reports whether any of account's workers is paused for a lapsed
// payment: what an export-only channel would check. Nothing consults it yet.
func (c *Coordinator) Lapsed(account string) bool {
	if c.mail == nil {
		return false
	}
	c.mu.Lock()
	var ids []string
	for _, w := range c.state.Workers {
		if w.Account == account {
			ids = append(ids, w.ID)
		}
	}
	c.mu.Unlock()
	for _, id := range ids {
		if c.mail.isLapsed(id) {
			return true
		}
	}
	return false
}

// mailRenewed is w's renewal as the loop last kept it.
func (c *Coordinator) mailRenewed(workerID string) Renewed {
	c.mail.mu.Lock()
	defer c.mail.mu.Unlock()
	return c.mail.renewed[workerID]
}
