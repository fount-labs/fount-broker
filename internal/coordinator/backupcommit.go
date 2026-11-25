package coordinator

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"sync/atomic"
	"time"
)

// commitSecurity makes a change to security state (a team's log, or the
// workers' changes owed to the vault, countedtree.go) durable
// before it is acknowledged (docs/membership-list.md §4.2), in this order:
//
//  1. state.json, with the change and the next security sequence, is
//     written to the volume;
//  2. a backup root that includes it is written, here, not on the backup
//     loop's timer, so a crash before the next backup can't lose an
//     acknowledged removal;
//  3. the vault's counter moves to the new sequence, with a compare-and-swap
//     on (generation, previous count).
//
// A restore below the counter is refused (Restore), and a coordinator of an
// older generation can't move it, so it can't append; it is retired.
//
// A sequence number, once written, is never given again: when step 2 or 3
// fails the caller puts its change back in memory, the volume still has it
// until the next save, and the next change takes the number after. A crash
// in that window leaves a volume one change ahead of the counter; the next
// boot backs it up and counts it (openDurability), as a database keeps a
// committed transaction whose acknowledgement was lost. A client that saw
// the error finds its entry in the log, or appends again.
//
// A team's log change and a key rotation hold c.mu through all three, as
// the caller puts its change back under the same lock: at the rate people
// make them, each bounded by durableTimeout. The workers' changes are
// counted by countOff, which holds c.mu only to take the sequence and the
// cut (2026-11-25 re-check, R3-2); the two may be in flight together
// (swapCount).
//
// Without Config.Backup (dev and tests) it is step 1 alone. Called with c.mu
// held.
func (c *Coordinator) commitSecurity() (err error) {
	if c.Retired() {
		return ErrStaleCoordinator
	}
	d := c.durable
	ctx, cancel := context.WithTimeout(context.Background(), durableTimeout)
	defer cancel()
	if d != nil {
		defer func() { d.status.noteCount(err, time.Now()) }()
		// Refuse before writing anything when another generation has
		// taken over, so a stale coordinator's change reaches neither its
		// volume nor the bucket.
		count, err := d.cfg.Counter.Load(ctx)
		if err != nil {
			return fmt.Errorf("%w: the vault's counter: %v", ErrNotDurable, err)
		}
		if count.Generation != d.gen {
			err := fmt.Errorf("%w: the vault is at generation %d", ErrVaultGeneration, count.Generation)
			c.retire(err)
			return fmt.Errorf("%w: %v", ErrStaleCoordinator, err)
		}
		c.noteLoadedCount(count)
	}
	away, err := c.bumpSecurity()
	if err != nil || d == nil {
		return err
	}
	if _, err := c.backupLocked(ctx); err != nil {
		return fmt.Errorf("%w: backing it up: %v", ErrNotDurable, err)
	}
	if err := c.swapCount(ctx, d.counted.Load(), c.state.SecuritySeq, securityDigest(c.state)); err != nil {
		return err
	}
	c.countedAway(away)
	return nil
}

// bumpSecurity takes the next security sequence, folds in the workers'
// changes owed so far and saves the state. It returns the take-away changes
// that a count of this sequence covers (countedAway). On a failed save the
// state is as it was. Called with c.mu held.
func (c *Coordinator) bumpSecurity() (map[string]uint64, error) {
	prev, prevGen := c.state.SecuritySeq, c.state.SecurityGen
	c.state.SecuritySeq++
	if c.durable != nil {
		c.state.SecurityGen = c.durable.gen
	}
	away := maps.Clone(c.owedAway)
	undo := c.foldOwed()
	if err := c.state.Save(c.cfg.StateDir); err != nil {
		c.state.SecuritySeq, c.state.SecurityGen = prev, prevGen
		undo()
		return nil, err
	}
	return away, nil
}

// noteLoadedCount takes a count this generation made whose answer was lost:
// only this generation's key moves the count within it, so a count above
// the one confirmed and below the volume's sequence is one it sent, and
// the volume holds its state. A count at the volume's sequence is taken
// only if it counted this state: a team change whose answer was lost is
// put back, and the next save writes that sequence without it, which only
// a new count covers. Called with c.mu held.
func (c *Coordinator) noteLoadedCount(count VaultCount) {
	if count.Count < c.state.SecuritySeq || (count.Count == c.state.SecuritySeq && sameState(count, c.state)) {
		c.durable.noteCounted(count.Count)
	}
}

// maxSwapTries bounds swapCount's compare-and-swaps for one count.
const maxSwapTries = 4

// swapCount moves the vault's count from prev to next, the sequence of the
// state whose digest is digest. Two counts may be in flight at once, a
// team's change under c.mu and the workers' changes beside it (countOff),
// each from the count confirmed when it began. A swap that finds the count
// moved by this generation (only its key moves the count within it) since
// then is done when the count is already at next or past it, since every
// count is of a state that holds every change before it, and is tried again
// from that count when it is below. Anything else is a count this
// coordinator didn't make: it is retired. Needs no c.mu.
func (c *Coordinator) swapCount(ctx context.Context, prev, next uint64, digest string) error {
	d := c.durable
	for range maxSwapTries {
		err := casCount(ctx, d.cfg.Counter, d.gen, prev, next, digest)
		if err == nil {
			d.noteCounted(next)
			return nil
		}
		if errors.Is(err, ErrVaultGeneration) {
			c.retire(err)
			return fmt.Errorf("%w: %v", ErrStaleCoordinator, err)
		}
		if !errors.Is(err, ErrVaultCount) {
			return fmt.Errorf("%w: counting it: %v", ErrNotDurable, err)
		}
		count, lerr := d.cfg.Counter.Load(ctx)
		switch {
		case lerr != nil:
			return fmt.Errorf("%w: counting it: %v; then the vault's counter: %v", ErrNotDurable, err, lerr)
		case count.Generation != d.gen:
			err := fmt.Errorf("%w: the vault is at generation %d", ErrVaultGeneration, count.Generation)
			c.retire(err)
			return fmt.Errorf("%w: %v", ErrStaleCoordinator, err)
		case count.Count >= next:
			d.noteCounted(next)
			return nil
		case count.Count > prev:
			prev = count.Count
			continue
		}
		c.retire(err)
		return fmt.Errorf("%w: %v", ErrStaleCoordinator, err)
	}
	return fmt.Errorf("%w: counting it: the count moved under it %d times", ErrNotDurable, maxSwapTries)
}

// fence is whether this coordinator has been retired: a newer generation
// took over (decision 18). Retired, it serves no client, runs no job, reads
// and sends no mail and writes no backup.
type fence struct {
	retired atomic.Bool
	why     atomic.Pointer[string]
}

// retire stops this coordinator for good.
func (c *Coordinator) retire(err error) {
	if !c.fence.retired.CompareAndSwap(false, true) {
		return
	}
	why := err.Error()
	c.fence.why.Store(&why)
	if c.mail != nil {
		c.mail.stale.Store(true)
	}
	log.Printf("STOPPED: %v. A newer coordinator generation owns Cloud; this one serves nothing", err)
}

// Retired says whether a newer generation has taken over from this
// coordinator.
func (c *Coordinator) Retired() bool { return c.fence.retired.Load() }

// serving answers 503 for every request once the coordinator is retired, so
// a partitioned old coordinator doesn't serve reads under a stale log.
func (c *Coordinator) serving(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if c.Retired() {
			fail(rw, http.StatusServiceUnavailable, ErrStaleCoordinator)
			return
		}
		h.ServeHTTP(rw, r)
	})
}
