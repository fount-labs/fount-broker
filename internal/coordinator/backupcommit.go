package coordinator

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
)

// commitSecurity makes a change to security state (a team's log) durable
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
// Without Config.Backup (dev and tests) it is step 1 alone. Called with c.mu
// held.
func (c *Coordinator) commitSecurity() error {
	if c.Retired() {
		return ErrStaleCoordinator
	}
	d := c.durable
	ctx, cancel := context.WithTimeout(context.Background(), durableTimeout)
	defer cancel()
	if d != nil {
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
	}
	prev := c.state.SecuritySeq
	c.state.SecuritySeq++
	if err := c.state.Save(c.cfg.StateDir); err != nil {
		c.state.SecuritySeq = prev
		return err
	}
	if d == nil {
		return nil
	}
	if _, err := c.backupLocked(ctx); err != nil {
		return fmt.Errorf("%w: backing it up: %v", ErrNotDurable, err)
	}
	if err := d.cfg.Counter.CompareAndSwap(ctx, d.gen, d.counted, c.state.SecuritySeq); err != nil {
		if errors.Is(err, ErrVaultGeneration) || errors.Is(err, ErrVaultCount) {
			c.retire(err)
			return fmt.Errorf("%w: %v", ErrStaleCoordinator, err)
		}
		return fmt.Errorf("%w: counting it: %v", ErrNotDurable, err)
	}
	d.counted = c.state.SecuritySeq
	return nil
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
