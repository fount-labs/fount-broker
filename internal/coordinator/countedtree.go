package coordinator

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"slices"
	"strings"
	"time"
)

// Workers' changes the vault counts (broker review M1). A tree change is a
// plain save unless it takes something away or moves the mail ledger on;
// a disk replayed to before such a change would bring back what it took
// (a requester, a reply mode, an approval email that still sends) or run
// mail again. So:
//
//   - a change that takes something away (Tree.countChange: a reply mode
//     lowered, an approval cancelled or its draft discarded, automatic runs
//     turned off, mail paused, a requester removed) is counted before it is
//     acknowledged, one vault round trip and one backup root each, at the
//     rate people make them;
//   - mail-ledger progress is counted at most once every ledgerCountEvery,
//     with everything owed since, by the mail loop and the backup loop: at
//     most 120 counted changes an hour however much mail comes in, each one
//     Load, a root and a compare-and-swap;
//   - a membership change (grants and revocations are the team's log) was
//     counted already.
//
// What is counted is each worker's tree version at its change, in
// State.Counted, which securityDigest covers: a volume at the vault's count
// with an older tree under it is a fork, and one behind the count is
// refused. Between counts a disk can still be replayed to any point after
// the last one; the boot sees that when a backup was taken after the point
// (replayedVolume) and treats the volume as a restore. What remains is a
// replay within one ledgerCountEvery and one backup interval of the end:
// that mail may run again.
const ledgerCountEvery = 30 * time.Second

// owe records that workerID's tree at version holds a change the vault
// should count, which takes something away when away is set. Called with
// c.mu held.
func (c *Coordinator) owe(workerID string, version uint64, away bool) {
	if c.durable == nil {
		return
	}
	if c.owed == nil {
		c.owed = map[string]uint64{}
	}
	c.owed[workerID] = max(c.owed[workerID], version)
	if away {
		if c.owedAway == nil {
			c.owedAway = map[string]uint64{}
		}
		c.owedAway[workerID] = max(c.owedAway[workerID], version)
	}
}

// countedAway drops the take-away changes a count covered: away is
// c.owedAway as the count's sequence was taken (bumpSecurity), and a later
// change to the same worker stays owed. Called with c.mu held.
func (c *Coordinator) countedAway(away map[string]uint64) {
	for id, v := range away {
		if c.owedAway[id] <= v {
			delete(c.owedAway, id)
		}
	}
}

// awayOwed is whether workerID has a take-away change the vault hasn't
// counted: one whose count failed, which its retry, finding the tree
// already changed, must count before it is acknowledged (2026-11-25
// re-check, R3-4). Called with c.mu held.
func (c *Coordinator) awayOwed(workerID string) bool {
	_, ok := c.owedAway[workerID]
	return ok
}

// countDue is whether anything saved is still uncounted: a worker's change,
// or a security change whose count failed after it was saved. Called with
// c.mu held.
func (c *Coordinator) countDue() bool {
	return c.durable != nil && (len(c.owed) > 0 || c.durable.counted.Load() < c.state.SecuritySeq)
}

// countOff counts what is owed now, holding c.mu only to take the next
// sequence and the cut of the volume, and then to drop what the count
// covered: the vault's counter, the root's upload and the compare-and-swap
// run without it, so a vault or bucket that hangs stalls nothing else
// (2026-11-25 re-check, R3-2). A change made meanwhile is counted by a later
// count; one in flight beside this one is reconciled by swapCount. A count
// that fails leaves its sequence uncounted, so countDue stays true and the
// next count covers it. Called without c.mu.
func (c *Coordinator) countOff(ctx context.Context) (err error) {
	d := c.durable
	if d == nil {
		return nil
	}
	if c.Retired() {
		return ErrStaleCoordinator
	}
	defer func() { d.status.noteCount(err, time.Now()) }()
	count, err := d.cfg.Counter.Load(ctx)
	if err != nil {
		return fmt.Errorf("%w: the vault's counter: %v", ErrNotDurable, err)
	}
	if count.Generation != d.gen {
		err := fmt.Errorf("%w: the vault is at generation %d", ErrVaultGeneration, count.Generation)
		c.retire(err)
		return fmt.Errorf("%w: %v", ErrStaleCoordinator, err)
	}
	c.mu.Lock()
	c.noteLoadedCount(count)
	if !c.countDue() {
		c.mu.Unlock()
		return nil
	}
	away, err := c.bumpSecurity()
	if err != nil {
		c.mu.Unlock()
		return err
	}
	next, digest, prev := c.state.SecuritySeq, securityDigest(c.state), d.counted.Load()
	cut, err := c.takeCut()
	d.store.hold()
	c.mu.Unlock()
	defer d.store.release()
	if err != nil {
		return err
	}
	if _, err := c.writeCut(ctx, cut); err != nil {
		return fmt.Errorf("%w: backing it up: %v", ErrNotDurable, err)
	}
	if err := c.swapCount(ctx, prev, next, digest); err != nil {
		return err
	}
	c.mu.Lock()
	c.countedAway(away)
	c.mu.Unlock()
	return nil
}

// countLedger counts the mail ledger's progress, at most every
// ledgerCountEvery and not while a count of it is in flight or backing off
// after a failure, in the background: the mail loop and the backup loop
// that call it don't wait on the vault.
func (c *Coordinator) countLedger(now time.Time) {
	d := c.durable
	if d == nil || c.Retired() {
		return
	}
	c.mu.Lock()
	due := c.countDue() && !c.counting && now.Sub(c.lastOwedCount) >= ledgerCountEvery && !d.status.countBackingOff(now)
	if due {
		c.counting = true
	}
	c.mu.Unlock()
	if !due {
		return
	}
	c.running.Go(func() {
		ctx, cancel := context.WithTimeout(context.Background(), durableTimeout)
		defer cancel()
		err := c.countOff(ctx)
		if err != nil {
			log.Printf("backup: counting the workers' changes: %v; tried again after a backoff", err)
		}
		c.mu.Lock()
		c.counting = false
		if err == nil {
			c.lastOwedCount = time.Now()
		}
		c.mu.Unlock()
	})
}

// foldOwed moves what is owed into st.Counted for commitSecurity, and drops
// workers no longer held. It returns how to put it back.
func (c *Coordinator) foldOwed() (undo func()) {
	was, owed := maps.Clone(c.state.Counted), c.owed
	for id, v := range c.owed {
		if c.state.Counted == nil {
			c.state.Counted = map[string]uint64{}
		}
		c.state.Counted[id] = max(c.state.Counted[id], v)
	}
	for id := range c.state.Counted {
		if _, ok := c.state.Workers[id]; !ok {
			delete(c.state.Counted, id)
		}
	}
	c.owed = nil
	return func() { c.state.Counted, c.owed = was, owed }
}

// replayedVolume is the backup root that shows this volume is behind it, or
// nil: the newest root that opens, when it was taken from a later save than
// the volume's, so the disk was replayed to an earlier point (or lost its
// last writes) after it was taken. A root that doesn't open is passed over:
// a bucket writer can plant one, not forge one. Called with c.mu held.
func (c *Coordinator) replayedVolume(ctx context.Context, roots []rootRef) (*backupRoot, error) {
	for i := len(roots) - 1; i >= 0; i-- {
		root, err := openRoot(ctx, c.durable.cfg.Bucket, c.durable.key, roots[i])
		if err != nil {
			log.Printf("backup: %v; checking the volume against the one before", err)
			continue
		}
		st, err := rootState(root)
		if err != nil {
			log.Printf("backup: %v; checking the volume against the one before", err)
			continue
		}
		ahead := st.SecuritySeq > c.state.SecuritySeq || (st.SecuritySeq == c.state.SecuritySeq && st.Saves > c.state.Saves)
		if !ahead {
			return nil, nil
		}
		return root, nil
	}
	return nil, nil
}

// treatAsRestored is a volume replayedVolume found behind root: it is run
// as a restore of itself (restore.go). Its queued jobs and the turns its mail
// owed are failed, since they may have run since; mail received before now
// that its ledger doesn't have is held for a person. Called with c.mu held.
func (c *Coordinator) treatAsRestored(root *backupRoot) error {
	now := time.Now().UTC()
	owed := map[string]pendingMail{}
	owedBy := map[string]string{}
	for _, id := range slices.Sorted(maps.Keys(c.state.Workers)) {
		w := c.state.Workers[id]
		if w.WrappedDEK == nil {
			continue
		}
		ring, err := c.cfg.Key.Keyring(w)
		if err != nil {
			return err
		}
		t, err := LoadTreeKeys(c.cfg.Store, id, ring, w.Version)
		if err != nil {
			ring.Clear()
			return fmt.Errorf("worker %s: %w", id, err)
		}
		pending, err := loadPending(t)
		ring.Clear()
		if err != nil {
			return fmt.Errorf("worker %s: %w", id, err)
		}
		for _, p := range pending {
			if p.Kind == pendingJob && p.JobID != "" {
				owed[p.JobID], owedBy[p.JobID] = p, id
			}
		}
	}
	stopped := stopRestoredWork(c.state, owed, owedBy, now)
	c.state.Restored = &RestoreMark{At: now, Root: root.ref.key, TakenAt: root.taken.UTC()}
	log.Printf("backup: the volume is behind backup %s, taken %s: it was replayed or lost writes, so it runs as a restore: %d jobs stopped, earlier mail held",
		root.ref.key, root.taken.UTC().Format(time.RFC3339), stopped)
	return c.state.Save(c.cfg.StateDir)
}

// stopRestoredWork fails the jobs queued or running on a restored state, and
// records the turns its mail owed as failed. It returns how many it stopped.
func stopRestoredWork(st *State, owed map[string]pendingMail, owedBy map[string]string, now time.Time) int {
	n := 0
	for _, j := range st.Jobs {
		if j.State == JobQueued || j.State == JobRunning {
			j.State, j.Spec, j.Error, j.Ended = JobFailed, nil, restoredJobError, now
			n++
		}
	}
	for _, jobID := range slices.Sorted(maps.Keys(owed)) {
		if _, ok := st.Jobs[jobID]; ok {
			continue
		}
		st.Seq++
		st.Jobs[jobID] = &Job{ID: jobID, WorkerID: owedBy[jobID], Seq: st.Seq, State: JobFailed, ThreadID: owed[jobID].ThreadID,
			Error: restoredJobError, Queued: now, Ended: now}
		n++
	}
	return n
}

// noteTakenAway marks t's change counted when data, about to replace the
// worker's mail or reply settings at path, takes away what they allowed: a
// requester removed or their automatic runs turned off, automatic runs
// turned off, mail paused, the reply mode lowered or its owner changed.
func (t *Tree) noteTakenAway(path string, data []byte) error {
	switch path {
	case mailSettingsPath:
		was, err := loadMailSettings(t)
		if err != nil {
			return err
		}
		var now MailSettings
		if err := json.Unmarshal(data, &now); err != nil {
			return err
		}
		if was.AutoRun && !now.AutoRun || !was.Paused && now.Paused || droppedRequester(was.Requesters, now.Requesters) {
			t.countChange()
		}
	case replySettingsPath:
		was, err := loadReplySettings(t)
		if err != nil {
			return err
		}
		var now replySettings
		if err := json.Unmarshal(data, &now); err != nil {
			return err
		}
		if defaultModeRank(now.Mode) < defaultModeRank(was.Mode) || was.Owner != "" && now.Owner != was.Owner {
			t.countChange()
		}
	}
	return nil
}

// droppedRequester is whether now lacks a requester was had, or has one's
// automatic runs off that was had on.
func droppedRequester(was, now []Requester) bool {
	for _, r := range was {
		i := slices.IndexFunc(now, func(q Requester) bool { return strings.EqualFold(q.Address, r.Address) })
		if i < 0 || r.AutoRun && !now[i].AutoRun {
			return true
		}
	}
	return false
}

// defaultModeRank orders the worker's default modes by what they let out.
func defaultModeRank(mode string) int {
	switch mode {
	case modeNotify:
		return 1
	case modeFullOwner:
		return 2
	case modeFull:
		return 3
	}
	return 0
}

// dropAsks cancels a draft's approval emails, which the vault counts.
func dropAsks(t *Tree, d *draftEntry) {
	if d.Ask != nil || len(d.Asks) > 0 {
		t.countChange()
	}
	d.Ask, d.Asks = nil, nil
}
