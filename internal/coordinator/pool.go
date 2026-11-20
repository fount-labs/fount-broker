package coordinator

import (
	"fmt"
	"strings"
	"sync"
)

// Pool assigns runner slots to accounts (m4-cloud-runners.md §5.1). A runner
// serves one account at a time, so a sandbox escape reaches only that account's
// running jobs. When its last job ends it is recycled, which wipes it, before
// any other account can have it.
type Pool struct {
	mu      sync.Mutex
	runners []*poolRunner
	// recycle restarts a runner that has drained. It runs outside the lock, and
	// the runner takes no jobs until it returns.
	recycle func(runnerID string) error
	// Ready, if set, gates every slot by account: with runners that dial in,
	// an account with no runner linked that its jobs may go to has no room,
	// and its jobs wait in the queue (RunnerHub.ReadyFor).
	Ready func(account string) bool
	// Dedicated, if set, says an account runs on a runner of its own, a
	// team's (RunnerHub.Placement), not on the pool's runners. Its slots are
	// counted apart, DedicatedSlots at once, and take none of the pool's.
	Dedicated      func(account string) bool
	DedicatedSlots int
	dedicated      map[string]int
}

// dedicatedPrefix starts the runner id of a dedicated account's slot.
const dedicatedPrefix = "dedicated:"

type poolRunner struct {
	id        string
	slots     int
	account   string
	active    int
	recycling bool
}

// NewPool makes n runners with the given slots each. recycle may be nil when
// runners hold nothing between jobs, as the local runner doesn't.
func NewPool(n, slots int, recycle func(runnerID string) error) *Pool {
	p := &Pool{recycle: recycle}
	for i := range n {
		p.runners = append(p.runners, &poolRunner{id: fmt.Sprintf("runner-%d", i+1), slots: slots})
	}
	return p
}

// Acquire takes a slot for account: first on a runner it already holds, then on
// a free one. It reports false when neither has room, and the job waits.
func (p *Pool) Acquire(account string) (string, bool) {
	if p.Ready != nil && !p.Ready(account) {
		return "", false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Dedicated != nil && p.Dedicated(account) {
		if p.dedicated[account] >= max(p.DedicatedSlots, 1) {
			return "", false
		}
		if p.dedicated == nil {
			p.dedicated = map[string]int{}
		}
		p.dedicated[account]++
		return dedicatedPrefix + account, true
	}
	for _, r := range p.runners {
		if r.account == account && !r.recycling && r.active < r.slots {
			r.active++
			return r.id, true
		}
	}
	for _, r := range p.runners {
		if r.account == "" && !r.recycling && r.slots > 0 {
			r.account = account
			r.active = 1
			return r.id, true
		}
	}
	return "", false
}

// Release returns a slot. A runner whose last job just ended is recycled and
// leaves its account.
func (p *Pool) Release(runnerID string) error {
	p.mu.Lock()
	if account, ok := strings.CutPrefix(runnerID, dedicatedPrefix); ok {
		defer p.mu.Unlock()
		if p.dedicated[account] == 0 {
			return fmt.Errorf("release of %s's runner, which has no job", account)
		}
		if p.dedicated[account]--; p.dedicated[account] == 0 {
			delete(p.dedicated, account)
		}
		return nil
	}
	r := p.find(runnerID)
	if r == nil || r.active == 0 {
		p.mu.Unlock()
		return fmt.Errorf("release of %s, which has no job", runnerID)
	}
	r.active--
	if r.active > 0 {
		p.mu.Unlock()
		return nil
	}
	r.recycling = true
	p.mu.Unlock()

	var err error
	if p.recycle != nil {
		err = p.recycle(runnerID)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	r.recycling = false
	if err != nil {
		// A runner that may still hold the last account's data can't serve
		// another, so it stays out of the pool.
		r.slots = 0
		return fmt.Errorf("recycle %s: %w; it is out of the pool", runnerID, err)
	}
	r.account = ""
	return nil
}

func (p *Pool) find(id string) *poolRunner {
	for _, r := range p.runners {
		if r.id == id {
			return r
		}
	}
	return nil
}
