package coordinator

import (
	"fmt"
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
}

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
	p.mu.Lock()
	defer p.mu.Unlock()
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
