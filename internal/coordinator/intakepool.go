package coordinator

import "errors"

// Intake takes a runner slot from the Pool as a job does, for the worker's
// account: a runner serves one account at a time (m4-cloud-runners.md §5.1),
// and a runner enclave's supervisor runs only the jobs it has slots for, which
// the Pool counts. With no slot, the email isn't acted on: it waits, in order,
// and the worker's mail is passed over again when a slot frees.

// errRunnersBusy is intake with no runner slot for its account. It isn't
// ErrIntake: the email isn't refused, only not read yet.
var errRunnersBusy = errors.New("no runner slot is free for intake")

// acquireIntake takes a slot for account's intake on workerID's mail. The
// worker is marked as waiting before the pool is asked, so a slot freed in
// between still passes over its mail.
func (c *Coordinator) acquireIntake(workerID, account string) (string, error) {
	m := c.mail
	if m != nil {
		m.mu.Lock()
		m.slotWaiters[workerID] = true
		m.mu.Unlock()
	}
	runner, ok := c.cfg.Pool.Acquire(account)
	c.noteIntakeWait(workerID, account, !ok)
	if !ok {
		return "", errRunnersBusy
	}
	if m != nil {
		m.mu.Lock()
		delete(m.slotWaiters, workerID)
		m.mu.Unlock()
	}
	return runner, nil
}

// releaseRunner returns a job's or intake's slot, then passes over the mail
// of workers whose intake waited for one and starts what jobs can start.
func (c *Coordinator) releaseRunner(runnerID string) error {
	err := c.cfg.Pool.Release(runnerID)
	c.RunnersChanged()
	return err
}

// RunnersChanged is a slot that may have come free: a released one, or a
// runner that linked in (RunnerHub.Changed). Workers whose intake waited for
// one have their mail passed over, and what jobs can start do.
func (c *Coordinator) RunnersChanged() {
	if m := c.mail; m != nil {
		m.mu.Lock()
		waiting := len(m.slotWaiters) > 0
		for id := range m.slotWaiters {
			m.kicked[id] = true
		}
		clear(m.slotWaiters)
		m.mu.Unlock()
		if waiting {
			m.poke()
		}
	}
	c.poke()
}
