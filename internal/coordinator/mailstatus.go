package coordinator

import (
	"time"
)

// The mail loop's phases, as MailStatus reports them.
const (
	// MailStarting is before the edge has taken this process's generation:
	// nothing is read yet. LastError says why, while it retries.
	MailStarting = "starting"
	// MailRunning is the loop reading and sending.
	MailRunning = "running"
	// MailStopped is the loop stopped for good: another generation owns Cloud
	// mail, or the edge refused this one's certificate. Stopped says which.
	MailStopped = "stopped"
)

// MailStatus is what the mail loop is doing, for the operator: it holds no
// mail, addresses or keys. A coordinator can stop reading mail while its jobs
// and clients go on, so without it a stopped loop shows only as mail that
// never arrives (2026-11-23).
type MailStatus struct {
	Phase string `json:"phase"`
	// Generation is this process's: the edge has taken it once Phase is
	// MailRunning. 0 before the vault or dev source gave one, or with none.
	Generation uint64 `json:"generation"`
	// Stopped is why the loop stopped, with Phase MailStopped.
	Stopped string `json:"stopped,omitempty"`
	// LastError is the latest failure of a generation call, feed read or
	// mailbox pass, and when.
	LastError   string     `json:"last_error,omitempty"`
	LastErrorAt *time.Time `json:"last_error_at,omitempty"`
	// LastPass is when a pass last finished.
	LastPass *time.Time `json:"last_pass,omitempty"`
	// Workers is how many workers have mail set up; Enrolled how many of
	// their mailboxes are under this generation at the edge.
	Workers  int `json:"workers"`
	Enrolled int `json:"enrolled"`
}

// mailStatus is the part of MailStatus the loop records; m.mu guards it.
type mailStatus struct {
	phase       string
	stopped     string
	lastError   string
	lastErrorAt time.Time
	lastPass    time.Time
}

func (m *mailLoop) noteError(err error) {
	m.mu.Lock()
	m.status.lastError, m.status.lastErrorAt = err.Error(), time.Now()
	m.mu.Unlock()
}

func (m *mailLoop) notePhase(phase string) {
	m.mu.Lock()
	m.status.phase = phase
	m.mu.Unlock()
}

// MailStatus is the mail loop's status, nil when the coordinator has no mail.
func (c *Coordinator) MailStatus() *MailStatus {
	m := c.mail
	if m == nil {
		return nil
	}
	workers := len(c.mailWorkers())
	m.mu.Lock()
	defer m.mu.Unlock()
	s := &MailStatus{
		Phase:      m.status.phase,
		Generation: m.service.Generation(),
		Stopped:    m.status.stopped,
		LastError:  m.status.lastError,
		Workers:    workers,
		Enrolled:   len(m.enrolled),
	}
	if s.Phase == "" {
		s.Phase = MailStarting
	}
	if !m.status.lastErrorAt.IsZero() {
		at := m.status.lastErrorAt.UTC()
		s.LastErrorAt = &at
	}
	if !m.status.lastPass.IsZero() {
		at := m.status.lastPass.UTC()
		s.LastPass = &at
	}
	return s
}
