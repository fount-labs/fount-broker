package coordinator

import (
	"log"
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
	// UnsentNotices counts the account and team notices no one could be
	// sent (sendowner.go): no email agent of the account has a mailbox, or
	// every address failed. LastUnsentNotice is the latest's kind and why,
	// naming no address.
	UnsentNotices      int        `json:"unsent_notices"`
	LastUnsentNotice   string     `json:"last_unsent_notice,omitempty"`
	LastUnsentNoticeAt *time.Time `json:"last_unsent_notice_at,omitempty"`
}

// mailStatus is the part of MailStatus the loop records; m.mu guards it.
type mailStatus struct {
	phase       string
	stopped     string
	lastError   string
	lastErrorAt time.Time
	lastPass    time.Time
	// unsent are the notice keys no one could be sent, so a retry of one
	// counts once; lastUnsent is the latest's kind and why.
	unsent       map[string]bool
	unsentCount  int
	lastUnsent   string
	lastUnsentAt time.Time
}

// maxUnsentKeys bounds unsent: past it, keys are forgotten and a retry of an
// old one counts again.
const maxUnsentKeys = 1024

// noticeUnsent raises the alert for a notice of kind for account that no one
// could be sent: an error-level log line with the stable event name
// notice_unsent, and MailStatus's UnsentNotices, once per key.
func (c *Coordinator) noticeUnsent(key, kind, account, why string) {
	if m := c.mail; m != nil {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.status.unsent[key] {
			return
		}
	}
	log.Printf("ERROR notice_unsent: kind=%s account=%s: no one could be sent it: %s", kind, account, why)
	m := c.mail
	if m == nil {
		return
	}
	if m.status.unsent == nil || len(m.status.unsent) >= maxUnsentKeys {
		m.status.unsent = map[string]bool{}
	}
	m.status.unsent[key] = true
	m.status.unsentCount++
	m.status.lastUnsent, m.status.lastUnsentAt = kind+": "+why, time.Now()
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

		UnsentNotices:    m.status.unsentCount,
		LastUnsentNotice: m.status.lastUnsent,
	}
	if !m.status.lastUnsentAt.IsZero() {
		at := m.status.lastUnsentAt.UTC()
		s.LastUnsentNoticeAt = &at
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
