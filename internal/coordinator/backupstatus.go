package coordinator

import (
	"regexp"
	"sync"
	"time"
)

// BackupStatus is what backups are doing, for the operator: it holds no key,
// credential, bucket name or object contents, only times, counts and the root
// names a bucket listing shows. Without it a backup that stopped working
// shows only in the bucket (g-production-runbook.md, blocker 5).
type BackupStatus struct {
	// Configured is whether this coordinator backs up at all; without it
	// the rest is empty.
	Configured bool `json:"configured"`
	// Generation is this process's, the one its roots are named under.
	Generation      uint64 `json:"generation,omitempty"`
	IntervalSeconds int64  `json:"interval_seconds,omitempty"`
	// Stopped is why this coordinator stopped backing up: a newer
	// generation took over.
	Stopped string `json:"stopped,omitempty"`
	// LastAttemptAt is when a backup last started, on the timer or for a
	// change to security state; LastSuccessAt when one last left the bucket
	// with the volume as it was, by writing a root or finding it unchanged.
	LastAttemptAt *time.Time `json:"last_attempt_at,omitempty"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	// LastError is the latest failure of a backup, of reading the vault's
	// counter on the timer, or of keeping to the retention, and when.
	LastError   string     `json:"last_error,omitempty"`
	LastErrorAt *time.Time `json:"last_error_at,omitempty"`
	// LastRoot is the root last written, roots/<generation>-<seq>-<unix>,
	// and LastRun what writing it put in the bucket.
	LastRoot   string     `json:"last_root,omitempty"`
	LastRootAt *time.Time `json:"last_root_at,omitempty"`
	LastRun    *BackupRun `json:"last_run,omitempty"`
}

// BackupRun is what one root's backup put in the bucket: the tree objects it
// copied that the bucket hadn't yet, and the bytes of those and the root.
type BackupRun struct {
	Objects int   `json:"objects"`
	Bytes   int64 `json:"bytes"`
}

// backupStatus is the part of BackupStatus backups record. It has its own
// lock, not durability.mu, so a backup stuck on the bucket doesn't hold up a
// read of why.
type backupStatus struct {
	mu          sync.Mutex
	attempt     time.Time
	success     time.Time
	lastError   string
	lastErrorAt time.Time
	root        string
	rootAt      time.Time
	run         BackupRun
}

func (s *backupStatus) noteAttempt() {
	s.mu.Lock()
	s.attempt = time.Now()
	s.mu.Unlock()
}

func (s *backupStatus) noteUnchanged() {
	s.mu.Lock()
	s.success = time.Now()
	s.mu.Unlock()
}

func (s *backupStatus) noteRoot(key string, run BackupRun) {
	s.mu.Lock()
	now := time.Now()
	s.success, s.root, s.rootAt, s.run = now, key, now, run
	s.mu.Unlock()
}

func (s *backupStatus) noteError(what string, err error) {
	s.mu.Lock()
	s.lastError, s.lastErrorAt = scrubBackupError(what+err.Error()), time.Now()
	s.mu.Unlock()
}

var (
	// awsKeyID is an AWS access key id, which an S3 or forwarder error could
	// echo.
	awsKeyID = regexp.MustCompile(`\b(AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}\b`)
	// longToken is a run of base64 longer than an id: a secret key (40),
	// session token, signature or a body S3 echoed. Bucket keys are kept
	// (idPath).
	longToken = regexp.MustCompile(`[A-Za-z0-9+/=]{40,}`)
	// idPath is a run of ids, as a bucket key names a worker's object:
	// <24 hex>/<32 hex>.
	idPath = regexp.MustCompile(`^[0-9a-f]{1,32}(/[0-9a-f]{1,32})*$`)
)

// maxBackupError bounds LastError: the s3 errors already cut S3's message.
const maxBackupError = 400

// scrubBackupError is err as the control plane may read it, outside the
// enclave: with nothing in it that looks like a credential.
func scrubBackupError(s string) string {
	s = awsKeyID.ReplaceAllString(s, "[key id]")
	s = longToken.ReplaceAllStringFunc(s, func(run string) string {
		if idPath.MatchString(run) {
			return run
		}
		return "[redacted]"
	})
	if len(s) > maxBackupError {
		s = s[:maxBackupError] + "..."
	}
	return s
}

// BackupStatus is backups' status; Configured false without Config.Backup.
func (c *Coordinator) BackupStatus() BackupStatus {
	d := c.durable
	if d == nil {
		return BackupStatus{}
	}
	out := BackupStatus{Configured: true, Generation: d.gen, IntervalSeconds: int64(d.cfg.Interval / time.Second)}
	if why := c.fence.why.Load(); why != nil {
		out.Stopped = scrubBackupError(*why)
	}
	s := &d.status
	s.mu.Lock()
	defer s.mu.Unlock()
	out.LastAttemptAt, out.LastSuccessAt = utcOrNil(s.attempt), utcOrNil(s.success)
	out.LastError, out.LastErrorAt = s.lastError, utcOrNil(s.lastErrorAt)
	out.LastRoot, out.LastRootAt = s.root, utcOrNil(s.rootAt)
	if s.root != "" {
		run := s.run
		out.LastRun = &run
	}
	return out
}

func utcOrNil(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	t = t.UTC()
	return &t
}
