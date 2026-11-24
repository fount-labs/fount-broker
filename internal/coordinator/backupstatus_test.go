package coordinator

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackupStatusWithoutBackups(t *testing.T) {
	dir := t.TempDir()
	key, _ := NewWrappingKey()
	c, err := New(Config{
		StateDir: filepath.Join(dir, "state"), WorkDir: filepath.Join(dir, "work"),
		Store: DirStore{Root: filepath.Join(dir, "objects")}, Key: key, Pool: NewPool(1, 1, nil),
		Runner: LocalRunner{Command: []string{"true"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if s := c.BackupStatus(); s != (BackupStatus{}) {
		t.Fatalf("%+v", s)
	}
}

func TestBackupStatusTellsTheLastRunAndWhyOneFailed(t *testing.T) {
	ctx := context.Background()
	v := newVaultRig(t, nil)
	c := v.boot(t.TempDir())
	s := c.BackupStatus()
	if !s.Configured || s.Generation != 1 || s.IntervalSeconds != 300 || s.LastRoot != v.newest() || s.LastError != "" {
		t.Fatalf("at boot: %+v", s)
	}
	if s.LastAttemptAt == nil || s.LastSuccessAt == nil || s.LastRootAt == nil || s.LastRun == nil || s.LastRun.Objects != 0 || s.LastRun.Bytes == 0 {
		t.Fatalf("at boot: %+v", s)
	}

	w, err := c.CreateWorker("acme", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.PutFile(w.ID, "files/memo.md", []byte("memo")); err != nil {
		t.Fatal(err)
	}
	key, err := c.Backup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s = c.BackupStatus()
	if s.LastRoot != key || s.LastRun.Objects == 0 || s.LastRun.Bytes <= int64(len("memo")) {
		t.Fatalf("after a change: %+v %+v", s, s.LastRun)
	}
	written := *s.LastRootAt

	// An unchanged volume is a success with no new root.
	if _, err := c.Backup(ctx); err != nil {
		t.Fatal(err)
	}
	if s = c.BackupStatus(); s.LastRoot != key || s.LastSuccessAt.Before(written) {
		t.Fatalf("unchanged: %+v", s)
	}

	// The bucket refuses, with an error that echoes what it was signed with.
	const keyID, secret = "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	v.bucket.FailPut = func(string) error {
		return errors.New("s3: put: 403 Forbidden: InvalidAccessKeyId " + keyID + " signed " + secret)
	}
	if err := c.PutFile(w.ID, "files/memo.md", []byte("memo 2")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Backup(ctx); err == nil {
		t.Fatal("a refused put backed up")
	}
	s = c.BackupStatus()
	if s.LastRoot != key || s.LastErrorAt == nil || s.LastErrorAt.Before(*s.LastSuccessAt) || s.LastAttemptAt.After(*s.LastErrorAt) {
		t.Fatalf("after a failure: %+v", s)
	}
	if !strings.Contains(s.LastError, "403 Forbidden") || strings.Contains(s.LastError, keyID) || strings.Contains(s.LastError, secret) {
		t.Fatalf("last_error %q", s.LastError)
	}

	v.bucket.FailPut = nil
	if _, err := c.Backup(ctx); err != nil {
		t.Fatal(err)
	}
	if s = c.BackupStatus(); s.LastRoot == key || s.LastSuccessAt.Before(*s.LastErrorAt) {
		t.Fatalf("after recovering: %+v", s)
	}
}

func TestScrubBackupError(t *testing.T) {
	root := "writing backup roots/00000000000000000003-00000000000000000007-00000000001763942400: s3: put: 500"
	if got := scrubBackupError(root); got != root {
		t.Errorf("a root's name was scrubbed: %q", got)
	}
	worker := "backing up worker w_0123456789abcdef01234567: s3: put \"objects/w_0123456789abcdef01234567/0123456789abcdef0123456789abcdef\": 500"
	if got := scrubBackupError(worker); got != worker {
		t.Errorf("ids were scrubbed: %q", got)
	}
	if got := scrubBackupError("token " + strings.Repeat("Ab+/", 40)); got != "token [redacted]" {
		t.Errorf("%q", got)
	}
	if got := scrubBackupError("secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"); got != "secret [redacted]" {
		t.Errorf("%q", got)
	}
	if got := scrubBackupError(strings.Repeat("x ", 400)); len(got) > maxBackupError+3 {
		t.Errorf("%d bytes", len(got))
	}
}
