package coordinator

import (
	"context"
	"errors"
	"testing"
)

// A dry run opens what a restore would and writes nothing: no volume, no
// count, and no generation, so the coordinator running now isn't stopped.
func TestARestoreDryRunChecksTheBackupAndChangesNothing(t *testing.T) {
	ctx := context.Background()
	v := newVaultRig(t, nil)
	c := v.boot(t.TempDir())
	w, err := c.CreateWorker("acme", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.PutFile(w.ID, "files/memo.md", []byte("memo")); err != nil {
		t.Fatal(err)
	}
	soloTeam(t, c, "acme", newTestDevice(t))
	if _, err := c.Backup(ctx); err != nil {
		t.Fatal(err)
	}
	before, objects := v.count(), len(v.bucket.objects)

	res, err := Restore(ctx, RestoreOptions{Bucket: v.bucket, Counter: v.vault, Key: v.key, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.DryRun || res.Workers != 1 || res.Objects == 0 || res.Root != v.newest() || res.Generation != 0 {
		t.Fatalf("dry run %+v", res)
	}
	if v.count() != before || len(v.bucket.objects) != objects || c.Retired() {
		t.Fatalf("the dry run changed something: vault %+v, %d objects, retired %v", v.count(), len(v.bucket.objects), c.Retired())
	}

	// It refuses what a restore would.
	oldest := v.roots()[0].key
	if _, err := Restore(ctx, RestoreOptions{Bucket: v.bucket, Counter: v.vault, Key: v.key, DryRun: true, Root: oldest}); !errors.Is(err, ErrBackupRolledBack) {
		t.Fatalf("a dry run of a backup below the counter: %v", err)
	}
	other, _ := NewWrappingKey()
	if _, err := Restore(ctx, RestoreOptions{Bucket: v.bucket, Counter: v.vault, Key: other, DryRun: true}); err == nil {
		t.Fatal("a dry run opened a backup under another key")
	}
	// A missing object is a backup that wouldn't restore.
	for k := range v.bucket.objects {
		if len(k) > len(backupObjectPrefix) && k[:len(backupObjectPrefix)] == backupObjectPrefix {
			delete(v.bucket.objects, k)
			break
		}
	}
	if _, err := Restore(ctx, RestoreOptions{Bucket: v.bucket, Counter: v.vault, Key: v.key, DryRun: true}); err == nil {
		t.Fatal("a dry run passed a backup with an object missing")
	}
}
