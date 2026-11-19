package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fount-labs/fount-broker/internal/coordinator"
	"github.com/fount-labs/fount-broker/internal/mail"
	"github.com/fount-labs/fount-broker/internal/s3bucket"
)

// backupFlags turn on backups (coordinator.BackupConfig) and restores, in
// docs/backups.md's terms.
type backupFlags struct {
	bucket     string // the bucket's endpoint, https://<bucket>.s3.<region>.amazonaws.com
	region     string
	forwarder  string
	interval   time.Duration
	retention  time.Duration
	deleteMail bool
	// devVault is the file standing in for the Cloud vault's generation and
	// counter, with --wrapping-key dev.
	devVault string
	// restore is a root to restore onto an empty volume before serving, or
	// "latest".
	restore string
	dryRun  bool

	keyMode string
	dir     string
	getenv  func(string) string
}

const restoreLatest = "latest"

func (f backupFlags) on() bool { return f.bucket != "" }

// check fails before anything listens.
func (f backupFlags) check() error {
	if !f.on() {
		switch {
		case f.devVault != "":
			return errors.New("--dev-vault needs --backup-bucket")
		case f.restore != "" || f.dryRun:
			return errors.New("--restore needs --backup-bucket, the bucket the backups are in")
		case f.forwarder != "" || f.region != "" || f.deleteMail:
			return errors.New("--backup-region, --backup-forwarder and --backup-delete-mail need --backup-bucket")
		}
		return nil
	}
	if f.region == "" {
		return errors.New("--backup-bucket needs --backup-region")
	}
	if f.retention > coordinator.MaxBackupRetention {
		return fmt.Errorf("--backup-retention %s: at most %s, under the edge's %s of sent records", f.retention, coordinator.MaxBackupRetention, coordinator.SentRecordWindow)
	}
	if f.interval < 0 || f.retention < 0 {
		return errors.New("--backup-interval and --backup-retention can't be negative")
	}
	if f.dryRun && f.restore == "" {
		return errors.New("--restore-dry-run needs --restore <root|latest>")
	}
	if f.restore != "" && f.restore != restoreLatest && !strings.HasPrefix(f.restore, "roots/") {
		return fmt.Errorf("--restore %q: latest, or a backup's key, roots/<generation>-<seq>-<unix>", f.restore)
	}
	switch f.keyMode {
	case keyVault:
		// The Cloud vault releases the wrapping key and nothing else yet:
		// no generation and no counter, and backups without the counter
		// could be rolled back by whoever holds the bucket.
		return errors.New("--backup-bucket with --wrapping-key vault needs the Cloud vault's generation and counter, which aren't built (fount-mail-vault docs/COORDINATOR-COUNTER.md)")
	case keyDev:
		if f.devVault == "" {
			return errors.New("--backup-bucket with --wrapping-key dev needs --dev-vault <file>, the stand-in for the Cloud vault's generation and counter")
		}
	}
	if f.restore != "" && f.keyMode == keyDev {
		// A new dev key is made on first run, and wouldn't open a backup.
		if _, err := os.Stat(filepath.Join(f.dir, "wrapping.key")); err != nil {
			return fmt.Errorf("--restore with --wrapping-key dev needs the dev key the backups were taken under in %s: %w", filepath.Join(f.dir, "wrapping.key"), err)
		}
	}
	if f.getenv("AWS_ACCESS_KEY_ID") == "" || f.getenv("AWS_SECRET_ACCESS_KEY") == "" {
		return errors.New("--backup-bucket needs the bucket's credentials in $AWS_ACCESS_KEY_ID and $AWS_SECRET_ACCESS_KEY ($AWS_SESSION_TOKEN too for temporary ones)")
	}
	return nil
}

// bucket is the backup bucket's client.
func (f backupFlags) openBucket() (*s3bucket.Bucket, error) {
	return s3bucket.New(s3bucket.Config{
		Endpoint:        f.bucket,
		Region:          f.region,
		AccessKeyID:     f.getenv("AWS_ACCESS_KEY_ID"),
		SecretAccessKey: f.getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken:    f.getenv("AWS_SESSION_TOKEN"),
		Forwarder:       f.forwarder,
	})
}

// devVault is --dev-vault: the vault file and the key that signs its
// generation certificates, authority (--mail-generation-authority) or a seed
// next to the file.
func (f backupFlags) openDevVault(authority string) (*coordinator.FileVault, error) {
	path, err := filepath.Abs(f.devVault)
	if err != nil {
		return nil, err
	}
	if dir, err := filepath.Abs(f.dir); err == nil {
		if rel, err := filepath.Rel(dir, path); err == nil && !strings.HasPrefix(rel, "..") {
			log.Printf("backup: --dev-vault %s is on the volume: a restore drill that wipes --dir wipes the counter too, so nothing it restores can be refused as rolled back", path)
		}
	}
	if authority == "" {
		authority = path + ".authority"
	}
	seed, err := devSeed(authority)
	if err != nil {
		return nil, fmt.Errorf("the dev vault's authority %s: %w", authority, err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	log.Printf("backup: the dev vault %s signs generations with %s (a dev edge's COORDINATOR_AUTHORITY_KEY)", path, base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)))
	if err := f.seedDevVault(path); err != nil {
		return nil, err
	}
	return &coordinator.FileVault{Path: path, Authority: key}, nil
}

// seedDevVault starts a new dev vault after the generation a dev edge last
// saw from --mail-generation-authority alone (state/mail-generation), since
// the edge refuses a lower one.
func (f backupFlags) seedDevVault(path string) error {
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	data, err := os.ReadFile(filepath.Join(f.dir, "state", "mail-generation"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var last uint64
	if _, err := fmt.Sscan(strings.TrimSpace(string(data)), &last); err != nil {
		return fmt.Errorf("state/mail-generation: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	out, err := json.Marshal(coordinator.VaultCount{Generation: last})
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o600)
}

// durable is what backups run with.
type durable struct {
	bucket coordinator.BackupBucket
	vault  coordinator.VaultCounter
	// gen is this process's generation; nil in a dry run, which must not
	// move the vault's.
	gen *coordinator.FixedGeneration
}

// openDurable opens the bucket and the dev vault and, unless this is a dry
// run, takes this process's generation.
func (f backupFlags) openDurable(authority string) (*durable, error) {
	if !f.on() {
		return nil, nil
	}
	bucket, err := f.openBucket()
	if err != nil {
		return nil, err
	}
	vault, err := f.openDevVault(authority)
	if err != nil {
		return nil, err
	}
	d := &durable{bucket: bucket, vault: vault}
	if f.dryRun {
		return d, nil
	}
	if d.gen, err = vault.Boot(); err != nil {
		return nil, fmt.Errorf("the dev vault's generation: %w", err)
	}
	log.Printf("backup: generation %d, backups to %s", d.gen.G.Number, f.bucket)
	return d, nil
}

func (f backupFlags) config(d *durable) *coordinator.BackupConfig {
	if d == nil {
		return nil
	}
	return &coordinator.BackupConfig{
		Bucket:      d.bucket,
		Counter:     d.vault,
		Generations: d.gen,
		Interval:    f.interval,
		Retention:   f.retention,
		DeleteMail:  f.deleteMail,
	}
}

// errDryRunDone ends a dry run: the coordinator checked the backup and
// serves nothing.
var errDryRunDone = errors.New("the restore dry run is done")

// restoreVolume is --restore, before the coordinator opens the volume. On
// an empty volume it restores the backup. On a volume a backup was restored
// onto it does nothing, so a deploy that keeps --restore restarts cleanly;
// on any other volume it refuses, as Restore does. A dry run checks the
// backup, writes nothing, and returns errDryRunDone.
func (f backupFlags) restoreVolume(ctx context.Context, d *durable, key coordinator.WrappingKey) error {
	if f.restore == "" {
		return nil
	}
	root := f.restore
	if root == restoreLatest {
		root = ""
	}
	stateDir := filepath.Join(f.dir, "state")
	opts := coordinator.RestoreOptions{Bucket: d.bucket, Counter: d.vault, Key: key, Root: root, DryRun: f.dryRun}
	if !f.dryRun {
		if _, err := os.Stat(filepath.Join(stateDir, "state.json")); err == nil {
			st, err := coordinator.LoadState(stateDir)
			if err != nil {
				return err
			}
			if st.Restored == nil {
				return fmt.Errorf("--restore: %w; this one was never restored onto, so take --restore off, or give the restore an empty --dir", coordinator.ErrRestoreOverVolume)
			}
			log.Printf("restore: the volume was restored from %s at %s; serving it", st.Restored.Root, st.Restored.At.Format(time.RFC3339))
			return nil
		}
		opts.Generations, opts.StateDir, opts.Store = d.gen, stateDir, coordinator.DirStore{Root: filepath.Join(f.dir, "objects")}
	}
	res, err := coordinator.Restore(ctx, opts)
	if err != nil {
		return fmt.Errorf("--restore %s: %w", f.restore, err)
	}
	out, _ := json.Marshal(res)
	log.Printf("restore: %s", out)
	if f.dryRun {
		return errDryRunDone
	}
	return nil
}

// generations is the mail loop's generation source with backups on: the
// same one backups count under.
func (d *durable) generations() mail.GenerationSource {
	if d == nil || d.gen == nil {
		return nil
	}
	return d.gen
}
