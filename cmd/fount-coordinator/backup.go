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
	// mail is --mail, which with the vault's key needs backups.
	mail bool
	// authority is --coordinator-authority-key, with --wrapping-key vault.
	authority string
	// vault is what the Cloud vaults gave this boot, with --wrapping-key
	// vault: set after the key is fetched, before openDurable.
	vault *vaultSide
}

const restoreLatest = "latest"

func (f backupFlags) on() bool { return f.bucket != "" }

// check fails before anything listens.
func (f backupFlags) check() error {
	if !f.on() {
		switch {
		case f.mail && f.keyMode == keyVault:
			// A production coordinator's volume is the only copy of every
			// worker's mail and keys: losing it, with no backup, loses them.
			return errors.New("--mail with --wrapping-key vault needs --backup-bucket: without backups, a lost volume loses every worker's mail and keys")
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
	if f.restore != "" && !f.dryRun {
		// Before the vault is asked for a generation: a refused start
		// mustn't fence the coordinator running now.
		if has, mark, err := f.volume(); err != nil {
			return err
		} else if has && mark == nil {
			return errNeverRestoredOnto
		}
	}
	switch f.keyMode {
	case keyVault:
		// Backups without the vault's counter could be rolled back by
		// whoever holds the bucket.
		switch {
		case f.authority == "":
			return errors.New("--backup-bucket with --wrapping-key vault needs --coordinator-authority-key, for the Cloud vault's generation and counter")
		case f.devVault != "":
			return errors.New("--dev-vault is for --wrapping-key dev; the Cloud vault counts these backups")
		case f.getenv("AWS_ACCESS_KEY_ID") != "" || f.getenv("AWS_SECRET_ACCESS_KEY") != "" || f.getenv("AWS_SESSION_TOKEN") != "":
			// The deployer's environment isn't measured; the vault's
			// credentials go only to an attested coordinator release.
			return errors.New("--backup-bucket with --wrapping-key vault takes the bucket's credentials from the vault (vaultctl import-s3), not $AWS_*; unset them")
		}
		return nil
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

// openBucket is the backup bucket's client: with the vault's key, under the
// credentials the vault released with it; otherwise from the environment.
func (f backupFlags) openBucket() (*s3bucket.Bucket, error) {
	cfg := s3bucket.Config{Endpoint: f.bucket, Region: f.region, Forwarder: f.forwarder}
	if f.keyMode == keyVault {
		if f.vault == nil || f.vault.s3 == nil {
			return nil, errors.New("--backup-bucket: the vault released no bucket credentials; import them with vaultctl import-s3")
		}
		cfg.AccessKeyID, cfg.SecretAccessKey = f.vault.s3.AccessKeyID, f.vault.s3.SecretAccessKey
	} else {
		cfg.AccessKeyID, cfg.SecretAccessKey, cfg.SessionToken = f.getenv("AWS_ACCESS_KEY_ID"), f.getenv("AWS_SECRET_ACCESS_KEY"), f.getenv("AWS_SESSION_TOKEN")
	}
	return s3bucket.New(cfg)
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

// openDurable opens the bucket and the vault's counter and, unless this is a
// dry run, takes this process's generation: from the Cloud vault, which
// gave it with the key, or from the dev vault.
func (f backupFlags) openDurable(authority string) (*durable, error) {
	if !f.on() {
		return nil, nil
	}
	bucket, err := f.openBucket()
	if err != nil {
		return nil, err
	}
	if f.keyMode == keyVault {
		d := &durable{bucket: bucket, vault: f.vault.counter, gen: f.vault.gen}
		if !f.dryRun && d.gen == nil {
			return nil, errors.New("backups need a generation, and the vault gave none")
		}
		if d.gen != nil {
			log.Printf("backup: generation %d, backups to %s", d.gen.G.Number, f.bucket)
		}
		return d, nil
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

var errNeverRestoredOnto = fmt.Errorf("--restore: %w; this one was never restored onto, so take --restore off, or give the restore an empty --dir", coordinator.ErrRestoreOverVolume)

// volume is whether --dir has a coordinator's state, and if so its restore
// mark, nil on a volume nothing was restored onto.
func (f backupFlags) volume() (bool, *coordinator.RestoreMark, error) {
	stateDir := filepath.Join(f.dir, "state")
	if _, err := os.Stat(filepath.Join(stateDir, "state.json")); errors.Is(err, fs.ErrNotExist) {
		return false, nil, nil
	} else if err != nil {
		return false, nil, err
	}
	st, err := coordinator.LoadState(stateDir)
	if err != nil {
		return false, nil, err
	}
	return true, st.Restored, nil
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
		has, mark, err := f.volume()
		switch {
		case err != nil:
			return err
		case has && mark == nil:
			return errNeverRestoredOnto
		case has:
			log.Printf("restore: the volume was restored from %s at %s; serving it", mark.Root, mark.At.Format(time.RFC3339))
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

// generations is the mail loop's generation source: the one backups count
// under, or else the one the Cloud vault gave this boot.
func generations(d *durable, side *vaultSide) mail.GenerationSource {
	switch {
	case d != nil && d.gen != nil:
		return d.gen
	case side != nil && side.gen != nil:
		return side.gen
	}
	return nil
}
