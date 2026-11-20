package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-vault/wire"

	"github.com/fount-labs/fount-broker/internal/coordinator"
	"github.com/fount-labs/fount-broker/internal/mail"
	"github.com/fount-labs/fount-broker/internal/s3bucket/s3buckettest"
	"github.com/fount-labs/fount-broker/internal/vaultkey"
	"github.com/fount-labs/fount-broker/internal/vaultkey/cloudvaulttest"
)

func testEnv(k string) string {
	return map[string]string{"AWS_ACCESS_KEY_ID": "AKIDTEST", "AWS_SECRET_ACCESS_KEY": "secret"}[k]
}

func TestBackupFlags(t *testing.T) {
	dir := t.TempDir()
	ok := backupFlags{bucket: "https://b.s3.us-east-1.amazonaws.com", region: "us-east-1", devVault: "/elsewhere/vault.json", keyMode: keyDev, dir: dir, getenv: testEnv}
	if err := ok.check(); err != nil {
		t.Fatal(err)
	}
	if err := (backupFlags{keyMode: keyDev, getenv: testEnv}).check(); err != nil {
		t.Fatalf("no backups: %v", err)
	}
	if err := (backupFlags{keyMode: keyDev, mail: true, getenv: testEnv}).check(); err != nil {
		t.Fatalf("dev mail with no backups: %v", err)
	}
	noEnv := func(string) string { return "" }
	if err := (backupFlags{keyMode: keyVault, getenv: noEnv}).check(); err != nil {
		t.Fatalf("the vault's key, no mail, no backups: %v", err)
	}
	if err := (backupFlags{keyMode: keyVault, mail: true, getenv: noEnv}).check(); err == nil || !strings.Contains(err.Error(), "--mail with --wrapping-key vault needs --backup-bucket") {
		t.Errorf("the vault's key, mail, no backups: %v", err)
	}
	vaultMail := backupFlags{bucket: ok.bucket, region: ok.region, keyMode: keyVault, authority: testAuthority, mail: true, dir: dir, getenv: noEnv}
	if err := vaultMail.check(); err != nil {
		t.Fatalf("the vault's key, mail, backups: %v", err)
	}
	for name, c := range map[string]struct {
		edit func(*backupFlags)
		want string
	}{
		"no region":                     {func(f *backupFlags) { f.region = "" }, "--backup-region"},
		"no dev vault":                  {func(f *backupFlags) { f.devVault = "" }, "--dev-vault"},
		"the vault's key, no authority": {func(f *backupFlags) { f.keyMode, f.devVault = keyVault, "" }, "--coordinator-authority-key"},
		"the vault's key, a dev vault":  {func(f *backupFlags) { f.keyMode, f.authority = keyVault, testAuthority }, "--dev-vault is for"},
		"the vault's key, env creds":    {func(f *backupFlags) { f.keyMode, f.authority, f.devVault = keyVault, testAuthority, "" }, "unset them"},
		"past the sent window":          {func(f *backupFlags) { f.retention = 85 * 24 * time.Hour }, "at most"},
		"no credentials":                {func(f *backupFlags) { f.getenv = func(string) string { return "" } }, "AWS_ACCESS_KEY_ID"},
		"a bad root":                    {func(f *backupFlags) { f.restore = "objects/x" }, "roots/"},
		"dry run alone":                 {func(f *backupFlags) { f.dryRun = true }, "--restore <root|latest>"},
		"restore with no key":           {func(f *backupFlags) { f.restore = restoreLatest }, "wrapping.key"},
		"dev vault alone":               {func(f *backupFlags) { f.bucket, f.region = "", "" }, "--dev-vault needs --backup-bucket"},
		"restore alone":                 {func(f *backupFlags) { f.bucket, f.region, f.devVault, f.restore = "", "", "", restoreLatest }, "--restore needs --backup-bucket"},
	} {
		f := ok
		c.edit(&f)
		if err := f.check(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// The wiring end to end: a coordinator backs up to S3 under the dev vault's
// generation, a dry run checks the backup without moving the vault, and a
// restore onto a new volume brings the worker back, once.
func TestBackupAndRestoreThroughTheFlags(t *testing.T) {
	ctx := context.Background()
	s3, srv := s3buckettest.Start(t, "AKIDTEST")
	vaultFile := filepath.Join(t.TempDir(), "dev-vault.json")
	flags := func(dir, restore string, dry bool) backupFlags {
		return backupFlags{bucket: srv.URL, region: "us-east-1", devVault: vaultFile, keyMode: keyDev, dir: dir,
			restore: restore, dryRun: dry, getenv: testEnv}
	}
	open := func(f backupFlags, d *durable, key coordinator.WrappingKey) *coordinator.Coordinator {
		t.Helper()
		c, err := coordinator.New(coordinator.Config{
			StateDir: filepath.Join(f.dir, "state"), WorkDir: filepath.Join(f.dir, "work"),
			Store: coordinator.DirStore{Root: filepath.Join(f.dir, "objects")}, Key: key,
			Pool: coordinator.NewPool(1, 1, nil), Runner: coordinator.LocalRunner{Command: []string{"true"}},
			Backup: f.config(d),
		})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	first := flags(t.TempDir(), "", false)
	if err := first.check(); err != nil {
		t.Fatal(err)
	}
	key, err := devWrappingKey(filepath.Join(first.dir, "wrapping.key"))
	if err != nil {
		t.Fatal(err)
	}
	d1, err := first.openDurable("")
	if err != nil {
		t.Fatal(err)
	}
	c1 := open(first, d1, key)
	w, err := c1.CreateWorker("acme", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c1.PutFile(w.ID, "files/memo.md", []byte("memo")); err != nil {
		t.Fatal(err)
	}
	if _, err := c1.Backup(ctx); err != nil {
		t.Fatal(err)
	}
	if n := s3.Len(); n < 3 {
		t.Fatalf("%d objects in the bucket", n)
	}

	// A new volume, with the dev key the backups were taken under.
	second := flags(t.TempDir(), restoreLatest, true)
	if err := second.check(); err == nil {
		t.Fatal("a restore without the dev key passed the check")
	}
	if err := os.WriteFile(filepath.Join(second.dir, "wrapping.key"), key[:], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := second.check(); err != nil {
		t.Fatal(err)
	}
	before, _ := d1.vault.Load(ctx)
	dd, err := second.openDurable("")
	if err != nil {
		t.Fatal(err)
	}
	if err := second.restoreVolume(ctx, dd, key); !errors.Is(err, errDryRunDone) {
		t.Fatalf("dry run: %v", err)
	}
	if after, _ := d1.vault.Load(ctx); after != before {
		t.Fatalf("the dry run moved the vault from %+v to %+v", before, after)
	}
	if _, err := os.Stat(filepath.Join(second.dir, "state")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the dry run wrote the volume: %v", err)
	}

	second.dryRun = false
	d2, err := second.openDurable("")
	if err != nil {
		t.Fatal(err)
	}
	if d2.gen.G.Number != d1.gen.G.Number+1 {
		t.Fatalf("generation %d after %d", d2.gen.G.Number, d1.gen.G.Number)
	}
	if err := second.restoreVolume(ctx, d2, key); err != nil {
		t.Fatal(err)
	}
	c2 := open(second, d2, key)
	if got, err := c2.ReadFile(w.ID, "root/files/memo.md"); err != nil || string(got) != "memo" {
		t.Fatalf("restored memo %q, %v", got, err)
	}
	// Restarting with --restore still set serves the restored volume.
	if err := second.restoreVolume(ctx, d2, key); err != nil {
		t.Fatalf("a restart with --restore: %v", err)
	}
	// A volume nothing was restored onto is refused.
	first.restore = restoreLatest
	if err := first.restoreVolume(ctx, d1, key); !errors.Is(err, coordinator.ErrRestoreOverVolume) {
		t.Fatalf("--restore over a live volume: %v", err)
	}
}

// With the vault's key, backups go to the bucket under the credentials the
// vault released, and count in the vault under the generation it gave.
func TestBackupsUnderTheVaultsKey(t *testing.T) {
	ctx := context.Background()
	// Every request must be signed by the vault's access key.
	s3, srv := s3buckettest.Start(t, "AKIDVAULT")
	pair := cloudvaulttest.Start(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	cert, n, err := pair.Boot(pub)
	if err != nil {
		t.Fatal(err)
	}
	fetched := &vaultkey.Fetched{
		S3:         &wire.S3Credentials{AccessKeyID: "AKIDVAULT", SecretAccessKey: "from-the-vault"},
		Generation: &mail.Generation{Number: n, Certificate: cert, Key: priv},
	}
	side, err := newVaultSide(pair.Vaults(), pair.AuthorityKey(), fetched)
	if err != nil {
		t.Fatal(err)
	}
	noEnv := func(string) string { return "" }
	f := backupFlags{bucket: srv.URL, region: "us-east-1", keyMode: keyVault, authority: testAuthority, dir: t.TempDir(), getenv: noEnv, vault: side}
	if err := f.check(); err != nil {
		t.Fatal(err)
	}
	d, err := f.openDurable("")
	if err != nil {
		t.Fatal(err)
	}
	if d.gen == nil || d.gen.G.Number != n || generations(d, side) != d.gen {
		t.Fatalf("durable %+v", d)
	}
	key, _ := coordinator.NewWrappingKey()
	c, err := coordinator.New(coordinator.Config{
		StateDir: filepath.Join(f.dir, "state"), WorkDir: filepath.Join(f.dir, "work"),
		Store: coordinator.DirStore{Root: filepath.Join(f.dir, "objects")}, Key: key,
		Pool: coordinator.NewPool(1, 1, nil), Runner: coordinator.LocalRunner{Command: []string{"true"}},
		Backup: f.config(d),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateWorker("acme", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Backup(ctx); err != nil {
		t.Fatal(err)
	}
	if s3.Len() == 0 {
		t.Fatal("nothing reached the bucket")
	}

	// A dry run's side has no generation and boots nothing.
	dry := f
	dry.dryRun, dry.restore = true, restoreLatest
	dry.vault, err = newVaultSide(pair.Vaults(), pair.AuthorityKey(), &vaultkey.Fetched{S3: fetched.S3})
	if err != nil {
		t.Fatal(err)
	}
	dd, err := dry.openDurable("")
	if err != nil || dd.gen != nil {
		t.Fatalf("dry run durable %+v %v", dd, err)
	}
	if err := dry.restoreVolume(ctx, dd, key); !errors.Is(err, errDryRunDone) {
		t.Fatalf("dry run: %v", err)
	}
	if st := pair.State(); st.Generation != n {
		t.Fatalf("the dry run moved the vault to %+v", st)
	}

	// No credentials in the vault: refused, not taken from elsewhere.
	f.vault = &vaultSide{counter: side.counter, gen: side.gen}
	if _, err := f.openDurable(""); err == nil || !strings.Contains(err.Error(), "import-s3") {
		t.Fatalf("a vault with no bucket credentials: %v", err)
	}
	// No authority, no counter: the side is nil.
	if s, err := newVaultSide(pair.Vaults(), nil, fetched); s != nil || err != nil {
		t.Fatalf("a side without an authority: %+v %v", s, err)
	}
}
