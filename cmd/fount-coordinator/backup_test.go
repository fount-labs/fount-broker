package main

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fount-labs/fount-broker/internal/coordinator"
)

// memS3 is just enough S3 for the wiring: conditional Put, Get, Delete, and
// List a page of two at a time.
type memS3 struct {
	mu   sync.Mutex
	objs map[string][]byte
}

func (m *memS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := strings.TrimPrefix(r.URL.Path, "/")
	switch {
	case r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2":
		var keys []string
		for _, k := range slices.Sorted(maps.Keys(m.objs)) {
			if strings.HasPrefix(k, r.URL.Query().Get("prefix")) && k > r.URL.Query().Get("continuation-token") {
				keys = append(keys, k)
			}
		}
		type content struct {
			Key string `xml:"Key"`
		}
		out := struct {
			XMLName     xml.Name  `xml:"ListBucketResult"`
			IsTruncated bool      `xml:"IsTruncated"`
			Next        string    `xml:"NextContinuationToken,omitempty"`
			Contents    []content `xml:"Contents"`
		}{}
		if len(keys) > 2 {
			keys = keys[:2]
			out.IsTruncated, out.Next = true, keys[1]
		}
		for _, k := range keys {
			out.Contents = append(out.Contents, content{k})
		}
		data, _ := xml.Marshal(out)
		w.Write(data)
	case r.Method == http.MethodGet:
		data, ok := m.objs[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write(data)
	case r.Method == http.MethodPut:
		if _, ok := m.objs[key]; ok && r.Header.Get("If-None-Match") == "*" {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		m.objs[key], _ = io.ReadAll(r.Body)
	case r.Method == http.MethodDelete:
		delete(m.objs, key)
		w.WriteHeader(http.StatusNoContent)
	}
}

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
	for name, c := range map[string]struct {
		edit func(*backupFlags)
		want string
	}{
		"no region":            {func(f *backupFlags) { f.region = "" }, "--backup-region"},
		"no dev vault":         {func(f *backupFlags) { f.devVault = "" }, "--dev-vault"},
		"the vault's key":      {func(f *backupFlags) { f.keyMode = keyVault }, "COORDINATOR-COUNTER"},
		"past the sent window": {func(f *backupFlags) { f.retention = 85 * 24 * time.Hour }, "at most"},
		"no credentials":       {func(f *backupFlags) { f.getenv = func(string) string { return "" } }, "AWS_ACCESS_KEY_ID"},
		"a bad root":           {func(f *backupFlags) { f.restore = "objects/x" }, "roots/"},
		"dry run alone":        {func(f *backupFlags) { f.dryRun = true }, "--restore <root|latest>"},
		"restore with no key":  {func(f *backupFlags) { f.restore = restoreLatest }, "wrapping.key"},
		"dev vault alone":      {func(f *backupFlags) { f.bucket, f.region = "", "" }, "--dev-vault needs --backup-bucket"},
		"restore alone":        {func(f *backupFlags) { f.bucket, f.region, f.devVault, f.restore = "", "", "", restoreLatest }, "--restore needs --backup-bucket"},
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
	s3 := &memS3{objs: map[string][]byte{}}
	srv := httptest.NewServer(s3)
	defer srv.Close()
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
	if n := len(s3.objs); n < 3 {
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
