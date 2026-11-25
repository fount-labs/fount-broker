package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fount-labs/fount-broker/internal/coordinator"
	"github.com/fount-labs/fount-broker/internal/vaultkey"
)

const testCommitment = "db2d1d4e7a8e474c78d48b89e93ccac6d9810776cda72ca8955000f9987dcb95"

// testAuthority is a GENERATION_AUTHORITY_KEY.
const testAuthority = "XIVBssrY9spP0DGRTC7Jue6vqFasENvFNje+z/94yJA="

func vaultFlags() keyFlags {
	return keyFlags{
		mode:       keyVault,
		vaults:     "cloud-vault-a.fount.containers.tinfoil.dev,cloud-vault-b.fount.containers.tinfoil.dev",
		vaultRepo:  "fount-labs/fount-cloud-vault",
		commitment: testCommitment,

		statusListen: "0.0.0.0:8791",
	}
}

func TestKeyFlags(t *testing.T) {
	if err := vaultFlags().check(); err != nil {
		t.Fatalf("vault flags: %v", err)
	}
	if err := (keyFlags{mode: keyDev}).check(); err != nil {
		t.Fatalf("dev flags: %v", err)
	}
	if err := (keyFlags{mode: keyDev, testAPI: true}).check(); err != nil {
		t.Fatalf("the test API with the dev key: %v", err)
	}
	withMail := vaultFlags()
	withMail.authority, withMail.mail = testAuthority, true
	if err := withMail.check(); err != nil || !withMail.boots() {
		t.Fatalf("mail with an authority: %v, boots %t", err, withMail.boots())
	}
	withMail.dryRun = true
	if withMail.boots() {
		t.Fatal("a dry run boots a generation")
	}
	for name, change := range map[string]func(f *keyFlags){
		"the test API with the vault's key": func(f *keyFlags) { f.testAPI = true },
		"an unknown mode":                   func(f *keyFlags) { f.mode = "file" },
		"no vaults":                         func(f *keyFlags) { f.vaults = "" },
		"a vault URL, not a host":           func(f *keyFlags) { f.vaults = "https://cloud-vault-a" },
		"no vault repo":                     func(f *keyFlags) { f.vaultRepo = "" },
		"a vault repo with a tag":           func(f *keyFlags) { f.vaultRepo = "fount-labs/fount-cloud-vault@v0.1.0" },
		"a vault repo path":                 func(f *keyFlags) { f.vaultRepo = "fount-labs/fount-cloud-vault/x" },
		"no commitment":                     func(f *keyFlags) { f.commitment = "" },
		"an uppercase commitment":           func(f *keyFlags) { f.commitment = strings.ToUpper(testCommitment) },
		"a short commitment":                func(f *keyFlags) { f.commitment = testCommitment[:62] },
		"no status listener":                func(f *keyFlags) { f.statusListen = "" },
		"vault flags with the dev key":      func(f *keyFlags) { f.mode = keyDev },
		"mail with no generation":           func(f *keyFlags) { f.mail = true },
		"a bad authority key":               func(f *keyFlags) { f.authority = "abc" },
		"an authority with the dev key": func(f *keyFlags) {
			f.mode, f.vaults, f.vaultRepo, f.commitment, f.authority = keyDev, "", "", "", testAuthority
		},
	} {
		f := vaultFlags()
		change(&f)
		if err := f.check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestStatusNamesTheKeyButNeverShowsIt(t *testing.T) {
	s := &keyStatus{Mode: keyVault, State: "waiting", Since: time.Now().UTC()}
	var jobs atomic.Pointer[coordinator.Coordinator]
	h := statusAPI(s, &jobs, nil)
	get := func(path string) (int, string) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w.Code, w.Body.String()
	}
	if code, _ := get("/health"); code != 200 {
		t.Fatalf("/health while waiting: %d", code)
	}
	s.failed(errors.New("vault-a: connection refused"))
	_, body := get("/status")
	var got struct {
		Key struct {
			State     string `json:"state"`
			Failures  int    `json:"failed_rounds"`
			LastError string `json:"last_error"`
			KeyID     string `json:"key_id"`
		} `json:"wrapping_key"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if got.Key.State != "waiting" || got.Key.Failures != 1 || !strings.Contains(got.Key.LastError, "refused") {
		t.Fatalf("waiting status: %s", body)
	}

	key, _ := coordinator.NewWrappingKey()
	s.held(&key, testCommitment, "https://cloud-vault-a")
	_, body = get("/status")
	got.Key.LastError = ""
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if got.Key.State != "held" || got.Key.KeyID != vaultkey.KeyID(&key) || got.Key.LastError != "" {
		t.Fatalf("held status: %s", body)
	}
	for _, leak := range []string{hex.EncodeToString(key[:]), base64.StdEncoding.EncodeToString(key[:])} {
		if strings.Contains(body, leak) {
			t.Fatal("/status shows the key")
		}
	}
	if code, _ := get("/v0/jobs/x"); code != 404 {
		t.Fatalf("the status listener serves the API: %d", code)
	}

	dir := t.TempDir()
	c, err := coordinator.New(coordinator.Config{
		StateDir: dir + "/state", WorkDir: dir + "/work", Store: coordinator.DirStore{Root: dir + "/objects"},
		Key: key, Pool: coordinator.NewPool(1, 1, nil), Runner: coordinator.LocalRunner{Command: []string{"false"}}, AccountJobs: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	w, _ := c.CreateWorker("acct_secret", nil)
	if _, err := c.Enqueue(w.ID, coordinator.JobSpec{ThreadID: "t1", SessionID: "s1", Instruction: "hi", Config: json.RawMessage(`{"model":"m"}`)}); err != nil {
		t.Fatal(err)
	}
	jobs.Store(c)
	_, body = get("/status")
	var load struct {
		Jobs coordinator.Load `json:"jobs"`
	}
	if err := json.Unmarshal([]byte(body), &load); err != nil {
		t.Fatal(err)
	}
	if load.Jobs.AccountJobs != 3 || load.Jobs.Queued != 1 || len(load.Jobs.Accounts) != 1 || load.Jobs.Accounts[0].Queued != 1 {
		t.Fatalf("jobs status: %s", body)
	}
	if strings.Contains(body, "acct_secret") || strings.Contains(body, w.ID) {
		t.Fatalf("/status names an account or worker: %s", body)
	}
}

func TestTheVaultsKeyServesNoDevAPI(t *testing.T) {
	dir := t.TempDir()
	key, _ := coordinator.NewWrappingKey()
	c, err := coordinator.New(coordinator.Config{
		StateDir: dir + "/state", WorkDir: dir + "/work", Store: coordinator.DirStore{Root: dir + "/objects"},
		Key: key, Pool: coordinator.NewPool(1, 1, nil), Runner: coordinator.LocalRunner{Command: []string{"false"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if h, err := devAPI(c, vaultFlags(), false); h != nil || err != nil {
		t.Errorf("vault: %v, %v", h, err)
	}
	h, err := devAPI(c, keyFlags{mode: keyDev}, false)
	if err != nil || h == nil {
		t.Fatalf("dev: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v0/workers", strings.NewReader(`{"account":"acme"}`)))
	if rec.Code != 201 {
		t.Errorf("dev: POST /v0/workers: %d %s", rec.Code, rec.Body)
	}
}

type fixedCount struct{ coordinator.VaultCount }

func (f fixedCount) Load(context.Context) (coordinator.VaultCount, error) { return f.VaultCount, nil }
func (fixedCount) CompareAndSwap(context.Context, uint64, uint64, uint64) error {
	return errors.New("not in this test")
}

// A volume behind the vault's count takes no generation: a blank disk, an
// old copy, or a create with no disk would otherwise fence the coordinator
// that holds the count (fount-mail-vault review H2, broker review H3).
func TestBootOnlyWhenTheVolumeHasReachedTheCount(t *testing.T) {
	dir := t.TempDir()
	b := backupFlags{dir: dir}
	allowed := func(count uint64, b backupFlags) error {
		return bootAllowed(context.Background(), fixedCount{coordinator.VaultCount{Generation: 4, Count: count}}, b, func(context.Context) error { return nil })
	}
	if err := allowed(0, b); err != nil {
		t.Fatalf("a blank volume before anything was counted: %v", err)
	}
	if err := allowed(3, b); !errors.Is(err, errBootRefused) || !strings.Contains(err.Error(), "a blank volume") {
		t.Fatalf("a blank volume after 3 changes: %v", err)
	}
	restore := b
	restore.restore = restoreLatest
	if err := allowed(3, restore); err != nil {
		t.Fatalf("--restore onto a blank volume: %v", err)
	}
	st, err := coordinator.LoadState(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	st.SecuritySeq = 3
	if err := os.MkdirAll(filepath.Join(dir, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(filepath.Join(dir, "state")); err != nil {
		t.Fatal(err)
	}
	for count, ok := range map[uint64]bool{2: true, 3: true, 4: false} {
		err := allowed(count, b)
		if ok != (err == nil) || (!ok && !errors.Is(err, errBootRefused)) {
			t.Fatalf("a volume at 3, the vault at %d: %v", count, err)
		}
	}
	// --restore on a volume that isn't empty is the volume's own case.
	if err := allowed(4, restore); !errors.Is(err, errBootRefused) {
		t.Fatalf("--restore onto a volume behind the count: %v", err)
	}
	// The 2026-11-25 re-review's N4 probe, flipped: a volume at the count
	// with another state than the vault counted is a fork, and took a
	// generation before openDurability refused it.
	fork := fixedCount{coordinator.VaultCount{Generation: 4, Count: 3, Writer: 4, Digest: "the-live-volumes-digest"}}
	if err := bootAllowed(context.Background(), fork, b, nil); !errors.Is(err, errBootRefused) || !strings.Contains(err.Error(), "fork") {
		t.Fatalf("a fork at the vault's count: %v", err)
	}
}

// --restore onto an empty volume runs Restore's refusals before it takes a
// generation; a bucket it can't reach is tried again, not refused
// (re-review L1).
func TestARefusedRestoreTakesNoGeneration(t *testing.T) {
	b := backupFlags{dir: t.TempDir(), restore: restoreLatest}
	count := fixedCount{coordinator.VaultCount{Generation: 4, Count: 3}}
	for _, refusal := range []error{coordinator.ErrNoBackup, coordinator.ErrBackupTooOld, coordinator.ErrBackupRolledBack} {
		err := bootAllowed(context.Background(), count, b, func(context.Context) error { return fmt.Errorf("roots/x: %w", refusal) })
		if !errors.Is(err, errBootRefused) || !errors.Is(err, refusal) {
			t.Fatalf("a restore refused with %v: %v", refusal, err)
		}
	}
	tries := 0
	err := bootAllowed(context.Background(), count, b, func(context.Context) error {
		if tries++; tries < 2 {
			return errors.New("the bucket is down")
		}
		return nil
	})
	if err != nil || tries != 2 {
		t.Fatalf("a bucket down once: %v after %d tries", err, tries)
	}
}
