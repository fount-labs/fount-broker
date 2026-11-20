package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
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
	h := statusAPI(s, &jobs)
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
