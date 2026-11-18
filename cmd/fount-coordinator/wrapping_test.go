package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fount-labs/fount-broker/internal/coordinator"
	"github.com/fount-labs/fount-broker/internal/vaultkey"
)

const testCommitment = "db2d1d4e7a8e474c78d48b89e93ccac6d9810776cda72ca8955000f9987dcb95"

func vaultFlags() keyFlags {
	return keyFlags{
		mode:       keyVault,
		vaults:     "cloud-vault-a.fount.containers.tinfoil.dev,cloud-vault-b.fount.containers.tinfoil.dev",
		vaultRepo:  "fount-labs/fount-cloud-vault",
		commitment: testCommitment,
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
	for name, change := range map[string]func(f *keyFlags){
		"the test API with the vault's key": func(f *keyFlags) { f.testAPI = true },
		"an unknown mode":                   func(f *keyFlags) { f.mode = "file" },
		"no vaults":                         func(f *keyFlags) { f.vaults = "" },
		"a vault URL, not a host":           func(f *keyFlags) { f.vaults = "https://cloud-vault-a" },
		"no vault repo":                     func(f *keyFlags) { f.vaultRepo = "" },
		"a vault repo with a tag":           func(f *keyFlags) { f.vaultRepo = "fount-labs/fount-cloud-vault@v0.1.0" },
		"a vault repo path":                 func(f *keyFlags) { f.vaultRepo = "fount-labs/fount-cloud-vault/x" },
		"no commitment":                     func(f *keyFlags) { f.commitment = "" },
		"vault flags with the dev key":      func(f *keyFlags) { f.mode = keyDev },
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
	h := statusAPI(s)
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
}
