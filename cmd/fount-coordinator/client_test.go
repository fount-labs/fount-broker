package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fount-labs/fount-broker/internal/channel"
	"github.com/fount-labs/fount-broker/internal/coordinator"
	"github.com/fount-labs/fount-broker/internal/link"
)

// identity is a device of account, signed in with fount-infra's key.
func identity(t *testing.T, infra *rsa.PrivateKey, account string) channel.Identity {
	t.Helper()
	_, device, _ := ed25519.GenerateKey(rand.Reader)
	_, session, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	payload, _ := json.Marshal(map[string]any{
		"v": 1, "typ": "fount-device", "acct": account, "dev": channel.DeviceID(device.Public().(ed25519.PublicKey)),
		"tier": "pro", "status": "active", "pe": nil, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	digest := sha256.Sum256(payload)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, infra, crypto.SHA256, digest[:])
	grant, err := channel.SignSession(device, session.Public().(ed25519.PublicKey), now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return channel.Identity{Credential: enc(payload) + "." + enc(sig), DeviceKey: device.Public().(ed25519.PublicKey), Session: grant, SessionKey: session}
}

func TestDesktopReachesItsAccountOverTheChannel(t *testing.T) {
	infra, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&infra.PublicKey)
	keys, _ := channel.ParseAccountKeys(base64.StdEncoding.EncodeToString(der))
	side, _ := link.Unattested()

	dir := t.TempDir()
	key, _ := coordinator.NewWrappingKey()
	c, err := coordinator.New(coordinator.Config{
		StateDir: filepath.Join(dir, "state"),
		WorkDir:  filepath.Join(dir, "work"),
		Store:    coordinator.DirStore{Root: filepath.Join(dir, "objects")},
		Key:      key,
		Pool:     coordinator.NewPool(1, 1, nil),
		Runner:   coordinator.LocalRunner{Command: []string{"false"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var ready atomic.Pointer[http.Handler]
	srv := httptest.NewServer(clientAPI(statusAPI(&keyStatus{Mode: keyDev, State: "waiting"}), &ready))
	defer srv.Close()

	resp, err := http.Get(srv.URL + channel.Path)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("before the key: %d", resp.StatusCode)
	}
	if resp, _ := http.Get(srv.URL + "/health"); resp.StatusCode != 200 {
		t.Fatalf("/health: %d", resp.StatusCode)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &channel.Server{Key: side.Key, Attester: side.Attester, AccountKeys: keys,
		Handler: func(p channel.Peer) http.Handler { return c.AccountHandler(p.Account) }}
	h, err := s.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ready.Store(&h)

	client := func(account string) *channel.Client {
		id := identity(t, infra, account)
		return &channel.Client{Origin: srv.URL, Check: side.Check, Identity: func() (channel.Identity, error) { return id, nil }}
	}
	acme, other := client("acct_acme"), client("acct_other")
	do := func(cl *channel.Client, method, target, body string) (int, string) {
		t.Helper()
		resp, err := cl.Do(context.Background(), method, target, []byte(body))
		if err != nil {
			t.Fatalf("%s %s: %v", method, target, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	code, body := do(acme, "POST", "v1/workers", `{}`)
	var w struct{ ID, Account string }
	json.Unmarshal([]byte(body), &w)
	if code != http.StatusCreated || w.Account != "acct_acme" {
		t.Fatalf("create: %d %s", code, body)
	}
	if code, body := do(acme, "PUT", "v1/workers/"+w.ID+"/root/instructions.md", "be brief"); code != http.StatusNoContent {
		t.Fatalf("put: %d %s", code, body)
	}
	if code, body := do(acme, "GET", "v1/workers/"+w.ID+"/files/root/instructions.md", ""); code != 200 || body != "be brief" {
		t.Fatalf("get: %d %s", code, body)
	}
	if code, body := do(acme, "GET", "v1/workers/"+w.ID+"/files?prefix=root/", ""); code != 200 || !strings.Contains(body, "root/instructions.md") {
		t.Fatalf("list: %d %s", code, body)
	}
	code, body = do(acme, "POST", "v1/workers/"+w.ID+"/jobs", `{"threadId":"t1","sessionId":"s1","instruction":"hi","config":{}}`)
	var j struct{ ID string }
	json.Unmarshal([]byte(body), &j)
	if code != http.StatusAccepted {
		t.Fatalf("enqueue: %d %s", code, body)
	}
	if code, body := do(acme, "GET", "v1/jobs/"+j.ID, ""); code != 200 || !strings.Contains(body, `"queued"`) {
		t.Fatalf("job: %d %s", code, body)
	}
	if code, _ := do(acme, "POST", "v1/workers/"+w.ID+"/grant", `{"v":1,"dek":"`+base64.StdEncoding.EncodeToString(make([]byte, 32))+`"}`); code != http.StatusNotImplemented {
		t.Fatalf("grant: %d", code)
	}

	for _, target := range []string{"v1/workers/" + w.ID, "v1/workers/" + w.ID + "/files/root/instructions.md", "v1/jobs/" + j.ID} {
		if code, body := do(other, "GET", target, ""); code != http.StatusNotFound {
			t.Errorf("another account's %s: %d %s", target, code, body)
		}
	}
	if code, body := do(other, "GET", "v1/workers", ""); code != 200 || !strings.Contains(body, `"workers":[]`) {
		t.Errorf("another account's workers: %d %s", code, body)
	}
}

func TestClientFlags(t *testing.T) {
	infra, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&infra.PublicKey)
	keys := base64.StdEncoding.EncodeToString(der)
	t.Setenv(accountKeysEnv, "")
	for _, f := range []clientFlags{
		{accountKeys: keys, attestation: attestTinfoil},
		{attestation: attestUnattested},
		{listen: ":8791", attestation: attestTinfoil},
		{listen: ":8791", accountKeys: "bm90IGEga2V5", attestation: attestTinfoil},
		{listen: ":8791", accountKeys: keys, attestation: "none"},
	} {
		if _, err := f.server(); err == nil {
			t.Errorf("%+v was taken", f)
		}
	}
	if s, err := (clientFlags{attestation: attestTinfoil}).server(); s != nil || err != nil {
		t.Errorf("no channel: %v %v", s, err)
	}
}
