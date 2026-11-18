package main

import (
	"context"
	"crypto"
	"crypto/ecdh"
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

const audience = "https://coordinator.example"

// identity is a device of account, signed in with fount-infra's key, and the
// device's key.
func identity(t *testing.T, infra *rsa.PrivateKey, account string) (channel.Identity, ed25519.PrivateKey) {
	t.Helper()
	_, device, _ := ed25519.GenerateKey(rand.Reader)
	_, session, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	payload, _ := json.Marshal(map[string]any{
		"v": 1, "typ": "fount-device", "acct": account, "dev": channel.DeviceID(device.Public().(ed25519.PublicKey)),
		"tier": "pro", "status": "active", "pe": now.Add(24 * time.Hour).Unix(), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	digest := sha256.Sum256(payload)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, infra, crypto.SHA256, digest[:])
	grant, err := channel.SignSession(device, session.Public().(ed25519.PublicKey), now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return channel.Identity{Credential: enc(payload) + "." + enc(sig), DeviceKey: device.Public().(ed25519.PublicKey), Session: grant, SessionKey: session}, device
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
		Audience: audience,
	})
	if err != nil {
		t.Fatal(err)
	}
	var ready atomic.Pointer[http.Handler]
	srv := httptest.NewServer(clientAPI(statusAPI(&keyStatus{Mode: keyDev, State: "waiting"}, &atomic.Pointer[coordinator.Coordinator]{}), &ready, false, nil))
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
	s := &channel.Server{Key: side.Key, Attester: side.Attester, AccountKeys: keys, Handler: handler(c)}
	h, err := s.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ready.Store(&h)

	client := func(account string) (*channel.Client, ed25519.PrivateKey) {
		id, device := identity(t, infra, account)
		return &channel.Client{Origin: srv.URL, Check: link.CheckUnattestedKey, Identity: func() (channel.Identity, error) { return id, nil }}, device
	}
	acme, device := client("acct_acme")
	other, _ := client("acct_other")
	// Another device of the same account, as fount-infra alone could sign in.
	stranger, _ := client("acct_acme")
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
	if code, body := do(acme, "PUT", "v1/workers/"+w.ID+"/root/instructions.md", "be brief"); code != http.StatusConflict {
		t.Fatalf("put before the grant: %d %s", code, body)
	}
	dek, _ := coordinator.NewDEK()
	enc, _ := ecdh.X25519().GenerateKey(rand.Reader)
	devID := channel.DeviceID(device.Public().(ed25519.PublicKey))
	inclusion, err := coordinator.SignInclusion(device, enc.PublicKey().Bytes(), coordinator.InclusionClaims{Aud: audience, Acct: "acct_acme", Worker: w.ID, DEK: coordinator.DEKCommitment(w.ID, dek), Seq: 1})
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := coordinator.SealWrap(enc.PublicKey().Bytes(), "acct_acme", w.ID, devID, dek)
	if err != nil {
		t.Fatal(err)
	}
	wraps := map[string][]byte{devID: wrap}
	digest, _ := coordinator.WrapsDigest([]string{devID}, wraps)
	grant, err := coordinator.SignGrant(device, coordinator.GrantClaims{
		Op: coordinator.OpGrant, Aud: audience, Acct: "acct_acme", Worker: w.ID, Seq: 1, DEK: coordinator.DEKCommitment(w.ID, dek),
		Devices: []string{base64.RawURLEncoding.EncodeToString(device.Public().(ed25519.PublicKey))}, Wraps: digest, Iat: time.Now().Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	grantBody, _ := json.Marshal(map[string]any{"v": coordinator.GrantBodyVersion, "dek": dek[:], "grant": grant, "inclusions": []string{inclusion}, "wraps": wraps})
	if code, body := do(acme, "POST", "v1/workers/"+w.ID+"/grant", string(grantBody)); code != http.StatusOK || !strings.Contains(body, `"granted":true`) {
		t.Fatalf("grant: %d %s", code, body)
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

	for _, target := range []string{"v1/workers/" + w.ID, "v1/workers/" + w.ID + "/files/root/instructions.md", "v1/jobs/" + j.ID} {
		if code, body := do(other, "GET", target, ""); code != http.StatusNotFound {
			t.Errorf("another account's %s: %d %s", target, code, body)
		}
		if code, body := do(stranger, "GET", target, ""); code != http.StatusNotFound {
			t.Errorf("an unnamed device's %s: %d %s", target, code, body)
		}
	}
	// Moving a worker back, before it was ever granted.
	_, body = do(acme, "POST", "v1/workers", `{}`)
	var back struct{ ID string }
	json.Unmarshal([]byte(body), &back)
	revoke, _ := coordinator.SignGrant(device, coordinator.GrantClaims{Op: coordinator.OpRevoke, Aud: audience, Acct: "acct_acme", Worker: back.ID, Seq: 1, Iat: time.Now().Unix()})
	if code, body := do(acme, "POST", "v1/workers/"+back.ID+"/revoke", `{"v":1,"grant":"`+revoke+`"}`); code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", code, body)
	}
	if code, _ := do(acme, "GET", "v1/workers/"+back.ID, ""); code != http.StatusNotFound {
		t.Errorf("a revoked worker: %d", code)
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
		{attestation: attestTinfoil, cloudOnly: true},
		{attestation: attestTinfoil, audience: audience},
		{listen: ":8791", attestation: attestTinfoil, audience: audience},
		{listen: ":8791", accountKeys: "bm90IGEga2V5", attestation: attestTinfoil, audience: audience},
		{listen: ":8791", accountKeys: keys, attestation: "none", audience: audience},
		{listen: ":8791", accountKeys: keys, attestation: attestTinfoil},
		{listen: ":8791", accountKeys: keys, attestation: attestTinfoil, audience: "coordinator.example"},
		{listen: ":8791", accountKeys: keys, attestation: attestTinfoil, audience: "http://coordinator.example"},
		{listen: ":8791", accountKeys: keys, attestation: attestTinfoil, audience: "https://coordinator.example/v1"},
	} {
		if _, err := f.server(); err == nil {
			t.Errorf("%+v was taken", f)
		}
	}
	if s, err := (clientFlags{attestation: attestTinfoil}).server(); s != nil || err != nil {
		t.Errorf("no channel: %v %v", s, err)
	}
}

// With --test-api the client listener serves the test API's /v0/ as well,
// 503 until the coordinator is up and behind its token after; without it,
// /v0/ isn't there.
func TestClientListenerServesTheTestAPI(t *testing.T) {
	status := statusAPI(&keyStatus{Mode: keyDev, State: "waiting"}, &atomic.Pointer[coordinator.Coordinator]{})
	var channelReady, testReady atomic.Pointer[http.Handler]
	srv := httptest.NewServer(clientAPI(status, &channelReady, true, &testReady))
	defer srv.Close()
	get := func(url string) int {
		t.Helper()
		resp, err := http.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get(srv.URL + "/v0/jobs/none"); code != http.StatusServiceUnavailable {
		t.Fatalf("/v0/ before the key: %d", code)
	}
	t.Setenv(testTokenEnv, strings.Repeat("ab", 32))
	api, err := testAPI(http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	testReady.Store(&api)
	if code := get(srv.URL + "/v0/jobs/none"); code != http.StatusUnauthorized {
		t.Fatalf("/v0/ without the token: %d", code)
	}

	off := httptest.NewServer(clientAPI(status, &channelReady, false, &testReady))
	defer off.Close()
	if code := get(off.URL + "/v0/jobs/none"); code != http.StatusNotFound {
		t.Fatalf("/v0/ without --test-api: %d", code)
	}
}
