package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/fount-labs/fount-broker/internal/coordinator"
)

const testControlToken = "0123456789abcdef0123456789abcdef0123456789abcdef"

func TestTheControlRoute(t *testing.T) {
	hub := coordinator.NewRunnerHub(nil)
	defer hub.Close()
	hub.TeamStage = "dev"
	var jobs atomic.Pointer[coordinator.Coordinator]
	control, err := controlAPI(testControlToken, "dev", hub, &jobs)
	if err != nil {
		t.Fatal(err)
	}
	var channelReady atomic.Pointer[http.Handler]
	status := statusAPI(&keyStatus{Mode: keyDev, State: "waiting"}, &jobs, func() any { return hub.Runners() })
	srv := httptest.NewServer(withControl(clientAPI(status, &channelReady, false, nil, nil), control))
	defer srv.Close()
	get := func(auth string) (int, string) { return getPath(t, srv.URL+"/control/runners", auth) }
	if code, _ := getPath(t, srv.URL+"/control/mail", ""); code != http.StatusUnauthorized {
		t.Errorf("/control/mail with no token: %d", code)
	}
	if code, _ := getPath(t, srv.URL+"/control/backup", "Bearer wrong"); code != http.StatusUnauthorized {
		t.Errorf("/control/backup with the wrong token: %d", code)
	}
	if code, _ := getPath(t, srv.URL+"/control/backup", "Bearer "+testControlToken); code != http.StatusServiceUnavailable {
		t.Errorf("/control/backup before the coordinator runs: %d", code)
	}
	for _, auth := range []string{"", "Bearer wrong", testControlToken, "Bearer " + testControlToken + "x"} {
		if code, _ := get(auth); code != http.StatusUnauthorized {
			t.Errorf("auth %q: %d", auth, code)
		}
	}
	if code, _ := get("Bearer " + testControlToken); code != http.StatusServiceUnavailable {
		t.Errorf("before the coordinator runs: %d", code)
	}

	dir := t.TempDir()
	key, _ := coordinator.NewWrappingKey()
	c, err := coordinator.New(coordinator.Config{
		StateDir: dir + "/state", WorkDir: dir + "/work", Store: coordinator.DirStore{Root: dir + "/objects"},
		Key: key, Pool: coordinator.NewPool(1, 1, nil), Runner: coordinator.LocalRunner{Command: []string{"false"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const team = "tm_0123456789abcdef01234567"
	w, _ := c.CreateWorker(team, nil)
	if _, err := c.Enqueue(w.ID, coordinator.JobSpec{ThreadID: "t1", SessionID: "s1", Instruction: "hi", Config: json.RawMessage(`{"model":"m"}`)}); err != nil {
		t.Fatal(err)
	}
	solo, _ := c.CreateWorker("acct_solo", nil)
	c.Enqueue(solo.ID, coordinator.JobSpec{ThreadID: "t1", SessionID: "s1", Instruction: "hi", Config: json.RawMessage(`{"model":"m"}`)})
	jobs.Store(c)
	code, body := get("Bearer " + testControlToken)
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, body)
	}
	var out struct {
		Runners []map[string]any `json:"runners"`
	}
	dec := json.NewDecoder(strings.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Runners) != 1 {
		t.Fatalf("%s", body)
	}
	r := out.Runners[0]
	want := map[string]any{"name": "runner-dev-tm-0123456789abcdef01234567", "account": team, "queued": float64(1), "running": float64(0), "connected": false}
	for k, v := range want {
		if r[k] != v {
			t.Errorf("%s: %v, want %v", k, r[k], v)
		}
	}
	// Never run and never linked: no lastActivityAt, and not retired.
	for _, k := range []string{"lastActivityAt", "retired"} {
		if _, ok := r[k]; ok {
			t.Errorf("%s is there: %s", k, body)
		}
	}
	if len(r) != len(want) {
		t.Errorf("fields %s", body)
	}

	// A coordinator with no mail loop has no mail status, here or in /status.
	if code, _ := getPath(t, srv.URL+"/control/mail", "Bearer "+testControlToken); code != http.StatusNotFound {
		t.Errorf("/control/mail without mail: %d", code)
	}
	if _, body := getPath(t, srv.URL+"/status", ""); strings.Contains(body, `"mail"`) {
		t.Errorf("/status without mail: %s", body)
	}
	// Without backups, /control/backup says so rather than 404.
	if code, body := getPath(t, srv.URL+"/control/backup", "Bearer "+testControlToken); code != http.StatusOK || body != `{"backup":{"configured":false}}`+"\n" {
		t.Errorf("/control/backup without backups: %d %s", code, body)
	}
}

func TestTheBackupControlRoute(t *testing.T) {
	hub := coordinator.NewRunnerHub(nil)
	defer hub.Close()
	var jobs atomic.Pointer[coordinator.Coordinator]
	control, err := controlAPI(testControlToken, "dev", hub, &jobs)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(control)
	defer srv.Close()

	_, authority, _ := ed25519.GenerateKey(nil)
	vault, bucket := &coordinator.MemVault{Authority: authority}, coordinator.NewMemBucket()
	g, err := vault.Boot()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	key, _ := coordinator.NewWrappingKey()
	c, err := coordinator.New(coordinator.Config{
		StateDir: dir + "/state", WorkDir: dir + "/work", Store: coordinator.DirStore{Root: dir + "/objects"},
		Key: key, Pool: coordinator.NewPool(1, 1, nil), Runner: coordinator.LocalRunner{Command: []string{"false"}},
		Backup: &coordinator.BackupConfig{Bucket: bucket, Counter: vault, Generations: g},
	})
	if err != nil {
		t.Fatal(err)
	}
	jobs.Store(c)
	read := func() map[string]any {
		t.Helper()
		code, body := getPath(t, srv.URL+"/control/backup", "Bearer "+testControlToken)
		if code != http.StatusOK {
			t.Fatalf("%d %s", code, body)
		}
		var out struct {
			Backup map[string]any `json:"backup"`
		}
		dec := json.NewDecoder(strings.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out.Backup
	}

	b := read()
	if b["configured"] != true || b["generation"] != float64(1) || !strings.HasPrefix(b["last_root"].(string), "roots/") {
		t.Fatalf("at boot: %v", b)
	}
	for _, k := range []string{"last_attempt_at", "last_success_at", "last_root_at", "last_run", "interval_seconds"} {
		if _, ok := b[k]; !ok {
			t.Errorf("no %s: %v", k, b)
		}
	}
	if _, ok := b["last_error"]; ok {
		t.Errorf("an error at boot: %v", b)
	}

	const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	bucket.FailPut = func(string) error { return errors.New("s3: put: 403 Forbidden: SignatureDoesNotMatch " + secret) }
	w, _ := c.CreateWorker("acme", nil)
	if err := c.PutFile(w.ID, "files/memo.md", []byte("memo")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Backup(context.Background()); err == nil {
		t.Fatal("a refused put backed up")
	}
	b = read()
	got, _ := b["last_error"].(string)
	if !strings.Contains(got, "SignatureDoesNotMatch") || strings.Contains(got, secret) || b["last_error_at"] == nil {
		t.Fatalf("after a failure: %v", b)
	}
}

func getPath(t *testing.T, url, auth string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func TestTheControlRouteIsOffWithoutItsToken(t *testing.T) {
	hub := coordinator.NewRunnerHub(nil)
	defer hub.Close()
	var jobs atomic.Pointer[coordinator.Coordinator]
	control, err := controlAPI("", "dev", hub, &jobs)
	if err != nil || control != nil {
		t.Fatalf("%v %v", control, err)
	}
	var channelReady atomic.Pointer[http.Handler]
	status := statusAPI(&keyStatus{Mode: keyDev, State: "waiting"}, &jobs, nil)
	srv := httptest.NewServer(withControl(clientAPI(status, &channelReady, false, nil, nil), control))
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL+"/control/runners", nil)
	req.Header.Set("Authorization", "Bearer "+testControlToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("%d", res.StatusCode)
	}
	if _, err := controlAPI("short", "dev", hub, &jobs); err == nil {
		t.Fatal("a short token")
	}
	if _, err := controlAPI(testControlToken, "", hub, &jobs); err == nil {
		t.Fatal("a token with no team stage")
	}
	if _, err := controlAPI(testControlToken, "dev", nil, &jobs); err == nil {
		t.Fatal("a token with no runners dialling in")
	}
	if err := checkTeamStage("dev", false); err == nil {
		t.Fatal("a stage with no runners dialling in")
	}
	if err := checkTeamStage("Dev_1", true); err == nil {
		t.Fatal("a stage that isn't a name part")
	}
}
