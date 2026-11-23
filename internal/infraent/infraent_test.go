package infraent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fount-labs/fount-broker/internal/coordinator"
	"github.com/fount-labs/fount-broker/internal/jobcred"
)

var (
	seed    = bytes.Repeat([]byte{1}, ed25519.SeedSize)
	key     = ed25519.NewKeyFromSeed(seed)
	address = ed25519.PublicKey(bytes.Repeat([]byte{7}, ed25519.PublicKeySize))
	now     = time.Unix(1_800_000_000, 0)
)

// vector is the request fount-infra's coordinator-mail-entitlement.test.ts
// verifies: this seed, account and address key at this time. Both pin it.
const vector = "eyJ2IjoxLCJ0eXAiOiJmb3VudC1tYWlsLXJlbmV3YWwiLCJhY2N0IjoiMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYiLCJkayI6IkJ3Y0hCd2NIQndjSEJ3Y0hCd2NIQndjSEJ3Y0hCd2NIQndjSEJ3Y0hCd2M9Iiwia2lkIjoiaW9qajNYUUo4Wlg5VXRzdFBMcGRjc3BuQ2I4ZGxCSWI4M1NJQWJRUGIxdyIsImlhdCI6MTgwMDAwMDAwMCwiZXhwIjoxODAwMDAwMzAwfQ.V4dWMYBRdhiXWwy8G4XdrA0hNa-M0VI1dJaDXdEtVSimr4n0P-ZQt4eHgDyXy9QrFFSRe8g9iQuQt_0ApWRaBw"

func client(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := New(srv.URL+"/", key)
	if err != nil {
		t.Fatal(err)
	}
	c.HTTP = srv.Client()
	c.Now = func() time.Time { return now }
	return c
}

// verify checks a request as fount-infra's verifyRenewalRequest does.
func verify(t *testing.T, token string) Claims {
	t.Helper()
	p, s, ok := strings.Cut(token, ".")
	if !ok {
		t.Fatalf("token %q has no dot", token)
	}
	payload, err1 := base64.RawURLEncoding.Strict().DecodeString(p)
	sig, err2 := base64.RawURLEncoding.Strict().DecodeString(s)
	if err1 != nil || err2 != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), payload, sig) {
		t.Fatalf("token %q doesn't verify", token)
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRequest(t *testing.T) {
	c := &Client{Key: key, Now: func() time.Time { return now }}
	token, err := c.Request("0123456789abcdef0123456789abcdef", "", address)
	if err != nil {
		t.Fatal(err)
	}
	got := verify(t, token)
	want := Claims{
		V: 1, Typ: "fount-mail-renewal", Acct: "0123456789abcdef0123456789abcdef",
		Dk:  base64.StdEncoding.EncodeToString(address),
		Kid: jobcred.PublicKey(key), Iat: now.Unix(), Exp: now.Unix() + 300,
	}
	if got != want {
		t.Fatalf("claims %+v, want %+v", got, want)
	}
	// Ed25519 is deterministic, so the whole token is pinned.
	if token != vector {
		t.Fatalf("token\n%s\nwant\n%s", token, vector)
	}
	// An account that pays for itself is a version 1 request.
	if same, _ := c.Request("0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef", address); same != vector {
		t.Fatalf("a payer that is the account: %s", same)
	}
}

// vectorPay is the version 2 request fount-infra's
// coordinator-mail-entitlement.test.ts verifies: vector's, paid by a team.
const vectorPay = "eyJ2IjoyLCJ0eXAiOiJmb3VudC1tYWlsLXJlbmV3YWwiLCJhY2N0IjoiMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYiLCJwYXkiOiJ0bV8wMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1NjciLCJkayI6IkJ3Y0hCd2NIQndjSEJ3Y0hCd2NIQndjSEJ3Y0hCd2NIQndjSEJ3Y0hCd2M9Iiwia2lkIjoiaW9qajNYUUo4Wlg5VXRzdFBMcGRjc3BuQ2I4ZGxCSWI4M1NJQWJRUGIxdyIsImlhdCI6MTgwMDAwMDAwMCwiZXhwIjoxODAwMDAwMzAwfQ.xvCKRFp1hfCNG-cPRnHHcCsNT5HNz__gJD87SjpIHCwrxc1grpUKdBSvQHGjOr1p-wn0Z6P_ldW4-juQK_IiAw"

// A worker a team pays for names its license account and the team.
func TestRequestPay(t *testing.T) {
	c := &Client{Key: key, Now: func() time.Time { return now }}
	token, err := c.Request("0123456789abcdef0123456789abcdef", "tm_0123456789abcdef01234567", address)
	if err != nil {
		t.Fatal(err)
	}
	got := verify(t, token)
	want := Claims{
		V: 2, Typ: "fount-mail-renewal", Acct: "0123456789abcdef0123456789abcdef", Pay: "tm_0123456789abcdef01234567",
		Dk:  base64.StdEncoding.EncodeToString(address),
		Kid: jobcred.PublicKey(key), Iat: now.Unix(), Exp: now.Unix() + 300,
	}
	if got != want {
		t.Fatalf("claims %+v, want %+v", got, want)
	}
	if token != vectorPay {
		t.Fatalf("token\n%s\nwant\n%s", token, vectorPay)
	}
}

func TestRequestRefuses(t *testing.T) {
	c := &Client{Key: key}
	if _, err := c.Request("", "", address); err == nil {
		t.Fatal("a request with no account")
	}
	if _, err := c.Request("acct", "", address[:31]); err == nil {
		t.Fatal("a request with a short key")
	}
}

func TestNew(t *testing.T) {
	for _, base := range []string{"http://api.fount.sh/", "https://", "https://api.fount.sh/?x=1", "https://u:p@api.fount.sh/", "api.fount.sh"} {
		if _, err := New(base, key); err == nil {
			t.Errorf("New(%q) took it", base)
		}
	}
	if _, err := New("https://api.fount.sh/", key[:32]); err == nil {
		t.Error("New took a short key")
	}
	if _, err := New("https://api.fount.sh/", key); err != nil {
		t.Error(err)
	}
}

func TestIssue(t *testing.T) {
	var seen *http.Request
	var body []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r
		body, _ = io.ReadAll(r.Body)
		w.Write([]byte(`{"entitlement":"tok.sig","issuedAt":1800000000,"expiresAt":1803000000,"graceEnds":null}`))
	}))
	defer srv.Close()
	ent, err := client(t, srv).Issue(context.Background(), coordinator.EntitlementRequest{Account: "acct1", Pay: "tm_1", WorkerID: "w1", MailboxID: "mb1", SigningKey: address})
	if err != nil {
		t.Fatal(err)
	}
	if ent.Token != "tok.sig" || !ent.IssuedAt.Equal(now) || !ent.GraceEnds.IsZero() {
		t.Fatalf("entitlement %+v", ent)
	}
	if seen.Method != http.MethodPost || seen.URL.Path != "/coordinator/mail-entitlement" || len(body) != 0 {
		t.Fatalf("asked %s %s with %q", seen.Method, seen.URL.Path, body)
	}
	claims := verify(t, strings.TrimPrefix(seen.Header.Get("Authorization"), "Bearer "))
	if claims.V != 2 || claims.Acct != "acct1" || claims.Pay != "tm_1" || claims.Dk != base64.StdEncoding.EncodeToString(address) {
		t.Fatalf("claims %+v", claims)
	}
	// The worker and the mailbox stay with the coordinator.
	if raw := seen.Header.Get("Authorization"); strings.Contains(raw, "w1") || strings.Contains(raw, "mb1") {
		t.Fatal("the request names the worker or mailbox")
	}
}

func TestIssueGrace(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"entitlement":"tok.sig","issuedAt":1800000000,"expiresAt":1803000000,"graceEnds":1800100000}`))
	}))
	defer srv.Close()
	ent, err := client(t, srv).Issue(context.Background(), coordinator.EntitlementRequest{Account: "acct1", SigningKey: address})
	if err != nil {
		t.Fatal(err)
	}
	if !ent.GraceEnds.Equal(time.Unix(1_800_100_000, 0)) {
		t.Fatalf("grace ends %s", ent.GraceEnds)
	}
}

func TestIssueRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		lapsed bool
	}{
		{"lapsed", 403, `{"error":"no_access","reason":"period_ended"}`, true},
		{"no plan", 403, `{"error":"no_access","reason":"no_cloud_plan"}`, true},
		{"another 403", 403, `{"message":"Forbidden"}`, false},
		{"unknown key", 401, `{"error":"unauthorized","reason":"unknown_key"}`, false},
		{"rate limited", 429, `{"error":"rate_limited","retry_after_seconds":60}`, false},
		{"not configured", 503, `{"error":"not_configured"}`, false},
		{"down", 500, `oops`, false},
		{"no entitlement", 200, `{"issuedAt":1800000000}`, false},
		{"not JSON", 200, `<html>`, false},
		{"a redirect", 302, ``, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.status == 302 {
					http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
					return
				}
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			_, err := client(t, srv).Issue(context.Background(), coordinator.EntitlementRequest{Account: "acct1", SigningKey: address})
			if err == nil {
				t.Fatal("no error")
			}
			if errors.Is(err, coordinator.ErrAccountLapsed) != tc.lapsed {
				t.Fatalf("lapsed %v: %v", !tc.lapsed, err)
			}
		})
	}
}

func TestIssueBoundsTheAnswer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(bytes.Repeat([]byte("a"), maxAnswer+1))
	}))
	defer srv.Close()
	if _, err := client(t, srv).Issue(context.Background(), coordinator.EntitlementRequest{Account: "acct1", SigningKey: address}); err == nil {
		t.Fatal("took an answer past the bound")
	}
}
