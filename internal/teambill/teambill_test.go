package teambill

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fount-labs/fount-broker/internal/coordinator"
	"github.com/fount-labs/fount-broker/internal/jobcred"
)

var (
	seed    = bytes.Repeat([]byte{1}, ed25519.SeedSize)
	key     = ed25519.NewKeyFromSeed(seed)
	other   = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	now     = time.Unix(1_800_000_000, 0)
	team    = "tm_0123456789abcdef01234567"
	account = "0123456789abcdef0123456789abcdef"
)

// vectors is testdata/team-billing-vectors.json, which fount-infra's
// test/unit/coordinator-statement.test.ts verifies from its copy at
// test/unit/fixtures/team-billing-vectors.json: the two must stay equal.
type vectors struct {
	Comment   string `json:"comment"`
	Seed      string `json:"coordinator_ed25519_seed"`
	Kid       string `json:"kid"`
	OtherSeed string `json:"other_ed25519_seed"`
	OtherKid  string `json:"other_kid"`
	Team      string `json:"team"`
	Account   string `json:"account"`
	Iat       int64  `json:"iat"`
	Admin     string `json:"admin"`
	Seat      string `json:"seat"`
	Status    string `json:"status"`
	// By a key no coordinator's attestation endorsed.
	AdminByOther string `json:"admin_by_other"`
}

const vectorsPath = "testdata/team-billing-vectors.json"

func makeVectors(t *testing.T) vectors {
	t.Helper()
	c := &Client{Key: key, Now: func() time.Time { return now }}
	o := &Client{Key: other, Now: func() time.Time { return now }}
	v := vectors{
		Comment: "Team billing statements (internal/teambill). Test keys only. Rewrite: TEAM_BILLING_VECTORS_WRITE=1 go test -run TestVectors ./internal/teambill, then copy to fount-infra test/unit/fixtures/team-billing-vectors.json",
		Seed:    hex.EncodeToString(seed), Kid: jobcred.PublicKey(key),
		OtherSeed: hex.EncodeToString(other.Seed()), OtherKid: jobcred.PublicKey(other),
		Team: team, Account: account, Iat: now.Unix(),
	}
	var err error
	for _, s := range []struct {
		out       *string
		c         *Client
		typ, acct string
	}{{&v.Admin, c, TypeAdmin, account}, {&v.Seat, c, TypeSeat, account}, {&v.Status, c, TypeStatus, ""}, {&v.AdminByOther, o, TypeAdmin, account}} {
		if *s.out, _, err = s.c.Sign(s.typ, team, s.acct); err != nil {
			t.Fatal(err)
		}
	}
	return v
}

func TestVectors(t *testing.T) {
	made := makeVectors(t)
	if os.Getenv("TEAM_BILLING_VECTORS_WRITE") != "" {
		out, _ := json.MarshalIndent(made, "", "  ")
		if err := os.WriteFile(vectorsPath, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if made != v {
		t.Fatalf("the vectors changed:\n%+v\nwant\n%+v", made, v)
	}
	if got := verify(t, v.Seat, key); got.Exp-got.Iat != int64(SeatLifetime/time.Second) || got.Acct != account {
		t.Fatalf("the seat vector: %+v", got)
	}
}

// verify checks a statement as fount-infra's verifyCoordinatorStatement does.
func verify(t *testing.T, token string, k ed25519.PrivateKey) Claims {
	t.Helper()
	p, s, ok := strings.Cut(token, ".")
	if !ok {
		t.Fatalf("token %q has no dot", token)
	}
	payload, err1 := base64.RawURLEncoding.Strict().DecodeString(p)
	sig, err2 := base64.RawURLEncoding.Strict().DecodeString(s)
	if err1 != nil || err2 != nil || !ed25519.Verify(k.Public().(ed25519.PublicKey), payload, sig) {
		t.Fatalf("token %q doesn't verify", token)
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestStatements(t *testing.T) {
	c := &Client{Key: key, Now: func() time.Time { return now }}
	admin, err := c.Statement(coordinator.StatementAdmin, team, account)
	if err != nil {
		t.Fatal(err)
	}
	got := verify(t, admin.Token, key)
	want := Claims{V: 1, Typ: TypeAdmin, Team: team, Acct: account, Kid: jobcred.PublicKey(key), Iat: now.Unix(), Exp: now.Unix() + 300}
	if got != want || !admin.ExpiresAt.Equal(now.Add(AdminLifetime)) {
		t.Fatalf("admin statement %+v, expires %s", got, admin.ExpiresAt)
	}
	seat, _ := c.Statement(coordinator.StatementSeat, team, account)
	if got := verify(t, seat.Token, key); got.Typ != TypeSeat || got.Exp != now.Unix()+86400 {
		t.Fatalf("seat statement %+v", got)
	}
	// The status request names no account.
	status, _, _ := c.Sign(TypeStatus, team, "")
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(status, ".")[0])
	if bytes.Contains(payload, []byte("acct")) {
		t.Fatalf("a status request names an account: %s", payload)
	}

	for _, bad := range []func() error{
		func() error { _, err := c.Statement("owner", team, account); return err },
		func() error { _, err := c.Statement(coordinator.StatementAdmin, team, ""); return err },
		func() error { _, err := c.Statement(coordinator.StatementAdmin, "", account); return err },
		func() error { _, _, err := c.Sign(TypeStatus, team, account); return err },
		func() error { _, _, err := c.Sign("fount-job", team, account); return err },
	} {
		if bad() == nil {
			t.Error("signed a statement it shouldn't")
		}
	}
}

func TestNew(t *testing.T) {
	for _, base := range []string{"http://api.fount.sh/", "https://", "https://api.fount.sh/?x=1", "https://u:p@api.fount.sh/"} {
		if _, err := New(base, key); err == nil {
			t.Errorf("New(%q) took it", base)
		}
	}
	if _, err := New("https://api.fount.sh/", key[:32]); err == nil {
		t.Error("New took a short key")
	}
}

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

func TestStatus(t *testing.T) {
	var seen *http.Request
	var body []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r
		body, _ = io.ReadAll(r.Body)
		w.Write([]byte(`{"status":"past_due","tier":"team","periodEnd":1800100000,"graceEnds":1800100000,"seats":5}`))
	}))
	defer srv.Close()
	ent, err := client(t, srv).Status(context.Background(), team)
	if err != nil {
		t.Fatal(err)
	}
	want := coordinator.TeamEntitlement{Status: "past_due", Tier: "team", PeriodEnd: time.Unix(1_800_100_000, 0).UTC(), GraceEnds: time.Unix(1_800_100_000, 0).UTC(), Seats: 5}
	if ent != want {
		t.Fatalf("entitlement %+v", ent)
	}
	if seen.Method != http.MethodPost || seen.URL.Path != "/coordinator/team-entitlement" || len(body) != 0 {
		t.Fatalf("asked %s %s with %q", seen.Method, seen.URL.Path, body)
	}
	got := verify(t, strings.TrimPrefix(seen.Header.Get("Authorization"), "Bearer "), key)
	if got.Typ != TypeStatus || got.Team != team || got.Acct != "" || got.Exp-got.Iat != 300 {
		t.Fatalf("claims %+v", got)
	}
}

func TestStatusRenewing(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"renewing","tier":"team","periodEnd":1800100000,"graceEnds":null,"seats":3}`))
	}))
	defer srv.Close()
	ent, err := client(t, srv).Status(context.Background(), team)
	if err != nil {
		t.Fatal(err)
	}
	want := coordinator.TeamEntitlement{Status: coordinator.BillingRenewing, Tier: "team", PeriodEnd: time.Unix(1_800_100_000, 0).UTC(), Seats: 3}
	if ent != want {
		t.Fatalf("entitlement %+v", ent)
	}
}

func TestStatusRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		refused    string
	}{
		{"no subscription", `{"error":"no_access","reason":"no_subscription"}`, 403, "no_subscription"},
		{"ended", `{"error":"no_access","reason":"period_ended"}`, 403, "period_ended"},
		{"another 403", `{"message":"Forbidden"}`, 403, ""},
		{"unknown key", `{"error":"unauthorized","reason":"unknown_key"}`, 401, ""},
		{"rate limited", `{"error":"rate_limited","retry_after_seconds":60}`, 429, ""},
		{"down", `oops`, 500, ""},
		{"no status", `{"tier":"team","periodEnd":1800100000,"seats":1}`, 200, ""},
		{"no seats", `{"status":"active","tier":"team","periodEnd":1800100000,"seats":0}`, 200, ""},
		{"canceled is not an answer", `{"status":"canceled","tier":"team","periodEnd":1800100000,"seats":1}`, 200, ""},
		{"a redirect", ``, 302, ""},
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
			_, err := client(t, srv).Status(context.Background(), team)
			if err == nil {
				t.Fatal("no error")
			}
			var refused *coordinator.TeamNotEntitled
			if errors.As(err, &refused) != (tc.refused != "") || (refused != nil && refused.Reason != tc.refused) {
				t.Fatalf("refused %q: %v", tc.refused, err)
			}
		})
	}
}
