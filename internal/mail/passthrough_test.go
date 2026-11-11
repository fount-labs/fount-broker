package mail

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// passEdge is a Device API that checks each request's signature the way the
// edge does, over the method, path and body it receives, and answers with
// whatever the test sets.
type passEdge struct {
	t   *testing.T
	pub ed25519.PublicKey
	srv *httptest.Server

	mu    sync.Mutex
	got   []*http.Request
	bodys [][]byte
	reply func(w http.ResponseWriter)
}

func newPassEdge(t *testing.T, pub ed25519.PublicKey) *passEdge {
	e := &passEdge{t: t, pub: pub}
	e.srv = httptest.NewServer(http.HandlerFunc(e.serve))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *passEdge) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if req.URL.Scheme+"://"+req.URL.Host+"/" != e.Base() {
		e.t.Errorf("request to %s, not the edge", req.URL)
	}
	return e.srv.Client().Do(req.WithContext(ctx))
}
func (e *passEdge) Base() string { return e.srv.URL + "/" }
func (e *passEdge) AttestedSigningKey(context.Context) (ed25519.PublicKey, error) {
	return nil, nil
}

func (e *passEdge) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	e.mu.Lock()
	e.got = append(e.got, r)
	e.bodys = append(e.bodys, body)
	reply := e.reply
	e.mu.Unlock()
	ts, _ := strconv.ParseInt(r.Header.Get(HeaderTimestamp), 10, 64)
	sig, _ := base64.StdEncoding.DecodeString(r.Header.Get(HeaderSignature))
	// Challenges and passkey-approved requests carry no device signature.
	passkey := strings.HasPrefix(r.URL.Path, "/recover") || strings.HasPrefix(r.URL.Path, "/pause")
	if !passkey && !ed25519.Verify(e.pub, []byte(Canonical(r.Method, r.URL.Path, body, ts, r.Header.Get(HeaderNonce))), sig) {
		http.Error(w, `{"error":"signature does not verify"}`, http.StatusUnauthorized)
		return
	}
	if reply != nil {
		reply(w)
		return
	}
	w.Write([]byte(`{"ok":true}`))
}

func (e *passEdge) calls() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.got)
}

// signed builds the headers I's DeviceClient sends for one call.
func signed(priv ed25519.PrivateKey, keyID, method, path string, body []byte, entitlement string) map[string]string {
	ts := time.Now().Unix()
	nonce := rand.Text()
	h := map[string]string{
		HeaderTimestamp: strconv.FormatInt(ts, 10),
		HeaderNonce:     nonce,
		HeaderSignature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(Canonical(method, path, body, ts, nonce)))),
	}
	if keyID != "" {
		h[HeaderKeyID] = keyID
	}
	if entitlement != "" {
		h[HeaderEntitlement] = entitlement
	}
	return h
}

func passSetup(t *testing.T) (*Service, *passEdge, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e := newPassEdge(t, pub)
	return New(e, &fakeChecker{}), e, priv
}

const testMailbox = "00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa"

func TestPassthroughOps(t *testing.T) {
	s, e, priv := passSetup(t)
	cases := []struct {
		op, mailbox, path, method, urlPath, entitlement string
		body                                            string
	}{
		{OpHandle, "", "smithcpa", "GET", "/handle/smithcpa", "ent.token", ""},
		{OpMailbox, "", "", "POST", "/mailbox", "ent.token", `{"handle":"smithcpa","decryption_key":"AAAA"}`},
		{OpAddress, testMailbox, "", "POST", "/address", "", `{"address":"tax.smithcpa@fountbox.com"}`},
		{OpRouting, testMailbox, "", "PUT", "/routing", "", `{"version":2,"owners":["a"]}`},
		{OpRenew, testMailbox, "", "POST", "/entitlement", "ent.token", `{}`},
	}
	for i, c := range cases {
		h := signed(priv, c.mailbox, c.method, c.urlPath, []byte(c.body), c.entitlement)
		res, err := s.Passthrough(context.Background(), c.op, c.mailbox, c.path, h, []byte(c.body))
		if err != nil {
			t.Fatalf("%s: %v", c.op, err)
		}
		if res.Status != 200 || string(res.Body) != `{"ok":true}` || res.RetryAfter != nil {
			t.Fatalf("%s: got %+v %s", c.op, res, res.Body)
		}
		r, body := e.got[i], e.bodys[i]
		if r.Method != c.method || r.URL.Path != c.urlPath || r.URL.RawQuery != "" || string(body) != c.body {
			t.Fatalf("%s: edge got %s %s %q", c.op, r.Method, r.URL, body)
		}
		var fount []string
		for name := range r.Header {
			if strings.HasPrefix(name, "Fount-") {
				fount = append(fount, name)
			}
		}
		slices.Sort(fount)
		want := slices.Sorted(maps.Keys(h))
		if !slices.Equal(fount, want) {
			t.Fatalf("%s: edge got Fount headers %v, want %v", c.op, fount, want)
		}
		if ct := r.Header.Get("Content-Type"); (c.body != "") != (ct == "application/json") {
			t.Fatalf("%s: Content-Type %q", c.op, ct)
		}
	}
}

// approved builds the headers I's DeviceClient sends for a passkey-approved
// call: no signature.
func approved(keyID string) map[string]string {
	return map[string]string{
		HeaderKeyID:     keyID,
		HeaderTimestamp: strconv.FormatInt(time.Now().Unix(), 10),
		HeaderNonce:     rand.Text(),
	}
}

func TestPassthroughPasskeyOps(t *testing.T) {
	s, e, _ := passSetup(t)
	kc := strings.Repeat("ab", 32)
	cases := []struct {
		op, path, method, url string
		headers               map[string]string
		body                  string
	}{
		{OpRecoverChallenge, kc, "GET", "/recover/" + testMailbox + "?kc=" + kc, nil, ""},
		{OpRecover, "", "POST", "/recover", approved(testMailbox), `{"challenge":"AA","assertion":{}}`},
		{OpPauseChallenge, "true", "GET", "/pause/" + testMailbox + "?paused=true", map[string]string{}, ""},
		{OpPauseChallenge, "false", "GET", "/pause/" + testMailbox + "?paused=false", nil, ""},
		{OpPause, "", "POST", "/pause", approved(testMailbox), `{"challenge":"AA","paused":true,"assertion":{}}`},
	}
	for i, c := range cases {
		res, err := s.Passthrough(context.Background(), c.op, testMailbox, c.path, c.headers, []byte(c.body))
		if err != nil {
			t.Fatalf("%s: %v", c.op, err)
		}
		if res.Status != 200 {
			t.Fatalf("%s: got %+v %s", c.op, res, res.Body)
		}
		r, body := e.got[i], e.bodys[i]
		if r.Method != c.method || r.URL.RequestURI() != c.url || string(body) != c.body {
			t.Fatalf("%s: edge got %s %s %q", c.op, r.Method, r.URL.RequestURI(), body)
		}
		var fount []string
		for name := range r.Header {
			if strings.HasPrefix(name, "Fount-") {
				fount = append(fount, name)
			}
		}
		slices.Sort(fount)
		if want := slices.Sorted(maps.Keys(c.headers)); !slices.Equal(fount, want) {
			t.Fatalf("%s: edge got Fount headers %v, want %v", c.op, fount, want)
		}
	}
}

func TestPassthroughStatuses(t *testing.T) {
	s, e, priv := passSetup(t)
	cases := []struct {
		reply      func(w http.ResponseWriter)
		status     int
		body       string
		retryAfter string
	}{
		{func(w http.ResponseWriter) { http.Error(w, `{"error":"handle already registered"}`, 409) }, 409, `{"error":"handle already registered"}`, ""},
		{func(w http.ResponseWriter) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, `{"error":"slow down"}`, 429)
		}, 429, `{"error":"slow down"}`, "1"},
		{func(w http.ResponseWriter) { http.Error(w, `{"error":"no such mailbox"}`, 404) }, 404, `{"error":"no such mailbox"}`, ""},
		{func(w http.ResponseWriter) {
			w.Header().Set("Retry-After", "Wed, 21 Oct 2026 07:28:00 GMT")
			w.WriteHeader(503)
			w.Write([]byte("busy\n"))
		}, 503, `"busy\n"`, ""},
		{func(w http.ResponseWriter) { w.WriteHeader(201) }, 201, `null`, ""},
		{func(w http.ResponseWriter) { w.WriteHeader(302) }, 302, `null`, ""},
	}
	for _, c := range cases {
		e.reply = c.reply
		h := signed(priv, testMailbox, "PUT", "/routing", []byte(`{}`), "")
		res, err := s.Passthrough(context.Background(), OpRouting, testMailbox, "", h, []byte(`{}`))
		if err != nil {
			t.Fatalf("%d: %v", c.status, err)
		}
		out, _ := json.Marshal(res)
		var back struct {
			Status     int             `json:"status"`
			Body       json.RawMessage `json:"body"`
			RetryAfter *uint64         `json:"retry_after"`
		}
		json.Unmarshal(out, &back)
		if back.Status != c.status || string(back.Body) != c.body {
			t.Errorf("%d: got %s", c.status, out)
		}
		if got := ""; back.RetryAfter != nil {
			got = strconv.FormatUint(*back.RetryAfter, 10)
			if got != c.retryAfter {
				t.Errorf("%d: retry_after %s", c.status, got)
			}
		} else if c.retryAfter != "" {
			t.Errorf("%d: no retry_after", c.status)
		}
	}

	e.reply = func(w http.ResponseWriter) { w.Write([]byte(`"` + strings.Repeat("a", MaxPassBody) + `"`)) }
	h := signed(priv, testMailbox, "PUT", "/routing", nil, "")
	if _, err := s.Passthrough(context.Background(), OpRouting, testMailbox, "", h, nil); !errors.Is(err, ErrEdge) {
		t.Fatalf("oversized reply: %v", err)
	}
}

func TestPassthroughRefusals(t *testing.T) {
	s, e, priv := passSetup(t)
	ok := func() map[string]string { return signed(priv, "", "GET", "/handle/x", nil, "t") }
	with := func(k, v string) map[string]string {
		h := ok()
		h[k] = v
		return h
	}
	without := func(k string) map[string]string {
		h := ok()
		delete(h, k)
		return h
	}
	routing := signed(priv, testMailbox, "PUT", "/routing", nil, "")
	cases := map[string]struct {
		op, mailbox, path string
		headers           map[string]string
		body              string
	}{
		"unknown op":             {"list", testMailbox, "", ok(), ""},
		"license op":             {OpLicenseEntitlement, "", "", ok(), ""},
		"handle traversal":       {OpHandle, "", "../mail", ok(), ""},
		"handle slash":           {OpHandle, "", "a/b", ok(), ""},
		"handle query":           {OpHandle, "", "a?x=1", ok(), ""},
		"handle encoded":         {OpHandle, "", "a%2fb", ok(), ""},
		"handle upper":           {OpHandle, "", "Smith", ok(), ""},
		"handle empty":           {OpHandle, "", "", ok(), ""},
		"handle too long":        {OpHandle, "", strings.Repeat("a", 65), ok(), ""},
		"handle url":             {OpHandle, "", "https://evil.example", ok(), ""},
		"handle body":            {OpHandle, "", "x", ok(), "{}"},
		"handle mailbox":         {OpHandle, testMailbox, "x", ok(), ""},
		"handle key id":          {OpHandle, "", "x", with(HeaderKeyID, testMailbox), ""},
		"mailbox with mailbox":   {OpMailbox, testMailbox, "", with(HeaderKeyID, testMailbox), "{}"},
		"mailbox path":           {OpMailbox, "", "x", ok(), "{}"},
		"address no mailbox":     {OpAddress, "", "", ok(), "{}"},
		"address short mailbox":  {OpAddress, "ab", "", with(HeaderKeyID, "ab"), "{}"},
		"routing key mismatch":   {OpRouting, testMailbox, "", with(HeaderKeyID, strings.Repeat("11", 32)), "{}"},
		"routing no key id":      {OpRouting, testMailbox, "", ok(), "{}"},
		"routing path":           {OpRouting, testMailbox, "x", routing, "{}"},
		"routing not json":       {OpRouting, testMailbox, "", routing, "{"},
		"routing too big":        {OpRouting, testMailbox, "", routing, `"` + strings.Repeat("a", MaxPassBody) + `"`},
		"no signature":           {OpHandle, "", "x", without(HeaderSignature), ""},
		"no nonce":               {OpHandle, "", "x", without(HeaderNonce), ""},
		"no timestamp":           {OpHandle, "", "x", without(HeaderTimestamp), ""},
		"content type":           {OpHandle, "", "x", with("Content-Type", "text/plain"), ""},
		"authorization":          {OpHandle, "", "x", with("Authorization", "Bearer x"), ""},
		"host":                   {OpHandle, "", "x", with("Host", "evil.example"), ""},
		"other fount header":     {OpHandle, "", "x", with("Fount-Other", "x"), ""},
		"header case duplicate":  {OpHandle, "", "x", with("fount-nonce", "again"), ""},
		"header newline":         {OpHandle, "", "x", with(HeaderEntitlement, "a\r\nHost: evil"), ""},
		"header empty":           {OpHandle, "", "x", with(HeaderEntitlement, ""), ""},
		"header too long":        {OpHandle, "", "x", with(HeaderEntitlement, strings.Repeat("a", maxHeaderValue+1)), ""},
		"header non-ascii":       {OpHandle, "", "x", with(HeaderEntitlement, "é"), ""},
		"renew uppercase id":     {OpRenew, strings.ToUpper(testMailbox), "", with(HeaderKeyID, strings.ToUpper(testMailbox)), "{}"},
		"mailbox no signature":   {OpMailbox, "", "", map[string]string{}, "{}"},
		"mailbox nil headers":    {OpMailbox, "", "", nil, "{}"},
		"address key id but not": {OpAddress, testMailbox, "", without(HeaderKeyID), "{}"},

		"recover challenge no mailbox": {OpRecoverChallenge, "", strings.Repeat("ab", 32), nil, ""},
		"recover challenge short kc":   {OpRecoverChallenge, testMailbox, "abcd", nil, ""},
		"recover challenge upper kc":   {OpRecoverChallenge, testMailbox, strings.Repeat("AB", 32), nil, ""},
		"recover challenge kc query":   {OpRecoverChallenge, testMailbox, strings.Repeat("ab", 31) + "&x=1", nil, ""},
		"recover challenge headers":    {OpRecoverChallenge, testMailbox, strings.Repeat("ab", 32), approved(testMailbox), ""},
		"recover challenge body":       {OpRecoverChallenge, testMailbox, strings.Repeat("ab", 32), nil, "{}"},
		"pause challenge bad state":    {OpPauseChallenge, testMailbox, "yes", nil, ""},
		"pause challenge empty state":  {OpPauseChallenge, testMailbox, "", nil, ""},
		"pause challenge traversal":    {OpPauseChallenge, "../mail", "true", nil, ""},
		"pause challenge signed":       {OpPauseChallenge, testMailbox, "true", signed(priv, "", "GET", "/pause", nil, ""), ""},
		"recover no key id":            {OpRecover, testMailbox, "", without2(approved(testMailbox), HeaderKeyID), "{}"},
		"recover key mismatch":         {OpRecover, testMailbox, "", approved(strings.Repeat("11", 32)), "{}"},
		"recover no nonce":             {OpRecover, testMailbox, "", without2(approved(testMailbox), HeaderNonce), "{}"},
		"recover no timestamp":         {OpRecover, testMailbox, "", without2(approved(testMailbox), HeaderTimestamp), "{}"},
		"recover with signature":       {OpRecover, testMailbox, "", with2(approved(testMailbox), HeaderSignature, "c2ln"), "{}"},
		"recover with entitlement":     {OpRecover, testMailbox, "", with2(approved(testMailbox), HeaderEntitlement, "t"), "{}"},
		"recover path":                 {OpRecover, testMailbox, "x", approved(testMailbox), "{}"},
		"recover not json":             {OpRecover, testMailbox, "", approved(testMailbox), "{"},
		"pause no mailbox":             {OpPause, "", "", approved(""), "{}"},
		"pause other header":           {OpPause, testMailbox, "", with2(approved(testMailbox), "Authorization", "x"), "{}"},
	}
	for name, c := range cases {
		if _, err := s.Passthrough(context.Background(), c.op, c.mailbox, c.path, c.headers, []byte(c.body)); !errors.Is(err, ErrRequest) {
			t.Errorf("%s: got %v, want ErrRequest", name, err)
		}
	}
	if n := e.calls(); n != 0 {
		t.Fatalf("refused requests reached the edge %d times", n)
	}
}

func with2(h map[string]string, k, v string) map[string]string {
	h[k] = v
	return h
}

func without2(h map[string]string, k string) map[string]string {
	delete(h, k)
	return h
}

func TestLicenseEntitlementRequest(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if got, err := LicenseEntitlementRequest([]byte(`{"deviceKey":"` + key + `"}`)); err != nil || got != key {
		t.Fatalf("got %q %v", got, err)
	}
	for _, body := range []string{
		``, `{}`, `[]`, `{"deviceKey":1}`,
		`{"deviceKey":"` + key + `","licenseKey":"LIC-1"}`,
		`{"deviceKey":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `"}`,
		`{"deviceKey":"` + base64.StdEncoding.EncodeToString(make([]byte, 31)) + `"}`,
		`{"deviceKey":"` + key + `"}{}`,
	} {
		if _, err := LicenseEntitlementRequest([]byte(body)); !errors.Is(err, ErrRequest) {
			t.Errorf("%s: got %v", body, err)
		}
	}
}
