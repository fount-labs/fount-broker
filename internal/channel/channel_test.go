package channel

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fount-labs/fount-broker/internal/link"
)

var (
	rsaOnce sync.Once
	rsaKeys [2]*rsa.PrivateKey
)

// accountKey is fount-infra's signing key, and another.
func accountKey(t *testing.T, i int) *rsa.PrivateKey {
	t.Helper()
	rsaOnce.Do(func() {
		for j := range rsaKeys {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
			rsaKeys[j] = k
		}
	})
	return rsaKeys[i]
}

// credential signs claims as fount-infra's signDeviceCredential does.
func credential(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	payload, _ := json.Marshal(claims)
	digest := sha256.Sum256(payload)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return b64.EncodeToString(payload) + "." + b64.EncodeToString(sig)
}

// device is one install: its device key, and what it proves with it.
type device struct {
	key     ed25519.PrivateKey
	session ed25519.PrivateKey
	claims  map[string]any
}

func newDevice(t *testing.T, account string) *device {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	_, session, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().Unix()
	return &device{key: key, session: session, claims: map[string]any{
		"v": 1, "typ": "fount-device", "acct": account, "dev": DeviceID(key.Public().(ed25519.PublicKey)),
		"tier": "pro", "status": "active", "pe": now + 86400, "iat": now, "exp": now + 7*86400,
	}}
}

func (d *device) identity(t *testing.T, signer *rsa.PrivateKey, grantFor time.Duration) Identity {
	t.Helper()
	now := time.Now()
	grant, err := SignSession(d.key, d.session.Public().(ed25519.PublicKey), now, now.Add(grantFor))
	if err != nil {
		t.Fatal(err)
	}
	return Identity{Credential: credential(t, signer, d.claims), DeviceKey: d.key.Public().(ed25519.PublicKey), Session: grant, SessionKey: d.session}
}

func spki(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// coordinator starts a server whose handler answers with the account it was
// given, and returns its origin.
func coordinator(t *testing.T, side *link.Side) string {
	t.Helper()
	return serve(t, &Server{Key: side.Key, Attester: side.Attester, Handler: func(p Peer) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, p.Account+" "+r.Method+" "+r.URL.RequestURI())
		})
	}})
}

// serve starts s, with fount-infra's key, and returns its origin.
func serve(t *testing.T, s *Server) string {
	t.Helper()
	keys, err := ParseAccountKeys(spki(t, accountKey(t, 0)))
	if err != nil {
		t.Fatal(err)
	}
	s.AccountKeys = keys
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h, err := s.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

func unattested(t *testing.T) *link.Side {
	t.Helper()
	s, err := link.Unattested()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func client(origin string, check link.KeyChecker, id Identity) *Client {
	return &Client{Origin: origin, Check: check, Identity: func() (Identity, error) { return id, nil }}
}

func TestAChannelCarriesItsAccountAndNoOther(t *testing.T) {
	side := unattested(t)
	origin := coordinator(t, side)
	d := newDevice(t, "acct_1")
	c := client(origin, link.CheckUnattestedKey, d.identity(t, accountKey(t, 0), time.Hour))

	conn, peer, err := c.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if peer.Account != "acct_1" || peer.Device != d.claims["dev"] || time.Until(peer.Expires) > time.Hour {
		t.Errorf("peer %+v", peer)
	}
	for range 2 {
		resp, err := c.Do(context.Background(), "GET", "v1/workers/w_0123456789abcdef01234567/files?prefix=root/a b", nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "acct_1 GET /v1/workers/w_0123456789abcdef01234567/files?prefix=root%2Fa+b" {
			t.Errorf("body %q", body)
		}
	}
	if _, err := c.Do(context.Background(), "DELETE", "v1/workers", nil); err == nil {
		t.Error("the client carried an operation the API doesn't have")
	}
}

func TestTheClientSendsNothingToAnUnprovenCoordinator(t *testing.T) {
	side := unattested(t)
	d := newDevice(t, "acct_1")
	id := d.identity(t, accountKey(t, 0), time.Hour)

	// A coordinator that isn't a release of the pinned repo, and one whose
	// document endorses another key than its TLS one.
	refuse := func(doc, nonce []byte) (link.Endorsement, error) {
		return link.Endorsement{}, errors.New("another repo")
	}
	// And one whose verification is no longer fresh.
	stale := func(doc, nonce []byte) (link.Endorsement, error) {
		e, err := link.CheckUnattestedKey(doc, nonce)
		e.Fresh = time.Now().Add(-time.Second)
		return e, err
	}
	impostor := &link.Side{Key: side.Key, Attester: unattested(t).Attester}
	for name, c := range map[string]struct {
		server *link.Side
		check  link.KeyChecker
	}{
		"wrong release": {side, refuse},
		"stale":         {side, stale},
		"other key":     {impostor, link.CheckUnattestedKey},
	} {
		got := make(chan []byte, 1)
		srv := spy(t, c.server, got)
		_, _, err := client(srv, c.check, id).Dial(context.Background())
		if !errors.Is(err, ErrCoordinator) {
			t.Errorf("%s: %v", name, err)
		}
		if hello := <-got; hello != nil {
			t.Errorf("%s: the client sent %q", name, hello)
		}
	}
}

// spy is a coordinator that sends its document, then reports what the client
// sent next.
func spy(t *testing.T, side *link.Side, got chan<- []byte) string {
	t.Helper()
	up := link.NewUpgradeListener(addr{}, Path, Protocol)
	srv := httptest.NewServer(up)
	t.Cleanup(srv.Close)
	t.Cleanup(func() { up.Close() })
	cert, _ := link.Certificate(side.Key)
	go func() {
		raw, err := up.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		tc := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})
		if tc.Handshake() != nil {
			got <- nil
			return
		}
		state := tc.ConnectionState()
		nonce, _ := state.ExportKeyingMaterial(labelServer, nil, 32)
		doc, _ := side.Attester.Attest(context.Background(), nonce)
		writeMsg(tc, doc)
		tc.SetReadDeadline(time.Now().Add(5 * time.Second))
		msg, _ := readMsg(tc, maxHello)
		got <- msg
	}()
	return srv.URL
}

func TestTheCoordinatorRefusesWhatItCantVerify(t *testing.T) {
	side := unattested(t)
	origin := coordinator(t, side)
	now := time.Now()
	other := newDevice(t, "acct_1")
	for _, c := range []struct {
		name   string
		change func(d *device, id *Identity)
	}{
		{"another signing key", func(d *device, id *Identity) { id.Credential = credential(t, accountKey(t, 1), d.claims) }},
		{"expired credential", func(d *device, id *Identity) {
			d.claims["exp"] = now.Add(-time.Minute).Unix()
			id.Credential = credential(t, accountKey(t, 0), d.claims)
		}},
		{"a changed claim", func(d *device, id *Identity) {
			payload, sig, _ := strings.Cut(id.Credential, ".")
			raw, _ := b64.DecodeString(payload)
			id.Credential = b64.EncodeToString([]byte(strings.Replace(string(raw), "acct_1", "acct_2", 1))) + "." + sig
		}},
		{"a bearer credential alone", func(d *device, id *Identity) { id.DeviceKey = other.key.Public().(ed25519.PublicKey) }},
		{"another device's grant", func(d *device, id *Identity) {
			id.Session, _ = SignSession(other.key, d.session.Public().(ed25519.PublicKey), now, now.Add(time.Hour))
		}},
		{"a grant too long", func(d *device, id *Identity) {
			id.Session, _ = SignSession(d.key, d.session.Public().(ed25519.PublicKey), now, now.Add(MaxSession+time.Hour))
		}},
		{"an expired grant", func(d *device, id *Identity) {
			id.Session, _ = SignSession(d.key, d.session.Public().(ed25519.PublicKey), now.Add(-2*time.Hour), now.Add(-time.Hour))
		}},
		{"a key the grant doesn't name", func(d *device, id *Identity) { id.SessionKey = other.session }},
	} {
		d := newDevice(t, "acct_1")
		id := d.identity(t, accountKey(t, 0), time.Hour)
		c.change(d, &id)
		_, _, err := client(origin, link.CheckUnattestedKey, id).Dial(context.Background())
		if !errors.Is(err, ErrRefused) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestAHelloDoesntReplayIntoAnotherSession(t *testing.T) {
	keys, _ := ParseAccountKeys(spki(t, accountKey(t, 0)))
	d := newDevice(t, "acct_1")
	id := d.identity(t, accountKey(t, 0), time.Hour)
	first, second := make([]byte, 32), make([]byte, 32)
	rand.Read(first)
	rand.Read(second)
	h := hello{Kind: "hello", Credential: id.Credential, DeviceKey: id.DeviceKey, Session: id.Session, Binding: ed25519.Sign(id.SessionKey, bindingMessage(first))}
	if _, err := verifyHello(h, first, keys, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyHello(h, second, keys, false, time.Now()); err == nil {
		t.Fatal("a hello verified in another session")
	}
}

func TestAChannelClosesWhenItsGrantRunsOut(t *testing.T) {
	side := unattested(t)
	origin := coordinator(t, side)
	d := newDevice(t, "acct_1")
	conn, peer, err := client(origin, link.CheckUnattestedKey, d.identity(t, accountKey(t, 0), 2*time.Second)).Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	start := time.Now()
	if _, err := conn.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read: %v", err)
	}
	if waited := time.Since(start); waited > 4*time.Second || time.Now().Before(peer.Expires.Add(-time.Second)) {
		t.Errorf("closed after %s, expires %s", waited, peer.Expires)
	}
}

func TestCheckRequest(t *testing.T) {
	w := "w_0123456789abcdef01234567"
	th := "thr_0123456789abcdef01234567"
	for _, ok := range []string{
		"POST v1/workers", "GET v1/workers", "GET v1/workers/" + w, "POST v1/workers/" + w + "/grant",
		"POST v1/workers/" + w + "/revoke",
		"PUT v1/workers/" + w + "/root/notes/a b.md", "POST v1/workers/" + w + "/jobs",
		"GET v1/workers/" + w + "/files", "GET v1/workers/" + w + "/files?prefix=root/",
		"GET v1/workers/" + w + "/files/root/a.md", "GET v1/jobs/j_0123456789abcdef01234567",
		"GET v1/workers/" + w + "/threads", "GET v1/workers/" + w + "/threads/" + th,
		"GET v1/workers/" + w + "/threads/" + th + "?since=42", "POST v1/workers/" + w + "/threads/" + th + "/ops",
		"POST v1/workers/" + w + "/ops", "GET v1/workers/" + w + "/mail", "PUT v1/workers/" + w + "/mail",
		"GET v1/teams/acct_acme/log", "GET v1/teams/acct_acme/log?since=3", "POST v1/teams/acct_acme/log",
		"POST v1/teams",
		"PUT v1/workers/" + w + "/threads/" + th + "/drafts/ent_0123456789abcdef01234567/files/threads/" + th[4:] + "/outputs/j/a b.docx?rev=2",
		"POST v1/teams/acct_acme/invites/i_m_ann/send", "GET v1/teams",
		"POST v1/teams/acct_acme/invites/inv_1/open", "POST v1/teams/acct_acme/invites/inv_1/accept",
		"POST v1/teams/acct_acme/passkey-join", "POST v1/teams/acct_acme/passkey-join/challenge",
		"POST v1/teams/acct_acme/passkey-vouch", "POST v1/teams/acct_acme/recovery-start",
		"POST v1/teams/tm_0123456789abcdef01234567/billing-statement", "POST v1/teams/tm_0123456789abcdef01234567/billing-refresh",
	} {
		method, target, _ := strings.Cut(ok, " ")
		if _, err := CheckRequest(method, target); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"DELETE v1/workers", "GET v0/workers/" + w, "GET /v1/workers", "GET v1/workers/w_nope",
		"PUT v1/workers/" + w + "/root/../state.json", "PUT v1/workers/" + w + "/root//a",
		"GET v1/workers/" + w + "/files?prefix=a&other=b", "GET v1/workers/" + w + "?prefix=a",
		"GET v1/workers/" + w + "/files/a\x00b", "POST v1/workers/" + w + "/root/a.md",
		"GET v1/jobs/j_0123456789abcdef01234567/x", "PUT v1/workers/" + w + "/root",
		"GET v1/workers/" + w + "/revoke", "POST v1/workers/" + w + "/grant/x",
		"POST v1/workers/" + w + "/threads", "GET v1/workers/" + w + "/threads/thr_nope",
		"GET v1/workers/" + w + "/threads/" + th + "?since=-1", "GET v1/workers/" + w + "/threads/" + th + "?prefix=a",
		"GET v1/workers/" + w + "/threads?since=1", "GET v1/workers/" + w + "/files?since=1",
		"GET v1/workers/" + w + "/threads/" + th + "/ops", "POST v1/workers/" + w + "/threads/" + th + "/ops/x",
		"GET v1/workers/" + w + "/ops", "GET v1/workers/" + w + "/threads/" + th + "?since=1&since=2",
		"PUT v1/teams/acct_acme/log", "GET v1/teams/acct_acme", "GET v1/teams/acct.acme/log", "GET v1/teams/acct_acme/log/x",
		"POST v1/teams/acct_acme/log?since=1", "GET v1/teams/acct_acme/log?prefix=a", "GET v1/teams/" + strings.Repeat("a", 65) + "/log",
		"PUT v1/teams", "POST v1/teams?since=1", "GET v1/teams?since=1",
		"GET v1/teams/acct_acme/invites/inv_1/open", "POST v1/teams/acct_acme/invites/inv_1/delete", "POST v1/teams/acct_acme/invites/inv_1",
		"PUT v1/teams/acct_acme/joins", "POST v1/teams/acct_acme/joins/jn_1", "GET v1/teams/acct_acme/joins/jn_1/approve",
		"POST v1/teams/acct_acme/joins/jn.1/accept", "POST v1/teams/acct_acme/joins?since=1", "POST v1/teams/acct_acme/joins/jn_1/approve/x",
		// The code join is gone (decided 2026-11-19).
		"POST v1/teams/acct_acme/joins", "GET v1/teams/acct_acme/joins", "GET v1/teams/acct_acme/joins/jn_1",
		"POST v1/teams/acct_acme/joins/jn_1/approve", "POST v1/teams/acct_acme/joins/jn_1/deny", "POST v1/teams/acct_acme/joins/jn_1/accept",
		"GET v1/teams/acct_acme/passkey-join", "POST v1/teams/acct_acme/passkey-join/x", "GET v1/teams/acct_acme/passkey-join/challenge",
		"GET v1/teams/acct_acme/passkey-vouch", "POST v1/teams/acct_acme/passkey-vouch/x",
		"POST v1/teams/acct_acme/recovery", "POST v1/teams/acct_acme/recovery/start", "POST v1/teams/acct_acme/x",
		"GET v1/teams/acct_acme/recovery-start", "POST v1/teams/acct_acme/recovery-start/x",
		"GET v1/teams/acct_acme/billing-statement", "POST v1/teams/acct_acme/billing-statement/x",
		"GET v1/teams/acct_acme/billing-refresh", "POST v1/teams/acct_acme/billing-refresh?since=1", "POST v1/teams/acct_acme/billing",
		"POST v1/workers/" + w + "/mail", "GET v1/workers/" + w + "/mail?since=1", "PUT v1/workers/" + w + "/mail?since=1",
		"GET v1/workers/" + w + "/mail/x", "PUT v1/workers/" + w + "/mail/x", "DELETE v1/workers/" + w + "/mail",
		"PUT v1/workers/" + w + "/threads/" + th + "/drafts/ent_0123456789abcdef01234567/files/a.docx",
		"PUT v1/workers/" + w + "/threads/" + th + "/drafts/ent_0123456789abcdef01234567/files/a.docx?rev=x",
		"PUT v1/workers/" + w + "/threads/" + th + "/drafts/ent_0123456789abcdef01234567/files/a.docx?since=1",
		"POST v1/workers/" + w + "/threads/" + th + "/drafts/ent_0123456789abcdef01234567/files/a.docx?rev=1",
		"PUT v1/workers/" + w + "/threads/" + th + "/drafts/e_1/files/a.docx?rev=1",
		"PUT v1/workers/" + w + "/threads/" + th + "/drafts/ent_0123456789abcdef01234567/files?rev=1",
		"GET v1/teams/acct_acme/invites/i_m_ann/send", "POST v1/teams/acct_acme/invites/i.x/send",
	} {
		method, target, _ := strings.Cut(bad, " ")
		if _, err := CheckRequest(method, target); err == nil {
			t.Errorf("%q passed", bad)
		}
	}
}

func TestParseIdentity(t *testing.T) {
	d := newDevice(t, "acct_1")
	id := d.identity(t, accountKey(t, 0), time.Hour)
	session, _ := json.Marshal(SessionCredential{
		DeviceKey: b64.EncodeToString(id.DeviceKey), Session: id.Session, SessionSeed: b64.EncodeToString(d.session.Seed()),
	})
	got, err := ParseIdentity(id.Credential, string(session))
	if err != nil {
		t.Fatal(err)
	}
	if !got.SessionKey.Equal(d.session) || !got.DeviceKey.Equal(id.DeviceKey) {
		t.Error("the identity doesn't round-trip")
	}
	for _, bad := range []string{"", `{"device_key":"x"}`, string(session[:len(session)-1]) + `,"extra":1}`} {
		if _, err := ParseIdentity(id.Credential, bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	if _, err := ParseIdentity("", string(session)); err == nil {
		t.Error("parsed without a license credential")
	}
}

func TestParseAccountKeys(t *testing.T) {
	keys, err := ParseAccountKeys(spki(t, accountKey(t, 0)) + ", " + spki(t, accountKey(t, 1)))
	if err != nil || len(keys) != 2 {
		t.Fatalf("%d keys, %v", len(keys), err)
	}
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(ed.Public())
	for _, bad := range []string{"", "not base64", base64.StdEncoding.EncodeToString(der)} {
		if _, err := ParseAccountKeys(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

// A request on a channel when the account changes finishes as the old
// account's, and that channel never carries another.
func TestResetRetiresAChannelInFlight(t *testing.T) {
	side := unattested(t)
	started, release := make(chan struct{}), make(chan struct{})
	origin := serve(t, &Server{Key: side.Key, Attester: side.Attester, Handler: func(p Peer) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/files") {
				close(started)
				<-release
			}
			io.WriteString(w, p.Account)
		})
	}})
	a := newDevice(t, "acct_a").identity(t, accountKey(t, 0), time.Hour)
	b := newDevice(t, "acct_b").identity(t, accountKey(t, 0), time.Hour)
	var mu sync.Mutex
	current := a
	c := &Client{Origin: origin, Check: link.CheckUnattestedKey, Identity: func() (Identity, error) {
		mu.Lock()
		defer mu.Unlock()
		return current, nil
	}}
	get := func(target string) string {
		resp, err := c.Do(context.Background(), "GET", target, nil)
		if err != nil {
			t.Error(err)
			return ""
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}
	worker := "v1/workers/w_0123456789abcdef01234567"
	if got := get(worker); got != "acct_a" {
		t.Fatalf("before: %q", got)
	}
	inFlight := make(chan string)
	go func() { inFlight <- get(worker + "/files") }()
	<-started
	mu.Lock()
	current = b
	mu.Unlock()
	c.Reset()
	// A request while the old one is still in flight.
	if got := get(worker); got != "acct_b" {
		t.Errorf("during: %q", got)
	}
	close(release)
	if got := <-inFlight; got != "acct_a" {
		t.Errorf("in flight: %q", got)
	}
	// Its channel goes back to a pool once the body is read.
	time.Sleep(100 * time.Millisecond)
	for i := range 4 {
		if got := get(worker); got != "acct_b" {
			t.Errorf("request %d after the switch: %q", i, got)
		}
	}
}

// slowAttester takes a while, as the attestation socket can after boot.
type slowAttester struct {
	link.Attester
	delay time.Duration
}

func (a slowAttester) Attest(ctx context.Context, nonce []byte) ([]byte, error) {
	time.Sleep(a.delay)
	return a.Attester.Attest(ctx, nonce)
}

// Connections that never start TLS hold their slots for a step, not the
// whole handshake; a client behind them waits for one, and the coordinator's
// own slow attestation isn't held against it.
func TestIdleConnectionsDontLockOutClients(t *testing.T) {
	side := unattested(t)
	origin := serve(t, &Server{
		Key: side.Key, Attester: slowAttester{side.Attester, 600 * time.Millisecond},
		Handler:       func(p Peer) http.Handler { return http.NotFoundHandler() },
		MaxHandshakes: 2, stepTimeout: 300 * time.Millisecond, slotWait: 5 * time.Second,
	})
	var idle []net.Conn
	for range 4 {
		conn, err := link.DialUpgrade(context.Background(), origin, Path, Protocol)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		idle = append(idle, conn)
	}
	d := newDevice(t, "acct_1")
	start := time.Now()
	conn, _, err := client(origin, link.CheckUnattestedKey, d.identity(t, accountKey(t, 0), time.Hour)).Dial(context.Background())
	if err != nil {
		t.Fatalf("after %s: %v", time.Since(start), err)
	}
	conn.Close()
	if took := time.Since(start); took > 4*time.Second {
		t.Errorf("the handshake took %s", took)
	}
	for i, conn := range idle {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("idle connection %d: %v", i, err)
		}
	}
}

// coordinatorWith is coordinator with a server configured by opt, whose
// handler answers with the peer it was given.
func coordinatorWith(t *testing.T, side *link.Side, opt func(*Server)) string {
	t.Helper()
	keys, _ := ParseAccountKeys(spki(t, accountKey(t, 0)))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := &Server{Key: side.Key, Attester: side.Attester, AccountKeys: keys, Handler: func(p Peer) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{"account": p.Account, "device": p.Device, "key_id": DeviceID(p.DeviceKey), "expires": p.Expires.Unix(), "paid": p.Paid, "email": p.Email})
		})
	}}
	if opt != nil {
		opt(s)
	}
	h, err := s.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

func peerOf(t *testing.T, c *Client) (map[string]any, error) {
	t.Helper()
	resp, err := c.Do(context.Background(), "GET", "v1/workers", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

func TestTheCoordinatorRefusesAccountsWithoutCloud(t *testing.T) {
	side := unattested(t)
	origin := coordinator(t, side)
	now := time.Now().Unix()
	for name, change := range map[string]map[string]any{
		"no subscription":   {"tier": nil, "status": nil, "pe": nil},
		"an unknown tier":   {"tier": "free"},
		"cancelled":         {"status": "canceled"},
		"no status":         {"status": nil},
		"an unknown status": {"status": "incomplete"},
		"the period ended":  {"pe": now - 60},
		"no period end":     {"pe": nil},
	} {
		d := newDevice(t, "acct_1")
		for k, v := range change {
			d.claims[k] = v
		}
		_, _, err := client(origin, link.CheckUnattestedKey, d.identity(t, accountKey(t, 0), time.Hour)).Dial(context.Background())
		if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "Cloud") {
			t.Errorf("%s: %v", name, err)
		}
	}
	d := newDevice(t, "acct_1")
	d.claims["tier"], d.claims["status"] = "plus", "past_due"
	if _, _, err := client(origin, link.CheckUnattestedKey, d.identity(t, accountKey(t, 0), time.Hour)).Dial(context.Background()); err != nil {
		t.Errorf("plus, past_due, in its period: %v", err)
	}
}

func TestAChannelEndsWithThePaidPeriodAndCarriesTheDeviceKey(t *testing.T) {
	side := unattested(t)
	origin := coordinatorWith(t, side, nil)
	d := newDevice(t, "acct_1")
	pe := time.Now().Add(30 * time.Minute).Unix()
	d.claims["pe"] = pe
	got, err := peerOf(t, client(origin, link.CheckUnattestedKey, d.identity(t, accountKey(t, 0), time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if got["expires"] != float64(pe) || got["key_id"] != d.claims["dev"] || got["device"] != d.claims["dev"] {
		t.Errorf("peer %v, want expiry %d", got, pe)
	}
}

func TestCloudCredentials(t *testing.T) {
	side := unattested(t)
	cloud := func(d *device, lasts time.Duration) {
		now := time.Now()
		d.claims["typ"], d.claims["iat"], d.claims["exp"] = CloudCredentialType, now.Unix(), now.Add(lasts).Unix()
	}
	for _, cloudOnly := range []bool{false, true} {
		origin := coordinatorWith(t, side, func(s *Server) { s.CloudCredentialsOnly = cloudOnly })
		d := newDevice(t, "acct_1")
		cloud(d, MaxCloudCredential)
		got, err := peerOf(t, client(origin, link.CheckUnattestedKey, d.identity(t, accountKey(t, 0), MaxSession)))
		if err != nil || got["expires"] != float64(d.claims["exp"].(int64)) {
			t.Errorf("cloudOnly %v: an hour's Cloud credential: %v %v", cloudOnly, got, err)
		}
		long := newDevice(t, "acct_1")
		cloud(long, MaxCloudCredential+time.Minute)
		if _, _, err := client(origin, link.CheckUnattestedKey, long.identity(t, accountKey(t, 0), time.Hour)).Dial(context.Background()); !errors.Is(err, ErrRefused) {
			t.Errorf("cloudOnly %v: a longer Cloud credential: %v", cloudOnly, err)
		}
		_, _, err = client(origin, link.CheckUnattestedKey, newDevice(t, "acct_1").identity(t, accountKey(t, 0), time.Hour)).Dial(context.Background())
		if cloudOnly != errors.Is(err, ErrRefused) {
			t.Errorf("cloudOnly %v: a device credential: %v", cloudOnly, err)
		}
	}
}

func TestTheClientReattestsAtTheFreshnessDeadline(t *testing.T) {
	side := unattested(t)
	origin := coordinator(t, side)
	var mu sync.Mutex
	checks := 0
	fresh := func(doc, nonce []byte) (link.Endorsement, error) {
		e, err := link.CheckUnattestedKey(doc, nonce)
		mu.Lock()
		checks++
		mu.Unlock()
		e.Fresh = time.Now().Add(time.Second)
		return e, err
	}
	c := client(origin, fresh, newDevice(t, "acct_1").identity(t, accountKey(t, 0), time.Hour))
	get := func() {
		t.Helper()
		resp, err := c.Do(context.Background(), "POST", "v1/workers", []byte("{}"))
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return checks
	}
	get()
	get()
	if n := count(); n != 1 {
		t.Fatalf("%d verifications before the deadline, want 1", n)
	}
	time.Sleep(1500 * time.Millisecond)
	get()
	if n := count(); n != 2 {
		t.Fatalf("%d verifications after the deadline, want 2", n)
	}

	// A channel past its deadline writes nothing, whether or not its timer
	// has fired yet.
	conn, _, err := c.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fc := conn.(*freshConn)
	fc.timer.Stop()
	fc.fresh = time.Now()
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\n\r\n")); !errors.Is(err, errStale) {
		t.Errorf("a write past the deadline: %v", err)
	}
}

func TestParseIdentityTakesACloudCredential(t *testing.T) {
	d := newDevice(t, "acct_1")
	id := d.identity(t, accountKey(t, 0), time.Hour)
	d.claims["typ"] = CloudCredentialType
	cloud := credential(t, accountKey(t, 0), d.claims)
	session, _ := json.Marshal(SessionCredential{
		DeviceKey: b64.EncodeToString(id.DeviceKey), Session: id.Session, SessionSeed: b64.EncodeToString(d.session.Seed()), Credential: cloud,
	})
	for _, license := range []string{"", id.Credential} {
		got, err := ParseIdentity(license, string(session))
		if err != nil || got.Credential != cloud {
			t.Errorf("license %q: %v, credential %q", license, err, got.Credential)
		}
	}
	bad := strings.Replace(string(session), cloud, "nope", 1)
	if _, err := ParseIdentity(id.Credential, bad); err == nil {
		t.Error("a malformed Cloud credential parsed")
	}
}

// The client stops using a channel a margin before its proof expires, before
// the coordinator closes it mid-request, and dials a new one.
func TestTheClientRetiresAChannelBeforeItsProofExpires(t *testing.T) {
	side := unattested(t)
	origin := coordinator(t, side)
	d := newDevice(t, "acct_1")
	var mu sync.Mutex
	dials := 0
	c := &Client{Origin: origin, Check: link.CheckUnattestedKey, expiryMargin: 1500 * time.Millisecond, Identity: func() (Identity, error) {
		mu.Lock()
		defer mu.Unlock()
		dials++
		return d.identity(t, accountKey(t, 0), 3*time.Second), nil
	}}
	conn, peer, err := c.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read: %v", err)
	}
	if left := time.Until(peer.Expires); left < time.Second/2 {
		t.Errorf("closed %s before the proof expires", left)
	}

	get := func() {
		t.Helper()
		resp, err := c.Do(context.Background(), "GET", "v1/workers", nil)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	get()
	get()
	time.Sleep(2 * time.Second)
	get()
	mu.Lock()
	defer mu.Unlock()
	if dials != 3 {
		t.Errorf("%d dials, want 3: the first channel, one, and one past its margin", dials)
	}
}

func TestUsableUntil(t *testing.T) {
	c := &Client{}
	now := time.Now()
	for _, tc := range []struct {
		name           string
		fresh, expires time.Time
		want           time.Time
	}{
		{"the margin first", now.Add(time.Hour), now.Add(10 * time.Minute), now.Add(9 * time.Minute)},
		{"freshness first", now.Add(5 * time.Minute), now.Add(10 * time.Minute), now.Add(5 * time.Minute)},
		{"no freshness deadline", time.Time{}, now.Add(10 * time.Minute), now.Add(9 * time.Minute)},
		{"shorter than the margin", time.Time{}, now.Add(30 * time.Second), now.Add(30 * time.Second)},
	} {
		if got := c.usableUntil(tc.fresh, tc.expires, now); !got.Equal(tc.want) {
			t.Errorf("%s: %s, want %s", tc.name, got.Sub(now), tc.want.Sub(now))
		}
	}
}

// A Cloud credential with no plan opens the channel as who it names, unpaid:
// the coordinator decides what that admits (team-billing-plan.md D3). A
// device credential still needs its own plan.
func TestACloudCredentialWithNoPlanIsDeferredToTheCoordinator(t *testing.T) {
	side := unattested(t)
	cloud := func(d *device, change map[string]any) {
		now := time.Now()
		d.claims["typ"], d.claims["iat"], d.claims["exp"], d.claims["eml"] = CloudCredentialType, now.Unix(), now.Add(MaxCloudCredential).Unix(), "maria@example.com"
		for k, v := range change {
			d.claims[k] = v
		}
	}
	for _, cloudOnly := range []bool{false, true} {
		origin := coordinatorWith(t, side, func(s *Server) { s.CloudCredentialsOnly = cloudOnly })
		for name, tc := range map[string]struct {
			change map[string]any
			paid   bool
		}{
			"identity only":    {map[string]any{"tier": nil, "status": nil, "pe": nil}, false},
			"an unknown tier":  {map[string]any{"tier": "free"}, false},
			"cancelled":        {map[string]any{"status": "canceled"}, false},
			"the period ended": {map[string]any{"pe": time.Now().Unix() - 60}, false},
			"pro":              {nil, true},
			"a firm team's":    {map[string]any{"tier": "team"}, true},
		} {
			d := newDevice(t, "acct_1")
			cloud(d, tc.change)
			got, err := peerOf(t, client(origin, link.CheckUnattestedKey, d.identity(t, accountKey(t, 0), MaxSession)))
			if err != nil {
				t.Errorf("cloudOnly %v, %s: %v", cloudOnly, name, err)
				continue
			}
			if got["paid"] != tc.paid || got["account"] != "acct_1" || got["email"] != "maria@example.com" {
				t.Errorf("cloudOnly %v, %s: %v", cloudOnly, name, got)
			}
			// An unpaid channel lasts as long as its credential, not a paid
			// period it doesn't have.
			if !tc.paid && got["expires"] != float64(d.claims["exp"].(int64)) {
				t.Errorf("cloudOnly %v, %s: expires %v, want %v", cloudOnly, name, got["expires"], d.claims["exp"])
			}
		}
		// Signature and lifetime are still checked first.
		forged := newDevice(t, "acct_1")
		cloud(forged, map[string]any{"tier": nil, "status": nil, "pe": nil})
		if _, _, err := client(origin, link.CheckUnattestedKey, forged.identity(t, accountKey(t, 1), time.Hour)).Dial(context.Background()); !errors.Is(err, ErrRefused) {
			t.Errorf("cloudOnly %v: another key's identity-only credential: %v", cloudOnly, err)
		}
		long := newDevice(t, "acct_1")
		cloud(long, map[string]any{"tier": nil, "status": nil, "pe": nil, "exp": time.Now().Add(MaxCloudCredential + time.Minute).Unix()})
		if _, _, err := client(origin, link.CheckUnattestedKey, long.identity(t, accountKey(t, 0), time.Hour)).Dial(context.Background()); !errors.Is(err, ErrRefused) {
			t.Errorf("cloudOnly %v: a longer identity-only credential: %v", cloudOnly, err)
		}
	}
	// A paid Cloud credential's channel ends with its paid period.
	origin := coordinatorWith(t, side, nil)
	d := newDevice(t, "acct_1")
	pe := time.Now().Add(30 * time.Minute).Unix()
	cloud(d, map[string]any{"pe": pe})
	got, err := peerOf(t, client(origin, link.CheckUnattestedKey, d.identity(t, accountKey(t, 0), MaxSession)))
	if err != nil || got["paid"] != true || got["expires"] != float64(pe) {
		t.Fatalf("a paid Cloud credential: %v %v", got, err)
	}
	// A device credential with no plan is refused, as before.
	dev := newDevice(t, "acct_1")
	dev.claims["tier"], dev.claims["status"], dev.claims["pe"] = nil, nil, nil
	if _, _, err := client(origin, link.CheckUnattestedKey, dev.identity(t, accountKey(t, 0), time.Hour)).Dial(context.Background()); !errors.Is(err, ErrRefused) {
		t.Fatalf("a device credential with no plan: %v", err)
	}
}
