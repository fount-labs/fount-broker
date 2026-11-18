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
	keys, err := ParseAccountKeys(spki(t, accountKey(t, 0)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := &Server{Key: side.Key, Attester: side.Attester, AccountKeys: keys, Handler: func(p Peer) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, p.Account+" "+r.Method+" "+r.URL.RequestURI())
		})
	}}
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

func client(origin string, check link.Checker, id Identity) *Client {
	return &Client{Origin: origin, Check: check, Identity: func() (Identity, error) { return id, nil }}
}

func TestAChannelCarriesItsAccountAndNoOther(t *testing.T) {
	side := unattested(t)
	origin := coordinator(t, side)
	d := newDevice(t, "acct_1")
	c := client(origin, side.Check, d.identity(t, accountKey(t, 0), time.Hour))

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
	refuse := func(doc, nonce []byte) (ed25519.PublicKey, error) { return nil, errors.New("another repo") }
	impostor := &link.Side{Key: side.Key, Attester: unattested(t).Attester}
	for name, c := range map[string]struct {
		server *link.Side
		check  link.Checker
	}{
		"wrong release": {side, refuse},
		"other key":     {impostor, side.Check},
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
		_, _, err := client(origin, side.Check, id).Dial(context.Background())
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
	if _, err := verifyHello(h, first, keys, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyHello(h, second, keys, time.Now()); err == nil {
		t.Fatal("a hello verified in another session")
	}
}

func TestAChannelClosesWhenItsGrantRunsOut(t *testing.T) {
	side := unattested(t)
	origin := coordinator(t, side)
	d := newDevice(t, "acct_1")
	conn, peer, err := client(origin, side.Check, d.identity(t, accountKey(t, 0), 2*time.Second)).Dial(context.Background())
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
	for _, ok := range []string{
		"POST v1/workers", "GET v1/workers", "GET v1/workers/" + w, "POST v1/workers/" + w + "/grant",
		"PUT v1/workers/" + w + "/root/notes/a b.md", "POST v1/workers/" + w + "/jobs",
		"GET v1/workers/" + w + "/files", "GET v1/workers/" + w + "/files?prefix=root/",
		"GET v1/workers/" + w + "/files/root/a.md", "GET v1/jobs/j_0123456789abcdef01234567",
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
