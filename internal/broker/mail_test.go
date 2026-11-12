package broker

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/fount-labs/fount-broker/internal/mail"
	"github.com/fount-labs/fount-broker/internal/policy"
	"github.com/fount-labs/fount-broker/internal/protocol"
	"github.com/fount-labs/fount-broker/internal/route"
)

type fakeMail struct {
	keys []byte
	err  error
	got  []string
}

func (f *fakeMail) SetKeys(body []byte) error {
	if string(body) == "bad" {
		return mail.ErrBadKeys
	}
	f.keys = body
	return nil
}

func (f *fakeMail) Handle(_ context.Context, op, mailbox, path string, body []byte) (any, error) {
	f.got = append(f.got, op+" "+mailbox+" "+path+" "+string(body))
	if f.err != nil {
		return nil, f.err
	}
	return map[string]string{"op": op}, nil
}

func (f *fakeMail) Passthrough(_ context.Context, op, mailbox, path string, headers map[string]string, body []byte) (*mail.Result, error) {
	f.got = append(f.got, fmt.Sprintf("pass %s %s %s %v %s", op, mailbox, path, headers, body))
	if f.err != nil {
		return nil, f.err
	}
	return &mail.Result{Status: 409, Body: json.RawMessage(`{"error":"handle already registered"}`)}, nil
}

func TestMailRequests(t *testing.T) {
	m := &fakeMail{}
	s := start(t, &fakeRoute{}, func(b *Broker) { b.Mail = m })

	s.send(`{"kind":"credential","id":1,"name":"mail_keys"}`, `{"addresses":[]}`)
	if r, _ := s.recv(); r.Kind != protocol.KindResult || string(m.keys) != `{"addresses":[]}` {
		t.Fatalf("mail_keys: %+v", r)
	}
	if _, ok := s.vault.Get("mail_keys"); ok {
		t.Fatal("mail_keys went to the vault")
	}
	s.send(`{"kind":"credential","id":2,"name":"mail_keys"}`, "bad")
	if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodeBadRequest {
		t.Fatalf("bad mail_keys: %+v", r)
	}

	s.send(`{"kind":"mail","id":3,"op":"get","mailbox":"ab","path":"cd"}`, "")
	r, body := s.recv()
	var out map[string]string
	json.Unmarshal(body, &out)
	if r.Kind != protocol.KindResult || r.ID != 3 || out["op"] != "get" || m.got[0] != "get ab cd " {
		t.Fatalf("get: %+v %s %v", r, body, m.got)
	}

	id := 10
	for err, code := range map[error]protocol.Code{
		fmt.Errorf("x: %w", mail.ErrRequest):      protocol.CodeBadRequest,
		mail.ErrNoKeys:                            protocol.CodeCredential,
		mail.ErrNotFound:                          protocol.CodeNotFound,
		mail.ErrSignature:                         protocol.CodeIntegrity,
		mail.ErrWrongKey:                          protocol.CodeIntegrity,
		fmt.Errorf("%w: x", route.ErrAttestation): protocol.CodeAttestation,
		fmt.Errorf("%w: 500", mail.ErrEdge):       protocol.CodeNetwork,
		errors.New("connection refused"):          protocol.CodeNetwork,
	} {
		m.err = err
		id++
		s.send(fmt.Sprintf(`{"kind":"mail","id":%d,"op":"list","mailbox":"ab"}`, id), "")
		if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != code {
			t.Errorf("%v: got %+v, want %s", err, r, code)
		}
	}
}

func TestMailWithoutAService(t *testing.T) {
	s := start(t, &fakeRoute{})
	s.send(`{"kind":"mail","id":1,"op":"list","mailbox":"ab"}`, "")
	if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodePolicy {
		t.Fatalf("got %+v", r)
	}
	s.send(`{"kind":"credential","id":2,"name":"mail_keys"}`, "{}")
	if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodePolicy {
		t.Fatalf("got %+v", r)
	}
}

// wireEdge answers every Device API call with 429 and records what it got.
type wireEdge struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []string
}

func (e *wireEdge) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	return e.srv.Client().Do(req.WithContext(ctx))
}
func (e *wireEdge) Base() string { return e.srv.URL + "/" }
func (e *wireEdge) AttestedSigningKey(context.Context) (ed25519.PublicKey, error) {
	return nil, nil
}

// TestMailPassthroughWire sends the frames fount's mail::transport
// BrokerTransport builds (its broker_header tests) through the real mail
// service, and checks the result has the shape its broker_response reads.
func TestMailPassthroughWire(t *testing.T) {
	e := &wireEdge{}
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		e.mu.Lock()
		e.reqs = append(e.reqs, fmt.Sprintf("%s %s %s|%s|%s|%s", r.Method, r.URL.RequestURI(), r.Header.Get("Fount-Key-Id"), r.Header.Get("Fount-Nonce"), r.Header.Get("Fount-Entitlement"), body))
		e.mu.Unlock()
		w.Header().Set("Retry-After", "1")
		http.Error(w, `{"error":"slow down"}`, http.StatusTooManyRequests)
	}))
	t.Cleanup(e.srv.Close)
	s := start(t, &fakeRoute{}, func(b *Broker) { b.Mail = mail.New(e, nil) })

	mailbox := strings.Repeat("00aa", 16)
	sig := `"Fount-Timestamp":"1762560000","Fount-Nonce":"n","Fount-Signature":"c2ln"`
	frames := []struct{ header, body, want string }{
		{`{"kind":"mail","id":1,"op":"handle","mailbox":"","path":"smithcpa","headers":{` + sig + `,"Fount-Entitlement":"t"}}`, ``,
			`GET /handle/smithcpa |n|t|`},
		{`{"kind":"mail","id":2,"op":"mailbox","mailbox":"","headers":{` + sig + `,"Fount-Entitlement":"t"}}`, `{"handle":"smithcpa"}`,
			`POST /mailbox |n|t|{"handle":"smithcpa"}`},
		{`{"kind":"mail","id":3,"op":"address","mailbox":"` + mailbox + `","headers":{"Fount-Key-Id":"` + mailbox + `",` + sig + `}}`, `{"address":"a.smithcpa@fountbox.com"}`,
			`POST /address ` + mailbox + `|n||{"address":"a.smithcpa@fountbox.com"}`},
		{`{"kind":"mail","id":4,"op":"routing","mailbox":"` + mailbox + `","headers":{"Fount-Key-Id":"` + mailbox + `",` + sig + `}}`, `{}`,
			`PUT /routing ` + mailbox + `|n||{}`},
		{`{"kind":"mail","id":5,"op":"renew","mailbox":"` + mailbox + `","headers":{"Fount-Key-Id":"` + mailbox + `",` + sig + `,"Fount-Entitlement":"t"}}`, `{}`,
			`POST /entitlement ` + mailbox + `|n|t|{}`},
		// As the app's broker_header writes them: challenges name the mailbox and carry no headers;
		// recover and pause carry a key id, timestamp and nonce but no signature.
		{`{"kind":"mail","id":6,"op":"recover_challenge","mailbox":"` + mailbox + `","path":"` + strings.Repeat("ab", 32) + `"}`, ``,
			`GET /recover/` + mailbox + `?kc=` + strings.Repeat("ab", 32) + ` |||`},
		{`{"kind":"mail","id":7,"op":"recover","mailbox":"` + mailbox + `","headers":{"Fount-Key-Id":"` + mailbox + `","Fount-Timestamp":"1762560000","Fount-Nonce":"n"}}`, `{"challenge":"AA"}`,
			`POST /recover ` + mailbox + `|n||{"challenge":"AA"}`},
		{`{"kind":"mail","id":8,"op":"pause_challenge","mailbox":"` + mailbox + `","path":"true"}`, ``,
			`GET /pause/` + mailbox + `?paused=true |||`},
		{`{"kind":"mail","id":9,"op":"pause","mailbox":"` + mailbox + `","headers":{"Fount-Key-Id":"` + mailbox + `","Fount-Timestamp":"1762560000","Fount-Nonce":"n"}}`, `{"paused":true}`,
			`POST /pause ` + mailbox + `|n||{"paused":true}`},
	}
	for i, f := range frames {
		s.send(f.header, f.body)
		r, body := s.recv()
		if r.Kind != protocol.KindResult || r.ID != uint64(i+1) {
			t.Fatalf("%d: got %+v %s", i+1, r, body)
		}
		var res struct {
			Status     int             `json:"status"`
			Body       json.RawMessage `json:"body"`
			RetryAfter uint64          `json:"retry_after"`
		}
		if err := json.Unmarshal(body, &res); err != nil || res.Status != 429 || string(res.Body) != `{"error":"slow down"}` || res.RetryAfter != 1 {
			t.Fatalf("%d: result %s", i+1, body)
		}
		if e.reqs[i] != f.want {
			t.Fatalf("%d: edge got %q, want %q", i+1, e.reqs[i], f.want)
		}
	}

	for i, h := range []string{
		`{"kind":"mail","id":20,"op":"routing","mailbox":"","headers":{` + sig + `}}`,
		`{"kind":"mail","id":21,"op":"handle","mailbox":"","path":"../boots/x","headers":{` + sig + `}}`,
		`{"kind":"mail","id":22,"op":"list","mailbox":"` + mailbox + `","headers":{` + sig + `}}`,
		`{"kind":"mail","id":23,"op":"list","mailbox":""}`,
		`{"kind":"mail","id":24,"op":"pause_challenge","mailbox":"` + mailbox + `","path":"true","headers":{` + sig + `}}`,
		`{"kind":"mail","id":25,"op":"recover","mailbox":"` + mailbox + `","headers":{"Fount-Key-Id":"` + mailbox + `",` + sig + `}}`,
	} {
		s.send(h, "")
		if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodeBadRequest {
			t.Errorf("refusal %d: got %+v", i, r)
		}
	}
	if len(e.reqs) != len(frames) {
		t.Fatalf("refused frames reached the edge: %v", e.reqs[len(frames):])
	}
}

func TestMailLicenseEntitlement(t *testing.T) {
	var got []route.Request
	status, reply := 200, `{"entitlement":"tok"}`
	s := start(t, &fakeRoute{do: func(_ context.Context, r route.Request) (*http.Response, error) {
		got = append(got, r)
		return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(reply))}, nil
	}}, func(b *Broker) { b.Mail = &fakeMail{} })
	deviceKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	frame := `{"kind":"mail","id":%d,"op":"license_entitlement","mailbox":""}`
	body := `{"deviceKey":"` + deviceKey + `"}`

	s.send(fmt.Sprintf(frame, 1), body)
	if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodeCredential || len(got) != 0 {
		t.Fatalf("without a license: %+v", r)
	}
	s.send(`{"kind":"credential","id":2,"name":"license"}`, deviceCredential)
	s.recv()

	s.send(fmt.Sprintf(frame, 3), body)
	r, out := s.recv()
	if r.Kind != protocol.KindResult || string(out) != `{"status":200,"body":{"entitlement":"tok"}}` {
		t.Fatalf("got %+v %s", r, out)
	}
	d := got[0].Dest
	if d.Route != policy.RouteFountAPI || d.Method != "POST" || d.Path != "mail/entitlement" || d.Credential != policy.CredentialLicense {
		t.Fatalf("dest %+v", d)
	}
	if got[0].Credential != deviceCredential {
		t.Fatal("the Bearer isn't the stored license credential")
	}
	if string(got[0].Body) != body {
		t.Fatalf("body sent %s, want %s", got[0].Body, body)
	}

	status, reply = 403, `{"error":"no_access","reason":"expired"}`
	s.send(fmt.Sprintf(frame, 4), body)
	if r, out := s.recv(); r.Kind != protocol.KindResult || string(out) != `{"status":403,"body":{"error":"no_access","reason":"expired"}}` {
		t.Fatalf("403: got %+v %s", r, out)
	}

	for i, f := range []struct{ header, body string }{
		{fmt.Sprintf(frame, 10), `{"deviceKey":"` + deviceKey + `","licenseKey":"OTHER-1"}`},
		{fmt.Sprintf(frame, 11), `{"licenseKey":"OTHER-1"}`},
		{fmt.Sprintf(frame, 12), `{}`},
		{`{"kind":"mail","id":13,"op":"license_entitlement","mailbox":"` + strings.Repeat("ab", 32) + `"}`, body},
		{`{"kind":"mail","id":14,"op":"license_entitlement","path":"../license/validate"}`, body},
		{`{"kind":"mail","id":15,"op":"license_entitlement","headers":{"Fount-Nonce":"n"}}`, body},
	} {
		s.send(f.header, f.body)
		if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodeBadRequest {
			t.Errorf("refusal %d: got %+v", i, r)
		}
	}
	s.send(`{"kind":"fetch","id":20,"dest":"fount.license_entitlement"}`, body)
	if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodePolicy {
		t.Errorf("fetch: got %+v", r)
	}
	if len(got) != 2 {
		t.Fatalf("refused requests reached Fount's API: %d calls", len(got))
	}
}

func TestMailLicenseEntitlementBodyHasNoLicenseKey(t *testing.T) {
	var got []route.Request
	s := start(t, &fakeRoute{do: func(_ context.Context, r route.Request) (*http.Response, error) {
		got = append(got, r)
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	}}, func(b *Broker) { b.Mail = &fakeMail{} })
	s.vault.Set(policy.CredentialLicense, deviceCredential)
	s.send(`{"kind":"mail","id":1,"op":"license_entitlement"}`, `{"deviceKey":"`+base64.StdEncoding.EncodeToString(make([]byte, 32))+`"}`)
	if r, _ := s.recv(); r.Kind != protocol.KindResult || len(got) != 1 {
		t.Fatalf("got %+v, %d calls", r, len(got))
	}
	var sent map[string]any
	if err := json.Unmarshal(got[0].Body, &sent); err != nil {
		t.Fatal(err)
	}
	if _, ok := sent["licenseKey"]; ok || len(sent) != 1 {
		t.Fatalf("body sent %s, want deviceKey only", got[0].Body)
	}
	if strings.Contains(string(got[0].Body), deviceCredential) {
		t.Fatal("the credential leaked into the body")
	}
}

func TestMailPassthroughUsesFake(t *testing.T) {
	m := &fakeMail{}
	s := start(t, &fakeRoute{}, func(b *Broker) { b.Mail = m })
	s.send(`{"kind":"mail","id":1,"op":"handle","mailbox":"","path":"x","headers":{"Fount-Nonce":"n"}}`, "")
	r, body := s.recv()
	if r.Kind != protocol.KindResult || string(body) != `{"status":409,"body":{"error":"handle already registered"}}` || m.got[0] != "pass handle  x map[Fount-Nonce:n] " {
		t.Fatalf("got %+v %s %q", r, body, m.got)
	}
	m.err = fmt.Errorf("%w: x", route.ErrAttestation)
	s.send(`{"kind":"mail","id":2,"op":"routing","mailbox":"ab"}`, "{}")
	if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodeAttestation {
		t.Fatalf("attestation: got %+v", r)
	}
}
