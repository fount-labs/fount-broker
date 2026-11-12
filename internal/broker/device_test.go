package broker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"testing"

	"github.com/fount-labs/fount-broker/internal/policy"
	"github.com/fount-labs/fount-broker/internal/protocol"
	"github.com/fount-labs/fount-broker/internal/route"
)

const deviceID = "0123456789abcdef0123456789abcdef"

var (
	deviceSignature = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 64)))
	signed          = map[string]string{
		"Fount-Device":    deviceID,
		"Fount-Timestamp": "1800000000",
		"Fount-Signature": deviceSignature,
	}
	signedHeaders = headersJSON(signed)
)

// deviceCredential is shaped like a device credential: base64url claims, a
// dot, and a base64url RSA signature.
var deviceCredential = base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"typ":"fount-device","acct":"a","dev":"`+deviceID+`","tier":"plus","status":"active","pe":1,"iat":1,"exp":2}`)) +
	"." + base64.RawURLEncoding.EncodeToString(make([]byte, 256))

func headersJSON(h map[string]string) string {
	b, _ := json.Marshal(h)
	return string(b)
}

func with(h map[string]string, name, value string) string {
	out := maps.Clone(h)
	if value == "" {
		delete(out, name)
	} else {
		out[name] = value
	}
	return headersJSON(out)
}

func drain(t *testing.T, s *session, id uint64) {
	t.Helper()
	for {
		r, _ := s.recv()
		if r.ID != id {
			t.Fatalf("got %+v, want a reply to %d", r, id)
		}
		switch r.Kind {
		case protocol.KindEnd:
			return
		case protocol.KindError:
			t.Fatalf("request %d: %+v", id, r)
		}
	}
}

func recordingRoute(got *[]route.Request) *fakeRoute {
	return &fakeRoute{do: func(_ context.Context, r route.Request) (*http.Response, error) {
		*got = append(*got, r)
		return okResponse("application/json", `{}`), nil
	}}
}

func TestDeviceCredentialForwardsTheSignedRequestAsSent(t *testing.T) {
	var got []route.Request
	s := start(t, recordingRoute(&got))
	s.vault.Set(policy.CredentialLicense, deviceCredential)
	// Spacing and key order a re-serialization would change.
	body := `{ "code" : "Xy-9_abc" }`
	s.send(`{"kind":"fetch","id":1,"dest":"fount.device_credential","accept":"application/json","headers":`+signedHeaders+`}`, body)
	drain(t, s, 1)

	if len(got) != 1 {
		t.Fatalf("route saw %d requests, want 1", len(got))
	}
	r := got[0]
	if string(r.Body) != body {
		t.Fatalf("body sent %q, want the app's bytes %q", r.Body, body)
	}
	if r.Credential != "" {
		t.Fatal("a device-signed request carried a bearer")
	}
	if r.Dest.Route != policy.RouteFountAPI || r.Dest.Method != "POST" || r.Dest.Path != "device/credential" || r.Dest.ContentType != "application/json" {
		t.Fatalf("dest %+v", r.Dest)
	}
	if !maps.Equal(r.Dest.Headers, signed) {
		t.Fatalf("headers sent %v, want %v", r.Dest.Headers, signed)
	}
	if policy.Destinations["fount.device_credential"].Headers != nil {
		t.Fatal("the request's headers leaked into the shared destination")
	}
}

func TestDeviceRenewSendsTheHeadersAndNoBody(t *testing.T) {
	var got []route.Request
	s := start(t, recordingRoute(&got))
	s.vault.Set(policy.CredentialLicense, deviceCredential)
	s.send(`{"kind":"fetch","id":1,"dest":"fount.device_renew","accept":"application/json","headers":`+signedHeaders+`}`, "")
	drain(t, s, 1)
	if len(got) != 1 {
		t.Fatalf("route saw %d requests, want 1", len(got))
	}
	r := got[0]
	if r.Credential != "" || len(r.Body) != 0 || r.Dest.Method != "POST" || r.Dest.Path != "device/renew" || !maps.Equal(r.Dest.Headers, signed) {
		t.Fatalf("route got %+v", r)
	}

	s.send(`{"kind":"fetch","id":2,"dest":"fount.device_renew","headers":`+signedHeaders+`}`, "{}")
	if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodePolicy {
		t.Fatalf("renew with a body: got %+v, want a policy error", r)
	}
}

func TestDeviceSignedHeadersAreCheckedStrictly(t *testing.T) {
	var got []route.Request
	s := start(t, recordingRoute(&got))
	refused := map[string]string{
		"no headers":             `{}`,
		"device missing":         with(signed, "Fount-Device", ""),
		"timestamp missing":      with(signed, "Fount-Timestamp", ""),
		"signature missing":      with(signed, "Fount-Signature", ""),
		"extra header":           with(signed, "Fount-Nonce", "n"),
		"authorization":          with(signed, "Authorization", "Bearer x"),
		"lowercase name":         `{"fount-device":"` + deviceID + `","Fount-Timestamp":"1800000000","Fount-Signature":"` + deviceSignature + `"}`,
		"device uppercase":       with(signed, "Fount-Device", strings.ToUpper(deviceID)),
		"device short":           with(signed, "Fount-Device", deviceID[:31]),
		"device long":            with(signed, "Fount-Device", deviceID+"0"),
		"device newline":         with(signed, "Fount-Device", deviceID+"\n"),
		"timestamp negative":     with(signed, "Fount-Timestamp", "-1"),
		"timestamp leading 0":    with(signed, "Fount-Timestamp", "01800000000"),
		"timestamp fraction":     with(signed, "Fount-Timestamp", "1800000000.5"),
		"timestamp huge":         with(signed, "Fount-Timestamp", "1"+strings.Repeat("0", 12)),
		"signature padded":       with(signed, "Fount-Signature", base64.URLEncoding.EncodeToString(make([]byte, 64))),
		"signature std base64":   with(signed, "Fount-Signature", strings.Repeat("+", 85)+"A"),
		"signature 63 bytes":     with(signed, "Fount-Signature", base64.RawURLEncoding.EncodeToString(make([]byte, 63))),
		"signature 65 bytes":     with(signed, "Fount-Signature", base64.RawURLEncoding.EncodeToString(make([]byte, 65))),
		"signature noncanonical": with(signed, "Fount-Signature", strings.Repeat("A", 85)+"B"),
		"signature CRLF":         with(signed, "Fount-Signature", deviceSignature+"\r\nX-Evil: 1"),
	}
	id := uint64(0)
	for name, h := range refused {
		for _, d := range []struct{ dest, body string }{
			{"fount.device_credential", `{"code":"abc"}`},
			{"fount.device_renew", ""},
		} {
			id++
			s.send(fmt.Sprintf(`{"kind":"fetch","id":%d,"dest":%q,"headers":%s}`, id, d.dest, h), d.body)
			if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodePolicy {
				t.Errorf("%s on %s: got %+v, want a policy error", name, d.dest, r)
			}
		}
	}
	for _, d := range []string{"fount.device_credential", "fount.device_renew"} {
		id++
		s.send(fmt.Sprintf(`{"kind":"fetch","id":%d,"dest":%q}`, id, d), "")
		if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodePolicy {
			t.Errorf("%s without headers: got %+v, want a policy error", d, r)
		}
	}
	if len(got) != 0 {
		t.Fatalf("refused requests reached Fount's API: %d", len(got))
	}
}

func TestOtherDestinationsRefuseHeaders(t *testing.T) {
	var got []route.Request
	s := start(t, recordingRoute(&got))
	s.vault.Set(policy.CredentialLicense, deviceCredential)
	for i, h := range []string{
		fmt.Sprintf(`{"kind":"fetch","id":1,"dest":%q,"headers":{}}`, dest),
		fmt.Sprintf(`{"kind":"fetch","id":2,"dest":%q,"headers":%s}`, dest, signedHeaders),
		`{"kind":"fetch","id":3,"dest":"fount.devices","headers":` + signedHeaders + `}`,
		`{"kind":"fetch","id":4,"dest":"fount.device_revoke","path":"` + deviceID + `","headers":{"Authorization":"Bearer x"}}`,
	} {
		s.send(h, "")
		if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodePolicy {
			t.Errorf("frame %d: got %+v, want a policy error", i, r)
		}
	}
	if len(got) != 0 {
		t.Fatalf("refused requests reached a route: %d", len(got))
	}
}

func TestDevicesListAndRevokeCarryTheDeviceCredential(t *testing.T) {
	var got []route.Request
	s := start(t, recordingRoute(&got))

	s.send(`{"kind":"fetch","id":1,"dest":"fount.devices","accept":"application/json"}`, "")
	if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodeCredential {
		t.Fatalf("without a credential: got %+v", r)
	}

	s.send(`{"kind":"credential","id":2,"name":"license"}`, deviceCredential)
	if r, _ := s.recv(); r.Kind != protocol.KindResult {
		t.Fatalf("credential: got %+v", r)
	}
	s.send(`{"kind":"fetch","id":3,"dest":"fount.devices","accept":"application/json"}`, "")
	drain(t, s, 3)
	s.send(`{"kind":"fetch","id":4,"dest":"fount.device_revoke","accept":"application/json","path":"`+deviceID+`"}`, "")
	drain(t, s, 4)

	if len(got) != 2 {
		t.Fatalf("route saw %d requests, want 2", len(got))
	}
	list, revoke := got[0], got[1]
	if list.Credential != deviceCredential || list.Dest.Method != "GET" || list.Dest.Path != "devices" || len(list.Body) != 0 || list.Dest.Headers != nil {
		t.Fatalf("list: %+v", list)
	}
	if revoke.Credential != deviceCredential || revoke.Dest.Method != "DELETE" || revoke.Dest.Path != "devices/"+deviceID || len(revoke.Body) != 0 || revoke.Dest.Headers != nil {
		t.Fatalf("revoke: %+v", revoke)
	}

	for i, h := range []string{
		`{"kind":"fetch","id":10,"dest":"fount.device_revoke"}`,
		`{"kind":"fetch","id":11,"dest":"fount.device_revoke","path":"` + strings.ToUpper(deviceID) + `"}`,
		`{"kind":"fetch","id":12,"dest":"fount.device_revoke","path":"` + deviceID[:31] + `"}`,
		`{"kind":"fetch","id":13,"dest":"fount.device_revoke","path":"` + deviceID + `0"}`,
		`{"kind":"fetch","id":14,"dest":"fount.device_revoke","path":"../account"}`,
		`{"kind":"fetch","id":15,"dest":"fount.device_revoke","path":"` + deviceID + `?x=1"}`,
		`{"kind":"fetch","id":16,"dest":"fount.devices","path":"` + deviceID + `"}`,
	} {
		s.send(h, "")
		if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodePolicy {
			t.Errorf("refusal %d: got %+v, want a policy error", i, r)
		}
	}
	for i, d := range []string{"fount.devices", "fount.device_revoke"} {
		path := ""
		if d == "fount.device_revoke" {
			path = `,"path":"` + deviceID + `"`
		}
		s.send(fmt.Sprintf(`{"kind":"fetch","id":%d,"dest":%q%s}`, 20+i, d, path), "{}")
		if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodePolicy {
			t.Errorf("%s with a body: got %+v, want a policy error", d, r)
		}
	}
	if len(got) != 2 {
		t.Fatalf("refused requests reached Fount's API: %d calls", len(got))
	}
}

func TestLicenseValidateIsGone(t *testing.T) {
	s := start(t, &fakeRoute{})
	s.send(`{"kind":"fetch","id":1,"dest":"fount.license_validate"}`, `{"licenseKey":"FOUNT-AAAA"}`)
	if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodePolicy {
		t.Fatalf("got %+v, want a policy error", r)
	}
}

func TestDeviceCredentialIsTheBearerOnTheProxyRoutes(t *testing.T) {
	var got []route.Request
	s := start(t, recordingRoute(&got))
	s.send(`{"kind":"credential","id":1,"name":"license"}`, deviceCredential)
	s.recv()
	for i, d := range []string{"tinfoil.chat_completions", "openrouter.chat_completions"} {
		s.send(fmt.Sprintf(`{"kind":"fetch","id":%d,"dest":%q}`, 10+i, d), "{}")
		drain(t, s, uint64(10+i))
	}
	for _, r := range got {
		if r.Credential != deviceCredential {
			t.Fatalf("%s carried %q, want the device credential", r.Dest.Path, r.Credential)
		}
	}
}
