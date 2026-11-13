package policy

import (
	"regexp"
	"strings"
	"testing"
)

func TestBodyCheck(t *testing.T) {
	object := Body{Kind: BodyObject, MaxBytes: 64, Fields: map[string]Field{
		"key":  {Types: []string{"string"}, Required: true, Pattern: regexp.MustCompile(`^[A-Z]+$`)},
		"note": {Types: []string{"string", "null"}},
	}}
	cases := []struct {
		body Body
		in   string
		ok   bool
	}{
		{Body{Kind: BodyNone}, "", true},
		{Body{Kind: BodyNone}, "x", false},
		{Body{Kind: BodyOpaque}, "anything", true},
		{object, `{"key":"ABC"}`, true},
		{object, `{"key":"ABC","note":null}`, true},
		{object, `{"key":"abc"}`, false},
		{object, `{"key":"ABC","other":1}`, false},
		{object, `{"note":"x"}`, false},
		{object, `{"key":1}`, false},
		{object, `{"key":"ABC"} {}`, false},
		{object, `null`, false},
		{object, `{"key":"` + strings.Repeat("A", 80) + `"}`, false},
	}
	for _, c := range cases {
		if err := c.body.Check([]byte(c.in)); (err == nil) != c.ok {
			t.Errorf("Check(%q) = %v, want ok=%v", c.in, err, c.ok)
		}
	}
}

func TestDestinationsAreWellFormed(t *testing.T) {
	for name, d := range Destinations {
		if d.Method == "" || d.Path == "" || len(d.Accept) == 0 {
			t.Errorf("%s: method, path and accept are required", name)
		}
		if strings.Contains(d.Path, "..") || strings.HasPrefix(d.Path, "/") {
			t.Errorf("%s: path %q escapes its base", name, d.Path)
		}
		if (d.Method == "GET" || d.Method == "DELETE") && d.Body.Kind != BodyNone {
			t.Errorf("%s: a %s must not take a body", name, d.Method)
		}
		if d.ClientHeaders != nil && (d.Credential != CredentialNone || d.Route != RouteFountAPI) {
			t.Errorf("%s: a request the app signs goes to Fount's API with no bearer", name)
		}
		for h, p := range d.ClientHeaders {
			if p == nil || !strings.HasPrefix(p.String(), "^") || !strings.HasSuffix(p.String(), "$") {
				t.Errorf("%s: header %s must be matched in full", name, h)
			}
		}
	}
}

func TestNestedFieldRules(t *testing.T) {
	body := Body{Kind: BodyObject, Fields: map[string]Field{
		"inner": {Types: []string{"object"}, Fields: map[string]Field{
			"list": {
				Types: []string{"array"}, Required: true, MinItems: 1, MaxItems: 2,
				Items: &Field{Types: []string{"string"}, Pattern: regexp.MustCompile(`^[a-z]+$`)},
			},
		}},
	}}
	cases := []struct {
		in string
		ok bool
	}{
		{`{"inner":{"list":["a","b"]}}`, true},
		{`{"inner":{"list":[]}}`, false},
		{`{"inner":{"list":["a","b","c"]}}`, false},
		{`{"inner":{"list":["A"]}}`, false},
		{`{"inner":{"list":[1]}}`, false},
		{`{"inner":{}}`, false},
		{`{"inner":{"list":["a"],"other":1}}`, false},
	}
	for _, c := range cases {
		if err := body.Check([]byte(c.in)); (err == nil) != c.ok {
			t.Errorf("Check(%q) = %v, want ok=%v", c.in, err, c.ok)
		}
	}
}

func TestWebSearchBodyIsOneSearchCall(t *testing.T) {
	body := Destinations["tinfoil.websearch"].Body
	cases := []struct {
		in string
		ok bool
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"query":"q"}}}`, true},
		{`{"jsonrpc":"2.0","id":"a","method":"tools/call","params":{"name":"search","arguments":{}}}`, true},
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch","arguments":{"urls":["https://a.b"]}}}`, false},
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search"}}`, false},
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`, false},
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{},"_meta":{}}}`, false},
		{`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`, false},
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`, false},
		{`{"jsonrpc":"1.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{}}}`, false},
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{}},"extra":1}`, false},
		{`[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}]`, false},
	}
	for _, c := range cases {
		if err := body.Check([]byte(c.in)); (err == nil) != c.ok {
			t.Errorf("Check(%q) = %v, want ok=%v", c.in, err, c.ok)
		}
	}
}

func TestWebFetchBodyIsOneFetchOfHTTPSURLs(t *testing.T) {
	body := Destinations["tinfoil.webfetch"].Body
	call := func(args string) string {
		return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch","arguments":` + args + `}}`
	}
	twentyOne := strings.TrimSuffix(strings.Repeat(`"https://a.example/",`, 21), ",")
	cases := []struct {
		in string
		ok bool
	}{
		{call(`{"urls":["https://example.com/a?b=c#d"]}`), true},
		{call(`{"urls":["https://example.com:8443/"]}`), true},
		{call(`{"urls":["https://example.com"]}`), true},
		{call(`{"urls":[]}`), false},
		{call(`{"urls":[` + twentyOne + `]}`), false},
		{call(`{"urls":["http://example.com/"]}`), false},
		{call(`{"urls":["https://user:pw@example.com/"]}`), false},
		{call(`{"urls":["https://example.com/a b"]}`), false},
		{call(`{"urls":["file:///etc/passwd"]}`), false},
		{call(`{"urls":["https://example.com/"],"allowed_domains":["example.com"]}`), false},
		{call(`{}`), false},
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"urls":["https://a.b/"]}}}`, false},
	}
	for _, c := range cases {
		if err := body.Check([]byte(c.in)); (err == nil) != c.ok {
			t.Errorf("Check(%q) = %v, want ok=%v", c.in, err, c.ok)
		}
	}
}

func TestWebFetchAsksForTheInjectionCheck(t *testing.T) {
	d := Destinations["tinfoil.webfetch"]
	if d.Headers["X-Tinfoil-Tool-Injection-Check"] != "true" {
		t.Fatal("webfetch must ask the enclave to check pages for prompt injection")
	}
	if d.Route != RouteTinfoilWebSearch || d.Credential != CredentialLicense {
		t.Fatal("webfetch must be sealed to the web-search enclave and carry the license")
	}
}

func TestConvertFileIsOneSealedVLMUploadUpTo16MiB(t *testing.T) {
	d := Destinations["tinfoil.convert_file"]
	if d.Route != RouteTinfoil || d.Method != "POST" || d.Path != "convert/file?mode=vlm" || d.PathPattern != nil {
		t.Fatalf("shape: %s %s %s", d.Route, d.Method, d.Path)
	}
	if d.ContentType != "multipart/form-data; boundary=fount-convert-7d3f9b2c4e1a8f6052b9d4c7e3a1f8b6" {
		t.Fatalf("content type: %q", d.ContentType)
	}
	if d.Credential != CredentialLicense {
		t.Fatalf("credential: %q", d.Credential)
	}
	if err := d.Body.Check(make([]byte, 16<<20)); err != nil {
		t.Fatalf("16 MiB refused: %v", err)
	}
	if err := d.Body.Check(make([]byte, 16<<20+1)); err == nil {
		t.Fatal("a body over 16 MiB passed")
	}
}

func TestDeviceDestinations(t *testing.T) {
	for _, c := range []struct {
		name, method, path string
		signed             bool
		credential         Credential
	}{
		{"fount.device_credential", "POST", "device/credential", true, CredentialNone},
		{"fount.device_renew", "POST", "device/renew", true, CredentialNone},
		{"fount.devices", "GET", "devices", false, CredentialLicense},
		{"fount.device_revoke", "DELETE", "devices/", false, CredentialLicense},
	} {
		d, ok := Destinations[c.name]
		if !ok {
			t.Fatalf("%s is missing", c.name)
		}
		if d.Route != RouteFountAPI || d.Method != c.method || d.Path != c.path || d.Credential != c.credential || (d.ClientHeaders != nil) != c.signed {
			t.Errorf("%s: %s %s %s credential %q signed %v", c.name, d.Route, d.Method, d.Path, d.Credential, d.ClientHeaders != nil)
		}
	}
	if _, ok := Destinations["fount.license_validate"]; ok {
		t.Error("fount.license_validate is replaced by fount.device_renew")
	}

	code := Destinations["fount.device_credential"].Body
	for body, ok := range map[string]bool{
		`{"code":"Xy-9_abc"}`:                         true,
		`{"code":"` + strings.Repeat("a", 128) + `"}`: true,
		`{"code":"` + strings.Repeat("a", 129) + `"}`: false,
		`{"code":""}`:             false,
		`{"code":"a b"}`:          false,
		`{"code":1}`:              false,
		`{"code":"a","name":"x"}`: false,
		``:                        false,
	} {
		if err := code.Check([]byte(body)); (err == nil) != ok {
			t.Errorf("device_credential body %q: %v, want ok=%v", body, err, ok)
		}
	}
	if err := Destinations["fount.device_renew"].Body.Check([]byte("{}")); err == nil {
		t.Error("device_renew took a body")
	}

	revoke := Destinations["fount.device_revoke"].PathPattern
	for path, ok := range map[string]bool{
		"0123456789abcdef0123456789abcdef":  true,
		"0123456789ABCDEF0123456789abcdef":  false,
		"0123456789abcdef0123456789abcde":   false,
		"0123456789abcdef0123456789abcdef0": false,
		"":                                  false,
	} {
		if revoke.MatchString(path) != ok {
			t.Errorf("revoke path %q: want ok=%v", path, ok)
		}
	}
}
