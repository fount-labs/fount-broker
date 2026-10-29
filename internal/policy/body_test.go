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
		if d.Method == "GET" && d.Body.Kind != BodyNone {
			t.Errorf("%s: a GET must not take a body", name)
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
