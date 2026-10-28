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
