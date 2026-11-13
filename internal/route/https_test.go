package route

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fount-labs/fount-broker/internal/policy"
)

func TestRedirectPolicy(t *testing.T) {
	get := func(url string) *http.Request {
		r, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	first := get("https://github.com/fount-labs/fount/releases/latest/download/latest.json")
	post, _ := http.NewRequest(http.MethodPost, "https://api.fount.sh/device/renew", nil)

	follow := redirectPolicy([]string{"github.com", "release-assets.githubusercontent.com"})
	if err := follow(get("https://release-assets.githubusercontent.com/a"), []*http.Request{first}); err != nil {
		t.Errorf("redirect to an allowed host: %v", err)
	}
	hf := redirectPolicy([]string{"huggingface.co", ".hf.co"})
	if err := hf(get("https://us.aws.cdn.hf.co/xet-bridge-us/a"), []*http.Request{first}); err != nil {
		t.Errorf("redirect to a subdomain of an allowed suffix: %v", err)
	}
	for _, url := range []string{"https://hf.co.evil.example/a", "https://evilhf.co/a"} {
		if err := hf(get(url), []*http.Request{first}); err == nil {
			t.Errorf("followed a redirect to %s", url)
		}
	}
	if err := follow(get("https://evil.example/a"), []*http.Request{first}); err == nil {
		t.Error("followed a redirect to another host")
	}
	if err := follow(get("http://github.com/a"), []*http.Request{first}); err == nil {
		t.Error("followed a redirect to plain HTTP")
	}
	if err := follow(get("https://github.com/a"), []*http.Request{post}); err != http.ErrUseLastResponse {
		t.Errorf("redirect after a POST: got %v, want the 3xx returned as is", err)
	}
	if err := redirectPolicy(nil)(get("https://github.com/a"), []*http.Request{first}); err != http.ErrUseLastResponse {
		t.Errorf("route without redirect hosts: got %v, want the 3xx returned as is", err)
	}
}

func TestHTTPSSendsTheBodyAndHeadersItIsGiven(t *testing.T) {
	var method, path, auth, contentType string
	var header http.Header
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path, auth, contentType, header = r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), r.Header
		body, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()

	dest := policy.Destinations["fount.device_credential"]
	dest.Headers = map[string]string{"Fount-Device": "d", "Fount-Timestamp": "1", "Fount-Signature": "s"}
	sent := []byte("{ \"code\" :\t\"abc\" }")
	resp, err := NewHTTPS(srv.URL+"/", nil).Do(t.Context(), Request{Dest: dest, Body: sent})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if method != "POST" || path != "/device/credential" || auth != "" || contentType != "application/json" || !bytes.Equal(body, sent) {
		t.Fatalf("server got %s %s auth %q type %q body %q", method, path, auth, contentType, body)
	}
	for k, v := range dest.Headers {
		if got := header.Values(k); len(got) != 1 || got[0] != v {
			t.Errorf("header %s: got %q, want %q", k, got, v)
		}
	}
}
