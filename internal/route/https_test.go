package route

import (
	"net/http"
	"testing"
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
	post, _ := http.NewRequest(http.MethodPost, "https://api.fount.sh/license/validate", nil)

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
