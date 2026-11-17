package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTestAPINeedsItsToken(t *testing.T) {
	t.Setenv(testTokenEnv, "short")
	if _, err := testAPI(http.NotFoundHandler()); err == nil {
		t.Fatal("a short token was taken")
	}

	token := strings.Repeat("ab", 32)
	t.Setenv(testTokenEnv, token)
	api := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h, err := testAPI(api)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		path, auth string
		want       int
	}{
		{"/health", "", http.StatusOK},
		{"/v0/jobs/x", "", http.StatusUnauthorized},
		{"/v0/jobs/x", "Bearer " + token[:63], http.StatusUnauthorized},
		{"/v0/jobs/x", "Bearer " + token + "0", http.StatusUnauthorized},
		{"/v0/jobs/x", "Basic " + token, http.StatusUnauthorized},
		{"/v0/jobs/x", "Bearer " + token, http.StatusTeapot},
	} {
		r := httptest.NewRequest("GET", c.path, nil)
		if c.auth != "" {
			r.Header.Set("Authorization", c.auth)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%s with %q: %d, want %d", c.path, c.auth, w.Code, c.want)
		}
	}
}
