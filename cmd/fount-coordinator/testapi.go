package main

import (
	"crypto/subtle"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
)

// testTokenEnv names the test API's bearer token: a Tinfoil secret in the
// coordinator enclave.
const testTokenEnv = "FOUNT_TEST_API_TOKEN"

// minTestToken is 32 bytes as hex, so the token can't be guessed.
const minTestToken = 64

// testAPI puts the dev API behind a bearer token so it can listen beyond
// loopback, in the coordinator enclave until the attested client channel
// replaces it (m4-cloud-runners.md §7, P2). The wrapping key is still the dev
// one, so a coordinator with it takes test data only. /health needs no token.
func testAPI(api http.Handler) (http.Handler, error) {
	token := os.Getenv(testTokenEnv)
	if len(token) < minTestToken {
		return nil, errors.New("--test-api needs " + testTokenEnv + ", at least 32 random bytes as hex")
	}
	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			io.WriteString(w, "ok\n")
			return
		}
		got := []byte(strings.TrimSpace(r.Header.Get("Authorization")))
		if subtle.ConstantTimeCompare(got, want) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "the test API needs its bearer token", http.StatusUnauthorized)
			return
		}
		api.ServeHTTP(w, r)
	}), nil
}
