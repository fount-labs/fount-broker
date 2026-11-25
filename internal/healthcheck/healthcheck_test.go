package healthcheck

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckReachesOnlyLoopback(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer ok.Close()
	if err := Check(ok.URL); err != nil {
		t.Fatal(err)
	}
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "refused: the volume didn't open: another key", http.StatusServiceUnavailable)
	}))
	defer down.Close()
	if err := Check(down.URL); err == nil || !strings.Contains(err.Error(), "another key") {
		t.Fatalf("a 503 passed, or without its reason: %v", err)
	}
	if err := Check("http://example.com/health"); err == nil {
		t.Fatal("reached a non-loopback host")
	}
}
