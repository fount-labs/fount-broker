package healthcheck

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckReachesOnlyLoopback(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer ok.Close()
	if err := Check(ok.URL); err != nil {
		t.Fatal(err)
	}
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer down.Close()
	if err := Check(down.URL); err == nil {
		t.Fatal("a 503 passed")
	}
	if err := Check("http://example.com/health"); err == nil {
		t.Fatal("reached a non-loopback host")
	}
}
