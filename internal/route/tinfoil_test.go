package route

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	tinfoil "github.com/tinfoilsh/tinfoil-go"
	"github.com/tinfoilsh/tinfoil-go/verify"

	"github.com/fount-labs/fount-broker/internal/policy"
)

type fakeEnclave struct {
	host string
	do   func(*http.Request) (*http.Response, error)
}

func (f *fakeEnclave) Do(r *http.Request) (*http.Response, error) { return f.do(r) }
func (f *fakeEnclave) Enclave() string                            { return f.host }
func (f *fakeEnclave) EnsureVerified(context.Context) (*verify.Verification, error) {
	return nil, errors.New("not used")
}

var chat = Request{Dest: policy.Destinations["tinfoil.chat_completions"], Accept: "text/event-stream", Body: []byte(`{"model":"m"}`), Credential: "LIC"}

func TestTinfoilSendsFixedShape(t *testing.T) {
	var got *http.Request
	var gotBody string
	tf := &Tinfoil{base: "https://proxy.example/proxy/v1/", discover: func(context.Context) (enclave, error) {
		return &fakeEnclave{host: "router-0", do: func(r *http.Request) (*http.Response, error) {
			got = r
			b, _ := io.ReadAll(r.Body)
			gotBody = string(b)
			return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
		}}, nil
	}}
	if _, err := tf.Do(context.Background(), chat); err != nil {
		t.Fatal(err)
	}
	if got.Method != "POST" || got.URL.String() != "https://proxy.example/proxy/v1/chat/completions" {
		t.Fatalf("got %s %s", got.Method, got.URL)
	}
	if got.Header.Get("Authorization") != "Bearer LIC" || got.Header.Get("Accept") != "text/event-stream" || got.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("headers: %v", got.Header)
	}
	if gotBody != `{"model":"m"}` {
		t.Fatalf("body: %q", gotBody)
	}
}

func TestTinfoilRediscoversOnceAfterNetworkFailure(t *testing.T) {
	discoveries := 0
	tf := &Tinfoil{base: "https://proxy.example/proxy/v1/", discover: func(context.Context) (enclave, error) {
		discoveries++
		n := discoveries
		return &fakeEnclave{host: "router", do: func(r *http.Request) (*http.Response, error) {
			if n == 1 {
				return nil, &tinfoil.NetworkError{Err: errors.New("connection refused")}
			}
			b, _ := io.ReadAll(r.Body)
			if string(b) != `{"model":"m"}` {
				t.Errorf("retry body: %q", b)
			}
			return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
		}}, nil
	}}
	if _, err := tf.Do(context.Background(), chat); err != nil {
		t.Fatal(err)
	}
	if discoveries != 2 {
		t.Fatalf("discoveries: %d, want 2", discoveries)
	}
}

func TestTinfoilDoesNotRetryAttestationFailure(t *testing.T) {
	discoveries := 0
	tf := &Tinfoil{base: "https://proxy.example/proxy/v1/", discover: func(context.Context) (enclave, error) {
		discoveries++
		return &fakeEnclave{do: func(*http.Request) (*http.Response, error) {
			return nil, &tinfoil.AttestationError{Err: errors.New("bad measurement")}
		}}, nil
	}}
	_, err := tf.Do(context.Background(), chat)
	if !errors.Is(err, ErrAttestation) {
		t.Fatalf("got %v, want ErrAttestation", err)
	}
	if discoveries != 1 {
		t.Fatalf("discoveries: %d, want 1", discoveries)
	}
}

func TestTinfoilDiscoveryAttestationFailure(t *testing.T) {
	tf := &Tinfoil{base: "https://proxy.example/proxy/v1/", discover: func(context.Context) (enclave, error) {
		return nil, &tinfoil.AttestationError{Err: errors.New("revoked")}
	}}
	if _, err := tf.Do(context.Background(), chat); !errors.Is(err, ErrAttestation) {
		t.Fatalf("got %v, want ErrAttestation", err)
	}
}

func TestTinfoilRefusesEscapingPath(t *testing.T) {
	tf := &Tinfoil{base: "https://proxy.example/proxy/v1/", discover: func(context.Context) (enclave, error) {
		return &fakeEnclave{do: func(*http.Request) (*http.Response, error) {
			t.Fatal("request was sent")
			return nil, nil
		}}, nil
	}}
	bad := chat
	bad.Dest.Path = "../../admin"
	if _, err := tf.Do(context.Background(), bad); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("got %v", err)
	}
}
