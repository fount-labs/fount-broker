package route

import (
	"context"
	"errors"
	"fmt"
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
				return nil, fmt.Errorf("%w: connection refused", tinfoil.ErrNetwork)
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
			return nil, fmt.Errorf("%w: bad measurement", tinfoil.ErrAttestation)
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
		return nil, fmt.Errorf("%w: revoked", tinfoil.ErrAttestation)
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

func TestTinfoilSendsDestinationHeaders(t *testing.T) {
	var got *http.Request
	tf := &Tinfoil{base: "https://proxy.example/proxy/", discover: func(context.Context) (enclave, error) {
		return &fakeEnclave{host: policy.TinfoilWebSearchHost, do: func(r *http.Request) (*http.Response, error) {
			got = r
			return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
		}}, nil
	}}
	search := Request{Dest: policy.Destinations["tinfoil.websearch"], Body: []byte(`{}`), Credential: "LIC"}
	if _, err := tf.Do(context.Background(), search); err != nil {
		t.Fatal(err)
	}
	if got.URL.String() != "https://proxy.example/proxy/mcp" {
		t.Fatalf("url: %s", got.URL)
	}
	if got.Header.Get("Accept") != "application/json, text/event-stream" || got.Header.Get("X-Tinfoil-Tool-PII-Check") != "true" {
		t.Fatalf("headers: %v", got.Header)
	}
}

func TestCheckRepoRefusesAnotherRepo(t *testing.T) {
	if err := checkRepo(policy.TinfoilWebSearchRepo)(&verify.Verification{}); err == nil {
		t.Fatal("an unpinned repo passed")
	}
}

func TestTinfoilSendsConvertFileWithFixedModeAndBoundary(t *testing.T) {
	var got *http.Request
	tf := &Tinfoil{base: "https://proxy.example/proxy/v1/", discover: func(context.Context) (enclave, error) {
		return &fakeEnclave{host: "router-0", do: func(r *http.Request) (*http.Response, error) {
			got = r
			return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
		}}, nil
	}}
	convert := Request{Dest: policy.Destinations["tinfoil.convert_file"], Accept: "application/json", Body: []byte("--x--"), Credential: "LIC"}
	if _, err := tf.Do(context.Background(), convert); err != nil {
		t.Fatal(err)
	}
	if got.Method != "POST" || got.URL.Path != "/proxy/v1/convert/file" || got.URL.RawQuery != "mode=vlm" {
		t.Fatalf("got %s %s", got.Method, got.URL)
	}
	if got.Header.Get("Content-Type") != "multipart/form-data; boundary=fount-convert-7d3f9b2c4e1a8f6052b9d4c7e3a1f8b6" {
		t.Fatalf("content type: %q", got.Header.Get("Content-Type"))
	}
	if got.Header.Get("Authorization") != "Bearer LIC" || got.Header.Get("Accept") != "application/json" {
		t.Fatalf("headers: %v", got.Header)
	}
}

// remembering is a route sharing m, whose discovery and remembered-router
// clients are fakes that count their calls.
type remembering struct {
	fresh, known []string // the hosts each was asked for, in order
	knownErr     error
	sendErr      error
}

func (f *remembering) route(m *RouterMemory, discovered string) *Tinfoil {
	ok := func(host string) enclave {
		return &fakeEnclave{host: host, do: func(*http.Request) (*http.Response, error) {
			if f.sendErr != nil {
				err := f.sendErr
				f.sendErr = nil
				return nil, err
			}
			return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
		}}
	}
	tf := &Tinfoil{base: "https://proxy.example/proxy/v1/", memory: m}
	tf.discover = m.discoverWith(func(context.Context) (enclave, error) {
		f.fresh = append(f.fresh, discovered)
		return ok(discovered), nil
	}, func(_ context.Context, host string) (enclave, error) {
		f.known = append(f.known, host)
		if f.knownErr != nil {
			return nil, f.knownErr
		}
		return ok(host), nil
	})
	return tf
}

func TestRemembersTheRouterAcrossRoutes(t *testing.T) {
	m := &RouterMemory{}
	f := &remembering{}
	for range 3 {
		if _, err := f.route(m, "router-0.tinfoil.sh").Do(context.Background(), chat); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.fresh) != 1 || fmt.Sprint(f.known) != "[router-0.tinfoil.sh router-0.tinfoil.sh]" {
		t.Fatalf("discovered %v, went straight to %v", f.fresh, f.known)
	}
}

func TestDiscoversAgainWhenTheRememberedRouterFails(t *testing.T) {
	m := &RouterMemory{}
	m.set("router-0.tinfoil.sh")
	f := &remembering{knownErr: fmt.Errorf("%w: timeout", tinfoil.ErrNetwork)}
	if _, err := f.route(m, "inference.tinfoil.sh").Do(context.Background(), chat); err != nil {
		t.Fatal(err)
	}
	if len(f.fresh) != 1 || m.get() != "inference.tinfoil.sh" {
		t.Fatalf("discovered %v, remembers %q", f.fresh, m.get())
	}
}

func TestForgetsTheRouterASendFailedOn(t *testing.T) {
	m := &RouterMemory{}
	m.set("router-0.tinfoil.sh")
	f := &remembering{sendErr: fmt.Errorf("%w: connection reset", tinfoil.ErrNetwork)}
	if _, err := f.route(m, "inference.tinfoil.sh").Do(context.Background(), chat); err != nil {
		t.Fatal(err)
	}
	// The retry discovers rather than going back to the router that failed.
	if fmt.Sprint(f.known) != "[router-0.tinfoil.sh]" || len(f.fresh) != 1 || m.get() != "inference.tinfoil.sh" {
		t.Fatalf("went straight to %v, discovered %v, remembers %q", f.known, f.fresh, m.get())
	}
}

func TestKeepsTheRouterWhenTheRouteIsCancelled(t *testing.T) {
	m := &RouterMemory{}
	m.set("router-0.tinfoil.sh")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &remembering{knownErr: context.Canceled}
	if _, err := f.route(m, "inference.tinfoil.sh").Do(ctx, chat); err == nil {
		t.Fatal("a cancelled route succeeded")
	}
	if len(f.fresh) != 0 || m.get() != "router-0.tinfoil.sh" {
		t.Fatalf("discovered %v, remembers %q", f.fresh, m.get())
	}
}

func TestProcessSecretOnlyWhenNoneIsSet(t *testing.T) {
	if orProcessSecret("mine") != "mine" {
		t.Fatal("replaced a set secret")
	}
	a, b := orProcessSecret(""), orProcessSecret("")
	if a == "" || a != b {
		t.Fatalf("process secrets %q, %q", a, b)
	}
}
