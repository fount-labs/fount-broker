package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/fount-labs/fount-broker/internal/frame"
	"github.com/fount-labs/fount-broker/internal/policy"
	"github.com/fount-labs/fount-broker/internal/protocol"
	"github.com/fount-labs/fount-broker/internal/route"
)

const dest = "tinfoil.chat_completions"

type fakeRoute struct {
	do     func(ctx context.Context, r route.Request) (*http.Response, error)
	status func(ctx context.Context) (any, error)
}

func (f *fakeRoute) Do(ctx context.Context, r route.Request) (*http.Response, error) {
	return f.do(ctx, r)
}

func (f *fakeRoute) Status(ctx context.Context) (any, error) { return f.status(ctx) }

// session runs a broker over pipes and plays the app's side.
type session struct {
	t     *testing.T
	in    *frame.Writer
	inW   *io.PipeWriter
	out   *io.PipeReader
	done  chan error
	vault *Vault
}

func start(t *testing.T, rt route.Route) *session {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	vault := NewVault()
	b := New("test", map[string]route.Route{policy.RouteTinfoil: rt}, vault)
	s := &session{t: t, in: frame.NewWriter(inW), inW: inW, out: outR, done: make(chan error, 1), vault: vault}
	go func() {
		s.done <- b.Serve(context.Background(), inR, outW)
		outW.Close()
	}()
	t.Cleanup(func() {
		inW.Close()
		go io.Copy(io.Discard, outR)
		select {
		case <-s.done:
		case <-time.After(5 * time.Second):
			t.Error("broker did not exit after stdin closed")
		}
	})
	if r, _ := s.recv(); r.Kind != protocol.KindReady || r.Protocol != protocol.Version {
		t.Fatalf("first frame: got %+v, want ready", r)
	}
	return s
}

func (s *session) send(header string, body string) {
	s.t.Helper()
	if err := s.in.Write(frame.Frame{Header: []byte(header), Body: []byte(body)}); err != nil {
		s.t.Fatal(err)
	}
}

func (s *session) recv() (protocol.Reply, []byte) {
	s.t.Helper()
	f, err := frame.Read(s.out)
	if err != nil {
		s.t.Fatalf("reading reply: %v", err)
	}
	var r protocol.Reply
	if err := json.Unmarshal(f.Header, &r); err != nil {
		s.t.Fatal(err)
	}
	return r, f.Body
}

func okResponse(contentType, body string) *http.Response {
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {contentType}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestFetchStreamsResponse(t *testing.T) {
	var got route.Request
	s := start(t, &fakeRoute{do: func(_ context.Context, r route.Request) (*http.Response, error) {
		got = r
		return okResponse("text/event-stream", "data: hi\n\n"), nil
	}})
	s.send(`{"kind":"credential","id":1,"name":"license"}`, "LIC-123")
	if r, _ := s.recv(); r.Kind != protocol.KindResult {
		t.Fatalf("credential: got %+v", r)
	}

	s.send(fmt.Sprintf(`{"kind":"fetch","id":2,"dest":%q,"accept":"text/event-stream"}`, dest), `{"model":"m"}`)
	head, _ := s.recv()
	if head.Kind != protocol.KindHead || head.Status != 200 || head.ContentType != "text/event-stream" {
		t.Fatalf("head: got %+v", head)
	}
	var body strings.Builder
	for {
		r, chunk := s.recv()
		if r.Kind == protocol.KindEnd {
			break
		}
		if r.Kind != protocol.KindData || r.ID != 2 {
			t.Fatalf("got %+v, want data for 2", r)
		}
		body.Write(chunk)
	}
	if body.String() != "data: hi\n\n" {
		t.Fatalf("body: got %q", body.String())
	}
	if got.Credential != "LIC-123" || string(got.Body) != `{"model":"m"}` || got.Accept != "text/event-stream" || got.Dest.Path != "chat/completions" {
		t.Fatalf("route got %+v", got)
	}
}

func TestPolicyRefusals(t *testing.T) {
	called := false
	s := start(t, &fakeRoute{do: func(context.Context, route.Request) (*http.Response, error) {
		called = true
		return okResponse("application/json", "{}"), nil
	}})

	cases := []struct {
		header string
		code   protocol.Code
	}{
		{`{"kind":"fetch","id":1,"dest":"https://evil.example/"}`, protocol.CodePolicy},
		{fmt.Sprintf(`{"kind":"fetch","id":2,"dest":%q,"accept":"text/html"}`, dest), protocol.CodePolicy},
		{fmt.Sprintf(`{"kind":"fetch","id":3,"dest":%q}`, dest), protocol.CodeCredential},
		{`{"kind":"credential","id":4,"name":"aws_secret"}`, protocol.CodePolicy},
		{`{"kind":"status","id":5,"route":"openrouter"}`, protocol.CodePolicy},
		{`{"kind":"fetch","id":6,"dest":"x","url":"https://evil.example/"}`, protocol.CodeBadRequest},
	}
	for _, c := range cases {
		s.send(c.header, "")
		r, _ := s.recv()
		if r.Kind != protocol.KindError || r.Code != c.code {
			t.Errorf("%s: got %+v, want %s", c.header, r, c.code)
		}
	}
	if called {
		t.Fatal("a refused request reached the route")
	}
}

func TestMalformedHeaderEchoesID(t *testing.T) {
	s := start(t, &fakeRoute{})
	s.send(`{"kind":"fetch","id":7,"dest":"x","bogus":1}`, "")
	r, _ := s.recv()
	if r.Kind != protocol.KindError || r.ID != 7 || r.Code != protocol.CodeBadRequest {
		t.Fatalf("got %+v", r)
	}
}

func TestCancelStopsInflightRequest(t *testing.T) {
	entered := make(chan struct{})
	s := start(t, &fakeRoute{do: func(ctx context.Context, _ route.Request) (*http.Response, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}})
	s.vault.Set(policy.CredentialLicense, "LIC")
	s.send(fmt.Sprintf(`{"kind":"fetch","id":9,"dest":%q}`, dest), "{}")
	<-entered
	s.send(`{"kind":"cancel","id":9}`, "")
	r, _ := s.recv()
	if r.Kind != protocol.KindError || r.ID != 9 || r.Code != protocol.CodeCancelled {
		t.Fatalf("got %+v, want cancelled", r)
	}
}

func TestAttestationFailureIsReportedAsSuch(t *testing.T) {
	s := start(t, &fakeRoute{do: func(context.Context, route.Request) (*http.Response, error) {
		return nil, fmt.Errorf("%w: measurement mismatch", route.ErrAttestation)
	}})
	s.vault.Set(policy.CredentialLicense, "LIC")
	s.send(fmt.Sprintf(`{"kind":"fetch","id":1,"dest":%q}`, dest), "{}")
	if r, _ := s.recv(); r.Code != protocol.CodeAttestation {
		t.Fatalf("got %+v, want attestation", r)
	}
}

func TestBrokenResponseStreamEndsInError(t *testing.T) {
	s := start(t, &fakeRoute{do: func(context.Context, route.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(io.MultiReader(
			strings.NewReader("partial"), errReader{errors.New("connection reset")},
		))}, nil
	}})
	s.vault.Set(policy.CredentialLicense, "LIC")
	s.send(fmt.Sprintf(`{"kind":"fetch","id":1,"dest":%q}`, dest), "{}")
	kinds := []protocol.Kind{}
	for {
		r, _ := s.recv()
		kinds = append(kinds, r.Kind)
		if r.Kind == protocol.KindEnd || r.Kind == protocol.KindError {
			if r.Kind != protocol.KindError || r.Code != protocol.CodeNetwork {
				t.Fatalf("got %v ending in %+v, want a network error", kinds, r)
			}
			return
		}
	}
}

func TestStatusReturnsJSON(t *testing.T) {
	s := start(t, &fakeRoute{status: func(context.Context) (any, error) {
		return map[string]string{"enclave": "router.example"}, nil
	}})
	s.send(`{"kind":"status","id":1,"route":"tinfoil"}`, "")
	r, body := s.recv()
	if r.Kind != protocol.KindResult || string(body) != `{"enclave":"router.example"}` {
		t.Fatalf("got %+v %s", r, body)
	}
}

func TestDuplicateInflightIDIsRefused(t *testing.T) {
	release := make(chan struct{})
	s := start(t, &fakeRoute{do: func(ctx context.Context, _ route.Request) (*http.Response, error) {
		<-release
		return okResponse("application/json", "{}"), nil
	}})
	s.vault.Set(policy.CredentialLicense, "LIC")
	s.send(fmt.Sprintf(`{"kind":"fetch","id":1,"dest":%q}`, dest), "{}")
	s.send(fmt.Sprintf(`{"kind":"fetch","id":1,"dest":%q}`, dest), "{}")
	if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodeBadRequest {
		t.Fatalf("got %+v", r)
	}
	close(release)
	for {
		if r, _ := s.recv(); r.Kind == protocol.KindEnd {
			return
		}
	}
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }
