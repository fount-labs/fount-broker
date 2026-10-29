package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
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
	routes := map[string]route.Route{}
	for _, name := range []string{policy.RouteTinfoil, policy.RouteFountAPI, policy.RouteFountProxy, policy.RouteModels, policy.RouteOpenRouter, policy.RouteHuggingFace, policy.RouteUpdates, policy.RouteLatex} {
		routes[name] = rt
	}
	b := New("test", routes, vault)
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

func TestBodyIsCheckedBeforeSending(t *testing.T) {
	s := start(t, &fakeRoute{do: func(context.Context, route.Request) (*http.Response, error) {
		t.Error("a refused body reached the route")
		return nil, errors.New("unreachable")
	}})
	for i, body := range []string{
		`{"licenseKey":"FOUNT-AAAA","extra":1}`,
		`{"licenseKey":"has spaces"}`,
		`{}`,
		`[1]`,
	} {
		s.send(fmt.Sprintf(`{"kind":"fetch","id":%d,"dest":"fount.license_validate"}`, i+1), body)
		if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodePolicy {
			t.Errorf("body %s: got %+v, want a policy error", body, r)
		}
	}
}

func TestPinnedDigestIsEnforced(t *testing.T) {
	const name = "test.pinned"
	content := "model bytes"
	policy.Destinations[name] = policy.Destination{
		Route: policy.RouteModels, Method: "GET", Path: "m/f", Accept: []string{""},
		SHA256: "1f1f2dd2dbbd8e4f2b0e3b8c8bd9fc2cb0f2a1e3fd2c4b6b0c1b0a8f2b4e9a7c",
	}
	t.Cleanup(func() { delete(policy.Destinations, name) })

	s := start(t, &fakeRoute{do: func(context.Context, route.Request) (*http.Response, error) {
		return okResponse("application/octet-stream", content), nil
	}})
	s.send(`{"kind":"fetch","id":1,"dest":"test.pinned"}`, "")
	if r, _ := s.recv(); r.Kind != protocol.KindHead {
		t.Fatalf("got %+v, want head", r)
	}
	if r, body := s.recv(); r.Kind != protocol.KindData || string(body) != content {
		t.Fatalf("got %+v %q, want the data", r, body)
	}
	if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodeIntegrity {
		t.Fatalf("got %+v, want an integrity error", r)
	}

	sum := sha256.Sum256([]byte(content))
	d := policy.Destinations[name]
	d.SHA256 = hex.EncodeToString(sum[:])
	policy.Destinations[name] = d
	s.send(`{"kind":"fetch","id":2,"dest":"test.pinned"}`, "")
	for {
		r, _ := s.recv()
		if r.Kind == protocol.KindEnd {
			break
		}
		if r.Kind == protocol.KindError {
			t.Fatalf("got %+v, want end", r)
		}
	}
}

func TestPathMustMatchTheDestinationPattern(t *testing.T) {
	var got []string
	s := start(t, &fakeRoute{do: func(_ context.Context, r route.Request) (*http.Response, error) {
		got = append(got, r.Dest.Path)
		return okResponse("application/octet-stream", ""), nil
	}})
	refused := []string{
		`{"kind":"fetch","id":1,"dest":"updates.package","path":"v1.2.3/../../evil"}`,
		`{"kind":"fetch","id":2,"dest":"updates.package","path":"v1.2.3/Fount_1.2.3_aarch64.app.tar.gz?x=1"}`,
		`{"kind":"fetch","id":3,"dest":"updates.package"}`,
		`{"kind":"fetch","id":4,"dest":"updates.manifest","path":"latest.json"}`,
	}
	for _, h := range refused {
		s.send(h, "")
		if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodePolicy {
			t.Errorf("%s: got %+v, want a policy error", h, r)
		}
	}
	s.send(`{"kind":"fetch","id":5,"dest":"updates.package","path":"v1.2.3/Fount_1.2.3_aarch64.app.tar.gz"}`, "")
	for r, _ := s.recv(); r.Kind != protocol.KindEnd; r, _ = s.recv() {
		if r.Kind == protocol.KindError {
			t.Fatalf("got %+v, want the package", r)
		}
	}
	if want := []string{"download/v1.2.3/Fount_1.2.3_aarch64.app.tar.gz"}; !slices.Equal(got, want) {
		t.Fatalf("route saw paths %q, want %q", got, want)
	}
}

func TestLatexFileIsARangeOfTheBundle(t *testing.T) {
	var got []route.Request
	s := start(t, &fakeRoute{do: func(_ context.Context, r route.Request) (*http.Response, error) {
		got = append(got, r)
		resp := okResponse("application/octet-stream", "x")
		resp.StatusCode = http.StatusPartialContent
		return resp, nil
	}})
	refused := []string{
		`{"kind":"fetch","id":1,"dest":"latex.file","path":"not-in-the-bundle.sty"}`,
		`{"kind":"fetch","id":2,"dest":"latex.file"}`,
		`{"kind":"fetch","id":3,"dest":"latex.file","path":"../evil"}`,
	}
	for _, h := range refused {
		s.send(h, "")
		if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodePolicy {
			t.Errorf("%s: got %+v, want a policy error", h, r)
		}
	}
	s.send(`{"kind":"fetch","id":4,"dest":"latex.file","path":"aasjournal.bst"}`, "")
	for r, _ := s.recv(); r.Kind != protocol.KindEnd; r, _ = s.recv() {
		if r.Kind == protocol.KindError {
			t.Fatalf("got %+v, want the file", r)
		}
	}
	if len(got) != 1 {
		t.Fatalf("route saw %d requests, want 1", len(got))
	}
	if got[0].Dest.Path != policy.LatexBundle || got[0].Dest.Headers["Range"] != "bytes=2560-40489" {
		t.Fatalf("route saw %q with Range %q", got[0].Dest.Path, got[0].Dest.Headers["Range"])
	}
	if policy.Destinations["latex.file"].Headers != nil {
		t.Fatal("the request's Range leaked into the shared destination")
	}
}

func TestLatexFileRefusesAWholeBundleReply(t *testing.T) {
	s := start(t, &fakeRoute{do: func(context.Context, route.Request) (*http.Response, error) {
		return okResponse("application/octet-stream", "the whole tar"), nil
	}})
	s.send(`{"kind":"fetch","id":1,"dest":"latex.file","path":"aasjournal.bst"}`, "")
	if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodeNetwork {
		t.Fatalf("got %+v, want a network error before any data", r)
	}
}
