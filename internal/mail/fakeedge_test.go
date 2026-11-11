package mail

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// vectors is testdata/edge-vectors.json (stored-message format 2) or
// edge-vectors-v1.json, written by the edge's own code.
type vectors struct {
	MailboxID     string `json:"mailbox_id"`
	SigningKey    []byte `json:"signing_key"`
	DecryptionKey []byte `json:"decryption_key"`
	Messages      []struct {
		EdgeID       string `json:"edge_id"`
		Sequence     uint64 `json:"sequence"`
		Boot         string `json:"boot"`
		Object       []byte `json:"object"`
		Sender       string `json:"sender"`
		Recipient    string `json:"recipient"`
		ClientIP     string `json:"client_ip"`
		ClientIPFrom byte   `json:"client_ip_from"`
		HELO         string `json:"helo"`
		Raw          []byte `json:"raw"`
	} `json:"messages"`
	Withheld     []uint64          `json:"withheld"`
	ListResponse string            `json:"list_response"`
	GapsResponse string            `json:"gaps_response"`
	Boots        map[string]string `json:"boots"`
	BootKeys     map[string]string `json:"boot_keys"`
	Request      struct {
		Method    string `json:"method"`
		Path      string `json:"path"`
		Body      string `json:"body"`
		Timestamp int64  `json:"timestamp"`
		Nonce     string `json:"nonce"`
		Signature string `json:"signature"`
	} `json:"request"`
	Comment string `json:"comment"`
}

const (
	vectorsV2 = "testdata/edge-vectors.json"
	vectorsV1 = "testdata/edge-vectors-v1.json"
)

func loadVectors(t *testing.T) *vectors { return loadVectorsTB(t, vectorsV2) }

func loadVectorsTB(t testing.TB, path string) *vectors {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func (v *vectors) keysJSON() []byte {
	b, _ := json.Marshal(map[string]any{"addresses": []map[string]any{{
		"mailbox_id": v.MailboxID, "signing_key": v.SigningKey, "decryption_key": v.DecryptionKey,
	}}})
	return b
}

// fakeEdge serves the vectors the way the edge's Device API does, and checks
// every signed request with the edge's rules.
type fakeEdge struct {
	t        *testing.T
	paused   bool // GET /mail carries it, as edge v0.2.1 does
	v        *vectors
	srv      *httptest.Server
	attested ed25519.PublicKey
	attErr   error

	mu      sync.Mutex
	objects map[string][]byte
	gaps    []string // GET /gaps records, lowest sequence first
	nonces  map[string]bool
	calls   []string
	// override lets a test answer a path itself.
	override func(w http.ResponseWriter, r *http.Request) bool
}

func newFakeEdge(t *testing.T, v *vectors) *fakeEdge {
	f := &fakeEdge{t: t, v: v, objects: map[string][]byte{}, nonces: map[string]bool{}}
	for _, m := range v.Messages {
		f.objects[m.EdgeID] = m.Object
	}
	var g struct {
		Records []string `json:"records"`
	}
	if err := json.Unmarshal([]byte(v.GapsResponse), &g); err != nil {
		t.Fatal(err)
	}
	f.gaps = g.Records
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeEdge) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	return f.srv.Client().Do(req.WithContext(ctx))
}
func (f *fakeEdge) Base() string { return f.srv.URL + "/" }
func (f *fakeEdge) AttestedSigningKey(context.Context) (ed25519.PublicKey, error) {
	return f.attested, f.attErr
}

func (f *fakeEdge) authorized(r *http.Request) bool {
	ts, err := strconv.ParseInt(r.Header.Get("Fount-Timestamp"), 10, 64)
	if err != nil || time.Since(time.Unix(ts, 0)).Abs() > 5*time.Minute {
		return false
	}
	nonce := r.Header.Get("Fount-Nonce")
	if nonce == "" || len(nonce) > 128 || f.nonces[nonce] {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(r.Header.Get("Fount-Signature"))
	if err != nil || r.Header.Get("Fount-Key-Id") != f.v.MailboxID {
		return false
	}
	pub := ed25519.NewKeyFromSeed(f.v.SigningKey).Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, []byte(Canonical(r.Method, r.URL.Path, nil, ts, nonce)), sig) {
		return false
	}
	f.nonces[nonce] = true
	return true
}

func (f *fakeEdge) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.RequestURI())
	if f.override != nil && f.override(w, r) {
		return
	}
	if id, ok := strings.CutPrefix(r.URL.Path, "/boots/"); ok && r.Method == "GET" {
		b, ok := f.v.Boots[id]
		if !ok {
			http.Error(w, `{"error":"no such boot"}`, http.StatusNotFound)
			return
		}
		w.Write([]byte(b))
		return
	}
	if !f.authorized(r) {
		http.Error(w, `{"error":"signature does not verify"}`, http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/mail":
		w.Write([]byte(f.listing()))
	case r.Method == "GET" && r.URL.Path == "/gaps":
		after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
		out := []string{}
		for _, g := range f.gaps {
			rec, _, _, err := splitRecord(g)
			if err != nil {
				f.t.Errorf("fake edge holds a bad record: %v", err)
			}
			if rec.Sequence > after {
				out = append(out, g)
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"records": out})
	case strings.HasPrefix(r.URL.Path, "/mail/"):
		id := strings.TrimPrefix(r.URL.Path, "/mail/")
		obj, ok := f.objects[id]
		if !ok {
			http.Error(w, `{"error":"no such message"}`, http.StatusNotFound)
			return
		}
		if r.Method == "DELETE" {
			delete(f.objects, id)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(obj)
	default:
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}
}

func (f *fakeEdge) listing() string {
	type listed struct {
		ID   string `json:"id"`
		Size int    `json:"size"`
	}
	out := []listed{}
	for _, m := range f.v.Messages {
		if o, ok := f.objects[m.EdgeID]; ok {
			out = append(out, listed{m.EdgeID, len(o)})
		}
	}
	b, _ := json.Marshal(map[string]any{"messages": out, "paused": f.paused})
	return string(b)
}

type fakeChecker struct {
	mu    sync.Mutex
	err   error
	calls []CheckInput
}

func (c *fakeChecker) Check(_ context.Context, in CheckInput) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, in)
	if c.err != nil {
		return nil, c.err
	}
	return json.RawMessage(`{"ok":true}`), nil
}
