package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeRegistry serves one image: an index naming this platform's manifest and
// another's, behind a bearer token, with blobs redirected to a second host.
type fakeRegistry struct {
	blobs    map[string][]byte
	index    string
	tamper   string
	realm    string
	redirect string
	tokens   int
	sawAuth  map[string]string
	other    string
}

func newFake(t *testing.T) (*fakeRegistry, *httptest.Server) {
	t.Helper()
	f := &fakeRegistry{blobs: map[string][]byte{}, sawAuth: map[string]string{}}
	put := func(data []byte) descriptor {
		d := descriptor{Digest: digestOf(data), Size: int64(len(data))}
		f.blobs[d.Digest] = data
		return d
	}
	config := put([]byte(`{"architecture":"` + runtime.GOARCH + `","os":"linux"}`))
	config.MediaType = "application/vnd.oci.image.config.v1+json"
	layer := put([]byte("layer bytes"))
	layer.MediaType = "application/vnd.oci.image.layer.v1.tar+gzip"
	m, _ := json.Marshal(manifest{MediaType: mediaOCIManifest, Config: &config, Layers: []descriptor{layer}})
	md := put(m)
	md.MediaType = mediaOCIManifest
	md.Platform = &struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
	}{runtime.GOARCH, "linux"}
	other := put([]byte(`{"mediaType":"` + mediaOCIManifest + `","layers":[]}`))
	other.MediaType = mediaOCIManifest
	other.Platform = &struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
	}{"s390x", "linux"}
	idx, _ := json.Marshal(manifest{MediaType: mediaOCIIndex, Manifests: []descriptor{md, other}})
	f.index = put(idx).Digest
	f.other = other.Digest

	blobHost := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.sawAuth["blob-host"] = r.Header.Get("Authorization")
		digest := strings.TrimPrefix(r.URL.Path, "/")
		data := f.blobs[digest]
		if digest == f.tamper {
			data = append([]byte("x"), data[1:]...)
		}
		w.Write(data)
	}))
	t.Cleanup(blobHost.Close)
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			f.tokens++
			if _, pass, _ := r.BasicAuth(); pass != "read-only" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, `{"token":"t0k"}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer t0k" {
			realm := f.realm
			if realm == "" {
				realm = srv.URL + "/token"
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+realm+`",service="fake",scope="repository:fount-labs/runner:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		repo, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/v2/"), "/")
		if repo != "fount-labs" {
			http.NotFound(w, r)
			return
		}
		kind, digest, _ := strings.Cut(strings.TrimPrefix(rest, "runner/"), "/")
		data, ok := f.blobs[digest]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if digest == f.tamper {
			data = append([]byte("x"), data[1:]...)
		}
		if kind == "blobs" {
			target := blobHost.URL
			if f.redirect != "" {
				target = f.redirect
			}
			http.Redirect(w, r, target+"/"+digest, http.StatusTemporaryRedirect)
			return
		}
		w.Write(data)
	}))
	t.Cleanup(srv.Close)
	return f, srv
}

func puller(srv *httptest.Server, hosts ...string) *Puller {
	c := Client(hosts...)
	c.Transport = srv.Client().Transport
	return &Puller{Base: srv.URL, Client: c, Token: "read-only"}
}

func TestPullWritesALayoutTheSupervisorCanCheck(t *testing.T) {
	f, srv := newFake(t)
	dir := t.TempDir()
	ref := Ref{Host: "fake", Repository: "fount-labs/runner", Digest: f.index}
	if err := puller(srv, "127.0.0.1").Pull(context.Background(), ref, dir); err != nil {
		t.Fatal(err)
	}
	if !Complete(dir, f.index) {
		t.Fatal("index.json doesn't name the pinned digest")
	}
	for digest, data := range f.blobs {
		got, err := os.ReadFile(blobPath(dir, digest))
		if digest == f.other {
			if err == nil {
				t.Errorf("fetched %s, another platform's manifest", digest)
			}
			continue
		}
		if err != nil || string(got) != string(data) {
			t.Errorf("blob %s: %v", digest, err)
		}
	}
	if f.sawAuth["blob-host"] != "" {
		t.Errorf("the blob host saw Authorization %q", f.sawAuth["blob-host"])
	}

	// A second pull keeps what's there and fetches nothing it already has.
	tokens := f.tokens
	if err := puller(srv, "127.0.0.1").Pull(context.Background(), ref, dir); err != nil {
		t.Fatal(err)
	}
	if f.tokens != tokens+1 {
		t.Errorf("tokens %d → %d", tokens, f.tokens)
	}
}

func TestPullRefusesWhatIsntPinned(t *testing.T) {
	cases := map[string]func(f *fakeRegistry){
		"tampered layer":          func(f *fakeRegistry) { f.tamper = layerDigest(f) },
		"tampered index":          func(f *fakeRegistry) { f.tamper = f.index },
		"realm on another host":   func(f *fakeRegistry) { f.realm = "https://example.com/token" },
		"redirect off the policy": func(f *fakeRegistry) { f.redirect = "https://localhost:1" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f, srv := newFake(t)
			mutate(f)
			dir := t.TempDir()
			ref := Ref{Host: "fake", Repository: "fount-labs/runner", Digest: f.index}
			err := puller(srv, "127.0.0.1").Pull(context.Background(), ref, dir)
			if err == nil {
				t.Fatal("pulled")
			}
			t.Log(err)
			if Complete(dir, f.index) {
				t.Error("index.json written for a failed pull")
			}
			if f.tamper != "" {
				if _, err := os.Stat(blobPath(dir, f.tamper)); err == nil {
					t.Error("kept the tampered blob")
				}
				if left, _ := filepath.Glob(filepath.Join(dir, "blobs", "sha256", ".pull-*")); len(left) > 0 {
					t.Errorf("left %v", left)
				}
			}
		})
	}
}

func layerDigest(f *fakeRegistry) string {
	for d, data := range f.blobs {
		if string(data) == "layer bytes" {
			return d
		}
	}
	return ""
}

func TestParseRefNeedsADigest(t *testing.T) {
	good := "ghcr.io/fount-labs/runner@sha256:" + strings.Repeat("a", 64)
	if r, err := ParseRef(good); err != nil || r.Host != "ghcr.io" || r.Repository != "fount-labs/runner" {
		t.Fatalf("%+v %v", r, err)
	}
	for _, bad := range []string{
		"ghcr.io/fount-labs/runner:latest",
		"fount-labs/runner@sha256:" + strings.Repeat("a", 64),
		"ghcr.io/Fount/runner@sha256:" + strings.Repeat("a", 64),
		"ghcr.io/fount-labs/../x@sha256:" + strings.Repeat("a", 64),
		"ghcr.io/fount-labs/runner@sha256:" + strings.Repeat("A", 64),
	} {
		if _, err := ParseRef(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
