// Package s3buckettest is an S3 bucket over HTTP for tests of the backup
// client's callers: the restore drill and the coordinator's flags. It keeps
// what the coordinator relies on from S3 (docs/backups.md): a write-once Put
// under If-None-Match: *, the body's SHA-256 checked, a 404 for a missing
// key, and List paged two keys at a time. It checks each request is SigV4
// under the access key it was made with, with the body's hash; package
// s3bucket's own tests check the signature itself.
package s3buckettest

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// Fake is the bucket. Its zero value isn't ready: use New or Start.
type Fake struct {
	keyID   string
	t       testing.TB
	mu      sync.Mutex
	objects map[string][]byte
}

// pageSize is how many keys a List page holds, so every List pages.
const pageSize = 2

// New is an empty bucket whose every request must be signed by keyID. It
// fails t on a request it can't take.
func New(t testing.TB, keyID string) *Fake {
	return &Fake{t: t, keyID: keyID, objects: map[string][]byte{}}
}

// Start serves a new bucket until the test ends; its endpoint is the
// server's URL.
func Start(t testing.TB, keyID string) (*Fake, *httptest.Server) {
	f := New(t, keyID)
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

// Keys are every key in the bucket, sorted.
func (f *Fake) Keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Sorted(maps.Keys(f.objects))
}

// Object is key's bytes, or nil.
func (f *Fake) Object(key string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.objects[key])
}

// Len is how many keys the bucket holds.
func (f *Fake) Len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.objects)
}

func fail(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	fmt.Fprintf(w, "<Error><Code>%s</Code><Message>%s</Message></Error>", code, code)
}

func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if err := f.signed(r, body); err != nil {
		f.t.Errorf("s3buckettest: %s %s: %v", r.Method, r.URL, err)
		fail(w, http.StatusForbidden, "SignatureDoesNotMatch")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.TrimPrefix(r.URL.Path, "/")
	switch {
	case r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2":
		f.list(w, r)
	case r.Method == http.MethodGet:
		data, ok := f.objects[key]
		if !ok {
			fail(w, http.StatusNotFound, "NoSuchKey")
			return
		}
		w.Write(data)
	case r.Method == http.MethodPut:
		sum := sha256.Sum256(body)
		if r.Header.Get("X-Amz-Checksum-Sha256") != base64.StdEncoding.EncodeToString(sum[:]) {
			fail(w, http.StatusBadRequest, "BadDigest")
			return
		}
		if _, ok := f.objects[key]; ok && r.Header.Get("If-None-Match") == "*" {
			fail(w, http.StatusPreconditionFailed, "PreconditionFailed")
			return
		}
		f.objects[key] = body
	case r.Method == http.MethodDelete:
		delete(f.objects, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		fail(w, http.StatusMethodNotAllowed, "MethodNotAllowed")
	}
}

func (f *Fake) signed(r *http.Request, body []byte) error {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential="+f.keyID+"/") {
		return fmt.Errorf("authorization %q isn't SigV4 by %q", auth, f.keyID)
	}
	sum := sha256.Sum256(body)
	if got := r.Header.Get("X-Amz-Content-Sha256"); got != hex.EncodeToString(sum[:]) {
		return fmt.Errorf("x-amz-content-sha256 %q isn't the body's", got)
	}
	return nil
}

func (f *Fake) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var keys []string
	for _, k := range slices.Sorted(maps.Keys(f.objects)) {
		if strings.HasPrefix(k, q.Get("prefix")) && k > q.Get("continuation-token") {
			keys = append(keys, k)
		}
	}
	type content struct {
		Key string `xml:"Key"`
	}
	out := struct {
		XMLName     xml.Name  `xml:"ListBucketResult"`
		IsTruncated bool      `xml:"IsTruncated"`
		Next        string    `xml:"NextContinuationToken,omitempty"`
		Contents    []content `xml:"Contents"`
	}{}
	if len(keys) > pageSize {
		keys = keys[:pageSize]
		out.IsTruncated, out.Next = true, keys[pageSize-1]
	}
	for _, k := range keys {
		out.Contents = append(out.Contents, content{k})
	}
	data, _ := xml.Marshal(out)
	w.Write(data)
}
