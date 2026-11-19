package s3bucket

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fount-labs/fount-broker/internal/coordinator"
)

const (
	testKeyID  = "AKIDTEST"
	testSecret = "secret/test+key"
	testRegion = "us-east-1"
)

// fakeS3 is a versioned bucket over HTTP: it checks each request's SigV4
// signature and body checksum, honours If-None-Match: *, keeps noncurrent
// versions on overwrite and delete, and pages List pageSize keys at a time.
type fakeS3 struct {
	t        *testing.T
	pageSize int

	mu       sync.Mutex
	current  map[string][]byte
	versions map[string]int // every version written or deleted, per key
	requests []string
	// fail answers the next requests with these statuses, first first.
	fail []int
	// raceOnce answers the next conditional Put with 409, as S3 does when
	// another conditional write to the key is in flight.
	raceOnce bool
	noBucket bool
}

func newFake(t *testing.T) (*fakeS3, *httptest.Server) {
	f := &fakeS3{t: t, pageSize: 2, current: map[string][]byte{}, versions: map[string]int{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func s3err(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	fmt.Fprintf(w, "<Error><Code>%s</Code><Message>%s</Message></Error>", code, code)
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if err := checkSignature(r, body); err != nil {
		f.t.Errorf("%s %s: %v", r.Method, r.URL, err)
		s3err(w, http.StatusForbidden, "SignatureDoesNotMatch")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	if len(f.fail) > 0 {
		status := f.fail[0]
		f.fail = f.fail[1:]
		s3err(w, status, "InternalError")
		return
	}
	if f.noBucket {
		s3err(w, http.StatusNotFound, "NoSuchBucket")
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/")
	switch {
	case r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2":
		f.list(w, r.URL.Query())
	case r.Method == http.MethodGet:
		data, ok := f.current[key]
		if !ok {
			s3err(w, http.StatusNotFound, "NoSuchKey")
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Write(data)
	case r.Method == http.MethodPut:
		sum := sha256.Sum256(body)
		if r.Header.Get("X-Amz-Checksum-Sha256") != base64.StdEncoding.EncodeToString(sum[:]) {
			s3err(w, http.StatusBadRequest, "BadDigest")
			return
		}
		if r.Header.Get("If-None-Match") == "*" {
			if f.raceOnce {
				f.raceOnce = false
				s3err(w, http.StatusConflict, "ConditionalRequestConflict")
				return
			}
			if _, ok := f.current[key]; ok {
				s3err(w, http.StatusPreconditionFailed, "PreconditionFailed")
				return
			}
		}
		f.current[key] = body
		f.versions[key]++
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodDelete:
		if _, ok := f.current[key]; ok {
			f.versions[key]++ // a delete marker over a noncurrent version
		}
		delete(f.current, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		s3err(w, http.StatusMethodNotAllowed, "MethodNotAllowed")
	}
}

func (f *fakeS3) list(w http.ResponseWriter, q url.Values) {
	prefix := q.Get("prefix")
	var keys []string
	for _, k := range slices.Sorted(maps.Keys(f.current)) {
		if strings.HasPrefix(k, prefix) && k > q.Get("continuation-token") {
			keys = append(keys, k)
		}
	}
	type content struct {
		Key string `xml:"Key"`
	}
	out := struct {
		XMLName     xml.Name  `xml:"ListBucketResult"`
		IsTruncated bool      `xml:"IsTruncated"`
		NextToken   string    `xml:"NextContinuationToken,omitempty"`
		Contents    []content `xml:"Contents"`
	}{}
	if len(keys) > f.pageSize {
		keys = keys[:f.pageSize]
		out.IsTruncated, out.NextToken = true, keys[len(keys)-1]
	}
	for _, k := range keys {
		out.Contents = append(out.Contents, content{k})
	}
	data, _ := xml.Marshal(out)
	w.Write(data)
}

// checkSignature signs a copy of the request as it arrived, with the
// client's date, and compares: the request wasn't changed after signing, and
// the canonical form is the server's view of it.
func checkSignature(r *http.Request, body []byte) error {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential="+testKeyID+"/") {
		return fmt.Errorf("authorization %q", auth)
	}
	hash := r.Header.Get("X-Amz-Content-Sha256")
	if hash != hexSHA256(body) {
		return fmt.Errorf("x-amz-content-sha256 %s isn't the body's", hash)
	}
	at, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil {
		return err
	}
	signed := strings.Split(between(auth, "SignedHeaders=", ","), ";")
	u := &url.URL{Scheme: "http", Host: r.Host, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	again, _ := http.NewRequest(r.Method, u.String(), nil)
	again.Host = r.Host
	for _, h := range signed {
		if h != "host" && h != "x-amz-date" {
			again.Header.Set(h, r.Header.Get(h))
		}
	}
	sign(again, hash, testRegion, service, creds{testKeyID, testSecret}, at)
	if got := again.Header.Get("Authorization"); got != auth {
		return fmt.Errorf("signature mismatch:\n got %s\nwant %s", auth, got)
	}
	return nil
}

func between(s, from, to string) string {
	_, rest, _ := strings.Cut(s, from)
	v, _, _ := strings.Cut(rest, to)
	return v
}

func newBucket(t *testing.T, srv *httptest.Server) *Bucket {
	t.Helper()
	b, err := New(Config{Endpoint: srv.URL, Region: testRegion, AccessKeyID: testKeyID, SecretAccessKey: testSecret})
	if err != nil {
		t.Fatal(err)
	}
	b.retries = []time.Duration{time.Millisecond, time.Millisecond}
	return b
}

func TestPutGetDelete(t *testing.T) {
	f, srv := newFake(t)
	b := newBucket(t, srv)
	ctx := context.Background()
	key := "objects/w1/obj one+two"
	if err := b.Put(ctx, key, []byte("sealed")); err != nil {
		t.Fatal(err)
	}
	got, err := b.Get(ctx, key)
	if err != nil || string(got) != "sealed" {
		t.Fatalf("Get = %q, %v", got, err)
	}
	if err := b.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Get(ctx, key); !errors.Is(err, coordinator.ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
	}
	if err := b.Delete(ctx, key); err != nil {
		t.Fatalf("Delete of a missing key: %v", err)
	}
	if err := b.Put(ctx, "roots/empty", nil); err != nil {
		t.Fatalf("Put of an empty object: %v", err)
	}
	if got, err := b.Get(ctx, "roots/empty"); err != nil || len(got) != 0 {
		t.Fatalf("Get of an empty object = %q, %v", got, err)
	}
	if f.versions[key] != 2 {
		t.Fatalf("versions of %s = %d, want the write and the delete marker", key, f.versions[key])
	}
}

func TestPutIsWriteOnce(t *testing.T) {
	f, srv := newFake(t)
	b := newBucket(t, srv)
	ctx := context.Background()
	if err := b.Put(ctx, "roots/1-1-1", []byte("first")); err != nil {
		t.Fatal(err)
	}
	// The same bytes again: a retry whose first answer was lost.
	if err := b.Put(ctx, "roots/1-1-1", []byte("first")); err != nil {
		t.Fatalf("a repeated Put of the same bytes: %v", err)
	}
	if err := b.Put(ctx, "roots/1-1-1", []byte("other")); !errors.Is(err, ErrExists) {
		t.Fatalf("Put over another object = %v, want ErrExists", err)
	}
	if got, _ := b.Get(ctx, "roots/1-1-1"); string(got) != "first" {
		t.Fatalf("the object became %q", got)
	}
	if f.versions["roots/1-1-1"] != 1 {
		t.Fatalf("%d versions, want 1: nothing was overwritten", f.versions["roots/1-1-1"])
	}
	// After a delete the key may be written again.
	if err := b.Delete(ctx, "roots/1-1-1"); err != nil {
		t.Fatal(err)
	}
	if err := b.Put(ctx, "roots/1-1-1", []byte("other")); err != nil {
		t.Fatalf("Put after Delete: %v", err)
	}
}

func TestPutAfterConditionalConflict(t *testing.T) {
	f, srv := newFake(t)
	b := newBucket(t, srv)
	f.raceOnce = true
	if err := b.Put(context.Background(), "objects/w/a", []byte("x")); err != nil {
		t.Fatalf("Put after a 409: %v", err)
	}
	if got, _ := b.Get(context.Background(), "objects/w/a"); string(got) != "x" {
		t.Fatalf("got %q", got)
	}
}

func TestListPagesSortedUnderPrefix(t *testing.T) {
	f, srv := newFake(t)
	b := newBucket(t, srv)
	ctx := context.Background()
	want := []string{"objects/w1/a", "objects/w1/b", "objects/w1/c", "objects/w2/a", "objects/w2/b+c d"}
	for _, k := range append(slices.Clone(want), "roots/1-1-1", "objectsx") {
		if err := b.Put(ctx, k, []byte(k)); err != nil {
			t.Fatal(err)
		}
	}
	f.requests = nil
	got, err := b.List(ctx, "objects/")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("List = %q, want %q", got, want)
	}
	if len(f.requests) != 3 {
		t.Fatalf("%d list requests, want 3 pages of 2: %q", len(f.requests), f.requests)
	}
	all, err := b.List(ctx, "")
	if err != nil || len(all) != len(want)+2 {
		t.Fatalf("List(\"\") = %q, %v", all, err)
	}
	none, err := b.List(ctx, "nothing/")
	if err != nil || none == nil || len(none) != 0 {
		t.Fatalf("List of an empty prefix = %#v, %v", none, err)
	}
}

func TestListRefusesARepeatedToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>same</NextContinuationToken><Contents><Key>a</Key></Contents></ListBucketResult>`)
	}))
	defer srv.Close()
	b := newBucket(t, srv)
	if _, err := b.List(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "continuation token") {
		t.Fatalf("List = %v, want a refusal of a looping token", err)
	}
}

func TestRetriesServerErrors(t *testing.T) {
	f, srv := newFake(t)
	b := newBucket(t, srv)
	ctx := context.Background()
	f.fail = []int{503, 500}
	if err := b.Put(ctx, "objects/w/a", []byte("x")); err != nil {
		t.Fatalf("Put after two 5xx: %v", err)
	}
	f.fail = []int{503, 503, 503}
	if _, err := b.Get(ctx, "objects/w/a"); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("Get after every retry failed = %v", err)
	}
	f.fail = []int{403}
	if _, err := b.Get(ctx, "objects/w/a"); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("a 403 = %v, want it reported, not retried", err)
	}
}

func TestMissingBucketIsNoEmptyBucket(t *testing.T) {
	f, srv := newFake(t)
	b := newBucket(t, srv)
	f.noBucket = true
	ctx := context.Background()
	if _, err := b.Get(ctx, "roots/x"); err == nil || errors.Is(err, coordinator.ErrNotFound) {
		t.Fatalf("Get from a missing bucket = %v, want an error that isn't ErrNotFound", err)
	}
	if err := b.Delete(ctx, "roots/x"); err == nil {
		t.Fatal("Delete from a missing bucket succeeded")
	}
	if _, err := b.List(ctx, ""); err == nil {
		t.Fatal("List of a missing bucket succeeded")
	}
}

func TestConfig(t *testing.T) {
	for _, c := range []Config{
		{Region: testRegion, AccessKeyID: "a", SecretAccessKey: "b"},
		{Endpoint: "https://b.s3.us-east-1.amazonaws.com", AccessKeyID: "a", SecretAccessKey: "b"},
		{Endpoint: "https://b.s3.us-east-1.amazonaws.com", Region: testRegion},
		{Endpoint: "https://s3.us-east-1.amazonaws.com/bucket", Region: testRegion, AccessKeyID: "a", SecretAccessKey: "b"},
		{Endpoint: "b.s3.us-east-1.amazonaws.com", Region: testRegion, AccessKeyID: "a", SecretAccessKey: "b"},
		{Endpoint: "https://b.s3.us-east-1.amazonaws.com", Region: testRegion, AccessKeyID: "a", SecretAccessKey: "b", Forwarder: "f:1", HTTPClient: http.DefaultClient},
	} {
		if _, err := New(c); err == nil {
			t.Errorf("New(%+v) succeeded", c)
		}
	}
	b, err := New(Config{Endpoint: "https://b.s3.us-east-1.amazonaws.com/", Region: testRegion, AccessKeyID: "a", SecretAccessKey: "b"})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"", "/abs", strings.Repeat("k", maxKey+1)} {
		if err := b.Put(context.Background(), k, nil); err == nil {
			t.Errorf("Put(%.20q) succeeded", k)
		}
	}
}

func TestSessionTokenIsSigned(t *testing.T) {
	var auth, token string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, token = r.Header.Get("Authorization"), r.Header.Get("X-Amz-Security-Token")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	b, err := New(Config{Endpoint: srv.URL, Region: testRegion, AccessKeyID: testKeyID, SecretAccessKey: testSecret, SessionToken: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Delete(context.Background(), "k"); err != nil {
		t.Fatal(err)
	}
	if token != "tok" || !strings.Contains(between(auth, "SignedHeaders=", ","), "x-amz-security-token") {
		t.Fatalf("token %q, authorization %q", token, auth)
	}
}

// TestForwarder: TCP goes to the forwarder, while the request still names
// the bucket's host, which TLS would verify.
func TestForwarder(t *testing.T) {
	f, srv := newFake(t)
	_ = f
	var dialed sync.Map
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	target := strings.TrimPrefix(srv.URL, "http://")
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			dialed.Store("yes", true)
			up, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			go func() { io.Copy(up, c); up.Close() }()
			go func() { io.Copy(c, up); c.Close() }()
		}
	}()
	b, err := New(Config{Endpoint: "http://bucket.s3.test:8080", Region: testRegion, AccessKeyID: testKeyID, SecretAccessKey: testSecret, Forwarder: ln.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := b.Put(ctx, "objects/w/a", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if got, err := b.Get(ctx, "objects/w/a"); err != nil || !bytes.Equal(got, []byte("x")) {
		t.Fatalf("Get = %q, %v", got, err)
	}
	if _, ok := dialed.Load("yes"); !ok {
		t.Fatal("nothing went through the forwarder")
	}
	// Only the bucket's own host goes through.
	other := newHTTPClient(&url.URL{Scheme: "https", Host: "bucket.s3.test"}, ln.Addr().String())
	if _, err := other.Get("https://elsewhere.example/"); err == nil || !strings.Contains(err.Error(), "no forwarder route") {
		t.Fatalf("a request to another host = %v", err)
	}
}
