// Package registry pulls one image, pinned by digest, from a container registry
// into an OCI image layout: the runner enclave's broker fetching the harness for
// the supervisor (m4-cloud-runners.md §5.1c). The broker is untrusted for this:
// the supervisor checks every digest again before it reads a byte. The checks
// here only stop a broken or hostile registry from filling the volume.
//
// The layout holds the pinned manifest or index, the one manifest for this
// platform, its config and its layers, under blobs/sha256/. index.json is
// written last, so a layout with one is complete.
package registry

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
)

const (
	maxJSON   = 4 << 20
	maxLayers = 128
	// MaxImageBytes bounds the compressed blobs of one pull. The harness is
	// about 1 GB compressed.
	MaxImageBytes = 8 << 30
)

const (
	mediaOCIIndex    = "application/vnd.oci.image.index.v1+json"
	mediaDockerList  = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaOCIManifest = "application/vnd.oci.image.manifest.v1+json"
	mediaDockerV2    = "application/vnd.docker.distribution.manifest.v2+json"
)

var manifestTypes = []string{mediaOCIIndex, mediaDockerList, mediaOCIManifest, mediaDockerV2}

var (
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// repoPattern is the distribution spec's repository name.
	repoPattern = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)
)

// Ref is an image pinned by digest: host/repository@sha256:<hex>.
type Ref struct {
	Host       string
	Repository string
	Digest     string
}

func (r Ref) String() string { return r.Host + "/" + r.Repository + "@" + r.Digest }

// ParseRef reads host/repository@sha256:<hex>. A tag isn't accepted: only a
// digest pins what the supervisor will run.
func ParseRef(s string) (Ref, error) {
	name, digest, ok := strings.Cut(s, "@")
	if !ok || !digestPattern.MatchString(digest) {
		return Ref{}, fmt.Errorf("image %q isn't pinned as host/repository@sha256:<64 hex>", s)
	}
	host, repo, ok := strings.Cut(name, "/")
	if !ok || host == "" || !strings.ContainsAny(host, ".:") || !repoPattern.MatchString(repo) {
		return Ref{}, fmt.Errorf("image %q needs a registry host and a repository", s)
	}
	return Ref{Host: host, Repository: repo, Digest: digest}, nil
}

// Puller fetches from one registry.
type Puller struct {
	// Base is the registry's origin, such as https://ghcr.io.
	Base string
	// Client must refuse redirects to hosts the policy doesn't list; see
	// Client.
	Client *http.Client
	// Token is a read-only registry token, sent as the password when the
	// registry asks for a bearer token. Empty pulls anonymously.
	Token string
	// Arch is the platform to pick from an index; runtime.GOARCH when empty.
	Arch string

	bearer string
}

// Client returns an HTTP client that follows a redirect only to https on one
// of hosts, dropping the registry token on any redirect off the registry's own
// host and port, so a blob store never sees it. Go's own rule keeps it for
// another port on the same host.
func Client(hosts ...string) *http.Client {
	return &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" || !slices.Contains(hosts, req.URL.Hostname()) {
			return fmt.Errorf("redirect to %s is outside the registry policy", req.URL.Redacted())
		}
		if req.URL.Host != via[0].URL.Host {
			req.Header.Del("Authorization")
		}
		return nil
	}}
}

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  *struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
	} `json:"platform,omitempty"`
}

type manifest struct {
	MediaType string       `json:"mediaType"`
	Manifests []descriptor `json:"manifests"`
	Config    *descriptor  `json:"config"`
	Layers    []descriptor `json:"layers"`
}

// Pull writes ref's image into the layout at dir, keeping any blob already
// there whose digest matches, and writes index.json last.
func (p *Puller) Pull(ctx context.Context, ref Ref, dir string) error {
	if err := os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0o755); err != nil {
		return err
	}
	top, mediaType, err := p.manifest(ctx, ref, ref.Digest, dir)
	if err != nil {
		return err
	}
	m := top
	if len(top.Manifests) > 0 {
		pick, err := p.pick(top.Manifests)
		if err != nil {
			return err
		}
		if m, _, err = p.manifest(ctx, ref, pick.Digest, dir); err != nil {
			return err
		}
		if len(m.Manifests) > 0 {
			return fmt.Errorf("manifest %s is another index", pick.Digest)
		}
	}
	if m.Config == nil || len(m.Layers) == 0 || len(m.Layers) > maxLayers {
		return fmt.Errorf("manifest has no config, or %d layers", len(m.Layers))
	}
	var total int64
	for _, d := range append([]descriptor{*m.Config}, m.Layers...) {
		if d.Size < 0 || total+d.Size > MaxImageBytes {
			return fmt.Errorf("image is over %d bytes", MaxImageBytes)
		}
		total += d.Size
		if err := p.blob(ctx, ref, d, dir); err != nil {
			return err
		}
	}
	return writeLayout(dir, descriptor{MediaType: mediaType, Digest: ref.Digest, Size: -1})
}

func (p *Puller) pick(ds []descriptor) (descriptor, error) {
	arch := cmp.Or(p.Arch, runtime.GOARCH)
	var found []descriptor
	for _, d := range ds {
		if d.Platform != nil && d.Platform.OS == "linux" && d.Platform.Architecture == arch &&
			(d.MediaType == mediaOCIManifest || d.MediaType == mediaDockerV2) {
			found = append(found, d)
		}
	}
	if len(found) != 1 {
		return descriptor{}, fmt.Errorf("index has %d manifests for linux/%s, want 1", len(found), arch)
	}
	return found[0], nil
}

// manifest fetches a manifest or index by digest, checks it, keeps it as a
// blob, and decodes it.
func (p *Puller) manifest(ctx context.Context, ref Ref, digest, dir string) (manifest, string, error) {
	var m manifest
	resp, err := p.get(ctx, ref, "manifests/"+digest, strings.Join(manifestTypes, ", "))
	if err != nil {
		return m, "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxJSON+1))
	if err != nil {
		return m, "", fmt.Errorf("manifest %s: %w", digest, err)
	}
	if len(data) > maxJSON {
		return m, "", fmt.Errorf("manifest %s is over %d bytes", digest, maxJSON)
	}
	if got := digestOf(data); got != digest {
		return m, "", fmt.Errorf("registry sent manifest %s for %s", got, digest)
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return m, "", fmt.Errorf("manifest %s: %w", digest, err)
	}
	mediaType := m.MediaType
	if mediaType == "" {
		mediaType, _, _ = strings.Cut(resp.Header.Get("Content-Type"), ";")
	}
	if !slices.Contains(manifestTypes, mediaType) {
		return m, "", fmt.Errorf("manifest %s has media type %q", digest, mediaType)
	}
	return m, mediaType, writeFile(blobPath(dir, digest), data)
}

// blob streams one blob to the layout, refusing it the moment it runs past its
// descriptor's size, and keeps it only if its digest matches.
func (p *Puller) blob(ctx context.Context, ref Ref, d descriptor, dir string) error {
	if !digestPattern.MatchString(d.Digest) {
		return fmt.Errorf("blob digest %q isn't sha256:<64 hex>", d.Digest)
	}
	path := blobPath(dir, d.Digest)
	if ok, err := present(path, d); ok || err != nil {
		return err
	}
	resp, err := p.get(ctx, ref, "blobs/"+d.Digest, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pull-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, d.Size+1))
	if err != nil {
		return fmt.Errorf("blob %s: %w", d.Digest, err)
	}
	if n != d.Size {
		return fmt.Errorf("blob %s is %d bytes or more, its descriptor says %d", d.Digest, n, d.Size)
	}
	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != d.Digest {
		return fmt.Errorf("registry sent blob %s for %s", got, d.Digest)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// get asks the registry for /v2/<repository>/<path>, fetching a bearer token
// first when the registry asks for one.
func (p *Puller) get(ctx context.Context, ref Ref, path, accept string) (*http.Response, error) {
	u := strings.TrimRight(p.Base, "/") + "/v2/" + ref.Repository + "/" + path
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if p.bearer != "" {
			req.Header.Set("Authorization", "Bearer "+p.bearer)
		}
		resp, err := p.Client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusOK {
			return resp, nil
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized || attempt > 0 {
			return nil, fmt.Errorf("registry answered %d for %s", resp.StatusCode, path)
		}
		if err := p.login(ctx, resp.Header.Get("WWW-Authenticate")); err != nil {
			return nil, err
		}
	}
}

// login fetches a bearer token from the realm a 401 named. The realm must be
// on the registry's own host, so the token goes nowhere else.
func (p *Puller) login(ctx context.Context, challenge string) error {
	scheme, params, _ := strings.Cut(challenge, " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return fmt.Errorf("registry wants %q authentication", scheme)
	}
	fields := parseChallenge(params)
	realm, err := url.Parse(fields["realm"])
	if err != nil || realm.Scheme == "" {
		return fmt.Errorf("registry's token realm %q isn't a URL", fields["realm"])
	}
	base, err := url.Parse(p.Base)
	if err != nil {
		return err
	}
	if realm.Scheme != base.Scheme || realm.Host != base.Host {
		return fmt.Errorf("token realm %s isn't on the registry's host", realm.Redacted())
	}
	q := realm.Query()
	for _, k := range []string{"service", "scope"} {
		if v := fields[k]; v != "" {
			q.Set(k, v)
		}
	}
	realm.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return err
	}
	if p.Token != "" {
		req.SetBasicAuth("fount", p.Token)
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registry's token endpoint answered %d", resp.StatusCode)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&tok); err != nil {
		return fmt.Errorf("registry's token: %w", err)
	}
	p.bearer = cmp.Or(tok.Token, tok.AccessToken)
	if p.bearer == "" {
		return errors.New("registry's token endpoint sent no token")
	}
	return nil
}

// parseChallenge reads key="value" pairs. Values here never hold quotes.
func parseChallenge(s string) map[string]string {
	out := map[string]string{}
	for part := range strings.SplitSeq(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok {
			out[strings.ToLower(k)] = strings.Trim(v, `"`)
		}
	}
	return out
}

// Complete reports whether dir holds a finished pull of digest.
func Complete(dir, digest string) bool {
	data, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		return false
	}
	var idx struct{ Manifests []descriptor }
	return json.Unmarshal(data, &idx) == nil && len(idx.Manifests) == 1 && idx.Manifests[0].Digest == digest
}

func writeLayout(dir string, top descriptor) error {
	data, err := os.ReadFile(blobPath(dir, top.Digest))
	if err != nil {
		return err
	}
	top.Size = int64(len(data))
	if err := writeFile(filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`)); err != nil {
		return err
	}
	idx, err := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": mediaOCIIndex, "manifests": []descriptor{top}})
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, "index.json"), idx)
}

func present(path string, d descriptor) (bool, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, d.Size+1))
	if err != nil {
		return false, err
	}
	return n == d.Size && "sha256:"+hex.EncodeToString(h.Sum(nil)) == d.Digest, nil
}

func writeFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func blobPath(dir, digest string) string {
	return filepath.Join(dir, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:"))
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
