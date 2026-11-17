// Package supervisor starts each Cloud job in its own gVisor sandbox
// (m4-cloud-runners.md §5.1c). It holds no customer data, keys or network: it
// unpacks the closed harness image, whose digest is pinned in its measured
// config, and runs every job under runsc with that image as a read-only root.
package supervisor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
)

// The harness image arrives from the broker, which fetched it and is untrusted
// for this. Nothing is parsed until its digest matches: the manifest's against
// the pinned digest, each layer's and the config's against the manifest.
const (
	maxJSONBlob = 4 << 20
	maxLayers   = 128
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

const (
	mediaOCIIndex      = "application/vnd.oci.image.index.v1+json"
	mediaDockerList    = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaOCIManifest   = "application/vnd.oci.image.manifest.v1+json"
	mediaDockerV2      = "application/vnd.docker.distribution.manifest.v2+json"
	mediaOCIConfig     = "application/vnd.oci.image.config.v1+json"
	mediaDockerConfig  = "application/vnd.docker.container.image.v1+json"
	mediaOCILayer      = "application/vnd.oci.image.layer.v1.tar"
	mediaOCILayerGzip  = "application/vnd.oci.image.layer.v1.tar+gzip"
	mediaDockerLayer   = "application/vnd.docker.image.rootfs.diff.tar"
	mediaDockerLayerGz = "application/vnd.docker.image.rootfs.diff.tar.gzip"
)

// Image is what the supervisor keeps of the harness image's config. User is
// ignored: the sandbox's user is the supervisor's policy, never the image's.
type Image struct {
	Digest     string   `json:"digest"`
	Entrypoint []string `json:"entrypoint"`
	Cmd        []string `json:"cmd"`
	Env        []string `json:"env"`
	WorkingDir string   `json:"working_dir"`
}

type descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Platform    *platform         `json:"platform"`
	Annotations map[string]string `json:"annotations"`
}

type platform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant"`
}

type manifest struct {
	MediaType string       `json:"mediaType"`
	Manifests []descriptor `json:"manifests"`
	Config    *descriptor  `json:"config"`
	Layers    []descriptor `json:"layers"`
}

type imageConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Config       struct {
		Entrypoint []string `json:"Entrypoint"`
		Cmd        []string `json:"Cmd"`
		Env        []string `json:"Env"`
		WorkingDir string   `json:"WorkingDir"`
	} `json:"config"`
	RootFS struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

// Blobs is a folder of blobs named by digest, as in an OCI image layout:
// <dir>/blobs/sha256/<hex>.
type Blobs struct{ Dir string }

func (b Blobs) path(digest string) (string, error) {
	if !digestPattern.MatchString(digest) {
		return "", fmt.Errorf("digest %q isn't sha256:<64 hex>", digest)
	}
	return filepath.Join(b.Dir, "blobs", "sha256", digest[len("sha256:"):]), nil
}

// readJSON reads a small blob whole, checks its digest, and only then decodes
// it. size is the descriptor's, or -1 for the pinned top-level manifest.
func (b Blobs) readJSON(digest string, size int64, v any) error {
	path, err := b.path(digest)
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("blob %s: %w", digest, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxJSONBlob+1))
	if err != nil {
		return fmt.Errorf("blob %s: %w", digest, err)
	}
	if len(data) > maxJSONBlob {
		return fmt.Errorf("blob %s is over %d bytes", digest, maxJSONBlob)
	}
	if size >= 0 && int64(len(data)) != size {
		return fmt.Errorf("blob %s is %d bytes, its descriptor says %d", digest, len(data), size)
	}
	if got := sha256Digest(data); got != digest {
		return fmt.Errorf("blob %s has digest %s", digest, got)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("blob %s: %w", digest, err)
	}
	return nil
}

// verifyFile checks a layer's size and digest before anything reads it as a
// tar.
func (b Blobs) verifyFile(d descriptor) (string, error) {
	path, err := b.path(d.Digest)
	if err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("layer %s: %w", d.Digest, err)
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", fmt.Errorf("layer %s: %w", d.Digest, err)
	}
	if n != d.Size {
		return "", fmt.Errorf("layer %s is %d bytes, its descriptor says %d", d.Digest, n, d.Size)
	}
	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != d.Digest {
		return "", fmt.Errorf("layer %s has digest %s", d.Digest, got)
	}
	return path, nil
}

func sha256Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Unpack checks the image pinned by digest, for linux on this machine's
// architecture, and unpacks its layers into root, which must not exist yet. A
// pinned index resolves to its manifest for this platform, which is checked
// against the digest the index names.
func Unpack(blobs Blobs, digest, root string, opts UnpackOptions) (*Image, error) {
	var m manifest
	if err := blobs.readJSON(digest, -1, &m); err != nil {
		return nil, fmt.Errorf("pinned image: %w", err)
	}
	if isIndex(m) {
		d, err := pickPlatform(m.Manifests)
		if err != nil {
			return nil, err
		}
		m = manifest{}
		if err := blobs.readJSON(d.Digest, d.Size, &m); err != nil {
			return nil, fmt.Errorf("platform manifest: %w", err)
		}
		if isIndex(m) {
			return nil, errors.New("the platform manifest is another index")
		}
	}
	if m.MediaType != "" && m.MediaType != mediaOCIManifest && m.MediaType != mediaDockerV2 {
		return nil, fmt.Errorf("manifest media type %q", m.MediaType)
	}
	if m.Config == nil {
		return nil, errors.New("manifest has no config")
	}
	if m.Config.MediaType != mediaOCIConfig && m.Config.MediaType != mediaDockerConfig {
		return nil, fmt.Errorf("config media type %q", m.Config.MediaType)
	}
	if len(m.Layers) == 0 || len(m.Layers) > maxLayers {
		return nil, fmt.Errorf("manifest has %d layers", len(m.Layers))
	}
	var cfg imageConfig
	if err := blobs.readJSON(m.Config.Digest, m.Config.Size, &cfg); err != nil {
		return nil, fmt.Errorf("image config: %w", err)
	}
	if cfg.OS != "linux" || cfg.Architecture != runtime.GOARCH {
		return nil, fmt.Errorf("image is %s/%s, this supervisor runs linux/%s", cfg.OS, cfg.Architecture, runtime.GOARCH)
	}
	if cfg.RootFS.Type != "layers" || len(cfg.RootFS.DiffIDs) != len(m.Layers) {
		return nil, fmt.Errorf("config lists %d diff ids for %d layers", len(cfg.RootFS.DiffIDs), len(m.Layers))
	}
	if len(cfg.Config.Entrypoint) == 0 {
		return nil, errors.New("image has no entrypoint")
	}

	// Every blob is checked before the first one is unpacked.
	paths := make([]string, len(m.Layers))
	for i, l := range m.Layers {
		if !digestPattern.MatchString(cfg.RootFS.DiffIDs[i]) {
			return nil, fmt.Errorf("diff id %q", cfg.RootFS.DiffIDs[i])
		}
		var err error
		if paths[i], err = blobs.verifyFile(l); err != nil {
			return nil, err
		}
	}

	if err := os.Mkdir(root, 0o755); err != nil {
		return nil, fmt.Errorf("unpack into %s: %w", root, err)
	}
	u, err := newUnpacker(root, opts)
	if err != nil {
		return nil, err
	}
	defer u.close()
	for i, l := range m.Layers {
		gzipped := false
		switch l.MediaType {
		case mediaOCILayer, mediaDockerLayer:
		case mediaOCILayerGzip, mediaDockerLayerGz:
			gzipped = true
		default:
			return nil, fmt.Errorf("layer %s media type %q", l.Digest, l.MediaType)
		}
		diffID, err := u.layerFile(paths[i], gzipped)
		if err != nil {
			return nil, fmt.Errorf("layer %d (%s): %w", i, l.Digest, err)
		}
		if diffID != cfg.RootFS.DiffIDs[i] {
			return nil, fmt.Errorf("layer %d (%s) unpacks to %s, the config says %s", i, l.Digest, diffID, cfg.RootFS.DiffIDs[i])
		}
	}
	return &Image{
		Digest:     digest,
		Entrypoint: cfg.Config.Entrypoint,
		Cmd:        cfg.Config.Cmd,
		Env:        cfg.Config.Env,
		WorkingDir: cfg.Config.WorkingDir,
	}, nil
}

func isIndex(m manifest) bool {
	return m.MediaType == mediaOCIIndex || m.MediaType == mediaDockerList || (m.MediaType == "" && m.Manifests != nil)
}

func pickPlatform(ds []descriptor) (descriptor, error) {
	var found []descriptor
	for _, d := range ds {
		if d.Platform == nil || d.Platform.OS != "linux" || d.Platform.Architecture != runtime.GOARCH {
			continue
		}
		if d.MediaType != mediaOCIManifest && d.MediaType != mediaDockerV2 {
			continue
		}
		found = append(found, d)
	}
	if len(found) != 1 {
		return descriptor{}, fmt.Errorf("index has %d manifests for linux/%s, want 1", len(found), runtime.GOARCH)
	}
	return found[0], nil
}
