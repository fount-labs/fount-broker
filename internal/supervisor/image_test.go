package supervisor

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type entry struct {
	name, body, link string
	typ              byte
	mode             int64
}

func file(name, body string) entry {
	return entry{name: name, body: body, typ: tar.TypeReg, mode: 0o644}
}
func dir(name string) entry { return entry{name: name, typ: tar.TypeDir, mode: 0o755} }
func symlink(name, to string) entry {
	return entry{name: name, link: to, typ: tar.TypeSymlink, mode: 0o777}
}
func hardlink(name, to string) entry {
	return entry{name: name, link: to, typ: tar.TypeLink, mode: 0o644}
}

func tarOf(t testing.TB, entries ...entry) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: e.mode, Linkname: e.link, Size: int64(len(e.body))}
		if e.typ != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	return buf.Bytes()
}

func gzipped(data []byte) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write(data)
	gz.Close()
	return buf.Bytes()
}

// layout is an OCI image layout under construction.
type layout struct {
	t   testing.TB
	dir string
}

func newLayout(t testing.TB) *layout {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0o755)
	return &layout{t, dir}
}

func (l *layout) put(data []byte) descriptor {
	d := sha256Digest(data)
	if err := os.WriteFile(filepath.Join(l.dir, "blobs", "sha256", d[7:]), data, 0o644); err != nil {
		l.t.Fatal(err)
	}
	return descriptor{Digest: d, Size: int64(len(data))}
}

func (l *layout) putJSON(v any) descriptor {
	data, err := json.Marshal(v)
	if err != nil {
		l.t.Fatal(err)
	}
	return l.put(data)
}

type layer struct {
	tar  []byte
	gzip bool
}

// image writes a config and manifest for the layers and returns the
// manifest's descriptor.
func (l *layout) image(layers ...layer) descriptor {
	cfg := map[string]any{
		"architecture": runtime.GOARCH,
		"os":           "linux",
		"config":       map[string]any{"Entrypoint": []string{"/bin/runner"}, "Env": []string{"PATH=/bin"}},
		"rootfs":       map[string]any{"type": "layers", "diff_ids": []string{}},
	}
	var descs []descriptor
	var diffIDs []string
	for _, ly := range layers {
		diffIDs = append(diffIDs, sha256Digest(ly.tar))
		if ly.gzip {
			d := l.put(gzipped(ly.tar))
			d.MediaType = mediaOCILayerGzip
			descs = append(descs, d)
		} else {
			d := l.put(ly.tar)
			d.MediaType = mediaOCILayer
			descs = append(descs, d)
		}
	}
	cfg["rootfs"].(map[string]any)["diff_ids"] = diffIDs
	c := l.putJSON(cfg)
	c.MediaType = mediaOCIConfig
	m := l.putJSON(map[string]any{"schemaVersion": 2, "mediaType": mediaOCIManifest, "config": c, "layers": descs})
	m.MediaType = mediaOCIManifest
	return m
}

func unpackTo(t *testing.T, l *layout, digest string) (string, *Image, error) {
	root := filepath.Join(t.TempDir(), "rootfs")
	img, err := Unpack(Blobs{Dir: l.dir}, digest, root, UnpackOptions{})
	return root, img, err
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestUnpackAppliesLayersInOrder(t *testing.T) {
	l := newLayout(t)
	setuid := file("bin/su", "su")
	setuid.mode = 0o4755
	sticky := dir("tmp")
	sticky.mode = 0o1777
	m := l.image(
		layer{tarOf(t, dir("etc"), file("etc/a", "lower a"), file("etc/gone", "x"), dir("opt"),
			file("opt/old", "old"), file("bin/runner", "v1"), setuid, sticky), true},
		layer{tarOf(t, file("etc/a", "upper a"), file("etc/.wh.gone", ""), file("opt/new", "new"),
			file("opt/.wh..wh..opq", ""), symlink("etc/link", "a"), hardlink("etc/hard", "etc/a"),
			symlink("usr", "/opt")), false},
	)
	root, img, err := unpackTo(t, l, m.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(root, "etc/a")); got != "upper a" {
		t.Errorf("etc/a = %q", got)
	}
	if got := read(t, filepath.Join(root, "etc/hard")); got != "upper a" {
		t.Errorf("etc/hard = %q", got)
	}
	if got, _ := os.Readlink(filepath.Join(root, "etc/link")); got != "a" {
		t.Errorf("etc/link -> %q", got)
	}
	if got, _ := os.Readlink(filepath.Join(root, "usr")); got != "/opt" {
		t.Errorf("usr -> %q", got)
	}
	for _, gone := range []string{"etc/gone", "opt/old"} {
		if _, err := os.Lstat(filepath.Join(root, gone)); !os.IsNotExist(err) {
			t.Errorf("%s survived its whiteout: %v", gone, err)
		}
	}
	if got := read(t, filepath.Join(root, "opt/new")); got != "new" {
		t.Errorf("the opaque whiteout hid this layer's own opt/new: %q", got)
	}
	fi, _ := os.Stat(filepath.Join(root, "bin/su"))
	if fi.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 || fi.Mode().Perm() != 0o755 {
		t.Errorf("bin/su mode %v, want 0755 without setuid", fi.Mode())
	}
	if fi, _ := os.Stat(filepath.Join(root, "tmp")); fi.Mode()&os.ModeSticky == 0 {
		t.Errorf("tmp lost its sticky bit: %v", fi.Mode())
	}
	if img.Digest != m.Digest || img.Entrypoint[0] != "/bin/runner" || img.Env[0] != "PATH=/bin" {
		t.Errorf("image = %+v", img)
	}
}

func TestUnpackResolvesAnIndexToThisPlatform(t *testing.T) {
	l := newLayout(t)
	m := l.image(layer{tarOf(t, file("bin/runner", "x")), false})
	m.Platform = &platform{OS: "linux", Architecture: runtime.GOARCH}
	other := descriptor{MediaType: mediaOCIManifest, Digest: sha256Digest([]byte("other")), Size: 5,
		Platform: &platform{OS: "linux", Architecture: "s390x"}}
	attestation := descriptor{MediaType: mediaOCIManifest, Digest: sha256Digest([]byte("att")), Size: 3,
		Platform: &platform{OS: "unknown", Architecture: "unknown"}}
	idx := l.putJSON(map[string]any{"schemaVersion": 2, "mediaType": mediaOCIIndex,
		"manifests": []descriptor{other, m, attestation}})
	root, _, err := unpackTo(t, l, idx.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(root, "bin/runner")); got != "x" {
		t.Errorf("bin/runner = %q", got)
	}
}

func TestUnpackRefusesBlobsThatDontMatch(t *testing.T) {
	cases := map[string]func(l *layout, m descriptor) string{
		"pinned digest names another manifest": func(l *layout, m descriptor) string {
			return sha256Digest([]byte("not it"))
		},
		"tampered layer": func(l *layout, m descriptor) string {
			var man manifest
			l.read(m.Digest, &man)
			p := filepath.Join(l.dir, "blobs", "sha256", man.Layers[0].Digest[7:])
			data, _ := os.ReadFile(p)
			data[len(data)/2] ^= 1
			os.WriteFile(p, data, 0o644)
			return m.Digest
		},
		"tampered manifest": func(l *layout, m descriptor) string {
			p := filepath.Join(l.dir, "blobs", "sha256", m.Digest[7:])
			data, _ := os.ReadFile(p)
			os.WriteFile(p, bytes.Replace(data, []byte(`"schemaVersion":2`), []byte(`"schemaVersion":3`), 1), 0o644)
			return m.Digest
		},
		"not a digest": func(l *layout, m descriptor) string { return "sha256:../../etc/passwd" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			l := newLayout(t)
			m := l.image(layer{tarOf(t, file("bin/runner", "x")), true})
			root, _, err := unpackTo(t, l, mutate(l, m))
			if err == nil {
				t.Fatal("unpacked")
			}
			if _, statErr := os.Lstat(root); !os.IsNotExist(statErr) {
				t.Errorf("made %s before the blobs were checked (%v)", root, err)
			}
		})
	}
}

func TestUnpackRefusesADiffIDMismatch(t *testing.T) {
	l := newLayout(t)
	ly := tarOf(t, file("bin/runner", "x"))
	cfg := map[string]any{"architecture": runtime.GOARCH, "os": "linux",
		"config": map[string]any{"Entrypoint": []string{"/bin/runner"}},
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{sha256Digest([]byte("other"))}}}
	c := l.putJSON(cfg)
	c.MediaType = mediaOCIConfig
	d := l.put(ly)
	d.MediaType = mediaOCILayer
	m := l.putJSON(map[string]any{"schemaVersion": 2, "mediaType": mediaOCIManifest, "config": c, "layers": []descriptor{d}})
	if _, _, err := unpackTo(t, l, m.Digest); err == nil || !strings.Contains(err.Error(), "unpacks to") {
		t.Fatalf("err = %v", err)
	}
}

func TestUnpackStaysInsideTheTree(t *testing.T) {
	cases := map[string][]entry{
		"dot-dot name":            {file("../outside/x", "x")},
		"absolute dot-dot":        {file("/../outside/x", "x")},
		"through a symlink":       {symlink("evil", "../outside"), file("evil/x", "x")},
		"through an absolute one": {symlink("evil", "/"), file("evil/outside/x", "x")},
		"hardlink out":            {hardlink("x", "../outside/secret")},
		"dir through a symlink":   {symlink("evil", "../outside"), dir("evil/d")},
		"symlink replaced by dir": {symlink("evil", "../outside"), dir("evil"), file("evil/x", "x")},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			outside := filepath.Join(base, "outside")
			os.Mkdir(outside, 0o755)
			os.WriteFile(filepath.Join(outside, "secret"), []byte("s"), 0o644)
			root := filepath.Join(base, "rootfs")
			os.Mkdir(root, 0o755)
			u, err := newUnpacker(root, UnpackOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer u.close()
			err = u.layer(bytes.NewReader(tarOf(t, entries...)))
			if name != "symlink replaced by dir" && err == nil {
				t.Error("layer applied")
			}
			t.Log(err)
			assertOnly(t, outside, "secret")
		})
	}
}

func assertOnly(t testing.TB, dir string, names ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(names) {
		var got []string
		for _, e := range entries {
			got = append(got, e.Name())
		}
		t.Fatalf("%s holds %v, want %v", dir, got, names)
	}
}

func (l *layout) read(digest string, v any) {
	if err := (Blobs{Dir: l.dir}).readJSON(digest, -1, v); err != nil {
		l.t.Fatal(err)
	}
}

// FuzzLayer feeds arbitrary tars to the unpacker: whatever they say, nothing
// lands outside the tree.
func FuzzLayer(f *testing.F) {
	f.Add(tarOf(f, symlink("evil", "../outside"), file("evil/x", "x")))
	f.Add(tarOf(f, dir("a"), file("a/.wh..wh..opq", ""), hardlink("b", "a/c"), file("a/c", "c")))
	f.Add(tarOf(f, symlink("a", "/"), symlink("a/b", "../.."), hardlink("c", "a/b/outside/secret")))
	f.Fuzz(func(t *testing.T, data []byte) {
		base := t.TempDir()
		outside := filepath.Join(base, "outside")
		os.Mkdir(outside, 0o755)
		os.WriteFile(filepath.Join(outside, "secret"), []byte("s"), 0o644)
		root := filepath.Join(base, "rootfs")
		os.Mkdir(root, 0o755)
		u, err := newUnpacker(root, UnpackOptions{MaxBytes: 1 << 20, MaxEntries: 1000})
		if err != nil {
			t.Fatal(err)
		}
		defer u.close()
		u.layer(bytes.NewReader(data))
		assertOnly(t, outside, "secret")
		assertOnly(t, base, "outside", "rootfs")
		if got, _ := os.ReadFile(filepath.Join(outside, "secret")); string(got) != "s" {
			t.Fatalf("outside/secret = %q", got)
		}
	})
}
