package filetree

import (
	"archive/tar"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, path, data string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
}

func TestRoundTripKeepsPlainFilesOnly(t *testing.T) {
	src := t.TempDir()
	write(t, filepath.Join(src, "files", "a.md"), "a", 0o666)
	write(t, filepath.Join(src, "bin", "run.sh"), "#!/bin/sh", 0o700)
	write(t, filepath.Join(src, ".fount", "s.json"), "{}", 0o600)
	os.MkdirAll(filepath.Join(src, "empty"), 0o700)
	outside := t.TempDir()
	write(t, filepath.Join(outside, "secret"), "s", 0o600)
	os.Symlink(filepath.Join(outside, "secret"), filepath.Join(src, "files", "link"))
	os.Symlink(outside, filepath.Join(src, "dirlink"))
	old := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	os.Chtimes(filepath.Join(src, "files", "a.md"), old, old)

	var buf bytes.Buffer
	if err := Pack(src, &buf, Limits{}); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	if _, err := Extract(&buf, dst, Limits{}, nil); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	filepath.WalkDir(dst, func(p string, d fs.DirEntry, err error) error {
		rel, _ := filepath.Rel(dst, p)
		info, _ := d.Info()
		got[rel] = info.Mode().String()
		return nil
	})
	want := map[string]string{
		".": got["."], "files": "drwxr-xr-x", "files/a.md": "-rw-r--r--", "bin": "drwxr-xr-x",
		"bin/run.sh": "-rwxr-xr-x", ".fount": "drwxr-xr-x", ".fount/s.json": "-rw-r--r--", "empty": "drwxr-xr-x",
	}
	if len(got) != len(want) {
		t.Errorf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
	if info, err := os.Stat(filepath.Join(dst, "files", "a.md")); err != nil || !info.ModTime().Equal(old) {
		t.Errorf("mtime %v", info.ModTime())
	}
}

type entry struct {
	name, body, link string
	flag             byte
}

func tarOf(t testing.TB, entries ...entry) *bytes.Buffer {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Typeflag: e.flag, Mode: 0o644, Size: int64(len(e.body)), Linkname: e.link}
		if e.flag != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(e.body))
	}
	tw.Close()
	return &buf
}

func TestExtractStaysInsideTheTree(t *testing.T) {
	cases := map[string][]entry{
		"dot-dot":             {{name: "../x", body: "x", flag: tar.TypeReg}},
		"nested dot-dot":      {{name: "a/../../x", body: "x", flag: tar.TypeReg}},
		"absolute":            {{name: "/etc/x", body: "x", flag: tar.TypeReg}},
		"file twice":          {{name: "a", body: "1", flag: tar.TypeReg}, {name: "a", body: "2", flag: tar.TypeReg}},
		"file over a dir":     {{name: "a/", flag: tar.TypeDir}, {name: "a", body: "x", flag: tar.TypeReg}},
		"dir through a file":  {{name: "a", body: "x", flag: tar.TypeReg}, {name: "a/b", body: "x", flag: tar.TypeReg}},
		"file names the root": {{name: ".", body: "x", flag: tar.TypeReg}},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			dst := filepath.Join(base, "tree")
			os.Mkdir(dst, 0o755)
			buf := tarOf(t, entries...)
			if _, err := Extract(buf, dst, Limits{}, nil); err == nil {
				t.Fatal("extracted")
			} else {
				t.Log(err)
			}
			assertOnly(t, base, "tree")
		})
	}
}

func TestExtractSkipsLinksAndDevices(t *testing.T) {
	base := t.TempDir()
	dst := filepath.Join(base, "tree")
	os.Mkdir(dst, 0o755)
	buf := tarOf(t,
		entry{name: "s", link: "/etc/passwd", flag: tar.TypeSymlink},
		entry{name: "up", link: "..", flag: tar.TypeSymlink},
		entry{name: "h", link: "../x", flag: tar.TypeLink},
		entry{name: "dev", flag: tar.TypeChar},
		entry{name: "up/x", body: "x", flag: tar.TypeReg},
	)
	skipped, err := Extract(buf, dst, Limits{}, nil)
	if err != nil || skipped != 4 {
		t.Fatalf("skipped %d, %v", skipped, err)
	}
	if data, err := os.ReadFile(filepath.Join(dst, "up", "x")); err != nil || string(data) != "x" {
		t.Errorf("up/x: %q %v", data, err)
	}
	assertOnly(t, base, "tree")
}

func TestLimits(t *testing.T) {
	big := entry{name: "big", body: strings.Repeat("x", 100), flag: tar.TypeReg}
	small := entry{name: "s", body: "x", flag: tar.TypeReg}
	for name, c := range map[string]struct {
		lim     Limits
		entries []entry
	}{
		"file":    {Limits{MaxFileBytes: 99}, []entry{big}},
		"bytes":   {Limits{MaxBytes: 150}, []entry{big, {name: "big2", body: big.body, flag: tar.TypeReg}}},
		"entries": {Limits{MaxEntries: 2}, []entry{small, {name: "t", flag: tar.TypeDir}, {name: "u", flag: tar.TypeDir}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Extract(tarOf(t, c.entries...), t.TempDir(), c.lim, nil); err == nil {
				t.Error("extract went over")
			}
			src := t.TempDir()
			Extract(tarOf(t, c.entries...), src, Limits{}, nil)
			var buf bytes.Buffer
			if err := Pack(src, &buf, c.lim); err == nil {
				t.Error("pack went over")
			}
		})
	}
	dst := t.TempDir()
	write(t, filepath.Join(dst, "x"), "x", 0o644)
	if _, err := Extract(tarOf(t, small), dst, Limits{}, nil); err == nil {
		t.Error("extracted into a folder that isn't empty")
	}
}

// assertOnly checks base holds nothing but the named entries, and that the
// tree holds no links.
func assertOnly(t *testing.T, base string, names ...string) {
	t.Helper()
	got, _ := os.ReadDir(base)
	if len(got) != len(names) {
		t.Errorf("%s holds %v", base, got)
	}
	filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if d != nil && d.Type()&fs.ModeSymlink != 0 {
			t.Errorf("link %s", p)
		}
		return nil
	})
}

func FuzzExtract(f *testing.F) {
	f.Add(tarOf(f, entry{name: "a/b", body: "x", flag: tar.TypeReg}).Bytes())
	f.Add(tarOf(f, entry{name: "a", link: "..", flag: tar.TypeSymlink}, entry{name: "a/x", body: "x", flag: tar.TypeReg}).Bytes())
	f.Add(tarOf(f, entry{name: "../x", body: "x", flag: tar.TypeReg}).Bytes())
	f.Fuzz(func(t *testing.T, data []byte) {
		base := t.TempDir()
		dst := filepath.Join(base, "tree")
		os.Mkdir(dst, 0o755)
		Extract(bytes.NewReader(data), dst, Limits{MaxBytes: 1 << 20, MaxEntries: 200}, nil)
		assertOnly(t, base, "tree")
	})
}
