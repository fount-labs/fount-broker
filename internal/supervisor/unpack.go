package supervisor

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
)

// UnpackOptions bound what a layer may write.
type UnpackOptions struct {
	// KeepOwners applies each entry's uid and gid, which needs root. Off, every
	// file belongs to the supervisor.
	KeepOwners bool
	// MaxBytes caps the image's unpacked file bytes, 16 GiB if zero.
	MaxBytes int64
	// MaxEntries caps its entries, 1,000,000 if zero.
	MaxEntries int
}

// unpacker applies layers to a tree through an os.Root, so no entry, symlink
// or hardlink can reach outside it, whatever the tar says. Setuid and setgid
// bits, devices, fifos and extended attributes (file capabilities among them)
// are dropped.
type unpacker struct {
	root    *os.Root
	opts    UnpackOptions
	bytes   int64
	entries int
}

func newUnpacker(dir string, opts UnpackOptions) (*unpacker, error) {
	if opts.MaxBytes == 0 {
		opts.MaxBytes = 16 << 30
	}
	if opts.MaxEntries == 0 {
		opts.MaxEntries = 1_000_000
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &unpacker{root: root, opts: opts}, nil
}

func (u *unpacker) close() { u.root.Close() }

// layerFile applies one layer blob and returns the digest of its uncompressed
// tar, the config's diff id for it.
func (u *unpacker) layerFile(blob string, gzipped bool) (string, error) {
	f, err := os.Open(blob)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var r io.Reader = f
	if gzipped {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return "", err
		}
		defer gz.Close()
		gz.Multistream(false)
		r = gz
	}
	h := sha256.New()
	tee := io.TeeReader(r, h)
	if err := u.layer(tee); err != nil {
		return "", err
	}
	// The tar's end padding counts toward the diff id.
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func (u *unpacker) layer(r io.Reader) error {
	tr := tar.NewReader(r)
	// Paths this layer wrote. An opaque whiteout hides only lower layers'
	// entries, whichever order the tar lists them in.
	written := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if u.entries++; u.entries > u.opts.MaxEntries {
			return fmt.Errorf("image has over %d entries", u.opts.MaxEntries)
		}
		if hdr.Size < 0 {
			return fmt.Errorf("%q has size %d", hdr.Name, hdr.Size)
		}
		if u.bytes += hdr.Size; u.bytes > u.opts.MaxBytes {
			return fmt.Errorf("image unpacks to over %d bytes", u.opts.MaxBytes)
		}
		name, err := cleanName(hdr.Name)
		if err != nil {
			return err
		}
		if name == "." {
			continue
		}
		dir, base := path.Dir(name), path.Base(name)
		if base == ".wh..wh..opq" {
			if err := u.opaque(dir, written); err != nil {
				return fmt.Errorf("opaque whiteout %q: %w", hdr.Name, err)
			}
			continue
		}
		if hidden, ok := strings.CutPrefix(base, ".wh."); ok {
			if hidden == "" || hidden == "." || hidden == ".." {
				return fmt.Errorf("whiteout %q", hdr.Name)
			}
			if err := u.root.RemoveAll(path.Join(dir, hidden)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("whiteout %q: %w", hdr.Name, err)
			}
			continue
		}
		if err := u.entry(tr, hdr, name); err != nil {
			return fmt.Errorf("%q: %w", hdr.Name, err)
		}
		for p := name; p != "."; p = path.Dir(p) {
			written[p] = true
		}
	}
}

func (u *unpacker) entry(tr *tar.Reader, hdr *tar.Header, name string) error {
	if dir := path.Dir(name); dir != "." {
		if err := u.root.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	switch hdr.Typeflag {
	case tar.TypeDir:
		if err := u.clear(name, true); err != nil {
			return err
		}
		if err := u.root.Mkdir(name, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		if err := u.root.Chmod(name, mode(hdr)); err != nil {
			return err
		}
		return u.chown(name, hdr, false)
	case tar.TypeReg:
		if err := u.clear(name, false); err != nil {
			return err
		}
		f, err := u.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, tr)
		if err == nil {
			err = f.Chmod(mode(hdr))
		}
		if err == nil && u.opts.KeepOwners {
			err = f.Chown(hdr.Uid, hdr.Gid)
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		return err
	case tar.TypeSymlink:
		if hdr.Linkname == "" || len(hdr.Linkname) > 4096 || strings.ContainsRune(hdr.Linkname, 0) {
			return fmt.Errorf("symlink target %q", hdr.Linkname)
		}
		if err := u.clear(name, false); err != nil {
			return err
		}
		// The link is only text here. Inside the sandbox it resolves within
		// the sandbox's root.
		if err := u.root.Symlink(hdr.Linkname, name); err != nil {
			return err
		}
		return u.chown(name, hdr, true)
	case tar.TypeLink:
		target, err := cleanName(hdr.Linkname)
		if err != nil {
			return err
		}
		fi, err := u.root.Lstat(target)
		if err != nil {
			return fmt.Errorf("hardlink to %q: %w", hdr.Linkname, err)
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("hardlink to %q, which isn't a regular file", hdr.Linkname)
		}
		if target == name {
			return nil
		}
		if err := u.clear(name, false); err != nil {
			return err
		}
		return u.root.Link(target, name)
	case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		// runsc gives the sandbox its own /dev.
		return nil
	default:
		return fmt.Errorf("tar entry type %q", hdr.Typeflag)
	}
}

// clear removes what a lower layer left at name, except a directory that
// stays one.
func (u *unpacker) clear(name string, keepDir bool) error {
	fi, err := u.root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.IsDir() {
		if keepDir {
			return nil
		}
		return u.root.RemoveAll(name)
	}
	return u.root.Remove(name)
}

func (u *unpacker) opaque(dir string, written map[string]bool) error {
	d, err := u.root.Open(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return err
	}
	for _, e := range entries {
		child := path.Join(dir, e.Name())
		if written[child] {
			continue
		}
		if err := u.root.RemoveAll(child); err != nil {
			return err
		}
	}
	return nil
}

func (u *unpacker) chown(name string, hdr *tar.Header, link bool) error {
	if !u.opts.KeepOwners {
		return nil
	}
	if link {
		return u.root.Lchown(name, hdr.Uid, hdr.Gid)
	}
	return u.root.Chown(name, hdr.Uid, hdr.Gid)
}

// mode keeps permission bits and the sticky bit, never setuid or setgid.
func mode(hdr *tar.Header) fs.FileMode {
	m := fs.FileMode(hdr.Mode & 0o777)
	if hdr.Mode&0o1000 != 0 {
		m |= fs.ModeSticky
	}
	return m
}

// cleanName turns a tar entry's name into a path relative to the tree's root,
// refusing any that climbs with "..".
func cleanName(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("entry name %q", name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", fmt.Errorf("entry name %q climbs out with ..", name)
		}
	}
	clean := path.Clean("/" + name)
	if clean == "/" {
		return ".", nil
	}
	return clean[1:], nil
}
