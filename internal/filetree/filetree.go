// Package filetree moves a folder of plain files as a tar stream: a Cloud job's
// workspace and index on their way into the runner enclave, and back out once
// the job has ended (m4-cloud-runners.md §5.1c).
//
// Only directories and regular files travel. Pack leaves out links, devices and
// anything else, and never follows a link; Extract skips them. Extract writes
// through an os.Root into a folder it requires to be empty, so no name in the
// stream reaches outside it, and it never creates a link for a later entry to
// write through. The stream coming back has been in a job's hands, so both ends
// cap its size.
package filetree

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"syscall"
	"time"
)

// Limits caps one tree. Zero fields take the defaults.
type Limits struct {
	MaxBytes     int64
	MaxFileBytes int64
	MaxEntries   int
}

// The coordinator's own caps on what one job hands back.
const (
	defaultMaxBytes     = 2 << 30
	defaultMaxFileBytes = 512 << 20
	defaultMaxEntries   = 20000
)

func (l Limits) orDefaults() Limits {
	if l.MaxBytes == 0 {
		l.MaxBytes = defaultMaxBytes
	}
	if l.MaxFileBytes == 0 {
		l.MaxFileBytes = defaultMaxFileBytes
	}
	if l.MaxEntries == 0 {
		l.MaxEntries = defaultMaxEntries
	}
	return l
}

var ErrTooLarge = errors.New("tree is over its limit")

// Pack writes dir's directories and regular files to w as a tar stream.
func Pack(dir string, w io.Writer, lim Limits) error {
	lim = lim.orDefaults()
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	tw := tar.NewWriter(w)
	var bytes int64
	entries := 0
	err = fs.WalkDir(root.FS(), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name == "." || !(d.IsDir() || d.Type().IsRegular()) {
			return nil
		}
		if entries++; entries > lim.MaxEntries {
			return fmt.Errorf("%w: more than %d entries", ErrTooLarge, lim.MaxEntries)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: name + "/", Mode: 0o755, ModTime: info.ModTime()})
		}
		f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		if info, err = f.Stat(); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		size := info.Size()
		if size > lim.MaxFileBytes || bytes+size > lim.MaxBytes {
			return fmt.Errorf("%w: %s is %d bytes", ErrTooLarge, name, size)
		}
		bytes += size
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: fileMode(info.Mode()), Size: size, ModTime: info.ModTime()}); err != nil {
			return err
		}
		if _, err := io.CopyN(tw, f, size); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return tw.Close()
}

// Owner is who extracted entries belong to. Nil leaves them to the caller.
type Owner struct{ UID, GID int }

// Extract writes the stream's directories and regular files into dir, which
// must exist and be empty, and returns how many other entries it skipped.
func Extract(r io.Reader, dir string, lim Limits, owner *Owner) (skipped int, err error) {
	lim = lim.orDefaults()
	if names, err := os.ReadDir(dir); err != nil || len(names) > 0 {
		if err == nil {
			err = fmt.Errorf("%s isn't empty", dir)
		}
		return 0, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	tr := tar.NewReader(r)
	var bytes int64
	entries := 0
	var dirTimes []func() error
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return skipped, err
		}
		if entries++; entries > lim.MaxEntries {
			return skipped, fmt.Errorf("%w: more than %d entries", ErrTooLarge, lim.MaxEntries)
		}
		name, err := cleanName(h.Name)
		if err != nil {
			return skipped, err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if name == "." {
				continue
			}
			if err := mkdirs(root, name, owner); err != nil {
				return skipped, err
			}
			mtime := h.ModTime
			dirTimes = append(dirTimes, func() error { return root.Chtimes(name, mtime, mtime) })
		case tar.TypeReg:
			if name == "." {
				return skipped, errors.New("a file names the tree's root")
			}
			if h.Size < 0 || h.Size > lim.MaxFileBytes || bytes+h.Size > lim.MaxBytes {
				return skipped, fmt.Errorf("%w: %s is %d bytes", ErrTooLarge, name, h.Size)
			}
			bytes += h.Size
			if err := writeFile(root, name, h, tr, owner); err != nil {
				return skipped, err
			}
		default:
			skipped++
		}
	}
	// Last, since writing into a directory moves its time.
	for _, set := range dirTimes {
		if err := set(); err != nil {
			return skipped, err
		}
	}
	return skipped, nil
}

func mkdirs(root *os.Root, name string, owner *Owner) error {
	parts := strings.Split(name, "/")
	for i := range parts {
		sub := strings.Join(parts[:i+1], "/")
		err := root.Mkdir(sub, 0o755)
		if errors.Is(err, fs.ErrExist) {
			if info, err := root.Lstat(sub); err != nil || !info.IsDir() {
				return fmt.Errorf("%s: a file stands where a directory goes", sub)
			}
			continue
		}
		if err != nil {
			return err
		}
		if owner != nil {
			if err := root.Lchown(sub, owner.UID, owner.GID); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeFile(root *os.Root, name string, h *tar.Header, r io.Reader, owner *Owner) error {
	if dir := path.Dir(name); dir != "." {
		if err := mkdirs(root, dir, owner); err != nil {
			return err
		}
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.CopyN(f, r, h.Size); err != nil {
		f.Close()
		return fmt.Errorf("%s: %w", name, err)
	}
	if owner != nil {
		if err := f.Chown(owner.UID, owner.GID); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Chmod(os.FileMode(fileMode(os.FileMode(h.Mode)))); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return root.Chtimes(name, time.Time{}, h.ModTime)
}

// fileMode keeps only whether a file is executable.
func fileMode(m os.FileMode) int64 {
	if m&0o111 != 0 {
		return 0o755
	}
	return 0o644
}

// cleanName turns an entry's name into a path relative to the tree, refusing
// absolute names and any that climb with "..". The root is ".".
func cleanName(name string) (string, error) {
	if strings.ContainsRune(name, 0) || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("entry %q isn't a relative name", name)
	}
	for part := range strings.SplitSeq(name, "/") {
		if part == ".." {
			return "", fmt.Errorf("entry %q climbs out with ..", name)
		}
	}
	return path.Clean(name), nil
}
