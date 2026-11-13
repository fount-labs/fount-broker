package coordinator

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// A worker's tree has four parts. Only "root/" is the worker root the agent sees
// (m4-cloud-runners.md §5.5); the rest are kept for the runner or the app.
const (
	prefixRoot  = "root/"
	prefixFount = "fount/" // the workspace's .fount folder: sessions and transcripts
	prefixIndex = "index/" // the kept index (§5.5), opaque
	prefixJobs  = "jobs/"  // per job: the runner's events and stderr, and proposed file versions
)

const fountDir = ".fount"

// Folders are open to all because the runner image runs as its own user; the
// job's parent folder is private to the coordinator.
const (
	dirMode  = 0o777
	fileMode = 0o666
)

// materialize writes a worker's tree into a job's folders and returns the hash of
// each root file it wrote, so collect can tell what the job changed.
func materialize(t *Tree, dirs JobDirs) (map[string]string, error) {
	given := map[string]string{}
	for _, d := range []string{dirs.Workspace, dirs.Index, dirs.Data} {
		if err := os.MkdirAll(d, dirMode); err != nil {
			return nil, err
		}
		if err := os.Chmod(d, dirMode); err != nil {
			return nil, err
		}
	}
	place := func(path, dir, rel string) error {
		data, err := t.Read(path)
		if err != nil {
			return err
		}
		return writeInto(dir, rel, data)
	}
	for _, p := range t.List(prefixRoot) {
		rel := strings.TrimPrefix(p, prefixRoot)
		if err := place(p, dirs.Workspace, rel); err != nil {
			return nil, err
		}
		given[rel], _ = t.Hash(p)
	}
	for _, p := range t.List(prefixFount) {
		if err := place(p, filepath.Join(dirs.Workspace, fountDir), strings.TrimPrefix(p, prefixFount)); err != nil {
			return nil, err
		}
	}
	for _, p := range t.List(prefixIndex) {
		if err := place(p, dirs.Index, strings.TrimPrefix(p, prefixIndex)); err != nil {
			return nil, err
		}
	}
	return given, nil
}

func writeInto(dir, rel string, data []byte) error {
	full := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), dirMode); err != nil {
		return err
	}
	return os.WriteFile(full, data, fileMode)
}

// Results is what a finished job adds to its worker's tree.
type Results struct {
	// Writes maps tree paths to their new contents.
	Writes map[string][]byte
	// Index is the runner's index, which replaces the kept one whole.
	Index map[string][]byte
	// Dropped lists files the runner wrote where a job may not.
	Dropped []string
}

// Limits on what one job can hand back, so a runner can't fill the coordinator's
// memory or the worker's storage.
const (
	maxResultFiles = 20000
	maxResultBytes = 2 << 30
	maxFileBytes   = 512 << 20
)

// collect reads back what a job left and keeps only what a job may write
// (§5.5): the thread's outputs/<job id>/, the workspace's .fount folder, changes
// to files/ as proposals, and the index. scratch/ is thrown away. Anything else
// the runner changed or added is dropped and counted.
func collect(dirs JobDirs, given map[string]string, threadID, jobID string) (*Results, error) {
	r := &Results{Writes: map[string][]byte{}, Index: map[string][]byte{}}
	budget := &budget{}
	outputs := "threads/" + threadID + "/outputs/" + jobID + "/"
	err := walkFiles(dirs.Workspace, budget, func(rel string, data []byte) {
		switch {
		case strings.HasPrefix(rel, fountDir+"/"):
			r.Writes[prefixFount+strings.TrimPrefix(rel, fountDir+"/")] = data
		case strings.HasPrefix(rel, outputs):
			if _, existed := given[rel]; !existed {
				r.Writes[prefixRoot+rel] = data
			}
		case strings.HasPrefix(rel, "scratch/"):
		case given[rel] == hashOf(data):
		case strings.HasPrefix(rel, "files/"):
			r.Writes[prefixJobs+jobID+"/proposed/"+rel] = data
		default:
			r.Dropped = append(r.Dropped, rel)
		}
	}, &r.Dropped)
	if err != nil {
		return nil, err
	}
	err = walkFiles(dirs.Index, budget, func(rel string, data []byte) { r.Index[rel] = data }, &r.Dropped)
	return r, err
}

type budget struct{ files, bytes int64 }

// walkFiles calls keep for each regular file under dir, by its slash path.
// Links, devices and anything else that isn't a plain file are never followed
// or read: a runner could point one at the coordinator's own files.
func walkFiles(dir string, b *budget, keep func(rel string, data []byte), dropped *[]string) error {
	return filepath.WalkDir(dir, func(full string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, full)
		if err != nil || rel == "." {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() || checkPath(rel) != nil {
			*dropped = append(*dropped, rel)
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		b.files++
		b.bytes += info.Size()
		if b.files > maxResultFiles || b.bytes > maxResultBytes || info.Size() > maxFileBytes {
			return fmt.Errorf("the job left more than its limits allow (%d files, %d bytes, or a file over %d bytes)", maxResultFiles, maxResultBytes, maxFileBytes)
		}
		data, err := readRegular(full)
		if err != nil {
			return err
		}
		keep(rel, data)
		return nil
	})
}

// readRegular opens without following a final link, in case the file was
// swapped for one after the walk saw it. A runner that is still running could
// do that; the coordinator collects only after it exits.
func readRegular(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a plain file", path)
	}
	data := make([]byte, info.Size())
	if _, err := io.ReadFull(f, data); err != nil {
		return nil, err
	}
	return data, nil
}

func hashOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
