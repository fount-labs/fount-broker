package coordinator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// A worker's tree has five parts. Only "root/" is the worker root the agent sees
// (m4-cloud-runners.md §5.5); the rest are kept for the runner or the app, and
// "record/" (thread.go) only for the app: no job is given it.
const (
	prefixRoot  = "root/"
	prefixFount = "fount/" // the workspace's .fount folder: sessions and transcripts
	prefixIndex = "index/" // the kept index (§5.5), opaque
	prefixJobs  = "jobs/"  // per job: the runner's events and stderr, proposed file versions, and its outbox
	// pathIndexed is rootDigest of the files the kept index was built from.
	pathIndexed = "indexed"
)

const fountDir = ".fount"

// Folders are open to all because the runner image runs as its own user; the
// job's parent folder is private to the coordinator.
const (
	dirMode  = 0o777
	fileMode = 0o666
)

// The worker root's folders (§5.5): the worker's Files, the reply's files, and
// a job's scratch space. outbox/ and scratch/ are never kept in the tree, so
// every job starts with them empty.
const (
	dirFiles   = "files/"
	dirOutbox  = "outbox/"
	dirScratch = "scratch/"
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
	for _, d := range []string{dirFiles, dirOutbox, dirScratch} {
		if err := os.MkdirAll(filepath.Join(dirs.Workspace, d), dirMode); err != nil {
			return nil, err
		}
	}
	return given, nil
}

// writeListings writes threads/index.md and each thread's thread.md into an
// agent job's workspace, from the thread records, and adds them to given.
// They are never kept, so they can't go stale; a change a job makes to them
// is dropped as any input's is.
func writeListings(t *Tree, workspace string, given map[string]string) error {
	for rel, data := range threadListings(t) {
		if err := writeInto(workspace, rel, data); err != nil {
			return err
		}
		given[rel] = hashOf(data)
	}
	return nil
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
	// Index, from the index step only, replaces the kept index whole. Nil
	// keeps it.
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
// (§5.5): the workspace's .fount folder; outbox/, the reply's files, at
// jobs/<job id>/outbox/; and each change or new file under files/ as a
// proposal. scratch/ is thrown away, and so is the index, which only the
// index step writes. Anything else the runner changed or added, an input, is
// dropped and counted: threads/, instructions.md, memory.md, and anything
// outside the worker root's folders.
func collect(dirs JobDirs, given map[string]string, jobID string) (*Results, error) {
	r := &Results{Writes: map[string][]byte{}}
	budget := &budget{}
	err := walkFiles(dirs.Workspace, budget, func(rel string, data []byte) {
		switch {
		case strings.HasPrefix(rel, fountDir+"/"):
			r.Writes[prefixFount+strings.TrimPrefix(rel, fountDir+"/")] = data
		case strings.HasPrefix(rel, dirOutbox):
			r.Writes[jobOutbox(jobID)+strings.TrimPrefix(rel, dirOutbox)] = data
		case strings.HasPrefix(rel, dirScratch):
		case given[rel] == hashOf(data):
		case strings.HasPrefix(rel, dirFiles):
			r.Writes[prefixJobs+jobID+"/proposed/"+rel] = data
		default:
			r.Dropped = append(r.Dropped, rel)
		}
	}, &r.Dropped)
	if err != nil {
		return nil, err
	}
	if err := keepBases(r, given, jobID); err != nil {
		return nil, err
	}
	if err := keepOutboxSources(r, given, jobID); err != nil {
		return nil, err
	}
	return r, nil
}

// jobOutbox is where a job's outbox is kept in the tree, ending in "/": the
// files its draft carries until it's sent or discarded.
func jobOutbox(jobID string) string { return prefixJobs + jobID + "/outbox/" }

// outboxSourcesPath holds, for each outbox file whose bytes equal a file the
// job was given, that file: a move in, or a copy (§5.5, "A move never
// deletes in Cloud").
func outboxSourcesPath(jobID string) string { return prefixJobs + jobID + "/outbox.json" }

// outboxSource is the given file an outbox file is: its path in the worker
// root and the version's hash.
type outboxSource struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// keepOutboxSources records which given file each outbox file is, if any,
// preferring the worker's Files, then the first path.
func keepOutboxSources(r *Results, given map[string]string, jobID string) error {
	byHash := map[string]string{}
	for rel, hash := range given {
		cur, ok := byHash[hash]
		files, curFiles := strings.HasPrefix(rel, dirFiles), strings.HasPrefix(cur, dirFiles)
		if !ok || files && !curFiles || files == curFiles && rel < cur {
			byHash[hash] = rel
		}
	}
	sources := map[string]outboxSource{}
	for p, data := range r.Writes {
		if strings.HasPrefix(p, jobOutbox(jobID)) {
			hash := hashOf(data)
			if from, ok := byHash[hash]; ok {
				sources[p] = outboxSource{Path: from, SHA256: hash}
			}
		}
	}
	if len(sources) == 0 {
		return nil
	}
	data, err := json.Marshal(sources)
	if err != nil {
		return err
	}
	r.Writes[outboxSourcesPath(jobID)] = data
	return nil
}

// basesPath holds, for each file a job proposed, the hash of the version it
// was given, or "" for a new file: what Accept checks (threadops.go).
func basesPath(jobID string) string { return prefixJobs + jobID + "/bases.json" }

func keepBases(r *Results, given map[string]string, jobID string) error {
	proposed := prefixJobs + jobID + "/proposed/"
	bases := map[string]string{}
	for p := range r.Writes {
		if rel, ok := strings.CutPrefix(p, proposed); ok {
			bases[rel] = given[rel]
		}
	}
	if len(bases) == 0 {
		return nil
	}
	data, err := json.Marshal(bases)
	if err != nil {
		return err
	}
	r.Writes[basesPath(jobID)] = data
	return nil
}

// collectIndex reads back the index the index step built.
func collectIndex(dirs JobDirs) (*Results, error) {
	r := &Results{Writes: map[string][]byte{}, Index: map[string][]byte{}}
	err := walkFiles(dirs.Index, &budget{}, func(rel string, data []byte) { r.Index[rel] = data }, &r.Dropped)
	return r, err
}

// rootDigest names the worker's files as they are: their paths and contents.
func rootDigest(t *Tree) string {
	h := sha256.New()
	for _, p := range t.List(prefixRoot) {
		hash, _ := t.Hash(p)
		fmt.Fprintf(h, "%q %s\n", p, hash)
	}
	return hex.EncodeToString(h.Sum(nil))
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
