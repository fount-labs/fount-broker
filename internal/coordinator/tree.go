package coordinator

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

const manifestObject = "manifest"

// A Tree is one worker's files: every object the coordinator keeps for it, under
// its DEK. The manifest maps each path to an object and the plaintext's hash, and
// is itself sealed, so the Store learns nothing but sizes.
//
// Objects are written once under fresh IDs. Changes are staged, then Commit
// writes a new manifest with the next version: a crash before that leaves the
// old tree whole, and a crash after leaves only orphaned objects.
type Tree struct {
	store    Store
	workerID string
	dek      DEK
	manifest manifest
	dirty    bool
	// garbage is the objects the next Commit makes unreachable.
	garbage []string
}

type manifest struct {
	Version uint64           `json:"version"`
	Entries map[string]entry `json:"entries"`
}

type entry struct {
	Object string `json:"object"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// ErrRolledBack means the Store returned a manifest older than the volume's
// record of it (fount-cloud-agents.md §4.2, "Rollback").
var ErrRolledBack = errors.New("the stored manifest is older than the last one committed")

// LoadTree opens a worker's tree. minVersion is the last version the volume
// recorded as committed; anything older is refused.
func LoadTree(store Store, workerID string, dek DEK, minVersion uint64) (*Tree, error) {
	t := &Tree{store: store, workerID: workerID, dek: dek, manifest: manifest{Entries: map[string]entry{}}}
	sealed, err := store.Get(workerID, manifestObject)
	switch {
	case errors.Is(err, ErrNotFound) && minVersion == 0:
		return t, nil
	case errors.Is(err, ErrNotFound):
		return nil, fmt.Errorf("worker %s: %w (no manifest, expected version %d)", workerID, ErrRolledBack, minVersion)
	case err != nil:
		return nil, err
	}
	plain, err := open(dek[:], sealed, aad(purposeManifest, workerID, ""))
	if err != nil {
		return nil, fmt.Errorf("worker %s manifest: %w", workerID, err)
	}
	if err := json.Unmarshal(plain, &t.manifest); err != nil {
		return nil, fmt.Errorf("worker %s manifest: %w", workerID, err)
	}
	if t.manifest.Version < minVersion {
		return nil, fmt.Errorf("worker %s: %w (version %d, expected %d)", workerID, ErrRolledBack, t.manifest.Version, minVersion)
	}
	if t.manifest.Entries == nil {
		t.manifest.Entries = map[string]entry{}
	}
	return t, nil
}

func (t *Tree) Version() uint64 { return t.manifest.Version }

func (t *Tree) Has(path string) bool {
	_, ok := t.manifest.Entries[path]
	return ok
}

// List returns the paths under prefix, sorted. A prefix ends in "/" to mean a
// folder.
func (t *Tree) List(prefix string) []string {
	var out []string
	for p := range t.manifest.Entries {
		if strings.HasPrefix(p, prefix) {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out
}

// Hash is the hex SHA-256 of the file at path, from the manifest.
func (t *Tree) Hash(path string) (string, bool) {
	e, ok := t.manifest.Entries[path]
	return e.SHA256, ok
}

func (t *Tree) Read(path string) ([]byte, error) {
	e, ok := t.manifest.Entries[path]
	if !ok {
		return nil, fmt.Errorf("%s: %w", path, ErrNotFound)
	}
	sealed, err := t.store.Get(t.workerID, e.Object)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	plain, err := open(t.dek[:], sealed, aad(purposeBlob, t.workerID, e.Object))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if sum := sha256.Sum256(plain); hex.EncodeToString(sum[:]) != e.SHA256 {
		return nil, fmt.Errorf("%s: object %s doesn't match the manifest's hash", path, e.Object)
	}
	return plain, nil
}

// Write seals data into a new object and stages it at path. Writing what a path
// already holds changes nothing.
func (t *Tree) Write(path string, data []byte) error {
	if err := checkPath(path); err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	if old, ok := t.manifest.Entries[path]; ok && old.SHA256 == hash {
		return nil
	}
	id, err := newObjectID()
	if err != nil {
		return err
	}
	sealed, err := seal(t.dek[:], data, aad(purposeBlob, t.workerID, id))
	if err != nil {
		return err
	}
	if err := t.store.Put(t.workerID, id, sealed); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if old, ok := t.manifest.Entries[path]; ok {
		t.garbage = append(t.garbage, old.Object)
	}
	t.manifest.Entries[path] = entry{Object: id, Size: int64(len(data)), SHA256: hash}
	t.dirty = true
	return nil
}

func (t *Tree) Remove(path string) {
	if old, ok := t.manifest.Entries[path]; ok {
		t.garbage = append(t.garbage, old.Object)
		delete(t.manifest.Entries, path)
		t.dirty = true
	}
}

// Commit writes the staged changes as the next version and returns it. With
// nothing staged it writes nothing.
func (t *Tree) Commit() (uint64, error) {
	if !t.dirty {
		return t.manifest.Version, nil
	}
	next := t.manifest
	next.Version++
	plain, err := json.Marshal(next)
	if err != nil {
		return 0, err
	}
	sealed, err := seal(t.dek[:], plain, aad(purposeManifest, t.workerID, ""))
	if err != nil {
		return 0, err
	}
	if err := t.store.Put(t.workerID, manifestObject, sealed); err != nil {
		return 0, fmt.Errorf("worker %s manifest: %w", t.workerID, err)
	}
	t.manifest = next
	t.dirty = false
	for _, id := range t.garbage {
		// An object left behind costs storage, not correctness.
		_ = t.store.Delete(t.workerID, id)
	}
	t.garbage = nil
	return next.Version, nil
}

func newObjectID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
