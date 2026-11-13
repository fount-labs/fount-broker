package coordinator

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Store holds ciphertext under opaque names, "<worker id>/<object id>". In an
// enclave it is the buckets sidecar in front of S3 (fount-cloud-agents.md
// §4.2), so it sees only object sizes and when they change: the paths, names and
// count of a worker's files are inside its sealed manifest.
type Store interface {
	Put(workerID, objectID string, data []byte) error
	// Get returns ErrNotFound for an object that was never written or was
	// deleted.
	Get(workerID, objectID string) ([]byte, error)
	Delete(workerID, objectID string) error
}

var ErrNotFound = errors.New("not found")

// DirStore is a Store on a local folder, for development and tests.
type DirStore struct{ Root string }

func (d DirStore) path(workerID, objectID string) (string, error) {
	if err := checkID("worker", workerID); err != nil {
		return "", err
	}
	if err := checkID("object", objectID); err != nil {
		return "", err
	}
	return filepath.Join(d.Root, workerID, objectID), nil
}

func (d DirStore) Put(workerID, objectID string, data []byte) error {
	p, err := d.path(workerID, objectID)
	if err != nil {
		return err
	}
	return writeFileAtomic(p, data)
}

func (d DirStore) Get(workerID, objectID string) ([]byte, error) {
	p, err := d.path(workerID, objectID)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	return data, err
}

func (d DirStore) Delete(workerID, objectID string) error {
	p, err := d.path(workerID, objectID)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// writeFileAtomic writes through a temporary file and a rename, so a crash
// leaves the old contents or the new, never a torn file.
func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
