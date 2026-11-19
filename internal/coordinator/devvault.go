package coordinator

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fount-labs/fount-broker/internal/mail"
)

// FileVault is the Cloud vault's generation and counter in a file, for dev
// and test coordinators until the Cloud vault has them (fount-mail-vault
// docs/COORDINATOR-COUNTER.md): MemVault, kept across restarts. It belongs
// outside the coordinator's volume, as the vault is, so a restore drill can
// wipe the volume and keep the counter.
//
// Every call reads the file, so a second process on the same file (a new
// generation) fences the first at its next call. Writes aren't locked across
// processes: it is a stand-in on one machine, not the vault's guarantee.
type FileVault struct {
	Path string
	// Authority signs generation certificates: the key a dev edge has as
	// COORDINATOR_AUTHORITY_KEY.
	Authority ed25519.PrivateKey

	mu sync.Mutex
}

var _ VaultCounter = (*FileVault)(nil)

// Boot moves the generation on, keeping the count, and returns the new
// coordinator's generation, fixed for the process.
func (v *FileVault) Boot() (*FixedGeneration, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	st, err := v.read()
	if err != nil {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	n := st.Generation + 1
	cert, err := mail.SignGenerationCertificate(v.Authority, mail.GenerationCertificate{Generation: n, CoordinatorKey: pub, IssuedAt: time.Now().Unix()})
	if err != nil {
		return nil, err
	}
	st.Generation = n
	if err := v.write(st); err != nil {
		return nil, err
	}
	return &FixedGeneration{G: mail.Generation{Number: n, Certificate: cert, Key: priv}}, nil
}

func (v *FileVault) Load(context.Context) (VaultCount, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.read()
}

func (v *FileVault) CompareAndSwap(_ context.Context, generation, prev, next uint64) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	st, err := v.read()
	if err != nil {
		return err
	}
	switch {
	case generation != st.Generation:
		return fmt.Errorf("%w: %d, not %d", ErrVaultGeneration, st.Generation, generation)
	case prev != st.Count || next <= prev:
		return fmt.Errorf("%w: it is %d, not %d", ErrVaultCount, st.Count, prev)
	}
	st.Count = next
	return v.write(st)
}

// read is the file's state; a missing file is generation 0, count 0.
func (v *FileVault) read() (VaultCount, error) {
	var st VaultCount
	data, err := os.ReadFile(v.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return st, fmt.Errorf("the dev vault %s: %w", v.Path, err)
	}
	return st, nil
}

// write replaces the file whole, synced before it is renamed into place.
func (v *FileVault) write(st VaultCount) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(v.Path), 0o700); err != nil {
		return err
	}
	tmp := v.Path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, v.Path)
}
