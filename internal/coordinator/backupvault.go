package coordinator

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fount-labs/fount-broker/internal/mail"
)

// What durability needs from outside the enclave (launch-plan.md decisions
// 17 and 18, "Durable storage"): a bucket for the backups, and the Cloud
// vault's counter of the latest security state. MemBucket and MemVault stand
// in for both in dev and tests.

// BackupBucket is the versioned S3 bucket backups go to. It sees only
// ciphertext and object sizes: roots are sealed under a key derived from the
// vault's wrapping key, and tree objects are already sealed under their
// worker's DEK.
//
// What the bucket must provide (lane G):
//   - Put is durable when it returns (S3's read-after-write), and a key is
//     written whole or not at all.
//   - List returns every key under a prefix, sorted, across pages.
//   - Versioning on, with noncurrent versions expiring so that nothing older
//     than MaxRestoreAge can be read back: the edge keeps sent records 90
//     days, and a restore must not reach past them.
//   - Credentials only the attested coordinator release holds.
type BackupBucket interface {
	Put(ctx context.Context, key string, data []byte) error
	// Get returns ErrNotFound for a key that isn't there.
	Get(ctx context.Context, key string) ([]byte, error)
	// List is every key under prefix, sorted.
	List(ctx context.Context, prefix string) ([]string, error)
	// Delete of a missing key is no error.
	Delete(ctx context.Context, key string) error
}

// VaultCounter is the Cloud vault's rollback counter: the coordinator's
// security sequence, as of the last change to security state it
// acknowledged, and the generation that may move it.
//
// What the Cloud vault provides (fount-mail-vault COORDINATOR_MODE;
// WireCounter is the client), next to the wrapping key and the generation
// certificate it releases together (decision 18):
//   - One counter per coordinator deployment, durable across vault restarts
//     and replicated to its peer before a CompareAndSwap returns.
//   - Load answers the current generation and count.
//   - CompareAndSwap(generation, prev, next) succeeds only when generation is
//     the vault's current one, the count is prev, and next > prev. Anything
//     else changes nothing: ErrVaultGeneration for an old generation,
//     ErrVaultCount for another count.
//   - Moving the generation on (a restore, an upgrade) keeps the count.
//   - Only the attested coordinator release of the current generation can
//     call it, authenticated by the key the generation certificate names.
type VaultCounter interface {
	Load(ctx context.Context) (VaultCount, error)
	CompareAndSwap(ctx context.Context, generation, prev, next uint64) error
}

// VaultCount is what the vault holds: the current coordinator generation
// and the security sequence it last counted.
type VaultCount struct {
	Generation uint64 `json:"generation"`
	Count      uint64 `json:"count"`
}

var (
	// ErrVaultGeneration is a counter call from a coordinator whose
	// generation the vault has moved past: it must stop.
	ErrVaultGeneration = errors.New("the vault has moved to a newer coordinator generation")
	// ErrVaultCount is a CompareAndSwap from a count the vault doesn't
	// hold.
	ErrVaultCount = errors.New("the vault's security counter isn't where this coordinator left it")
)

// MemBucket is a BackupBucket in memory, for dev and tests. FailPut, when
// set, is asked before each Put and fails it with its error.
type MemBucket struct {
	mu      sync.Mutex
	objects map[string][]byte
	FailPut func(key string) error
}

func NewMemBucket() *MemBucket { return &MemBucket{objects: map[string][]byte{}} }

func (b *MemBucket) Put(_ context.Context, key string, data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.FailPut != nil {
		if err := b.FailPut(key); err != nil {
			return err
		}
	}
	b.objects[key] = slices.Clone(data)
	return nil
}

func (b *MemBucket) Get(_ context.Context, key string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	data, ok := b.objects[key]
	if !ok {
		return nil, fmt.Errorf("%s: %w", key, ErrNotFound)
	}
	return slices.Clone(data), nil
}

func (b *MemBucket) List(_ context.Context, prefix string) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for _, k := range slices.Sorted(maps.Keys(b.objects)) {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out, nil
}

func (b *MemBucket) Delete(_ context.Context, key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.objects, key)
	return nil
}

// MemVault is the Cloud vault's generation and counter in memory, for dev
// and tests. Boot is a coordinator release starting: it moves the generation
// on and certifies a new coordinator key with Authority, which a fake edge
// has as its COORDINATOR_AUTHORITY_KEY. FailSwap, when set, is asked before
// each CompareAndSwap.
type MemVault struct {
	Authority ed25519.PrivateKey
	FailSwap  func(generation, prev, next uint64) error

	mu         sync.Mutex
	generation uint64
	count      uint64
}

// Boot moves the generation on and returns the new coordinator's
// generation, fixed for the process.
func (v *MemVault) Boot() (*FixedGeneration, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	n := v.generation + 1
	cert, err := mail.SignGenerationCertificate(v.Authority, mail.GenerationCertificate{Generation: n, CoordinatorKey: pub, IssuedAt: time.Now().Unix()})
	if err != nil {
		return nil, err
	}
	v.generation = n
	return &FixedGeneration{G: mail.Generation{Number: n, Certificate: cert, Key: priv}}, nil
}

func (v *MemVault) Load(context.Context) (VaultCount, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return VaultCount{Generation: v.generation, Count: v.count}, nil
}

func (v *MemVault) CompareAndSwap(_ context.Context, generation, prev, next uint64) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.FailSwap != nil {
		if err := v.FailSwap(generation, prev, next); err != nil {
			return err
		}
	}
	switch {
	case generation != v.generation:
		return fmt.Errorf("%w: %d, not %d", ErrVaultGeneration, v.generation, generation)
	case prev != v.count || next <= prev:
		return fmt.Errorf("%w: it is %d, not %d", ErrVaultCount, v.count, prev)
	}
	v.count = next
	return nil
}

// FixedGeneration is one coordinator process's generation: a
// mail.GenerationSource that answers the same one every time, as the vault
// releases one per coordinator boot.
type FixedGeneration struct{ G mail.Generation }

func (f *FixedGeneration) Generation(context.Context) (mail.Generation, error) { return f.G, nil }
