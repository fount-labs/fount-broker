package coordinator

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"slices"
	"strconv"
)

// DEK epochs (team security review 2026-11-23, finding 2). A device that
// reached a worker holds its DEK, so once removed it could still open, with
// the bucket, every object the worker wrote after. So when a list or record
// leaves a device without the reach it had, the worker gets a new DEK, an
// epoch: the coordinator makes it, wraps it under its wrapping key and to
// each device that still reaches the worker, and seals all new objects, and
// at once the manifest, under it.
//
// Old epochs are kept, not re-encrypted under the new one: the removed device
// held those keys and could have copied those objects already, so rewriting
// them would cost a full copy of the tree and protect nothing. Every device
// that reaches the worker gets a wrap of every epoch, so a current member
// reads old objects too.
//
// Epoch 0 is the DEK the list signed a commitment to: Worker.WrappedDEK,
// Device.Wrap and workerView.wrap, unchanged, so a worker that never lost a
// device stores exactly what it did before. Epoch n ≥ 1 is DEKEpochs[n-1].
//
// Each manifest entry names the epoch its object is under; the manifest is
// under the worker's current epoch, which the volume records. A rotation
// commits the new epoch with its list, then reseals the manifest; until that
// lands (Worker.ManifestEpoch) the manifest may also be under the epoch
// before, and no other.

// DEKEpoch is one of a worker's DEKs after its first.
type DEKEpoch struct {
	Epoch uint32 `json:"epoch"`
	// Wrapped is under the coordinator's wrapping key (WrapEpoch).
	Wrapped []byte `json:"wrapped"`
	// Commitment is DEKCommitment of the epoch's DEK, which its device wraps
	// are bound to. No list signs it: the coordinator made the key.
	Commitment string `json:"commitment"`
}

// EpochWrap is a device's wrap of one DEK epoch after the first.
type EpochWrap struct {
	Epoch uint32 `json:"epoch"`
	Wrap  []byte `json:"wrap"`
}

func epochName(epoch uint32) string { return "epoch/" + strconv.FormatUint(uint64(epoch), 10) }

// WrapEpoch seals a worker's DEK of epoch ≥ 1 for the volume.
func (w *WrappingKey) WrapEpoch(workerID string, epoch uint32, dek DEK) ([]byte, error) {
	if epoch == 0 {
		return w.Wrap(workerID, dek)
	}
	return seal(w[:], dek[:], aad(purposeDEK, workerID, epochName(epoch)))
}

// UnwrapEpoch opens a DEK sealed by WrapEpoch for the same worker and epoch.
func (w *WrappingKey) UnwrapEpoch(workerID string, epoch uint32, wrapped []byte) (DEK, error) {
	if epoch == 0 {
		return w.Unwrap(workerID, wrapped)
	}
	var k DEK
	plain, err := open(w[:], wrapped, aad(purposeDEK, workerID, epochName(epoch)))
	if err != nil {
		return k, fmt.Errorf("unwrap DEK epoch %d of worker %s: %w", epoch, workerID, err)
	}
	if len(plain) != KeySize {
		return k, fmt.Errorf("worker %s: wrapped DEK epoch %d is %d bytes", workerID, epoch, len(plain))
	}
	copy(k[:], plain)
	clear(plain)
	return k, nil
}

// A Keyring is a worker's DEKs by epoch, unwrapped.
type Keyring struct {
	keys []DEK
	// manifest is the epoch the volume last recorded the manifest under.
	manifest uint32
}

// SingleKeyring is a keyring of one epoch, a worker's first DEK.
func SingleKeyring(dek DEK) *Keyring { return &Keyring{keys: []DEK{dek}} }

func (k *Keyring) Current() uint32 { return uint32(len(k.keys) - 1) }

func (k *Keyring) key(epoch uint32) (*DEK, error) {
	if int(epoch) >= len(k.keys) {
		return nil, fmt.Errorf("no DEK epoch %d (the worker has %d)", epoch, len(k.keys))
	}
	return &k.keys[epoch], nil
}

// manifestEpochs are the epochs a stored manifest may be under, newest first.
func (k *Keyring) manifestEpochs() []uint32 {
	if k.manifest < k.Current() {
		return []uint32{k.Current(), k.manifest}
	}
	return []uint32{k.Current()}
}

func (k *Keyring) clone() *Keyring {
	return &Keyring{keys: slices.Clone(k.keys), manifest: k.manifest}
}

// Clear zeroes the keys.
func (k *Keyring) Clear() {
	if k == nil {
		return
	}
	for i := range k.keys {
		clear(k.keys[i][:])
	}
}

// Keyring unwraps every DEK epoch of a granted worker.
func (w *WrappingKey) Keyring(wk *Worker) (*Keyring, error) {
	if wk.WrappedDEK == nil {
		return nil, ErrNotGranted
	}
	k0, err := w.Unwrap(wk.ID, wk.WrappedDEK)
	if err != nil {
		return nil, err
	}
	ring := &Keyring{keys: []DEK{k0}, manifest: wk.ManifestEpoch}
	for i, e := range wk.DEKEpochs {
		if e.Epoch != uint32(i+1) {
			ring.Clear()
			return nil, fmt.Errorf("worker %s: DEK epoch %d is out of order", wk.ID, e.Epoch)
		}
		dek, err := w.UnwrapEpoch(wk.ID, e.Epoch, e.Wrapped)
		if err != nil {
			ring.Clear()
			return nil, err
		}
		ring.keys = append(ring.keys, dek)
	}
	if ring.manifest > ring.Current() {
		ring.Clear()
		return nil, fmt.Errorf("worker %s: its manifest is under epoch %d, past its last", wk.ID, ring.manifest)
	}
	return ring, nil
}

// epochAAD is aad for what is sealed under a DEK of epoch ≥ 1, bound to the
// epoch; epoch 0 keeps the AAD from before epochs.
func epochAAD(purpose, workerID, name string, epoch uint32) []byte {
	ad := aad(purpose, workerID, name)
	if epoch == 0 {
		return ad
	}
	return append(ad, "\x00"+epochName(epoch)...)
}

// lostReach says whether a device that held a wrap of the worker's DEK no
// longer reaches it with the same X25519 key: a member or device removed, a
// reviewer unassigned, or an admin lowered off it.
func lostReach(old []Device, reachers []TeamDevice) bool {
	for _, o := range old {
		if o.Wrap == nil {
			continue
		}
		kept := false
		for _, d := range reachers {
			if d.ID == o.ID && subtle.ConstantTimeCompare(o.Enc, d.Enc) == 1 {
				kept = true
				break
			}
		}
		if !kept {
			return true
		}
	}
	return false
}

// newEpoch gives nw a new DEK epoch. Called with c.mu held.
func (c *Coordinator) newEpoch(nw *Worker) error {
	dek, err := NewDEK()
	if err != nil {
		return err
	}
	defer clear(dek[:])
	n := uint32(len(nw.DEKEpochs) + 1)
	wrapped, err := c.cfg.Key.WrapEpoch(nw.ID, n, dek)
	if err != nil {
		return err
	}
	nw.DEKEpochs = append(slices.Clone(nw.DEKEpochs), DEKEpoch{Epoch: n, Wrapped: wrapped, Commitment: DEKCommitment(nw.ID, dek)})
	return nil
}

// epochWrapsFor is d's wraps of each epoch ≥ 1 in ring, keeping one it
// already has for the same X25519 key.
func epochWrapsFor(old []Device, d TeamDevice, account, workerID string, ring *Keyring) ([]EpochWrap, error) {
	var had []EpochWrap
	for _, o := range old {
		if o.ID == d.ID && subtle.ConstantTimeCompare(o.Enc, d.Enc) == 1 {
			had = o.EpochWraps
		}
	}
	var out []EpochWrap
	for n := uint32(1); n <= ring.Current(); n++ {
		var wrap []byte
		for _, h := range had {
			if h.Epoch == n {
				wrap = h.Wrap
			}
		}
		if wrap == nil {
			var err error
			if wrap, err = SealWrap(d.Enc, account, workerID, d.ID, ring.keys[n]); err != nil {
				return nil, err
			}
		}
		out = append(out, EpochWrap{Epoch: n, Wrap: wrap})
	}
	return out, nil
}

// resealManifestLocked seals a worker's manifest under its current epoch
// right after a rotation, so no removed device's key opens a manifest from
// now on, and records it. Called with c.mu and the worker's tree lock held.
// On a failure the old manifest stays, and the worker's next commit reseals
// it.
func (c *Coordinator) resealManifestLocked(id string) error {
	w := c.state.Workers[id]
	if w == nil {
		return ErrNoWorker
	}
	ring, err := c.cfg.Key.Keyring(w)
	if err != nil {
		return err
	}
	defer ring.Clear()
	if w.ManifestEpoch == ring.Current() {
		return nil
	}
	t, err := LoadTreeKeys(c.cfg.Store, id, ring, w.Version)
	if err != nil {
		return err
	}
	version, epoch := w.Version, ring.Current()
	if t.manifestEpoch != epoch {
		t.dirty = true
		if version, err = t.Commit(); err != nil {
			return err
		}
	}
	oldVersion, oldEpoch := w.Version, w.ManifestEpoch
	w.Version, w.ManifestEpoch = version, epoch
	if err := c.state.Save(c.cfg.StateDir); err != nil {
		// The manifest stays openable: it is under the current epoch, which
		// the volume names, and at a version past the one it records.
		w.Version, w.ManifestEpoch = oldVersion, oldEpoch
		return err
	}
	return nil
}

// resealAll reseals each rotated worker's manifest, logging what fails.
// Called with c.mu and the workers' tree locks held.
func (c *Coordinator) resealAll(ids []string) {
	for _, id := range ids {
		if err := c.resealManifestLocked(id); err != nil && !errors.Is(err, ErrNoWorker) {
			log.Printf("coordinator: worker %s: resealing its manifest under its new DEK epoch: %v (its next commit does)", id, err)
		}
	}
}
