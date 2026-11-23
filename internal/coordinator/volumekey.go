package coordinator

import (
	"crypto/hkdf"
	"crypto/sha256"
)

// Labels of the keys a coordinator's encrypted volume is opened with.
const (
	volumeKeyInfo    = "fount-coordinator/volume-key/v1"
	devVolumeKeyInfo = "fount-coordinator/dev-volume-key/v1"
)

// VolumeKey opens the coordinator's Tinfoil volume: HKDF-SHA256 from the
// wrapping key the Cloud vaults release after attestation. It's derived,
// never stored, so only an attested coordinator can open the disk, and a
// coordinator's volume opens under every release the vaults trust, as its
// workers' DEKs do. The wrapping key can't change without every worker
// rewrapped, so neither can this.
func VolumeKey(w *WrappingKey) []byte { return derive(w[:], volumeKeyInfo) }

// DevVolumeKey stands in for VolumeKey on a --wrapping-key dev coordinator,
// whose wrapping key is a file on the volume: derived instead from the dev
// mail generation authority's seed, a Tinfoil secret standing in for the
// vaults.
func DevVolumeKey(seed []byte) []byte { return derive(seed, devVolumeKeyInfo) }

func derive(secret []byte, info string) []byte {
	key, err := hkdf.Key(sha256.New, secret, nil, info, KeySize)
	if err != nil {
		panic("hkdf: " + err.Error())
	}
	return key
}
