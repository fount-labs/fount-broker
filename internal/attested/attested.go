// Package attested reads the private halves of a Tinfoil enclave's attested
// keys: generated inside the enclave each boot, granted to one container, and
// endorsed by its attestation document (tinfoil-config.yml's attested-keys).
package attested

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// Dir is where Tinfoil puts them.
const Dir = "/run/tinfoil/keys"

// LoadEd25519 reads key id's private half from dir.
func LoadEd25519(dir, id string) (ed25519.PrivateKey, error) {
	path := filepath.Join(dir, id, "private_key.pem")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s holds no PEM", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s isn't an Ed25519 key", path)
	}
	return key, nil
}
