//go:build dev

package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"

	"github.com/fount-labs/fount-broker/internal/jobcred"
)

// jobKeys are the job-signing key and cache secret, kept in dir so a dev
// proxy can be told the key once.
func jobKeys(dir string) (ed25519.PrivateKey, []byte, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	return jobcred.DevKeys(filepath.Join(dir, "job-signing.key"))
}
