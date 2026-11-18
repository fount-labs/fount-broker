package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fount-labs/fount-broker/internal/coordinator"
	"github.com/fount-labs/fount-broker/internal/vaultkey"
)

// keyFlags say where the wrapping key comes from.
type keyFlags struct {
	mode       string // dev or vault
	dir        string
	vaults     string
	vaultRepo  string
	commitment string
	testAPI    bool
}

const (
	keyDev   = "dev"
	keyVault = "vault"
)

// check fails before anything listens. A coordinator with the vault's key
// takes no bearer-token way in: anyone can deploy a public release with a
// token of their own, and a release that both held the key and took a token
// would hand that deployer every worker it could load.
func (f keyFlags) check() error {
	switch f.mode {
	case keyDev:
		if f.vaults != "" || f.vaultRepo != "" || f.commitment != "" {
			return errors.New("--vaults, --vault-repo and --keyset-commitment need --wrapping-key vault")
		}
		return nil
	case keyVault:
	default:
		return fmt.Errorf("--wrapping-key %q: dev or vault", f.mode)
	}
	if f.testAPI {
		return errors.New("--wrapping-key vault refuses --test-api: a coordinator with the vault's key takes no bearer token")
	}
	if _, err := vaultkey.ParseVaults(f.vaults); err != nil {
		return fmt.Errorf("--vaults: %w", err)
	}
	if owner, name, ok := strings.Cut(f.vaultRepo, "/"); !ok || owner == "" || name == "" || strings.ContainsAny(name, "/@ ") || strings.ContainsAny(owner, "@ ") {
		return fmt.Errorf("--vault-repo %q: the vault pair's config repo, owner/repo", f.vaultRepo)
	}
	if f.commitment == "" {
		return errors.New("--wrapping-key vault needs --keyset-commitment, the vaults' KEYSET_COMMITMENT")
	}
	return nil
}

// keyStatus is what /status says about the wrapping key. It names the key by
// an ID derived from it, never the key.
type keyStatus struct {
	mu         sync.Mutex
	Mode       string    `json:"mode"`
	State      string    `json:"state"` // waiting, then held
	KeyID      string    `json:"key_id,omitempty"`
	Commitment string    `json:"keyset_commitment,omitempty"`
	Vault      string    `json:"vault,omitempty"`
	Since      time.Time `json:"since"`
	Failures   int       `json:"failed_rounds,omitempty"`
	LastError  string    `json:"last_error,omitempty"`
}

func (s *keyStatus) held(key *coordinator.WrappingKey, commitment, vault string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.State, s.KeyID, s.Commitment, s.Vault, s.Since, s.LastError = "held", vaultkey.KeyID(key), commitment, vault, time.Now().UTC(), ""
}

func (s *keyStatus) failed(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Failures++
	s.LastError = fmt.Sprintf("%.400v", err)
}

// statusAPI is /health and /status, safe beyond loopback: neither carries user
// data. /health answers while the coordinator waits for its key, since an
// enclave that fails its boot gate is restarted, and that wouldn't bring the
// vaults back.
func statusAPI(s *keyStatus) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		body, err := json.Marshal(map[string]any{"wrapping_key": s})
		s.mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(append(body, '\n'))
	})
	return mux
}

// wrappingKey gets the key by f.mode: the dev key from its file, or the
// vaults' keyset, waiting for a vault as long as it takes.
func wrappingKey(ctx context.Context, f keyFlags, status *keyStatus) (coordinator.WrappingKey, error) {
	if f.mode == keyDev {
		key, err := devWrappingKey(filepath.Join(f.dir, "wrapping.key"))
		if err == nil {
			status.held(&key, "", "")
		}
		return key, err
	}
	vaults, err := vaultkey.ParseVaults(f.vaults)
	if err != nil {
		return coordinator.WrappingKey{}, err
	}
	src, err := vaultkey.Tinfoil(vaults, f.vaultRepo, f.commitment)
	if err != nil {
		return coordinator.WrappingKey{}, err
	}
	log.Printf("waiting for the wrapping key from %s (releases of %s, keyset %s)", f.vaults, f.vaultRepo, f.commitment)
	got, err := src.Wait(ctx, vaultkey.DefaultBackoff, func(err error) {
		status.failed(err)
		log.Printf("no vault gave the wrapping key: %v", err)
	})
	if err != nil {
		return coordinator.WrappingKey{}, err
	}
	status.held(&got.Key, got.Commitment, got.Vault)
	log.Printf("wrapping key %s from %s in %s", vaultkey.KeyID(&got.Key), got.Vault, got.Elapsed.Round(time.Millisecond))
	return got.Key, nil
}
