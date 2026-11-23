package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fount-labs/fount-broker/internal/coordinator"
	"github.com/fount-labs/fount-broker/internal/vaultkey"
	"github.com/fount-labs/fount-mail-vault/wire"
)

// keyFlags say where the wrapping key comes from.
type keyFlags struct {
	mode       string // dev or vault
	dir        string
	vaults     string
	vaultRepo  string
	commitment string
	// authority is --coordinator-authority-key, the Cloud vaults'
	// GENERATION_AUTHORITY_KEY: with it, a boot takes a generation.
	authority string
	// mail is --mail, which with the vault's key needs a generation.
	mail bool
	// dryRun is --restore-dry-run, which must not move the generation.
	dryRun  bool
	testAPI bool
	// statusListen is --status-listen, or --client-listen, which serves
	// /health too. Vault needs one for the healthcheck, since it serves no
	// dev API.
	statusListen string
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
		if f.vaults != "" || f.vaultRepo != "" || f.commitment != "" || f.authority != "" {
			return errors.New("--vaults, --vault-repo, --keyset-commitment and --coordinator-authority-key need --wrapping-key vault")
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
	if err := wire.ValidateCommitment(f.commitment); err != nil {
		return fmt.Errorf("--keyset-commitment: %w", err)
	}
	if f.statusListen == "" {
		return errors.New("--wrapping-key vault needs --status-listen or --client-listen, for the healthcheck while it waits for a vault")
	}
	if f.authority != "" {
		if _, err := wire.ParseAuthorityKey(f.authority); err != nil {
			return fmt.Errorf("--coordinator-authority-key: %w", err)
		}
	} else if f.mail {
		// Without a generation the edge never fences an old coordinator,
		// and an address key is never rotated (security review H2).
		return errors.New("--mail with --wrapping-key vault needs --coordinator-authority-key, so the coordinator has a generation")
	}
	return nil
}

// boots says whether this process takes a generation from the vault.
func (f keyFlags) boots() bool { return f.mode == keyVault && f.authority != "" && !f.dryRun }

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
	Generation uint64    `json:"generation,omitempty"`
	Failures   int       `json:"failed_rounds,omitempty"`
	LastError  string    `json:"last_error,omitempty"`
	// vol is /status's "volume", under mu too.
	vol volumeStatus
}

// volumeStatus is the encrypted volume --dir is on: none without --volume,
// so a coordinator whose state goes with every boot shows it.
type volumeStatus struct {
	State     string `json:"state"` // none; opening; unlocked or initialized; refused
	LastError string `json:"last_error,omitempty"`
}

func (s *keyStatus) volume(state string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vol.State, s.vol.LastError = state, ""
	if err != nil {
		s.vol.LastError = fmt.Sprintf("%.400v", err)
	}
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
// vaults back. Once the coordinator runs, /status counts its jobs by account,
// naming none.
//
// runners, if set, is the runner enclaves linked in, by hostname and key.
func statusAPI(s *keyStatus, jobs *atomic.Pointer[coordinator.Coordinator], runners func() any) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		out := map[string]any{"wrapping_key": s, "volume": &s.vol}
		if c := jobs.Load(); c != nil {
			out["jobs"] = c.Load()
			// The phase only: the last error stays behind /control/mail.
			if m := c.MailStatus(); m != nil {
				out["mail"] = map[string]any{"phase": m.Phase, "generation": m.Generation}
			}
		}
		if runners != nil {
			out["runners"] = runners()
		}
		s.mu.Lock()
		body, err := json.Marshal(out)
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
// vaults' keyset, waiting for a vault as long as it takes. With the vaults'
// key and an authority it also returns what else the vault gave: the
// generation, the counter and the bucket's credentials.
func wrappingKey(ctx context.Context, f keyFlags, status *keyStatus) (coordinator.WrappingKey, *vaultSide, error) {
	if f.mode == keyDev {
		key, err := devWrappingKey(filepath.Join(f.dir, "wrapping.key"))
		if err == nil {
			status.held(&key, "", "")
		}
		return key, nil, err
	}
	vaults, err := vaultkey.ParseVaults(f.vaults)
	if err != nil {
		return coordinator.WrappingKey{}, nil, err
	}
	src, err := vaultkey.Tinfoil(vaults, f.vaultRepo, f.commitment)
	if err != nil {
		return coordinator.WrappingKey{}, nil, err
	}
	if f.authority != "" {
		src.Authority, _ = wire.ParseAuthorityKey(f.authority)
		src.Boot = f.boots()
	}
	log.Printf("waiting for the wrapping key from %s (releases of %s, keyset %s, generation %t)", f.vaults, f.vaultRepo, f.commitment, src.Boot)
	got, err := src.Wait(ctx, vaultkey.DefaultBackoff, func(err error) {
		status.failed(err)
		log.Printf("no vault gave the wrapping key: %v", err)
	})
	if err != nil {
		return coordinator.WrappingKey{}, nil, err
	}
	status.held(&got.Key, got.Commitment, got.Vault)
	log.Printf("wrapping key %s from %s in %s", vaultkey.KeyID(&got.Key), got.Vault, got.Elapsed.Round(time.Millisecond))
	side, err := newVaultSide(vaults, src.Authority, got)
	if err != nil {
		return coordinator.WrappingKey{}, nil, err
	}
	if side != nil && side.gen != nil {
		status.generation(side.gen.G.Number)
		log.Printf("coordinator generation %d from %s", side.gen.G.Number, got.Vault)
	}
	return got.Key, side, nil
}

// vaultSide is what the Cloud vaults give a coordinator beyond its key.
type vaultSide struct {
	counter coordinator.VaultCounter
	// gen is this process's generation; nil in a dry run.
	gen *coordinator.FixedGeneration
	// s3 is the backup bucket's credentials, nil when the vault holds none.
	s3 *wire.S3Credentials
}

// newVaultSide is nil without an authority: no generation, no counter.
func newVaultSide(vaults []string, authority ed25519.PublicKey, got *vaultkey.Fetched) (*vaultSide, error) {
	if authority == nil {
		return nil, nil
	}
	side := &vaultSide{s3: got.S3}
	if got.Generation != nil {
		side.gen = &coordinator.FixedGeneration{G: *got.Generation}
	}
	counter, err := vaultkey.NewCounter(vaults, authority, side.gen)
	if err != nil {
		return nil, err
	}
	side.counter = counter
	return side, nil
}

func (s *keyStatus) generation(n uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Generation = n
}
