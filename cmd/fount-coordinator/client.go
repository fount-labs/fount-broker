package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync/atomic"

	"github.com/fount-labs/fount-broker/internal/channel"
)

// accountKeysEnv names fount-infra's device-credential keys in the measured
// config.
const accountKeysEnv = "FOUNT_ACCOUNT_KEYS"

// clientFlags say whether and how the attested client channel listens.
type clientFlags struct {
	listen      string
	accountKeys string
	attestation string
}

const (
	attestTinfoil    = "tinfoil"
	attestUnattested = "unattested"
)

// server checks the flags and loads what the channel needs before anything
// listens: the account keys, and this enclave's attested key and attestation
// socket. Its Handler is set once the coordinator is up.
func (f clientFlags) server() (*channel.Server, error) {
	if f.listen == "" {
		if f.accountKeys != "" || f.attestation != attestTinfoil {
			return nil, errors.New("--account-keys and --client-attestation need --client-listen")
		}
		return nil, nil
	}
	accountKeys := f.accountKeys
	if accountKeys == "" {
		accountKeys = os.Getenv(accountKeysEnv)
	}
	keys, err := channel.ParseAccountKeys(accountKeys)
	if err != nil {
		return nil, fmt.Errorf("--client-listen needs --account-keys (or $%s), fount-infra's device-credential keys: %w", accountKeysEnv, err)
	}
	key, attester, err := clientAttestation(f.attestation)
	if err != nil {
		return nil, err
	}
	return &channel.Server{Key: key, Attester: attester, AccountKeys: keys}, nil
}

// clientAPI is what --client-listen serves: /health and /status, which answer
// while the coordinator waits for its wrapping key, and the channel, which
// answers 503 until ready says it's up.
func clientAPI(status http.Handler, ready *atomic.Pointer[http.Handler]) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", status)
	mux.HandleFunc(channel.Path, func(w http.ResponseWriter, r *http.Request) {
		h := ready.Load()
		if h == nil {
			http.Error(w, "the coordinator is waiting for its wrapping key", http.StatusServiceUnavailable)
			return
		}
		(*h).ServeHTTP(w, r)
	})
	return mux
}
