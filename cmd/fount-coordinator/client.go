package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"

	"github.com/fount-labs/fount-broker/internal/attested"
	"github.com/fount-labs/fount-broker/internal/channel"
	"github.com/fount-labs/fount-broker/internal/coordinator"
	"github.com/fount-labs/fount-broker/internal/link"
)

// accountKeysEnv names fount-infra's device-credential keys in the measured
// config.
const accountKeysEnv = "FOUNT_ACCOUNT_KEYS"

// clientFlags say whether and how the attested client channel listens.
type clientFlags struct {
	listen      string
	accountKeys string
	attestation string
	cloudOnly   bool
	// audience is the coordinator's origin, as Desktop dials it, which
	// worker grants must name (coordinator.Config.Audience).
	audience string
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
		if f.accountKeys != "" || f.attestation != attestTinfoil || f.cloudOnly || f.audience != "" {
			return nil, errors.New("--account-keys, --client-attestation, --cloud-credentials-only and --client-audience need --client-listen")
		}
		return nil, nil
	}
	if u, err := url.Parse(f.audience); err != nil || u.Scheme != "https" || u.Host == "" || u.String() != u.Scheme+"://"+u.Host {
		return nil, fmt.Errorf("--client-listen needs --client-audience, the coordinator's origin https://<host> that worker grants name; not %q", f.audience)
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
	return &channel.Server{Key: key, Attester: attester, AccountKeys: keys, CloudCredentialsOnly: f.cloudOnly}, nil
}

// handler serves each channel the account API for the account and device it
// proved.
func handler(c *coordinator.Coordinator) func(channel.Peer) http.Handler {
	return func(p channel.Peer) http.Handler {
		return c.AccountHandler(coordinator.Caller{Account: p.Account, Device: p.Device, DeviceKey: p.DeviceKey, Email: p.Email})
	}
}

// loadClientKey reads the enclave's attested channel key.
func loadClientKey() (ed25519.PrivateKey, error) {
	key, err := attested.LoadEd25519(attested.Dir, channel.KeyID)
	if err != nil {
		return nil, fmt.Errorf("the attested %s key (attested-keys in the enclave's config): %w", channel.KeyID, err)
	}
	return key, nil
}

// clientAPI is what --client-listen serves: /health and /status, which answer
// while the coordinator waits for its wrapping key, and the channel, which
// answers 503 until ready says it's up. With test set (--test-api), it serves
// the test API's /v0/ too, from testReady, so a test coordinator's shim needs
// only this port.
//
// linkIn, if set, takes runner enclaves' links on link.Path (--runners-dial-in).
func clientAPI(status http.Handler, ready *atomic.Pointer[http.Handler], test bool, testReady *atomic.Pointer[http.Handler], linkIn http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", status)
	mux.Handle(channel.Path, waitFor(ready))
	if linkIn != nil {
		mux.Handle(link.Path, linkIn)
	}
	if test {
		mux.Handle("/v0/", waitFor(testReady))
	}
	return mux
}

// waitFor serves what h holds, or 503 until it holds something.
func waitFor(h *atomic.Pointer[http.Handler]) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := h.Load()
		if next == nil {
			http.Error(w, "the coordinator is waiting for its wrapping key", http.StatusServiceUnavailable)
			return
		}
		(*next).ServeHTTP(w, r)
	})
}
