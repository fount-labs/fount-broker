// Command fount-coordinator is the dev build of Fount Cloud's coordinator: it
// keeps Cloud workers' files under their keys, queues jobs and runs each with a
// local runner command. See package coordinator for what isn't built yet.
//
//	fount-coordinator --dir <folder> --wrapping-key dev [--listen 127.0.0.1:8790] [--runners 2] [--slots 2]
//	  [--account-jobs 12] [--job-timeout 30m] -- <runner command...>
//	fount-coordinator --dir <folder> [flags] --runner-addr https://<domain> --runner-repo <owner/repo>
//	  [--credentials <file.json>] [--wrapping-key dev --test-api --listen 0.0.0.0:8790]
//	  [--wrapping-key vault --vaults <host,host> --vault-repo <owner/repo> --keyset-commitment <hex>
//	   --status-listen 0.0.0.0:8791]
//	  [--client-listen 0.0.0.0:8792 --account-keys <base64 SPKI,...> [--client-attestation tinfoil]
//	   [--cloud-credentials-only]]
//	fount-coordinator health [http://127.0.0.1:8790/health]
//
// The runner command is started once per job with fount-runner's --workspace,
// --job, --data and --index-read-only added (or --mode index and --index for
// the index step): fount-runner itself, or scripts/dev-runner.sh for the
// runner image in Docker. With --runner-addr, each job goes instead to a
// runner enclave's broker (fount-broker runner) over the attested link, an
// upgrade on its /fount-link path, which checks the runner runs a release of
// --runner-repo; dev builds also take "unattested", a link no hardware vouches
// for, to a dev build's runner. Each job carries credentials
// minted for that job (package jobcred), signed by the enclave's attested
// job-signing key, which the proxy learns from this enclave's attestation; a
// dev build signs with a key kept in --dir instead. The key is logged. --credentials gives every job the
// file's tokens instead, by the broker's names: a device credential, to reach
// a proxy that doesn't take job credentials yet.
//
// --client-listen serves the attested client channel (package channel) on
// its /fount-client upgrade, with /health and /status, so the shim needs one
// port: the way Desktop's broker reaches an account's workers, files and jobs.
// The coordinator proves itself with its attested fount-client key, and each
// client its account with a credential that one of --account-keys,
// fount-infra's, signed and whose subscription includes Cloud, and its device
// with that device key's grant. Each channel serves coordinator.AccountHandler
// for the account and device it proved; a worker opens only to the devices
// its DEK grant names. --cloud-credentials-only refuses 7-day device
// credentials, for when fount-infra issues hour-long Cloud ones. Dev builds
// also take --client-attestation unattested, for a dev broker.
//
// --test-api lets the dev API listen beyond loopback behind a bearer token in
// $FOUNT_TEST_API_TOKEN: the test coordinator enclave's way in, which the
// client channel replaces (m4-cloud-runners.md §7, P2). Test data only, while
// the wrapping key is the dev one. With --client-listen, that listener serves
// its /v0/ too, so the shim needs one port for both.
//
// --wrapping-key says where the key that wraps every worker's DEK comes from:
// vault (the default) is Fount Cloud's vault pair, which hands it only to an
// attested release of the real coordinators' config repo (package vaultkey);
// dev is a file in --dir, made on first run, for test coordinators
// (fount-labs/fount-cloud-coordinator), which must say --wrapping-key dev. The
// vault's key lives in memory only, and a coordinator waits for a vault before
// it loads the volume. It refuses --test-api. --status-listen serves /health and /status, which
// says where the key came from, on an address the shim can reach; vault needs
// it or --client-listen, which serves both too, and the healthcheck must point
// at one. Vault serves no dev API: its workers come only over the client
// channel, to the devices their grants name.
package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fount-labs/fount-broker/internal/channel"
	"github.com/fount-labs/fount-broker/internal/coordinator"
	"github.com/fount-labs/fount-broker/internal/healthcheck"
	"github.com/fount-labs/fount-broker/internal/jobcred"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetPrefix("fount-coordinator: ")
	if len(os.Args) > 1 && os.Args[1] == "health" {
		url := "http://127.0.0.1:8790/health"
		if len(os.Args) > 2 {
			url = os.Args[2]
		}
		if err := healthcheck.Check(url); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	dir := flag.String("dir", "", "folder for the state, the stored objects, job folders and the dev wrapping key")
	listen := flag.String("listen", "127.0.0.1:8790", "loopback address for the dev API, with --wrapping-key dev")
	runners := flag.Int("runners", 2, "runners in the pool")
	slots := flag.Int("slots", 2, "jobs at once per runner")
	accountJobs := flag.Int("account-jobs", 12, "jobs at once per account, which share its inference key's rate limit; more wait in the queue; 0 for no cap")
	timeout := flag.Duration("job-timeout", 30*time.Minute, "longest a job may run")
	runnerAddr := flag.String("runner-addr", "", "a runner enclave broker's origin, https://<domain>, in place of a runner command")
	credentials := flag.String("credentials", "", "JSON file of every job's broker credentials, with --runner-addr")
	test := flag.Bool("test-api", false, "listen beyond loopback, behind the bearer token in $"+testTokenEnv+"; test data only")
	runnerRepo := flag.String("runner-repo", os.Getenv("FOUNT_RUNNER_REPO"), "GitHub repository whose releases the runner enclave must run, or unattested")
	keyMode := flag.String("wrapping-key", keyVault, "where the wrapping key comes from: vault, Fount Cloud's vaults, held in memory only; or dev, a file in --dir, for test coordinators")
	vaults := flag.String("vaults", os.Getenv("FOUNT_VAULTS"), "with --wrapping-key vault: the vaults' hostnames, comma-separated")
	vaultRepo := flag.String("vault-repo", os.Getenv("FOUNT_VAULT_REPO"), "with --wrapping-key vault: GitHub repository whose releases the vaults must run")
	commitment := flag.String("keyset-commitment", os.Getenv("FOUNT_KEYSET_COMMITMENT"), "with --wrapping-key vault: the vaults' KEYSET_COMMITMENT")
	statusListen := flag.String("status-listen", "", "address for /health and /status, which may be beyond loopback")
	clientListen := flag.String("client-listen", "", "address for the attested client channel ("+channel.Path+"), /health and /status, which may be beyond loopback")
	accountKeys := flag.String("account-keys", "", "with --client-listen: fount-infra's device-credential keys, SPKI DER as base64, comma-separated (default $"+accountKeysEnv+")")
	clientAttest := flag.String("client-attestation", attestTinfoil, "with --client-listen: how the coordinator proves itself: tinfoil, or unattested in a dev build")
	cloudOnly := flag.Bool("cloud-credentials-only", false, "with --client-listen: take only hour-long Cloud credentials, not device credentials")
	audience := flag.String("client-audience", os.Getenv("FOUNT_CLIENT_AUDIENCE"), "with --client-listen: the coordinator's origin, https://<host>, which worker grants must name")
	flag.Parse()
	if *dir == "" || (flag.NArg() == 0) == (*runnerAddr == "") {
		return errors.New("usage: fount-coordinator --dir <folder> [flags] (-- <runner command...> | --runner-addr <host:port>)")
	}
	if *accountJobs < 0 {
		return fmt.Errorf("--account-jobs %d: a cap of 1 or more, or 0 for none", *accountJobs)
	}
	var runner coordinator.Runner = coordinator.LocalRunner{Command: flag.Args(), Timeout: *timeout}
	var mint func(account, workerID, jobID string) (map[string]string, error)
	if *runnerAddr != "" {
		if u, err := url.Parse(*runnerAddr); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("--runner-addr %s: the runner broker's origin, https://<domain>", *runnerAddr)
		}
		side, err := linkSide(*runnerRepo)
		if err != nil {
			return err
		}
		runner = coordinator.RemoteRunner{Addr: *runnerAddr, Timeout: *timeout, Link: side}
		if *credentials != "" {
			data, err := os.ReadFile(*credentials)
			if err != nil {
				return err
			}
			var fixed map[string]string
			if err := json.Unmarshal(data, &fixed); err != nil {
				return fmt.Errorf("%s: %w", *credentials, err)
			}
			mint = func(string, string, string) (map[string]string, error) { return maps.Clone(fixed), nil }
		} else {
			key, cacheSecret, err := jobKeys(*dir)
			if err != nil {
				return fmt.Errorf("the job-signing key: %w", err)
			}
			// Each is minted as its job starts: the job's timeout, and the
			// time to reach the runner.
			m := &jobcred.Minter{Key: key, CacheSecret: cacheSecret, Lifetime: *timeout + 5*time.Minute}
			mint = m.Mint
			log.Printf("job credentials are signed by %s", jobcred.PublicKey(key))
		}
	} else if *credentials != "" {
		return errors.New("--credentials needs --runner-addr")
	}
	if !*test {
		if err := loopbackOnly(*listen); err != nil {
			return err
		}
	}
	// --client-listen serves /health and /status too, so it does for vault's
	// --status-listen.
	keys := keyFlags{mode: *keyMode, dir: *dir, vaults: *vaults, vaultRepo: *vaultRepo, commitment: *commitment, testAPI: *test, statusListen: cmp.Or(*statusListen, *clientListen)}
	if err := keys.check(); err != nil {
		return err
	}
	clients, err := clientFlags{listen: *clientListen, accountKeys: *accountKeys, attestation: *clientAttest, cloudOnly: *cloudOnly, audience: *audience}.server()
	if err != nil {
		return err
	}

	// Every listener binds before the wait for the key, so a coordinator
	// that can't serve fails now, not once a vault answers. With the vault's
	// key there is no dev API, so nothing listens on --listen.
	var ln net.Listener
	if keys.mode == keyDev {
		if ln, err = net.Listen("tcp", *listen); err != nil {
			return fmt.Errorf("--listen: %w", err)
		}
		defer ln.Close()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	status := &keyStatus{Mode: keys.mode, State: "waiting", Since: time.Now().UTC()}
	var jobs atomic.Pointer[coordinator.Coordinator]
	if *statusListen != "" {
		statusLn, err := net.Listen("tcp", *statusListen)
		if err != nil {
			return fmt.Errorf("--status-listen: %w", err)
		}
		serveBeyond(ctx, stop, "status", statusLn, statusAPI(status, &jobs))
	}
	var channelReady, testReady atomic.Pointer[http.Handler]
	if clients != nil {
		clientLn, err := net.Listen("tcp", *clientListen)
		if err != nil {
			return fmt.Errorf("--client-listen: %w", err)
		}
		serveBeyond(ctx, stop, "client channel", clientLn, clientAPI(statusAPI(status, &jobs), &channelReady, *test, &testReady))
	}
	key, err := wrappingKey(ctx, keys, status)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	c, err := coordinator.New(coordinator.Config{
		StateDir: filepath.Join(*dir, "state"),
		WorkDir:  filepath.Join(*dir, "work"),
		Store:    coordinator.DirStore{Root: filepath.Join(*dir, "objects")},
		Key:      key,
		Pool:     coordinator.NewPool(*runners, *slots, nil),
		Runner:   runner,

		Credentials: mint,
		Audience:    *audience,
		AccountJobs: *accountJobs,
	})
	if err != nil {
		return err
	}
	jobs.Store(c)

	if clients != nil {
		clients.Handler = handler(c)
		h, err := clients.Start(ctx)
		if err != nil {
			return err
		}
		channelReady.Store(&h)
		log.Printf("client channel on %s%s, for device credentials of %d keys", *clientListen, channel.Path, len(clients.AccountKeys))
	}

	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()
	api, err := devAPI(c, keys, *test)
	if err != nil {
		return err
	}
	if api == nil {
		log.Printf("no dev API: with the vault's wrapping key, workers come only over the client channel")
		<-ctx.Done()
		<-done
		return nil
	}
	if *test {
		testReady.Store(&api)
	}
	srv := &http.Server{Handler: api, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()
	if *test {
		log.Printf("test API on http://%s behind its bearer token; test data only", *listen)
	} else {
		log.Printf("dev API on http://%s, no client authentication", *listen)
	}
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	<-done
	return nil
}

// devAPI is what --listen serves: the dev API, behind the test API's token
// with --test-api, or nil with the vault's wrapping key. The dev API opens
// any worker without a device list, and a coordinator with the vault's key
// must open a worker only to the devices its grant names.
func devAPI(c *coordinator.Coordinator, keys keyFlags, test bool) (http.Handler, error) {
	if keys.mode != keyDev {
		return nil, nil
	}
	if test {
		return testAPI(c.Handler())
	}
	return c.Handler(), nil
}

// serveBeyond serves h on ln, which may be beyond loopback, until ctx ends;
// it stops the coordinator if the listener fails.
func serveBeyond(ctx context.Context, stop func(), name string, ln net.Listener, h http.Handler) {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("%s listener: %v", name, err)
			stop()
		}
	}()
}

// The dev API has no client authentication, so it never listens beyond this
// machine.
func loopbackOnly(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("--listen %s: the dev API has no authentication, so it listens only on loopback", addr)
	}
	return nil
}

// devWrappingKey is --wrapping-key dev, standing in for the vault-held
// wrapping key (m4-cloud-runners.md §4): a file made on first run. Losing it
// loses every worker's files.
func devWrappingKey(path string) (coordinator.WrappingKey, error) {
	var key coordinator.WrappingKey
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if key, err = coordinator.NewWrappingKey(); err != nil {
			return key, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return key, err
		}
		return key, os.WriteFile(path, key[:], 0o600)
	case err != nil:
		return key, err
	case len(data) != coordinator.KeySize:
		return key, fmt.Errorf("%s is %d bytes, not a %d-byte key", path, len(data), coordinator.KeySize)
	}
	copy(key[:], data)
	return key, nil
}
