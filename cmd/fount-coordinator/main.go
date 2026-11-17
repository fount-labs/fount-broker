// Command fount-coordinator is the dev build of Fount Cloud's coordinator: it
// keeps Cloud workers' files under their keys, queues jobs and runs each with a
// local runner command. See package coordinator for what isn't built yet.
//
//	fount-coordinator --dir <folder> [--listen 127.0.0.1:8790] [--runners 2] [--slots 2]
//	  [--job-timeout 30m] -- <runner command...>
//	fount-coordinator --dir <folder> [flags] --runner-addr https://<domain> --runner-repo <owner/repo>
//	  [--credentials <file.json>] [--test-api --listen 0.0.0.0:8790]
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
// --test-api lets the dev API listen beyond loopback behind a bearer token in
// $FOUNT_TEST_API_TOKEN: the coordinator enclave's way in until the attested
// client channel (m4-cloud-runners.md §7, P2). Test data only, while the
// wrapping key is the dev one.
package main

import (
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
	"syscall"
	"time"

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
	listen := flag.String("listen", "127.0.0.1:8790", "loopback address for the dev API")
	runners := flag.Int("runners", 2, "runners in the pool")
	slots := flag.Int("slots", 2, "jobs at once per runner")
	timeout := flag.Duration("job-timeout", 30*time.Minute, "longest a job may run")
	runnerAddr := flag.String("runner-addr", "", "a runner enclave broker's origin, https://<domain>, in place of a runner command")
	credentials := flag.String("credentials", "", "JSON file of every job's broker credentials, with --runner-addr")
	test := flag.Bool("test-api", false, "listen beyond loopback, behind the bearer token in $"+testTokenEnv+"; test data only")
	runnerRepo := flag.String("runner-repo", os.Getenv("FOUNT_RUNNER_REPO"), "GitHub repository whose releases the runner enclave must run, or unattested")
	flag.Parse()
	if *dir == "" || (flag.NArg() == 0) == (*runnerAddr == "") {
		return errors.New("usage: fount-coordinator --dir <folder> [flags] (-- <runner command...> | --runner-addr <host:port>)")
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
	key, err := devWrappingKey(filepath.Join(*dir, "wrapping.key"))
	if err != nil {
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
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	api := c.Handler()
	if *test {
		if api, err = testAPI(api); err != nil {
			return err
		}
	}
	srv := &http.Server{Addr: *listen, Handler: api, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()
	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()
	if *test {
		log.Printf("test API on http://%s behind its bearer token; test data only", *listen)
	} else {
		log.Printf("dev API on http://%s, no client authentication", *listen)
	}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	<-done
	return nil
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

// devWrappingKey stands in for the vault-held wrapping key (m4-cloud-runners.md
// §4): a file made on first run. Losing it loses every worker's files.
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
