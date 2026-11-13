// Command fount-coordinator is the dev build of Fount Cloud's coordinator: it
// keeps Cloud workers' files under their keys, queues jobs and runs each with a
// local runner command. See package coordinator for what isn't built yet.
//
//	fount-coordinator --dir <folder> [--listen 127.0.0.1:8790] [--runners 2] [--slots 2]
//	  [--job-timeout 30m] -- <runner command...>
//
// The runner command is started once per job with fount-runner's --workspace,
// --job, --data and --index added: fount-runner itself, or scripts/dev-runner.sh
// for the runner image in Docker.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/fount-labs/fount-broker/internal/coordinator"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetPrefix("fount-coordinator: ")
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
	flag.Parse()
	if *dir == "" || flag.NArg() == 0 {
		return errors.New("usage: fount-coordinator --dir <folder> [flags] -- <runner command...>")
	}
	if err := loopbackOnly(*listen); err != nil {
		return err
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
		Runner:   coordinator.LocalRunner{Command: flag.Args(), Timeout: *timeout},
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv := &http.Server{Addr: *listen, Handler: c.Handler(), ReadHeaderTimeout: 10 * time.Second}
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
	log.Printf("dev API on http://%s, no client authentication", *listen)
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
