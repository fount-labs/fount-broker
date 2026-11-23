package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/fount-labs/fount-broker/internal/coordinator"
	"github.com/fount-labs/fount-broker/internal/volume"
)

// volumeFlags is --volume: the Tinfoil encrypted volume --dir is on, which
// the coordinator opens itself before it reads --dir. Without it, --dir on
// Tinfoil is enclave memory, and a boot starts from nothing: coordinator-a
// lost its wrapping key, workers and mail generation on every boot until
// 2026-11-23.
type volumeFlags struct {
	name string
	// mode is --wrapping-key; with dev, the key derives from authority, the
	// --mail-generation-authority seed.
	mode      string
	authority string
	// dial stands in for the control socket in tests.
	dial func(ctx context.Context, path string) (net.Conn, error)
}

var mountName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

func (f volumeFlags) check() error {
	if f.name == "" {
		return nil
	}
	if !mountName.MatchString(f.name) {
		return fmt.Errorf("--volume %q: a mount name from tinfoil-config.yml's volumes", f.name)
	}
	if f.mode == keyDev && !strings.HasPrefix(f.authority, "env:") {
		// A seed made on first run would be a file on the volume it opens.
		return errors.New("--volume with --wrapping-key dev needs --mail-generation-authority env:NAME: the dev volume key derives from that seed")
	}
	return nil
}

// devKey is the dev volume key, nil without --volume or with the vault's key,
// whose volume opens once a vault releases the wrapping key.
func (f volumeFlags) devKey() ([]byte, error) {
	if f.name == "" || f.mode != keyDev {
		return nil, nil
	}
	seed, err := devSeed(f.authority)
	if err != nil {
		return nil, fmt.Errorf("--volume: %w", err)
	}
	defer clear(seed)
	return coordinator.DevVolumeKey(seed), nil
}

// open opens the volume with key, trying again while the socket is missing
// or the volume fails, as long as it takes. A volume that refuses the key
// holds another coordinator's disk: that's volume.ErrRefused, final.
func (f volumeFlags) open(ctx context.Context, key []byte, status *keyStatus) error {
	defer clear(key)
	s := volume.Socket{Path: volume.SocketPath(f.name), Dial: f.dial}
	status.volume("opening", nil)
	for delay := time.Second; ; delay = min(2*delay, 30*time.Second) {
		opened, err := s.Open(ctx, key)
		if err == nil {
			status.volume(string(opened), nil)
			if opened == volume.Initialized {
				log.Printf("volume %s: a blank disk, initialized: this coordinator starts with no state", f.name)
			} else {
				log.Printf("volume %s unlocked", f.name)
			}
			return nil
		}
		if errors.Is(err, volume.ErrRefused) {
			status.volume("refused", err)
			return err
		}
		status.volume("opening", err)
		log.Printf("volume %s: %v; trying again in %s", f.name, err, delay)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
}

// openVolume opens the volume, or, once it's refused, serves /health and
// /status alone until stopped, saying why: exiting would only restart the
// container into the same refusal. Its error is nil when ctx ends.
func openVolume(ctx context.Context, f volumeFlags, key []byte, status *keyStatus) error {
	err := f.open(ctx, key, status)
	switch {
	case ctx.Err() != nil:
		return nil
	case errors.Is(err, volume.ErrRefused):
		log.Printf("volume %s: %v; serving /status alone until stopped", f.name, err)
		<-ctx.Done()
		return nil
	}
	return err
}
