//go:build !dev

package main

import "errors"

// The runner's job listener is plain TCP until the coordinator's channel is
// attested, so release builds leave it out.
func runner([]string) error {
	return errors.New("the runner enclave's broker is only in dev builds for now")
}
