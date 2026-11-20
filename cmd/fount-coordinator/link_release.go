//go:build !dev

package main

import (
	"errors"

	"github.com/fount-labs/fount-broker/internal/link"
)

// linkSide is the coordinator's end of the link, checking a runner built from
// repo.
func linkSide(repo string) (*link.Side, error) {
	if repo == "" {
		return nil, errors.New("a runner enclave (--runner-addr, --runners-dial-in) needs --runner-repo")
	}
	return link.Tinfoil(repo)
}
