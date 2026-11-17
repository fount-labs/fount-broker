//go:build !dev

package main

import (
	"errors"

	"github.com/fount-labs/fount-broker/internal/link"
)

// linkSide is the runner's end of the link, checking a coordinator built
// from repo.
func linkSide(repo string) (*link.Side, error) {
	if repo == "" {
		return nil, errors.New("runner needs --coordinator-repo")
	}
	return link.Tinfoil(repo)
}
