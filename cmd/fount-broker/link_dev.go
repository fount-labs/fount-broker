//go:build dev

package main

import (
	"errors"
	"log"

	"github.com/fount-labs/fount-broker/internal/link"
)

// linkSide is the runner's end of the link, checking a coordinator built
// from repo; "unattested" is a link no hardware vouches for, for a coordinator
// that isn't in an enclave.
func linkSide(repo string) (*link.Side, error) {
	switch repo {
	case "":
		return nil, errors.New("runner needs --coordinator-repo (or unattested, in a dev build)")
	case "unattested":
		log.Printf("the coordinator's link is unattested: nothing vouches for either end")
		return link.Unattested()
	}
	return link.Tinfoil(repo)
}
