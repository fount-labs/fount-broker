//go:build dev

package main

import (
	"errors"
	"log"

	"github.com/fount-labs/fount-broker/internal/link"
)

// linkSide is the coordinator's end of the link, checking a runner built from
// repo; "unattested" is a link no hardware vouches for, to a dev build's
// runner.
func linkSide(repo string) (*link.Side, error) {
	switch repo {
	case "":
		return nil, errors.New("a runner enclave (--runner-addr, --runners-dial-in) needs --runner-repo (or unattested, in a dev build)")
	case "unattested":
		log.Printf("the runner's link is unattested: nothing vouches for either end")
		return link.Unattested()
	}
	return link.Tinfoil(repo)
}
