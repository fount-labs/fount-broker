//go:build dev

package main

import (
	"log"

	"github.com/fount-labs/fount-broker/internal/link"
	"github.com/fount-labs/fount-broker/internal/policy"
)

// coordinator is FOUNT_BROKER_COORDINATOR and its repo, or the policy's.
func coordinator() (origin, repo string) {
	if origin, repo := policy.CoordinatorDev(); origin != "" {
		return origin, repo
	}
	return policy.CoordinatorOrigin, policy.CoordinatorRepo
}

// coordinatorCheck checks a coordinator built from repo; "unattested" takes
// a dev coordinator's document, which no hardware vouches for.
func coordinatorCheck(repo string) (link.Checker, error) {
	if repo == "unattested" {
		log.Printf("the coordinator's channel is unattested: nothing vouches for it")
		side, err := link.Unattested()
		if err != nil {
			return nil, err
		}
		return side.Check, nil
	}
	return link.TinfoilChecker(repo)
}
