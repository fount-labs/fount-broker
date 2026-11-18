//go:build dev

package main

import (
	"log"

	"github.com/fount-labs/fount-broker/internal/channel"
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

// coordinatorCheck checks a coordinator built from repo, for its channel
// key; "unattested" takes a dev coordinator's document, which no hardware
// vouches for.
func coordinatorCheck(repo string) (link.KeyChecker, error) {
	if repo == "unattested" {
		log.Printf("the coordinator's channel is unattested: nothing vouches for it")
		return link.CheckUnattestedKey, nil
	}
	return link.TinfoilKeyChecker(repo, channel.KeyID)
}
