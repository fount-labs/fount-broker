//go:build !dev

package main

import (
	"github.com/fount-labs/fount-broker/internal/channel"
	"github.com/fount-labs/fount-broker/internal/link"
	"github.com/fount-labs/fount-broker/internal/policy"
)

// coordinator is the policy's coordinator and the config repo it must run.
func coordinator() (origin, repo string) { return policy.CoordinatorOrigin, policy.CoordinatorRepo }

// coordinatorCheck checks a coordinator built from repo, for its channel key.
func coordinatorCheck(repo string) (link.KeyChecker, error) {
	return link.TinfoilKeyChecker(repo, channel.KeyID)
}
