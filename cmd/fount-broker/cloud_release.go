//go:build !dev

package main

import (
	"github.com/fount-labs/fount-broker/internal/link"
	"github.com/fount-labs/fount-broker/internal/policy"
)

// coordinator is the policy's coordinator and the config repo it must run.
func coordinator() (origin, repo string) { return policy.CoordinatorOrigin, policy.CoordinatorRepo }

func coordinatorCheck(repo string) (link.Checker, error) { return link.TinfoilChecker(repo) }
