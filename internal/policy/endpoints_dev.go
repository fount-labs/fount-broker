//go:build dev

package policy

import (
	"os"
	"strings"
)

// A dev build can point at a staging backend. FOUNT_BROKER_FOUNT_API is the
// license API's base URL. FOUNT_BROKER_PROXY is the model proxy's origin, such
// as http://localhost:3000. FOUNT_BROKER_MAIL_EDGE is a dev edge's Device API
// origin, such as https://localhost:18443, reached without attestation and
// without checking its certificate. Release builds don't compile this file.

func FountAPIBase() string {
	if base := strings.TrimRight(os.Getenv("FOUNT_BROKER_FOUNT_API"), "/"); base != "" {
		return base + "/"
	}
	return fountAPIBase
}

func FountProxyBase() string {
	if origin := strings.TrimRight(os.Getenv("FOUNT_BROKER_PROXY"), "/"); origin != "" {
		return origin + "/proxy/"
	}
	return fountProxyBase
}

// MailEdgeDev is a dev edge's origin, or "" to use the attested edge.
func MailEdgeDev() string {
	if origin := strings.TrimRight(os.Getenv("FOUNT_BROKER_MAIL_EDGE"), "/"); origin != "" {
		return origin + "/"
	}
	return ""
}

// CoordinatorDev is a coordinator's origin and the config repo it must run,
// from FOUNT_BROKER_COORDINATOR and FOUNT_BROKER_COORDINATOR_REPO, in place of
// CoordinatorOrigin and CoordinatorRepo: the test coordinator's, or
// "unattested" for a dev coordinator.
func CoordinatorDev() (origin, repo string) {
	return strings.TrimRight(os.Getenv("FOUNT_BROKER_COORDINATOR"), "/"), os.Getenv("FOUNT_BROKER_COORDINATOR_REPO")
}

// harnessRegistryDev is FOUNT_BROKER_REGISTRY, a dev registry's origin such as
// http://registry:5000, which then stands in for ghcr.io. Plain http is
// allowed: the supervisor checks every digest anyway.
func harnessRegistryDev() string {
	return strings.TrimRight(os.Getenv("FOUNT_BROKER_REGISTRY"), "/")
}
