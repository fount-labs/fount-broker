package policy

import (
	"fmt"
	"strings"
)

// The runner enclave's broker fetches the closed harness image, pinned by
// digest in the supervisor's measured config, from this registry only
// (m4-cloud-runners.md §5.1c). GitHub's registry hands blobs off to its CDN.
const HarnessRegistry = "ghcr.io"

var HarnessRegistryRedirectHosts = []string{"pkg-containers.githubusercontent.com"}

// HarnessRegistryBase is the origin to pull an image on host from, or an error
// when the policy doesn't allow that registry.
func HarnessRegistryBase(host string) (string, error) {
	if dev := harnessRegistryDev(); dev != "" {
		if host != hostOf(dev) {
			return "", fmt.Errorf("registry %s isn't the dev registry %s", host, dev)
		}
		return dev, nil
	}
	if host != HarnessRegistry {
		return "", fmt.Errorf("registry %s isn't %s", host, HarnessRegistry)
	}
	return "https://" + host, nil
}

func hostOf(origin string) string {
	_, host, _ := strings.Cut(origin, "://")
	return host
}
