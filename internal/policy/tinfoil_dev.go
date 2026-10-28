//go:build dev

package policy

import (
	"os"
	"strings"
)

// TinfoilProxyBase lets a dev build point at a local or staging proxy with
// FOUNT_BROKER_TINFOIL_PROXY, an origin such as http://localhost:3000. Release
// builds don't compile this file.
func TinfoilProxyBase() string {
	if origin := strings.TrimRight(os.Getenv("FOUNT_BROKER_TINFOIL_PROXY"), "/"); origin != "" {
		return origin + "/proxy/v1/"
	}
	return tinfoilProxyBase
}
