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
