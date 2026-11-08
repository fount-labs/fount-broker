package verify

import (
	"path/filepath"
	"strings"
)

// Confined is true where the verifier runs under an OS sandbox.
const Confined = true

// confine wraps the verifier in sandbox-exec with a profile that denies
// everything but running its own binary: no network, no files beyond the
// system libraries, no writes.
func confine(exe string, args ...string) (string, []string) {
	// The sandbox matches real paths, and /var is a link to /private/var.
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return "/usr/bin/sandbox-exec", append([]string{"-p", profile(exe), exe}, args...)
}

func profile(exe string) string {
	q := `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(exe) + `"`
	return "(version 1)\n" +
		"(deny default)\n" +
		"(allow process-exec (literal " + q + "))\n" +
		"(allow file-read* (literal " + q + "))\n" +
		"(allow file-read* (literal \"/\"))\n" +
		"(allow file-read-metadata)\n" +
		"(allow file-map-executable)\n" +
		"(allow sysctl-read)\n" +
		"(allow signal (target self))\n" +
		"(allow file-read* (subpath \"/usr/lib\") (subpath \"/System/Library\") (subpath \"/System/Volumes/Preboot/Cryptexes\"))\n"
}
