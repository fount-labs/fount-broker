package coordinator

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// ErrInvalid is a request the coordinator refuses for its shape: a bad ID,
// path or field.
var ErrInvalid = errors.New("invalid")

var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// checkID accepts the IDs the coordinator puts in paths and object names:
// workers, accounts, threads, sessions and jobs.
func checkID(kind, id string) error {
	if !idPattern.MatchString(id) {
		return fmt.Errorf("%w: %s id %q: use 1 to 64 letters, digits, '_' or '-'", ErrInvalid, kind, id)
	}
	return nil
}

const (
	maxPathBytes    = 1024
	maxPathSegments = 32
	maxSegmentBytes = 255
)

// checkPath accepts a relative path inside a worker's tree: slash-separated, no
// empty, "." or ".." segments, no backslashes and no control characters. Paths
// come from clients and from runners, which are assumed hostile.
func checkPath(p string) error {
	if p == "" || len(p) > maxPathBytes {
		return fmt.Errorf("%w: path must be 1 to %d bytes", ErrInvalid, maxPathBytes)
	}
	segments := strings.Split(p, "/")
	if len(segments) > maxPathSegments {
		return fmt.Errorf("%w: path %q is more than %d folders deep", ErrInvalid, p, maxPathSegments)
	}
	for _, s := range segments {
		if s == "" || s == "." || s == ".." || len(s) > maxSegmentBytes {
			return fmt.Errorf("%w: path %q has an empty, '.', '..' or overlong part", ErrInvalid, p)
		}
		if strings.ContainsRune(s, '\\') || strings.ContainsFunc(s, unicode.IsControl) {
			return fmt.Errorf("%w: path %q has a backslash or control character", ErrInvalid, p)
		}
	}
	return nil
}
