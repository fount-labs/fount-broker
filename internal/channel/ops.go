package channel

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// CheckRequest accepts only the account API's operations
// (coordinator.AccountHandler), and returns the URL to send. target is the
// path without its leading slash, as the app gives it, with a query only on a
// file listing:
//
//	POST v1/workers                       GET v1/workers
//	GET  v1/workers/{id}                  POST v1/workers/{id}/grant
//	POST v1/workers/{id}/revoke           POST v1/workers/{id}/jobs
//	PUT  v1/workers/{id}/root/{path...}   GET  v1/workers/{id}/files?prefix=…
//	GET  v1/workers/{id}/files/{path...}  GET  v1/jobs/{id}
//
// The coordinator checks every path again; this keeps the broker from
// carrying anything else.
func CheckRequest(method, target string) (*url.URL, error) {
	u, err := checkRequest(method, target)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOperation, err)
	}
	return u, nil
}

// ErrOperation is a request the account API doesn't have. Nothing was sent.
var ErrOperation = errors.New("not a Cloud operation")

func checkRequest(method, target string) (*url.URL, error) {
	path, query, hasQuery := strings.Cut(target, "?")
	seg := strings.Split(path, "/")
	for _, s := range seg {
		if s == "" || s == "." || s == ".." || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f || r == '\\' }) {
			return nil, fmt.Errorf("path %q: empty, dot or control segment", target)
		}
	}
	ok := false
	listing := false
	if len(seg) >= 2 && seg[0] == "v1" {
		switch {
		case seg[1] == "workers" && len(seg) == 2:
			ok = method == http.MethodPost || method == http.MethodGet
		case seg[1] == "jobs" && len(seg) == 3:
			ok = method == http.MethodGet && jobID.MatchString(seg[2])
		case seg[1] == "workers" && workerID.MatchString(seg[2]):
			switch {
			case len(seg) == 3:
				ok = method == http.MethodGet
			case len(seg) == 4 && (seg[3] == "grant" || seg[3] == "revoke" || seg[3] == "jobs"):
				ok = method == http.MethodPost
			case len(seg) == 4 && seg[3] == "files":
				ok, listing = method == http.MethodGet, true
			case len(seg) > 4 && seg[3] == "files":
				ok = method == http.MethodGet
			case len(seg) > 4 && seg[3] == "root":
				ok = method == http.MethodPut
			}
		}
	}
	if !ok {
		return nil, fmt.Errorf("%s %s", method, target)
	}
	u := &url.URL{Scheme: "http", Host: host, Path: "/" + path}
	if hasQuery {
		q, err := url.ParseQuery(query)
		if !listing || err != nil || len(q) != 1 || len(q["prefix"]) != 1 {
			return nil, fmt.Errorf("path %q: only a file listing takes a query, prefix", target)
		}
		u.RawQuery = q.Encode()
	}
	return u, nil
}

var (
	workerID = regexp.MustCompile(`^w_[0-9a-f]{24}$`)
	jobID    = regexp.MustCompile(`^j_[0-9a-f]{24}$`)
)
