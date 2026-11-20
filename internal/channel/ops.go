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
// file listing or a thread's changes:
//
//	POST v1/workers                       GET v1/workers
//	GET  v1/workers/{id}                  POST v1/workers/{id}/grant
//	POST v1/workers/{id}/revoke           POST v1/workers/{id}/jobs
//	PUT  v1/workers/{id}/root/{path...}   GET  v1/workers/{id}/files?prefix=…
//	GET  v1/workers/{id}/files/{path...}  GET  v1/jobs/{id}
//	GET  v1/workers/{id}/threads          GET  v1/workers/{id}/threads/{tid}[?since=N]
//	POST v1/workers/{id}/threads/{tid}/ops  POST v1/workers/{id}/ops
//	GET  v1/workers/{id}/mail             PUT  v1/workers/{id}/mail
//	GET  v1/teams/{team}/log[?since=N]    POST v1/teams/{team}/log
//	POST v1/teams                         GET  v1/teams
//	PUT  v1/workers/{id}/threads/{tid}/drafts/{draft}/files/{path...}?rev=N
//	POST v1/teams/{team}/invites/{invite}/{open,accept,send}
//	POST v1/teams/{team}/passkey-join     POST v1/teams/{team}/passkey-join/challenge
//	POST v1/teams/{team}/passkey-vouch
//
// The v2 grant and revoke routes stay, so Desktop hears they are retired
// (410) rather than that the broker refused them.
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
	listing, changes, draftRev := false, false, false
	if len(seg) >= 2 && seg[0] == "v1" {
		switch {
		case seg[1] == "workers" && len(seg) == 2:
			ok = method == http.MethodPost || method == http.MethodGet
		case seg[1] == "teams" && len(seg) == 2:
			ok = method == http.MethodPost || method == http.MethodGet
		case seg[1] == "teams" && len(seg) >= 4 && teamID.MatchString(seg[2]):
			ok, changes = teamOp(method, seg[3:])
		case seg[1] == "jobs" && len(seg) == 3:
			ok = method == http.MethodGet && jobID.MatchString(seg[2])
		case seg[1] == "workers" && workerID.MatchString(seg[2]):
			switch {
			case len(seg) == 3:
				ok = method == http.MethodGet
			case len(seg) == 4 && (seg[3] == "grant" || seg[3] == "revoke" || seg[3] == "jobs" || seg[3] == "ops"):
				ok = method == http.MethodPost
			case len(seg) == 4 && seg[3] == "threads":
				ok = method == http.MethodGet
			case len(seg) == 4 && seg[3] == "mail":
				ok = method == http.MethodGet || method == http.MethodPut
			case len(seg) == 5 && seg[3] == "threads" && threadID.MatchString(seg[4]):
				ok, changes = method == http.MethodGet, true
			case len(seg) == 6 && seg[3] == "threads" && threadID.MatchString(seg[4]) && seg[5] == "ops":
				ok = method == http.MethodPost
			case len(seg) > 8 && seg[3] == "threads" && threadID.MatchString(seg[4]) && seg[5] == "drafts" && entryID.MatchString(seg[6]) && seg[7] == "files":
				ok, draftRev = method == http.MethodPut, true
			case len(seg) == 4 && seg[3] == "files":
				ok, listing = method == http.MethodGet, true
			case len(seg) > 4 && seg[3] == "files":
				ok = method == http.MethodGet
			case len(seg) > 4 && seg[3] == "root":
				ok = method == http.MethodPut
			}
		}
	}
	if !ok || draftRev && !hasQuery {
		return nil, fmt.Errorf("%s %s", method, target)
	}
	u := &url.URL{Scheme: "http", Host: host, Path: "/" + path}
	if hasQuery {
		q, err := url.ParseQuery(query)
		switch {
		case err != nil || len(q) != 1:
			return nil, fmt.Errorf("path %q: one query parameter at most", target)
		case listing && len(q["prefix"]) == 1:
		case changes && len(q["since"]) == 1 && revision.MatchString(q.Get("since")):
		case draftRev && len(q["rev"]) == 1 && revision.MatchString(q.Get("rev")):
		default:
			return nil, fmt.Errorf("path %q: only a file listing takes a query, prefix; a thread or team log, since; and a draft file's save, rev", target)
		}
		u.RawQuery = q.Encode()
	}
	return u, nil
}

// teamOp is one of a team's routes, after v1/teams/{team}/; changes is a
// team log's read, which takes since.
func teamOp(method string, rest []string) (ok, changes bool) {
	post := method == http.MethodPost
	switch {
	case len(rest) == 1 && rest[0] == "log":
		return post || method == http.MethodGet, method == http.MethodGet
	case len(rest) == 3 && rest[0] == "invites" && teamID.MatchString(rest[1]):
		return post && (rest[2] == "open" || rest[2] == "accept" || rest[2] == "send"), false
	case len(rest) == 1 && (rest[0] == "passkey-join" || rest[0] == "passkey-vouch"):
		return post, false
	case len(rest) == 2 && rest[0] == "passkey-join" && rest[1] == "challenge":
		return post, false
	}
	return false, false
}

var (
	workerID = regexp.MustCompile(`^w_[0-9a-f]{24}$`)
	jobID    = regexp.MustCompile(`^j_[0-9a-f]{24}$`)
	threadID = regexp.MustCompile(`^thr_[0-9a-f]{24}$`)
	entryID  = regexp.MustCompile(`^ent_[0-9a-f]{24}$`)
	revision = regexp.MustCompile(`^[0-9]{1,20}$`)
	// teamID is coordinator.checkID's: a team's id is its account's or one
	// the coordinator made.
	teamID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)
