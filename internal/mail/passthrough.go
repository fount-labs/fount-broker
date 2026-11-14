package mail

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Passthrough ops carry a Device API request the app has already authorized:
// most are signed by a device key, and recovery and pause are approved by a
// passkey assertion in the body. The broker fixes each op's method and path,
// because the signature or the edge's challenge covers them, and sends it only
// to the attested edge. OpLicenseEntitlement goes to Fount's API instead and
// is served by package broker, which holds the license.
const (
	OpHandle             = "handle"            // GET /handle/{path}
	OpMailbox            = "mailbox"           // POST /mailbox
	OpAddress            = "address"           // POST /address
	OpRouting            = "routing"           // PUT /routing
	OpConnect            = "connect"           // POST /connect
	OpSend               = "send"              // POST /send
	OpRenew              = "renew"             // POST /entitlement
	OpRecoverChallenge   = "recover_challenge" // GET /recover/{mailbox}?kc={path}
	OpRecover            = "recover"           // POST /recover
	OpPauseChallenge     = "pause_challenge"   // GET /pause/{mailbox}?paused={path}
	OpPause              = "pause"             // POST /pause
	OpLicenseEntitlement = "license_entitlement"
)

// auth is what authorizes an op at the edge, and so which headers it carries.
type auth int

const (
	// authSigned ops carry a device signature: timestamp, nonce and signature.
	authSigned auth = iota
	// authNone ops are the edge's unsigned challenge requests, and carry no
	// headers. A challenge is an opaque MAC, so asking for one proves nothing.
	authNone
	// authPasskey ops are approved by a passkey assertion in the body. The edge
	// wants a fresh timestamp and nonce but no signature, since the device that
	// would sign may be the one that was lost.
	authPasskey
)

type passOp struct {
	method, path string
	// perMailbox ops name their mailbox. A signed or passkey op's mailbox must
	// be its Fount-Key-Id; a challenge's goes in its path. The others are
	// authorized by an entitlement and name none.
	perMailbox bool
	auth       auth
	// query, for a challenge, is the query parameter its path fills, and
	// valid checks that value.
	query string
	valid func(string) bool
	// maxBody bounds the request body. Zero means MaxPassBody.
	maxBody int
}

var passOps = map[string]passOp{
	OpHandle:  {method: http.MethodGet, path: "/handle/"},
	OpMailbox: {method: http.MethodPost, path: "/mailbox"},
	OpAddress: {method: http.MethodPost, path: "/address", perMailbox: true},
	OpRouting: {method: http.MethodPut, path: "/routing", perMailbox: true},
	OpConnect: {method: http.MethodPost, path: "/connect", perMailbox: true},
	OpSend:    {method: http.MethodPost, path: "/send", perMailbox: true, maxBody: MaxSendBody},
	OpRenew:   {method: http.MethodPost, path: "/entitlement", perMailbox: true},
	OpRecoverChallenge: {method: http.MethodGet, path: "/recover/", perMailbox: true, auth: authNone,
		query: "kc", valid: func(v string) bool { return validHex(v, 32) }},
	OpRecover: {method: http.MethodPost, path: "/recover", perMailbox: true, auth: authPasskey},
	OpPauseChallenge: {method: http.MethodGet, path: "/pause/", perMailbox: true, auth: authNone,
		query: "paused", valid: func(v string) bool { return v == "true" || v == "false" }},
	OpPause: {method: http.MethodPost, path: "/pause", perMailbox: true, auth: authPasskey},
}

// IsPassthrough reports whether op is a pre-signed edge write.
func IsPassthrough(op string) bool {
	_, ok := passOps[op]
	return ok
}

// Signature headers the broker forwards. Nothing else the app names reaches
// the edge.
const (
	HeaderKeyID       = "Fount-Key-Id"
	HeaderTimestamp   = "Fount-Timestamp"
	HeaderNonce       = "Fount-Nonce"
	HeaderSignature   = "Fount-Signature"
	HeaderEntitlement = "Fount-Entitlement"
)

var forwarded = []string{HeaderKeyID, HeaderTimestamp, HeaderNonce, HeaderSignature, HeaderEntitlement}

const (
	// MaxPassBody bounds a passthrough request and its reply.
	MaxPassBody = 64 << 10
	// MaxSendBody bounds a send request, which carries a whole message in
	// base64: up to 25 MiB (Gmail's limit), room for a reply with its files
	// attached. It is the edge's POST /send body limit.
	MaxSendBody = 34 << 20
	// maxHeaderValue bounds one signature header. An entitlement token is the
	// longest, well under this.
	maxHeaderValue = 4 << 10
)

// handlePattern is the edge's validHandle alphabet and length. The edge
// refuses reserved names itself.
var handlePattern = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

// Result is a passthrough op's answer: the remote status and its JSON body,
// whatever the status. A broker failure is an error frame instead.
type Result struct {
	Status int `json:"status"`
	// Body is the reply's JSON, null when empty, or a JSON string holding a
	// reply that isn't JSON.
	Body       json.RawMessage `json:"body"`
	RetryAfter *uint64         `json:"retry_after,omitempty"`
}

// ReadResult reads resp, at most MaxPassBody bytes, into a Result and closes it.
func ReadResult(resp *http.Response) (*Result, error) {
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxPassBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxPassBody {
		return nil, fmt.Errorf("%w: answered %d with more than %d bytes", ErrEdge, resp.StatusCode, MaxPassBody)
	}
	r := &Result{Status: resp.StatusCode}
	switch trimmed := bytes.TrimSpace(body); {
	case len(trimmed) == 0:
	case json.Valid(trimmed):
		r.Body = json.RawMessage(trimmed)
	default:
		r.Body, _ = json.Marshal(strings.ToValidUTF8(string(body), "�"))
	}
	if s, err := strconv.ParseUint(strings.TrimSpace(resp.Header.Get("Retry-After")), 10, 32); err == nil {
		r.RetryAfter = &s
	}
	return r, nil
}

// Passthrough sends one pre-authorized request to the edge. mailbox is the hex
// mailbox id for every op but handle and mailbox, where it's empty. path is
// the handle name for handle, the hex kc for recover_challenge, "true" or
// "false" for pause_challenge, and empty otherwise.
func (s *Service) Passthrough(ctx context.Context, op, mailbox, path string, headers map[string]string, body []byte) (*Result, error) {
	p, ok := passOps[op]
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a passthrough op", ErrRequest, op)
	}
	switch {
	case p.perMailbox && !validHex(mailbox, 32):
		return nil, fmt.Errorf("%w: %s needs a mailbox of 64 lowercase hex characters", ErrRequest, op)
	case !p.perMailbox && mailbox != "":
		return nil, fmt.Errorf("%w: %s names no mailbox", ErrRequest, op)
	}
	urlPath := p.path
	switch {
	case op == OpHandle:
		if !handlePattern.MatchString(path) {
			return nil, fmt.Errorf("%w: handle takes a name of 1 to 64 lowercase letters, digits and hyphens as its path", ErrRequest)
		}
		urlPath += path
	case p.query != "":
		if !p.valid(path) {
			return nil, fmt.Errorf("%w: %s's path isn't a valid %s", ErrRequest, op, p.query)
		}
		urlPath += mailbox + "?" + p.query + "=" + path
	case path != "":
		return nil, fmt.Errorf("%w: %s takes no path", ErrRequest, op)
	}
	if p.method == http.MethodGet && len(body) > 0 {
		return nil, fmt.Errorf("%w: %s takes no body", ErrRequest, op)
	}
	maxBody := p.maxBody
	if maxBody == 0 {
		maxBody = MaxPassBody
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("%w: %s body is over %d bytes", ErrRequest, op, maxBody)
	}
	if len(body) > 0 && !json.Valid(body) {
		return nil, fmt.Errorf("%w: %s body is not JSON", ErrRequest, op)
	}
	h, err := authHeaders(p.auth, op, headers)
	if err != nil {
		return nil, err
	}
	if p.auth != authNone && h.Get(HeaderKeyID) != mailbox {
		if p.perMailbox {
			return nil, fmt.Errorf("%w: %s must equal the mailbox", ErrRequest, HeaderKeyID)
		}
		return nil, fmt.Errorf("%w: %s is signed by an entitlement and takes no %s", ErrRequest, op, HeaderKeyID)
	}

	req, err := http.NewRequestWithContext(ctx, p.method, s.c.edge.Base()+urlPath[1:], bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header = h
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.c.edge.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	return ReadResult(resp)
}

// authHeaders checks the app's headers for an op authorized by a: none for a
// challenge; otherwise only the forwarded names, each once, with a short
// printable value, a timestamp and nonce, and a signature exactly when the op
// is signed. A passkey op takes no entitlement either.
func authHeaders(a auth, op string, in map[string]string) (http.Header, error) {
	if a == authNone {
		if len(in) > 0 {
			return nil, fmt.Errorf("%w: %s is unsigned and takes no headers", ErrRequest, op)
		}
		return http.Header{}, nil
	}
	h, err := forwardedHeaders(in)
	if err != nil {
		return nil, err
	}
	required := []string{HeaderTimestamp, HeaderNonce}
	if a == authSigned {
		required = append(required, HeaderSignature)
	} else {
		for _, name := range []string{HeaderSignature, HeaderEntitlement} {
			if h.Get(name) != "" {
				return nil, fmt.Errorf("%w: %s is approved by a passkey and takes no %s", ErrRequest, op, name)
			}
		}
	}
	for _, name := range required {
		if h.Get(name) == "" {
			return nil, fmt.Errorf("%w: %s needs %s", ErrRequest, op, name)
		}
	}
	return h, nil
}

// forwardedHeaders checks that in names only forwarded headers, each once,
// with a short printable value.
func forwardedHeaders(in map[string]string) (http.Header, error) {
	h := http.Header{}
	for name, value := range in {
		canon := http.CanonicalHeaderKey(name)
		if !slices.Contains(forwarded, canon) {
			return nil, fmt.Errorf("%w: header %q is not forwarded", ErrRequest, name)
		}
		if h.Get(canon) != "" {
			return nil, fmt.Errorf("%w: header %q given twice", ErrRequest, canon)
		}
		if value == "" || len(value) > maxHeaderValue || !printable(value) {
			return nil, fmt.Errorf("%w: header %q must be 1 to %d printable ASCII characters", ErrRequest, canon, maxHeaderValue)
		}
		h.Set(canon, value)
	}
	return h, nil
}

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// LicenseEntitlementRequest reads the app's license_entitlement body,
// {"deviceKey":"<std base64 Ed25519 public key>"}, and returns the key as sent.
// A licenseKey field is refused; the broker sends its license credential as
// Bearer instead.
func LicenseEntitlementRequest(body []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var in struct {
		DeviceKey *string `json:"deviceKey"`
	}
	if err := dec.Decode(&in); err != nil || dec.More() || in.DeviceKey == nil {
		return "", fmt.Errorf(`%w: license_entitlement takes {"deviceKey":"<base64>"} and nothing else`, ErrRequest)
	}
	key, err := base64.StdEncoding.DecodeString(*in.DeviceKey)
	if err != nil || len(key) != 32 {
		return "", fmt.Errorf("%w: deviceKey must be a 32-byte Ed25519 public key in standard base64", ErrRequest)
	}
	return *in.DeviceKey, nil
}
