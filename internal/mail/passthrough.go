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

// Passthrough ops carry a Device API write the app has already signed. The
// broker fixes each op's method and path, because the signature covers them,
// and sends it only to the attested edge. OpLicenseEntitlement goes to Fount's
// API instead and is served by package broker, which holds the license.
const (
	OpHandle             = "handle"  // GET /handle/{path}
	OpMailbox            = "mailbox" // POST /mailbox
	OpAddress            = "address" // POST /address
	OpRouting            = "routing" // PUT /routing
	OpRenew              = "renew"   // POST /entitlement
	OpLicenseEntitlement = "license_entitlement"
)

type passOp struct {
	method, path string
	// perMailbox ops name their mailbox, which must be the Fount-Key-Id the
	// app signed with. The others are authorized by an entitlement and name
	// none.
	perMailbox bool
}

var passOps = map[string]passOp{
	OpHandle:  {method: http.MethodGet, path: "/handle/"},
	OpMailbox: {method: http.MethodPost, path: "/mailbox"},
	OpAddress: {method: http.MethodPost, path: "/address", perMailbox: true},
	OpRouting: {method: http.MethodPut, path: "/routing", perMailbox: true},
	OpRenew:   {method: http.MethodPost, path: "/entitlement", perMailbox: true},
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

// Passthrough sends one pre-signed write to the edge. mailbox is the hex
// mailbox id for address, routing and renew, and empty for handle and
// mailbox; path is the handle name for handle, and empty otherwise.
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
	if op == OpHandle {
		if !handlePattern.MatchString(path) {
			return nil, fmt.Errorf("%w: handle takes a name of 1 to 64 lowercase letters, digits and hyphens as its path", ErrRequest)
		}
		urlPath += path
	} else if path != "" {
		return nil, fmt.Errorf("%w: %s takes no path", ErrRequest, op)
	}
	if p.method == http.MethodGet && len(body) > 0 {
		return nil, fmt.Errorf("%w: %s takes no body", ErrRequest, op)
	}
	if len(body) > MaxPassBody {
		return nil, fmt.Errorf("%w: body is over %d bytes", ErrRequest, MaxPassBody)
	}
	if len(body) > 0 && !json.Valid(body) {
		return nil, fmt.Errorf("%w: %s body is not JSON", ErrRequest, op)
	}
	h, err := signatureHeaders(headers)
	if err != nil {
		return nil, err
	}
	if h.Get(HeaderKeyID) != mailbox {
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

// signatureHeaders checks the app's headers: only the forwarded names, each
// once, with a short printable value, and a timestamp, nonce and signature.
func signatureHeaders(in map[string]string) (http.Header, error) {
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
	for _, name := range []string{HeaderTimestamp, HeaderNonce, HeaderSignature} {
		if h.Get(name) == "" {
			return nil, fmt.Errorf("%w: the request isn't signed: %s is missing", ErrRequest, name)
		}
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
// The broker adds the license itself.
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
