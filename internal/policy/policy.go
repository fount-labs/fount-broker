// Package policy is the broker's compiled-in egress policy: every destination
// the app can name, where it goes, and which credential it carries. Nothing
// here can change at runtime, so the policy of a release is exactly what its
// source says.
package policy

import (
	"regexp"
	"slices"
)

// Credential names a secret the broker holds on the app's behalf.
type Credential string

const (
	CredentialNone    Credential = ""
	CredentialLicense Credential = "license"
	// CredentialTinfoilCacheSecret scopes Tinfoil's prompt cache to this
	// user. It is sealed into each request body, so the proxy never sees it.
	CredentialTinfoilCacheSecret Credential = "tinfoil_cache_secret"
)

// Credentials is every credential the app may hand the broker.
var Credentials = []Credential{CredentialLicense, CredentialTinfoilCacheSecret}

func KnownCredential(name string) bool {
	return slices.Contains(Credentials, Credential(name))
}

// Destination is one operation the app may ask for, by name.
type Destination struct {
	// Route is the transport that carries it.
	Route string
	// Method and Path are fixed; Path is relative to the route's base URL.
	Method string
	Path   string
	// Accept lists the Accept values the app may send.
	Accept []string
	// ContentType is sent with the body.
	ContentType string
	// Body is what the request body may hold.
	Body Body
	// Credential is sent as a bearer token.
	Credential Credential
	// IdempotencyKey sends a fresh random Idempotency-Key header, so the
	// server can drop a retried duplicate.
	IdempotencyKey bool
	// SHA256, when set, is the hex digest the response body must have. A
	// mismatch ends the reply with an integrity error instead of end.
	SHA256 string
}

const (
	RouteTinfoil = "tinfoil"
	// RouteFountAPI is Fount's license and feedback API.
	RouteFountAPI = "fount_api"
	// RouteFountProxy is Fount's model proxy, which adds Fount's provider key
	// and meters usage against the license.
	RouteFountProxy = "fount_proxy"
	// RouteModels serves embedding model files.
	RouteModels = "models"
)

var chatAccept = []string{"", "application/json", "text/event-stream"}

var Destinations = map[string]Destination{
	"tinfoil.chat_completions": {
		Route:       RouteTinfoil,
		Method:      "POST",
		Path:        "chat/completions",
		Accept:      chatAccept,
		ContentType: "application/json",
		Body:        Body{Kind: BodyOpaque},
		Credential:  CredentialLicense,
	},
	// Fount-hosted OpenRouter models. Unlike Tinfoil, OpenRouter and the
	// model provider can read these requests.
	"openrouter.chat_completions": {
		Route:       RouteFountProxy,
		Method:      "POST",
		Path:        "openrouter/v1/chat/completions",
		Accept:      chatAccept,
		ContentType: "application/json",
		Body:        Body{Kind: BodyOpaque},
		Credential:  CredentialLicense,
	},
	// Checks a license key and returns a signed certificate of its access.
	"fount.license_validate": {
		Route:       RouteFountAPI,
		Method:      "POST",
		Path:        "license/validate",
		Accept:      []string{"", "application/json"},
		ContentType: "application/json",
		Body: Body{Kind: BodyObject, MaxBytes: 256, Fields: map[string]Field{
			"licenseKey": {Types: []string{"string"}, Required: true, Pattern: licenseKeyPattern},
		}},
	},
	// A report the user writes and previews in the app before sending. A
	// chat report includes the conversation it is about.
	"fount.feedback_report": {
		Route:          RouteFountAPI,
		Method:         "POST",
		Path:           "feedback/v1/report",
		Accept:         []string{"", "application/json"},
		ContentType:    "application/json",
		IdempotencyKey: true,
		Body: Body{Kind: BodyObject, MaxBytes: 2 << 20, Fields: map[string]Field{
			"source":                 {Types: []string{"string"}, Required: true, Pattern: regexp.MustCompile(`^(report-button|support-button)$`)},
			"client":                 {Types: []string{"object"}, Required: true},
			"install_id":             {Types: []string{"string"}, Required: true},
			"submitted_at":           {Types: []string{"string"}, Required: true},
			"session_id":             {Types: []string{"string", "null"}},
			"session_messages_count": {Types: []string{"number"}},
			"target_message_id":      {Types: []string{"string", "null"}},
			"target_message_index":   {Types: []string{"number", "null"}},
			"comment":                {Types: []string{"string", "null"}},
			"reply_email":            {Types: []string{"string", "null"}},
			"conversation":           {Types: []string{"object"}},
			"active_model":           {Types: []string{"object", "null"}},
			"chat_mode":              {Types: []string{"string", "null"}},
			"errors":                 {Types: []string{"array"}},
		}},
	},
}

var licenseKeyPattern = regexp.MustCompile(`^[A-Z0-9-]{1,64}$`)

// Routes is every route a status request may name.
var Routes = []string{RouteTinfoil, RouteModels}

// Tinfoil inference goes through Fount's proxy, which attaches Fount's Tinfoil
// key and meters usage. The proxy sees only ciphertext: bodies are sealed to
// a router the broker attested itself.
const TinfoilRouterRepo = "tinfoilsh/confidential-model-router"

// Release endpoints. A dev build can override the first two; see
// endpoints_dev.go.
const (
	fountAPIBase   = "https://api.fount.sh/"
	fountProxyBase = "https://api.fount.sh/proxy/"
	ModelsBase     = "https://fount-embedding-models.s3.us-east-1.amazonaws.com/models/"
)

// TinfoilProxyBase is where sealed Tinfoil requests go.
func TinfoilProxyBase() string { return FountProxyBase() + "v1/" }
