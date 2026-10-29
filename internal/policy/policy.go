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
	// CredentialOpenRouterKey is the user's own OpenRouter API key.
	CredentialOpenRouterKey Credential = "openrouter_api_key"
)

// Credentials is every credential the app may hand the broker.
var Credentials = []Credential{CredentialLicense, CredentialTinfoilCacheSecret, CredentialOpenRouterKey}

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
	// PathPattern, when set, lets the app complete Path with a suffix that
	// matches it in full. Without it the app can't add to Path.
	PathPattern *regexp.Regexp
	// Accept lists the Accept values the app may send.
	Accept []string
	// ContentType is sent with the body.
	ContentType string
	// Headers are sent as they are, after any the app's request sets.
	Headers map[string]string
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
	// Range, when set, takes the app's path and returns the Range header to
	// send, or false to refuse it. The path then names a part of the
	// resource; it doesn't extend the URL.
	Range func(path string) (string, bool)
}

const (
	RouteTinfoil = "tinfoil"
	// RouteTinfoilWebSearch is Tinfoil's web-search enclave, reached through
	// Fount's proxy like the router.
	RouteTinfoilWebSearch = "tinfoil_websearch"
	// RouteFountAPI is Fount's license and feedback API.
	RouteFountAPI = "fount_api"
	// RouteFountProxy is Fount's model proxy, which adds Fount's provider key
	// and meters usage against the license.
	RouteFountProxy = "fount_proxy"
	// RouteModels serves embedding model files.
	RouteModels = "models"
	// RouteOpenRouter is OpenRouter itself, for users with their own key.
	RouteOpenRouter = "openrouter"
	// RouteHuggingFace serves vision model files.
	RouteHuggingFace = "huggingface"
	// RouteUpdates serves Fount's own releases from GitHub.
	RouteUpdates = "updates"
	// RouteLatex serves TeX support files from the Tectonic bundle.
	RouteLatex = "latex"
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
	// Tinfoil's web-search MCP server. The body is sealed to the enclave,
	// which sends the search query, after removing what its PII filter
	// detects, to Exa. Exa can read that query; Fount's proxy and Tinfoil
	// can't. The MCP server is stateless, so each call is one tools/call.
	"tinfoil.websearch": {
		Route:       RouteTinfoilWebSearch,
		Method:      "POST",
		Path:        "mcp",
		Accept:      []string{""},
		ContentType: "application/json",
		Headers: map[string]string{
			"Accept":                   "application/json, text/event-stream",
			"X-Tinfoil-Tool-PII-Check": "true",
		},
		Body:       toolCall(16<<10, "search", Field{Types: []string{"object"}, Required: true}),
		Credential: CredentialLicense,
	},
	// The same enclave's fetch tool: it asks Exa for the text of up to 20
	// public HTTPS pages. Exa's crawler visits them, or Exa serves a copy up
	// to two hours old, so the sites never see the user's address. The
	// enclave doesn't run its PII filter on fetches, so Exa and each site see
	// the URL as it is. It does check each page for prompt injection, which
	// the broker always asks for.
	"tinfoil.webfetch": {
		Route:       RouteTinfoilWebSearch,
		Method:      "POST",
		Path:        "mcp",
		Accept:      []string{""},
		ContentType: "application/json",
		Headers: map[string]string{
			"Accept":                         "application/json, text/event-stream",
			"X-Tinfoil-Tool-Injection-Check": "true",
		},
		Body: toolCall(64<<10, "fetch", Field{Types: []string{"object"}, Required: true, Fields: map[string]Field{
			"urls": {
				Types: []string{"array"}, Required: true, MinItems: 1, MaxItems: 20,
				Items: &Field{Types: []string{"string"}, Pattern: fetchURLPattern},
			},
		}}),
		Credential: CredentialLicense,
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
	// OpenRouter with the user's own key. The request goes straight to
	// OpenRouter; Fount's servers don't see it.
	"openrouter_byok.chat_completions": {
		Route:       RouteOpenRouter,
		Method:      "POST",
		Path:        "chat/completions",
		Accept:      chatAccept,
		ContentType: "application/json",
		Body:        Body{Kind: BodyOpaque},
		Credential:  CredentialOpenRouterKey,
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

// fetchURLPattern is an https URL with no user info or whitespace.
var fetchURLPattern = regexp.MustCompile(`^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/\S*)?$`)

// toolCall is the body of one MCP tools/call naming tool, with arguments
// checked by args.
func toolCall(maxBytes int, tool string, args Field) Body {
	return Body{Kind: BodyObject, MaxBytes: maxBytes, Fields: map[string]Field{
		"jsonrpc": {Types: []string{"string"}, Required: true, Pattern: regexp.MustCompile(`^2\.0$`)},
		"id":      {Types: []string{"number", "string"}, Required: true},
		"method":  {Types: []string{"string"}, Required: true, Pattern: regexp.MustCompile(`^tools/call$`)},
		"params": {Types: []string{"object"}, Required: true, Fields: map[string]Field{
			"name":      {Types: []string{"string"}, Required: true, Pattern: regexp.MustCompile(`^` + regexp.QuoteMeta(tool) + `$`)},
			"arguments": args,
		}},
	}}
}

// Routes is every route a status request may name.
var Routes = []string{RouteTinfoil, RouteTinfoilWebSearch, RouteModels, RouteHuggingFace}

// Tinfoil inference goes through Fount's proxy, which attaches Fount's Tinfoil
// key and meters usage. The proxy sees only ciphertext: bodies are sealed to
// a router the broker attested itself.
const TinfoilRouterRepo = "tinfoilsh/confidential-model-router"

// The web-search enclave, attested against its own repository.
const (
	TinfoilWebSearchHost = "websearch.tinfoil.sh"
	TinfoilWebSearchRepo = "tinfoilsh/confidential-websearch"
)

// Release endpoints. A dev build can override the first two; see
// endpoints_dev.go.
const (
	fountAPIBase   = "https://api.fount.sh/"
	fountProxyBase = "https://api.fount.sh/proxy/"
	ModelsBase     = "https://fount-embedding-models.s3.us-east-1.amazonaws.com/models/"
	OpenRouterBase = "https://openrouter.ai/api/v1/"
)

// TinfoilProxyBase is where sealed Tinfoil requests go.
func TinfoilProxyBase() string { return FountProxyBase() + "v1/" }
