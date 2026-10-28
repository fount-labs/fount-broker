// Package policy is the broker's compiled-in egress policy: every destination
// the app can name, where it goes, and which credential it carries. Nothing
// here can change at runtime, so the policy of a release is exactly what its
// source says.
package policy

import "slices"

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
	Credential  Credential
}

const RouteTinfoil = "tinfoil"

var Destinations = map[string]Destination{
	"tinfoil.chat_completions": {
		Route:       RouteTinfoil,
		Method:      "POST",
		Path:        "chat/completions",
		Accept:      []string{"", "application/json", "text/event-stream"},
		ContentType: "application/json",
		Credential:  CredentialLicense,
	},
}

// Routes is every route a status request may name.
var Routes = []string{RouteTinfoil}

// Tinfoil inference goes through Fount's proxy, which attaches Fount's Tinfoil
// key and meters usage. The proxy sees only ciphertext: bodies are sealed to
// a router the broker attested itself.
const (
	TinfoilRouterRepo = "tinfoilsh/confidential-model-router"
	tinfoilProxyBase  = "https://api.fount.sh/proxy/v1/"
)
