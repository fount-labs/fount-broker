package policy

import "regexp"

// Fount Mail's edge, reached over TLS pinned to the key its Tinfoil
// attestation endorses. The broker signs each read with the address's key;
// the app signs the writes itself and the broker fixes their method and path.
// Either way the app names an op, never a URL (package mail).
const (
	MailEdgeHost = "edge.fount.containers.tinfoil.dev"
	MailEdgeRepo = "fount-labs/fount-mail-edge"
	// MailSignKeyID is the attested key the edge signs stored messages with.
	MailSignKeyID = "mail-sign"
)

// MailDNSResolvers answer the sender verifier's DNS questions (DKIM keys,
// DMARC and SPF records). Both must agree. They learn the domains of the
// people who mail you, and nothing else: the broker sends only questions the
// verifier asks, bounded per message.
var MailDNSResolvers = []string{
	"https://dns.google/dns-query",
	"https://cloudflare-dns.com/dns-query",
}

// LicenseEntitlement asks Fount's API for a mail entitlement bound to a device
// key, for the mail op license_entitlement. The broker sends the license
// credential (a device credential) as Bearer; the body is only deviceKey. It
// isn't in Destinations: the app can't name it as a fetch.
var LicenseEntitlement = Destination{
	Route:       RouteFountAPI,
	Method:      "POST",
	Path:        "mail/entitlement",
	ContentType: "application/json",
	Credential:  CredentialLicense,
	Body: Body{Kind: BodyObject, MaxBytes: 128, Fields: map[string]Field{
		"deviceKey": {Types: []string{"string"}, Required: true, Pattern: regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)},
	}},
}
