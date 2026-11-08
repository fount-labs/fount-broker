package policy

// Fount Mail's edge, reached over TLS pinned to the key its Tinfoil
// attestation endorses. The broker signs each Device API request with the
// address's key; the app names an op, never a path (package mail).
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
