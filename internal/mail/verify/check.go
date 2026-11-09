// Package verify is the offline sender verifier (design §6, "Verifying the
// sender"). The broker starts it as a short-lived child process for each
// decrypted message, with no keys and no network: the only way out is to ask
// the broker for a DNS answer, which the broker fetches from two DNS-over-HTTPS
// resolvers and passes back unread. Every parser of hostile mail headers runs
// here, so a bug in one can crash or mislead this process but can't reach the
// broker's keys or the network.
//
// It reports facts. The app decides whether a message counts as a request,
// using these and what only it knows: the paired owners, the d= stored at
// pairing, and the signatures it has already seen.
package verify

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"slices"
	"strings"
	"sync"
	"time"

	"blitiri.com.ar/go/spf"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
	"golang.org/x/net/publicsuffix"
)

// Input is one message to check.
type Input struct {
	Raw []byte
	// Sender is the SMTP envelope sender (MAIL FROM), unverified.
	Sender string
	// Recipient is the Fount address the edge delivered to.
	Recipient string
	// ReceivedAt is the edge's clock when the message arrived.
	ReceivedAt time.Time
	// ClientIP and HELO are the sending server's, when the edge records them.
	// It doesn't yet, so SPF reports none.
	ClientIP string
	HELO     string
}

// Resolver answers DNS questions. Errors are *net.DNSError, with IsNotFound
// for NXDOMAIN or no records and IsTemporary for anything else.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// Verdict is everything the verifier found.
type Verdict struct {
	From  From        `json:"from"`
	DKIM  []Signature `json:"dkim"`
	SPF   SPF         `json:"spf"`
	DMARC DMARC       `json:"dmarc"`
	// Aligned is true when at least one signature in DKIM is Aligned.
	Aligned bool `json:"aligned"`
	// RecipientSigned is true when the Fount address is in the To or Cc field
	// an aligned signature covers.
	RecipientSigned bool `json:"recipient_signed"`
	// DateSkewSeconds is the signed Date minus the edge's received_at. Absent
	// when there's no single parseable Date.
	DateSkewSeconds *int64 `json:"date_skew_seconds,omitempty"`
	// Headers are the values intake threads on, so the app never re-parses
	// them.
	Headers Headers `json:"headers"`
}

// From is the single author mailbox, or why there isn't one.
type From struct {
	Address string `json:"address,omitempty"` // lowercase domain, local part as written
	Domain  string `json:"domain,omitempty"`
	Name    string `json:"name,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Signature is one DKIM-Signature field's result.
type Signature struct {
	Domain    string `json:"domain"`
	Selector  string `json:"selector"`
	Algorithm string `json:"algorithm"`
	// Result is pass, fail, temperror or permerror.
	Result  string   `json:"result"`
	Error   string   `json:"error,omitempty"`
	KeyBits int      `json:"key_bits,omitempty"`
	Headers []string `json:"headers"`
	// BodyLength is true when the signature has an l= tag, which lets anyone
	// append to the body.
	BodyLength bool `json:"body_length"`
	// Testing is true when the key record has t=y.
	Testing bool `json:"testing"`
	// Covers is true when every field design §6 requires is signed, and no
	// signed field has an unsigned second copy.
	Covers bool `json:"covers"`
	// Unsigned lists the required fields that fail Covers.
	Unsigned []string `json:"unsigned,omitempty"`
	// Hash is the SHA-256 of the b= value, for the app's replay check.
	Hash string `json:"hash"`
	// Aligned: Result is pass, d= equals the From domain, the algorithm and key
	// meet design §6, there's no l=, the key isn't t=y, and Covers.
	Aligned bool `json:"aligned"`
}

type SPF struct {
	Result string `json:"result"`
	Domain string `json:"domain,omitempty"`
	Error  string `json:"error,omitempty"`
}

type DMARC struct {
	// Result is pass, fail, none (no record) or temperror.
	Result string `json:"result"`
	Policy string `json:"policy,omitempty"`
	// RecordDomain is where the record was found: the From domain or its
	// organizational domain.
	RecordDomain string `json:"record_domain,omitempty"`
	DKIMAligned  bool   `json:"dkim_aligned"`
	SPFAligned   bool   `json:"spf_aligned"`
	Error        string `json:"error,omitempty"`
}

type Headers struct {
	MessageID  string   `json:"message_id,omitempty"`
	InReplyTo  string   `json:"in_reply_to,omitempty"`
	References string   `json:"references,omitempty"`
	Subject    string   `json:"subject,omitempty"`
	Date       string   `json:"date,omitempty"`
	To         []string `json:"to,omitempty"`
	Cc         []string `json:"cc,omitempty"`
	ReplyTo    []string `json:"reply_to,omitempty"`
	// Duplicated lists the fields above that appear more than once. Their
	// values are left empty rather than guessed.
	Duplicated []string `json:"duplicated,omitempty"`
}

// required are always signed; whenPresent are signed if the message has them.
var (
	required    = []string{"from", "to", "date", "subject"}
	whenPresent = []string{"cc", "content-type", "mime-version", "reply-to", "in-reply-to", "references"}
)

const maxSignatures = 8

// Check runs every check on in. It fails only when the message can't be read
// at all; a failed check is a result, not an error.
func Check(ctx context.Context, in Input, r Resolver) (*Verdict, error) {
	fields, err := splitHeader(in.Raw)
	if err != nil {
		return nil, err
	}
	v := &Verdict{DKIM: []Signature{}}
	v.From = parseFrom(fields)
	v.Headers = threadHeaders(fields)
	if dates := all(fields, "Date"); len(dates) == 1 {
		if d, err := mail.ParseDate(dates[0]); err == nil && !in.ReceivedAt.IsZero() {
			skew := int64(d.Sub(in.ReceivedAt) / time.Second)
			v.DateSkewSeconds = &skew
		}
	}

	v.DKIM = checkDKIM(ctx, in.Raw, fields, v.From.Domain, r)
	for _, s := range v.DKIM {
		v.Aligned = v.Aligned || s.Aligned
	}
	v.RecipientSigned = v.Aligned && recipientIn(v.Headers, in.Recipient)
	v.SPF = checkSPF(ctx, in, r)
	v.DMARC = checkDMARC(ctx, v, in, r)
	return v, nil
}

// parseFrom accepts exactly one From field holding exactly one plain mailbox.
// Comments, groups, lists and encoded words are refused, not interpreted.
func parseFrom(fields []field) From {
	froms := all(fields, "From")
	if len(froms) != 1 {
		return From{Error: fmt.Sprintf("%d From fields", len(froms))}
	}
	s := froms[0]
	switch {
	case strings.ContainsAny(s, "()"):
		return From{Error: "From has a comment"}
	case strings.ContainsAny(s, ",;:"):
		return From{Error: "From has more than one mailbox, or a group"}
	case strings.Contains(s, "=?"):
		return From{Error: "From has an encoded word"}
	case strings.ContainsFunc(s, func(r rune) bool { return r > 0x7e || r < 0x20 && r != '\t' }):
		return From{Error: "From isn't printable ASCII"}
	}
	a, err := (&mail.AddressParser{}).Parse(s)
	if err != nil {
		return From{Error: "From isn't a mailbox: " + err.Error()}
	}
	local, domain, ok := strings.Cut(a.Address, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
		return From{Error: "From isn't a mailbox"}
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	return From{Address: local + "@" + domain, Domain: domain, Name: a.Name}
}

func threadHeaders(fields []field) Headers {
	var h Headers
	one := func(name string) (string, bool) {
		vs := all(fields, name)
		if len(vs) > 1 {
			h.Duplicated = append(h.Duplicated, strings.ToLower(name))
			return "", false
		}
		if len(vs) == 0 {
			return "", false
		}
		return vs[0], true
	}
	list := func(name string) []string {
		s, ok := one(name)
		if !ok {
			return nil
		}
		as, err := (&mail.AddressParser{WordDecoder: &mime.WordDecoder{}}).ParseList(s)
		if err != nil {
			return nil
		}
		out := make([]string, 0, len(as))
		for _, a := range as {
			out = append(out, a.Address)
		}
		return out
	}
	h.MessageID, _ = one("Message-ID")
	h.InReplyTo, _ = one("In-Reply-To")
	h.References, _ = one("References")
	if s, ok := one("Subject"); ok {
		if d, err := (&mime.WordDecoder{}).DecodeHeader(s); err == nil {
			s = d
		}
		h.Subject = s
	}
	h.Date, _ = one("Date")
	h.To = list("To")
	h.Cc = list("Cc")
	h.ReplyTo = list("Reply-To")
	return h
}

func recipientIn(h Headers, recipient string) bool {
	for _, a := range slices.Concat(h.To, h.Cc) {
		if strings.EqualFold(a, recipient) {
			return true
		}
	}
	return false
}

// keyRecords remembers the DKIM key records the library fetched, so the
// verdict can report key size and t=y.
type keyRecords struct {
	mu  sync.Mutex
	txt map[string][]string
}

func checkDKIM(ctx context.Context, raw []byte, fields []field, fromDomain string, r Resolver) []Signature {
	var sigs []Signature
	var values []string
	for _, f := range fields {
		if strings.EqualFold(f.Name, "DKIM-Signature") {
			values = append(values, f.Value)
		}
	}
	if len(values) == 0 {
		return []Signature{}
	}
	if len(values) > maxSignatures {
		values = values[:maxSignatures]
	}
	keys := &keyRecords{txt: map[string][]string{}}
	verifs, err := dkim.VerifyWithOptions(strings.NewReader(string(raw)), &dkim.VerifyOptions{
		MaxVerifications: maxSignatures,
		LookupTXT: func(name string) ([]string, error) {
			txt, err := r.LookupTXT(ctx, name)
			if err == nil {
				keys.mu.Lock()
				keys.txt[strings.ToLower(name)] = txt
				keys.mu.Unlock()
			}
			return txt, err
		},
	})
	if err != nil && !errors.Is(err, dkim.ErrTooManySignatures) {
		for _, val := range values {
			sigs = append(sigs, Signature{Result: "permerror", Error: err.Error(), Headers: []string{}, Hash: sigHash(val)})
		}
		return sigs
	}
	counts := map[string]int{}
	for _, f := range fields {
		counts[strings.ToLower(f.Name)]++
	}
	for i, val := range values {
		s := Signature{Headers: []string{}, Hash: sigHash(val), Result: "permerror"}
		t, ok := tags(val)
		if !ok {
			s.Error = "DKIM-Signature tag list is malformed"
			sigs = append(sigs, s)
			continue
		}
		s.Domain = strings.ToLower(t["d"])
		s.Selector = strings.ToLower(t["s"])
		s.Algorithm = strings.ToLower(t["a"])
		_, s.BodyLength = t["l"]
		for h := range strings.SplitSeq(stripSpace(t["h"]), ":") {
			if h != "" {
				s.Headers = append(s.Headers, strings.ToLower(h))
			}
		}
		if i < len(verifs) {
			switch e := verifs[i].Err; {
			case e == nil:
				s.Result = "pass"
			case dkim.IsTempFail(e):
				s.Result, s.Error = "temperror", e.Error()
			case dkim.IsPermFail(e):
				s.Result, s.Error = "permerror", e.Error()
			default:
				s.Result, s.Error = "fail", e.Error()
			}
		}
		keys.mu.Lock()
		rec := keys.txt[s.Selector+"._domainkey."+s.Domain]
		keys.mu.Unlock()
		s.KeyBits, s.Testing = keyFacts(rec)
		s.Unsigned = unsigned(s.Headers, counts)
		s.Covers = len(s.Unsigned) == 0
		goodAlg := s.Algorithm == "ed25519-sha256" || s.Algorithm == "rsa-sha256" && s.KeyBits >= 1024
		s.Aligned = s.Result == "pass" && fromDomain != "" && s.Domain == fromDomain && goodAlg && !s.BodyLength && !s.Testing && s.Covers
		sigs = append(sigs, s)
	}
	return sigs
}

// unsigned lists the required fields a signature doesn't fully cover. A field
// with n copies must be listed at least n times in h=, or an unsigned copy
// could be the one a reader shows.
func unsigned(h []string, counts map[string]int) []string {
	listed := map[string]int{}
	for _, name := range h {
		listed[name]++
	}
	var out []string
	for _, name := range required {
		if counts[name] == 0 || listed[name] < counts[name] {
			out = append(out, name)
		}
	}
	for _, name := range whenPresent {
		if listed[name] < counts[name] {
			out = append(out, name)
		}
	}
	return out
}

func sigHash(val string) string {
	t, ok := tags(val)
	if !ok {
		return ""
	}
	sum := sha256.Sum256([]byte(stripSpace(t["b"])))
	return hex.EncodeToString(sum[:])
}

// keyFacts reads a key record's size and its t=y flag.
func keyFacts(rec []string) (bits int, testing bool) {
	if len(rec) != 1 {
		return 0, false
	}
	t, ok := tags(rec[0])
	if !ok {
		return 0, false
	}
	for flag := range strings.SplitSeq(stripSpace(t["t"]), ":") {
		testing = testing || flag == "y"
	}
	der, err := base64.StdEncoding.DecodeString(stripSpace(t["p"]))
	if err != nil || len(der) == 0 {
		return 0, testing
	}
	if strings.EqualFold(t["k"], "ed25519") {
		if len(der) == ed25519.PublicKeySize {
			return 256, testing
		}
		return 0, testing
	}
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		if rk, ok := pub.(*rsa.PublicKey); ok {
			return rk.N.BitLen(), testing
		}
	}
	if rk, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return rk.N.BitLen(), testing
	}
	return 0, testing
}

func checkSPF(ctx context.Context, in Input, r Resolver) SPF {
	domain := in.HELO
	if _, d, ok := strings.Cut(in.Sender, "@"); ok && d != "" {
		domain = d
	}
	out := SPF{Domain: strings.ToLower(domain)}
	if in.ClientIP == "" {
		out.Result = string(spf.None)
		out.Error = "the edge doesn't record the sending server's IP address"
		return out
	}
	ip := net.ParseIP(in.ClientIP)
	if ip == nil {
		out.Result, out.Error = string(spf.PermError), "bad client IP"
		return out
	}
	res, err := spf.CheckHostWithSender(ip, in.HELO, in.Sender, spf.WithResolver(r), spf.WithContext(ctx))
	out.Result = string(res)
	if err != nil {
		out.Error = err.Error()
	}
	return out
}

func checkDMARC(ctx context.Context, v *Verdict, in Input, r Resolver) DMARC {
	if v.From.Domain == "" {
		return DMARC{Result: "none", Error: "no single From domain"}
	}
	lookup := func(name string) ([]string, error) { return r.LookupTXT(ctx, name) }
	out := DMARC{RecordDomain: v.From.Domain}
	rec, err := dmarc.LookupWithOptions(v.From.Domain, &dmarc.LookupOptions{LookupTXT: lookup})
	org := orgDomain(v.From.Domain)
	if errors.Is(err, dmarc.ErrNoPolicy) && org != v.From.Domain {
		out.RecordDomain = org
		rec, err = dmarc.LookupWithOptions(org, &dmarc.LookupOptions{LookupTXT: lookup})
	}
	switch {
	case errors.Is(err, dmarc.ErrNoPolicy):
		return DMARC{Result: "none"}
	case err != nil:
		return DMARC{Result: "temperror", Error: err.Error(), RecordDomain: out.RecordDomain}
	}
	out.Policy = string(rec.Policy)
	if out.RecordDomain != v.From.Domain && rec.SubdomainPolicy != "" {
		out.Policy = string(rec.SubdomainPolicy)
	}
	aligned := func(d string, mode dmarc.AlignmentMode) bool {
		if mode == dmarc.AlignmentStrict {
			return d == v.From.Domain
		}
		return d != "" && orgDomain(d) == org
	}
	for _, s := range v.DKIM {
		if s.Result == "pass" && aligned(s.Domain, rec.DKIMAlignment) {
			out.DKIMAligned = true
		}
	}
	out.SPFAligned = v.SPF.Result == string(spf.Pass) && aligned(v.SPF.Domain, rec.SPFAlignment)
	out.Result = "fail"
	if out.DKIMAligned || out.SPFAligned {
		out.Result = "pass"
	}
	return out
}

func orgDomain(d string) string {
	if o, err := publicsuffix.EffectiveTLDPlusOne(d); err == nil {
		return o
	}
	return d
}
