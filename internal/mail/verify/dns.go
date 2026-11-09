package verify

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// Query types the verifier may ask for: TXT for DKIM, DMARC and SPF, the rest
// for SPF's a, mx and ptr mechanisms.
var queryTypes = map[string]dnsmessage.Type{
	"TXT":  dnsmessage.TypeTXT,
	"A":    dnsmessage.TypeA,
	"AAAA": dnsmessage.TypeAAAA,
	"MX":   dnsmessage.TypeMX,
	"PTR":  dnsmessage.TypePTR,
}

// namePattern is a DNS name the verifier may ask about: letters, digits,
// hyphens and underscores (for _domainkey and _dmarc), dot-separated.
var namePattern = regexp.MustCompile(`^([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)*[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.?$`)

// ValidQuery reports whether the broker should ask a resolver this question.
func ValidQuery(qtype, name string) bool {
	_, ok := queryTypes[qtype]
	return ok && len(name) <= 253 && namePattern.MatchString(name)
}

// BuildQuery makes the wire-format question the broker sends to each resolver.
// The ID is 0, as RFC 8484 recommends for DNS over HTTPS.
func BuildQuery(qtype, name string) ([]byte, error) {
	t, ok := queryTypes[qtype]
	if !ok || !ValidQuery(qtype, name) {
		return nil, fmt.Errorf("verify: query %s %q isn't allowed", qtype, name)
	}
	n, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: t, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// answer is one resolver's records for a question, as comparable strings.
type answer struct {
	notFound bool
	records  []string
}

// parseAnswer reads one resolver's response to (qtype, name).
func parseAnswer(msg []byte, qtype, name string) (answer, error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return answer{}, err
	}
	if !h.Response {
		return answer{}, errors.New("not a response")
	}
	q, err := p.Question()
	if err != nil {
		return answer{}, err
	}
	want := queryTypes[qtype]
	if q.Type != want || !strings.EqualFold(strings.TrimSuffix(q.Name.String(), "."), strings.TrimSuffix(name, ".")) {
		return answer{}, errors.New("response is for another question")
	}
	if err := p.SkipAllQuestions(); err != nil {
		return answer{}, err
	}
	switch h.RCode {
	case dnsmessage.RCodeNameError:
		return answer{notFound: true}, nil
	case dnsmessage.RCodeSuccess:
	default:
		return answer{}, fmt.Errorf("rcode %v", h.RCode)
	}
	var out []string
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return answer{}, err
		}
		if ah.Type != want || ah.Class != dnsmessage.ClassINET {
			if err := p.SkipAnswer(); err != nil {
				return answer{}, err
			}
			continue
		}
		var rec string
		switch want {
		case dnsmessage.TypeTXT:
			r, err := p.TXTResource()
			if err != nil {
				return answer{}, err
			}
			rec = strings.Join(r.TXT, "")
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return answer{}, err
			}
			rec = net.IP(r.A[:]).String()
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return answer{}, err
			}
			rec = net.IP(r.AAAA[:]).String()
		case dnsmessage.TypeMX:
			r, err := p.MXResource()
			if err != nil {
				return answer{}, err
			}
			rec = fmt.Sprintf("%d %s", r.Pref, r.MX.String())
		case dnsmessage.TypePTR:
			r, err := p.PTRResource()
			if err != nil {
				return answer{}, err
			}
			rec = r.PTR.String()
		}
		out = append(out, rec)
	}
	slices.Sort(out)
	return answer{records: out, notFound: len(out) == 0}, nil
}

// agree combines two resolvers' answers. They must say the same thing; a DKIM
// key one resolver can't see, or sees differently, is a temporary failure.
func agree(name string, answers [][]byte, qtype string) ([]string, error) {
	if len(answers) != 2 {
		return nil, tempErr(name, fmt.Sprintf("%d resolvers answered, want 2", len(answers)))
	}
	var got [2]answer
	for i, msg := range answers {
		a, err := parseAnswer(msg, qtype, name)
		if err != nil {
			return nil, tempErr(name, "resolver "+fmt.Sprint(i+1)+": "+err.Error())
		}
		got[i] = a
	}
	if got[0].notFound != got[1].notFound || !slices.Equal(got[0].records, got[1].records) {
		return nil, tempErr(name, "the two resolvers disagree")
	}
	if got[0].notFound {
		return nil, &net.DNSError{Err: "no such record", Name: name, IsNotFound: true}
	}
	return got[0].records, nil
}

func tempErr(name, why string) error {
	return &net.DNSError{Err: why, Name: name, IsTemporary: true}
}

// asker sends one question to the broker and returns both resolvers' raw
// responses.
type asker func(ctx context.Context, qtype, name string) ([][]byte, error)

// remoteResolver is the child's Resolver: every question goes to the broker.
type remoteResolver struct{ ask asker }

func (r remoteResolver) lookup(ctx context.Context, qtype, name string) ([]string, error) {
	if !ValidQuery(qtype, name) {
		return nil, &net.DNSError{Err: "name isn't a hostname", Name: name, IsNotFound: true}
	}
	answers, err := r.ask(ctx, qtype, name)
	if err != nil {
		return nil, tempErr(name, err.Error())
	}
	return agree(name, answers, qtype)
}

func (r remoteResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return r.lookup(ctx, "TXT", name)
}

func (r remoteResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	recs, err := r.lookup(ctx, "MX", name)
	if err != nil {
		return nil, err
	}
	out := make([]*net.MX, 0, len(recs))
	for _, rec := range recs {
		var pref uint16
		var host string
		if _, err := fmt.Sscanf(rec, "%d %s", &pref, &host); err == nil {
			out = append(out, &net.MX{Host: host, Pref: pref})
		}
	}
	return out, nil
}

func (r remoteResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	var out []net.IPAddr
	var firstErr error
	for _, t := range []string{"A", "AAAA"} {
		recs, err := r.lookup(ctx, t, host)
		var dnsErr *net.DNSError
		if err != nil && !(errors.As(err, &dnsErr) && dnsErr.IsNotFound) {
			return nil, err
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
		for _, rec := range recs {
			out = append(out, net.IPAddr{IP: net.ParseIP(rec)})
		}
	}
	if len(out) == 0 {
		return nil, firstErr
	}
	return out, nil
}

func (r remoteResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	name, err := reverseName(addr)
	if err != nil {
		return nil, &net.DNSError{Err: err.Error(), Name: addr, IsNotFound: true}
	}
	return r.lookup(ctx, "PTR", name)
}

// reverseName is addr's in-addr.arpa or ip6.arpa name.
func reverseName(addr string) (string, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return "", errors.New("not an IP address")
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", v4[3], v4[2], v4[1], v4[0]), nil
	}
	const hexDigits = "0123456789abcdef"
	var b strings.Builder
	for i := len(ip) - 1; i >= 0; i-- {
		b.WriteByte(hexDigits[ip[i]&0xf])
		b.WriteByte('.')
		b.WriteByte(hexDigits[ip[i]>>4])
		b.WriteByte('.')
	}
	b.WriteString("ip6.arpa")
	return b.String(), nil
}
