package verify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/fount-labs/fount-broker/internal/mail"
)

// The test binary doubles as the verifier, the way the broker binary does.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == Subcommand {
		if err := Run(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if len(os.Args) > 1 && os.Args[1] == "probe-escape" {
		probeEscape()
		return
	}
	os.Exit(m.Run())
}

// zone answers TXT questions; split makes the second resolver differ for a name.
type zone struct {
	txt   map[string][]string
	split map[string]bool
	asked []string
}

func (z *zone) Ask(_ context.Context, qtype, name string) ([][]byte, error) {
	z.asked = append(z.asked, qtype+" "+name)
	q, err := BuildQuery(qtype, name)
	if err != nil {
		return nil, err
	}
	mk := func(second bool) []byte {
		var p dnsmessage.Parser
		h, _ := p.Start(q)
		qs, _ := p.AllQuestions()
		h.Response = true
		recs, ok := z.txt[strings.ToLower(strings.TrimSuffix(name, "."))]
		if qtype != "TXT" || !ok {
			h.RCode = dnsmessage.RCodeNameError
		}
		b := dnsmessage.NewBuilder(nil, h)
		b.StartQuestions()
		b.Question(qs[0])
		b.StartAnswers()
		for _, r := range recs {
			if second && z.split[name] {
				r += "x"
			}
			var parts []string
			for len(r) > 200 {
				parts, r = append(parts, r[:200]), r[200:]
			}
			parts = append(parts, r)
			b.TXTResource(dnsmessage.ResourceHeader{Name: qs[0].Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.TXTResource{TXT: parts})
		}
		out, _ := b.Finish()
		return out
	}
	return [][]byte{mk(false), mk(true)}, nil
}

func (z *zone) resolver() Resolver { return remoteResolver{ask: z.Ask} }

const recipient = "worker@fountbox.com"

func message(extra string) string {
	return "From: Owner <owner@example.com>\r\n" +
		"To: " + recipient + "\r\n" +
		"Subject: =?utf-8?q?Q3_numbers?=\r\n" +
		"Date: Sun, 08 Nov 2026 10:00:00 +0000\r\n" +
		"Message-ID: <a1@example.com>\r\n" +
		"In-Reply-To: <a0@example.com>\r\n" +
		"References: <a0@example.com>\r\n" +
		extra +
		"\r\nPlease look at the attached.\r\n"
}

var signHeaders = []string{"From", "To", "Subject", "Date", "Message-ID", "In-Reply-To", "References"}

func sign(t *testing.T, raw string, o dkim.SignOptions) string {
	t.Helper()
	if o.HeaderKeys == nil {
		o.HeaderKeys = signHeaders
	}
	if o.Domain == "" {
		o.Domain = "example.com"
	}
	if o.Selector == "" {
		o.Selector = "s1"
	}
	var b bytes.Buffer
	if err := dkim.Sign(&b, strings.NewReader(raw), &o); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func edKey(t *testing.T, z *zone, selector, flags string) crypto.Signer {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	z.txt[selector+"._domainkey.example.com"] = []string{"v=DKIM1; k=ed25519;" + flags + " p=" + base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))}
	return priv
}

func rsaKey(t *testing.T, z *zone, selector string, bits int) crypto.Signer {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	z.txt[selector+"._domainkey.example.com"] = []string{"v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)}
	return priv
}

func newZone() *zone {
	return &zone{txt: map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject; adkim=s"}}, split: map[string]bool{}}
}

var received = time.Date(2026, 11, 8, 10, 0, 30, 0, time.UTC)

func check(t *testing.T, z *zone, raw string) *Verdict {
	t.Helper()
	v, err := Check(context.Background(), Input{Raw: []byte(raw), Sender: "owner@example.com", Recipient: recipient, ReceivedAt: received}, z.resolver())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestAlignedSignatures(t *testing.T) {
	z := newZone()
	ed := edKey(t, z, "s1", "")
	rs := rsaKey(t, z, "s2", 2048)
	for name, raw := range map[string]string{
		"ed25519": sign(t, message(""), dkim.SignOptions{Signer: ed}),
		"rsa":     sign(t, message(""), dkim.SignOptions{Signer: rs, Selector: "s2"}),
	} {
		v := check(t, z, raw)
		if !v.Aligned || !v.RecipientSigned || len(v.DKIM) != 1 || v.DKIM[0].Result != "pass" || v.DKIM[0].Hash == "" {
			t.Fatalf("%s: %+v", name, v)
		}
		if v.DMARC.Result != "pass" || v.DMARC.Policy != "reject" || !v.DMARC.DKIMAligned {
			t.Fatalf("%s dmarc: %+v", name, v.DMARC)
		}
		if v.From.Address != "owner@example.com" || v.From.Name != "Owner" {
			t.Fatalf("%s from: %+v", name, v.From)
		}
		if v.Headers.Subject != "Q3 numbers" || v.Headers.MessageID != "<a1@example.com>" || v.Headers.InReplyTo != "<a0@example.com>" || len(v.Headers.To) != 1 {
			t.Fatalf("%s headers: %+v", name, v.Headers)
		}
		if v.DateSkewSeconds == nil || *v.DateSkewSeconds != -30 {
			t.Fatalf("%s skew %v", name, v.DateSkewSeconds)
		}
		if v.SPF.Result != "none" {
			t.Fatalf("%s spf %+v", name, v.SPF)
		}
	}
	if k := check(t, z, sign(t, message(""), dkim.SignOptions{Signer: rs, Selector: "s2"})).DKIM[0]; k.KeyBits != 2048 || k.Algorithm != "rsa-sha256" {
		t.Fatalf("rsa facts %+v", k)
	}
}

func TestWeakSignaturesArentAligned(t *testing.T) {
	z := newZone()
	ed := edKey(t, z, "s1", "")
	edKeyTesting := edKey(t, z, "test", " t=y;")
	cases := map[string]string{
		// go-msgauth can't sign with l=, so this one also fails to verify.
		"body length":      strings.Replace(sign(t, message(""), dkim.SignOptions{Signer: ed}), "DKIM-Signature: ", "DKIM-Signature: l=10; ", 1),
		"testing key":      sign(t, message(""), dkim.SignOptions{Signer: edKeyTesting, Selector: "test"}),
		"another domain":   strings.Replace(sign(t, message(""), dkim.SignOptions{Signer: ed}), "From: Owner <owner@example.com>", "From: Owner <owner@example.org>", 1),
		"subject unsigned": sign(t, message(""), dkim.SignOptions{Signer: ed, HeaderKeys: []string{"From", "To", "Date"}}),
		// A second From the signature doesn't cover. Real readers may show either.
		"unsigned second copy": sign(t, message(""), dkim.SignOptions{Signer: ed}) + "",
		"tampered":             strings.Replace(sign(t, message(""), dkim.SignOptions{Signer: ed}), "attached", "attachment", 1),
		"no key":               sign(t, message(""), dkim.SignOptions{Signer: ed, Selector: "gone"}),
	}
	// Prepend an unsigned Cc after signing: Cc must be signed when present.
	cases["unsigned second copy"] = "Cc: attacker@example.net\r\n" + cases["unsigned second copy"]
	for name, raw := range cases {
		v := check(t, z, raw)
		if v.Aligned {
			t.Errorf("%s: aligned: %+v", name, v.DKIM)
		}
	}
	if s := check(t, z, cases["body length"]).DKIM[0]; !s.BodyLength {
		t.Errorf("l= %+v", s)
	}
	if s := check(t, z, cases["testing key"]).DKIM[0]; !s.Testing {
		t.Errorf("t=y %+v", s)
	}
	if s := check(t, z, cases["unsigned second copy"]).DKIM[0]; s.Covers || !strings.Contains(strings.Join(s.Unsigned, ","), "cc") {
		t.Errorf("cc %+v", s)
	}
	if s := check(t, z, cases["no key"]).DKIM[0]; s.Result != "permerror" {
		t.Errorf("no key %+v", s)
	}
}

func TestOversigningStopsAnAddedField(t *testing.T) {
	z := newZone()
	ed := edKey(t, z, "s1", "")
	// Listing From twice signs it and the absence of a second one.
	raw := sign(t, message(""), dkim.SignOptions{Signer: ed, HeaderKeys: append(signHeaders, "From")})
	if v := check(t, z, raw); !v.Aligned {
		t.Fatalf("oversigned message: %+v", v.DKIM)
	}
	v := check(t, z, "From: Attacker <owner@example.com>\r\n"+raw)
	if v.Aligned || v.From.Error == "" {
		t.Fatalf("added From: aligned=%v from=%+v", v.Aligned, v.From)
	}
}

func TestFromIsStrict(t *testing.T) {
	for from, ok := range map[string]bool{
		"owner@example.com":                     true,
		"\"Owner, CPA\" <owner@Example.COM>":    false, // comma
		"Owner <owner@example.com> (work)":      false,
		"=?utf-8?q?Owner?= <owner@example.com>": false,
		"a@example.com, b@example.com":          false,
		"Team: a@example.com;":                  false,
		"Owner <owner@example.com>":             true,
		"<owner@EXAMPLE.com>":                   true,
		"owner":                                 false,
	} {
		got := parseFrom([]field{{Name: "From", Value: from}})
		if (got.Error == "") != ok {
			t.Errorf("%q: %+v", from, got)
		}
	}
	if got := parseFrom([]field{{Name: "From", Value: "<owner@EXAMPLE.com>"}}); got.Domain != "example.com" {
		t.Errorf("domain %+v", got)
	}
	if got := parseFrom(nil); got.Error == "" {
		t.Error("no From")
	}
}

func TestResolversMustAgree(t *testing.T) {
	z := newZone()
	ed := edKey(t, z, "s1", "")
	z.split["s1._domainkey.example.com"] = true
	v := check(t, z, sign(t, message(""), dkim.SignOptions{Signer: ed}))
	if v.Aligned || v.DKIM[0].Result != "temperror" {
		t.Fatalf("split answers: %+v", v.DKIM[0])
	}
}

func TestDMARCFallsBackToTheOrgDomain(t *testing.T) {
	z := newZone()
	delete(z.txt, "_dmarc.example.com")
	z.txt["_dmarc.example.co.uk"] = []string{"v=DMARC1; p=quarantine; sp=reject"}
	v := check(t, z, strings.ReplaceAll(message(""), "owner@example.com", "owner@mail.example.co.uk"))
	if v.DMARC.Result != "fail" || v.DMARC.RecordDomain != "example.co.uk" || v.DMARC.Policy != "reject" {
		t.Fatalf("%+v", v.DMARC)
	}
	z2 := newZone()
	delete(z2.txt, "_dmarc.example.com")
	if v := check(t, z2, message("")); v.DMARC.Result != "none" {
		t.Fatalf("no record: %+v", v.DMARC)
	}
}

func TestSPFWithAnIP(t *testing.T) {
	z := newZone()
	z.txt["example.com"] = []string{"v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all"}
	for ip, want := range map[string]string{"192.0.2.7": "pass", "198.51.100.1": "fail", "2001:db8::25": "pass"} {
		v, err := Check(context.Background(), Input{Raw: []byte(message("")), Sender: "owner@example.com", Recipient: recipient, ClientIP: ip, ClientIPSource: mail.ClientIPGatewayProxy, HELO: "mx.example.com"}, z.resolver())
		if err != nil {
			t.Fatal(err)
		}
		if v.SPF.Result != want || v.SPF.ClientIP != ip || v.SPF.ClientIPSource != "gateway_proxy" || v.SPF.HELO != "mx.example.com" || v.SPF.Domain != "example.com" {
			t.Errorf("%s: %+v", ip, v.SPF)
		}
		if want == "pass" && !v.DMARC.SPFAligned {
			t.Errorf("%s: dmarc %+v", ip, v.DMARC)
		}
	}
}

// With an empty MAIL FROM, SPF checks the HELO name.
func TestSPFChecksHELOForANullSender(t *testing.T) {
	z := newZone()
	z.txt["mx.example.com"] = []string{"v=spf1 ip4:192.0.2.7 -all"}
	v, err := Check(context.Background(), Input{Raw: []byte(message("")), Recipient: recipient, ClientIP: "192.0.2.7", ClientIPSource: mail.ClientIPGatewayProxy, HELO: "mx.example.com"}, z.resolver())
	if err != nil {
		t.Fatal(err)
	}
	if v.SPF.Result != "pass" || v.SPF.Domain != "mx.example.com" {
		t.Fatalf("%+v", v.SPF)
	}
}

// SPF runs only on an address the edge took from the gateway's PROXY header.
func TestSPFNoneWithoutAProxyAddress(t *testing.T) {
	z := newZone()
	z.txt["example.com"] = []string{"v=spf1 ip4:192.0.2.0/24 -all"}
	for name, in := range map[string]Input{
		"no address":     {HELO: "mx.example.com"},
		"unknown source": {ClientIP: "192.0.2.7", ClientIPSource: "header"},
		"no source":      {ClientIP: "192.0.2.7"},
	} {
		in.Raw, in.Sender, in.Recipient = []byte(message("")), "owner@example.com", recipient
		v, err := Check(context.Background(), in, z.resolver())
		if err != nil {
			t.Fatal(err)
		}
		if v.SPF.Result != "none" || v.SPF.ClientIP != "" || v.SPF.ClientIPSource != "" || v.SPF.Error == "" || v.DMARC.SPFAligned {
			t.Errorf("%s: %+v", name, v.SPF)
		}
	}
	for _, q := range z.asked {
		if strings.TrimSuffix(q, ".") == "TXT example.com" {
			t.Errorf("looked up SPF without an address: %v", z.asked)
		}
	}
}

func TestQueryPolicy(t *testing.T) {
	for _, c := range []struct {
		qtype, name string
		ok          bool
	}{
		{"TXT", "s1._domainkey.example.com", true},
		{"TXT", "_dmarc.example.com.", true},
		{"PTR", "7.2.0.192.in-addr.arpa", true},
		{"ANY", "example.com", false},
		{"TXT", "exa mple.com", false},
		{"TXT", "a..b", false},
		{"TXT", strings.Repeat("a.", 130) + "com", false},
		{"TXT", "-bad.example.com", false},
	} {
		if ValidQuery(c.qtype, c.name) != c.ok {
			t.Errorf("%s %q: want %v", c.qtype, c.name, c.ok)
		}
	}
	if n, _ := reverseName("2001:db8::1"); !strings.HasSuffix(n, ".8.b.d.0.1.0.0.2.ip6.arpa") || !strings.HasPrefix(n, "1.0.0.0.") {
		t.Errorf("reverse %s", n)
	}
}

func selfCommand(t *testing.T) func(context.Context) *exec.Cmd {
	cmd, err := SelfCommand()
	if err != nil {
		t.Fatal(err)
	}
	return cmd
}

func TestProcessRunsTheConfinedVerifier(t *testing.T) {
	z := newZone()
	ed := edKey(t, z, "s1", "")
	p := &Process{Command: selfCommand(t), DNS: z}
	raw, err := p.Check(context.Background(), mail.CheckInput{Raw: []byte(sign(t, message(""), dkim.SignOptions{Signer: ed})), Sender: "owner@example.com", Recipient: recipient, ReceivedAt: received})
	if err != nil {
		t.Fatal(err)
	}
	var v Verdict
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if !v.Aligned || v.DMARC.Result != "pass" {
		t.Fatalf("verdict %s", raw)
	}
	if len(z.asked) != 2 {
		t.Fatalf("asked %v", z.asked)
	}
}

// The client IP and HELO reach the child, and its SPF lookup goes through the
// broker's DNS.
func TestProcessRunsSPF(t *testing.T) {
	z := newZone()
	z.txt["example.com"] = []string{"v=spf1 ip4:192.0.2.0/24 -all"}
	p := &Process{Command: selfCommand(t), DNS: z}
	raw, err := p.Check(context.Background(), mail.CheckInput{
		Raw: []byte(message("")), Sender: "owner@example.com", Recipient: recipient, ReceivedAt: received,
		ClientIP: "192.0.2.7", ClientIPSource: mail.ClientIPGatewayProxy, HELO: "mx.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	var v Verdict
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.SPF.Result != "pass" || v.SPF.ClientIP != "192.0.2.7" || v.SPF.ClientIPSource != "gateway_proxy" || v.SPF.HELO != "mx.example.com" {
		t.Fatalf("spf %+v", v.SPF)
	}
	asked := false
	for _, q := range z.asked {
		asked = asked || strings.TrimSuffix(q, ".") == "TXT example.com"
	}
	if !asked {
		t.Fatalf("the SPF record wasn't asked through the broker: %v", z.asked)
	}
}

func TestProcessFailsClosed(t *testing.T) {
	z := newZone()
	ctx := context.Background()
	in := mail.CheckInput{Raw: []byte(message("")), Recipient: recipient}
	crash := &Process{Command: func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "echo boom >&2; exit 3")
	}, DNS: z}
	if _, err := crash.Check(ctx, in); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("crash: %v", err)
	}
	garbage := &Process{Command: func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "cat >/dev/null & printf 'not a frame'")
	}, DNS: z}
	if _, err := garbage.Check(ctx, in); err == nil {
		t.Fatal("garbage output passed")
	}
	if _, err := (&Process{Command: selfCommand(t), DNS: z}).Check(ctx, mail.CheckInput{Raw: []byte("no header end")}); err == nil {
		t.Fatal("unreadable message passed")
	}
}

// probeEscape runs inside the sandbox and reports what it could reach.
func probeEscape() {
	var reached []string
	if c, err := net.DialTimeout("tcp", "1.1.1.1:443", 2*time.Second); err == nil {
		c.Close()
		reached = append(reached, "network")
	}
	if _, err := net.LookupHost("example.com"); err == nil {
		reached = append(reached, "dns")
	}
	home, _ := os.UserHomeDir()
	for _, p := range []string{"/etc/hosts", home, "/Users"} {
		if p == "" {
			continue
		}
		if _, err := os.ReadDir(p); err == nil {
			reached = append(reached, "read "+p)
		}
	}
	if err := os.WriteFile("/tmp/fount-verify-probe", []byte("x"), 0o600); err == nil {
		reached = append(reached, "write /tmp")
	}
	fmt.Print(strings.Join(reached, ","))
}

func TestSandboxHoldsOnDarwin(t *testing.T) {
	if !Confined {
		t.Skip("no OS confinement on this platform")
	}
	exe, _ := os.Executable()
	name, args := confine(exe, "probe-escape")
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("probe didn't run: %v %s", err, out)
	}
	if len(out) != 0 {
		t.Fatalf("the confined verifier reached: %s", out)
	}
	// The probe itself works unconfined, so an empty result means the sandbox.
	free, _ := exec.Command(exe, "probe-escape").Output()
	if !strings.Contains(string(free), "read") {
		t.Fatalf("unconfined probe reached nothing (%s), so the test proves nothing", free)
	}
}
