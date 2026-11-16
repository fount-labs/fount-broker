package mail

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/fount-labs/fount-broker/internal/mail/mailtest"
)

// The app mints and checks nothing itself, but it builds addresses from this
// vector: seed 00 01 … 1f, handle 0123456789.
const (
	replyVectorSeed   = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	replyVectorHandle = "0123456789"
	replyVectorToken  = "aerukz4jeak3r2q7"
)

func replyVectorKeys(seed []byte) *Keys {
	return &Keys{Signing: ed25519.NewKeyFromSeed(seed)}
}

func seq32(start byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func TestReplyTokenVector(t *testing.T) {
	k := replyVectorKeys(seq32(0))
	if hexOf(k.Signing.Seed()) != replyVectorSeed {
		t.Fatal("vector seed")
	}
	tok, err := MintReplyToken(k, replyVectorHandle)
	if err != nil || tok != replyVectorToken {
		t.Fatalf("token %q, %v; want %q", tok, err, replyVectorToken)
	}
}

func TestReplyTokenChecks(t *testing.T) {
	k := replyVectorKeys(seq32(0))
	other := replyVectorKeys(seq32(1))
	tok, _ := MintReplyToken(k, "ffee000102")
	flipped := []byte(tok)
	flipped[15] = map[bool]byte{true: 'b', false: 'a'}[flipped[15] == 'a']
	for _, c := range []struct {
		name, recipient string
		keys            *Keys
		want            *ReplyToken
	}{
		{"round trip", "worker+" + tok + "@fountbox.com", k, &ReplyToken{Handle: "ffee000102"}},
		{"uppercase", "worker+" + strings.ToUpper(tok) + "@fountbox.com", k, &ReplyToken{Handle: "ffee000102"}},
		{"vector", "worker+" + replyVectorToken + "@fountbox.com", k, &ReplyToken{Handle: replyVectorHandle}},
		{"wrong key", "worker+" + tok + "@fountbox.com", other, &ReplyToken{Error: replyTokenMismatch}},
		{"flipped mac", "worker+" + string(flipped) + "@fountbox.com", k, &ReplyToken{Error: replyTokenMismatch}},
		{"short", "worker+" + tok[:15] + "@fountbox.com", k, &ReplyToken{Error: replyTokenMalformed}},
		{"long", "worker+" + tok + "a@fountbox.com", k, &ReplyToken{Error: replyTokenMalformed}},
		{"empty tag", "worker+@fountbox.com", k, &ReplyToken{Error: replyTokenMalformed}},
		{"bad alphabet", "worker+" + tok[:15] + "1@fountbox.com", k, &ReplyToken{Error: replyTokenMalformed}},
		{"two tags", "worker+a+" + tok + "@fountbox.com", k, &ReplyToken{Error: replyTokenMalformed}},
		{"connect form", "fount+" + tok + "@fountbox.com", other, &ReplyToken{Error: replyTokenMismatch}},
		{"no tag", "worker@fountbox.com", k, nil},
		{"plus in domain only", "worker@foo+bar.com", k, nil},
		{"no at", "worker+" + tok, k, &ReplyToken{Handle: "ffee000102"}},
	} {
		got := CheckReplyToken(c.keys, c.recipient)
		if (got == nil) != (c.want == nil) || got != nil && *got != *c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestReplyTokenOp(t *testing.T) {
	s, f, _, v := newService(t)
	ctx := context.Background()
	r, err := s.Handle(ctx, OpReplyToken, v.MailboxID, replyVectorHandle, nil)
	if err != nil {
		t.Fatal(err)
	}
	tok := r.(map[string]string)["token"]
	if len(tok) != replyTokenLen {
		t.Fatalf("token %q", tok)
	}
	keys, _ := ParseKeys(v.keysJSON())
	if got := CheckReplyToken(keys[v.MailboxID], "worker+"+tok+"@fountbox.com"); got == nil || got.Handle != replyVectorHandle {
		t.Fatalf("minted token checks as %+v", got)
	}
	for _, path := range []string{"", "012345678", "01234567890", "ABCDEF0123", "0123456789ab", "zz23456789", "../boots/x"} {
		if _, err := s.Handle(ctx, OpReplyToken, v.MailboxID, path, nil); !errors.Is(err, ErrRequest) {
			t.Errorf("path %q: %v", path, err)
		}
	}
	if _, err := s.Handle(ctx, OpReplyToken, v.MailboxID, replyVectorHandle, []byte("x")); !errors.Is(err, ErrRequest) {
		t.Errorf("body: %v", err)
	}
	if _, err := s.Handle(ctx, OpReplyToken, strings.Repeat("00", 32), replyVectorHandle, nil); !errors.Is(err, ErrNoKeys) {
		t.Errorf("no keys: %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("reply_token reached the edge: %v", f.calls)
	}
}

func TestGetOmitsReplyTokenWithoutTag(t *testing.T) {
	s, _, _, v := newService(t)
	m, err := s.Handle(context.Background(), OpGet, v.MailboxID, v.Messages[0].EdgeID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(v.Messages[0].Recipient, "+") {
		t.Fatal("vector recipient is tagged")
	}
	if rt := m.(*Message).ReplyToken; rt != nil {
		t.Fatalf("reply_token %+v for an untagged recipient", rt)
	}
}

// replyID is a worker email's Message-ID carrying tok.
func replyID(tok string) string {
	return "<fm." + strings.Repeat("0", replyIDRandomLen) + "." + tok + "@fountbox.com>"
}

func signedCheck(inReplyTo, references string) *EdgeCheck {
	return &EdgeCheck{
		Aligned: true,
		DKIM:    []EdgeSignature{{Result: "pass", Covers: true, Aligned: true}},
		Headers: EdgeCheckHeaders{InReplyTo: inReplyTo, References: references},
	}
}

func TestReplyTokenHeaders(t *testing.T) {
	k := replyVectorKeys(seq32(0))
	a, _ := MintReplyToken(k, "aaaaaaaaaa")
	b, _ := MintReplyToken(k, "bbbbbbbbbb")
	other, _ := MintReplyToken(replyVectorKeys(seq32(1)), "aaaaaaaaaa")
	flipped := []byte(a)
	flipped[15] = map[bool]byte{true: 'b', false: 'a'}[flipped[15] == 'a']
	old := "<fm." + strings.Repeat("0", replyIDRandomLen) + "@fountbox.com>"
	unsigned := func(field string) *EdgeCheck {
		c := signedCheck(replyID(a), replyID(a))
		c.DKIM[0].Unsigned = []string{field}
		return c
	}
	unaligned := signedCheck(replyID(a), replyID(a))
	unaligned.Aligned, unaligned.DKIM[0].Aligned = false, false
	otherSigner := signedCheck(replyID(a), "")
	otherSigner.DKIM = []EdgeSignature{{Result: "pass", Aligned: true, Unsigned: []string{"references"}}, {Result: "pass"}}
	handleA, handleB := &ReplyToken{Handle: "aaaaaaaaaa"}, &ReplyToken{Handle: "bbbbbbbbbb"}
	for _, c := range []struct {
		name  string
		check *EdgeCheck
		want  *ReplyToken
	}{
		{"in-reply-to", signedCheck(replyID(a), ""), handleA},
		{"references only", signedCheck("", "<x@example.com> "+replyID(a)+" <y@example.com>"), handleA},
		{"both, one handle", signedCheck(replyID(a), "<x@example.com> "+replyID(a)), handleA},
		{"uppercase token", signedCheck(replyID(strings.ToUpper(a)), ""), handleA},
		{"no brackets", signedCheck("", strings.Trim(replyID(a), "<>")+", x@example.com"), handleA},
		{"two handles, the parent's", signedCheck(replyID(b), replyID(a)+" "+replyID(b)), handleB},
		{"two handles, In-Reply-To over References", signedCheck(replyID(a), replyID(b)), handleA},
		{"two handles, the last References one", signedCheck("<x@example.com>", replyID(b)+"\r\n "+replyID(a)), handleA},
		{"a failure then a pass", signedCheck(replyID(other), replyID(a)), handleA},
		{"unsigned In-Reply-To", unsigned("in-reply-to"), nil},
		{"unsigned References", unsigned("references"), nil},
		{"not aligned", unaligned, nil},
		{"no signature covers both", otherSigner, nil},
		{"wrong key", signedCheck(replyID(other), ""), &ReplyToken{Error: replyTokenMismatch}},
		{"flipped mac", signedCheck("", replyID(string(flipped))), &ReplyToken{Error: replyTokenMismatch}},
		{"first failure", signedCheck(replyID(a[:15]), replyID(other)), &ReplyToken{Error: replyTokenMalformed}},
		{"old ids", signedCheck(old, "<x@example.com> "+old), nil},
		{"other domain", signedCheck("<fm."+strings.Repeat("0", replyIDRandomLen)+"."+a+"@example.com>", ""), nil},
		{"short random", signedCheck("<fm.0000."+a+"@fountbox.com>", ""), nil},
		{"no headers", signedCheck("", ""), nil},
		{"no check", nil, nil},
	} {
		got := CheckReplyTokenHeaders(k, c.check, "fountbox.com")
		if (got == nil) != (c.want == nil) || got != nil && *got != *c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
}

// getWithThreadHeaders gets a vector message re-sealed for recipient, with a
// sender check whose aligned signature covers In-Reply-To.
func getWithThreadHeaders(t *testing.T, recipient, inReplyTo string) *ReplyToken {
	t.Helper()
	s, f, _, v := newService(t)
	v.Messages[0].Recipient = recipient
	replaceWithV3(t, f, v, 0, func(raw []byte) []byte {
		var m map[string]any
		json.Unmarshal(mailtest.Check("dana@example.com", recipient, raw), &m)
		m["headers"].(map[string]any)["in_reply_to"] = inReplyTo
		b, _ := json.Marshal(m)
		return b
	})
	r, err := s.Handle(context.Background(), OpGet, v.MailboxID, v.Messages[0].EdgeID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.(*Message).SenderCheckError != "" {
		t.Fatal(r.(*Message).SenderCheckError)
	}
	return r.(*Message).ReplyToken
}

func TestGetReadsReplyTokenFromHeaders(t *testing.T) {
	v := loadVectors(t)
	keys, _ := ParseKeys(v.keysJSON())
	k := keys[v.MailboxID]
	a, _ := MintReplyToken(k, "aaaaaaaaaa")
	b, _ := MintReplyToken(k, "bbbbbbbbbb")
	for _, c := range []struct {
		name, recipient, inReplyTo string
		want                       ReplyToken
	}{
		{"headers", "worker@fountbox.com", replyID(b), ReplyToken{Handle: "bbbbbbbbbb"}},
		{"the +tag wins", "worker+" + a + "@fountbox.com", replyID(b), ReplyToken{Handle: "aaaaaaaaaa"}},
		{"headers over a bad +tag", "worker+nottoken@fountbox.com", replyID(b), ReplyToken{Handle: "bbbbbbbbbb"}},
		{"a bad +tag over bad headers", "worker+nottoken@fountbox.com", replyID(a[:15]), ReplyToken{Error: replyTokenMalformed}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := getWithThreadHeaders(t, c.recipient, c.inReplyTo); got == nil || *got != c.want {
				t.Fatalf("%+v, want %+v", got, c.want)
			}
		})
	}
}
