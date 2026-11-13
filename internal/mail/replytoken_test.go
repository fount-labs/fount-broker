package mail

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
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
