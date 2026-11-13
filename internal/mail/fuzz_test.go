package mail

import (
	"crypto/ed25519"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
)

// The object parser must never accept trailing bytes or overrun, and anything
// it accepts must re-verify only with the right key.
func FuzzParseObject(f *testing.F) {
	v := loadVectorsTB(f, vectorsV2)
	for _, path := range []string{vectorsV2, vectorsV1} {
		for _, m := range loadVectorsTB(f, path).Messages {
			f.Add(m.Object)
		}
	}
	pub, _ := hex.DecodeString(v.BootKeys[v.Messages[0].Boot])
	f.Fuzz(func(t *testing.T, b []byte) {
		o, err := ParseObject(b)
		if err != nil {
			return
		}
		if len(o.signed)+len(o.sig) != len(b) || len(o.sig) != ed25519.SignatureSize {
			t.Fatalf("parsed %d bytes as %d+%d", len(b), len(o.signed), len(o.sig))
		}
		_ = o.Verify(pub)
	})
}

// unframe must never overrun, and an envelope it accepts must be one the edge
// could have written.
func FuzzUnframe(f *testing.F) {
	f.Add(byte(2), []byte(v2Layout))
	f.Add(byte(2), []byte(v2LayoutNone))
	f.Add(byte(1), []byte("\x00\x05a@b.c\x00\x06w@f.coRAW"))
	f.Add(byte(3), []byte(v3Layout))
	f.Fuzz(func(t *testing.T, version byte, p []byte) {
		o, err := unframe(version, p)
		if err != nil {
			return
		}
		env, raw := o.Envelope, o.Raw
		if version < objV1 || version > objV3 {
			t.Fatalf("accepted version %d", version)
		}
		if (env.ClientIP == "") != (env.ClientIPSource == "") || len(env.ClientIP) > maxClientIP || len(env.HELO) > maxHELO {
			t.Fatalf("accepted %+v", env)
		}
		if env.ClientIP != "" {
			if a, err := netip.ParseAddr(env.ClientIP); err != nil || a.String() != env.ClientIP {
				t.Fatalf("accepted client IP %q", env.ClientIP)
			}
		}
		if (version == objV3) != (o.Check != nil) || len(o.Check) > MaxCheck {
			t.Fatalf("check %d bytes at version %d", len(o.Check), version)
		}
		if len(raw)+len(o.Check) > len(p) {
			t.Fatalf("raw longer than the plaintext")
		}
	})
}

func FuzzParseRecord(f *testing.F) {
	f.Add("eyJhIjoxfQ.AAAA")
	f.Add("..")
	_, priv, _ := ed25519.GenerateKey(nil)
	pub := priv.Public().(ed25519.PublicKey)
	f.Fuzz(func(t *testing.T, s string) {
		if _, err := ParseRecord(s, pub); err == nil {
			t.Fatalf("a random key verified %q", s)
		}
	})
}

func FuzzParseKeys(f *testing.F) {
	f.Add([]byte(`{"addresses":[]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		keys, err := ParseKeys(b)
		if err != nil {
			return
		}
		for id, k := range keys {
			if hex.EncodeToString(k.MailboxID) != id || k.Signing == nil || k.Decryption == nil {
				t.Fatalf("bad entry for %s", id)
			}
		}
	})
}

// The +tag parser must never panic, and must accept only a token minted with
// the right key.
func FuzzCheckReplyToken(f *testing.F) {
	k := &Keys{Signing: ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))}
	tok, _ := MintReplyToken(k, "0123456789")
	f.Add("worker+" + tok + "@fountbox.com")
	f.Add("worker@fountbox.com")
	f.Add("a+b+c@d@e")
	f.Fuzz(func(t *testing.T, recipient string) {
		r := CheckReplyToken(k, recipient)
		if r == nil || r.Handle == "" {
			return
		}
		if !validHex(r.Handle, replyHandleLen) || r.Error != "" {
			t.Fatalf("checked as %+v", r)
		}
		if want, _ := MintReplyToken(k, r.Handle); !strings.Contains(strings.ToLower(recipient), "+"+want) {
			t.Fatalf("accepted %q", recipient)
		}
	})
}
