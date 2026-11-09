package mail

import (
	"crypto/ed25519"
	"encoding/hex"
	"net/netip"
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
	f.Fuzz(func(t *testing.T, version byte, p []byte) {
		env, raw, err := unframe(version, p)
		if err != nil {
			return
		}
		if version != objV1 && version != objV2 {
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
		if len(raw) > len(p) {
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
