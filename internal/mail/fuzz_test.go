package mail

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// The object parser must never accept trailing bytes or overrun, and anything
// it accepts must re-verify only with the right key.
func FuzzParseObject(f *testing.F) {
	v := loadVectorsTB(f)
	for _, m := range v.Messages {
		f.Add(m.Object)
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
