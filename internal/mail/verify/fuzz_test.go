package verify

import (
	"context"
	"strings"
	"testing"
)

// Check must never panic on a message, and a From it accepts must be one
// plain address.
func FuzzCheck(f *testing.F) {
	f.Add([]byte(message("")))
	f.Add([]byte("From: a@b\r\nDKIM-Signature: v=1; a=rsa-sha256; d=b; s=s; h=from; bh=; b=\r\n\r\n"))
	z := newZone()
	f.Fuzz(func(t *testing.T, raw []byte) {
		v, err := Check(context.Background(), Input{Raw: raw, Recipient: recipient}, z.resolver())
		if err != nil {
			return
		}
		if v.From.Error == "" && (strings.Count(v.From.Address, "@") != 1 || strings.ContainsAny(v.From.Address, ",;:()<> \r\n")) {
			t.Fatalf("accepted From %q", v.From.Address)
		}
		if v.Aligned {
			t.Fatal("an unsigned fuzz input is aligned")
		}
	})
}

func FuzzParseAnswer(f *testing.F) {
	z := newZone()
	z.txt["example.com"] = []string{"v=spf1 -all"}
	a, _ := z.Ask(context.Background(), "TXT", "example.com")
	f.Add(a[0])
	f.Fuzz(func(t *testing.T, msg []byte) {
		_, _ = parseAnswer(msg, "TXT", "example.com")
	})
}
