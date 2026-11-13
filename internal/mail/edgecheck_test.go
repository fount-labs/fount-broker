package mail

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/fount-labs/fount-broker/internal/mail/mailtest"
)

func TestDecodeEdgeCheck(t *testing.T) {
	raw := []byte("From: dana@example.com\r\n\r\nhi\r\n")
	good := mailtest.Check("dana@example.com", "w@fountbox.com", raw)
	c, err := DecodeEdgeCheck(good, raw)
	if err != nil || c.From.Address != "dana@example.com" || !c.Aligned || len(c.DKIM) != 1 || *c.DateSkewSeconds != -30 {
		t.Fatalf("%+v %v", c, err)
	}
	edit := func(f func(map[string]any)) []byte {
		var m map[string]any
		json.Unmarshal(good, &m)
		f(m)
		b, _ := json.Marshal(m)
		return b
	}
	for name, tc := range map[string]struct {
		b    []byte
		want error
	}{
		"unknown field":   {edit(func(m map[string]any) { m["spf"] = map[string]any{"result": "pass"} }), ErrEdgeCheckMalformed},
		"version 2":       {edit(func(m map[string]any) { m["v"] = 2 }), ErrEdgeCheckMalformed},
		"not the edge":    {edit(func(m map[string]any) { m["checked_by"] = "runner" }), ErrEdgeCheckMalformed},
		"another message": {edit(func(m map[string]any) { m["raw_sha256"] = strings.Repeat("0", 64) }), ErrEdgeCheckMalformed},
		"trailing data":   {append(append([]byte{}, good...), "{}"...), ErrEdgeCheckMalformed},
		"empty":           {nil, ErrEdgeCheckMalformed},
		"couldn't run":    {[]byte(`{"v":1,"checked_by":"edge","error":"dns timeout"}`), ErrEdgeCheckFailed},
	} {
		if _, err := DecodeEdgeCheck(tc.b, raw); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
}

// replaceWithV3 swaps a vector message for a version 3 object carrying check,
// signed by a new key that the fake edge serves as that boot's.
func replaceWithV3(t *testing.T, f *fakeEdge, v *vectors, i int, check func(raw []byte) []byte) {
	t.Helper()
	m := v.Messages[i]
	keys, err := ParseKeys(v.keysJSON())
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	edgeID, _ := hex.DecodeString(m.EdgeID)
	mailboxID, _ := hex.DecodeString(v.MailboxID)
	bootID, _ := hex.DecodeString(m.Boot)
	o, _ := ParseObject(m.Object)
	obj, err := mailtest.SealV3(mailtest.Object{
		EdgeID: edgeID, MailboxID: mailboxID, ReceivedAt: o.ReceivedAt, Sequence: m.Sequence, BootID: bootID,
		Sender: m.Sender, Recipient: m.Recipient, Check: check(m.Raw), Raw: m.Raw,
	}, keys[v.MailboxID].Decryption.PublicKey(), priv)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(boot{BootID: m.Boot, SigningKey: pub})
	f.v.Boots[m.Boot] = string(b)
	f.objects[m.EdgeID] = obj
}

func TestV3UsesTheEdgesCheck(t *testing.T) {
	s, f, checker, v := newService(t)
	var want []byte
	replaceWithV3(t, f, v, 0, func(raw []byte) []byte {
		want = mailtest.Check("dana@example.com", v.Messages[0].Recipient, raw)
		return want
	})
	r, err := s.Handle(context.Background(), OpGet, v.MailboxID, v.Messages[0].EdgeID, nil)
	if err != nil {
		t.Fatal(err)
	}
	m := r.(*Message)
	if string(m.SenderCheck) != string(want) || m.SenderCheckError != "" || m.Quarantined || string(m.Raw) != string(v.Messages[0].Raw) {
		t.Fatalf("message %+v", m)
	}
	if len(checker.calls) != 0 {
		t.Fatal("the local verifier ran on a version 3 message")
	}
}

func TestV3BadCheckIsAnError(t *testing.T) {
	for name, check := range map[string]func([]byte) []byte{
		"couldn't run": func([]byte) []byte { return []byte(`{"v":1,"checked_by":"edge","error":"dns"}`) },
		"other raw":    func([]byte) []byte { return mailtest.Check("dana@example.com", "w@fountbox.com", []byte("other")) },
	} {
		t.Run(name, func(t *testing.T) {
			s, f, checker, v := newService(t)
			replaceWithV3(t, f, v, 0, check)
			r, err := s.Handle(context.Background(), OpGet, v.MailboxID, v.Messages[0].EdgeID, nil)
			if err != nil {
				t.Fatal(err)
			}
			m := r.(*Message)
			if m.SenderCheck != nil || m.SenderCheckError == "" || len(checker.calls) != 0 {
				t.Fatalf("message %+v, checker calls %d", m, len(checker.calls))
			}
		})
	}
}
