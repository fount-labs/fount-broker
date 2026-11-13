package coordinator

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/fount-labs/fount-broker/internal/mail"
	"github.com/fount-labs/fount-broker/internal/mail/decide"
	"github.com/fount-labs/fount-broker/internal/mail/mailtest"
)

const workerAddr = "ap@fountbox.com"

func sealedMail(t *testing.T, check func(raw []byte) []byte) ([]byte, ed25519.PublicKey, *mail.Keys) {
	t.Helper()
	dec, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := &mail.Keys{MailboxID: make([]byte, 32), Decryption: dec}
	rand.Read(keys.MailboxID)
	pub, priv, _ := ed25519.GenerateKey(nil)
	raw := []byte("From: dana@example.com\r\nTo: " + workerAddr + "\r\n\r\nPlease file Q3.\r\n")
	obj, err := mailtest.SealV3(mailtest.Object{
		EdgeID: make([]byte, 16), MailboxID: keys.MailboxID, ReceivedAt: time.UnixMilli(1_700_000_000_000),
		Sequence: 7, BootID: make([]byte, 16), Sender: "dana@example.com", Recipient: workerAddr,
		Check: check(raw), Raw: raw,
	}, dec.PublicKey(), priv)
	if err != nil {
		t.Fatal(err)
	}
	return obj, pub, keys
}

func TestOpenMailDecidesFromTheEdgesCheck(t *testing.T) {
	obj, boot, keys := sealedMail(t, func(raw []byte) []byte { return mailtest.Check("dana@example.com", workerAddr, raw) })
	m, err := OpenMail(obj, boot, true, keys)
	if err != nil {
		t.Fatal(err)
	}
	if m.Check == nil || m.CheckError != "" || m.Sequence != 7 || m.Envelope.Sender != "dana@example.com" {
		t.Fatalf("%+v", m)
	}
	w := decide.Worker{Address: workerAddr, Requesters: []decide.Requester{{Address: "dana@example.com", DKIMDomain: "example.com", AutoRun: true}}}
	r := m.Received()
	if d := decide.Decide(w, r, "", decide.FirstSigners([]decide.Received{r})); d.Verdict != decide.Request {
		t.Fatalf("%+v", d)
	}
	m, _ = OpenMail(obj, boot, false, keys)
	r = m.Received()
	if d := decide.Decide(w, r, "", decide.FirstSigners([]decide.Received{r})); d.Verdict != decide.NeedsConfirmation {
		t.Fatalf("unattested: %+v", d)
	}
}

func TestOpenMailHoldsABadCheck(t *testing.T) {
	obj, boot, keys := sealedMail(t, func([]byte) []byte { return []byte(`{"v":1,"checked_by":"edge","error":"dns"}`) })
	m, err := OpenMail(obj, boot, true, keys)
	if err != nil {
		t.Fatal(err)
	}
	if m.Check != nil || m.CheckError == "" {
		t.Fatalf("%+v", m)
	}
	w := decide.Worker{Address: workerAddr, Requesters: []decide.Requester{{Address: "dana@example.com", DKIMDomain: "example.com", AutoRun: true}}}
	if d := decide.Decide(w, m.Received(), "", nil); d.Verdict != decide.Held {
		t.Fatalf("%+v", d)
	}
}

func TestOpenMailRefuses(t *testing.T) {
	obj, boot, keys := sealedMail(t, func(raw []byte) []byte { return mailtest.Check("dana@example.com", workerAddr, raw) })
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := OpenMail(obj, other, true, keys); !errors.Is(err, mail.ErrSignature) {
		t.Fatalf("another boot key: %v", err)
	}
	// The version byte is under the signature, so an old version needs an old
	// object; re-sign one with version 2 to check the refusal itself.
	v2 := append([]byte{}, obj...)
	v2[4] = 2
	body := v2[:len(v2)-ed25519.SignatureSize]
	pub, priv, _ := ed25519.GenerateKey(nil)
	v2 = append(append([]byte{}, body...), ed25519.Sign(priv, body)...)
	if _, err := OpenMail(v2, pub, true, keys); !errors.Is(err, ErrNoEdgeCheck) {
		t.Fatalf("version 2: %v", err)
	}
	k := *keys
	k.MailboxID = make([]byte, 32)
	binary.BigEndian.PutUint32(k.MailboxID, 1)
	if _, err := OpenMail(obj, boot, true, &k); !errors.Is(err, mail.ErrWrongMailbox) {
		t.Fatalf("another mailbox: %v", err)
	}
}
