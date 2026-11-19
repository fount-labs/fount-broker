package mail

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fount-labs/fount-broker/internal/mail/mailtest"
)

// generation makes generation n under the fake edge's authority.
func (f *fakeEdge) generation(t *testing.T, n uint64) Generation {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	cert, err := SignGenerationCertificate(f.authority, GenerationCertificate{Generation: n, CoordinatorKey: pub, IssuedAt: 1})
	if err != nil {
		t.Fatal(err)
	}
	return Generation{Number: n, Certificate: cert, Key: priv}
}

func TestCanonicalGenerationIsTheEdgesString(t *testing.T) {
	// fount-mail-edge internal/deviceapi canonicalString, for "{}" with
	// Fount-Generation: 7.
	const want = "POST\n/coordinator/changes\n44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a\n1700000000\nn1\n7"
	if got := CanonicalGeneration("POST", "/coordinator/changes", []byte("{}"), 1700000000, "n1", 7); got != want {
		t.Fatalf("%q", got)
	}
	if CanonicalGeneration("GET", "/mail", nil, 1, "n", 0) != Canonical("GET", "/mail", nil, 1, "n") {
		t.Fatal("generation 0 changed the string")
	}
}

func TestCertificateRoundTrip(t *testing.T) {
	apub, apriv, _ := ed25519.GenerateKey(nil)
	cpub, _, _ := ed25519.GenerateKey(nil)
	cert, err := SignGenerationCertificate(apriv, GenerationCertificate{Generation: 3, CoordinatorKey: cpub, IssuedAt: 9})
	if err != nil {
		t.Fatal(err)
	}
	c, err := ReadGenerationCertificate(cert, apub)
	if err != nil || c.Generation != 3 || !cpub.Equal(ed25519.PublicKey(c.CoordinatorKey)) || c.IssuedAt != 9 {
		t.Fatalf("%+v %v", c, err)
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := ReadGenerationCertificate(cert, other); !errors.Is(err, ErrBadCertificate) {
		t.Fatalf("another authority: %v", err)
	}
	if _, err := SignGenerationCertificate(apriv, GenerationCertificate{CoordinatorKey: cpub}); err == nil {
		t.Fatal("generation 0 signed")
	}
}

func TestSetGenerationChecksTheCertificate(t *testing.T) {
	s, f, _, _ := newService(t)
	g := f.generation(t, 2)
	bad := g
	bad.Number = 3
	if err := s.SetGeneration(bad); !errors.Is(err, ErrBadCertificate) {
		t.Fatalf("another number: %v", err)
	}
	_, bad.Key, _ = ed25519.GenerateKey(nil)
	bad.Number = 2
	if err := s.SetGeneration(bad); !errors.Is(err, ErrBadCertificate) {
		t.Fatalf("another key: %v", err)
	}
	if s.Generation() != 0 {
		t.Fatal("a bad generation was kept")
	}
	if err := s.SetGeneration(g); err != nil || s.Generation() != 2 {
		t.Fatalf("%v %d", err, s.Generation())
	}
}

// An enrolled mailbox's calls must name the generation; the fake edge holds
// them to the fence, so a call without it fails here as it would at the edge.
func TestTheFenceAfterEnrolling(t *testing.T) {
	s, f, _, v := newService(t)
	ctx := context.Background()
	if err := s.AdvanceGeneration(ctx); !errors.Is(err, ErrNoGeneration) {
		t.Fatalf("advance without a generation: %v", err)
	}
	g := f.generation(t, 4)
	if err := s.SetGeneration(g); err != nil {
		t.Fatal(err)
	}
	if err := s.AdvanceGeneration(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Enroll(ctx, v.MailboxID); err != nil {
		t.Fatal(err)
	}
	if err := s.Enroll(ctx, v.MailboxID); err != nil {
		t.Fatalf("enrolling again: %v", err)
	}
	if !f.coord.Mailbox(v.MailboxID).Enrolled {
		t.Fatal("not enrolled")
	}
	if _, err := s.List(ctx, v.MailboxID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, v.MailboxID, v.Messages[0].EdgeID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Gaps(ctx, v.MailboxID); err != nil {
		t.Fatal(err)
	}

	// A Service that names no generation is refused.
	bare := New(f, &fakeChecker{})
	bare.SetKeys(v.keysJSON())
	_, err := bare.List(ctx, v.MailboxID)
	var ee *EdgeError
	if !errors.Is(err, ErrGenerationRequired) || !errors.Is(err, ErrEdge) || !errors.As(err, &ee) || ee.Status != http.StatusConflict {
		t.Fatalf("no generation: %v", err)
	}

	// One the edge hasn't seen.
	ahead := New(f, &fakeChecker{})
	ahead.SetKeys(v.keysJSON())
	ahead.SetGeneration(f.generation(t, 9))
	if _, err := ahead.List(ctx, v.MailboxID); !errors.Is(err, ErrUnknownGeneration) {
		t.Fatalf("unseen generation: %v", err)
	}

	// The same number with another key.
	twin := New(f, &fakeChecker{})
	twin.SetGeneration(f.generation(t, 4))
	if err := twin.AdvanceGeneration(ctx); !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("conflict: %v", err)
	}

	// A newer coordinator takes over: this one is stale everywhere.
	newer := New(f, &fakeChecker{})
	newer.SetKeys(v.keysJSON())
	newer.SetGeneration(f.generation(t, 5))
	if err := newer.AdvanceGeneration(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(ctx, v.MailboxID); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("stale list: %v", err)
	}
	if err := s.AdvanceGeneration(ctx); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("stale advance: %v", err)
	}
	if _, err := s.Changes(ctx, "", 0); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("stale changes: %v", err)
	}
	if _, err := newer.List(ctx, v.MailboxID); err != nil {
		t.Fatal(err)
	}
}

func TestSendAndSentQueryNameTheGeneration(t *testing.T) {
	s, f, _, v := newService(t)
	ctx := context.Background()
	s.SetGeneration(f.generation(t, 1))
	if err := s.AdvanceGeneration(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Enroll(ctx, v.MailboxID); err != nil {
		t.Fatal(err)
	}
	var sent []string
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/send" && r.URL.Path != "/sent/query" {
			return false
		}
		var body json.RawMessage
		json.NewDecoder(r.Body).Decode(&body)
		if ref := f.coord.Address(r, body, v.MailboxID, f.addressKey(v.MailboxID)); ref != nil {
			ref.Write(w)
			return true
		}
		sent = append(sent, r.URL.Path+" "+r.Header.Get(HeaderGeneration))
		if r.URL.Path == "/send" {
			w.WriteHeader(http.StatusConflict)
			w.Write([]byte(`{"error":"in doubt","code":"send_in_doubt"}`))
			return true
		}
		w.Write([]byte(`{"records":[{"message_id":"<a@b>","state":"done","sha256":"","first_at":1,"updated_at":2,"results":[{"recipient":"x@y","status":"sent","detail":""}]}]}`))
		return true
	}
	if _, err := s.Send(ctx, v.MailboxID, []byte(`{"raw":"eA=="}`)); !errors.Is(err, ErrSendInDoubt) {
		t.Fatalf("send: %v", err)
	}
	recs, err := s.SentQuery(ctx, v.MailboxID, []string{"<a@b>"})
	if err != nil || len(recs) != 1 || recs[0].State != "done" || recs[0].Results[0].Status != "sent" {
		t.Fatalf("%+v %v", recs, err)
	}
	if len(sent) != 2 || sent[0] != "/send 1" || sent[1] != "/sent/query 1" {
		t.Fatalf("%v", sent)
	}
}

func TestDevGenerationsMoveOnPerProcess(t *testing.T) {
	apub, apriv, _ := ed25519.GenerateKey(nil)
	path := filepath.Join(t.TempDir(), "generation")
	ctx := context.Background()
	d1 := &DevGenerations{Authority: apriv, Path: path}
	g1, err := d1.Generation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := d1.Generation(ctx); again.Number != g1.Number || again.Certificate != g1.Certificate {
		t.Fatal("one process moved on twice")
	}
	g2, err := (&DevGenerations{Authority: apriv, Path: path}).Generation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if g1.Number != 1 || g2.Number != 2 || g1.Key.Equal(g2.Key) {
		t.Fatalf("%d %d", g1.Number, g2.Number)
	}
	if _, err := ReadGenerationCertificate(g2.Certificate, apub); err != nil {
		t.Fatal(err)
	}
	if err := g2.check(); err != nil {
		t.Fatal(err)
	}
}

// An invite goes on POST /coordinator/invite, signed by the generation's key,
// and the fake edge holds it to the edge's rules: enrolled, one plain-text
// recipient, the day's budget.
func TestSendInviteIsTheCoordinatorsCall(t *testing.T) {
	s, f, _, v := newService(t)
	ctx := context.Background()
	invite := func(to, id string, extra string) []byte {
		return []byte("From: w@fountbox.com\r\nTo: " + to + "\r\nSubject: Join\r\nDate: Thu, 19 Nov 2026 12:00:00 +0000\r\nMessage-ID: <" + id + ">\r\n" + extra + "\r\nHi.\r\n")
	}
	var got [][]byte
	f.coord.OnInvite = func(w http.ResponseWriter, mailbox string, message []byte) {
		got = append(got, message)
		w.Write([]byte(`{"results":[{"recipient":"ann@firm.com","status":"sent"}]}`))
	}
	if _, err := s.SendInvite(ctx, v.MailboxID, invite("ann@firm.com", "i0@x", "")); !errors.Is(err, ErrNoGeneration) {
		t.Fatalf("before a generation: %v", err)
	}
	s.SetGeneration(f.generation(t, 1))
	if err := s.AdvanceGeneration(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SendInvite(ctx, v.MailboxID, invite("ann@firm.com", "i1@x", "")); !errors.Is(err, ErrNotCoordinated) {
		t.Fatalf("not enrolled: %v", err)
	}
	if err := s.Enroll(ctx, v.MailboxID); err != nil {
		t.Fatal(err)
	}
	data, err := s.SendInvite(ctx, v.MailboxID, invite("ann@firm.com", "i2@x", "Content-Type: text/plain; charset=utf-8\r\n"))
	if err != nil || !strings.Contains(string(data), `"sent"`) || len(got) != 1 {
		t.Fatalf("%s %v", data, err)
	}
	for name, raw := range map[string][]byte{
		"two":  invite("ann@firm.com, bo@firm.com", "i3@x", ""),
		"html": invite("ann@firm.com", "i4@x", "Content-Type: text/html\r\n"),
	} {
		if _, err := s.SendInvite(ctx, v.MailboxID, raw); !errors.Is(err, ErrInviteRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	f.coord.UseInvites(v.MailboxID, mailtest.InvitesPerDay)
	if _, err := s.SendInvite(ctx, v.MailboxID, invite("ann@firm.com", "i5@x", "")); !errors.Is(err, ErrInviteLimit) {
		t.Fatalf("past the limit: %v", err)
	}
	// A newer generation has spoken: this one is stale.
	f.coord.Advance(2, f.generation(t, 2).Key.Public().(ed25519.PublicKey))
	if _, err := s.SendInvite(ctx, v.MailboxID, invite("ann@firm.com", "i6@x", "")); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("stale: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("%d invites reached the sink", len(got))
	}
}
