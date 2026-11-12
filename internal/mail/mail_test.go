package mail

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
)

func TestCanonicalMatchesTheEdgeVector(t *testing.T) {
	v := loadVectors(t)
	r := v.Request
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(v.SigningKey), []byte(Canonical(r.Method, r.Path, []byte(r.Body), r.Timestamp, r.Nonce)))
	if got := base64.StdEncoding.EncodeToString(sig); got != r.Signature {
		t.Fatalf("signature %s, the edge accepted %s", got, r.Signature)
	}
}

func TestOpenEdgeObjects(t *testing.T) {
	for _, path := range []string{vectorsV2, vectorsV1} {
		t.Run(path, func(t *testing.T) {
			openEdgeObjects(t, loadVectorsTB(t, path), byte(map[string]int{vectorsV2: 2, vectorsV1: 1}[path]))
		})
	}
}

func openEdgeObjects(t *testing.T, v *vectors, version byte) {
	keys, err := ParseKeys(v.keysJSON())
	if err != nil {
		t.Fatal(err)
	}
	k := keys[v.MailboxID]
	for _, m := range v.Messages {
		o, err := ParseObject(m.Object)
		if err != nil {
			t.Fatal(err)
		}
		pub, _ := hex.DecodeString(v.BootKeys[m.Boot])
		if err := o.Verify(pub); err != nil {
			t.Fatalf("seq %d: %v", m.Sequence, err)
		}
		if o.Version != version || o.Sequence != m.Sequence || hexOf(o.BootID) != m.Boot || hexOf(o.EdgeID) != m.EdgeID {
			t.Fatalf("header %+v doesn't match %+v", o, m)
		}
		env, raw, err := o.Open(k)
		if err != nil {
			t.Fatal(err)
		}
		want := Envelope{Sender: m.Sender, Recipient: m.Recipient, ClientIP: m.ClientIP, HELO: m.HELO}
		if m.ClientIPFrom == ipFromProxy {
			want.ClientIPSource = ClientIPGatewayProxy
		}
		if env != want || string(raw) != string(m.Raw) {
			t.Fatalf("opened %+v %q, want %+v", env, raw, want)
		}
		other := v.BootKeys[v.Messages[0].Boot]
		if m.Boot != v.Messages[0].Boot {
			wrong, _ := hex.DecodeString(other)
			if err := o.Verify(wrong); !errors.Is(err, ErrSignature) {
				t.Fatalf("verified against another boot's key: %v", err)
			}
		}
	}
}

func TestObjectTamperIsCaught(t *testing.T) {
	v := loadVectors(t)
	m := v.Messages[0]
	pub, _ := hex.DecodeString(v.BootKeys[m.Boot])
	for i := range len(m.Object) {
		b := slices.Clone(m.Object)
		b[i] ^= 0x01
		o, err := ParseObject(b)
		if err != nil {
			continue
		}
		if o.Verify(pub) == nil {
			t.Fatalf("flipping byte %d still verifies", i)
		}
	}
	for _, n := range []int{0, 10, headerLen, len(m.Object) - 1} {
		if _, err := ParseObject(m.Object[:n]); err == nil {
			t.Fatalf("truncated to %d parsed", n)
		}
	}
	if _, err := ParseObject(append(slices.Clone(m.Object), 0)); err == nil {
		t.Fatal("trailing byte parsed")
	}
}

func TestOpenRefusesAnotherKey(t *testing.T) {
	v := loadVectors(t)
	o, _ := ParseObject(v.Messages[0].Object)
	keys, _ := ParseKeys(v.keysJSON())
	k := *keys[v.MailboxID]
	other, _ := ParseKeys([]byte(`{"addresses":[{"mailbox_id":"` + v.MailboxID + `","signing_key":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `","decryption_key":"` + base64.StdEncoding.EncodeToString(append(make([]byte, 31), 9)) + `"}]}`))
	if _, _, err := o.Open(other[v.MailboxID]); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("another key: %v", err)
	}
	k.MailboxID = make([]byte, 32)
	if _, _, err := o.Open(&k); !errors.Is(err, ErrWrongMailbox) {
		t.Fatalf("another mailbox: %v", err)
	}
}

func TestParseKeys(t *testing.T) {
	v := loadVectors(t)
	if _, err := ParseKeys(v.keysJSON()); err != nil {
		t.Fatal(err)
	}
	// A role key file from edgectl role-keygen, with mailbox_id added.
	role := `{"addresses":[{"mailbox_id":"` + v.MailboxID + `","role":"abuse","decryption_key":"` + base64.StdEncoding.EncodeToString(v.DecryptionKey) +
		`","signing_key":"` + base64.StdEncoding.EncodeToString(v.SigningKey) + `","mailbox_key":"AA==","owner_change_key":"AA==","passkey_key":"AA=="}]}`
	if _, err := ParseKeys([]byte(role)); err != nil {
		t.Fatalf("role file: %v", err)
	}
	for _, bad := range []string{
		`{}x`, `{"addresses":[{"mailbox_id":"zz"}]}`, `{"other":1}`,
		`{"addresses":[{"mailbox_id":"` + strings.ToUpper(v.MailboxID) + `","signing_key":"` + base64.StdEncoding.EncodeToString(v.SigningKey) + `","decryption_key":"` + base64.StdEncoding.EncodeToString(v.DecryptionKey) + `"}]}`,
		`{"addresses":[{"mailbox_id":"` + v.MailboxID + `","signing_key":"AA==","decryption_key":"` + base64.StdEncoding.EncodeToString(v.DecryptionKey) + `"}]}`,
	} {
		if _, err := ParseKeys([]byte(bad)); !errors.Is(err, ErrBadKeys) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	dup := strings.Replace(string(v.keysJSON()), `[{`, `[{"mailbox_id":"`+v.MailboxID+`","signing_key":"`+base64.StdEncoding.EncodeToString(v.SigningKey)+`","decryption_key":"`+base64.StdEncoding.EncodeToString(v.DecryptionKey)+`"},{`, 1)
	if _, err := ParseKeys([]byte(dup)); !errors.Is(err, ErrBadKeys) {
		t.Errorf("duplicate: %v", err)
	}
}

func newService(t *testing.T) (*Service, *fakeEdge, *fakeChecker, *vectors) {
	v := loadVectors(t)
	f := newFakeEdge(t, v)
	c := &fakeChecker{}
	s := New(f, c)
	if err := s.SetKeys(v.keysJSON()); err != nil {
		t.Fatal(err)
	}
	return s, f, c, v
}

func TestSyncFindsTheWithheldMessage(t *testing.T) {
	s, f, checker, v := newService(t)
	ctx := context.Background()
	mb := v.MailboxID

	lr, err := s.Handle(ctx, OpList, mb, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	listed := lr.(map[string]any)["messages"].([]Listed)
	if len(listed) != len(v.Messages) {
		t.Fatalf("listed %d", len(listed))
	}
	// Before anything is fetched, gaps knows the records but can't call anything withheld.
	gr, err := s.Handle(ctx, OpGaps, mb, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	g := gr.(GapsResult)
	if len(g.Records) != 2 || g.Ledger.Complete {
		t.Fatalf("gaps before fetch: %+v", g)
	}
	reasons := map[uint64]string{}
	for _, r := range g.Records {
		reasons[r.Sequence] = r.Reason
		if !r.MessageBootKnown || r.BootAttested {
			t.Fatalf("record %+v", r)
		}
	}
	if reasons[2] != ReasonExpired || reasons[3] != ReasonVoid {
		t.Fatalf("reasons %v", reasons)
	}

	var last *Message
	for _, m := range listed {
		r, err := s.Handle(ctx, OpGet, mb, m.ID, nil)
		if err != nil {
			t.Fatal(err)
		}
		last = r.(*Message)
		if string(last.SenderCheck) != `{"ok":true}` || last.Reused || last.Quarantined {
			t.Fatalf("message %+v", last)
		}
	}
	if !last.Ledger.Complete || !slices.Equal(last.Ledger.Missing, v.Withheld) {
		t.Fatalf("after a full fetch: %+v, want missing %v", last.Ledger, v.Withheld)
	}
	if len(checker.calls) != len(v.Messages) || checker.calls[0].Recipient != "worker@fountbox.com" || checker.calls[0].ReceivedAt.IsZero() {
		t.Fatalf("checker saw %+v", checker.calls)
	}
	var gotIPs, wantIPs []string
	for i, c := range checker.calls {
		gotIPs = append(gotIPs, c.ClientIP+"|"+c.ClientIPSource+"|"+c.HELO)
		m := v.Messages[i]
		src := ""
		if m.ClientIP != "" {
			src = ClientIPGatewayProxy
		}
		wantIPs = append(wantIPs, m.ClientIP+"|"+src+"|"+m.HELO)
	}
	slices.Sort(gotIPs)
	slices.Sort(wantIPs)
	if !slices.Equal(gotIPs, wantIPs) || !slices.Contains(gotIPs, "192.0.2.25|gateway_proxy|mail.example.com") {
		t.Fatalf("checker saw addresses %v, want %v", gotIPs, wantIPs)
	}
	for _, m := range listed {
		if _, err := s.Handle(ctx, OpDelete, mb, m.ID, nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.objects) != 0 {
		t.Fatalf("left %d objects", len(f.objects))
	}

	// The ledger survives a restart through the app.
	saved, _ := s.Handle(ctx, OpLedger, mb, "", nil)
	b, _ := json.Marshal(saved)
	s2, _, _, _ := newService(t)
	r, err := s2.Handle(ctx, OpRestore, mb, "", b)
	if err != nil {
		t.Fatal(err)
	}
	if sum := r.(Summary); !slices.Equal(sum.Missing, v.Withheld) || sum.High != 6 || sum.Floor != 4 {
		t.Fatalf("restored %+v", sum)
	}
}

func TestAttestedBootIsMarked(t *testing.T) {
	s, f, _, v := newService(t)
	m := v.Messages[len(v.Messages)-1]
	key, _ := hex.DecodeString(v.BootKeys[m.Boot])
	f.attested = key
	r, err := s.Handle(context.Background(), OpGet, v.MailboxID, m.EdgeID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !r.(*Message).BootAttested {
		t.Fatal("the attested boot's message isn't marked attested")
	}
	r, err = s.Handle(context.Background(), OpGet, v.MailboxID, v.Messages[0].EdgeID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.(*Message).BootAttested {
		t.Fatal("an older boot's message is marked attested")
	}
	f.attErr = errors.New("attestation failed")
	if _, err := s.Handle(context.Background(), OpGet, v.MailboxID, v.Messages[1].EdgeID, nil); err == nil {
		t.Fatal("fetched through a failed attestation")
	}
}

func TestPlantedBootKeyFailsTheMessage(t *testing.T) {
	s, f, _, v := newService(t)
	m := v.Messages[0]
	_, other, _ := ed25519.GenerateKey(nil)
	planted, _ := json.Marshal(boot{BootID: m.Boot, SigningKey: other.Public().(ed25519.PublicKey)})
	f.v.Boots[m.Boot] = string(planted)
	if _, err := s.Handle(context.Background(), OpGet, v.MailboxID, m.EdgeID, nil); !errors.Is(err, ErrSignature) {
		t.Fatalf("planted key: %v", err)
	}
}

func TestSequenceReuseIsAnAnomaly(t *testing.T) {
	s, f, _, v := newService(t)
	ctx := context.Background()
	m := v.Messages[1] // sequence 4, so the floor stays at 0
	if _, err := s.Handle(ctx, OpGet, v.MailboxID, m.EdgeID, nil); err != nil {
		t.Fatal(err)
	}
	// A rolled-back counter gave sequence 4 to another message, which was voided.
	var records []string
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/gaps" || !f.authorized(r) {
			return false
		}
		json.NewEncoder(w).Encode(map[string]any{"records": records})
		return true
	}
	records = []string{signRecord(t, v, GapRecord{MailboxID: v.MailboxID, EdgeID: strings.Repeat("ab", 16), Sequence: m.Sequence, BootID: m.Boot, MessageBoot: m.Boot, Reason: ReasonVoid})}
	r, err := s.Handle(ctx, OpGaps, v.MailboxID, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if a := r.(GapsResult).Ledger.Anomalies; len(a) != 1 || a[0].Kind != AnomalyReuse || a[0].Sequence != m.Sequence {
		t.Fatalf("anomalies %+v", a)
	}

	// Another mailbox's record is an anomaly too, and isn't counted.
	records = []string{signRecord(t, v, GapRecord{MailboxID: strings.Repeat("cd", 32), EdgeID: strings.Repeat("ab", 16), Sequence: 1, BootID: m.Boot, MessageBoot: m.Boot, Reason: ReasonVoid})}
	r, err = s.Handle(ctx, OpGaps, v.MailboxID, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if g := r.(GapsResult); len(g.Records) != 0 || len(g.Ledger.Anomalies) != 2 || g.Ledger.Anomalies[1].Kind != AnomalyBadRecord || g.Ledger.Floor != 0 {
		t.Fatalf("foreign record: %+v", g)
	}

	// Records must come back above after, lowest first.
	records = []string{
		signRecord(t, v, GapRecord{MailboxID: v.MailboxID, EdgeID: strings.Repeat("01", 16), Sequence: 3, BootID: m.Boot, MessageBoot: m.Boot, Reason: ReasonVoid}),
		signRecord(t, v, GapRecord{MailboxID: v.MailboxID, EdgeID: strings.Repeat("02", 16), Sequence: 2, BootID: m.Boot, MessageBoot: m.Boot, Reason: ReasonVoid}),
	}
	if _, err := s.Handle(ctx, OpGaps, v.MailboxID, "", nil); !errors.Is(err, ErrEdge) {
		t.Fatalf("out of order records: %v", err)
	}
}

func TestQuarantineAfterThreeFailures(t *testing.T) {
	s, _, checker, v := newService(t)
	checker.err = errors.New("verifier crashed")
	id := v.Messages[0].EdgeID
	for i := 1; i <= MaxFailures+1; i++ {
		r, err := s.Handle(context.Background(), OpGet, v.MailboxID, id, nil)
		if err != nil {
			t.Fatal(err)
		}
		m := r.(*Message)
		if m.Quarantined != (i >= MaxFailures) || m.SenderCheck != nil {
			t.Fatalf("attempt %d: %+v", i, m)
		}
	}
	if len(checker.calls) != MaxFailures {
		t.Fatalf("checker ran %d times", len(checker.calls))
	}
}

func TestHandleRefusesBadRequests(t *testing.T) {
	s, f, _, v := newService(t)
	ctx := context.Background()
	id := v.Messages[0].EdgeID
	for _, c := range []struct{ op, mb, path, body string }{
		{"steal", v.MailboxID, "", ""},
		{OpList, "nothex", "", ""},
		{OpList, v.MailboxID, id, ""},
		{OpGet, v.MailboxID, "", ""},
		{OpGet, v.MailboxID, "../boots", ""},
		{OpGet, v.MailboxID, strings.ToUpper(id), ""},
		{OpList, v.MailboxID, "", "x"},
		{OpRestore, v.MailboxID, "", `{"delivered":{},"x":1}`},
	} {
		if _, err := s.Handle(ctx, c.op, c.mb, c.path, []byte(c.body)); !errors.Is(err, ErrRequest) {
			t.Errorf("%+v: %v", c, err)
		}
	}
	if _, err := s.Handle(ctx, OpList, strings.Repeat("00", 32), "", nil); !errors.Is(err, ErrNoKeys) {
		t.Errorf("unknown mailbox: %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("refused requests reached the edge: %v", f.calls)
	}
	if _, err := s.Handle(ctx, OpGet, v.MailboxID, strings.Repeat("00", 16), nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing message: %v", err)
	}
}

func TestGapRecordChecks(t *testing.T) {
	v := loadVectors(t)
	var g struct{ Records []string }
	json.Unmarshal([]byte(v.GapsResponse), &g)
	for _, tok := range g.Records {
		boot, err := RecordBoot(tok)
		if err != nil {
			t.Fatal(err)
		}
		key, _ := hex.DecodeString(v.BootKeys[boot])
		if _, err := ParseRecord(tok, key); err != nil {
			t.Fatal(err)
		}
		_, other, _ := ed25519.GenerateKey(nil)
		if _, err := ParseRecord(tok, other.Public().(ed25519.PublicKey)); !errors.Is(err, ErrRecord) {
			t.Fatalf("another key: %v", err)
		}
		if _, err := ParseRecord(tok+".x", key); !errors.Is(err, ErrRecord) {
			t.Fatalf("three parts: %v", err)
		}
	}
}

// signRecord signs rec as the boot it names. The generator derives each boot's
// key from a fixed seed: boot A from 11, boot B from 21.
func signRecord(t *testing.T, v *vectors, rec GapRecord) string {
	t.Helper()
	for _, b := range []byte{11, 21} {
		seed := make([]byte, 32)
		for i := range seed {
			seed[i] = b + byte(i)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		if hex.EncodeToString(priv.Public().(ed25519.PublicKey)) != v.BootKeys[rec.BootID] {
			continue
		}
		payload, _ := json.Marshal(rec)
		enc := base64.RawURLEncoding
		return enc.EncodeToString(payload) + "." + enc.EncodeToString(ed25519.Sign(priv, payload))
	}
	t.Fatalf("no seed for boot %s", rec.BootID)
	return ""
}

func TestListPassesPausedOnlyWhenTheEdgeSaysIt(t *testing.T) {
	ctx := context.Background()
	for _, paused := range []bool{true, false} {
		s, f, _, v := newService(t)
		f.paused = paused
		lr, err := s.Handle(ctx, OpList, v.MailboxID, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := lr.(map[string]any)["paused"]; !ok || got != paused {
			t.Fatalf("paused %v: list gave %v (present %v)", paused, got, ok)
		}
	}

	s, f, _, v := newService(t)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != "GET" || r.URL.Path != "/mail" {
			return false
		}
		w.Write([]byte(`{"messages":[]}`))
		return true
	}
	lr, err := s.Handle(ctx, OpList, v.MailboxID, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := lr.(map[string]any)["paused"]; ok {
		t.Fatalf("an edge that didn't say gave paused %v", got)
	}
}
