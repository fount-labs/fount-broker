package coordinator

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// mailSetupVectors is testdata/mail-setup.json, which Desktop's Rust port
// checks too (src-tauri/src/account/testdata/mail-setup.json in the Fount
// repo): a setup as Desktop writes it, sealed under a fixed DEK and nonce.
type mailSetupVectors struct {
	Comment   string `json:"comment"`
	Worker    string `json:"worker"`
	DEK       string `json:"dek"`
	Nonce     string `json:"nonce"`
	AAD       string `json:"aad"`
	Plaintext string `json:"plaintext"`
	Sealed    string `json:"sealed"`
	Body      string `json:"body"`
}

const mailSetupVectorsPath = "testdata/mail-setup.json"

func vectorSetup() MailSetup {
	return MailSetup{
		Mailbox: Mailbox{Address: "ap.smith@fountbox.com", MailboxID: hex.EncodeToString(seq(0x81)), SigningKey: seq(0x01), DecryptionKey: seq(0x21)},
		Requesters: []SetupRequester{
			{Address: "dana@example.com", AutoRun: true},
			{Address: "lee@client.example", AutoRun: false},
		},
		Instructions:   "Answer client questions.\nBe brief.",
		Worker:         json.RawMessage(`{"address":"ap.smith@fountbox.com","name":"ap.smith","schema":2}`),
		Reply:          SetupReply{Mode: modeFullOwner, Owner: "dana@example.com", Firm: "Smith CPA"},
		AutoRun:        true,
		Acknowledge:    false,
		RoutingVersion: 2,
	}
}

// sealWithNonce is seal with a fixed nonce, for the vectors.
func sealWithNonce(t *testing.T, key, nonce, plain, ad []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return gcm.Seal(append([]byte{}, nonce...), nonce, plain, ad)
}

func makeMailSetupVectors(t *testing.T) mailSetupVectors {
	t.Helper()
	worker := "w_0123456789abcdef01234567"
	dek, nonce := seq(0x41), seq(0x61)[:12]
	plain, err := json.Marshal(vectorSetup())
	if err != nil {
		t.Fatal(err)
	}
	sealed := sealWithNonce(t, dek, nonce, plain, mailSetupAAD(worker))
	body, _ := json.Marshal(mailSetupBody{V: mailSetupVersion, Sealed: base64.StdEncoding.EncodeToString(sealed)})
	return mailSetupVectors{
		Comment: "A Cloud worker's mail setup (internal/coordinator/mailsetup.go), sealed under its DEK. Hex but plaintext and body. Test keys only. Rewrite: MAIL_SETUP_WRITE=1 go test -run TestMailSetupVectors ./internal/coordinator",
		Worker:  worker, DEK: hex.EncodeToString(dek), Nonce: hex.EncodeToString(nonce), AAD: hex.EncodeToString(mailSetupAAD(worker)),
		Plaintext: string(plain), Sealed: hex.EncodeToString(sealed), Body: string(body),
	}
}

func TestMailSetupVectors(t *testing.T) {
	made := makeMailSetupVectors(t)
	if os.Getenv("MAIL_SETUP_WRITE") != "" {
		out, _ := json.MarshalIndent(made, "", "  ")
		if err := os.WriteFile(mailSetupVectorsPath, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(mailSetupVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var v mailSetupVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	made.Comment = v.Comment
	if made != v {
		t.Fatalf("the vectors changed:\n%+v\nwant\n%+v", made, v)
	}
	var dek DEK
	b, _ := hex.DecodeString(v.DEK)
	copy(dek[:], b)
	sealed, _ := hex.DecodeString(v.Sealed)
	s, err := OpenMailSetup(dek, v.Worker, sealed)
	if err != nil {
		t.Fatal(err)
	}
	want := vectorSetup()
	if s.Mailbox.Address != want.Mailbox.Address || len(s.Requesters) != 2 || s.Reply != want.Reply || s.RoutingVersion != 2 || !s.AutoRun || s.Instructions != want.Instructions {
		t.Fatalf("opened %+v", s)
	}
	if _, err := OpenMailSetup(dek, "w_ffffffffffffffffffffffff", sealed); !errors.Is(err, ErrInvalid) {
		t.Errorf("opened under another worker: %v", err)
	}
}

func TestASealedSetupRoundTripsAndIsChecked(t *testing.T) {
	dek := mustDEK(t)
	const w = "w_0123456789abcdef01234567"
	sealed, err := SealMailSetup(dek, w, vectorSetup())
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenMailSetup(dek, w, sealed)
	if err != nil || !s.Mailbox.same(vectorSetup().Mailbox) {
		t.Fatalf("%v %+v", err, s)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := OpenMailSetup(dek, w, sealed); !errors.Is(err, ErrInvalid) {
		t.Errorf("a changed setup opened: %v", err)
	}
	if _, err := OpenMailSetup(mustDEK(t), w, sealed); !errors.Is(err, ErrInvalid) {
		t.Errorf("another key opened it: %v", err)
	}
	for name, change := range map[string]func(*MailSetup){
		"no mode, as nothing is preselected": func(s *MailSetup) { s.Reply = SetupReply{} },
		"an unknown mode":                    func(s *MailSetup) { s.Reply.Mode = "off" },
		"full_owner without an owner":        func(s *MailSetup) { s.Reply.Owner = "" },
		"an owner who isn't a requester":     func(s *MailSetup) { s.Reply.Owner = "zoe@example.com" },
		"a worker's address as requester":    func(s *MailSetup) { s.Requesters[1].Address = "ar.smith@fountbox.com" },
		"a requester twice":                  func(s *MailSetup) { s.Requesters[1].Address = "Dana@Example.com" },
		"a short signing key":                func(s *MailSetup) { s.Mailbox.SigningKey = s.Mailbox.SigningKey[:16] },
		"another worker's worker.json":       func(s *MailSetup) { s.Worker = json.RawMessage(`{"address":"ar.smith@fountbox.com"}`) },
		"a worker.json that isn't an object": func(s *MailSetup) { s.Worker = json.RawMessage(`[1]`) },
		"long instructions":                  func(s *MailSetup) { s.Instructions = strings.Repeat("x", maxSetupInstruction+1) },
	} {
		s := vectorSetup()
		change(&s)
		sealed, err := SealMailSetup(dek, w, s)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OpenMailSetup(dek, w, sealed); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	plain, _ := json.Marshal(vectorSetup())
	extra := append(plain[:len(plain)-1:len(plain)-1], []byte(`,"keys":"more"}`)...)
	if _, err := OpenMailSetup(dek, w, sealWithNonce(t, dek[:], seq(1)[:12], extra, mailSetupAAD(w))); !errors.Is(err, ErrInvalid) {
		t.Errorf("an unknown field: %v", err)
	}
}

func setupBody(t *testing.T, dek DEK, worker string, s MailSetup) string {
	t.Helper()
	sealed, err := SealMailSetup(dek, worker, s)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(mailSetupBody{V: 1, Sealed: base64.StdEncoding.EncodeToString(sealed)})
	return string(body)
}

// Only an admin hands over the address keys, and no client reads them back.
func TestOnlyAnAdminSetsUpAWorkersMail(t *testing.T) {
	f := newTeamFixture(t)
	reviewer, admin := f.api(t, f.reviewer, "maria"), f.api(t, f.admin, "dev")
	path := "/v1/workers/" + f.w1.ID + "/mail"
	setup := vectorSetup()
	body := setupBody(t, f.dek1, f.w1.ID, setup)

	if code, out := do(t, reviewer, "PUT", path, body); code != 403 {
		t.Fatalf("a reviewer set up mail: %d %v", code, out)
	}
	if _, err := f.c.mailView(anyDevice, f.w1.ID); !errors.Is(err, ErrNoMailbox) {
		t.Fatalf("the reviewer's setup landed: %v", err)
	}
	if code, out := do(t, admin, "PUT", path, setupBody(t, f.dek2, f.w1.ID, setup)); code != 400 {
		t.Fatalf("a setup under another worker's key: %d %v", code, out)
	}
	code, out := do(t, admin, "PUT", path, body)
	if code != 200 || out["address"] != "ap.smith@fountbox.com" {
		t.Fatalf("the admin's setup: %d %v", code, out)
	}
	if _, has := out["signingKey"]; has {
		t.Fatal("the mail view shows the keys")
	}

	v, err := f.c.mailView(anyDevice, f.w1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Requesters) != 2 || !v.Requesters[0].AutoRun || v.Requesters[1].AutoRun || v.Requesters[0].PairedBy != "added" ||
		!v.AutoRun || v.Acknowledge || v.RoutingUnsent {
		t.Errorf("settings: %+v", v.MailSettings)
	}
	var rs replySettings
	var worker map[string]any
	var instructions []byte
	f.c.view(f.w1.ID, anyDevice, func(tr *Tree) error {
		readJSON(tr, replySettingsPath, &rs)
		readJSON(tr, workerFilePath, &worker)
		instructions, _ = tr.Read(instructionsPath)
		return nil
	})
	if rs.Mode != modeFullOwner || rs.Owner != "dana@example.com" || rs.Firm != "Smith CPA" || rs.Revision != 1 {
		t.Errorf("reply settings: %+v", rs)
	}
	if worker["name"] != "ap.smith" || string(instructions) != setup.Instructions {
		t.Errorf("worker.json %v, instructions %q", worker, instructions)
	}
	if w, _ := f.c.Worker(f.w1.ID); w.Mailbox != setup.Mailbox.MailboxID {
		t.Errorf("the volume's mailbox id: %q", w.Mailbox)
	}

	// The keys are the coordinator's alone: no client reads them as a file.
	for _, srv := range []*httptest.Server{reviewer, admin} {
		for _, p := range []string{"record/mail/mailbox.json", "record/mail/./mailbox.json"} {
			if code, _ := do(t, srv, "GET", "/v1/workers/"+f.w1.ID+"/files/"+p, ""); code != 404 {
				t.Errorf("GET %s: %d", p, code)
			}
		}
	}
	if code, _ := do(t, reviewer, "GET", "/v1/workers/"+f.w1.ID+"/files/record/worker.json", ""); code != 200 {
		t.Errorf("worker.json: %d", code)
	}

	// A retry changes nothing; another address is refused.
	before, _ := f.c.Worker(f.w1.ID)
	if code, out := do(t, admin, "PUT", path, body); code != 200 {
		t.Fatalf("a retry: %d %v", code, out)
	}
	if after, _ := f.c.Worker(f.w1.ID); after.Version != before.Version {
		t.Errorf("a retry moved the tree from %d to %d", before.Version, after.Version)
	}
	other := vectorSetup()
	other.Mailbox = newMailbox(t, "ap.smith@fountbox.com")
	if code, out := do(t, admin, "PUT", path, setupBody(t, f.dek1, f.w1.ID, other)); code != 409 {
		t.Errorf("another address: %d %v", code, out)
	}
}

// A setup on a coordinator with a generation enrolls the mailbox at the edge
// at once; one without a generation doesn't enroll.
func TestASetupEnrollsTheMailbox(t *testing.T) {
	r := genRig(t, MailConfig{})
	dek := mustDEK(t)
	w, err := r.c.CreateWorker("acct_1", &dek)
	if err != nil {
		t.Fatal(err)
	}
	s := vectorSetup()
	s.Mailbox = newMailbox(t, "ap.smith@fountbox.com")
	r.edge.register(s.Mailbox)
	sealed, _ := SealMailSetup(dek, w.ID, s)
	if err := r.c.SetUpMail(anyDevice, w.ID, sealed); err != nil {
		t.Fatal(err)
	}
	if !r.edge.coord.Mailbox(s.Mailbox.MailboxID).Enrolled {
		t.Fatal("the mailbox wasn't enrolled")
	}
	enrolls := 0
	for _, c := range r.edge.coord.Calls() {
		if strings.HasPrefix(c, "PUT /coordinator ") {
			enrolls++
		}
	}
	if enrolls != 1 {
		t.Fatalf("enrolled %d times", enrolls)
	}

	plain := newMailRig(t, MailConfig{})
	w2, _ := plain.c.CreateWorker("acct_1", &dek)
	s.Mailbox = newMailbox(t, "ar.smith@fountbox.com")
	s.Worker = json.RawMessage(`{}`)
	plain.edge.register(s.Mailbox)
	sealed, _ = SealMailSetup(dek, w2.ID, s)
	if err := plain.c.SetUpMail(anyDevice, w2.ID, sealed); err != nil {
		t.Fatal(err)
	}
	for _, c := range plain.edge.coord.Calls() {
		if strings.HasPrefix(c, "PUT /coordinator ") {
			t.Fatal("enrolled without a generation")
		}
	}
}
