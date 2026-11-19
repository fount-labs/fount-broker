package coordinator

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fount-labs/fount-broker/internal/jobwire"
	"github.com/fount-labs/fount-broker/internal/mail"
	"github.com/fount-labs/fount-broker/internal/mail/mailtest"
)

// fakeMailEdge serves the Device API reads the mail loop makes, for any
// number of mailboxes, from one attested boot.
type fakeMailEdge struct {
	t    *testing.T
	srv  *httptest.Server
	boot []byte // 16 bytes
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey

	mu      sync.Mutex
	paused  *bool
	mail    map[string][]string          // mailbox -> edge ids, in arrival order
	objects map[string]map[string][]byte // mailbox -> edge id -> object
	lists   map[string]int               // mailbox -> GET /mail calls
	seq     map[string]uint64
	renews  []string // the Fount-Entitlement of each POST /entitlement
	expiry  int64
}

func newFakeMailEdge(t *testing.T) *fakeMailEdge {
	pub, priv, _ := ed25519.GenerateKey(nil)
	running := false
	f := &fakeMailEdge{
		t: t, boot: make([]byte, 16), pub: pub, priv: priv, paused: &running,
		mail: map[string][]string{}, objects: map[string]map[string][]byte{}, lists: map[string]int{}, seq: map[string]uint64{},
		expiry: time.Now().Add(30 * 24 * time.Hour).Unix(),
	}
	rand.Read(f.boot)
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeMailEdge) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	return f.srv.Client().Do(req.WithContext(ctx))
}
func (f *fakeMailEdge) Base() string { return f.srv.URL + "/" }
func (f *fakeMailEdge) AttestedSigningKey(context.Context) (ed25519.PublicKey, error) {
	return f.pub, nil
}

func (f *fakeMailEdge) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id, ok := strings.CutPrefix(r.URL.Path, "/boots/"); ok {
		if id != hex.EncodeToString(f.boot) {
			http.Error(w, `{"error":"no such boot"}`, 404)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"boot_id": id, "signing_key": []byte(f.pub), "started_at": 1})
		return
	}
	mb := r.Header.Get("Fount-Key-Id")
	switch {
	case r.Method == "GET" && r.URL.Path == "/mail":
		f.lists[mb]++
		type listed struct {
			ID   string `json:"id"`
			Size int    `json:"size"`
		}
		out := []listed{}
		for _, id := range f.mail[mb] {
			out = append(out, listed{id, len(f.objects[mb][id])})
		}
		body := map[string]any{"messages": out}
		if f.paused != nil {
			body["paused"] = *f.paused
		}
		json.NewEncoder(w).Encode(body)
	case r.Method == "GET" && r.URL.Path == "/gaps":
		w.Write([]byte(`{"records":[]}`))
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/mail/"):
		obj, ok := f.objects[mb][strings.TrimPrefix(r.URL.Path, "/mail/")]
		if !ok {
			http.Error(w, `{"error":"no such message"}`, 404)
			return
		}
		w.Write(obj)
	case r.Method == "POST" && r.URL.Path == "/entitlement":
		f.renews = append(f.renews, r.Header.Get("Fount-Entitlement"))
		json.NewEncoder(w).Encode(map[string]int64{"entitlement_exp": f.expiry})
	default:
		http.Error(w, `{"error":"not found"}`, 404)
	}
}

// email is one message for the fake edge to hold.
type email struct {
	from, to   string
	recipient  string // the envelope recipient; to's address when empty
	subject    string
	inReplyTo  string
	sigHash    string // the aligned signature's hash; random when empty
	unsigned   bool
	receivedAt time.Time
}

// deliver seals e to mb's address and holds it, returning its edge id.
func (f *fakeMailEdge) deliver(mb Mailbox, e email) string {
	f.t.Helper()
	keys, err := mb.keys()
	if err != nil {
		f.t.Fatal(err)
	}
	raw := []byte("From: " + e.from + "\r\nTo: " + e.to + "\r\nSubject: " + e.subject + "\r\n\r\nPlease file Q3.\r\n")
	sum := sha256.Sum256(raw)
	domain := domainOf(e.from)
	hash := e.sigHash
	if hash == "" {
		hash = rand.Text()
	}
	dkim := []any{map[string]any{"domain": domain, "selector": "s", "algorithm": "ed25519-sha256", "result": "pass",
		"key_bits": 256, "headers": []string{"from", "to", "date", "subject", "in-reply-to", "references"}, "body_length": false,
		"testing": false, "covers": true, "hash": hash, "aligned": true}}
	if e.unsigned {
		dkim = []any{}
	}
	check, _ := json.Marshal(map[string]any{
		"v": 1, "checked_by": "edge",
		"from":    map[string]any{"address": e.from, "domain": domain, "name": "Dana"},
		"dkim":    dkim,
		"aligned": !e.unsigned, "recipient_signed": true, "date_skew_seconds": -30,
		"headers":    map[string]any{"to": []string{e.to}, "subject": e.subject, "in_reply_to": e.inReplyTo},
		"raw_sha256": hex.EncodeToString(sum[:]),
	})
	at := e.receivedAt
	if at.IsZero() {
		at = time.Now()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq[mb.MailboxID]++
	edgeID := make([]byte, 16)
	rand.Read(edgeID)
	obj, err := mailtest.SealV3(mailtest.Object{
		EdgeID: edgeID, MailboxID: keys.MailboxID, ReceivedAt: at, Sequence: f.seq[mb.MailboxID], BootID: f.boot,
		Sender: e.from, Recipient: cmpOrStr(e.recipient, e.to), Check: check, Raw: raw,
	}, keys.Decryption.PublicKey(), f.priv)
	if err != nil {
		f.t.Fatal(err)
	}
	id := hex.EncodeToString(edgeID)
	if f.objects[mb.MailboxID] == nil {
		f.objects[mb.MailboxID] = map[string][]byte{}
	}
	f.objects[mb.MailboxID][id] = obj
	f.mail[mb.MailboxID] = append(f.mail[mb.MailboxID], id)
	return id
}

func cmpOrStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (f *fakeMailEdge) listCalls(mailbox string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lists[mailbox]
}

func newMailbox(t *testing.T, address string) Mailbox {
	t.Helper()
	dec, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, 32)
	id := make([]byte, 32)
	rand.Read(seed)
	rand.Read(id)
	return Mailbox{Address: address, MailboxID: hex.EncodeToString(id), SigningKey: seed, DecryptionKey: dec.Bytes()}
}

// mailRunner finishes each agent job at once, keeping its prompt.
type mailRunner struct {
	mu      sync.Mutex
	prompts []string
}

func (r *mailRunner) Run(_ context.Context, _, _ string, job JobDirs) (RunResult, error) {
	if job.Mode == jobwire.ModeIndex {
		return RunResult{}, os.MkdirAll(job.Index, dirMode)
	}
	data, err := os.ReadFile(job.JobFile)
	if err != nil {
		return RunResult{}, err
	}
	var rj runnerJob
	json.Unmarshal(data, &rj)
	r.mu.Lock()
	r.prompts = append(r.prompts, rj.Prompt)
	r.mu.Unlock()
	return RunResult{}, nil
}

// crashStore fails the next manifest write once armed: the tree change it
// belonged to never commits, as if the coordinator stopped before it.
type crashStore struct {
	Store
	mu    sync.Mutex
	armed bool
}

var errCrash = errors.New("the coordinator stopped")

func (s *crashStore) Put(workerID, objectID string, data []byte) error {
	s.mu.Lock()
	crash := s.armed && objectID == manifestObject
	if crash {
		s.armed = false
	}
	s.mu.Unlock()
	if crash {
		return errCrash
	}
	return s.Store.Put(workerID, objectID, data)
}

func (s *crashStore) arm() {
	s.mu.Lock()
	s.armed = true
	s.mu.Unlock()
}

// mailRig is a coordinator with a mail loop over a fake edge, and what it
// takes to start another on the same volume and store, as after a restart.
type mailRig struct {
	t      *testing.T
	edge   *fakeMailEdge
	dir    string
	key    WrappingKey
	store  *crashStore
	runner *mailRunner
	cfg    MailConfig
	c      *Coordinator
	cancel context.CancelFunc
}

func newMailRig(t *testing.T, cfg MailConfig) *mailRig {
	t.Helper()
	key, _ := NewWrappingKey()
	dir := t.TempDir()
	r := &mailRig{t: t, edge: newFakeMailEdge(t), dir: dir, key: key, store: &crashStore{Store: DirStore{Root: filepath.Join(dir, "objects")}}, runner: &mailRunner{}, cfg: cfg}
	r.start()
	return r
}

// start starts a coordinator on the rig's volume, with a fresh Service as a
// new process has.
func (r *mailRig) start() {
	r.t.Helper()
	if r.cancel != nil {
		r.cancel()
		r.c.running.Wait()
	}
	cfg := r.cfg
	cfg.Service = mail.New(r.edge, NoLocalCheck{})
	c, err := New(Config{
		StateDir: filepath.Join(r.dir, "state"), WorkDir: filepath.Join(r.dir, "work"),
		Store: r.store, Key: r.key, Pool: NewPool(1, 2, nil), Runner: r.runner, Audience: testAudience,
		JobConfig: json.RawMessage(`{"model":"m"}`), Mail: cfg,
	})
	if err != nil {
		r.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go c.Run(ctx)
	r.t.Cleanup(func() {
		// Jobs a test didn't wait for end before the volume goes.
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if l := c.Load(); l.Running+l.Queued == 0 {
				break
			}
		}
		cancel()
		c.running.Wait()
	})
	r.c, r.cancel = c, cancel
}

const testWorkerAddr = "ap@fountbox.com"

// worker makes a worker with a mailbox and dana@example.com as a requester
// whose jobs run by themselves, and turns automatic runs on.
func (r *mailRig) worker() (Worker, Mailbox) {
	r.t.Helper()
	w, err := r.c.CreateWorker("acct_1", nil)
	if err != nil {
		r.t.Fatal(err)
	}
	mb := newMailbox(r.t, testWorkerAddr)
	if err := r.c.SetMailbox(w.ID, mb, []Requester{{Address: "Dana@Example.com", DKIMDomain: "example.com", AutoRun: true, PairedBy: "reply"}}); err != nil {
		r.t.Fatal(err)
	}
	if res := r.workerOp(w.ID, "op_auto", "setAutoRun", switchArgs{On: true}); !res.OK {
		r.t.Fatalf("setAutoRun: %+v", res)
	}
	w, _ = r.c.Worker(w.ID)
	return w, mb
}

func (r *mailRig) workerOp(workerID, opID, kind string, args any) OpResult {
	r.t.Helper()
	raw, _ := json.Marshal(args)
	res, err := r.c.applyWorkerOp(anyDevice, workerID, workerOpEnvelope{OpID: opID, Kind: kind, Args: raw})
	if err != nil {
		r.t.Fatalf("%s: %v", kind, err)
	}
	return res
}

func (r *mailRig) threadOp(workerID, threadID, opID, kind string, args any) OpResult {
	r.t.Helper()
	raw, _ := json.Marshal(args)
	res, err := r.c.applyThreadOp(anyDevice, workerID, threadID, opEnvelope{OpID: opID, ThreadID: threadID, Kind: kind, Args: raw})
	if err != nil {
		r.t.Fatalf("%s: %v", kind, err)
	}
	return res
}

// pass runs one mail pass as a sweep.
func (r *mailRig) pass() {
	r.t.Helper()
	r.c.mail.mu.Lock()
	r.c.mail.lastSweep = time.Time{}
	r.c.mail.mu.Unlock()
	r.c.mailPass(context.Background(), time.Now())
}

func (r *mailRig) threads(workerID string) []*threadRecord {
	r.t.Helper()
	var out []*threadRecord
	if err := r.c.view(workerID, anyDevice, func(t *Tree) error {
		for _, id := range threadIDs(t) {
			th, err := loadThread(t, id)
			if err != nil {
				return err
			}
			out = append(out, th)
		}
		return nil
	}); err != nil {
		r.t.Fatal(err)
	}
	return out
}

func (r *mailRig) ledger(workerID string) *mailLedger {
	r.t.Helper()
	var l *mailLedger
	if err := r.c.view(workerID, anyDevice, func(t *Tree) (err error) {
		l, err = loadMailLedger(t)
		return err
	}); err != nil {
		r.t.Fatal(err)
	}
	return l
}

func (r *mailRig) settings(workerID string) *MailSettings {
	r.t.Helper()
	v, err := r.c.mailView(anyDevice, workerID)
	if err != nil {
		r.t.Fatal(err)
	}
	return &v.MailSettings
}

func (r *mailRig) waitStatus(workerID, threadID string, want ThreadStatus) *threadRecord {
	r.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		th, err := r.c.thread(anyDevice, workerID, threadID)
		if err != nil {
			r.t.Fatal(err)
		}
		if th.Status == want {
			return th
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("thread %s is %s, want %s: %+v", threadID, th.Status, want, th)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func onlyThread(t *testing.T, ths []*threadRecord) *threadRecord {
	t.Helper()
	if len(ths) != 1 {
		t.Fatalf("%d threads, want 1", len(ths))
	}
	return ths[0]
}

func mailEntries(th *threadRecord) []*mailEntry {
	var out []*mailEntry
	for _, e := range th.Entries {
		if e.Kind == entryMail {
			out = append(out, e.Mail)
		}
	}
	return out
}

func TestARequestersEmailBecomesATurn(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	w, mb := r.worker()
	id := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Q3 filing"})
	r.pass()

	th := onlyThread(t, r.threads(w.ID))
	if th.Origin != "mail" || th.Subject != "Q3 filing" || th.Handle == "" || !th.hasParticipant("dana@example.com") {
		t.Fatalf("thread: %+v", th)
	}
	m := mailEntries(th)
	if len(m) != 1 || m[0].EdgeID != id || m[0].Verdict != "request" || m[0].Held != "" || m[0].Intake != intakeQueued || m[0].JobID != mailJobID(id) {
		t.Fatalf("mail entry: %+v", m)
	}
	if a := r.ledger(w.ID).Acted[id]; a.Outcome != outcomeJob || a.Thread != th.ID {
		t.Fatalf("ledger: %+v", a)
	}
	j := waitJob(t, r.c, mailJobID(id))
	if j.State != JobFinished {
		t.Fatalf("job: %+v", j)
	}
	th = r.waitStatus(w.ID, th.ID, StatusIdle)
	if !strings.Contains(r.runner.prompts[0], "threads/"+th.ID+"/mail/"+id+"/message.eml") || strings.Contains(r.runner.prompts[0], "Please file") {
		t.Fatalf("the job's instruction points at the email and doesn't quote it: %q", r.runner.prompts[0])
	}
	raw, err := r.c.ReadFile(w.ID, prefixRoot+"threads/"+th.ID+"/mail/"+id+"/message.eml")
	if err != nil || !strings.Contains(string(raw), "Please file Q3.") {
		t.Fatalf("the email in the thread's folder: %q %v", raw, err)
	}
	if s := r.c.MailStats(); s.Pickups != 1 || s.Max > time.Minute {
		t.Fatalf("pickup: %+v", s)
	}

	// Another pass acts on nothing again.
	r.pass()
	if th := onlyThread(t, r.threads(w.ID)); len(th.Jobs) != 1 || len(mailEntries(th)) != 1 {
		t.Fatalf("a second pass changed the thread: %+v", th)
	}
	v := th.view()
	if mi, ok := v.Entries[0].(mailInView); !ok || mi.Kind != "mail-in" || mi.From.Address != "dana@example.com" || mi.Check.Kind != "signed" || mi.Verdict.Kind != "request" {
		t.Fatalf("display: %#v", v.Entries[0])
	}
}

func TestAStrangersEmailIsHeldUntilRunOnce(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	w, mb := r.worker()
	id := r.edge.deliver(mb, email{from: "eve@else.example", to: testWorkerAddr, subject: "Invoice"})
	r.pass()

	th := onlyThread(t, r.threads(w.ID))
	m := mailEntries(th)
	if th.Status != StatusHeld || len(m) != 1 || m[0].Held != heldWaiting || m[0].Reason != "not from an owner" || th.hasParticipant("eve@else.example") {
		t.Fatalf("held: %s %+v %+v", th.Status, th, m)
	}
	if len(th.Jobs) != 0 {
		t.Fatalf("a held email started a job: %+v", th.Jobs)
	}
	if mi := th.view().Entries[0].(mailInView); !mi.Held || mi.Verdict.Kind != "held" {
		t.Fatalf("display: %+v", mi)
	}
	mailID := th.Entries[0].ID

	text := "Summarise it for me."
	res := r.threadOp(w.ID, th.ID, "op_run", "runHeldMail", heldMailArgs{MailID: mailID, Text: &text})
	if !res.OK {
		t.Fatalf("runHeldMail: %+v", res)
	}
	if again := r.threadOp(w.ID, th.ID, "op_run", "runHeldMail", heldMailArgs{MailID: mailID, Text: &text}); !reflect.DeepEqual(again, res) {
		t.Fatalf("a retry: %+v, want %+v", again, res)
	}
	if twice := r.threadOp(w.ID, th.ID, "op_run2", "runHeldMail", heldMailArgs{MailID: mailID}); twice.OK || twice.Code != CodeAlreadyRun {
		t.Fatalf("run twice: %+v", twice)
	}
	// The operation left the intake owed; the mail loop, kicked, queues it.
	r.pass()
	waitJob(t, r.c, mailJobID(id))
	th = r.waitStatus(w.ID, th.ID, StatusIdle)
	if m := mailEntries(th)[0]; m.Held != heldRun || m.Intake != intakeQueued {
		t.Fatalf("after running: %+v", m)
	}
	if p := r.runner.prompts[0]; !strings.HasPrefix(p, text) {
		t.Fatalf("the instruction is what was typed: %q", p)
	}
	if th.hasParticipant("eve@else.example") {
		t.Fatal("running a stranger's email once made them a participant")
	}

	// addRequester from the held email: only its sender, and only once.
	if res := r.threadOp(w.ID, th.ID, "op_add0", "addRequester", mailRequesterArgs{MailID: mailID, Address: "mallory@else.example"}); res.Code != CodeRecipientNotAllowed {
		t.Fatalf("someone else: %+v", res)
	}
	if res := r.threadOp(w.ID, th.ID, "op_add1", "addRequester", mailRequesterArgs{MailID: mailID, Address: "Eve@else.example"}); !res.OK {
		t.Fatalf("addRequester: %+v", res)
	}
	if res := r.threadOp(w.ID, th.ID, "op_add2", "addRequester", mailRequesterArgs{MailID: mailID, Address: "eve@else.example"}); res.Code != CodeAlreadyRequester {
		t.Fatalf("twice: %+v", res)
	}
	s := r.settings(w.ID)
	q := s.requester("eve@else.example")
	if q == nil || q.AutoRun || q.DKIMDomain != "else.example" || q.PairedBy != "added" || !s.RoutingUnsent || s.RequestersRev != 2 {
		t.Fatalf("requesters: %+v", s)
	}
	th, _ = r.c.thread(anyDevice, w.ID, th.ID)
	if !th.hasParticipant("eve@else.example") || mailEntries(th)[0].Held != heldAdded {
		t.Fatalf("thread after addRequester: %+v", th)
	}
}

func TestAReplyTokenPicksTheThread(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	w, mb := r.worker()
	first := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Q3"})
	r.pass()
	th := onlyThread(t, r.threads(w.ID))
	waitJob(t, r.c, mailJobID(first))
	keys, _ := mb.keys()
	token, err := mail.MintReplyToken(keys, th.Handle)
	if err != nil {
		t.Fatal(err)
	}
	reply := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr, recipient: "ap+" + token + "@fountbox.com", subject: "Re: Q3"})
	stranger := r.edge.deliver(mb, email{from: "eve@else.example", to: testWorkerAddr, recipient: "ap+" + token + "@fountbox.com", subject: "Re: Q3"})
	forged := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr, recipient: "ap+aaaaaaaaaaaaaaaa@fountbox.com", subject: "Re: Q3"})
	r.pass()

	ths := r.threads(w.ID)
	if len(ths) != 2 {
		t.Fatalf("%d threads, want the first and one for the forged token", len(ths))
	}
	th, _ = r.c.thread(anyDevice, w.ID, th.ID)
	m := mailEntries(th)
	if len(m) != 3 || m[1].EdgeID != reply || m[1].Verdict != verdictThreadReply || m[1].Intake != intakeQueued {
		t.Fatalf("the reply: %+v", m)
	}
	if m[2].EdgeID != stranger || m[2].Held != heldWaiting {
		t.Fatalf("a stranger with the token: %+v", m[2])
	}
	if a := r.ledger(w.ID).Acted[forged]; a.Thread == th.ID || a.Outcome != outcomeJob {
		t.Fatalf("a forged token starts its own thread: %+v", a)
	}
}

func TestAPausedWorkerHoldsRequests(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	w, mb := r.worker()
	paused := true
	for _, tc := range []struct {
		paused *bool
		reason string
	}{
		{&paused, "the worker is paused"},
		{nil, "Fount couldn't tell whether the worker is paused"},
	} {
		r.edge.mu.Lock()
		r.edge.paused = tc.paused
		r.edge.mu.Unlock()
		id := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr})
		r.pass()
		if a := r.ledger(w.ID).Acted[id]; a.Outcome != outcomeHeld || a.Reason != tc.reason {
			t.Fatalf("%+v, want held because %s", a, tc.reason)
		}
	}
}

func TestMailBeforeAutoRunIsHeld(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	w, mb := r.worker()
	r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr, receivedAt: time.Now().Add(-time.Hour)})
	r.pass()
	if m := mailEntries(onlyThread(t, r.threads(w.ID)))[0]; m.Held != heldWaiting || m.Reason != "it arrived before automatic runs were turned on" {
		t.Fatalf("%+v", m)
	}
}

func TestAReplayIsIgnored(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	w, mb := r.worker()
	a := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr, sigHash: "same"})
	b := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr, sigHash: "same"})
	r.pass()
	l := r.ledger(w.ID)
	if l.Acted[a].Outcome != outcomeJob || l.Acted[b].Outcome != outcomeIgnored {
		t.Fatalf("%+v", l.Acted)
	}
	onlyThread(t, r.threads(w.ID))
}

// A crash between fetching a message and committing its thread operation
// leaves it unacted on, and the next pass, after a restart, acts on it once.
func TestACrashBeforeTheCommitActsOnTheMessageOnce(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	w, mb := r.worker()
	id := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr})
	r.store.arm()
	r.pass()
	if ths := r.threads(w.ID); len(ths) != 0 {
		t.Fatalf("a crashed change left %d threads", len(ths))
	}
	if _, acted := r.ledger(w.ID).Acted[id]; acted {
		t.Fatal("the ledger names a message whose thread operation never committed")
	}

	r.start()
	r.pass()
	r.pass()
	th := onlyThread(t, r.threads(w.ID))
	if m := mailEntries(th); len(m) != 1 || m[0].EdgeID != id {
		t.Fatalf("%+v", m)
	}
	waitJob(t, r.c, mailJobID(id))
	if l := r.ledger(w.ID); l.Acted[id].Outcome != outcomeJob || l.Sequences.Delivered[1] != id {
		t.Fatalf("ledger: %+v", l)
	}
}

// failingIntake fails until it's told not to.
type failingIntake struct {
	mu    sync.Mutex
	fail  bool
	calls map[string]int
	next  Intake
}

func (f *failingIntake) Queue(ctx context.Context, req IntakeRequest) error {
	f.mu.Lock()
	f.calls[req.EdgeID]++
	fail := f.fail
	f.mu.Unlock()
	if fail {
		return errors.New("the intake runner is down")
	}
	return f.next.Queue(ctx, req)
}

// A crash after the commit and before the turn is queued leaves the intake
// owed, and a restart queues it once.
func TestACrashAfterTheCommitQueuesTheTurnOnce(t *testing.T) {
	in := &failingIntake{fail: true, calls: map[string]int{}}
	r := newMailRig(t, MailConfig{Intake: in})
	in.next = directIntake{r.c}
	w, mb := r.worker()
	id := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr})
	r.pass()
	th := onlyThread(t, r.threads(w.ID))
	if m := mailEntries(th)[0]; m.Intake != intakePending || th.Status != StatusWorking {
		t.Fatalf("an owed intake: %s %+v", th.Status, m)
	}
	if _, err := r.c.Job(mailJobID(id)); !errors.Is(err, ErrNoJob) {
		t.Fatalf("a job before intake: %v", err)
	}

	in.mu.Lock()
	in.fail = false
	in.mu.Unlock()
	r.start()
	in.next = directIntake{r.c}
	r.pass()
	r.pass()
	waitJob(t, r.c, mailJobID(id))
	th = r.waitStatus(w.ID, th.ID, StatusIdle)
	if m := mailEntries(th)[0]; m.Intake != intakeQueued || len(th.Jobs) != 1 {
		t.Fatalf("%+v %+v", m, th.Jobs)
	}
	if in.calls[id] != 2 {
		t.Fatalf("intake asked %d times, want the failed try and one more", in.calls[id])
	}
	var pending []pendingMail
	r.c.view(w.ID, anyDevice, func(t *Tree) (err error) { pending, err = loadPending(t); return err })
	if len(pending) != 0 {
		t.Fatalf("still owed: %+v", pending)
	}

	// Queueing twice, as after a crash between queueing and settling, is
	// one job.
	if err := (directIntake{r.c}).Queue(context.Background(), IntakeRequest{WorkerID: w.ID, ThreadID: th.ID, EdgeID: id, Stored: storedMailPath(id), JobID: mailJobID(id)}); err != nil {
		t.Fatal(err)
	}
	if len(r.runner.prompts) != 1 {
		t.Fatalf("%d jobs ran", len(r.runner.prompts))
	}
}

// A restart, with a Service that has never seen the mailbox, acts on nothing
// twice and restores the sequence ledger.
func TestARestartDoesntActTwice(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	w, mb := r.worker()
	ids := []string{
		r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr}),
		r.edge.deliver(mb, email{from: "eve@else.example", to: testWorkerAddr}),
	}
	r.pass()
	waitJob(t, r.c, mailJobID(ids[0]))
	r.start()
	r.pass()
	if ths := r.threads(w.ID); len(ths) != 2 {
		t.Fatalf("%d threads after a restart", len(ths))
	}
	if l := r.c.mail.service.Ledger(mb.MailboxID); l.Delivered[1] != ids[0] || l.Delivered[2] != ids[1] {
		t.Fatalf("the Service's ledger wasn't restored: %+v", l)
	}
	if len(r.runner.prompts) != 1 {
		t.Fatalf("%d jobs", len(r.runner.prompts))
	}
}

type countingAck struct {
	mu   sync.Mutex
	sent []AckRequest
}

func (a *countingAck) Acknowledge(_ context.Context, req AckRequest) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sent = append(a.sent, req)
	return nil
}

func TestTheAcknowledgementIsOffByDefault(t *testing.T) {
	ack := &countingAck{}
	r := newMailRig(t, MailConfig{Ack: ack})
	w, mb := r.worker()
	r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr})
	r.pass()
	if len(ack.sent) != 0 {
		t.Fatalf("acknowledged while off: %+v", ack.sent)
	}
	if res := r.workerOp(w.ID, "op_ack", "setAcknowledge", switchArgs{On: true}); !res.OK || res.Revision != 1 {
		t.Fatalf("setAcknowledge: %+v", res)
	}
	r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr})
	r.edge.deliver(mb, email{from: "eve@else.example", to: testWorkerAddr})
	r.pass()
	r.pass()
	if len(ack.sent) != 1 || ack.sent[0].To != "dana@example.com" {
		t.Fatalf("acknowledgements: %+v", ack.sent)
	}
}

type fakeChanges struct {
	mu      sync.Mutex
	changed []string
	asked   []string
}

func (f *fakeChanges) Since(_ context.Context, cursor string, _ []string) (MailboxChanges, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, cursor)
	out := MailboxChanges{Cursor: "c" + string(rune('0'+len(f.asked))), Changed: f.changed}
	f.changed = nil
	return out, nil
}

func TestTheChangesListingPicksTheMailboxes(t *testing.T) {
	ch := &fakeChanges{}
	r := newMailRig(t, MailConfig{Changes: ch, SweepInterval: time.Hour})
	w1, mb1 := r.worker()
	_, mb2 := r.worker()
	now := time.Now()
	r.c.mailPass(context.Background(), now) // the first pass sweeps
	l1, l2 := r.edge.listCalls(mb1.MailboxID), r.edge.listCalls(mb2.MailboxID)
	if l1 != 1 || l2 != 1 {
		t.Fatalf("the sweep listed %d and %d", l1, l2)
	}
	r.c.mailPass(context.Background(), now.Add(time.Second))
	if r.edge.listCalls(mb1.MailboxID) != 1 || r.edge.listCalls(mb2.MailboxID) != 1 {
		t.Fatal("a pass with no changes listed a mailbox")
	}
	id := r.edge.deliver(mb1, email{from: "dana@example.com", to: testWorkerAddr})
	ch.mu.Lock()
	ch.changed = []string{mb1.MailboxID}
	ch.mu.Unlock()
	r.c.mailPass(context.Background(), now.Add(2*time.Second))
	if r.edge.listCalls(mb1.MailboxID) != 2 || r.edge.listCalls(mb2.MailboxID) != 1 {
		t.Fatal("the changed mailbox alone is listed")
	}
	if r.ledger(w1.ID).Acted[id].Outcome != outcomeJob {
		t.Fatal("the changed mailbox's mail wasn't acted on")
	}
	waitJob(t, r.c, mailJobID(id))
	if ch.asked[0] != "" || ch.asked[1] != "c1" {
		t.Fatalf("cursors: %q", ch.asked)
	}
}

func TestRunMailPicksUpWithinTheInterval(t *testing.T) {
	r := newMailRig(t, MailConfig{PollInterval: 20 * time.Millisecond, SweepInterval: 20 * time.Millisecond})
	w, mb := r.worker()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.c.RunMail(ctx)
	id := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr})
	deadline := time.Now().Add(10 * time.Second)
	for _, err := r.c.Job(mailJobID(id)); err != nil; _, err = r.c.Job(mailJobID(id)) {
		if time.Now().After(deadline) {
			t.Fatal("the loop didn't pick the email up")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if j := waitJob(t, r.c, mailJobID(id)); j.State != JobFinished || j.WorkerID != w.ID {
		t.Fatalf("%+v", j)
	}
}
