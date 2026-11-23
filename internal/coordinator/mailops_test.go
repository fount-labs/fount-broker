package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Each part of the mail settings has its own revision (decision 5): a stale
// base is refused, and changes to different parts don't refuse each other.
func TestMailSettingsOpsNameTheirRevision(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	w, _ := r.worker()
	s := r.settings(w.ID)
	if s.AutoRunRev != 1 || s.RequestersRev != 1 || s.AcknowledgeRev != 0 || s.AutoRunSince.IsZero() {
		t.Fatalf("%+v", s)
	}
	// Two reviewers, both having seen the same settings.
	if res := r.workerOp(w.ID, "op_a", "addRequester", requesterArgs{Address: "lee@client.example", BaseRevision: 1}); !res.OK || res.Revision != 2 {
		t.Fatalf("addRequester: %+v", res)
	}
	if res := r.workerOp(w.ID, "op_b", "setAutoRun", switchArgs{On: false, BaseRevision: 1}); !res.OK || res.Revision != 2 {
		t.Fatalf("setAutoRun on another part: %+v", res)
	}
	if res := r.workerOp(w.ID, "op_c", "addRequester", requesterArgs{Address: "kim@client.example", BaseRevision: 1}); res.OK || res.Code != CodeWorkerChanged || res.Revision != 2 {
		t.Fatalf("a stale base: %+v", res)
	}
	if res := r.workerOp(w.ID, "op_a", "addRequester", requesterArgs{Address: "lee@client.example", BaseRevision: 1}); !res.OK || res.Revision != 2 {
		t.Fatalf("a retry answers as the first time: %+v", res)
	}
	if res := r.workerOp(w.ID, "op_a", "addRequester", requesterArgs{Address: "kim@client.example", BaseRevision: 2}); res.Code != CodeOpIDReused {
		t.Fatalf("an opId reused: %+v", res)
	}
	for _, tc := range []struct {
		address string
		code    OpCode
	}{
		{"lee@client.example", CodeAlreadyRequester},
		{"other@fountbox.com", CodeFountboxAddress},
	} {
		if res := r.workerOp(w.ID, "op_"+strings.Split(tc.address, "@")[0], "addRequester", requesterArgs{Address: tc.address, BaseRevision: 2}); res.Code != tc.code {
			t.Errorf("%s: %+v, want %s", tc.address, res, tc.code)
		}
	}
	raw, _ := json.Marshal(requesterArgs{Address: "not an address", BaseRevision: 2})
	if _, err := r.c.applyWorkerOp(anyDevice, w.ID, workerOpEnvelope{OpID: "op_x", Kind: "addRequester", Args: raw}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a bad address: %v", err)
	}
	if res := r.workerOp(w.ID, "op_saved", "routingSaved", routingSavedArgs{RequestersRevision: 2}); !res.OK {
		t.Fatalf("routingSaved: %+v", res)
	}
	if s := r.settings(w.ID); s.RoutingUnsent || s.AutoRun || s.requester("lee@client.example") == nil {
		t.Fatalf("%+v", s)
	}

	bare, _ := r.c.CreateWorker("acct_1", nil)
	if res := r.workerOp(bare.ID, "op_1", "setAutoRun", switchArgs{On: true}); res.Code != CodeNoMailbox {
		t.Fatalf("no mailbox: %+v", res)
	}
}

// Every mail operation is role-checked against the worker's team log: the
// requester list, automatic runs, the acknowledgement and pairing are an
// admin's; running held mail is any reviewer's who reaches the worker.
func TestMailOpsCheckTheRole(t *testing.T) {
	f := newTeamFixture(t)
	if err := f.c.SetMailbox(f.w1.ID, newMailbox(t, testWorkerAddr), nil); err != nil {
		t.Fatal(err)
	}
	reviewer, admin := f.api(t, f.reviewer, "maria"), f.api(t, f.admin, "dev")
	base := "/v1/workers/" + f.w1.ID
	op := func(id, kind string, args any) string {
		raw, _ := json.Marshal(args)
		return `{"opId":"` + id + `","kind":"` + kind + `","args":` + string(raw) + `}`
	}
	for _, tc := range []struct {
		kind string
		args any
	}{
		{"setAutoRun", switchArgs{On: true}},
		{"setAcknowledge", switchArgs{On: true}},
		{"addRequester", requesterArgs{Address: "lee@client.example"}},
		{"pairingStart", pairingStartArgs{Requester: "lee@client.example", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}},
		{"pairingConfirm", pairingConfirmArgs{MailID: "e_1"}},
		{"routingSaved", routingSavedArgs{}},
	} {
		if code, out := do(t, reviewer, "POST", base+"/ops", op("op_r_"+tc.kind, tc.kind, tc.args)); code != 403 {
			t.Errorf("reviewer %s: %d %v", tc.kind, code, out)
		}
		if code, out := do(t, admin, "POST", base+"/ops", op("op_a_"+tc.kind, tc.kind, tc.args)); code != 200 {
			t.Errorf("admin %s: %d %v", tc.kind, code, out)
		}
	}
	v, err := f.c.mailView(anyDevice, f.w1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if s := v.MailSettings; !s.AutoRun || !s.Acknowledge || s.requester("lee@client.example") == nil {
		t.Fatalf("the admin's operations didn't apply: %+v", v.MailSettings)
	}
	if code, out := do(t, reviewer, "GET", base+"/mail", ""); code != 200 || out["address"] != testWorkerAddr {
		t.Errorf("the reviewer reads the mail settings: %d %v", code, out)
	}

	// Held mail: the reviewer may run it, not add its sender.
	f.c.cfg.JobConfig = json.RawMessage(`{"model":"m"}`)
	var th *threadRecord
	entry := &mailEntry{EdgeID: "e_9", Sender: "eve@else.example", Verdict: "unknown", Held: heldWaiting, Folder: "01 2026-11-19 eve@else.example"}
	if err := f.c.change(f.w1.ID, anyDevice, func(tr *Tree) (err error) {
		if th, err = newMailThread(tr, f.w1.ID, "hello", time.Now()); err != nil {
			return err
		}
		if _, err := threadHandle(tr, th); err != nil {
			return err
		}
		if _, err := th.push(1, time.Now(), threadEntry{Kind: entryMail, Mail: entry}); err != nil {
			return err
		}
		th.finish(1, time.Now())
		return saveThread(tr, th)
	}); err != nil {
		t.Fatal(err)
	}
	tops := base + "/threads/" + th.ID + "/ops"
	threadOp := func(id, kind string, args any) string {
		raw, _ := json.Marshal(args)
		return `{"opId":"` + id + `","threadId":"` + th.ID + `","baseRevision":1,"kind":"` + kind + `","args":` + string(raw) + `}`
	}
	mailID := th.Entries[0].ID
	if code, out := do(t, reviewer, "POST", tops, threadOp("op_add", "addRequester", mailRequesterArgs{MailID: mailID, Address: "eve@else.example"})); code != 403 {
		t.Errorf("reviewer addRequester from held mail: %d %v", code, out)
	}
	if code, out := do(t, reviewer, "POST", tops, threadOp("op_run", "runHeldMail", heldMailArgs{MailID: mailID})); code != 200 || out["ok"] != true {
		t.Errorf("reviewer runHeldMail: %d %v", code, out)
	}
}

func TestPairingByReply(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	w, mb := r.worker()
	if res := r.workerOp(w.ID, "op_p", "pairingStart", pairingStartArgs{Requester: "Lee@Client.example", ExpiresAt: time.Now().Add(48 * time.Hour).UnixMilli()}); !res.OK || res.Revision != 1 {
		t.Fatalf("pairingStart: %+v", res)
	}
	s := r.settings(w.ID)
	if p := s.Pairing; p == nil || p.Requester != "lee@client.example" || p.ExpiresAt.After(time.Now().Add(connectLifetime+time.Minute)) {
		t.Fatalf("the pairing, its expiry capped at a day: %+v", s.Pairing)
	}
	other := r.edge.deliver(mb, email{from: "kim@client.example", to: testWorkerAddr, inReplyTo: "<c.1700000000.abc123@fountbox.com>"})
	reply := r.edge.deliver(mb, email{from: "lee@client.example", to: testWorkerAddr, inReplyTo: "<c.1700000000.abc123@fountbox.com>"})
	r.pass()

	s = r.settings(w.ID)
	q := s.requester("lee@client.example")
	if q == nil || !q.AutoRun || q.DKIMDomain != "client.example" || q.PairedBy != "reply" {
		t.Fatalf("the requester the reply paired: %+v", s.Requesters)
	}
	if !s.RoutingUnsent || len(s.Proofs) != 1 || s.Proofs[0] != (ConnectProof{Owner: "lee@client.example", MessageID: "<c.1700000000.abc123@fountbox.com>"}) {
		t.Fatalf("the proof for the device's PUT /routing: %+v", s)
	}
	if p := s.Pairing; p.Paired == nil || len(p.Untokened) != 1 || p.Untokened[0].Message != other {
		t.Fatalf("pairing: %+v", p)
	}
	l := r.ledger(w.ID)
	if l.Acted[reply].Outcome != outcomePaired || l.Acted[other].Outcome != outcomeHeld {
		t.Fatalf("ledger: %+v", l.Acted)
	}
	// The pairing's reply makes no thread and isn't read by intake; kim's
	// email waits on one.
	onlyThread(t, r.threads(w.ID))
	if r.intake.ran(reply) || !r.intake.ran(other) {
		t.Fatalf("intake read %v", r.intake.read)
	}
	if res := r.workerOp(w.ID, "op_c", "pairingConfirm", pairingConfirmArgs{MailID: other, BaseRevision: s.PairingRev}); res.Code != CodePairingClosed {
		t.Fatalf("confirm after pairing: %+v", res)
	}
}

func TestPairingConfirmedInTheApp(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	w, mb := r.worker()
	r.workerOp(w.ID, "op_p", "pairingStart", pairingStartArgs{Requester: "lee@client.example", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()})
	// From lee, but no reply to the connect email.
	id := r.edge.deliver(mb, email{from: "lee@client.example", to: testWorkerAddr, unsigned: true})
	r.pass()
	s := r.settings(w.ID)
	if len(s.Pairing.Untokened) != 1 || s.requester("lee@client.example") != nil {
		t.Fatalf("%+v", s)
	}
	if res := r.workerOp(w.ID, "op_c0", "pairingConfirm", pairingConfirmArgs{MailID: "nope", BaseRevision: s.PairingRev}); res.Code != CodeNotFound {
		t.Fatalf("another email: %+v", res)
	}
	if res := r.workerOp(w.ID, "op_c1", "pairingConfirm", pairingConfirmArgs{MailID: id, BaseRevision: s.PairingRev - 1}); res.Code != CodeWorkerChanged {
		t.Fatalf("stale: %+v", res)
	}
	if res := r.workerOp(w.ID, "op_c2", "pairingConfirm", pairingConfirmArgs{MailID: id, BaseRevision: s.PairingRev}); !res.OK {
		t.Fatalf("pairingConfirm: %+v", res)
	}
	q := r.settings(w.ID).requester("lee@client.example")
	if q == nil || q.AutoRun || q.PairedBy != "confirmed" || q.DKIMDomain != "" {
		t.Fatalf("%+v", q)
	}
}

func TestConnectIDs(t *testing.T) {
	for id, want := range map[string]bool{
		"<c.1700000000.abc123@fountbox.com>": true,
		"c.1.Z9@FOUNTBOX.COM":                true,
		"<c.x.abc@fountbox.com>":             false,
		"<c.1.ab-c@fountbox.com>":            false,
		"<c.1.abc@example.com>":              false,
		"<fm.1.abc@fountbox.com>":            false,
	} {
		if got := isConnectID(id, "@fountbox.com"); got != want {
			t.Errorf("%s: %v", id, got)
		}
	}
	if got := connectIDIn("<a@b.c> <c.1.ab@fountbox.com>", "@fountbox.com"); got != "<c.1.ab@fountbox.com>" {
		t.Errorf("%q", got)
	}
}

type fakeEntitlements struct {
	issued []EntitlementRequest
	err    error
}

func (f *fakeEntitlements) Issue(_ context.Context, req EntitlementRequest) (Entitlement, error) {
	f.issued = append(f.issued, req)
	if f.err != nil {
		return Entitlement{}, f.err
	}
	return Entitlement{Token: "ent-" + req.MailboxID[:8], IssuedAt: time.Now()}, nil
}

func TestCloudMailboxesRenewDaily(t *testing.T) {
	ents := &fakeEntitlements{err: errors.New("fount-infra is down")}
	r := newMailRig(t, MailConfig{Entitlements: ents})
	w, mb := r.worker()
	now := time.Now()
	sweep := func(at time.Time) {
		r.c.mail.mu.Lock()
		r.c.mail.lastSweep = time.Time{}
		r.c.mail.mu.Unlock()
		r.c.mailPass(context.Background(), at)
	}
	sweep(now)
	if len(ents.issued) != 1 || len(r.edge.renews) != 0 {
		t.Fatalf("%d issued, %d presented", len(ents.issued), len(r.edge.renews))
	}
	keys, _ := mb.keys()
	if req := ents.issued[0]; req.Account != "acct_1" || req.Pay != "acct_1" || req.WorkerID != w.ID || !req.SigningKey.Equal(keys.SigningPublic()) {
		t.Fatalf("%+v", req)
	}
	v, _ := r.c.mailView(anyDevice, w.ID)
	if v.Renewal == nil || v.Renewal.Error == "" {
		t.Fatalf("the failure is kept: %+v", v.Renewal)
	}
	sweep(now.Add(time.Minute))
	if len(ents.issued) != 1 {
		t.Fatal("a failure is retried within the hour")
	}
	ents.err = nil
	sweep(now.Add(renewRetry))
	if len(ents.issued) != 2 || len(r.edge.renews) != 1 || r.edge.renews[0] != "ent-"+mb.MailboxID[:8] {
		t.Fatalf("renewed: %d %v", len(ents.issued), r.edge.renews)
	}
	v, _ = r.c.mailView(anyDevice, w.ID)
	if v.Renewal.Error != "" || v.Renewal.ExpiresAt.Unix() != r.edge.expiry {
		t.Fatalf("%+v", v.Renewal)
	}
	sweep(now.Add(renewRetry + time.Hour))
	if len(ents.issued) != 2 {
		t.Fatal("renewed again within the day")
	}
	r.start()
	r.pass()
	if len(ents.issued) != 2 {
		t.Fatal("a restart renewed again within the day")
	}
	sweep(now.Add(renewRetry + renewAfter + time.Minute))
	if len(ents.issued) != 3 {
		t.Fatal("not renewed after a day")
	}
}

// A worker made by an account and then added to a firm team renews under
// its creator's license, which the edge bound its mailbox to, paid for by the
// team.
func TestATeamWorkerRenewsUnderItsCreatorsLicense(t *testing.T) {
	ents := &fakeEntitlements{}
	r := newMailRig(t, MailConfig{Entitlements: ents})
	me := newTestDevice(t)
	team, err := r.c.MintTeam(me.caller("acct_1"))
	if err != nil {
		t.Fatal(err)
	}
	tt := newTestTeam(t, r.c, team)
	tt.set("m_owner", "acct_1", RoleAdmin, me)
	if err := tt.push(me, "acct_1", nil); err != nil {
		t.Fatal(err)
	}
	w, err := tt.addWorker(me, "acct_1", mustDEK(t))
	if err != nil {
		t.Fatal(err)
	}
	if w.Team != team || w.Account != team || w.License != "acct_1" {
		t.Fatalf("the team worker: team %s account %s license %s", w.Team, w.Account, w.License)
	}
	mb := newMailbox(t, testWorkerAddr)
	r.edge.register(mb)
	if err := r.c.SetMailbox(w.ID, mb, nil); err != nil {
		t.Fatal(err)
	}
	// Another list keeps the license.
	tt.set("m_rev", "acct_2", RoleReviewer, newTestDevice(t))
	if err := tt.push(me, "acct_1", nil); err != nil {
		t.Fatal(err)
	}
	r.start()
	if got, _ := r.c.Worker(w.ID); got.License != "acct_1" || got.Account != team {
		t.Fatalf("after another list and a restart: account %s license %s", got.Account, got.License)
	}
	r.c.mailPass(context.Background(), time.Now())
	if len(ents.issued) != 1 {
		t.Fatalf("%d issued", len(ents.issued))
	}
	if req := ents.issued[0]; req.Account != "acct_1" || req.Pay != team || req.WorkerID != w.ID {
		t.Fatalf("renewed as %+v", req)
	}
}

func TestTheMailboxThroughTheDevAPI(t *testing.T) {
	r := newMailRig(t, MailConfig{})
	w, err := r.c.CreateWorker("acct_1", nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(r.c.Handler())
	defer srv.Close()
	mb := newMailbox(t, "AP@fountbox.com")
	body, _ := json.Marshal(putMailboxBody{Mailbox: mb, Requesters: []Requester{{Address: "dana@example.com"}}})
	code, out := do(t, srv, "PUT", "/v0/workers/"+w.ID+"/mail", string(body))
	if code != 200 || out["address"] != "ap@fountbox.com" || out["signingKey"] != nil || out["requestersRevision"] != float64(1) {
		t.Fatalf("PUT: %d %v", code, out)
	}
	if got, _ := r.c.Worker(w.ID); got.Mailbox != mb.MailboxID {
		t.Fatalf("the volume's mailbox: %+v", got)
	}
	if code, out := do(t, srv, "GET", "/v0/workers/"+w.ID+"/mail", ""); code != 200 || out["autoRun"] != false {
		t.Fatalf("GET: %d %v", code, out)
	}
	bad := mb
	bad.SigningKey = []byte{1}
	body, _ = json.Marshal(putMailboxBody{Mailbox: bad})
	if code, _ := do(t, srv, "PUT", "/v0/workers/"+w.ID+"/mail", string(body)); code != 400 {
		t.Fatalf("bad keys: %d", code)
	}
	other, _ := r.c.CreateWorker("acct_1", nil)
	if code, _ := do(t, srv, "GET", "/v0/workers/"+other.ID+"/mail", ""); code != 404 {
		t.Fatalf("no mailbox: %d", code)
	}
}
