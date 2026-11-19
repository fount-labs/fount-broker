package coordinator

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A team of two admins, a reviewer and two workers: what most of these tests
// start from.
type teamFixture struct {
	c                      *Coordinator
	tt                     *testTeam
	owner, admin, reviewer testDevice
	w1, w2                 Worker
	dek1, dek2             DEK
}

func newTeamFixture(t *testing.T) teamFixture {
	t.Helper()
	c, _ := newTestCoordinator(t, "ok", 0)
	f := teamFixture{c: c, owner: newTestDevice(t), admin: newTestDevice(t), reviewer: newTestDevice(t), dek1: mustDEK(t), dek2: mustDEK(t)}
	f.tt = soloTeam(t, c, "acme", f.owner)
	f.tt.set("m_admin", "dev", RoleAdmin, f.admin)
	f.tt.set("m_reviewer", "maria", RoleReviewer, f.reviewer)
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	var err error
	if f.w1, err = f.tt.addWorker(f.owner, "acme", f.dek1); err != nil {
		t.Fatal(err)
	}
	if f.w2, err = f.tt.addWorker(f.admin, "dev", f.dek2); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f teamFixture) api(t *testing.T, d testDevice, account string) *httptest.Server {
	srv := httptest.NewServer(f.c.AccountHandler(d.caller(account)))
	t.Cleanup(srv.Close)
	return srv
}

func (f teamFixture) team(t *testing.T) *Team {
	t.Helper()
	f.c.mu.Lock()
	defer f.c.mu.Unlock()
	return f.c.state.Teams["acme"]
}

func TestATeamsFirstListIsItsOwnAccountsWithItsSignerAdmin(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	me, other := newTestDevice(t), newTestDevice(t)

	// Another account's team: the server can't claim one for someone else.
	tt := newTestTeam(t, c, "firm")
	tt.set("m_owner", "acme", RoleAdmin, me)
	if err := tt.push(me, "acme", nil); !errors.Is(err, ErrNotAdmin) {
		t.Errorf("a first list for another account's team: %v", err)
	}
	// Its signer a reviewer under another admin.
	tt = newTestTeam(t, c, "acme")
	tt.set("m_admin", "other", RoleAdmin, other)
	tt.set("m_me", "acme", RoleReviewer, me)
	if err := tt.push(me, "acme", nil); !errors.Is(err, ErrNotAdmin) {
		t.Errorf("a first list its signer is a reviewer in: %v", err)
	}
	// Its signer not in it.
	tt = newTestTeam(t, c, "acme")
	tt.set("m_admin", "acme", RoleAdmin, other)
	if err := tt.push(me, "acme", nil); !errors.Is(err, ErrNotAdmin) {
		t.Errorf("a first list without its signer: %v", err)
	}
	// Numbered as if it weren't the first.
	tt = newTestTeam(t, c, "acme")
	tt.set("m_owner", "acme", RoleAdmin, me)
	l := tt.list()
	l.Seq, l.Prev = 2, entryHash(TeamListContext, []byte("x"))
	if err := tt.pushList(me.caller("acme"), me.sign(t, l), l, nil); !errors.Is(err, ErrTeamStale) && !errors.Is(err, ErrListRefused) {
		t.Errorf("a first list numbered 2: %v", err)
	}
	if err := tt.push(me, "acme", nil); err != nil {
		t.Fatalf("the team of one: %v", err)
	}
	if seq, head := tt.head(); seq != 1 || head == "" {
		t.Errorf("the head: %d %q", seq, head)
	}
}

func TestOnlyAnAdminsDeviceSignsTheNextList(t *testing.T) {
	f := newTeamFixture(t)
	stranger := newTestDevice(t)
	seq, head := f.tt.head()
	// The reviewer makes themself admin.
	f.tt.update("m_reviewer", func(m *ListMember) { m.Role, m.Workers = RoleAdmin, nil })
	l := f.tt.list()
	for _, tc := range []struct {
		name   string
		caller Caller
		token  string
		want   error
	}{
		{"the reviewer escalating", f.reviewer.caller("maria"), f.reviewer.sign(t, l), ErrNotAdmin},
		{"a device of the account the team doesn't admit", stranger.caller("acme"), stranger.sign(t, l), ErrNotAdmin},
		{"an admin's device under another account's credential", f.admin.caller("acme"), f.admin.sign(t, l), ErrNotAdmin},
		{"signed by the admin, sent by the reviewer", f.reviewer.caller("maria"), f.admin.sign(t, l), ErrListRefused},
		{"signed by the reviewer, sent as the admin", f.admin.caller("dev"), f.reviewer.sign(t, l), ErrListRefused},
	} {
		if _, err := f.c.AppendTeamList(tc.caller, "acme", tc.token, nil); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	if s, h := f.tt.head(); s != seq || h != head {
		t.Fatalf("the log moved: %d", s)
	}
	// An admin may make an admin.
	if err := f.tt.pushList(f.admin.caller("dev"), f.admin.sign(t, l), l, nil); err != nil {
		t.Fatalf("an admin's list: %v", err)
	}
	// A removed admin's device can't sign again.
	f.tt.drop("m_admin")
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	f.tt.set("m_admin", "dev", RoleAdmin, f.admin)
	if err := f.tt.push(f.admin, "dev", nil); !errors.Is(err, ErrNotAdmin) {
		t.Errorf("a removed admin re-adding themself: %v", err)
	}
}

func TestAListFollowsTheHeadOnce(t *testing.T) {
	f := newTeamFixture(t)
	f.tt.set("m_new", "ann", RoleReviewer, newTestDevice(t))
	l := f.tt.list()
	token := f.owner.sign(t, l)
	if err := f.tt.pushList(f.owner.caller("acme"), token, l, nil); err != nil {
		t.Fatal(err)
	}
	// The same list again: a replay.
	if _, err := f.c.AppendTeamList(f.owner.caller("acme"), "acme", token, nil); !errors.Is(err, ErrTeamStale) {
		t.Errorf("a replay: %v", err)
	}
	// Two admins racing for the next number: the first wins, the second is
	// stale and signs again over the new head.
	f.tt.drop("m_new")
	a := f.tt.list()
	f.tt.set("m_new", "ann", RoleAdmin, newTestDevice(t))
	b := f.tt.list()
	if a.Seq != b.Seq {
		t.Fatal("not a race")
	}
	tokenA, tokenB := f.owner.sign(t, a), f.admin.sign(t, b)
	if err := f.tt.pushList(f.owner.caller("acme"), tokenA, a, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.AppendTeamList(f.admin.caller("dev"), "acme", tokenB, nil); !errors.Is(err, ErrTeamStale) {
		t.Errorf("the second of two for one number: %v", err)
	}
	// A list whose prev isn't the head's hash, though its number is next.
	f.tt.drop("m_new")
	l = f.tt.list()
	l.Prev = entryHash(TeamListContext, []byte("another branch"))
	if err := f.tt.pushList(f.owner.caller("acme"), f.owner.sign(t, l), l, nil); !errors.Is(err, ErrTeamStale) {
		t.Errorf("a fork: %v", err)
	}
	// An old number: rolling the team back to an earlier list.
	l = f.tt.list()
	l.Seq, l.Prev = 2, f.team(t).Log[0].Hash
	if err := f.tt.pushList(f.owner.caller("acme"), f.owner.sign(t, l), l, nil); !errors.Is(err, ErrTeamStale) {
		t.Errorf("a rollback: %v", err)
	}
	// Signed too long ago, or in the future.
	for _, iat := range []time.Time{time.Now().Add(-MaxGrantAge), time.Now().Add(grantSkew + time.Minute)} {
		l = f.tt.list()
		l.Iat = iat.Unix()
		if err := f.tt.pushList(f.owner.caller("acme"), f.owner.sign(t, l), l, nil); !errors.Is(err, ErrListRefused) {
			t.Errorf("signed at %s: %v", iat, err)
		}
	}
}

// Each list is strictly one shape: anything the Go and the Rust decoders
// could read two ways is refused before the signature means anything.
func TestAListIsDecodedStrictly(t *testing.T) {
	f := newTeamFixture(t)
	raw := []byte(claimsOf(f.owner.sign(t, f.tt.list())))
	inject := func(old, new string) func(*testing.T) []byte {
		return func(t *testing.T) []byte {
			if !strings.Contains(string(raw), old) {
				t.Fatalf("no %q in the list", old)
			}
			return []byte(strings.Replace(string(raw), old, new, 1))
		}
	}
	for _, tc := range []struct {
		name    string
		payload func(*testing.T) []byte
	}{
		{"a duplicate key at the top", inject(`"team":"acme"`, `"team":"acme","team":"evil"`)},
		{"a duplicate key in a member", inject(`"role":"reviewer"`, `"role":"reviewer","role":"admin"`)},
		{"an unknown field", inject(`"team":"acme"`, `"team":"acme","admins":["all"]`)},
		{"an unknown field in a member", inject(`"role":"reviewer"`, `"role":"reviewer","owner":true`)},
		{"trailing data", func(*testing.T) []byte { return append(slices.Clone(raw), []byte(` {}`)...) }},
		{"another version", inject(`"v":3`, `"v":2`)},
		{"another type", inject(`"typ":"fount-team-members"`, `"typ":"fount-worker-grant"`)},
		{"another coordinator", inject(`"aud":"`+testAudience+`"`, `"aud":"https://evil.example"`)},
		{"another team", inject(`"team":"acme"`, `"team":"evil"`)},
	} {
		payload := tc.payload(t)
		var l TeamList
		json.Unmarshal(payload, &l)
		token := b64.EncodeToString(payload) + "." + b64.EncodeToString(signRawList(f.owner, payload))
		if err := f.tt.pushList(f.owner.caller("acme"), token, l, nil); !errors.Is(err, ErrListRefused) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func signRawList(d testDevice, payload []byte) []byte {
	return ed25519.Sign(d.key, append([]byte(TeamListContext), payload...))
}

func TestAListsShapeIsChecked(t *testing.T) {
	f := newTeamFixture(t)
	other := newTestDevice(t)
	for _, tc := range []struct {
		name   string
		change func(*TeamList)
	}{
		{"no admin", func(l *TeamList) {
			for i := range l.Members {
				l.Members[i].Role, l.Members[i].Workers = RoleReviewer, []string{allWorkers}
			}
		}},
		{"no members", func(l *TeamList) { l.Members = nil }},
		{"members out of order", func(l *TeamList) { l.Members[0], l.Members[1] = l.Members[1], l.Members[0] }},
		{"a member twice", func(l *TeamList) { l.Members = append(l.Members, l.Members[len(l.Members)-1]) }},
		{"no role", func(l *TeamList) { l.Members[2].Role = "owner" }},
		{"an admin limited to some workers", func(l *TeamList) { l.Members[0].Workers = []string{f.w1.ID} }},
		{"a reviewer of no worker", func(l *TeamList) { l.Members[2].Workers = nil }},
		{"a reviewer of another team's worker", func(l *TeamList) { l.Members[2].Workers = []string{"w_0123456789abcdef01234567"} }},
		{"one account as two members", func(l *TeamList) { l.Members[2].Account = "dev" }},
		{"one device under two members", func(l *TeamList) {
			l.Members[2].Devices = []string{f.admin.include(t, "acme", "maria", f.tt.since[f.admin.id()])}
		}},
		{"a device included for another account", func(l *TeamList) {
			l.Members[2].Devices = append(l.Members[2].Devices, other.include(t, "acme", "dev", l.Seq))
		}},
		{"a device included for another team", func(l *TeamList) {
			l.Members[2].Devices = append(l.Members[2].Devices, other.include(t, "firm", "maria", l.Seq))
		}},
		{"an inclusion signed by another key", func(l *TeamList) {
			bad, _ := signToken(f.reviewer.key, TeamInclusionContext, TeamInclusion{V: 1, Typ: TeamInclusionType, Aud: testAudience, Team: "acme", Acct: "maria",
				Dev: other.id(), Key: other.b64(), Enc: b64.EncodeToString(other.enc.PublicKey().Bytes()), Seq: l.Seq})
			l.Members[2].Devices = append(l.Members[2].Devices, bad)
		}},
		{"an upper-case email", func(l *TeamList) { l.Members[2].Email = "Maria@firm.com" }},
		{"an invited member with no email", func(l *TeamList) {
			l.Members = append(l.Members, ListMember{ID: "m_zed", Role: RoleReviewer, Workers: []string{allWorkers}, Invite: &ListInvite{ID: "i_1", Commit: b64.EncodeToString(make([]byte, 32)), Exp: 1}})
		}},
		{"an invited member with a device", func(l *TeamList) {
			l.Members = append(l.Members, ListMember{ID: "m_zed", Email: "z@firm.com", Role: RoleReviewer, Workers: []string{allWorkers},
				Invite: &ListInvite{ID: "i_1", Commit: b64.EncodeToString(make([]byte, 32)), Exp: 1}, Devices: []string{other.include(t, "acme", "", l.Seq)}})
		}},
		{"a malformed invite", func(l *TeamList) {
			l.Members[2].Invite = &ListInvite{ID: "i_1", Commit: "short", Exp: 1}
			l.Members[2].Email = "maria@firm.com"
		}},
		{"a malformed passkey", func(l *TeamList) { l.Members[0].Rec = &ListRec{Cred: "AA", Pub: "AA"} }},
		{"workers out of order", func(l *TeamList) { l.Workers[0], l.Workers[1] = l.Workers[1], l.Workers[0] }},
	} {
		l := f.tt.list()
		tc.change(&l)
		if err := f.tt.pushList(f.owner.caller("acme"), f.owner.sign(t, l), l, nil); !errors.Is(err, ErrListRefused) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

// A device keeps the inclusion it was admitted on; a removed device's old
// one can't bring it back, and an admin can't move a device to another
// member.
func TestADeviceKeepsItsInclusion(t *testing.T) {
	f := newTeamFixture(t)
	old := f.tt.since[f.reviewer.id()]
	oldInclusion := f.reviewer.include(t, "acme", "maria", old)
	f.tt.devices["m_reviewer"] = nil
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	// Back on the inclusion it was first admitted on.
	l := f.tt.list()
	for i := range l.Members {
		if l.Members[i].ID == "m_reviewer" {
			l.Members[i].Devices = []string{oldInclusion}
		}
	}
	if err := f.tt.pushList(f.owner.caller("acme"), f.owner.sign(t, l), l, nil); !errors.Is(err, ErrListRefused) {
		t.Errorf("a removed device on its old inclusion: %v", err)
	}
	// A listed device on a newer inclusion than it was admitted on.
	l = f.tt.list()
	l.Members[0].Devices = []string{f.admin.include(t, "acme", "dev", l.Seq)}
	if err := f.tt.pushList(f.owner.caller("acme"), f.owner.sign(t, l), l, nil); !errors.Is(err, ErrListRefused) {
		t.Errorf("a listed device's inclusion swapped: %v", err)
	}
	// The admin's device moved under the reviewer: a role change by the
	// back door.
	f.tt.devices["m_reviewer"] = []testDevice{f.admin}
	f.tt.devices["m_admin"] = nil
	f.tt.update("m_reviewer", func(m *ListMember) { m.Account = "dev" })
	f.tt.update("m_admin", func(m *ListMember) { m.Account = "dev2" })
	if err := f.tt.push(f.owner, "acme", nil); !errors.Is(err, ErrListRefused) {
		t.Errorf("a device moved to another member: %v", err)
	}
	f.tt.update("m_reviewer", func(m *ListMember) { m.Account = "maria" })
	f.tt.update("m_admin", func(m *ListMember) { m.Account = "dev" })
	f.tt.devices["m_admin"] = []testDevice{f.admin}
	// Re-admitted on a new inclusion, it is back.
	f.tt.devices["m_reviewer"] = []testDevice{f.reviewer}
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatalf("re-admitting on a new inclusion: %v", err)
	}
	if _, _, err := f.c.access(f.reviewer.caller("maria"), f.w1.ID, RoleReviewer); err != nil {
		t.Errorf("the re-admitted reviewer: %v", err)
	}
}

func TestAMembersAccountNeverChanges(t *testing.T) {
	f := newTeamFixture(t)
	f.tt.update("m_reviewer", func(m *ListMember) { m.Account = "mallory" })
	f.tt.devices["m_reviewer"] = nil
	if err := f.tt.push(f.owner, "acme", nil); !errors.Is(err, ErrListRefused) {
		t.Errorf("a member's account changed: %v", err)
	}
}

// A firm team's id is one the coordinator made for the signer's account: an
// organisation's id, or another account's minted id, can't be claimed.
func TestAFirmTeamsIDIsMinted(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	me, other := newTestDevice(t), newTestDevice(t)

	id, err := c.MintTeam(me.caller("acme"))
	if err != nil || !strings.HasPrefix(id, teamIDPrefix+"_") || checkID("team", id) != nil {
		t.Fatalf("minted %q: %v", id, err)
	}
	if again, _ := c.MintTeam(me.caller("acme")); again != id {
		t.Errorf("an account's open mint is returned again: %q, want %q", again, id)
	}
	theirs, _ := c.MintTeam(other.caller("globex"))
	if theirs == id {
		t.Fatal("two accounts were given one id")
	}

	// An organisation's id, and another account's mint, aren't the
	// signer's.
	for _, team := range []string{"org_2abcDEF", theirs} {
		tt := newTestTeam(t, c, team)
		tt.set("m_owner", "acme", RoleAdmin, me)
		if err := tt.push(me, "acme", nil); !errors.Is(err, ErrNotAdmin) {
			t.Errorf("a first list for %s: %v", team, err)
		}
	}

	// Through the account API, as Desktop asks.
	srv := httptest.NewServer(c.AccountHandler(me.caller("acme")))
	t.Cleanup(srv.Close)
	if code, out := do(t, srv, "POST", "/v1/teams", ""); code != 200 || out["team"] != id {
		t.Fatalf("POST /v1/teams: %d %v", code, out)
	}

	tt := newTestTeam(t, c, id)
	tt.set("m_owner", "acme", RoleAdmin, me)
	if err := tt.push(me, "acme", nil); err != nil {
		t.Fatalf("the firm's first list: %v", err)
	}
	w, err := tt.addWorker(me, "acme", mustDEK(t))
	if err != nil {
		t.Fatal(err)
	}
	if w.Team != id || w.Account != id {
		t.Errorf("a firm worker's team and account: %s %s", w.Team, w.Account)
	}
	// The mint is used: the next is a new team's, and survives a restart.
	next, _ := c.MintTeam(me.caller("acme"))
	if next == id {
		t.Error("a used mint was given again")
	}
	c2, err := New(c.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := c2.MintTeam(me.caller("acme")); again != next {
		t.Errorf("after a restart: %q, want %q", again, next)
	}
}

// Every route and operation needs its role on the worker, and a reviewer
// reaches only the workers assigned them.
func TestEveryOperationChecksTheRole(t *testing.T) {
	f := newTeamFixture(t)
	f.tt.update("m_reviewer", func(m *ListMember) { m.Workers = []string{f.w1.ID} })
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	f.c.PutFile(f.w1.ID, "instructions.md", []byte("be brief"))
	j, _ := f.c.Enqueue(f.w1.ID, spec("t1"))
	waitJob(t, f.c, j.ID)
	reviewer, admin := f.api(t, f.reviewer, "maria"), f.api(t, f.admin, "dev")
	op := func(kind string) string {
		return `{"opId":"op_` + kind + `","kind":"` + kind + `","args":{"text":"hi"}}`
	}
	base := "/v1/workers/" + f.w1.ID
	for _, tc := range []struct {
		method, path, body string
		reviewer, admin    int
	}{
		{"GET", base, "", 200, 200},
		{"GET", base + "/files", "", 200, 200},
		{"GET", base + "/files/root/instructions.md", "", 200, 200},
		{"GET", base + "/threads", "", 200, 200},
		{"GET", "/v1/jobs/" + j.ID, "", 200, 200},
		{"GET", "/v1/teams/acme/log", "", 200, 200},
		{"POST", base + "/ops", op("startThread"), 200, 200},
		{"PUT", base + "/root/instructions.md", "x", 403, 204},
		{"POST", base + "/jobs", `{"threadId":"t2","sessionId":"s2","instruction":"hi","config":{}}`, 403, 202},
		{"POST", base + "/ops", `{"opId":"op_auto","kind":"setAutoRun","args":{"on":true,"baseRevision":0}}`, 403, 200},
		{"POST", base + "/ops", `{"opId":"op_req","kind":"addRequester","args":{"address":"lee@client.example","baseRevision":0}}`, 403, 200},
		{"POST", base + "/threads/thr_0123456789abcdef01234567/ops", `{"opId":"op_x","threadId":"thr_0123456789abcdef01234567","baseRevision":0,"kind":"runHeldMail","args":{"mailId":"m_1"}}`, 200, 200},
		{"POST", base + "/ops", op("noSuchKind"), 403, 403},
		{"POST", base + "/threads/thr_0123456789abcdef01234567/ops", `{"opId":"op_x","threadId":"thr_0123456789abcdef01234567","baseRevision":0,"kind":"setThreadReplyMode","args":{}}`, 403, 501},
		{"POST", base + "/threads/thr_0123456789abcdef01234567/ops", `{"opId":"op_x","threadId":"thr_0123456789abcdef01234567","baseRevision":0,"kind":"approveDraft","args":{}}`, 501, 501},
		// The worker not assigned to the reviewer: as if there were none.
		{"GET", "/v1/workers/" + f.w2.ID, "", 404, 200},
		{"GET", "/v1/workers/" + f.w2.ID + "/threads", "", 404, 200},
	} {
		if code, out := do(t, reviewer, tc.method, tc.path, tc.body); code != tc.reviewer {
			t.Errorf("reviewer: %s %s: %d %v, want %d", tc.method, tc.path, code, out, tc.reviewer)
		}
		code, out := do(t, admin, tc.method, tc.path, tc.body)
		if code != tc.admin {
			t.Errorf("admin: %s %s: %d %v, want %d", tc.method, tc.path, code, out, tc.admin)
		}
		if id, ok := out["id"].(string); ok && strings.HasPrefix(id, "j_") {
			waitJob(t, f.c, id)
		}
	}
	if _, list := do(t, reviewer, "GET", "/v1/workers", ""); len(list["workers"].([]any)) != 1 {
		t.Errorf("the reviewer's workers: %v", list)
	}
	if _, list := do(t, admin, "GET", "/v1/workers", ""); len(list["workers"].([]any)) != 2 {
		t.Errorf("the admin's workers: %v", list)
	}
	if _, w := do(t, reviewer, "GET", base, ""); w["role"] != "reviewer" || w["wrap"] == nil {
		t.Errorf("the reviewer's view: %v", w)
	}
	if w, _ := f.c.Worker(f.w2.ID); slices.ContainsFunc(w.Devices, func(d Device) bool { return d.ID == f.reviewer.id() }) {
		t.Error("the reviewer has a wrap for a worker they don't reach")
	}
}

// opRoles has every route the account API serves and every operation kind
// the coordinator knows, so none is let through by a missing entry.
func TestEveryOperationHasARole(t *testing.T) {
	var routes routeList
	(&api{}).accountRoutes(&routes)
	for _, p := range routes {
		if _, ok := opRole(routeKey(p)); !ok {
			t.Errorf("route %s has no role", p)
		}
	}
	kinds := opKindsIn(t, "threadops.go")
	kinds = append(kinds, opKindsIn(t, "mailops.go")...)
	for k := range mailWorkerOps {
		kinds = append(kinds, k)
	}
	for k := range unsupportedThreadOps {
		kinds = append(kinds, k)
	}
	for k := range unsupportedWorkerOps {
		kinds = append(kinds, k)
	}
	if !slices.Contains(kinds, "sendNote") || !slices.Contains(kinds, "startThread") || !slices.Contains(kinds, "runHeldMail") {
		t.Fatalf("the walk found %v", kinds)
	}
	for _, k := range kinds {
		if r, ok := opRole(k); !ok || (r != RoleAdmin && r != RoleReviewer) {
			t.Errorf("operation %s has no role", k)
		}
	}
	if _, ok := opRole("noSuchKind"); ok {
		t.Error("an unknown kind has a role")
	}
}

type routeList []string

func (r *routeList) HandleFunc(pattern string, _ func(http.ResponseWriter, *http.Request)) {
	*r = append(*r, pattern)
}

// opKindsIn are the string literals a file compares an envelope's Kind
// with: its switch cases and its == and != tests.
func opKindsIn(t *testing.T, file string) []string {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	isKind := func(e ast.Expr) bool {
		s, ok := e.(*ast.SelectorExpr)
		return ok && s.Sel.Name == "Kind"
	}
	var kinds []string
	lit := func(e ast.Expr) {
		if b, ok := e.(*ast.BasicLit); ok && b.Kind == token.STRING {
			if s, err := strconv.Unquote(b.Value); err == nil {
				kinds = append(kinds, s)
			}
		}
	}
	ast.Inspect(parsed, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SwitchStmt:
			if n.Tag != nil && isKind(n.Tag) {
				for _, s := range n.Body.List {
					for _, e := range s.(*ast.CaseClause).List {
						lit(e)
					}
				}
			}
		case *ast.BinaryExpr:
			if isKind(n.X) {
				lit(n.Y)
			}
			if isKind(n.Y) {
				lit(n.X)
			}
		}
		return true
	})
	return kinds
}

// Removing a member refuses their devices at once, on every route, and drops
// their wraps.
func TestARemovedMemberIsRefusedAtOnce(t *testing.T) {
	f := newTeamFixture(t)
	reviewer := f.api(t, f.reviewer, "maria")
	if code, _ := do(t, reviewer, "GET", "/v1/workers/"+f.w1.ID, ""); code != 200 {
		t.Fatalf("before: %d", code)
	}
	f.tt.drop("m_reviewer")
	if err := f.tt.push(f.admin, "dev", nil); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/workers/" + f.w1.ID, "/v1/workers/" + f.w1.ID + "/files", "/v1/teams/acme/log"} {
		if code, out := do(t, reviewer, "GET", path, ""); code != http.StatusNotFound {
			t.Errorf("after: GET %s: %d %v", path, code, out)
		}
	}
	if _, list := do(t, reviewer, "GET", "/v1/workers", ""); len(list["workers"].([]any)) != 0 {
		t.Errorf("their workers: %v", list)
	}
	for _, w := range []Worker{f.w1, f.w2} {
		got, _ := f.c.Worker(w.ID)
		if slices.ContainsFunc(got.Devices, func(d Device) bool { return d.ID == f.reviewer.id() }) {
			t.Errorf("worker %s keeps their wrap", w.ID)
		}
	}
	if _, err := f.c.readFile(f.reviewer.id(), f.w1.ID, prefixRoot+"instructions.md"); !errors.Is(err, ErrNoWorker) {
		t.Errorf("a read under the tree's lock: %v", err)
	}
	// A reviewer's removal rotates nothing.
	if rot := f.team(t).Rotate; len(rot) != 0 {
		t.Errorf("rotation: %v", rot)
	}
}

// Losing an admin, by removal, demotion or a device, marks every team
// worker's address signing key for rotation.
func TestLosingAnAdminRotatesEveryWorkersSigningKey(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(f teamFixture)
	}{
		{"removed", func(f teamFixture) { f.tt.drop("m_admin") }},
		{"demoted", func(f teamFixture) {
			f.tt.update("m_admin", func(m *ListMember) { m.Role, m.Workers = RoleReviewer, []string{allWorkers} })
		}},
		{"a device removed", func(f teamFixture) { f.tt.devices["m_admin"] = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newTeamFixture(t)
			if rot := f.team(t).Rotate; len(rot) != 0 {
				t.Fatalf("before: %v", rot)
			}
			tc.change(f)
			if err := f.tt.push(f.owner, "acme", nil); err != nil {
				t.Fatal(err)
			}
			want := []string{f.w1.ID, f.w2.ID}
			slices.Sort(want)
			if rot := f.team(t).Rotate; !slices.Equal(rot, want) {
				t.Errorf("rotation: %v, want %v", rot, want)
			}
		})
	}
	// A new admin wraps nothing away, so rotates nothing.
	f := newTeamFixture(t)
	f.tt.set("m_zed", "zed", RoleAdmin, newTestDevice(t))
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	if rot := f.team(t).Rotate; len(rot) != 0 {
		t.Errorf("a new admin: %v", rot)
	}
	f.c.mu.Lock()
	st, _ := f.c.teamState("acme")
	admins := len(st.adminDevices())
	f.c.mu.Unlock()
	if admins != 3 {
		t.Errorf("admin devices: %d", admins)
	}
}

// A worker joins a team only from an admin's device, with the DEK the list
// signs; and every device that reaches it, admin or reviewer, gets a wrap.
func TestAWorkerJoinsATeamOnlyWithItsDEKFromAnAdmin(t *testing.T) {
	f := newTeamFixture(t)
	dek := mustDEK(t)
	// Made by the reviewer's device.
	w, _ := f.c.CreateWorkerFor(f.reviewer.caller("maria"))
	f.tt.workers[w.ID] = DEKCommitment(w.ID, dek)
	if err := f.tt.push(f.owner, "acme", map[string]DEK{w.ID: dek}); !errors.Is(err, ErrListRefused) {
		t.Errorf("a worker the reviewer made: %v", err)
	}
	delete(f.tt.workers, w.ID)
	w, _ = f.c.CreateWorkerFor(f.admin.caller("dev"))
	f.tt.workers[w.ID] = DEKCommitment(w.ID, dek)
	for _, tc := range []struct {
		name string
		deks map[string]DEK
	}{
		{"no DEK", nil},
		{"another DEK", map[string]DEK{w.ID: mustDEK(t)}},
		{"a DEK for a worker already in the team", map[string]DEK{w.ID: dek, f.w1.ID: f.dek1}},
		{"a DEK for a worker the list doesn't name", map[string]DEK{w.ID: dek, "w_0123456789abcdef01234567": dek}},
	} {
		if err := f.tt.push(f.owner, "acme", tc.deks); !errors.Is(err, ErrListRefused) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	// A worker already in another team.
	other := newTestDevice(t)
	ot := soloTeam(t, f.c, "other", other)
	ow, err := ot.addWorker(other, "other", mustDEK(t))
	if err != nil {
		t.Fatal(err)
	}
	f.tt.workers[ow.ID] = ow.DEKCommitment
	if err := f.tt.push(f.owner, "acme", map[string]DEK{w.ID: dek}); !errors.Is(err, ErrListRefused) {
		t.Errorf("another team's worker: %v", err)
	}
	delete(f.tt.workers, ow.ID)
	// A worker's DEK commitment changed.
	f.tt.workers[f.w1.ID] = DEKCommitment(f.w1.ID, mustDEK(t))
	if err := f.tt.push(f.owner, "acme", map[string]DEK{w.ID: dek}); !errors.Is(err, ErrListRefused) {
		t.Errorf("a changed DEK: %v", err)
	}
	f.tt.workers[f.w1.ID] = f.w1.DEKCommitment
	// Signed by the owner, made by the other admin: fine.
	if err := f.tt.push(f.owner, "acme", map[string]DEK{w.ID: dek}); err != nil {
		t.Fatal(err)
	}
	got, _ := f.c.Worker(w.ID)
	if got.Team != "acme" || got.Account != "acme" || len(got.Devices) != 3 {
		t.Fatalf("the worker: %+v", got)
	}
	for _, d := range []testDevice{f.owner, f.admin, f.reviewer} {
		i := slices.IndexFunc(got.Devices, func(x Device) bool { return x.ID == d.id() })
		if i < 0 {
			t.Fatalf("device %s has no wrap", d.id())
		}
		if opened, err := OpenWrap(d.enc.Bytes(), "acme", w.ID, d.id(), got.DEKCommitment, got.Devices[i].Wrap); err != nil || opened != dek {
			t.Errorf("device %s's wrap: %v", d.id(), err)
		}
	}
}

func TestAWorkerTheListLeavesOutIsDeleted(t *testing.T) {
	f := newTeamFixture(t)
	f.c.PutFile(f.w2.ID, "instructions.md", []byte("be brief"))
	delete(f.tt.workers, f.w2.ID)
	f.c.mu.Lock()
	f.c.busy[f.w2.ID] = true
	f.c.mu.Unlock()
	if err := f.tt.push(f.owner, "acme", nil); !errors.Is(err, ErrBusy) {
		t.Errorf("deleting a busy worker: %v", err)
	}
	f.c.mu.Lock()
	delete(f.c.busy, f.w2.ID)
	f.c.mu.Unlock()
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.Worker(f.w2.ID); !errors.Is(err, ErrNoWorker) {
		t.Errorf("the deleted worker: %v", err)
	}
	if _, err := f.c.cfg.Store.Get(f.w2.ID, manifestObject); err == nil {
		t.Error("its objects outlived it")
	}
	// A reviewer can't delete one: they can't sign a list.
	delete(f.tt.workers, f.w1.ID)
	f.tt.update("m_reviewer", func(m *ListMember) { m.Workers = []string{allWorkers} })
	if err := f.tt.push(f.reviewer, "maria", nil); !errors.Is(err, ErrNotAdmin) {
		t.Errorf("a reviewer deleting a worker: %v", err)
	}
}

func TestTheLogSurvivesARestartAndADamagedLogOpensNothing(t *testing.T) {
	f := newTeamFixture(t)
	c2, err := New(f.c.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, role, err := c2.access(f.reviewer.caller("maria"), f.w1.ID, RoleReviewer); err != nil || role != RoleReviewer {
		t.Fatalf("after a restart: %v %s", err, role)
	}
	if c2.state.SecuritySeq != f.c.state.SecuritySeq || c2.state.SecuritySeq != 4 {
		t.Errorf("the security sequence: %d", c2.state.SecuritySeq)
	}
	// An entry's hash changed on the volume: the chain doesn't check, so
	// the team's state is nobody's.
	c2.mu.Lock()
	c2.state.Teams["acme"].Log[1].Hash = c2.state.Teams["acme"].Log[0].Hash
	c2.state.Teams["acme"].state = nil
	c2.mu.Unlock()
	if _, _, err := c2.access(f.owner.caller("acme"), f.w1.ID, RoleReviewer); !errors.Is(err, ErrNoWorker) {
		t.Errorf("a damaged log: %v", err)
	}
}

func TestTheLogIsReadByMembersFromAPoint(t *testing.T) {
	f := newTeamFixture(t)
	reviewer := f.api(t, f.reviewer, "maria")
	code, all := do(t, reviewer, "GET", "/v1/teams/acme/log", "")
	if code != 200 || all["seq"] != 4.0 || len(all["entries"].([]any)) != 4 {
		t.Fatalf("the log: %d %v", code, all)
	}
	_, tail := do(t, reviewer, "GET", "/v1/teams/acme/log?since=3", "")
	entries := tail["entries"].([]any)
	if len(entries) != 1 || tail["head"] != all["head"] || entries[0].(map[string]any)["hash"] != all["head"] {
		t.Errorf("after 3: %v", tail)
	}
	if _, none := do(t, reviewer, "GET", "/v1/teams/acme/log?since=9", ""); len(none["entries"].([]any)) != 0 {
		t.Errorf("after the head: %v", none)
	}
	// What a client checks: the chain from the first list.
	prev := ""
	for _, e := range all["entries"].([]any) {
		token := e.(map[string]any)["list"].(string)
		payload, _, _ := splitToken(token)
		l, err := decodeTeamList(payload)
		if err != nil || l.Prev != prev {
			t.Fatalf("entry %d: %v", l.Seq, err)
		}
		prev = entryHash(TeamListContext, payload)
	}
	if code, _ := do(t, reviewer, "GET", "/v1/teams/nope/log", ""); code != 404 {
		t.Errorf("another team: %d", code)
	}
}

// The record interface T and H build on: an invite taken once, by the
// invited account, for the next entry, binds the member's account.
func TestAnInviteRecordAdmitsOnceAndBindsTheAccount(t *testing.T) {
	f := newTeamFixture(t)
	invite := &ListInvite{ID: "i_ann", Commit: b64.EncodeToString(make([]byte, 32)), Exp: time.Now().Add(time.Hour).Unix()}
	f.tt.members["m_zed"] = ListMember{ID: "m_zed", Email: "ann@firm.com", Role: RoleReviewer, Workers: []string{allWorkers}, Invite: invite}
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	ann, eve := newTestDevice(t), newTestDevice(t)
	ok := func(*teamState, *Member) error { return nil }
	seq, _ := f.tt.head()
	rec := func(d testDevice, account string, since uint64) TeamRecord {
		return TeamRecord{Kind: RecordInvite, Member: "m_zed", Account: account, Device: d.include(t, "acme", account, since)}
	}
	for _, tc := range []struct {
		name   string
		caller Caller
		rec    TeamRecord
		proof  func(*teamState, *Member) error
	}{
		{"no proof checked", ann.caller("ann"), rec(ann, "ann", seq+1), nil},
		{"a proof that fails", ann.caller("ann"), rec(ann, "ann", seq+1), func(*teamState, *Member) error { return ErrListRefused }},
		{"another device's inclusion", eve.caller("ann"), rec(ann, "ann", seq+1), ok},
		{"an inclusion for another entry", ann.caller("ann"), rec(ann, "ann", seq), ok},
		{"for another account than the caller", ann.caller("eve"), rec(ann, "ann", seq+1), ok},
		{"an account already a member", f.reviewer.caller("maria"), rec(f.reviewer, "maria", seq+1), ok},
		{"a device already admitted", f.reviewer.caller("ann"), rec(f.reviewer, "ann", seq+1), ok},
		{"a join before the invite is taken", ann.caller("ann"), TeamRecord{Kind: RecordJoin, Member: "m_zed", Account: "ann", Device: ann.include(t, "acme", "ann", seq+1)}, ok},
		{"no kind", ann.caller("ann"), TeamRecord{Kind: "admin", Member: "m_zed", Account: "ann"}, ok},
		{"no member", ann.caller("ann"), TeamRecord{Kind: RecordInvite, Member: "m_nobody", Account: "ann", Device: ann.include(t, "acme", "ann", seq+1)}, ok},
	} {
		if err := f.c.appendRecord(tc.caller, "acme", tc.rec, tc.proof); err == nil {
			t.Errorf("%s: appended", tc.name)
		}
	}
	if s, _ := f.tt.head(); s != seq {
		t.Fatalf("the log moved to %d", s)
	}
	if err := f.c.appendRecord(ann.caller("ann"), "acme", rec(ann, "ann", seq+1), ok); err != nil {
		t.Fatal(err)
	}
	if _, role, err := f.c.access(ann.caller("ann"), f.w1.ID, RoleReviewer); err != nil || role != RoleReviewer {
		t.Fatalf("ann after her invite: %v %s", err, role)
	}
	if w, _ := f.c.Worker(f.w2.ID); !slices.ContainsFunc(w.Devices, func(d Device) bool { return d.ID == ann.id() }) {
		t.Error("ann has no wrap")
	}
	// The invite is taken: not again, by anyone.
	if err := f.c.appendRecord(eve.caller("ann"), "acme", rec(eve, "ann", seq+2), ok); err == nil {
		t.Error("the invite taken twice")
	}
	// The next list keeps ann on the inclusion her record admitted her on,
	// can't reopen the used invite, and can't move her to another account.
	f.tt.since[ann.id()] = seq + 1
	f.tt.members["m_zed"] = ListMember{ID: "m_zed", Account: "ann", Email: "ann@firm.com", Role: RoleReviewer, Workers: []string{allWorkers}, Invite: invite}
	f.tt.devices["m_zed"] = []testDevice{ann}
	if err := f.tt.push(f.owner, "acme", nil); !errors.Is(err, ErrListRefused) {
		t.Errorf("a list reopening a used invite: %v", err)
	}
	f.tt.update("m_zed", func(m *ListMember) { m.Invite, m.Account = nil, "eve" })
	f.tt.devices["m_zed"] = nil
	if err := f.tt.push(f.owner, "acme", nil); !errors.Is(err, ErrListRefused) {
		t.Errorf("a list moving ann to another account: %v", err)
	}
	f.tt.update("m_zed", func(m *ListMember) { m.Account = "ann" })
	f.tt.devices["m_zed"] = []testDevice{ann}
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatalf("the list after the record: %v", err)
	}
	// An admin's omission removes her.
	f.tt.devices["m_zed"] = nil
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.c.access(ann.caller("ann"), f.w1.ID, RoleReviewer); !errors.Is(err, ErrNoWorker) {
		t.Errorf("ann after her device's removal: %v", err)
	}
}
