package coordinator

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// teamMailRig is a sending, enrolled mail rig whose worker is in a team:
// dana owns it and is its requester; maria reviews it, by her invite's
// address, and isn't a requester.
type teamMailRig struct {
	*sendRig
	tt       *testTeam
	owner    testDevice
	reviewer testDevice
}

func newTeamMailRig(t *testing.T, mode string) *teamMailRig {
	t.Helper()
	r := genRig(t, MailConfig{Send: true})
	old := sendBackoff
	sendBackoff = func(int) time.Duration { return 0 }
	t.Cleanup(func() { sendBackoff = old })
	se := newFakeSendEdge(t)
	r.edge.mu.Lock()
	r.edge.send = se
	r.edge.mu.Unlock()
	r.runner.events = eventsWith(summaryWith(t, func(p map[string]any) {
		p["state"], p["text"], p["steps"] = "ready_for_review", agentAnswer, []any{}
		delete(p, "question")
	}))
	tr := &teamMailRig{owner: newTestDevice(t), reviewer: newTestDevice(t)}
	tr.tt = newTestTeam(t, r.c, "acme")
	tr.tt.set("m_owner", "acme", RoleAdmin, tr.owner)
	if err := tr.tt.push(tr.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	w, err := tr.tt.addWorker(tr.owner, "acme", mustDEK(t))
	if err != nil {
		t.Fatal(err)
	}
	mb := newMailbox(t, testWorkerAddr)
	r.edge.register(mb)
	if err := r.c.SetMailbox(w.ID, mb, []Requester{{Address: "dana@example.com", DKIMDomain: "example.com", AutoRun: true, PairedBy: "reply"}}); err != nil {
		t.Fatal(err)
	}
	if res := r.workerOp(w.ID, "op_auto", "setAutoRun", switchArgs{On: true}); !res.OK {
		t.Fatalf("setAutoRun: %+v", res)
	}
	if res := r.workerOp(w.ID, "op_mode", "setDefaultMode", defaultModeArgs{Mode: mode, Owner: "dana@example.com", Firm: "Acme"}); !res.OK {
		t.Fatalf("setDefaultMode: %+v", res)
	}
	w, _ = r.c.Worker(w.ID)
	tr.sendRig = &sendRig{mailRig: r, send: se, w: w, mb: mb}
	return tr
}

// join lists maria as a reviewer with her device.
func (r *teamMailRig) join() {
	r.t.Helper()
	r.tt.set("m_reviewer", "maria", RoleReviewer, r.reviewer)
	r.tt.update("m_reviewer", func(m *ListMember) { m.Email = "maria@example.com" })
	if err := r.tt.push(r.owner, "acme", nil); err != nil {
		r.t.Fatal(err)
	}
}

func (r *teamMailRig) sentRaw(id string) string {
	r.send.mu.Lock()
	defer r.send.mu.Unlock()
	return string(r.send.raw[id])
}

func (r *teamMailRig) edgeOwners() string {
	return fmt.Sprint(r.edge.coord.Mailbox(r.mb.MailboxID).Owners)
}

func TestNextNoticeOwnersAddsOneAtATime(t *testing.T) {
	for _, c := range []struct {
		taken, wanted []string
		requesters    int
		next          string
		more          bool
	}{
		{nil, nil, 1, "[]", false},
		{nil, []string{"a"}, 1, "[a]", false},
		{nil, []string{"a", "b", "c"}, 1, "[a]", true},
		{[]string{"a"}, []string{"a", "b", "c"}, 1, "[a b]", true},
		{[]string{"a", "b"}, []string{"b", "c"}, 1, "[b c]", false},
		{[]string{"a", "b"}, nil, 1, "[]", false},
		// The edge's limit: requesters first.
		{nil, []string{"a", "b"}, edgeMaxOwners, "[]", false},
		{[]string{"a", "b"}, []string{"a", "b", "c"}, edgeMaxOwners - 1, "[a]", false},
	} {
		next, more := nextNoticeOwners(c.taken, c.wanted, c.requesters)
		if fmt.Sprint(next) != c.next || more != c.more {
			t.Errorf("nextNoticeOwners(%v, %v, %d) = %v %v, want %s %v", c.taken, c.wanted, c.requesters, next, more, c.next, c.more)
		}
	}
}

// A reviewer who joins goes on the edge's owner list, so the edge proves
// them and may mail them; leaving takes them off it.
func TestAReviewerGoesOnTheEdgesOwnerList(t *testing.T) {
	r := newTeamMailRig(t, modeNotify)
	r.pass()
	if got := r.edgeOwners(); got != "[dana@example.com]" {
		t.Fatalf("before maria joins the edge holds %s", got)
	}
	r.join()
	r.c.mail.mu.Lock()
	kicked := r.c.mail.kicked[r.w.ID]
	r.c.mail.mu.Unlock()
	if !kicked {
		t.Fatal("a list change didn't kick the team's worker")
	}
	r.pass()
	if got := r.edgeOwners(); got != "[dana@example.com maria@example.com]" {
		t.Fatalf("the edge holds %s", got)
	}
	s := r.settings(r.w.ID)
	if fmt.Sprint(s.NoticeOwners) != "[maria@example.com]" || s.requester("maria@example.com") != nil {
		t.Fatalf("settings %+v", s)
	}
	calls := len(r.edge.coord.Calls())
	r.pass()
	if slices.Contains(r.edge.coord.Calls()[calls:], "POST /coordinator/routing") {
		t.Fatal("a list the edge took was sent again")
	}

	// A notice owner's email starts no work: it's held like a stranger's.
	id := r.edge.deliver(r.mb, email{from: "maria@example.com", to: testWorkerAddr, subject: "Please file it"})
	r.pass()
	if a := r.ledger(r.w.ID).Acted[id]; a.Outcome != outcomeHeld {
		t.Fatalf("maria's email: %+v", a)
	}

	r.tt.drop("m_reviewer")
	if err := r.tt.push(r.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	r.pass()
	if got := r.edgeOwners(); got != "[dana@example.com]" {
		t.Fatalf("after maria left the edge holds %s", got)
	}
	if s := r.settings(r.w.ID); len(s.NoticeOwners) != 0 {
		t.Fatalf("settings %+v", s)
	}
}

// Every reviewer the edge took hears of a draft, a held email and a
// question; one it hasn't taken yet doesn't.
func TestAReviewerHearsOfDraftsHeldMailAndQuestions(t *testing.T) {
	r := newTeamMailRig(t, modeNotify)
	r.join()
	r.edge.coord.LimitNewOwners(0)
	r.pass()
	th, _ := r.drafted()
	r.pass()
	for _, to := range []string{"dana@example.com", "maria@example.com"} {
		if got := r.send.sentTo(to, "A draft reply is ready in Acme"); len(got) != 1 {
			t.Fatalf("draft notices to %s: %v", to, got)
		}
	}

	r.edge.deliver(r.mb, email{from: "eve@else.example", to: testWorkerAddr, subject: "Hello"})
	r.pass()
	r.pass()
	for _, to := range []string{"dana@example.com", "maria@example.com"} {
		if got := r.send.sentTo(to, "An email is waiting in Acme"); len(got) != 1 {
			t.Fatalf("held notices to %s: %v", to, got)
		}
	}

	r.runner.events = eventsWith(goodSummary)
	id := r.edge.deliver(r.mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Bank statements"})
	r.pass()
	waitJob(t, r.c, mailJobID(id))
	for _, cur := range r.threads(r.w.ID) {
		if cur.ID != th.ID && cur.Subject == "Bank statements" {
			r.waitStatus(r.w.ID, cur.ID, StatusWaiting)
		}
	}
	r.pass()
	for _, to := range []string{"dana@example.com", "maria@example.com"} {
		got := r.send.sentTo(to, "A question is waiting in Acme")
		if len(got) != 1 {
			t.Fatalf("question notices to %s: %v", to, got)
		}
		raw := r.sentRaw(got[0])
		if strings.Contains(raw, "Which month?") {
			t.Fatalf("a question notice has content:\n%s", raw)
		}
	}
}

// The edge's new-owner cap holds a member back, not the requesters: the
// list goes without them, and they're added on a later pass.
func TestTheNewOwnerCapHoldsBackOnlyTheMember(t *testing.T) {
	r := newTeamMailRig(t, modeNotify)
	r.pass()
	r.edge.coord.LimitNewOwners(1)
	r.join()
	if res := r.workerOp(r.w.ID, "op_add", "addRequester", requesterArgs{Address: "lee@client.example", BaseRevision: r.settings(r.w.ID).RequestersRev}); !res.OK {
		t.Fatalf("addRequester: %+v", res)
	}
	r.pass()
	if got := r.edgeOwners(); got != "[dana@example.com lee@client.example]" {
		t.Fatalf("the edge holds %s", got)
	}
	if s := r.settings(r.w.ID); s.RoutingUnsent || len(s.NoticeOwners) != 0 {
		t.Fatalf("settings %+v", s)
	}
	calls := len(r.edge.coord.Calls())
	r.pass()
	if slices.Contains(r.edge.coord.Calls()[calls:], "fenced") {
		t.Fatal("a refused member fenced the worker")
	}
	r.edge.coord.LimitNewOwners(0)
	r.pass()
	if got := r.edgeOwners(); got != "[dana@example.com lee@client.example maria@example.com]" {
		t.Fatalf("later the edge holds %s", got)
	}
}

// A reviewer on Full approves by email as the owner does; once they leave
// the team their approval email stops working.
func TestAReviewersEmailApprovalNeedsThemStillOnTheTeam(t *testing.T) {
	for _, leave := range []bool{false, true} {
		t.Run(fmt.Sprint("leave=", leave), func(t *testing.T) {
			r := newTeamMailRig(t, modeFull)
			r.join()
			r.pass()
			r.intake.set(func(f *fakeIntake) { f.instruction, f.source, f.reply = "Yes.", "owner", true })
			th, e := r.drafted()
			r.pass()
			asks := r.send.sentTo("maria@example.com", "Approve: Re: Q3 close")
			if len(asks) != 1 {
				t.Fatalf("maria's approval email: %v", asks)
			}
			if raw := r.sentRaw(asks[0]); !strings.Contains(raw, "waits in Fount until someone runs it") {
				t.Fatalf("a member who isn't a requester is told their reply is a note:\n%s", raw)
			}
			if leave {
				r.tt.drop("m_reviewer")
				if err := r.tt.push(r.owner, "acme", nil); err != nil {
					t.Fatal(err)
				}
			}
			r.edge.deliver(r.mb, email{from: "maria@example.com", to: testWorkerAddr, subject: "Re: Approve: Re: Q3 close", inReplyTo: asks[0]})
			r.pass()
			d := r.draft(th.ID, e.ID)
			if leave {
				if d.State != draftPending {
					t.Fatalf("approved by someone who left: %s", d.State)
				}
				cur := r.waitStatus(r.w.ID, th.ID, StatusReview)
				if !slices.ContainsFunc(cur.Entries, func(e threadEntry) bool {
					return e.Code == "approval_refused" && strings.Contains(e.Args["reason"], "no longer reviews")
				}) {
					t.Fatal("the thread doesn't say why")
				}
				return
			}
			if d.State != draftSent || d.Approval.By != "maria@example.com" || d.Approval.Via != viaEmail || d.Approval.Member != "m_reviewer" {
				t.Fatalf("maria's approval: %s %+v", d.State, d.Approval)
			}
		})
	}
}
