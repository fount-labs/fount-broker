package coordinator

import (
	"context"
	"strings"
	"testing"
	"time"
)

// withTeam makes r's worker's account a team of members, as its log would
// reduce to.
func (r *sendRig) withTeam(members ...*Member) {
	r.c.mu.Lock()
	defer r.c.mu.Unlock()
	r.c.state.Teams[r.w.Account] = &Team{ID: r.w.Account, state: &teamState{members: members}}
}

// Security review 2026-11-23, finding 3: a team's admission notice goes to
// the owner and every admin who joined, once each, and to no reviewer or
// invited admin.
func TestATeamNoticeGoesToEveryAdmin(t *testing.T) {
	r := newSendRig(t, modeNotify)
	r.withTeam(
		&Member{ID: "m_owner", Account: "acct_dana", Email: "dana@example.com", Role: RoleAdmin},
		&Member{ID: "m_ann", Account: "acct_ann", Email: "ann@example.com", Role: RoleAdmin},
		&Member{ID: "m_rob", Account: "acct_rob", Email: "rob@example.com", Role: RoleReviewer},
		&Member{ID: "m_ivy", Email: "ivy@example.com", Role: RoleAdmin},
	)
	ctx := context.Background()
	for range 2 {
		if err := r.c.NotifyOwner(ctx, "acct/member_joined/4", noticeMemberJoined, r.w.Account, r.w.ID, time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	r.pass()
	for to, want := range map[string]int{"dana@example.com": 1, "ann@example.com": 1, "rob@example.com": 0, "ivy@example.com": 0} {
		if got := r.send.sentTo(to, "A new device joined Acme"); len(got) != want {
			t.Errorf("%s: %d notices, want %d", to, len(got), want)
		}
	}
	if s := r.c.MailStatus(); s.UnsentNotices != 0 {
		t.Errorf("unsent: %+v", s)
	}
}

// A lapse notice on a team reaches its admins too.
func TestATeamLapseNoticeGoesToEveryAdmin(t *testing.T) {
	r := newSendRig(t, modeNotify)
	r.withTeam(
		&Member{ID: "m_owner", Account: "acct_dana", Email: "dana@example.com", Role: RoleAdmin},
		&Member{ID: "m_ann", Account: "acct_ann", Email: "Ann@Example.com", Role: RoleAdmin},
	)
	if err := r.c.NotifyOwner(context.Background(), "acct/lapsed/1", "lapsed", r.w.Account, r.w.ID, time.Time{}); err != nil {
		t.Fatal(err)
	}
	r.pass()
	for _, to := range []string{"dana@example.com", "ann@example.com"} {
		if got := r.send.sentTo(to, "Acme is paused"); len(got) != 1 {
			t.Errorf("%s: %v", to, got)
		}
	}
}

// A solo account's notices go to its owner alone, as before, even when its
// team lists the owner at another address.
func TestASoloNoticeGoesToTheOwnerAlone(t *testing.T) {
	r := newSendRig(t, modeNotify)
	r.withTeam(&Member{ID: "m_owner", Account: "acct_dana", Email: "dana@work.example.com", Role: RoleAdmin})
	if err := r.c.NotifyOwner(context.Background(), "acct/member_joined/2", noticeMemberJoined, r.w.Account, r.w.ID, time.Time{}); err != nil {
		t.Fatal(err)
	}
	r.pass()
	if got := r.send.sentTo("dana@example.com", "A new device joined Acme"); len(got) != 1 {
		t.Errorf("owner: %v", got)
	}
	if got := r.send.sentTo("dana@work.example.com", "A new device joined Acme"); len(got) != 0 {
		t.Errorf("solo admin address: %v", got)
	}
}

// A notice no one can be sent, as for an account none of whose email agents
// has a mailbox, raises notice_unsent once per key on /control/mail.
func TestANoticeNoOneCanBeSentIsAnAlert(t *testing.T) {
	r := newSendRig(t, modeNotify)
	ctx := context.Background()
	for range 2 {
		if err := r.c.NotifyOwner(ctx, "nobody/member_joined/3", noticeMemberJoined, "nobody", "", time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	s := r.c.MailStatus()
	if s.UnsentNotices != 1 || !strings.HasPrefix(s.LastUnsentNotice, noticeMemberJoined+": ") || s.LastUnsentNoticeAt == nil {
		t.Fatalf("status: %+v", s)
	}
	if strings.Contains(s.LastUnsentNotice, "@") {
		t.Errorf("the alert names an address: %q", s.LastUnsentNotice)
	}
	if err := r.c.NotifyOwner(ctx, "nobody/member_joined/4", noticeMemberJoined, "nobody", "", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if s := r.c.MailStatus(); s.UnsentNotices != 2 {
		t.Fatalf("a second notice: %+v", s)
	}
}
