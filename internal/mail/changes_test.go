package mail

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestChangesFeedPagesAndResets(t *testing.T) {
	s, f, _, v := newService(t)
	ctx := context.Background()
	if _, err := s.Changes(ctx, "", 0); !errors.Is(err, ErrNoGeneration) {
		t.Fatalf("no generation: %v", err)
	}
	s.SetGeneration(f.generation(t, 1))
	if err := s.AdvanceGeneration(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Enroll(ctx, v.MailboxID); err != nil {
		t.Fatal(err)
	}
	others := make([]string, 3)
	for i := range others {
		others[i] = strings.Repeat(fmt.Sprintf("%02x", i+1), 32)
		if err := f.coord.Enroll(others[i]); err != nil {
			t.Fatal(err)
		}
	}

	// From the start: a reset, every enrolled mailbox, one a page.
	page, err := s.Changes(ctx, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !page.Reset || !page.More || len(page.Changes) != 1 || page.Changes[0].MailboxID != v.MailboxID {
		t.Fatalf("first page %+v", page)
	}
	seen := []string{page.Changes[0].MailboxID}
	for page.More {
		if page, err = s.Changes(ctx, page.Cursor, 1); err != nil {
			t.Fatal(err)
		}
		if page.Reset {
			t.Fatal("a later page reset")
		}
		for _, c := range page.Changes {
			seen = append(seen, c.MailboxID)
		}
	}
	if want := append([]string{v.MailboxID}, others...); fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Fatalf("pages listed %v, want %v", seen, want)
	}
	cursor := page.Cursor

	// Nothing since: an empty page at the same cursor.
	if page, err = s.Changes(ctx, cursor, 0); err != nil || len(page.Changes) != 0 || page.More || page.Reset || page.Cursor != cursor {
		t.Fatalf("idle %+v %v", page, err)
	}

	// New mail moves one mailbox, with its sequence.
	f.coord.Arrived(others[1], 9)
	if page, err = s.Changes(ctx, cursor, 0); err != nil || len(page.Changes) != 1 || page.Changes[0].MailboxID != others[1] || page.Changes[0].Sequence != 9 {
		t.Fatalf("after mail %+v %v", page, err)
	}
	cursor = page.Cursor

	// A restore picks a new epoch: the old cursor resets and lists all.
	f.coord.Restore()
	if page, err = s.Changes(ctx, cursor, 0); err != nil || !page.Reset || len(page.Changes) != 4 || page.Cursor == cursor {
		t.Fatalf("after a restore %+v %v", page, err)
	}

	if _, err := s.Changes(ctx, strings.Repeat("a", 65), 0); !errors.Is(err, ErrRequest) {
		t.Fatalf("long cursor: %v", err)
	}
	if _, err := s.Changes(ctx, "", 1001); !errors.Is(err, ErrRequest) {
		t.Fatalf("big limit: %v", err)
	}
}

func TestChangesFeedRefusesABadPage(t *testing.T) {
	s, f, _, _ := newService(t)
	ctx := context.Background()
	s.SetGeneration(f.generation(t, 1))
	for name, body := range map[string]string{
		"bad mailbox": `{"changes":[{"mailbox_id":"zz","changed":1,"sequence":1,"paused":false,"lapsed":false}],"cursor":"e.1","more":false,"reset":false}`,
		"no cursor":   `{"changes":[],"cursor":"","more":false,"reset":false}`,
		"unknown":     `{"changes":[],"cursor":"e.1","more":false,"reset":false,"extra":1}`,
	} {
		f.override = func(w http.ResponseWriter, r *http.Request) bool {
			w.Write([]byte(body))
			return true
		}
		if _, err := s.Changes(ctx, "", 0); !errors.Is(err, ErrEdge) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestLapse(t *testing.T) {
	s, f, _, v := newService(t)
	ctx := context.Background()
	s.SetGeneration(f.generation(t, 1))
	if err := s.AdvanceGeneration(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lapse(ctx, v.MailboxID, true); !errors.Is(err, ErrNotCoordinated) {
		t.Fatalf("not enrolled: %v", err)
	}
	if err := s.Enroll(ctx, v.MailboxID); err != nil {
		t.Fatal(err)
	}
	st, err := s.Lapse(ctx, v.MailboxID, true)
	if err != nil || !st.Lapsed || st.HoldUntil.IsZero() || !f.coord.Mailbox(v.MailboxID).Lapsed {
		t.Fatalf("%+v %v", st, err)
	}
	l, err := s.List(ctx, v.MailboxID)
	if err != nil {
		t.Fatal(err)
	}
	if l.Lapsed == nil || !*l.Lapsed || l.HoldUntil != st.HoldUntil.Unix() {
		t.Fatalf("listing %+v", l)
	}
	if st, err = s.Lapse(ctx, v.MailboxID, false); err != nil || st.Lapsed || !st.HoldUntil.IsZero() {
		t.Fatalf("resume %+v %v", st, err)
	}
}

func TestSetRouting(t *testing.T) {
	s, f, _, v := newService(t)
	ctx := context.Background()
	s.SetGeneration(f.generation(t, 1))
	if err := s.AdvanceGeneration(ctx); err != nil {
		t.Fatal(err)
	}
	owners := []string{"dana@example.com"}
	if err := s.SetRouting(ctx, v.MailboxID, 1, owners, nil); !errors.Is(err, ErrNotCoordinated) {
		t.Fatalf("not enrolled: %v", err)
	}
	if err := s.Enroll(ctx, v.MailboxID); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRouting(ctx, v.MailboxID, 0, owners, nil); !errors.Is(err, ErrRequest) {
		t.Fatalf("version 0: %v", err)
	}
	proof := []RoutingProof{{Owner: "dana@example.com", MessageID: "<c1@fountbox.com>"}}
	if err := s.SetRouting(ctx, v.MailboxID, 2, owners, proof); err != nil {
		t.Fatal(err)
	}
	if m := f.coord.Mailbox(v.MailboxID); m.RoutingVersion != 2 || fmt.Sprint(m.Owners) != fmt.Sprint(owners) || fmt.Sprint(m.Proved) != fmt.Sprint(owners) {
		t.Fatalf("edge holds %+v", m)
	}
	// The same version and list again is a retry: it succeeds.
	if err := s.SetRouting(ctx, v.MailboxID, 2, owners, nil); err != nil {
		t.Fatalf("retry: %v", err)
	}
	two := []string{"dana@example.com", "lee@client.example"}
	for _, ver := range []uint64{1, 2} {
		if err := s.SetRouting(ctx, v.MailboxID, ver, two, nil); !StaleRouting(err) {
			t.Fatalf("version %d: %v", ver, err)
		}
	}
	f.coord.RefuseProofs(true)
	if err := s.SetRouting(ctx, v.MailboxID, 3, two, []RoutingProof{{Owner: "lee@client.example", MessageID: "<c2@fountbox.com>"}}); !ProofRefused(err) || StaleRouting(err) {
		t.Fatalf("refused proof: %v", err)
	}
	if err := s.SetRouting(ctx, v.MailboxID, 3, two, nil); err != nil {
		t.Fatal(err)
	}
}

func TestSetPaused(t *testing.T) {
	s, f, _, v := newService(t)
	ctx := context.Background()
	s.SetGeneration(f.generation(t, 1))
	if err := s.AdvanceGeneration(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPaused(ctx, v.MailboxID, true); !errors.Is(err, ErrNotCoordinated) {
		t.Fatalf("not enrolled: %v", err)
	}
	if err := s.Enroll(ctx, v.MailboxID); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPaused(ctx, v.MailboxID, true); err != nil || !f.coord.Mailbox(v.MailboxID).Paused {
		t.Fatalf("pause: %v", err)
	}
	if err := s.SetPaused(ctx, v.MailboxID, false); err != nil || f.coord.Mailbox(v.MailboxID).Paused {
		t.Fatalf("resume: %v", err)
	}
	if err := s.SetPaused(ctx, "zz", true); !errors.Is(err, ErrRequest) {
		t.Fatalf("bad mailbox: %v", err)
	}
}
