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
