package decide

import (
	"encoding/json"
	"strings"
	"testing"
)

// Ported from Desktop's src-tauri/src/workers/verdict/tests.rs.

const worker = "ap.smithcpa@fountbox.com"

func newWorker(rs ...Requester) Worker { return Worker{Address: worker, Requesters: rs} }

func checkJSON(t *testing.T, from string, to, cc []string, hash string, edit func(map[string]any)) json.RawMessage {
	t.Helper()
	domain := from[strings.LastIndex(from, "@")+1:]
	sig := map[string]any{"domain": domain, "selector": "s", "algorithm": "rsa-sha256", "result": "pass",
		"headers": []string{}, "body_length": false, "testing": false, "covers": true, "hash": hash, "aligned": true}
	c := map[string]any{
		"from":              map[string]any{"address": from, "domain": domain},
		"dkim":              []any{sig},
		"aligned":           true,
		"recipient_signed":  true,
		"date_skew_seconds": -30,
		"headers":           map[string]any{"to": to, "cc": cc, "subject": "Q3"},
	}
	if edit != nil {
		edit(c)
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func received(id string, at int64, c json.RawMessage) Received {
	return Received{ID: id, Sequence: 1, ReceivedAt: at, BootAttested: true, EnvelopeSender: "dana@example.com", SenderCheck: c}
}

func verdictOf(w Worker, r Received) Decision {
	return Decide(w, r, "", FirstSigners([]Received{r}))
}

var dana = Requester{Address: "dana@example.com", DKIMDomain: "example.com", AutoRun: true}

func TestARequestersSignedMailToTheWorkerIsARequest(t *testing.T) {
	r := received("a", 1, checkJSON(t, "Dana@example.com", []string{worker}, nil, "h1", nil))
	d := verdictOf(newWorker(dana), r)
	if d.Verdict != Request || d.SignatureHash != "h1" {
		t.Fatalf("%+v", d)
	}
}

func TestAWorkerWithNoRequestersHoldsEverything(t *testing.T) {
	r := received("a", 1, checkJSON(t, "dana@example.com", []string{worker}, nil, "h1", nil))
	if d := verdictOf(newWorker(), r); d.Verdict != Held {
		t.Fatalf("%+v", d)
	}
}

func TestCopiesBlindCopiesAndWeakPairingsDontRun(t *testing.T) {
	w := newWorker(dana)
	cases := []struct {
		name string
		w    Worker
		r    Received
		want Verdict
	}{
		{"cc", w, received("a", 1, checkJSON(t, "dana@example.com", []string{"x@example.com"}, []string{worker}, "h1", nil)), Context},
		{"bcc", w, received("b", 1, checkJSON(t, "dana@example.com", []string{"x@example.com"}, nil, "h2", nil)), NeedsConfirmation},
		{"confirm each job", newWorker(Requester{Address: "dana@example.com", DKIMDomain: "example.com"}),
			received("c", 1, checkJSON(t, "dana@example.com", []string{worker}, nil, "h3", nil)), NeedsConfirmation},
		{"no dkim at pairing", newWorker(Requester{Address: "dana@example.com", AutoRun: true}),
			received("c", 1, checkJSON(t, "dana@example.com", []string{worker}, nil, "h3", nil)), NeedsConfirmation},
	}
	for _, c := range cases {
		if d := verdictOf(c.w, c.r); d.Verdict != c.want {
			t.Errorf("%s: %+v, want %s", c.name, d, c.want)
		}
	}
}

func TestUnsignedStaleOrUnattestedMailNeedsConfirming(t *testing.T) {
	w := newWorker(dana)
	unsigned := received("a", 1, checkJSON(t, "dana@example.com", []string{worker}, nil, "h1", func(c map[string]any) {
		c["dkim"].([]any)[0].(map[string]any)["aligned"] = false
	}))
	stale := received("b", 1, checkJSON(t, "dana@example.com", []string{worker}, nil, "h2", func(c map[string]any) {
		c["date_skew_seconds"] = -(MaxDateAgeSecs + 1)
	}))
	ahead := received("d", 1, checkJSON(t, "dana@example.com", []string{worker}, nil, "h4", func(c map[string]any) {
		c["date_skew_seconds"] = MaxDateAheadSecs + 1
	}))
	undated := received("e", 1, checkJSON(t, "dana@example.com", []string{worker}, nil, "h5", func(c map[string]any) {
		delete(c, "date_skew_seconds")
	}))
	unattested := received("c", 1, checkJSON(t, "dana@example.com", []string{worker}, nil, "h3", nil))
	unattested.BootAttested = false
	for name, r := range map[string]Received{"unsigned": unsigned, "stale": stale, "ahead": ahead, "undated": undated, "unattested": unattested} {
		if d := verdictOf(w, r); d.Verdict != NeedsConfirmation {
			t.Errorf("%s: %+v", name, d)
		}
	}
}

func TestAutomaticMailBouncesAndReplaysAreIgnored(t *testing.T) {
	w := newWorker(dana)
	r := received("a", 1, checkJSON(t, "dana@example.com", []string{worker}, nil, "h1", nil))
	auto := Decide(w, r, "Auto-Submitted: auto-replied", FirstSigners([]Received{r}))
	if auto.Verdict != Ignored || !strings.Contains(auto.Reason, "auto-replied") {
		t.Fatalf("auto: %+v", auto)
	}

	bounce := r
	bounce.EnvelopeSender = ""
	if d := verdictOf(w, bounce); d.Verdict != Ignored {
		t.Fatalf("bounce: %+v", d)
	}

	again := received("b", 2, checkJSON(t, "dana@example.com", []string{worker}, nil, "h1", nil))
	first := FirstSigners([]Received{again, r})
	if d := Decide(w, r, "", first); d.Verdict != Request {
		t.Fatalf("first: %+v", d)
	}
	if d := Decide(w, again, "", first); d.Verdict != Ignored {
		t.Fatalf("replay: %+v", d)
	}
}

func TestUncheckedMailIsHeld(t *testing.T) {
	w := newWorker(dana)
	r := received("a", 1, checkJSON(t, "dana@example.com", []string{worker}, nil, "h1", nil))
	r.SenderCheckError = "timeout"
	if d := verdictOf(w, r); d.Verdict != Held {
		t.Fatalf("%+v", d)
	}
	r.SenderCheckError = ""
	r.Quarantined = true
	if d := verdictOf(w, r); d.Verdict != Held {
		t.Fatalf("%+v", d)
	}
	r.Quarantined = false
	r.SenderCheck = json.RawMessage(`{"date_skew_seconds":"soon"}`)
	if d := verdictOf(w, r); d.Verdict != Held {
		t.Fatalf("malformed: %+v", d)
	}
}
