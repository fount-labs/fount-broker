package coordinator

import (
	"crypto/rand"
	"encoding/hex"
	"slices"
	"strings"
	"time"
)

// A received email on a thread is one entry, kind "mail": the edge's id for
// it, who the edge's check says sent it, and what was decided. Its text isn't
// here: the coordinator parses no email, and the intake runner (C) makes the
// message's text for the thread. Mail that may not run by itself waits on its
// thread, held, for runHeldMail or addRequester (mailops.go).
type mailEntry struct {
	EdgeID     string `json:"edgeId"`
	ReceivedAt int64  `json:"receivedAt"`
	Sender     string `json:"sender"`
	SenderName string `json:"senderName,omitempty"`
	// Signed is the aligned DKIM domain the edge found, or empty; CheckError
	// says the edge couldn't check the sender at all.
	Signed     string `json:"signed,omitempty"`
	CheckError bool   `json:"checkError,omitempty"`
	// Verdict and Reason are message-format.md §6.3's, as decide words them.
	Verdict string `json:"verdict"`
	Reason  string `json:"reason,omitempty"`
	// Held is "held" while it waits for someone, then "run" or "added".
	// Empty for mail that ran by itself or needs nothing.
	Held string `json:"held,omitempty"`
	// Intake is "pending" from when it was run until its intake is queued,
	// then "queued" (intake.go). JobID is that job's.
	Intake string `json:"intake,omitempty"`
	JobID  string `json:"jobId,omitempty"`
}

const (
	heldWaiting = "held"
	heldRun     = "run"
	heldAdded   = "added"

	intakePending = "pending"
	intakeQueued  = "queued"

	// verdictThreadReply is a requester on the thread answering it with its
	// token (message-format.md §6.3), which gets a turn.
	verdictThreadReply = "thread_reply"

	maxSubjectChars = 200
)

func (th *threadRecord) intakePending() bool {
	return slices.ContainsFunc(th.Entries, func(e threadEntry) bool {
		return e.Kind == entryMail && e.Mail.Intake == intakePending
	})
}

func (th *threadRecord) holding() bool {
	return slices.ContainsFunc(th.Entries, func(e threadEntry) bool {
		return e.Kind == entryMail && e.Mail.Held == heldWaiting
	})
}

func (th *threadRecord) hasParticipant(address string) bool {
	return slices.ContainsFunc(th.Participants, func(p string) bool { return strings.EqualFold(p, address) })
}

func (th *threadRecord) entry(id string) *threadEntry {
	for i := range th.Entries {
		if th.Entries[i].ID == id {
			return &th.Entries[i]
		}
	}
	return nil
}

// mailOn is the mail entry for edgeID on th.
func (th *threadRecord) mailOn(edgeID string) *threadEntry {
	for i := range th.Entries {
		if e := &th.Entries[i]; e.Kind == entryMail && e.Mail.EdgeID == edgeID {
			return e
		}
	}
	return nil
}

// newMailThread is a thread an email starts. Its subject is the one the
// edge's check read from the signed headers.
func newMailThread(workerID, subject string, now time.Time) (*threadRecord, error) {
	id, err := newID("thr")
	if err != nil {
		return nil, err
	}
	session, err := newID("ses")
	if err != nil {
		return nil, err
	}
	subject = strings.Join(strings.Fields(subject), " ")
	if subject == "" {
		subject = "(no subject)"
	}
	return &threadRecord{
		Schema: threadSchema, ID: id, WorkerID: workerID, Origin: "mail", SessionID: session,
		Subject: cut(subject, maxSubjectChars), CreatedAt: now, Status: StatusIdle, Entries: []threadEntry{}, Jobs: []threadJob{},
	}, nil
}

// handles maps each reply-token handle to its thread.
type handles map[string]string

func loadHandles(t *Tree) (handles, error) {
	h := handles{}
	if _, err := readJSON(t, mailHandlesPath, &h); err != nil {
		return nil, err
	}
	return h, nil
}

// threadHandle gives th a reply-token handle if it has none, and stages the
// index. Sending (D) mints the token from it (mail.MintReplyToken).
func threadHandle(t *Tree, th *threadRecord) (string, error) {
	if th.Handle != "" {
		return th.Handle, nil
	}
	h, err := loadHandles(t)
	if err != nil {
		return "", err
	}
	for {
		var b [5]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		handle := hex.EncodeToString(b[:])
		if _, taken := h[handle]; taken {
			continue
		}
		h[handle], th.Handle = th.ID, handle
		return handle, writeJSON(t, mailHandlesPath, h)
	}
}

// The display form of a mail entry is Desktop's mail-in (view.rs), with an
// empty text until intake reads the message.

type namedAddress struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

type senderCheckView struct {
	Kind   string `json:"kind"`
	Domain string `json:"domain,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type verdictView struct {
	Kind   string `json:"kind"`
	Reason string `json:"reason,omitempty"`
}

type mailInView struct {
	entryHead
	From    namedAddress    `json:"from"`
	Text    string          `json:"text"`
	Check   senderCheckView `json:"check"`
	Verdict verdictView     `json:"verdict"`
	Held    bool            `json:"held,omitempty"`
	// HeldState is what became of held mail: "held", "run" or "added".
	HeldState string `json:"heldState,omitempty"`
}

func mailIn(head entryHead, e threadEntry) mailInView {
	head.Kind = "mail-in"
	m := e.Mail
	v := mailInView{
		entryHead: head, From: namedAddress{Name: m.SenderName, Address: m.Sender},
		Held: m.Held == heldWaiting, HeldState: m.Held,
	}
	switch {
	case m.CheckError:
		v.Check = senderCheckView{Kind: "unchecked", Reason: "Fount couldn't check the sender"}
	case m.Signed != "":
		v.Check = senderCheckView{Kind: "signed", Domain: m.Signed}
	default:
		v.Check = senderCheckView{Kind: "unsigned"}
	}
	switch m.Verdict {
	case "request", verdictThreadReply:
		v.Verdict = verdictView{Kind: "request"}
	case "context":
		v.Verdict = verdictView{Kind: "context"}
	default:
		v.Verdict = verdictView{Kind: m.Verdict, Reason: m.Reason}
	}
	if m.Held == heldWaiting && v.Verdict.Kind == "request" {
		// A request that couldn't run by itself waits as held mail.
		v.Verdict = verdictView{Kind: "held", Reason: m.Reason}
	}
	return v
}

type participantView struct {
	Address string `json:"address"`
	Role    string `json:"role"`
}

func (th *threadRecord) participantViews() []any {
	out := []any{}
	for _, p := range th.Participants {
		out = append(out, participantView{Address: p, Role: "requester"})
	}
	return out
}
