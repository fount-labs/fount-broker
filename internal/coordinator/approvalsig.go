package coordinator

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Approvals signed by the member's device key (launch-plan decision 27,
// teams.md §5 and §7). An approval in the app carries a token the approving
// device signed, in the shape of a team list: base64url(payload) "."
// base64url(Ed25519 over ApprovalContext ‖ payload). It names what the person
// saw: the draft and the draft_rev, the recipients, the subject, a hash of the
// exact text and each attached file's hash. The coordinator checks it against
// what it is about to send, after any edit the approval makes, and keeps it in
// the send record, the draft and the sign-off record. So "Approved by Dev at
// 14:02" holds up without trusting the coordinator's word for who approved:
// the device's key, listed in the team's admin-signed log, signed it.
//
// An approval by email (sendapproval.go) has no device signature; its record
// says so, with the reply's aligned DKIM domain and its edge id.

const (
	ApprovalVersion = 1
	ApprovalType    = "fount-draft-approval"
	ApprovalContext = "fount-draft-approval-v1\n"
	// approvalSkew and approvalAge bound an approval's iat.
	approvalSkew = 5 * time.Minute
	approvalAge  = time.Hour
)

// ApprovalClaims are a signed approval's payload.
type ApprovalClaims struct {
	V        int    `json:"v"`
	Typ      string `json:"typ"`
	Aud      string `json:"aud"`
	Worker   string `json:"worker"`
	Thread   string `json:"thread"`
	Draft    string `json:"draft"`
	DraftRev int    `json:"draftRev"`
	// To are the recipients, lower-case and sorted.
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	// Text is the SHA-256 of the exact text sent, hex.
	Text string `json:"text"`
	// Files are the attachments sent, in order, each with its SHA-256, hex.
	Files []ApprovedFile `json:"files"`
	Dev   string         `json:"dev"`
	Iat   int64          `json:"iat"`
}

// ApprovedFile is one attachment an approval covers.
type ApprovedFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// SignApproval is Desktop's half: the device signs a, filling in its version,
// type and id. Desktop does the same in Rust; this is the reference, and the
// tests'.
func SignApproval(device ed25519.PrivateKey, a ApprovalClaims) (string, error) {
	a.V, a.Typ, a.Dev = ApprovalVersion, ApprovalType, deviceID(device.Public().(ed25519.PublicKey))
	if a.Files == nil {
		a.Files = []ApprovedFile{}
	}
	if a.To == nil {
		a.To = []string{}
	}
	return signToken(device, ApprovalContext, a)
}

// ErrApproval is a signed approval that doesn't check out.
var ErrApproval = errors.New("the approval isn't signed for this draft")

// approvedAs is what an approval must say: the draft as it will be sent.
type approvedAs struct {
	worker, thread, draft string
	draftRev              int
	to                    []string
	subject, text         string
	files                 []ApprovedFile
}

// verifyApproval checks token: signed by key, the device's, for this
// coordinator, lately, and naming exactly want.
func verifyApproval(token string, key ed25519.PublicKey, device, aud string, want approvedAs, now time.Time) error {
	refuse := func(why string) error { return fmt.Errorf("%w: %s", ErrApproval, why) }
	payload, sig, err := splitToken(token)
	if err != nil {
		return refuse("it is malformed")
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, append([]byte(ApprovalContext), payload...), sig) {
		return refuse("the approving device didn't sign it")
	}
	var a ApprovalClaims
	if err := decodeStrictJSON(payload, &a); err != nil || a.V != ApprovalVersion || a.Typ != ApprovalType {
		return refuse("it is malformed")
	}
	to := slices.Clone(want.to)
	for i := range to {
		to[i] = strings.ToLower(to[i])
	}
	slices.Sort(to)
	switch {
	case a.Aud != aud:
		return refuse("it is for another coordinator")
	case a.Dev != device || a.Dev != deviceID(key):
		return refuse("it names another device")
	case a.Iat > now.Add(approvalSkew).Unix() || a.Iat <= now.Add(-approvalAge).Unix():
		return refuse("it was signed too long ago, or in the future")
	case a.Worker != want.worker || a.Thread != want.thread || a.Draft != want.draft || a.DraftRev != want.draftRev:
		return refuse("it is for another draft or version")
	case !slices.Equal(a.To, to):
		return refuse("its recipients aren't the draft's")
	case a.Subject != want.subject:
		return refuse("its subject isn't the draft's")
	case a.Text != want.text:
		return refuse("its text isn't what would be sent")
	case !slices.Equal(a.Files, want.files):
		return refuse("its attachments aren't what would be sent")
	}
	return nil
}

// deviceKey is the Ed25519 key of a device that reaches a worker: its team
// state's, or the worker's own list's.
func (c *Coordinator) deviceKey(workerID, device string) (ed25519.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	w, ok := c.state.Workers[workerID]
	if !ok {
		return nil, ErrNoWorker
	}
	if w.Team != "" {
		st, err := c.teamState(w.Team)
		if err != nil {
			return nil, err
		}
		if d, m := st.device(device); m != nil {
			return d.Key, nil
		}
	}
	for _, d := range w.Devices {
		if d.ID == device {
			return d.Key, nil
		}
	}
	return nil, ErrNoWorker
}

// memberOf is the member a device acts as on a team worker, or nil.
func (c *Coordinator) memberOf(workerID, device string) *Member {
	c.mu.Lock()
	defer c.mu.Unlock()
	if w, ok := c.state.Workers[workerID]; ok && w.Team != "" {
		if st, err := c.teamState(w.Team); err == nil {
			_, m := st.device(device)
			return m
		}
	}
	return nil
}

// fileHashes are each attachment's SHA-256, hex, by its tree path.
func fileHashes(t *Tree, paths []string) (map[string]string, error) {
	out := map[string]string{}
	for _, p := range paths {
		data, err := t.Read(p)
		if err != nil {
			return nil, err
		}
		out[p] = sha256Hex(data)
	}
	return out, nil
}

// signoffDir keeps the sign-off record of each sent reply, by send id.
const signoffDir = prefixMailRecord + "signoff/"

// signoff is the record a firm keeps for its files (decision 27): who asked,
// who approved, when, how, what was sent, with the files' hashes and the
// approving device's signature.
type signoff struct {
	V         int    `json:"v"`
	Worker    string `json:"worker"`
	Thread    string `json:"thread"`
	Draft     string `json:"draft"`
	DraftRev  int    `json:"draftRev"`
	SendID    string `json:"sendId"`
	MessageID string `json:"messageId"`
	// Bytes is the SHA-256 of the message as sent, hex.
	Bytes string `json:"bytes"`
	// Requesters are the people on the thread the reply answers.
	Requesters []string       `json:"requesters"`
	Reviewer   signoffBy      `json:"reviewer"`
	Via        string         `json:"via"`
	At         time.Time      `json:"at"`
	To         []string       `json:"to"`
	Subject    string         `json:"subject"`
	Text       string         `json:"text"`
	Files      []ApprovedFile `json:"files"`
	// Signature is the approving device's signed approval, for an approval
	// in the app; DKIM and Email an approval by email's.
	Signature string `json:"signature,omitempty"`
	DKIM      string `json:"dkim,omitempty"`
	Email     string `json:"email,omitempty"`
	// Resent is who sent an approved reply again under a new Message-ID.
	Resent *resend `json:"resent,omitempty"`
}

type signoffBy struct {
	Name   string `json:"name"`
	Member string `json:"member,omitempty"`
	Device string `json:"device,omitempty"`
}

// writeSignoff keeps the sign-off record of a reply just approved.
func writeSignoff(t *Tree, th *threadRecord, e *threadEntry, r *sendRecord, a approval) error {
	d := e.Draft
	files := []ApprovedFile{}
	for _, p := range d.Files {
		files = append(files, ApprovedFile{Path: p, SHA256: d.FileHashes[p]})
	}
	s := signoff{
		V: 1, Worker: th.WorkerID, Thread: th.ID, Draft: e.ID, DraftRev: d.DraftRev, SendID: r.ID, MessageID: r.MessageID,
		Bytes: r.Hash, Requesters: slices.Clone(th.Participants), Reviewer: signoffBy{Name: a.By, Member: a.Member, Device: a.Device},
		Via: a.Via, At: a.At, To: d.To, Subject: d.Subject, Text: a.SentTextHash, Files: files,
		Signature: a.Token, DKIM: a.DKIM, Email: a.Email, Resent: a.Resent,
	}
	if s.Requesters == nil {
		s.Requesters = []string{}
	}
	return writeJSON(t, signoffDir+r.ID+".json", s)
}
