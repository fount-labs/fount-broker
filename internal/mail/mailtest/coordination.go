package mailtest

import (
	"bufio"
	"bytes"
	"cmp"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/textproto"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Coordination is the edge's coordinator side (fount-mail-edge DESIGN.md §8)
// for fake edges: the current generation and its key, which mailboxes are
// enrolled, the lapse hold and the changes feed. It checks signatures the
// way the edge's guard does, its canonical string written here apart from
// package mail's, and holds an enrolled mailbox's calls to the generation
// fence, so a test catches a call that doesn't name it.
type Coordination struct {
	authority ed25519.PublicKey

	mu        sync.Mutex
	gen       uint64
	key       ed25519.PublicKey
	epoch     string
	version   uint64
	mailboxes map[string]*CoordinatedMailbox
	nonces    map[string]bool
	// calls is every coordinator route called and fence refusal, in order.
	calls []string
	// invites counts each mailbox's invites taken, against InvitesPerDay.
	invites map[string]int
	// noDecryptionRoute answers POST /coordinator/decryption-key 404, as an
	// edge from before it.
	noDecryptionRoute bool
	// refuseProofs answers a POST /coordinator/routing with proofs 422, as
	// the edge does for an expired connect reply.
	refuseProofs bool
	// newOwnerLimit caps the owners a mailbox's lists may ever add (the
	// edge's daily cap, never refilled here); 0 is no cap. added counts
	// each mailbox's, by address.
	newOwnerLimit int
	added         map[string]map[string]bool

	// OnInvite sends an invite the fake took (POST /coordinator/invite):
	// the fake edge's send path, which answers it and keeps its sent
	// record under mailbox. nil answers 501, as an edge with sending off.
	OnInvite func(w http.ResponseWriter, mailbox string, message []byte)
}

// InvitesPerDay is the edge's per-worker invite budget (send.InvitesPerDay).
// The fake never refills it.
const InvitesPerDay = 20

// CoordinatedMailbox is what the fake keeps of one mailbox.
type CoordinatedMailbox struct {
	Enrolled  bool
	Paused    bool
	Lapsed    bool
	HoldUntil int64
	Sequence  uint64
	Changed   uint64
	// SigningKey is the address signing key a rotation set, nil before one.
	SigningKey ed25519.PublicKey
	// DecryptionKey is the X25519 public key a rotation set, nil before one.
	DecryptionKey []byte
	// Owners and RoutingVersion are the owner list POST /coordinator/routing
	// wrote last, and Proved the owners a connect proof proved.
	Owners         []string
	RoutingVersion uint64
	Proved         []string
}

func NewCoordination(authority ed25519.PublicKey) *Coordination {
	return &Coordination{authority: authority, epoch: randomHex(8), mailboxes: map[string]*CoordinatedMailbox{}, nonces: map[string]bool{}, invites: map[string]int{}}
}

// Refusal is an answer the fake gives instead of serving a call.
type Refusal struct {
	Status int
	Code   string
	Msg    string
}

func (r *Refusal) Write(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(r.Status)
	body := map[string]string{"error": r.Msg}
	if r.Code != "" {
		body["code"] = r.Code
	}
	json.NewEncoder(w).Encode(body)
}

func refuse(status int, code, msg string) *Refusal { return &Refusal{status, code, msg} }

// canonical is the edge's deviceapi canonicalString.
func canonical(method, path string, body []byte, ts int64, nonce, gen string) string {
	sum := sha256.Sum256(body)
	s := fmt.Sprintf("%s\n%s\n%s\n%d\n%s", method, path, hex.EncodeToString(sum[:]), ts, nonce)
	if gen != "" {
		s += "\n" + gen
	}
	return s
}

// verify checks the timestamp, nonce and signature against pub. c.mu held.
func (c *Coordination) verify(r *http.Request, body []byte, pub ed25519.PublicKey) *Refusal {
	ts, err := strconv.ParseInt(r.Header.Get("Fount-Timestamp"), 10, 64)
	if err != nil || time.Since(time.Unix(ts, 0)).Abs() > 5*time.Minute {
		return refuse(http.StatusUnauthorized, "", "timestamp outside window")
	}
	nonce := r.Header.Get("Fount-Nonce")
	if nonce == "" || len(nonce) > 128 || c.nonces[nonce] {
		return refuse(http.StatusUnauthorized, "", "nonce")
	}
	gen := r.Header.Get("Fount-Generation")
	if gen != "" {
		if _, err := strconv.ParseUint(gen, 10, 64); err != nil {
			return refuse(http.StatusUnauthorized, "", "bad Fount-Generation")
		}
	}
	sig, err := base64.StdEncoding.DecodeString(r.Header.Get("Fount-Signature"))
	if err != nil || !ed25519.Verify(pub, []byte(canonical(r.Method, r.URL.Path, body, ts, nonce, gen)), sig) {
		return refuse(http.StatusUnauthorized, "", "signature does not verify")
	}
	c.nonces[nonce] = true
	return nil
}

// Address checks a call signed by mailbox's address key pub: the signature,
// and for an enrolled mailbox, the generation fence. Fount-Key-Id must be
// the mailbox. PUT /coordinator isn't fenced, as the edge's isn't.
func (c *Coordination) Address(r *http.Request, body []byte, mailbox string, pub ed25519.PublicKey) *Refusal {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r.Header.Get("Fount-Key-Id") != mailbox {
		return refuse(http.StatusUnauthorized, "", "unknown address key")
	}
	if m := c.mailboxes[mailbox]; m != nil && m.SigningKey != nil {
		pub = m.SigningKey
	}
	if ref := c.verify(r, body, pub); ref != nil {
		return ref
	}
	m := c.mailboxes[mailbox]
	if m == nil || !m.Enrolled || r.Method+" "+r.URL.Path == "PUT /coordinator" {
		return nil
	}
	v := r.Header.Get("Fount-Generation")
	n, _ := strconv.ParseUint(v, 10, 64)
	var ref *Refusal
	switch {
	case v == "":
		ref = refuse(http.StatusConflict, "generation_required", "this mailbox is under a coordinator; name its generation in Fount-Generation")
	case n < c.gen:
		ref = refuse(http.StatusConflict, "stale_generation", "a newer coordinator generation has taken over")
	case n > c.gen:
		ref = refuse(http.StatusConflict, "unknown_generation", "the edge hasn't seen this generation")
	}
	if ref != nil {
		c.calls = append(c.calls, "fenced "+r.Method+" "+r.URL.Path+": "+ref.Code)
	}
	return ref
}

// certificate reads and verifies a {"certificate"} body.
func (c *Coordination) certificate(body []byte) (uint64, ed25519.PublicKey, *Refusal) {
	var req struct {
		Certificate string `json:"certificate"`
	}
	if json.Unmarshal(body, &req) != nil {
		return 0, nil, refuse(http.StatusBadRequest, "", "bad request body")
	}
	p, s, ok := strings.Cut(req.Certificate, ".")
	enc := base64.RawURLEncoding
	payload, err1 := enc.DecodeString(p)
	sig, err2 := enc.DecodeString(s)
	if !ok || err1 != nil || err2 != nil || !ed25519.Verify(c.authority, append([]byte("fount-coordinator-generation/v1\n"), payload...), sig) {
		return 0, nil, refuse(http.StatusForbidden, "", "generation certificate does not verify")
	}
	var cert struct {
		Generation uint64 `json:"generation"`
		Key        []byte `json:"coordinator_key"`
		IssuedAt   int64  `json:"issued_at"`
	}
	if json.Unmarshal(payload, &cert) != nil || cert.Generation == 0 || len(cert.Key) != ed25519.PublicKeySize {
		return 0, nil, refuse(http.StatusForbidden, "", "generation certificate does not verify")
	}
	return cert.Generation, cert.Key, nil
}

// advance moves the edge to gen under key. c.mu held.
func (c *Coordination) advance(gen uint64, key ed25519.PublicKey) *Refusal {
	switch {
	case gen < c.gen:
		return refuse(http.StatusConflict, "stale_generation", "a newer coordinator generation has taken over")
	case gen == c.gen && !key.Equal(c.key):
		return refuse(http.StatusConflict, "generation_conflict", "this generation already has another coordinator key")
	case gen > c.gen:
		c.gen, c.key = gen, key
		c.version++
	}
	return nil
}

// Serve answers the coordinator routes: PUT /coordinator (with addressKey,
// the mailbox's address key, or nil when the fake doesn't know it),
// POST /coordinator/generation, /coordinator/lapse, /coordinator/changes,
// /coordinator/routing, /coordinator/pause and the rotations and invite.
// It returns false for any other path.
func (c *Coordination) Serve(w http.ResponseWriter, r *http.Request, body []byte, addressKey func(mailbox string) ed25519.PublicKey) bool {
	route := r.Method + " " + r.URL.Path
	switch route {
	case "PUT /coordinator":
		mailbox := r.Header.Get("Fount-Key-Id")
		pub := addressKey(mailbox)
		if pub == nil {
			refuse(http.StatusUnauthorized, "", "unknown address key").Write(w)
			return true
		}
		if ref := c.Address(r, body, mailbox, pub); ref != nil {
			ref.Write(w)
			return true
		}
		gen, key, ref := c.certificate(body)
		if ref != nil {
			ref.Write(w)
			return true
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		c.calls = append(c.calls, route+" "+mailbox)
		if ref := c.advance(gen, key); ref != nil {
			ref.Write(w)
			return true
		}
		m := c.box(mailbox)
		if !m.Enrolled {
			m.Enrolled = true
			c.touch(m)
		}
		json.NewEncoder(w).Encode(map[string]any{"mailbox_id": mailbox, "generation": c.gen})
	case "POST /coordinator/generation":
		gen, key, ref := c.certificate(body)
		if ref != nil {
			ref.Write(w)
			return true
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		c.calls = append(c.calls, route)
		if r.Header.Get("Fount-Key-Id") != hex.EncodeToString(key) {
			refuse(http.StatusUnauthorized, "", "the key id isn't the certificate's key").Write(w)
			return true
		}
		if ref := c.verify(r, body, key); ref != nil {
			ref.Write(w)
			return true
		}
		if ref := c.advance(gen, key); ref != nil {
			ref.Write(w)
			return true
		}
		json.NewEncoder(w).Encode(map[string]uint64{"generation": c.gen})
	case "POST /coordinator/lapse", "POST /coordinator/changes", "POST /coordinator/signing-key", "POST /coordinator/decryption-key", "POST /coordinator/invite",
		"POST /coordinator/routing", "POST /coordinator/pause":
		c.mu.Lock()
		defer c.mu.Unlock()
		c.calls = append(c.calls, route)
		key, err := hex.DecodeString(r.Header.Get("Fount-Key-Id"))
		if err != nil || len(key) != ed25519.PublicKeySize {
			refuse(http.StatusUnauthorized, "", "coordinator key id").Write(w)
			return true
		}
		if ref := c.verify(r, body, key); ref != nil {
			ref.Write(w)
			return true
		}
		if c.key == nil || !c.key.Equal(ed25519.PublicKey(key)) {
			refuse(http.StatusConflict, "stale_generation", "a newer coordinator generation has taken over").Write(w)
			return true
		}
		switch route {
		case "POST /coordinator/lapse":
			c.lapse(w, body)
		case "POST /coordinator/routing":
			c.routing(w, body)
		case "POST /coordinator/pause":
			c.pause(w, body)
		case "POST /coordinator/signing-key":
			c.rotate(w, body, addressKey)
		case "POST /coordinator/decryption-key":
			if c.noDecryptionRoute {
				refuse(http.StatusNotFound, "", "not found").Write(w)
				return true
			}
			c.rotateDecryption(w, body)
		case "POST /coordinator/invite":
			mailbox, message, ref := c.invite(body)
			if ref != nil {
				ref.Write(w)
				return true
			}
			if c.OnInvite == nil {
				refuse(http.StatusNotImplemented, "", "sending is off").Write(w)
				return true
			}
			// The sink keeps its own lock, and may read c.
			c.mu.Unlock()
			c.OnInvite(w, mailbox, message)
			c.mu.Lock()
		default:
			c.changes(w, body)
		}
	default:
		return false
	}
	return true
}

func (c *Coordination) lapse(w http.ResponseWriter, body []byte) {
	var req struct {
		MailboxID string `json:"mailbox_id"`
		Lapsed    *bool  `json:"lapsed"`
	}
	if json.Unmarshal(body, &req) != nil || req.Lapsed == nil {
		refuse(http.StatusBadRequest, "", "bad request body").Write(w)
		return
	}
	m := c.mailboxes[req.MailboxID]
	if m == nil || !m.Enrolled {
		refuse(http.StatusConflict, "not_coordinated", "the mailbox isn't enrolled").Write(w)
		return
	}
	if m.Lapsed != *req.Lapsed {
		m.Lapsed = *req.Lapsed
		m.HoldUntil = 0
		if m.Lapsed {
			m.HoldUntil = time.Now().Add(30 * 24 * time.Hour).Unix()
		}
		c.touch(m)
	}
	json.NewEncoder(w).Encode(map[string]any{"mailbox_id": req.MailboxID, "lapsed": m.Lapsed, "hold_until": m.HoldUntil})
}

// routing is POST /coordinator/routing: the edge's version rule (never
// backwards; the stored version again only with the same list) and limits.
// c.mu held.
func (c *Coordination) routing(w http.ResponseWriter, body []byte) {
	var req struct {
		MailboxID string   `json:"mailbox_id"`
		Version   uint64   `json:"version"`
		Owners    []string `json:"owners"`
		Proofs    []struct {
			Owner     string `json:"owner"`
			MessageID string `json:"messageId"`
		} `json:"proofs"`
	}
	if json.Unmarshal(body, &req) != nil {
		refuse(http.StatusBadRequest, "", "bad request body").Write(w)
		return
	}
	if _, err := hex.DecodeString(req.MailboxID); err != nil || len(req.MailboxID) != 64 {
		refuse(http.StatusBadRequest, "", "bad mailbox id").Write(w)
		return
	}
	m := c.mailboxes[req.MailboxID]
	if m == nil || !m.Enrolled {
		refuse(http.StatusConflict, "not_coordinated", "this mailbox is not under a coordinator").Write(w)
		return
	}
	if req.Version == 0 {
		refuse(http.StatusBadRequest, "", "version must be >= 1").Write(w)
		return
	}
	if len(req.Owners) > 64 {
		refuse(http.StatusBadRequest, "", "too many owners").Write(w)
		return
	}
	var proved []string
	for _, p := range req.Proofs {
		if c.refuseProofs || p.MessageID == "" || !slices.Contains(req.Owners, p.Owner) {
			refuse(http.StatusUnprocessableEntity, "", "connect proof invalid or expired").Write(w)
			return
		}
		proved = append(proved, p.Owner)
	}
	if req.Version < m.RoutingVersion || req.Version == m.RoutingVersion && !slices.Equal(req.Owners, m.Owners) {
		refuse(http.StatusConflict, "", "routing version did not advance").Write(w)
		return
	}
	if c.newOwnerLimit > 0 && req.Version > m.RoutingVersion {
		seen := c.added[req.MailboxID]
		n := len(seen)
		for _, o := range req.Owners {
			if !seen[o] && !slices.Contains(m.Owners, o) {
				n++
			}
		}
		if n > c.newOwnerLimit {
			refuse(http.StatusTooManyRequests, "", "new-owner limit reached, retry later").Write(w)
			return
		}
		if seen == nil {
			seen = map[string]bool{}
			c.added[req.MailboxID] = seen
		}
		for _, o := range req.Owners {
			if !slices.Contains(m.Owners, o) {
				seen[o] = true
			}
		}
	}
	if req.Version > m.RoutingVersion {
		m.Owners, m.RoutingVersion = slices.Clone(req.Owners), req.Version
		m.Proved = append(m.Proved, proved...)
		c.touch(m)
	}
	json.NewEncoder(w).Encode(map[string]any{"version": req.Version, "owners": len(req.Owners)})
}

// pause is POST /coordinator/pause: the worker's own pause. c.mu held.
func (c *Coordination) pause(w http.ResponseWriter, body []byte) {
	var req struct {
		MailboxID string `json:"mailbox_id"`
		Paused    *bool  `json:"paused"`
	}
	if json.Unmarshal(body, &req) != nil || req.Paused == nil {
		refuse(http.StatusBadRequest, "", "bad request body").Write(w)
		return
	}
	m := c.mailboxes[req.MailboxID]
	if m == nil || !m.Enrolled {
		refuse(http.StatusConflict, "not_coordinated", "this mailbox is not under a coordinator").Write(w)
		return
	}
	if m.Paused != *req.Paused {
		m.Paused = *req.Paused
		c.touch(m)
	}
	json.NewEncoder(w).Encode(map[string]any{"mailbox_id": req.MailboxID, "paused": m.Paused})
}

// RefuseProofs makes the fake refuse every connect proof on POST
// /coordinator/routing, as the edge does once they expire, or not.
func (c *Coordination) RefuseProofs(refuse bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refuseProofs = refuse
}

// LimitNewOwners refuses, 429, a routing write that would take a mailbox's
// added owners past n, counted from now.
func (c *Coordination) LimitNewOwners(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.newOwnerLimit, c.added = n, map[string]map[string]bool{}
}

// SetRouting sets mailbox's owner list and version directly, as a device's
// PUT /routing before it was enrolled would have.
func (c *Coordination) SetRouting(mailbox string, version uint64, owners []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := c.box(mailbox)
	m.Owners, m.RoutingVersion = slices.Clone(owners), version
	c.touch(m)
}

// rotate is POST /coordinator/signing-key: the new key must prove it's held
// and differ from the current one, which addressKey or an earlier rotation
// gives.
func (c *Coordination) rotate(w http.ResponseWriter, body []byte, addressKey func(string) ed25519.PublicKey) {
	var req struct {
		MailboxID  string `json:"mailbox_id"`
		SigningKey string `json:"signing_key"`
		Proof      string `json:"proof"`
	}
	if json.Unmarshal(body, &req) != nil {
		refuse(http.StatusBadRequest, "", "bad request body").Write(w)
		return
	}
	key, kerr := base64.StdEncoding.DecodeString(req.SigningKey)
	proof, perr := base64.StdEncoding.DecodeString(req.Proof)
	id, ierr := hex.DecodeString(req.MailboxID)
	if kerr != nil || perr != nil || ierr != nil || len(key) != ed25519.PublicKeySize {
		refuse(http.StatusBadRequest, "", "bad request body").Write(w)
		return
	}
	m := c.mailboxes[req.MailboxID]
	if m == nil || !m.Enrolled {
		refuse(http.StatusConflict, "not_coordinated", "the mailbox isn't enrolled").Write(w)
		return
	}
	msg := append(append([]byte("fount-mail-edge/v1/signing-key\x00"), id...), key...)
	if !ed25519.Verify(key, msg, proof) {
		refuse(http.StatusForbidden, "", "the proof isn't the new key's").Write(w)
		return
	}
	current := m.SigningKey
	if current == nil && addressKey != nil {
		current = addressKey(req.MailboxID)
	}
	if current != nil && current.Equal(ed25519.PublicKey(key)) {
		refuse(http.StatusConflict, "", "routing: that is already the mailbox's signing key").Write(w)
		return
	}
	m.SigningKey = ed25519.PublicKey(key)
	c.touch(m)
	sum := sha256.Sum256(key)
	json.NewEncoder(w).Encode(map[string]string{"mailbox_id": req.MailboxID, "signing_key_sha256": hex.EncodeToString(sum[:])})
}

// WithoutDecryptionRoute makes the fake an edge from before POST
// /coordinator/decryption-key, or not.
func (c *Coordination) WithoutDecryptionRoute(without bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.noDecryptionRoute = without
}

// rotateDecryption is POST /coordinator/decryption-key: a new X25519 key,
// not the one a rotation set last.
func (c *Coordination) rotateDecryption(w http.ResponseWriter, body []byte) {
	var req struct {
		MailboxID     string `json:"mailbox_id"`
		DecryptionKey string `json:"decryption_key"`
	}
	if json.Unmarshal(body, &req) != nil {
		refuse(http.StatusBadRequest, "", "bad request body").Write(w)
		return
	}
	key, err := base64.StdEncoding.DecodeString(req.DecryptionKey)
	if err != nil || len(key) != 32 {
		refuse(http.StatusBadRequest, "", "bad request body").Write(w)
		return
	}
	m := c.mailboxes[req.MailboxID]
	if m == nil || !m.Enrolled {
		refuse(http.StatusConflict, "not_coordinated", "the mailbox isn't enrolled").Write(w)
		return
	}
	if bytes.Equal(m.DecryptionKey, key) {
		refuse(http.StatusConflict, "", "routing: that is already the mailbox's decryption key").Write(w)
		return
	}
	m.DecryptionKey = key
	c.touch(m)
	sum := sha256.Sum256(key)
	json.NewEncoder(w).Encode(map[string]string{"mailbox_id": req.MailboxID, "decryption_key_sha256": hex.EncodeToString(sum[:])})
}

// invite checks POST /coordinator/invite as the edge's send.Policy.CheckInvite
// does: an enrolled worker, one recipient outside its domain, plain text, and
// the day's budget. c.mu held.
func (c *Coordination) invite(body []byte) (string, []byte, *Refusal) {
	var req struct {
		MailboxID string `json:"mailbox_id"`
		Message   []byte `json:"message"`
	}
	if json.Unmarshal(body, &req) != nil || len(req.Message) == 0 {
		return "", nil, refuse(http.StatusBadRequest, "", "bad request body")
	}
	m := c.mailboxes[req.MailboxID]
	if m == nil || !m.Enrolled {
		return "", nil, refuse(http.StatusConflict, "not_coordinated", "the mailbox isn't enrolled")
	}
	h, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(req.Message))).ReadMIMEHeader()
	if err != nil {
		return "", nil, refuse(http.StatusBadRequest, "", "bad message")
	}
	notInvite := refuse(http.StatusBadRequest, "invite_refused", "not an invite")
	from, to := h.Get("From"), h.Values("To")
	if len(to) != 1 || strings.Contains(to[0], ",") || len(h.Values("Cc")) > 0 || len(req.Message) > 64<<10 {
		return "", nil, notInvite
	}
	if at := strings.LastIndexByte(from, '@'); at < 0 || strings.HasSuffix(strings.ToLower(strings.TrimRight(to[0], "> ")), strings.ToLower(strings.TrimRight(from[at:], "> "))) {
		return "", nil, notInvite
	}
	if ct := h.Get("Content-Type"); ct != "" {
		if mt, _, err := mime.ParseMediaType(ct); err != nil || mt != "text/plain" {
			return "", nil, notInvite
		}
	}
	if c.invites[req.MailboxID] >= InvitesPerDay {
		return "", nil, refuse(http.StatusTooManyRequests, "invite_limit", "this worker's invite limit for the day is reached")
	}
	c.invites[req.MailboxID]++
	return req.MailboxID, req.Message, nil
}

func (c *Coordination) changes(w http.ResponseWriter, body []byte) {
	var req struct {
		Cursor string `json:"cursor"`
		Limit  int    `json:"limit"`
	}
	if json.Unmarshal(body, &req) != nil || req.Limit < 0 || req.Limit > 1000 {
		refuse(http.StatusBadRequest, "", "bad request body").Write(w)
		return
	}
	if req.Limit == 0 {
		req.Limit = 500
	}
	var after uint64
	reset := req.Cursor == ""
	if !reset {
		epoch, ver, ok := strings.Cut(req.Cursor, ".")
		n, err := strconv.ParseUint(ver, 10, 64)
		if !ok || err != nil {
			refuse(http.StatusBadRequest, "", "bad cursor").Write(w)
			return
		}
		if after = n; epoch != c.epoch || n > c.version {
			reset, after = true, 0
		}
	}
	type change struct {
		MailboxID string `json:"mailbox_id"`
		Changed   uint64 `json:"changed"`
		Sequence  uint64 `json:"sequence"`
		Paused    bool   `json:"paused"`
		Lapsed    bool   `json:"lapsed"`
	}
	var all []change
	for id, m := range c.mailboxes {
		if m.Enrolled && (reset || m.Changed > after) {
			all = append(all, change{id, m.Changed, m.Sequence, m.Paused, m.Lapsed})
		}
	}
	slices.SortFunc(all, func(a, b change) int {
		return cmp.Or(cmp.Compare(a.Changed, b.Changed), strings.Compare(a.MailboxID, b.MailboxID))
	})
	out := []change{}
	cursor, more := c.cursor(c.version), false
	for i, ch := range all {
		if i >= req.Limit && ch.Changed != all[i-1].Changed {
			more, cursor = true, c.cursor(all[i-1].Changed)
			break
		}
		out = append(out, ch)
	}
	json.NewEncoder(w).Encode(map[string]any{"changes": out, "cursor": cursor, "more": more, "reset": reset})
}

func (c *Coordination) cursor(v uint64) string { return c.epoch + "." + strconv.FormatUint(v, 10) }

// box is mailbox's record, made on first use. c.mu held.
func (c *Coordination) box(mailbox string) *CoordinatedMailbox {
	m := c.mailboxes[mailbox]
	if m == nil {
		m = &CoordinatedMailbox{}
		c.mailboxes[mailbox] = m
	}
	return m
}

// touch is a write that changed m. c.mu held.
func (c *Coordination) touch(m *CoordinatedMailbox) {
	c.version++
	m.Changed = c.version
}

// Arrived records new mail for mailbox, up to sequence: a change the feed
// lists once the mailbox is enrolled.
func (c *Coordination) Arrived(mailbox string, sequence uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := c.box(mailbox)
	m.Sequence = sequence
	c.touch(m)
}

// Restore is the edge's routing object restored from backup: a new epoch, so
// every cursor from before it is reset.
func (c *Coordination) Restore() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.epoch = randomHex(8)
}

// Mailbox is a copy of what the fake keeps of mailbox.
func (c *Coordination) Mailbox(mailbox string) CoordinatedMailbox {
	c.mu.Lock()
	defer c.mu.Unlock()
	if m := c.mailboxes[mailbox]; m != nil {
		return *m
	}
	return CoordinatedMailbox{}
}

// Generation is the edge's current generation.
func (c *Coordination) Generation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen
}

// Enroll enrolls mailbox under the current generation directly, as another
// coordinator would have.
func (c *Coordination) Enroll(mailbox string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen == 0 {
		return errors.New("mailtest: no generation yet")
	}
	m := c.box(mailbox)
	m.Enrolled = true
	c.touch(m)
	return nil
}

// Advance moves the edge to gen under key, as a newer coordinator would.
func (c *Coordination) Advance(gen uint64, key ed25519.PublicKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.advance(gen, key)
}

// Calls is every coordinator route called, and every call the fence
// refused, in order.
func (c *Coordination) Calls() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.calls)
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// UseInvites spends n of mailbox's invites for the day, as earlier invites
// would have.
func (c *Coordination) UseInvites(mailbox string, n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.invites[mailbox] += n
}
