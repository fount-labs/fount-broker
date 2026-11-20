package mail

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Coordinator generations (fount launch-plan decision 18, edge DESIGN.md §8).
// One coordinator runs at a time. The Cloud vault signs a certificate binding
// a generation number to that coordinator's own Ed25519 key, and moves the
// number on with every restore and upgrade. The coordinator presents it once
// at start (POST /coordinator/generation), enrolls each mailbox under it
// (PUT /coordinator), and from then on names it in Fount-Generation on every
// address-key call, so the edge refuses a stale coordinator's.

// The edge's 409 codes, as typed errors. An *EdgeError carrying one of these
// codes matches it with errors.Is.
var (
	// ErrStaleGeneration: a newer coordinator generation has taken over, or
	// this key isn't the current generation's. This coordinator must stop.
	ErrStaleGeneration = errors.New("mail: a newer coordinator generation has taken over")
	// ErrUnknownGeneration: the edge hasn't seen this generation; present
	// the certificate (AdvanceGeneration) first.
	ErrUnknownGeneration = errors.New("mail: the edge hasn't seen this coordinator generation")
	// ErrGenerationRequired: the mailbox is enrolled and the call named no
	// generation.
	ErrGenerationRequired = errors.New("mail: the mailbox is under a coordinator; name its generation")
	// ErrGenerationConflict: this generation already has another
	// coordinator key.
	ErrGenerationConflict = errors.New("mail: this coordinator generation has another key")
	// ErrNotCoordinated: a coordinator route named a mailbox that isn't
	// enrolled.
	ErrNotCoordinated = errors.New("mail: the mailbox isn't enrolled under a coordinator")
	// ErrSendInDoubt: the edge stopped mid-send and won't send this
	// Message-ID again (POST /send).
	ErrSendInDoubt = errors.New("mail: the send is in doubt")
)

var edgeCodes = map[string]error{
	"stale_generation":    ErrStaleGeneration,
	"unknown_generation":  ErrUnknownGeneration,
	"generation_required": ErrGenerationRequired,
	"generation_conflict": ErrGenerationConflict,
	"not_coordinated":     ErrNotCoordinated,
	"send_in_doubt":       ErrSendInDoubt,
	"invite_limit":        ErrInviteLimit,
	"invite_refused":      ErrInviteRefused,
}

// EdgeError is a Device API call the edge refused. It matches ErrEdge, and
// the typed error for its Code when it has one the coordinator branches on.
type EdgeError struct {
	Method, Path string
	Status       int
	// Code is the edge's machine-readable code, empty when it gave none.
	Code    string
	Message string
}

func (e *EdgeError) Error() string {
	s := fmt.Sprintf("%v: %s %s answered %d: %s", ErrEdge, e.Method, e.Path, e.Status, e.Message)
	if e.Code != "" {
		s += " (" + e.Code + ")"
	}
	return s
}

func (e *EdgeError) Unwrap() []error {
	if typed, ok := edgeCodes[e.Code]; ok {
		return []error{ErrEdge, typed}
	}
	return []error{ErrEdge}
}

func edgeError(method, path string, status int, body []byte) *EdgeError {
	var e struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(body, &e)
	code := e.Code
	if len(code) > 64 {
		code = code[:64]
	}
	return &EdgeError{Method: method, Path: path, Status: status, Code: code, Message: edgeMessage(body)}
}

// Generation is what the coordinator holds of its generation: the number,
// the vault's certificate for it, and the coordinator key the certificate
// names, which signs the coordinator routes.
type Generation struct {
	Number      uint64
	Certificate string
	Key         ed25519.PrivateKey
}

// GenerationSource gives the coordinator its generation. The Cloud vault is
// the real one: it releases the wrapping key with a generation number, moves
// the number on with every restore and upgrade, and signs the certificate
// with the key the edge has as COORDINATOR_AUTHORITY_KEY. DevGenerations
// stands in for it.
type GenerationSource interface {
	Generation(ctx context.Context) (Generation, error)
}

// generationLabel separates the vault's certificate signatures from any other
// use of its key (edge internal/generation).
const generationLabel = "fount-coordinator-generation/v1\n"

// maxCertificate is the edge's limit on a certificate.
const maxCertificate = 1024

// GenerationCertificate is a certificate's payload.
type GenerationCertificate struct {
	Generation     uint64 `json:"generation"`
	CoordinatorKey []byte `json:"coordinator_key"` // Ed25519 public key, 32 bytes
	IssuedAt       int64  `json:"issued_at"`       // unix seconds; informational
}

var ErrBadCertificate = errors.New("mail: bad generation certificate")

// SignGenerationCertificate makes a certificate in the edge's format:
// b64url(json) "." b64url(Ed25519 over the label and the json), by authority.
func SignGenerationCertificate(authority ed25519.PrivateKey, c GenerationCertificate) (string, error) {
	if c.Generation == 0 || len(c.CoordinatorKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: generation must be at least 1 and the key 32 bytes", ErrBadCertificate)
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(authority, append([]byte(generationLabel), payload...))
	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(sig), nil
}

// ReadGenerationCertificate reads a certificate's payload. With authority
// set it also checks the signature; the coordinator, which may not know the
// vault's key, reads only, and the edge verifies.
func ReadGenerationCertificate(cert string, authority ed25519.PublicKey) (GenerationCertificate, error) {
	var c GenerationCertificate
	if len(cert) > maxCertificate {
		return c, fmt.Errorf("%w: over %d bytes", ErrBadCertificate, maxCertificate)
	}
	p, s, ok := strings.Cut(cert, ".")
	if !ok {
		return c, fmt.Errorf("%w: no signature", ErrBadCertificate)
	}
	enc := base64.RawURLEncoding
	payload, err := enc.DecodeString(p)
	if err != nil {
		return c, fmt.Errorf("%w: payload: %v", ErrBadCertificate, err)
	}
	sig, err := enc.DecodeString(s)
	if err != nil {
		return c, fmt.Errorf("%w: signature: %v", ErrBadCertificate, err)
	}
	if authority != nil && !ed25519.Verify(authority, append([]byte(generationLabel), payload...), sig) {
		return c, fmt.Errorf("%w: the signature doesn't verify", ErrBadCertificate)
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, fmt.Errorf("%w: %v", ErrBadCertificate, err)
	}
	if c.Generation == 0 || len(c.CoordinatorKey) != ed25519.PublicKeySize {
		return c, fmt.Errorf("%w: generation must be at least 1 and the key 32 bytes", ErrBadCertificate)
	}
	return c, nil
}

// check is that the certificate names g's number and key.
func (g Generation) check() error {
	if len(g.Key) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: no coordinator key", ErrBadCertificate)
	}
	c, err := ReadGenerationCertificate(g.Certificate, nil)
	if err != nil {
		return err
	}
	if c.Generation != g.Number || !ed25519.PublicKey(c.CoordinatorKey).Equal(g.Key.Public()) {
		return fmt.Errorf("%w: it names generation %d and another key", ErrBadCertificate, c.Generation)
	}
	return nil
}

// KeyID is the coordinator routes' Fount-Key-Id: the hex of the key.
func (g Generation) KeyID() string {
	return hex.EncodeToString(g.Key.Public().(ed25519.PublicKey))
}

// DevGenerations is a GenerationSource for dev and test coordinators: it
// signs certificates with Authority, which a dev edge has as its
// COORDINATOR_AUTHORITY_KEY, and keeps the last number in the file at Path,
// moving it on once per process, as the vault does once per coordinator
// release. The coordinator key is drawn per process.
type DevGenerations struct {
	Authority ed25519.PrivateKey
	Path      string

	once sync.Once
	g    Generation
	err  error
}

func (d *DevGenerations) Generation(context.Context) (Generation, error) {
	d.once.Do(func() { d.g, d.err = d.next() })
	return d.g, d.err
}

func (d *DevGenerations) next() (Generation, error) {
	var last uint64
	data, err := os.ReadFile(d.Path)
	switch {
	case err == nil:
		if last, err = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err != nil {
			return Generation{}, fmt.Errorf("%s: %w", d.Path, err)
		}
	case !errors.Is(err, os.ErrNotExist):
		return Generation{}, err
	}
	n := last + 1
	if err := os.MkdirAll(filepath.Dir(d.Path), 0o700); err != nil {
		return Generation{}, err
	}
	if err := os.WriteFile(d.Path+".tmp", []byte(strconv.FormatUint(n, 10)), 0o600); err != nil {
		return Generation{}, err
	}
	if err := os.Rename(d.Path+".tmp", d.Path); err != nil {
		return Generation{}, err
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return Generation{}, err
	}
	cert, err := SignGenerationCertificate(d.Authority, GenerationCertificate{Generation: n, CoordinatorKey: pub, IssuedAt: time.Now().Unix()})
	if err != nil {
		return Generation{}, err
	}
	return Generation{Number: n, Certificate: cert, Key: priv}, nil
}

// SetGeneration makes every address-key call from now on name g, and the
// coordinator routes sign with its key. It checks that the certificate names
// g's number and key; the edge checks the vault's signature.
func (s *Service) SetGeneration(g Generation) error {
	if err := g.check(); err != nil {
		return err
	}
	s.c.gen.Store(&g)
	return nil
}

// Generation is the generation calls name, 0 before SetGeneration.
func (s *Service) Generation() uint64 { return s.c.generation() }

var ErrNoGeneration = errors.New("mail: the coordinator has no generation")

// coordinatorCall is a call on a coordinator route: signed by the current
// generation's key, Fount-Key-Id its hex, with Fount-Generation.
func (s *Service) coordinatorCall(ctx context.Context, path string, body []byte, limit int64) ([]byte, error) {
	g := s.c.gen.Load()
	if g == nil {
		return nil, ErrNoGeneration
	}
	out, _, err := s.c.do(ctx, "POST", path, "", body, limit, func(h http.Header) {
		sign(h, g.Key, g.KeyID(), "POST", path, body, s.c.now(), g.Number)
	})
	return out, err
}

// AdvanceGeneration presents the certificate (POST /coordinator/generation),
// moving the edge to this generation. A new coordinator calls it once at
// start. ErrStaleGeneration means a newer one has spoken, and
// ErrGenerationConflict that this number has another key.
func (s *Service) AdvanceGeneration(ctx context.Context) error {
	g := s.c.gen.Load()
	if g == nil {
		return ErrNoGeneration
	}
	body, err := json.Marshal(map[string]string{"certificate": g.Certificate})
	if err != nil {
		return err
	}
	data, err := s.coordinatorCall(ctx, "/coordinator/generation", body, maxJSON)
	if err != nil {
		return err
	}
	var out struct {
		Generation uint64 `json:"generation"`
	}
	if err := strictJSON(data, &out); err != nil {
		return err
	}
	if out.Generation != g.Number {
		return fmt.Errorf("%w: POST /coordinator/generation moved the edge to %d, not %d", ErrEdge, out.Generation, g.Number)
	}
	return nil
}

// Enroll puts mailbox under the coordinator's generation (PUT /coordinator,
// signed by its address key). Enrolling again is a no-op at the edge. From
// then on the edge refuses any call on the mailbox without the generation.
func (s *Service) Enroll(ctx context.Context, mailbox string) error {
	k, err := s.keysFor(mailbox)
	if err != nil {
		return err
	}
	g := s.c.gen.Load()
	if g == nil {
		return ErrNoGeneration
	}
	body, err := json.Marshal(map[string]string{"certificate": g.Certificate})
	if err != nil {
		return err
	}
	data, err := s.c.addressPost(ctx, k, "PUT", "/coordinator", body, maxJSON)
	if err != nil {
		return err
	}
	var out struct {
		MailboxID  string `json:"mailbox_id"`
		Generation uint64 `json:"generation"`
	}
	if err := strictJSON(data, &out); err != nil {
		return err
	}
	if out.MailboxID != mailbox || out.Generation != g.Number {
		return fmt.Errorf("%w: PUT /coordinator enrolled %s under %d", ErrEdge, out.MailboxID, out.Generation)
	}
	return nil
}

// Send posts a message for mailbox (POST /send), signed by its address key
// and naming the generation. body is the edge's /send body, built by the
// caller; the answer is the edge's, unread. ErrSendInDoubt is the edge
// refusing to send a Message-ID again after stopping mid-send.
func (s *Service) Send(ctx context.Context, mailbox string, body []byte) (json.RawMessage, error) {
	k, err := s.keysFor(mailbox)
	if err != nil {
		return nil, err
	}
	if len(body) > MaxSendBody || !json.Valid(body) {
		return nil, fmt.Errorf("%w: a send body is JSON of at most %d bytes", ErrRequest, MaxSendBody)
	}
	return s.c.addressPost(ctx, k, "POST", "/send", body, maxJSON)
}

// The edge's codes for a refused invite (POST /coordinator/invite).
var (
	// ErrInviteLimit: the worker's invites for the day are spent.
	ErrInviteLimit = errors.New("mail: the worker's invite limit for the day is reached")
	// ErrInviteRefused: the message isn't an invite's shape: one recipient,
	// plain text, small.
	ErrInviteRefused = errors.New("mail: the edge refused the invite")
)

// SendInvite posts a team invite from mailbox (POST /coordinator/invite,
// decision 26): signed by the current generation's key, not the address
// key, which is what lets the edge send it to someone who isn't an owner.
// raw is the whole message; the answer is the edge's, as for Send. The
// edge records it as the worker's, so SentQuery finds it.
func (s *Service) SendInvite(ctx context.Context, mailbox string, raw []byte) (json.RawMessage, error) {
	if !validHex(mailbox, 32) || len(raw) == 0 {
		return nil, fmt.Errorf("%w: a mailbox is 64 lowercase hex characters and an invite a message", ErrRequest)
	}
	body, err := json.Marshal(struct {
		MailboxID string `json:"mailbox_id"`
		Message   []byte `json:"message"`
	}{mailbox, raw})
	if err != nil {
		return nil, err
	}
	if len(body) > MaxSendBody {
		return nil, fmt.Errorf("%w: an invite body is at most %d bytes", ErrRequest, MaxSendBody)
	}
	return s.coordinatorCall(ctx, "/coordinator/invite", body, maxJSON)
}

// SentRecord is one answer of POST /sent/query.
type SentRecord struct {
	MessageID string `json:"message_id"`
	// State is none, in_progress, in_doubt, retryable or done.
	State     string `json:"state"`
	SHA256    string `json:"sha256"`
	FirstAt   int64  `json:"first_at"`
	UpdatedAt int64  `json:"updated_at"`
	Results   []struct {
		Recipient string `json:"recipient"`
		Status    string `json:"status"`
		Detail    string `json:"detail"`
	} `json:"results"`
}

// SentQuery asks whether mailbox sent each Message-ID (POST /sent/query, 1
// to 100), from the edge's durable send records, in the order asked.
func (s *Service) SentQuery(ctx context.Context, mailbox string, messageIDs []string) ([]SentRecord, error) {
	k, err := s.keysFor(mailbox)
	if err != nil {
		return nil, err
	}
	if len(messageIDs) == 0 || len(messageIDs) > 100 {
		return nil, fmt.Errorf("%w: ask about 1 to 100 Message-IDs", ErrRequest)
	}
	body, err := json.Marshal(map[string][]string{"message_ids": messageIDs})
	if err != nil {
		return nil, err
	}
	data, err := s.c.addressPost(ctx, k, "POST", "/sent/query", body, maxJSON)
	if err != nil {
		return nil, err
	}
	var out struct {
		Records []SentRecord `json:"records"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("%w: POST /sent/query: %v", ErrEdge, err)
	}
	if len(out.Records) != len(messageIDs) {
		return nil, fmt.Errorf("%w: POST /sent/query answered %d records for %d ids", ErrEdge, len(out.Records), len(messageIDs))
	}
	return out.Records, nil
}

// Change is one enrolled mailbox in the changes feed: its record changed at
// routing version Changed (new mail moves Sequence; pause, lapse, keys,
// owners, entitlement and enrollment are changes too).
type Change struct {
	MailboxID string `json:"mailbox_id"`
	Changed   uint64 `json:"changed"`
	Sequence  uint64 `json:"sequence"`
	Paused    bool   `json:"paused"`
	Lapsed    bool   `json:"lapsed"`
}

// ChangesPage is one page of POST /coordinator/changes.
type ChangesPage struct {
	Changes []Change `json:"changes"`
	// Cursor is the one to ask from next; More says another page is
	// waiting now. Reset says the edge didn't know the cursor asked from
	// (empty, from before a restore, or ahead of it) and listed from the
	// start.
	Cursor string `json:"cursor"`
	More   bool   `json:"more"`
	Reset  bool   `json:"reset"`
}

const (
	maxChangesLimit = 1000
	maxCursor       = 64
	// maxChangesBody bounds one page: a page may run past its limit when
	// one write changed many mailboxes.
	maxChangesBody = 16 << 20
)

// Changes reads one page of the edge's changes feed after cursor (empty for
// the start), across every mailbox enrolled under the coordinator: POST
// /coordinator/changes, signed by the generation's key. limit is 1 to 1000,
// or 0 for the edge's default.
func (s *Service) Changes(ctx context.Context, cursor string, limit int) (ChangesPage, error) {
	if limit < 0 || limit > maxChangesLimit || len(cursor) > maxCursor {
		return ChangesPage{}, fmt.Errorf("%w: a changes limit is 0 to %d and a cursor at most %d bytes", ErrRequest, maxChangesLimit, maxCursor)
	}
	body, err := json.Marshal(struct {
		Cursor string `json:"cursor"`
		Limit  int    `json:"limit"`
	}{cursor, limit})
	if err != nil {
		return ChangesPage{}, err
	}
	data, err := s.coordinatorCall(ctx, "/coordinator/changes", body, maxChangesBody)
	if err != nil {
		return ChangesPage{}, err
	}
	var page ChangesPage
	if err := strictJSON(data, &page); err != nil {
		return ChangesPage{}, err
	}
	if page.Cursor == "" || len(page.Cursor) > maxCursor {
		return ChangesPage{}, fmt.Errorf("%w: the changes feed answered cursor %q", ErrEdge, page.Cursor)
	}
	for _, c := range page.Changes {
		if !validHex(c.MailboxID, 32) {
			return ChangesPage{}, fmt.Errorf("%w: the changes feed named mailbox %q", ErrEdge, c.MailboxID)
		}
	}
	return page, nil
}

// SigningKeyLabel prefixes what a new address signing key signs to prove it
// is held (edge internal/deviceapi SigningKeyProof).
const SigningKeyLabel = "fount-mail-edge/v1/signing-key\x00"

// RotateSigningKey replaces an enrolled worker's address signing key at the
// edge with next's (decision 25, POST /coordinator/signing-key): next signs
// the proof, the current generation's key the call. From the edge's next
// request on, the old key gets 401. The edge answers 409 for the current key
// again, which a retry after a lost answer meets: AlreadyCurrent reports it.
func (s *Service) RotateSigningKey(ctx context.Context, mailbox string, next ed25519.PrivateKey) error {
	if !validHex(mailbox, 32) || len(next) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: a mailbox is 64 lowercase hex characters and a key Ed25519", ErrRequest)
	}
	id, _ := hex.DecodeString(mailbox)
	pub := next.Public().(ed25519.PublicKey)
	proof := ed25519.Sign(next, append(append([]byte(SigningKeyLabel), id...), pub...))
	body, err := json.Marshal(map[string]string{
		"mailbox_id":  mailbox,
		"signing_key": base64.StdEncoding.EncodeToString(pub),
		"proof":       base64.StdEncoding.EncodeToString(proof),
	})
	if err != nil {
		return err
	}
	data, err := s.coordinatorCall(ctx, "/coordinator/signing-key", body, maxJSON)
	if err != nil {
		return err
	}
	var out struct {
		MailboxID string `json:"mailbox_id"`
		KeySHA256 string `json:"signing_key_sha256"`
	}
	if err := strictJSON(data, &out); err != nil {
		return err
	}
	sum := sha256.Sum256(pub)
	if out.MailboxID != mailbox || out.KeySHA256 != hex.EncodeToString(sum[:]) {
		return fmt.Errorf("%w: POST /coordinator/signing-key answered %s", ErrEdge, out.MailboxID)
	}
	return nil
}

// AlreadyCurrent says err is the edge refusing a rotation to the key it
// already has: a retry whose first answer was lost.
func AlreadyCurrent(err error) bool {
	var e *EdgeError
	return errors.As(err, &e) && e.Status == http.StatusConflict && e.Code == "" &&
		(strings.Contains(e.Message, "already the mailbox's signing key") || strings.Contains(e.Message, "already the mailbox's decryption key"))
}

// LapseState is POST /coordinator/lapse's answer.
type LapseState struct {
	Lapsed bool
	// HoldUntil is when the edge stops holding the worker's mail and
	// bounces it: the entitlement's expiry plus 30 days. Zero when the
	// entitlement has no expiry, or when not lapsed.
	HoldUntil time.Time
}

// Lapse pauses or resumes an enrolled worker for a lapsed payment (decision
// 11, POST /coordinator/lapse): while lapsed it can't send, and the edge holds
// its mail instead of bouncing it, until HoldUntil. ErrNotCoordinated is a
// mailbox that isn't enrolled.
func (s *Service) Lapse(ctx context.Context, mailbox string, lapsed bool) (LapseState, error) {
	if !validHex(mailbox, 32) {
		return LapseState{}, fmt.Errorf("%w: mailbox must be 64 lowercase hex characters", ErrRequest)
	}
	body, err := json.Marshal(struct {
		MailboxID string `json:"mailbox_id"`
		Lapsed    bool   `json:"lapsed"`
	}{mailbox, lapsed})
	if err != nil {
		return LapseState{}, err
	}
	data, err := s.coordinatorCall(ctx, "/coordinator/lapse", body, maxJSON)
	if err != nil {
		return LapseState{}, err
	}
	var out struct {
		MailboxID string `json:"mailbox_id"`
		Lapsed    bool   `json:"lapsed"`
		HoldUntil int64  `json:"hold_until"`
	}
	if err := strictJSON(data, &out); err != nil {
		return LapseState{}, err
	}
	if out.MailboxID != mailbox || out.Lapsed != lapsed {
		return LapseState{}, fmt.Errorf("%w: POST /coordinator/lapse answered %s lapsed=%t", ErrEdge, out.MailboxID, out.Lapsed)
	}
	st := LapseState{Lapsed: out.Lapsed}
	if out.HoldUntil > 0 {
		st.HoldUntil = time.Unix(out.HoldUntil, 0).UTC()
	}
	return st, nil
}

// RotateDecryptionKey replaces an enrolled worker's X25519 decryption key at
// the edge with next's public key (security review 2026-11-19, M1; POST
// /coordinator/decryption-key), signed by the current generation's key. Mail
// the edge stores from then on is sealed to next; mail already stored stays
// sealed to the old key, which the caller keeps in Keys.Older. A retry after
// a lost answer meets the edge's 409 for the current key: AlreadyCurrent
// reports it.
func (s *Service) RotateDecryptionKey(ctx context.Context, mailbox string, next *ecdh.PrivateKey) error {
	if !validHex(mailbox, 32) || next == nil || next.Curve() != ecdh.X25519() {
		return fmt.Errorf("%w: a mailbox is 64 lowercase hex characters and a key X25519", ErrRequest)
	}
	pub := next.PublicKey().Bytes()
	body, err := json.Marshal(map[string]string{
		"mailbox_id":     mailbox,
		"decryption_key": base64.StdEncoding.EncodeToString(pub),
	})
	if err != nil {
		return err
	}
	data, err := s.coordinatorCall(ctx, "/coordinator/decryption-key", body, maxJSON)
	if err != nil {
		return err
	}
	var out struct {
		MailboxID string `json:"mailbox_id"`
		KeySHA256 string `json:"decryption_key_sha256"`
	}
	if err := strictJSON(data, &out); err != nil {
		return err
	}
	sum := sha256.Sum256(pub)
	if out.MailboxID != mailbox || out.KeySHA256 != hex.EncodeToString(sum[:]) {
		return fmt.Errorf("%w: POST /coordinator/decryption-key answered %s", ErrEdge, out.MailboxID)
	}
	return nil
}

// RoutingProof is a connect reply the coordinator saw, which proves an owner
// on POST /coordinator/routing as on PUT /routing.
type RoutingProof struct {
	Owner     string `json:"owner"`
	MessageID string `json:"messageId"`
}

// SetRouting writes an enrolled worker's owner list at version (security
// review 2026-11-19, H1; POST /coordinator/routing), signed by the current
// generation's key: PUT /routing's rule, limits and connect proofs, which the
// edge no longer takes from a device for an enrolled mailbox. The version must
// not go backwards; the stored version again with the same list succeeds and
// changes nothing, so a retry after a lost answer is safe. StaleRouting reports
// a version the edge refused, ProofRefused a connect proof it didn't take, and
// an *EdgeError with status 429 the day's new-owner limit.
func (s *Service) SetRouting(ctx context.Context, mailbox string, version uint64, owners []string, proofs []RoutingProof) error {
	if !validHex(mailbox, 32) || version == 0 {
		return fmt.Errorf("%w: a mailbox is 64 lowercase hex characters and a routing version at least 1", ErrRequest)
	}
	if owners == nil {
		owners = []string{}
	}
	body, err := json.Marshal(struct {
		MailboxID string         `json:"mailbox_id"`
		Version   uint64         `json:"version"`
		Owners    []string       `json:"owners"`
		Proofs    []RoutingProof `json:"proofs,omitempty"`
	}{mailbox, version, owners, proofs})
	if err != nil {
		return err
	}
	data, err := s.coordinatorCall(ctx, "/coordinator/routing", body, maxJSON)
	if err != nil {
		return err
	}
	var out struct {
		Version uint64 `json:"version"`
		Owners  int    `json:"owners"`
	}
	if err := strictJSON(data, &out); err != nil {
		return err
	}
	if out.Version != version || out.Owners != len(owners) {
		return fmt.Errorf("%w: POST /coordinator/routing answered version %d with %d owners", ErrEdge, out.Version, out.Owners)
	}
	return nil
}

// StaleRouting says err is the edge refusing a routing version: lower than
// the one it holds, or the one it holds with a different list.
func StaleRouting(err error) bool {
	var e *EdgeError
	return errors.As(err, &e) && e.Status == http.StatusConflict && e.Code == "" && strings.Contains(e.Message, "routing version did not advance")
}

// OwnerLimit says err is the edge refusing a routing write that would pass
// the license's daily new-owner cap.
func OwnerLimit(err error) bool {
	var e *EdgeError
	return errors.As(err, &e) && e.Status == http.StatusTooManyRequests
}

// ProofRefused says err is the edge refusing a routing write's connect
// proofs: one didn't verify, had expired, or named no owner in the list.
func ProofRefused(err error) bool {
	var e *EdgeError
	return errors.As(err, &e) && e.Status == http.StatusUnprocessableEntity
}

// SetPaused pauses or resumes an enrolled worker (security review 2026-11-19,
// H1; POST /coordinator/pause), signed by the current generation's key: the
// worker's own pause, which POST /pause sets with a passkey for a worker that
// isn't enrolled, apart from the lapse pause. ErrNotCoordinated is a mailbox
// that isn't enrolled.
func (s *Service) SetPaused(ctx context.Context, mailbox string, paused bool) error {
	if !validHex(mailbox, 32) {
		return fmt.Errorf("%w: mailbox must be 64 lowercase hex characters", ErrRequest)
	}
	body, err := json.Marshal(struct {
		MailboxID string `json:"mailbox_id"`
		Paused    bool   `json:"paused"`
	}{mailbox, paused})
	if err != nil {
		return err
	}
	data, err := s.coordinatorCall(ctx, "/coordinator/pause", body, maxJSON)
	if err != nil {
		return err
	}
	var out struct {
		MailboxID string `json:"mailbox_id"`
		Paused    bool   `json:"paused"`
	}
	if err := strictJSON(data, &out); err != nil {
		return err
	}
	if out.MailboxID != mailbox || out.Paused != paused {
		return fmt.Errorf("%w: POST /coordinator/pause answered %s paused=%t", ErrEdge, out.MailboxID, out.Paused)
	}
	return nil
}
