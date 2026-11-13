package mail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"
)

// Ops the app may ask for. Each names one mailbox by its hex id.
const (
	OpList    = "list"    // GET /mail
	OpGet     = "get"     // GET /mail/{id}, verified, decrypted and sender-checked
	OpDelete  = "delete"  // DELETE /mail/{id}
	OpGaps    = "gaps"    // GET /gaps, verified, and the ledger's view of what's missing
	OpLedger  = "ledger"  // the mailbox's ledger, for the app to save
	OpRestore = "restore" // body: a ledger the app saved earlier
	// OpReplyToken mints a thread's reply token from the address's key. Path:
	// the thread handle, 10 lowercase hex characters. It contacts no edge.
	OpReplyToken = "reply_token"
)

var Ops = []string{OpList, OpGet, OpDelete, OpGaps, OpLedger, OpRestore, OpReplyToken}

var (
	// ErrRequest is a request the mail route doesn't allow.
	ErrRequest = errors.New("mail: bad request")
	// ErrNoKeys means the app hasn't given the broker this mailbox's keys.
	ErrNoKeys = errors.New("mail: no keys for this mailbox")
)

// MaxFailures is how many times the sender check may fail on one message
// before the message is quarantined (design §6, "bad messages").
const MaxFailures = 3

// Checker runs the offline sender verifier on one decrypted message.
type Checker interface {
	Check(ctx context.Context, in CheckInput) (json.RawMessage, error)
}

// CheckInput is what the verifier gets: the message and the edge's facts about
// it, never a key.
type CheckInput struct {
	Raw        []byte    `json:"-"`
	Sender     string    `json:"sender"`
	Recipient  string    `json:"recipient"`
	ReceivedAt time.Time `json:"received_at"`
	// ClientIP, ClientIPSource and HELO are Envelope's, as the edge sealed them.
	ClientIP       string `json:"client_ip,omitempty"`
	ClientIPSource string `json:"client_ip_source,omitempty"`
	HELO           string `json:"helo,omitempty"`
}

type Service struct {
	c       client
	checker Checker
	keys    keyring
	boots   boots

	mu       sync.Mutex
	ledgers  map[string]*Ledger
	pending  map[string]map[string]bool // mailbox -> listed edge ids not yet fetched
	failures map[string]int             // edge id -> failed sender checks
}

func New(edge Edge, checker Checker) *Service {
	return &Service{
		c:        client{edge: edge, now: time.Now},
		checker:  checker,
		boots:    boots{keys: map[string]BootKey{}},
		ledgers:  map[string]*Ledger{},
		pending:  map[string]map[string]bool{},
		failures: map[string]int{},
	}
}

// SetKeys replaces every address's keys with a mail_keys credential.
func (s *Service) SetKeys(body []byte) error {
	k, err := ParseKeys(body)
	if err != nil {
		return err
	}
	s.keys.set(k)
	return nil
}

// Handle runs one op. path is the edge id for get and delete, the thread
// handle for reply_token, and empty otherwise; body is the saved ledger for restore, and empty otherwise.
func (s *Service) Handle(ctx context.Context, op, mailbox, path string, body []byte) (any, error) {
	if !slices.Contains(Ops, op) {
		return nil, fmt.Errorf("%w: unknown op %q", ErrRequest, op)
	}
	if !validHex(mailbox, 32) {
		return nil, fmt.Errorf("%w: mailbox must be 64 lowercase hex characters", ErrRequest)
	}
	if op == OpReplyToken {
		if !validHex(path, replyHandleLen) || len(body) > 0 {
			return nil, fmt.Errorf("%w: reply_token takes a 10-hex-character thread handle as its path and no body", ErrRequest)
		}
	} else if takesID := op == OpGet || op == OpDelete; takesID != (path != "") || takesID && !validHex(path, 16) {
		return nil, fmt.Errorf("%w: %s takes %s", ErrRequest, op, map[bool]string{true: "a 32-hex-character edge id as its path", false: "no path"}[takesID])
	}
	if (op == OpRestore) != (len(body) > 0) {
		return nil, fmt.Errorf("%w: only restore takes a body", ErrRequest)
	}
	k, ok := s.keys.get(mailbox)
	if !ok {
		return nil, ErrNoKeys
	}
	switch op {
	case OpReplyToken:
		tok, err := MintReplyToken(k, path)
		if err != nil {
			return nil, err
		}
		return map[string]string{"token": tok}, nil
	case OpList:
		return s.list(ctx, k, mailbox)
	case OpGet:
		return s.get(ctx, k, mailbox, path)
	case OpDelete:
		if err := s.c.delete(ctx, k, path); err != nil {
			return nil, err
		}
		s.mu.Lock()
		delete(s.pending[mailbox], path)
		delete(s.failures, path)
		s.mu.Unlock()
		return map[string]bool{"ok": true}, nil
	case OpGaps:
		return s.gaps(ctx, k, mailbox)
	case OpLedger:
		s.mu.Lock()
		defer s.mu.Unlock()
		return cloneLedger(s.ledger(mailbox)), nil
	default:
		var saved Ledger
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&saved); err != nil || dec.More() {
			return nil, fmt.Errorf("%w: restore body is not a ledger", ErrRequest)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		l := s.ledger(mailbox)
		l.merge(&saved)
		return summarize(l, len(s.pending[mailbox])), nil
	}
}

// ledger returns mailbox's ledger. s.mu must be held.
func (s *Service) ledger(mailbox string) *Ledger {
	l := s.ledgers[mailbox]
	if l == nil {
		l = newLedger()
		s.ledgers[mailbox] = l
	}
	return l
}

func cloneLedger(l *Ledger) *Ledger {
	return &Ledger{Delivered: maps.Clone(l.Delivered), Accounted: maps.Clone(l.Accounted), Anomalies: slices.Clone(l.Anomalies)}
}

func (s *Service) list(ctx context.Context, k *Keys, mailbox string) (any, error) {
	l, err := s.c.list(ctx, k)
	if err != nil {
		return nil, err
	}
	msgs := l.Messages
	s.mu.Lock()
	defer s.mu.Unlock()
	delivered := map[string]bool{}
	for _, id := range s.ledger(mailbox).Delivered {
		delivered[id] = true
	}
	p := map[string]bool{}
	for _, m := range msgs {
		if !delivered[m.ID] {
			p[m.ID] = true
		}
	}
	s.pending[mailbox] = p
	out := map[string]any{"messages": msgs}
	if l.Paused != nil {
		out["paused"] = *l.Paused
	}
	return out, nil
}

// Message is one verified, decrypted message with its sender check.
type Message struct {
	ID         string   `json:"id"`
	Mailbox    string   `json:"mailbox"`
	Sequence   uint64   `json:"sequence"`
	ReceivedAt int64    `json:"received_at"` // unix ms, the edge's clock
	Boot       string   `json:"boot"`
	Envelope   Envelope `json:"envelope"`
	Raw        []byte   `json:"raw"`
	// BootAttested is false when the signing key came only from S3 (design §9).
	BootAttested bool `json:"boot_attested"`
	// Reused is true when this message's sequence already belonged to another
	// message or record. The ledger holds the anomaly.
	Reused bool `json:"reused"`

	SenderCheck      json.RawMessage `json:"sender_check,omitempty"`
	SenderCheckError string          `json:"sender_check_error,omitempty"`
	// Quarantined is true once the sender check has failed MaxFailures times.
	// The app holds the message and shows it; it never counts as a request.
	Quarantined bool `json:"quarantined"`
	// ReplyToken is the envelope recipient's +tag, checked against this
	// address's key. Absent when the recipient has no tag.
	ReplyToken *ReplyToken `json:"reply_token,omitempty"`

	Ledger Summary `json:"ledger"`
}

func (s *Service) get(ctx context.Context, k *Keys, mailbox, id string) (any, error) {
	raw, err := s.c.get(ctx, k, id)
	if err != nil {
		return nil, err
	}
	o, err := ParseObject(raw)
	if err != nil {
		return nil, err
	}
	if hexOf(o.EdgeID) != id {
		return nil, fmt.Errorf("%w: GET /mail/%s returned message %s", ErrMalformed, id, hexOf(o.EdgeID))
	}
	bk, err := s.c.bootKey(ctx, &s.boots, hexOf(o.BootID))
	if err != nil {
		return nil, err
	}
	if err := o.Verify(bk.Key); err != nil {
		return nil, err
	}
	opened, err := o.Open(k)
	env, body := opened.Envelope, opened.Raw
	if errors.Is(err, ErrWrongKey) {
		s.mu.Lock()
		s.ledger(mailbox).anomaly(Anomaly{Kind: AnomalyWrongKey, Sequence: o.Sequence, Detail: fmt.Sprintf("message %s is sealed to public key hash %s", id, hexOf(o.PubKeyHash))})
		s.mu.Unlock()
	}
	if err != nil {
		return nil, err
	}
	m := &Message{
		ID: id, Mailbox: mailbox, Sequence: o.Sequence, ReceivedAt: o.ReceivedAt.UnixMilli(),
		Boot: hexOf(o.BootID), Envelope: env, Raw: body, BootAttested: bk.Attested,
		ReplyToken: CheckReplyToken(k, env.Recipient),
	}

	s.mu.Lock()
	m.Reused = !s.ledger(mailbox).Deliver(o.Sequence, id)
	delete(s.pending[mailbox], id)
	failures := s.failures[id]
	s.mu.Unlock()

	if o.Version >= objV3 {
		// The edge checked the sender when the message arrived (EdgeCheck).
		if _, err := DecodeEdgeCheck(opened.Check, body); err != nil {
			m.SenderCheckError = err.Error()
		} else {
			m.SenderCheck = json.RawMessage(opened.Check)
		}
	} else if failures >= MaxFailures {
		m.Quarantined = true
	} else if v, err := s.checker.Check(ctx, CheckInput{
		Raw: body, Sender: env.Sender, Recipient: env.Recipient, ReceivedAt: o.ReceivedAt,
		ClientIP: env.ClientIP, ClientIPSource: env.ClientIPSource, HELO: env.HELO,
	}); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		s.mu.Lock()
		s.failures[id]++
		m.Quarantined = s.failures[id] >= MaxFailures
		s.mu.Unlock()
		m.SenderCheckError = err.Error()
	} else {
		m.SenderCheck = v
	}

	s.mu.Lock()
	m.Ledger = summarize(s.ledger(mailbox), len(s.pending[mailbox]))
	s.mu.Unlock()
	return m, nil
}

// Summary is the ledger's verdict after a call.
type Summary struct {
	Floor uint64 `json:"floor"`
	High  uint64 `json:"high"`
	// Missing are numbers below High with neither a message nor a record. They
	// are withheld mail only when Complete: until every listed message has been
	// fetched, a missing number may just be a message not read yet.
	Missing   []uint64  `json:"missing"`
	Complete  bool      `json:"complete"`
	Pending   int       `json:"pending"`
	Anomalies []Anomaly `json:"anomalies"`
}

const maxMissing = 1024

func summarize(l *Ledger, pending int) Summary {
	return Summary{
		Floor: l.Floor(), High: l.High(), Missing: l.Missing(maxMissing),
		Complete: pending == 0, Pending: pending, Anomalies: slices.Clone(l.Anomalies),
	}
}

// VerifiedRecord is a gap record whose signature checked out.
type VerifiedRecord struct {
	GapRecord
	BootAttested bool `json:"boot_attested"`
	// MessageBootKnown is false when the edge has no boot record for the boot
	// the record says signed the message. Design §9: the broker must check that
	// boot before trusting an expiry.
	MessageBootKnown bool `json:"message_boot_known"`
}

type GapsResult struct {
	Records []VerifiedRecord `json:"records"`
	Ledger  Summary          `json:"ledger"`
}

// maxGapPages bounds one gaps call: 256 pages of 256 records.
const maxGapPages = 256

func (s *Service) gaps(ctx context.Context, k *Keys, mailbox string) (any, error) {
	s.mu.Lock()
	after := s.ledger(mailbox).Floor()
	s.mu.Unlock()
	res := GapsResult{Records: []VerifiedRecord{}}
	for range maxGapPages {
		page, err := s.c.gaps(ctx, k, after)
		if err != nil {
			return nil, err
		}
		for _, tok := range page {
			vr, seq, err := s.verifyRecord(ctx, mailbox, tok)
			if err != nil {
				return nil, err
			}
			if seq <= after {
				return nil, fmt.Errorf("%w: GET /gaps?after=%d returned sequence %d", ErrEdge, after, seq)
			}
			after = seq
			if vr != nil {
				res.Records = append(res.Records, *vr)
			}
		}
		if len(page) < maxGapsPage {
			break
		}
	}
	s.mu.Lock()
	res.Ledger = summarize(s.ledger(mailbox), len(s.pending[mailbox]))
	s.mu.Unlock()
	return res, nil
}

// verifyRecord checks one record and returns it with its sequence. A record
// that is well formed and signed but isn't this mailbox's becomes an anomaly
// and comes back nil.
func (s *Service) verifyRecord(ctx context.Context, mailbox, tok string) (*VerifiedRecord, uint64, error) {
	bootID, err := RecordBoot(tok)
	if err != nil {
		return nil, 0, err
	}
	bk, err := s.c.bootKey(ctx, &s.boots, bootID)
	if err != nil {
		return nil, 0, err
	}
	rec, err := ParseRecord(tok, bk.Key)
	if err != nil {
		return nil, 0, err
	}
	if rec.MailboxID != mailbox {
		s.mu.Lock()
		s.ledger(mailbox).anomaly(Anomaly{Kind: AnomalyBadRecord, Sequence: rec.Sequence, Detail: "GET /gaps returned a record for mailbox " + rec.MailboxID})
		s.mu.Unlock()
		return nil, rec.Sequence, nil
	}
	vr := &VerifiedRecord{GapRecord: rec, BootAttested: bk.Attested}
	switch _, err := s.c.bootKey(ctx, &s.boots, rec.MessageBoot); {
	case err == nil:
		vr.MessageBootKnown = true
	case !errors.Is(err, ErrNotFound):
		return nil, 0, err
	}
	s.mu.Lock()
	s.ledger(mailbox).Account(rec)
	s.mu.Unlock()
	return vr, rec.Sequence, nil
}
