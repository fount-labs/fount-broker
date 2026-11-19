package coordinator

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fount-labs/fount-broker/internal/mail"
)

// MailSender is the edge's sending side (edge DESIGN.md §8): POST /send and
// POST /sent/query, each signed with the worker's address key. The send
// journal (sendjournal.go) is its only caller.
type MailSender interface {
	// Send posts raw as it is. A refusal is a *SendError.
	Send(ctx context.Context, k *mail.Keys, raw []byte) ([]RecipientResult, error)
	// QuerySent asks what the edge knows of messageID from the worker.
	QuerySent(ctx context.Context, k *mail.Keys, messageID string) (SentRecord, error)
}

// RecipientResult is one recipient's outcome: "sent", "temporary",
// "permanent", or in a sent record "unknown".
type RecipientResult struct {
	Recipient string `json:"recipient"`
	Status    string `json:"status"`
	Detail    string `json:"detail,omitempty"`
}

// SentRecord is the edge's answer for one Message-ID.
type SentRecord struct {
	MessageID string `json:"message_id"`
	// State is none, in_progress, in_doubt, retryable or done.
	State string `json:"state"`
	// SHA256 is hex, of the message as it was posted.
	SHA256    string            `json:"sha256,omitempty"`
	FirstAt   int64             `json:"first_at,omitempty"`
	UpdatedAt int64             `json:"updated_at,omitempty"`
	Results   []RecipientResult `json:"results,omitempty"`
}

const (
	sentNone       = "none"
	sentInProgress = "in_progress"
	sentInDoubt    = "in_doubt"
	sentRetryable  = "retryable"
	sentDone       = "done"

	resultSent      = "sent"
	resultTemporary = "temporary"
	resultPermanent = "permanent"
)

// SendError is the edge refusing a send or a query: its status, its error
// code if it gave one, and how long it asked to wait.
type SendError struct {
	Status     int
	Code       string
	Message    string
	RetryAfter time.Duration
}

func (e *SendError) Error() string {
	return fmt.Sprintf("the mail edge answered %d %s: %s", e.Status, e.Code, e.Message)
}

// EdgeSender is MailSender over the attested edge transport the mail loop
// uses. Generation, when set, is the coordinator generation its calls carry
// (Fount-Generation, decision 18), which the signature then covers too.
//
// internal/mail has no generation header yet: until it does, Generation is
// nil and the calls go out as an address-key client's do.
type EdgeSender struct {
	Edge       mail.Edge
	Generation func() uint64
	Now        func() time.Time
}

func NewEdgeSender(edge mail.Edge) *EdgeSender { return &EdgeSender{Edge: edge} }

const maxSendAnswer = 1 << 20

func (s *EdgeSender) Send(ctx context.Context, k *mail.Keys, raw []byte) ([]RecipientResult, error) {
	body, err := json.Marshal(map[string][]byte{"message": raw})
	if err != nil {
		return nil, err
	}
	if len(body) > mail.MaxSendBody {
		return nil, &SendError{Status: http.StatusRequestEntityTooLarge, Code: "too_large", Message: "the message is over the edge's limit"}
	}
	var out struct {
		Results []RecipientResult `json:"results"`
	}
	if err := s.post(ctx, k, "/send", body, &out); err != nil {
		return nil, err
	}
	return out.Results, nil
}

func (s *EdgeSender) QuerySent(ctx context.Context, k *mail.Keys, messageID string) (SentRecord, error) {
	body, err := json.Marshal(map[string][]string{"message_ids": {messageID}})
	if err != nil {
		return SentRecord{}, err
	}
	var out struct {
		Records []SentRecord `json:"records"`
	}
	if err := s.post(ctx, k, "/sent/query", body, &out); err != nil {
		return SentRecord{}, err
	}
	if len(out.Records) != 1 {
		return SentRecord{}, fmt.Errorf("%w: /sent/query answered %d records for one Message-ID", mail.ErrEdge, len(out.Records))
	}
	return out.Records[0], nil
}

func (s *EdgeSender) post(ctx context.Context, k *mail.Keys, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Edge.Base()+path[1:], bytes.NewReader(body))
	if err != nil {
		return err
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	ts, nonce := now().Unix(), rand.Text()
	canonical := mail.Canonical(http.MethodPost, path, body, ts, nonce)
	if s.Generation != nil {
		g := strconv.FormatUint(s.Generation(), 10)
		req.Header.Set("Fount-Generation", g)
		canonical += "\n" + g
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(mail.HeaderKeyID, hex.EncodeToString(k.MailboxID))
	req.Header.Set(mail.HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(mail.HeaderNonce, nonce)
	req.Header.Set(mail.HeaderSignature, base64.StdEncoding.EncodeToString(ed25519.Sign(k.Signing, []byte(canonical))))
	resp, err := s.Edge.Do(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSendAnswer+1))
	if err != nil {
		return err
	}
	if len(data) > maxSendAnswer {
		return fmt.Errorf("%w: %s answered more than %d bytes", mail.ErrEdge, path, maxSendAnswer)
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		_ = json.Unmarshal(data, &e)
		se := &SendError{Status: resp.StatusCode, Code: e.Code, Message: cut(strings.TrimSpace(e.Error), 300)}
		if secs, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && secs > 0 {
			se.RetryAfter = time.Duration(secs) * time.Second
		}
		return se
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%w: %s: %v", mail.ErrEdge, path, err)
	}
	return nil
}

// asSendError is err as the edge's refusal, or nil for a transport failure,
// after which the edge may or may not have the request.
func asSendError(err error) *SendError {
	var se *SendError
	if errors.As(err, &se) {
		return se
	}
	return nil
}
