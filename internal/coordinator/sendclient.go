package coordinator

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/fount-labs/fount-broker/internal/mail"
)

// MailSender is the edge's sending side (edge DESIGN.md §8): POST /send and
// POST /sent/query, each signed with the worker's address key. The send
// journal (sendjournal.go) is its only caller, and serviceSender the one
// implementation.
type MailSender interface {
	// Send posts raw as it is. A refusal is a *SendError.
	Send(ctx context.Context, k *mail.Keys, raw []byte) ([]RecipientResult, error)
	// SendInvite posts a team invite as it is (POST /coordinator/invite),
	// signed by the coordinator's generation key, so it may go to someone
	// who isn't an owner. A refusal is a *SendError.
	SendInvite(ctx context.Context, k *mail.Keys, raw []byte) ([]RecipientResult, error)
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

// SendError is the edge refusing a send or a query: its status and its
// error code if it gave one.
type SendError struct {
	Status  int
	Code    string
	Message string
}

func (e *SendError) Error() string {
	return fmt.Sprintf("the mail edge answered %d %s: %s", e.Status, e.Code, e.Message)
}

// serviceSender is MailSender over the mail loop's Service, so a send and a
// query are signed like every other address-key call and name the
// coordinator generation (Fount-Generation, decision 18) once it has one.
type serviceSender struct {
	service *mail.Service
}

func (s serviceSender) Send(ctx context.Context, k *mail.Keys, raw []byte) ([]RecipientResult, error) {
	body, err := json.Marshal(map[string][]byte{"message": raw})
	if err != nil {
		return nil, err
	}
	if len(body) > mail.MaxSendBody {
		return nil, &SendError{Status: http.StatusRequestEntityTooLarge, Code: "too_large", Message: "the message is over the edge's limit"}
	}
	data, err := s.service.Send(ctx, s.mailbox(k), body)
	if err != nil {
		return nil, sendError(err)
	}
	var out struct {
		Results []RecipientResult `json:"results"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("%w: POST /send: %v", mail.ErrEdge, err)
	}
	return out.Results, nil
}

func (s serviceSender) SendInvite(ctx context.Context, k *mail.Keys, raw []byte) ([]RecipientResult, error) {
	data, err := s.service.SendInvite(ctx, s.mailbox(k), raw)
	if err != nil {
		return nil, sendError(err)
	}
	var out struct {
		Results []RecipientResult `json:"results"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("%w: POST /coordinator/invite: %v", mail.ErrEdge, err)
	}
	return out.Results, nil
}

func (s serviceSender) QuerySent(ctx context.Context, k *mail.Keys, messageID string) (SentRecord, error) {
	records, err := s.service.SentQuery(ctx, s.mailbox(k), []string{messageID})
	if err != nil {
		return SentRecord{}, sendError(err)
	}
	q := records[0]
	r := SentRecord{MessageID: q.MessageID, State: q.State, SHA256: q.SHA256, FirstAt: q.FirstAt, UpdatedAt: q.UpdatedAt}
	for _, res := range q.Results {
		r.Results = append(r.Results, RecipientResult{Recipient: res.Recipient, Status: res.Status, Detail: res.Detail})
	}
	return r, nil
}

// mailbox is k's mailbox id, with its keys put in the Service as the mail
// loop puts them, so a send needn't wait for a pass to have read it.
func (s serviceSender) mailbox(k *mail.Keys) string {
	id := hex.EncodeToString(k.MailboxID)
	if !s.service.HasKeys(id) {
		s.service.PutKeys(k)
	}
	return id
}

// sendError is internal/mail's refusal as the journal reads it: the edge's
// status and code, a 404 as one, and an in-doubt send as send_in_doubt.
// Anything else, a transport failure, stays as it is.
func sendError(err error) error {
	var ee *mail.EdgeError
	switch {
	case errors.Is(err, mail.ErrSendInDoubt):
		se := &SendError{Status: http.StatusConflict, Code: "send_in_doubt"}
		if errors.As(err, &ee) {
			se.Message = ee.Message
		}
		return se
	case errors.As(err, &ee):
		return &SendError{Status: ee.Status, Code: ee.Code, Message: ee.Message}
	case errors.Is(err, mail.ErrNotFound):
		return &SendError{Status: http.StatusNotFound, Message: "not found"}
	}
	return err
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
