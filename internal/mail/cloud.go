package mail

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"
)

// The coordinator's side of the Service (launch-plan.md, B). Desktop's broker
// is handed every address's keys in one mail_keys credential and answers the
// app's ops; the coordinator holds each Cloud worker's keys under that
// worker's own DEK, so it gives them over one address at a time and calls the
// Service directly, typed.

// PutKeys adds or replaces one address's keys and leaves the others.
func (s *Service) PutKeys(k *Keys) {
	s.keys.mu.Lock()
	defer s.keys.mu.Unlock()
	if s.keys.keys == nil {
		s.keys.keys = map[string]*Keys{}
	}
	s.keys.keys[hexOf(k.MailboxID)] = k
}

// DropKeys forgets one address's keys, as when its worker is deleted.
func (s *Service) DropKeys(mailbox string) {
	s.keys.mu.Lock()
	defer s.keys.mu.Unlock()
	delete(s.keys.keys, mailbox)
}

// HasKeys reports whether the Service holds mailbox's keys.
func (s *Service) HasKeys(mailbox string) bool {
	_, ok := s.keys.get(mailbox)
	return ok
}

func (s *Service) keysFor(mailbox string) (*Keys, error) {
	if !validHex(mailbox, 32) {
		return nil, fmt.Errorf("%w: mailbox must be 64 lowercase hex characters", ErrRequest)
	}
	k, ok := s.keys.get(mailbox)
	if !ok {
		return nil, ErrNoKeys
	}
	return k, nil
}

// List is GET /mail for one mailbox: the messages waiting and whether the
// worker is paused.
func (s *Service) List(ctx context.Context, mailbox string) (Listing, error) {
	k, err := s.keysFor(mailbox)
	if err != nil {
		return Listing{}, err
	}
	l, err := s.c.list(ctx, k)
	if err != nil {
		return Listing{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notePending(mailbox, l.Messages)
	return l, nil
}

// notePending records which listed messages the ledger hasn't seen delivered.
// s.mu must be held.
func (s *Service) notePending(mailbox string, msgs []Listed) {
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
}

// Get is GET /mail/{id}: the message verified against its boot, opened and
// with its sender check, as the get op answers it.
func (s *Service) Get(ctx context.Context, mailbox, id string) (*Message, error) {
	k, err := s.keysFor(mailbox)
	if err != nil {
		return nil, err
	}
	if !validHex(id, 16) {
		return nil, fmt.Errorf("%w: an edge id is 32 hex characters", ErrRequest)
	}
	m, err := s.get(ctx, k, mailbox, id)
	if err != nil {
		return nil, err
	}
	return m.(*Message), nil
}

// Gaps is GET /gaps from the ledger's floor, every record verified.
func (s *Service) Gaps(ctx context.Context, mailbox string) (GapsResult, error) {
	k, err := s.keysFor(mailbox)
	if err != nil {
		return GapsResult{}, err
	}
	res, err := s.gaps(ctx, k, mailbox)
	if err != nil {
		return GapsResult{}, err
	}
	return res.(GapsResult), nil
}

// Ledger is a copy of mailbox's ledger, to keep.
func (s *Service) Ledger(mailbox string) *Ledger {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneLedger(s.ledger(mailbox))
}

// RestoreLedger folds a ledger kept earlier into mailbox's, as the restore op
// does: facts from both are kept, and a conflict becomes an anomaly.
func (s *Service) RestoreLedger(mailbox string, saved *Ledger) Summary {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.ledger(mailbox)
	if saved != nil {
		l.merge(saved)
	}
	return summarize(l, len(s.pending[mailbox]))
}

// Renewal is what POST /entitlement answered: the mailbox's stored expiry,
// which the edge moved to the entitlement's.
type Renewal struct {
	ExpiresAt time.Time
}

// RenewEntitlement presents an entitlement for the address's signing key to
// the edge, which extends the mailbox's stored expiry to it (fount-mail-design.md
// §5). The edge bounces a mailbox's mail once that expiry passes.
func (s *Service) RenewEntitlement(ctx context.Context, mailbox, entitlement string) (Renewal, error) {
	k, err := s.keysFor(mailbox)
	if err != nil {
		return Renewal{}, err
	}
	if entitlement == "" {
		return Renewal{}, fmt.Errorf("%w: no entitlement", ErrRequest)
	}
	body := []byte("{}")
	req, err := http.NewRequestWithContext(ctx, "POST", s.c.edge.Base()+"entitlement", bytes.NewReader(body))
	if err != nil {
		return Renewal{}, err
	}
	signRequest(req.Header, k, "POST", "/entitlement", body, s.c.now())
	req.Header.Set("Fount-Entitlement", entitlement)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.c.edge.Do(ctx, req)
	if err != nil {
		return Renewal{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxJSON+1))
	if err != nil || len(data) > maxJSON {
		return Renewal{}, fmt.Errorf("%w: POST /entitlement: unreadable or over %d bytes", ErrEdge, maxJSON)
	}
	if resp.StatusCode != http.StatusOK {
		return Renewal{}, fmt.Errorf("%w: POST /entitlement answered %d: %s", ErrEdge, resp.StatusCode, edgeMessage(data))
	}
	var out struct {
		EntitlementExp int64 `json:"entitlement_exp"`
	}
	if err := strictJSON(data, &out); err != nil {
		return Renewal{}, err
	}
	return Renewal{ExpiresAt: time.Unix(out.EntitlementExp, 0).UTC()}, nil
}

// SigningPublic is the address's request-signing public key, which an
// entitlement is bound to.
func (k *Keys) SigningPublic() ed25519.PublicKey {
	return k.Signing.Public().(ed25519.PublicKey)
}

// MailboxHex is the mailbox id as the edge and the Service name it.
func (k *Keys) MailboxHex() string { return hex.EncodeToString(k.MailboxID) }
