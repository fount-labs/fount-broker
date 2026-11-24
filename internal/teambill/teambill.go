// Package teambill is the coordinator's TeamBiller (coordinator/teambilling.go)
// against fount-infra: it signs firm teams' billing statements, and asks
// fount-infra for a team's subscription (fount team-billing-plan.md §6.1).
//
// Every statement is signed, as internal/infraent signs mail renewals, with
// the enclave's attested job-signing key (jobcred.AttestedKeyID), over the
// exact claims bytes:
//
//	base64url(claims JSON) "." base64url(Ed25519 signature)
//
//	{ "v": 1, "typ": "fount-team-admin", "team", "acct", "kid", "iat", "exp" }  ≤ 5 minutes
//	{ "v": 1, "typ": "fount-team-seat",  "team", "acct", "kid", "iat", "exp" }  ≤ 7 days
//	{ "v": 1, "typ": "fount-team-status", "team", "kid", "iat", "exp" }        ≤ 5 minutes
//
// fount-infra trusts the key once one of the coordinators it is deployed with
// endorsed it in an attestation (proxy-server/coordinator-statement.ts
// verifies all three). `typ` keeps each apart from the others and from a job
// credential or a renewal signed by the same key.
//
// The status request goes as the bearer of
//
//	POST <base>/coordinator/team-entitlement
//
// with no body, and the answer is { status, tier, periodEnd, graceEnds,
// seats, subscription }, or 403 { error: "no_access", reason, subscription }.
// subscription, the id of the team's subscription, is absent from an older
// fount-infra, and from a refusal for a team with none.
package teambill

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/fount-labs/fount-broker/internal/coordinator"
	"github.com/fount-labs/fount-broker/internal/jobcred"
)

const (
	Version    = 1
	TypeAdmin  = "fount-team-admin"
	TypeSeat   = "fount-team-seat"
	TypeStatus = "fount-team-status"
	// AdminLifetime and StatusLifetime are at most fount-infra's five
	// minutes; SeatLifetime is a device credential's week.
	AdminLifetime  = 5 * time.Minute
	SeatLifetime   = 7 * 24 * time.Hour
	StatusLifetime = 5 * time.Minute
	// Path is the status route under the base URL.
	Path      = "coordinator/team-entitlement"
	maxAnswer = 16 << 10
)

// Claims are a statement's payload. Acct is empty, and left out, in a status
// request.
type Claims struct {
	V    int    `json:"v"`
	Typ  string `json:"typ"`
	Team string `json:"team"`
	Acct string `json:"acct,omitempty"`
	Kid  string `json:"kid"`
	Iat  int64  `json:"iat"`
	Exp  int64  `json:"exp"`
}

// Client is the coordinator's TeamBiller against fount-infra.
type Client struct {
	// Base is fount-infra's API origin, https://api.fount.sh/.
	Base string
	// Key is the coordinator's attested job-signing key.
	Key  ed25519.PrivateKey
	HTTP *http.Client
	Now  func() time.Time
}

var _ coordinator.TeamBiller = (*Client)(nil)

// New checks base and returns a client signing with key.
func New(base string, key ed25519.PrivateKey) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.User != nil {
		return nil, fmt.Errorf("%s: fount-infra's API, https://<host>/", base)
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("the job-signing key is an Ed25519 private key")
	}
	return &Client{Base: u.String(), Key: key}, nil
}

// Sign signs a statement of typ about team (and acct, but for a status
// request) from now for its type's lifetime.
func (c *Client) Sign(typ, team, acct string) (string, time.Time, error) {
	var life time.Duration
	switch typ {
	case TypeAdmin:
		life = AdminLifetime
	case TypeSeat:
		life = SeatLifetime
	case TypeStatus:
		life = StatusLifetime
	default:
		return "", time.Time{}, fmt.Errorf("no statement type %q", typ)
	}
	if team == "" || (typ == TypeStatus) != (acct == "") {
		return "", time.Time{}, errors.New("a statement names a team, and an account unless it asks a status")
	}
	iat := c.now().Unix()
	exp := iat + int64(life/time.Second)
	payload, err := json.Marshal(Claims{V: Version, Typ: typ, Team: team, Acct: acct, Kid: jobcred.PublicKey(c.Key), Iat: iat, Exp: exp})
	if err != nil {
		return "", time.Time{}, err
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(ed25519.Sign(c.Key, payload)), time.Unix(exp, 0).UTC(), nil
}

// Statement signs an admin or seat statement.
func (c *Client) Statement(kind coordinator.StatementKind, team, account string) (coordinator.TeamStatement, error) {
	typ := map[coordinator.StatementKind]string{coordinator.StatementAdmin: TypeAdmin, coordinator.StatementSeat: TypeSeat}[kind]
	if typ == "" || account == "" {
		return coordinator.TeamStatement{}, fmt.Errorf("a %q statement for no account", kind)
	}
	token, exp, err := c.Sign(typ, team, account)
	if err != nil {
		return coordinator.TeamStatement{}, err
	}
	return coordinator.TeamStatement{Token: token, ExpiresAt: exp}, nil
}

type answer struct {
	Status    string `json:"status"`
	Tier      string `json:"tier"`
	PeriodEnd int64  `json:"periodEnd"`
	GraceEnds *int64 `json:"graceEnds"`
	Seats     int    `json:"seats"`
	// Subscription is optional.
	Subscription string `json:"subscription"`
}

type refusal struct {
	Error        string `json:"error"`
	Reason       string `json:"reason"`
	Subscription string `json:"subscription"`
}

// Status asks fount-infra for team's subscription. A 403 no_access is a
// *coordinator.TeamNotEntitled; anything else but a full answer is an error
// to retry.
func (c *Client) Status(ctx context.Context, team string) (coordinator.TeamEntitlement, error) {
	token, _, err := c.Sign(TypeStatus, team, "")
	if err != nil {
		return coordinator.TeamEntitlement{}, err
	}
	u, err := url.JoinPath(c.Base, Path)
	if err != nil {
		return coordinator.TeamEntitlement{}, err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return coordinator.TeamEntitlement{}, err
	}
	hr.Header.Set("Authorization", "Bearer "+token)
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: time.Minute}
	}
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedirect.Do(hr)
	if err != nil {
		return coordinator.TeamEntitlement{}, fmt.Errorf("fount-infra: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return coordinator.TeamEntitlement{}, fmt.Errorf("fount-infra: %w", err)
	}
	if len(data) > maxAnswer {
		return coordinator.TeamEntitlement{}, errors.New("fount-infra's answer is too long")
	}
	if resp.StatusCode != http.StatusOK {
		var r refusal
		_ = json.Unmarshal(data, &r)
		if resp.StatusCode == http.StatusForbidden && r.Error == "no_access" && r.Reason != "" {
			return coordinator.TeamEntitlement{}, &coordinator.TeamNotEntitled{Reason: r.Reason, Subscription: r.Subscription}
		}
		return coordinator.TeamEntitlement{}, fmt.Errorf("fount-infra answered %d %s %s", resp.StatusCode, r.Error, r.Reason)
	}
	var a answer
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&a); err != nil ||
		(a.Status != "active" && a.Status != "past_due") || a.Tier == "" || a.PeriodEnd <= 0 || a.Seats < 1 {
		return coordinator.TeamEntitlement{}, errors.New("fount-infra answered with no team status")
	}
	ent := coordinator.TeamEntitlement{Status: a.Status, Tier: a.Tier, PeriodEnd: time.Unix(a.PeriodEnd, 0).UTC(), Seats: a.Seats, Subscription: a.Subscription}
	if a.GraceEnds != nil {
		ent.GraceEnds = time.Unix(*a.GraceEnds, 0).UTC()
	}
	return ent, nil
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
