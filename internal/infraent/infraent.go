// Package infraent asks fount-infra for Cloud mailboxes' entitlements, so a
// Cloud worker's mailbox renews with every laptop closed (fount launch-plan
// decision 12). It is the coordinator's Entitlements (coordinator/renew.go).
//
// The coordinator proves itself with a request it signs with its enclave's
// attested job-signing key (jobcred.AttestedKeyID), the key it signs job
// credentials with. fount-infra trusts that key once an attestation from one
// of the coordinators it is deployed with, checked against their repo's
// releases, endorses it, as the proxy does for job credentials:
//
//	POST <base>/coordinator/mail-entitlement
//	Authorization: Bearer base64url(claims) "." base64url(Ed25519 signature)
//
// over the exact claims bytes, no body. A request names the mailbox's license
// account (acct), whose hash the entitlement carries, and, when another
// account pays for it (a team worker's team), that payer (pay, version 2);
// version 1 is a request whose payer is acct. The answer is fount-infra's
// lambda/coordinator-mail-entitlement: the same token Desktop's
// /mail/entitlement mints, so a mailbox Desktop made renews unchanged.
package infraent

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
	Version = 1
	// VersionPay is a request with a payer apart from the license account.
	VersionPay = 2
	Type    = "fount-mail-renewal"
	// Lifetime is how long a request lasts; fount-infra refuses one longer
	// than five minutes.
	Lifetime = 5 * time.Minute
	// Path is the route under the base URL.
	Path = "coordinator/mail-entitlement"
	// maxAnswer bounds the answer; a token is a few hundred bytes.
	maxAnswer = 16 << 10
)

// Claims are a renewal request's payload.
type Claims struct {
	V    int    `json:"v"`
	Typ  string `json:"typ"`
	Acct string `json:"acct"`
	// Pay is the account whose subscription must entitle the mailbox, in a
	// version 2 request only.
	Pay string `json:"pay,omitempty"`
	// Dk is the address's request-signing key, standard base64: the key the
	// entitlement is bound to, as Desktop's /mail/entitlement deviceKey.
	Dk  string `json:"dk"`
	Kid string `json:"kid"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

// Client is the coordinator's Entitlements against fount-infra.
type Client struct {
	// Base is fount-infra's API origin, https://api.fount.sh/.
	Base string
	// Key is the coordinator's attested job-signing key.
	Key  ed25519.PrivateKey
	HTTP *http.Client
	Now  func() time.Time
}

var _ coordinator.Entitlements = (*Client)(nil)

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

// Request is a signed renewal request for the license account, the payer
// and the address key. A payer that is empty or the account itself makes a
// version 1 request.
func (c *Client) Request(account, pay string, signing ed25519.PublicKey) (string, error) {
	if account == "" || len(signing) != ed25519.PublicKeySize {
		return "", errors.New("a renewal request names an account and a 32-byte address key")
	}
	v := Version
	if pay == account {
		pay = ""
	}
	if pay != "" {
		v = VersionPay
	}
	iat := c.now().Unix()
	payload, err := json.Marshal(Claims{
		V: v, Typ: Type, Acct: account, Pay: pay,
		Dk:  base64.StdEncoding.EncodeToString(signing),
		Kid: jobcred.PublicKey(c.Key),
		Iat: iat, Exp: iat + int64(Lifetime/time.Second),
	})
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(ed25519.Sign(c.Key, payload)), nil
}

// answer is fount-infra's 200.
type answer struct {
	Entitlement string `json:"entitlement"`
	IssuedAt    int64  `json:"issuedAt"`
	ExpiresAt   int64  `json:"expiresAt"`
	GraceEnds   *int64 `json:"graceEnds"`
}

// refusal is any other answer.
type refusal struct {
	Error  string `json:"error"`
	Reason string `json:"reason"`
}

// Issue asks for the mailbox's entitlement. A 403 no_access is the account
// lapsed (its past_due grace has ended, or it has no paid plan), wrapping
// coordinator.ErrAccountLapsed; anything else is an error to retry.
func (c *Client) Issue(ctx context.Context, req coordinator.EntitlementRequest) (coordinator.Entitlement, error) {
	token, err := c.Request(req.Account, req.Pay, req.SigningKey)
	if err != nil {
		return coordinator.Entitlement{}, err
	}
	u, err := url.JoinPath(c.Base, Path)
	if err != nil {
		return coordinator.Entitlement{}, err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return coordinator.Entitlement{}, err
	}
	hr.Header.Set("Authorization", "Bearer "+token)
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: time.Minute}
	}
	// No redirects: the request goes to the route it names, or nowhere.
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedirect.Do(hr)
	if err != nil {
		return coordinator.Entitlement{}, fmt.Errorf("fount-infra: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return coordinator.Entitlement{}, fmt.Errorf("fount-infra: %w", err)
	}
	if len(data) > maxAnswer {
		return coordinator.Entitlement{}, errors.New("fount-infra's answer is too long")
	}
	if resp.StatusCode != http.StatusOK {
		var r refusal
		_ = json.Unmarshal(data, &r)
		if resp.StatusCode == http.StatusForbidden && r.Error == "no_access" {
			return coordinator.Entitlement{}, fmt.Errorf("%w (%s)", coordinator.ErrAccountLapsed, r.Reason)
		}
		return coordinator.Entitlement{}, fmt.Errorf("fount-infra answered %d %s %s", resp.StatusCode, r.Error, r.Reason)
	}
	var a answer
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&a); err != nil || a.Entitlement == "" || a.IssuedAt <= 0 {
		return coordinator.Entitlement{}, errors.New("fount-infra answered with no entitlement")
	}
	ent := coordinator.Entitlement{Token: a.Entitlement, IssuedAt: time.Unix(a.IssuedAt, 0).UTC()}
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
