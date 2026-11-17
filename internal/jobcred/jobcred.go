// Package jobcred mints each Cloud job's credentials (m4-cloud-runners.md
// §5.1c). In the pool no job carries an account's long-lived credential: the
// coordinator signs a license for one job of one worker, which expires soon
// after the job's timeout. A runner enclave that leaks it leaks one job's
// inference until then, and nothing else.
//
// A job credential has the device credential's shape, so the proxy reads both
// the same way: base64url(claims JSON) "." base64url(signature), the signature
// Ed25519 over the exact claims bytes, by the coordinator's signing key. The
// proxy tells the two apart by "typ" and checks a job's against the
// coordinators' public keys it is configured with.
package jobcred

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fount-labs/fount-broker/internal/policy"
)

const (
	Version = 1
	Type    = "fount-job"
	// MaxLifetime is the longest a job credential may run. The proxy refuses
	// any that claims longer.
	MaxLifetime = 24 * time.Hour
)

// Claims are a job credential's payload.
type Claims struct {
	V      int    `json:"v"`
	Typ    string `json:"typ"`
	Acct   string `json:"acct"`
	Worker string `json:"wkr"`
	Job    string `json:"job"`
	Iat    int64  `json:"iat"`
	Exp    int64  `json:"exp"`
}

// Minter is the coordinator's half.
type Minter struct {
	Key ed25519.PrivateKey
	// CacheSecret derives each account's Tinfoil cache secret, so an
	// account's jobs share a prompt cache and no two accounts do.
	CacheSecret []byte
	// Lifetime is how long a job's credential lasts: its timeout, and some.
	Lifetime time.Duration
	Now      func() time.Time
}

// Mint is the job's credentials, by the broker's names.
func (m *Minter) Mint(account, worker, job string) (map[string]string, error) {
	if account == "" || worker == "" || job == "" {
		return nil, errors.New("a job credential names its account, worker and job")
	}
	if m.Lifetime <= 0 || m.Lifetime > MaxLifetime {
		return nil, fmt.Errorf("a job credential lasts up to %s", MaxLifetime)
	}
	if len(m.CacheSecret) < 32 {
		return nil, errors.New("the cache secret is 32 bytes or more")
	}
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	iat := now().Unix()
	payload, err := json.Marshal(Claims{V: Version, Typ: Type, Acct: account, Worker: worker, Job: job, Iat: iat, Exp: iat + int64(m.Lifetime/time.Second)})
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, m.CacheSecret)
	mac.Write([]byte("tinfoil-cache\x00" + account))
	return map[string]string{
		string(policy.CredentialLicense):            encode(payload) + "." + encode(ed25519.Sign(m.Key, payload)),
		string(policy.CredentialTinfoilCacheSecret): hex.EncodeToString(mac.Sum(nil)),
	}, nil
}

func encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Verify checks a job credential as the proxy does.
func Verify(token string, key ed25519.PublicKey, now time.Time) (Claims, error) {
	payloadPart, sigPart, ok := strings.Cut(token, ".")
	if !ok || strings.Contains(sigPart, ".") {
		return Claims{}, errors.New("malformed")
	}
	payload, err1 := base64.RawURLEncoding.Strict().DecodeString(payloadPart)
	sig, err2 := base64.RawURLEncoding.Strict().DecodeString(sigPart)
	if err1 != nil || err2 != nil || len(payload) == 0 {
		return Claims{}, errors.New("malformed")
	}
	if !ed25519.Verify(key, payload, sig) {
		return Claims{}, errors.New("bad signature")
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Claims{}, errors.New("malformed")
	}
	if c.V != Version || c.Typ != Type || c.Acct == "" || c.Worker == "" || c.Job == "" {
		return Claims{}, errors.New("malformed")
	}
	if c.Exp-c.Iat > int64(MaxLifetime/time.Second) {
		return Claims{}, errors.New("lasts too long")
	}
	if now.Unix() >= c.Exp {
		return Claims{}, errors.New("expired")
	}
	return c, nil
}

// DevKeys reads the dev signing key and cache secret from path, making them
// the first time. In the pool both live only in enclave memory, held between
// updates the way the wrapping key is (m4-cloud-runners.md §4).
func DevKeys(path string) (ed25519.PrivateKey, []byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		data = make([]byte, ed25519.SeedSize+32)
		if _, err := rand.Read(data); err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return nil, nil, err
		}
	} else if err != nil {
		return nil, nil, err
	}
	if len(data) != ed25519.SeedSize+32 {
		return nil, nil, fmt.Errorf("%s: want %d bytes", path, ed25519.SeedSize+32)
	}
	return ed25519.NewKeyFromSeed(data[:ed25519.SeedSize]), data[ed25519.SeedSize:], nil
}

// PublicKey is how the proxy is told the key: raw, base64url.
func PublicKey(key ed25519.PrivateKey) string {
	return encode(key.Public().(ed25519.PublicKey))
}
