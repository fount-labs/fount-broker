package channel

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// A device credential is fount-infra's (packages/shared/src/devices.ts):
// base64url(claims JSON) "." base64url(signature), RSASSA-PKCS1-v1_5 SHA-256
// over the exact claims bytes, by the KMS certificate-signing key. It names
// the account and the device, and the subscription as it was when it was
// signed. It lasts up to 7 days; the proxy checks entitlement and revocation
// live, which the coordinator can't, so it trusts the claims until exp.
//
// A Cloud credential is the same, typed CloudCredentialType, and lasts at most
// MaxCloudCredential: fount-infra would sign it only after checking the
// device and the subscription live, so a revoked device or a cancelled
// subscription loses Cloud within the hour, not the week. fount-infra
// doesn't issue it yet; the coordinator takes both until told to take only
// the short one (Server.CloudCredentialsOnly).
const (
	DeviceCredentialVersion = 1
	DeviceCredentialType    = "fount-device"
	CloudCredentialType     = "fount-cloud"
	MaxCloudCredential      = time.Hour
)

// DeviceClaims are the device credential's claims the coordinator reads.
// Readers ignore claims they don't know.
type DeviceClaims struct {
	V    int    `json:"v"`
	Typ  string `json:"typ"`
	Acct string `json:"acct"`
	Dev  string `json:"dev"`
	// Tier and Status are the subscription's, or null without one; Pe is the
	// end of its paid period, Unix seconds, or null.
	Tier   *string `json:"tier"`
	Status *string `json:"status"`
	Pe     *int64  `json:"pe"`
	Iat    int64   `json:"iat"`
	Exp    int64   `json:"exp"`
	// Eml is the account's email address as the identity provider verified
	// it, lower-cased; absent when it isn't verified. Only a Cloud
	// credential's counts (VerifiedEmail): fount-infra signs it after
	// checking live, and an invite is accepted only for it.
	Eml string `json:"eml,omitempty"`
}

// VerifiedEmail is the credential's verified email, or empty: a Cloud
// credential's eml, when it is a lower-case address. A device credential's
// is never read, since it lasts a week and the address may have changed.
func (c DeviceClaims) VerifiedEmail() string {
	if c.Typ != CloudCredentialType || c.Eml == "" || len(c.Eml) > 254 || c.Eml != strings.ToLower(c.Eml) {
		return ""
	}
	local, domain, ok := strings.Cut(c.Eml, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") || strings.ContainsFunc(c.Eml, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return ""
	}
	return c.Eml
}

// cloudTiers are the plans that include Cloud: every paid one (pricing.md).
var cloudTiers = []string{"plus", "pro"}

// ErrNotEntitled is a credential whose claims don't include Cloud.
var ErrNotEntitled = errors.New("the account's subscription doesn't include Cloud")

// Entitled is fount-infra's evaluateSubscriptionAccess over the claims: a
// paid tier, active or past_due, inside its period.
func (c DeviceClaims) Entitled(now time.Time) error {
	switch {
	case c.Tier == nil || !slices.Contains(cloudTiers, *c.Tier):
		return fmt.Errorf("%w: no paid plan", ErrNotEntitled)
	case c.Status == nil || (*c.Status != "active" && *c.Status != "past_due"):
		return fmt.Errorf("%w: the subscription isn't active", ErrNotEntitled)
	case c.Pe == nil || now.Unix() >= *c.Pe:
		return fmt.Errorf("%w: the paid period ended", ErrNotEntitled)
	}
	return nil
}

// A session grant is the device key's signature over a session key the
// broker holds: the app signs it in its keychain, so the device key never
// reaches the broker, and the broker signs each channel's binding with the
// session key. Its shape is the credential's, signed Ed25519 over
// SessionContext followed by the claims bytes.
const (
	SessionVersion = 1
	SessionType    = "fount-client-session"
	SessionContext = "fount-client-session-v1\n"
	// MaxSession is the longest a session grant may run. The session key
	// alone reads, writes and queues jobs on its device's workers
	// (coordinator/grant.go), so a broker's key that leaks is good for that
	// long at most; the app re-signs a session before it runs out.
	MaxSession = 8 * time.Hour
	// clockSkew is how far in the future a grant may say it was signed.
	clockSkew = 5 * time.Minute
)

// SessionClaims are a session grant's.
type SessionClaims struct {
	V   int    `json:"v"`
	Typ string `json:"typ"`
	// Dev is the device's id, which the credential names too.
	Dev string `json:"dev"`
	// Key is the session's Ed25519 public key, raw, base64url.
	Key string `json:"key"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

var b64 = base64.RawURLEncoding.Strict()

// DeviceID is fount-infra's id for a device key: the first 16 bytes of
// SHA-256(public key), lowercase hex.
func DeviceID(key ed25519.PublicKey) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:16])
}

// ParseAccountKeys reads the device credential's verifying keys:
// comma-separated SubjectPublicKeyInfo DER, standard base64, as `aws kms
// get-public-key` prints it. More than one lets the key rotate.
func ParseAccountKeys(s string) ([]*rsa.PublicKey, error) {
	var keys []*rsa.PublicKey
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(part)
		if err != nil {
			return nil, fmt.Errorf("an account key isn't base64: %w", err)
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, fmt.Errorf("an account key: %w", err)
		}
		k, ok := pub.(*rsa.PublicKey)
		if !ok || k.N.BitLen() < 2048 {
			return nil, errors.New("an account key isn't RSA of 2048 bits or more")
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, errors.New("no account keys")
	}
	return keys, nil
}

func split(token string) (payload, sig []byte, err error) {
	p, s, ok := strings.Cut(token, ".")
	if !ok || strings.Contains(s, ".") {
		return nil, nil, errors.New("malformed")
	}
	if payload, err = b64.DecodeString(p); err != nil || len(payload) == 0 {
		return nil, nil, errors.New("malformed")
	}
	if sig, err = b64.DecodeString(s); err != nil || len(sig) == 0 {
		return nil, nil, errors.New("malformed")
	}
	return payload, sig, nil
}

// VerifyDeviceCredential checks a device credential as fount-infra's
// verifyDeviceCredential does: signature by one of keys, shape and expiry.
func VerifyDeviceCredential(token string, keys []*rsa.PublicKey, now time.Time) (DeviceClaims, error) {
	c, err := verifyCredential(token, keys, now)
	if err == nil && c.Typ != DeviceCredentialType {
		return DeviceClaims{}, errors.New("malformed")
	}
	return c, err
}

// VerifyAccountCredential checks what a client proves its account with: a
// Cloud credential, or unless cloudOnly a device credential; either entitled
// to Cloud.
func VerifyAccountCredential(token string, keys []*rsa.PublicKey, now time.Time, cloudOnly bool) (DeviceClaims, error) {
	c, err := verifyCredential(token, keys, now)
	if err != nil {
		return DeviceClaims{}, err
	}
	switch {
	case c.Typ == CloudCredentialType:
		if c.Exp <= c.Iat || time.Duration(c.Exp-c.Iat)*time.Second > MaxCloudCredential {
			return DeviceClaims{}, fmt.Errorf("a Cloud credential lasts up to %s", MaxCloudCredential)
		}
		if c.Iat > now.Add(clockSkew).Unix() {
			return DeviceClaims{}, errors.New("the Cloud credential is from the future")
		}
	case cloudOnly:
		return DeviceClaims{}, errors.New("this coordinator takes only a Cloud credential, not a device credential")
	}
	if err := c.Entitled(now); err != nil {
		return DeviceClaims{}, err
	}
	return c, nil
}

func verifyCredential(token string, keys []*rsa.PublicKey, now time.Time) (DeviceClaims, error) {
	payload, sig, err := split(token)
	if err != nil {
		return DeviceClaims{}, err
	}
	digest := sha256.Sum256(payload)
	signed := false
	for _, k := range keys {
		if rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) == nil {
			signed = true
			break
		}
	}
	if !signed {
		return DeviceClaims{}, errors.New("bad signature")
	}
	var c DeviceClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return DeviceClaims{}, errors.New("malformed")
	}
	if c.V != DeviceCredentialVersion || (c.Typ != DeviceCredentialType && c.Typ != CloudCredentialType) || c.Acct == "" || c.Dev == "" || c.Exp == 0 {
		return DeviceClaims{}, errors.New("malformed")
	}
	if now.Unix() >= c.Exp {
		return DeviceClaims{}, errors.New("expired")
	}
	return c, nil
}

// SignSession is the app's half: the device key grants key a session until
// exp. Desktop does the same in Rust; this is the reference, and the tests'.
func SignSession(device ed25519.PrivateKey, key ed25519.PublicKey, iat, exp time.Time) (string, error) {
	payload, err := json.Marshal(SessionClaims{
		V: SessionVersion, Typ: SessionType, Dev: DeviceID(device.Public().(ed25519.PublicKey)),
		Key: b64.EncodeToString(key), Iat: iat.Unix(), Exp: exp.Unix(),
	})
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(device, append([]byte(SessionContext), payload...))
	return b64.EncodeToString(payload) + "." + b64.EncodeToString(sig), nil
}

// VerifySession checks a session grant against the device key that signed
// it, and returns the session key it grants.
func VerifySession(token string, device ed25519.PublicKey, now time.Time) (SessionClaims, ed25519.PublicKey, error) {
	payload, sig, err := split(token)
	if err != nil {
		return SessionClaims{}, nil, err
	}
	if len(device) != ed25519.PublicKeySize || !ed25519.Verify(device, append([]byte(SessionContext), payload...), sig) {
		return SessionClaims{}, nil, errors.New("the session grant isn't the device key's")
	}
	var c SessionClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return SessionClaims{}, nil, errors.New("malformed session grant")
	}
	if c.V != SessionVersion || c.Typ != SessionType || c.Dev != DeviceID(device) {
		return SessionClaims{}, nil, errors.New("malformed session grant")
	}
	key, err := b64.DecodeString(c.Key)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return SessionClaims{}, nil, errors.New("malformed session grant")
	}
	if c.Exp <= c.Iat || time.Duration(c.Exp-c.Iat)*time.Second > MaxSession {
		return SessionClaims{}, nil, fmt.Errorf("a session grant lasts up to %s", MaxSession)
	}
	if c.Iat > now.Add(clockSkew).Unix() {
		return SessionClaims{}, nil, errors.New("the session grant is from the future")
	}
	if now.Unix() >= c.Exp {
		return SessionClaims{}, nil, errors.New("the session grant expired")
	}
	return c, ed25519.PublicKey(key), nil
}

// Identity is what the client proves: the account, by fount-infra's
// credential; the device, by its key's session grant; and this broker, by the
// session key the grant names.
type Identity struct {
	Credential string
	DeviceKey  ed25519.PublicKey
	Session    string
	SessionKey ed25519.PrivateKey
}

// SessionCredential is the cloud_session credential the app hands the broker,
// JSON: the device's public key, the grant, and the session key's seed, each
// base64url. The device credential is the license credential, as for the
// proxy, unless Credential holds a Cloud credential, which goes in its place.
// The app renews it before it expires, and each renewal reaches the next
// channel.
type SessionCredential struct {
	DeviceKey   string `json:"device_key"`
	Session     string `json:"session"`
	SessionSeed string `json:"session_seed"`
	Credential  string `json:"credential,omitempty"`
}

// ParseIdentity reads the license credential and the cloud_session credential.
func ParseIdentity(license, session string) (Identity, error) {
	if session == "" {
		return Identity{}, errors.New("Cloud needs the cloud_session credential")
	}
	var s SessionCredential
	dec := json.NewDecoder(strings.NewReader(session))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Identity{}, fmt.Errorf("cloud_session: %w", err)
	}
	dev, err := b64.DecodeString(s.DeviceKey)
	if err != nil || len(dev) != ed25519.PublicKeySize {
		return Identity{}, errors.New("cloud_session: device_key isn't 32 bytes of base64url")
	}
	seed, err := b64.DecodeString(s.SessionSeed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return Identity{}, errors.New("cloud_session: session_seed isn't 32 bytes of base64url")
	}
	if _, _, err := split(s.Session); err != nil {
		return Identity{}, errors.New("cloud_session: session is malformed")
	}
	if s.Credential != "" {
		if _, _, err := split(s.Credential); err != nil {
			return Identity{}, errors.New("cloud_session: credential is malformed")
		}
		license = s.Credential
	}
	if license == "" {
		return Identity{}, errors.New("Cloud needs the license credential, or a Cloud credential in cloud_session")
	}
	return Identity{Credential: license, DeviceKey: dev, Session: s.Session, SessionKey: ed25519.NewKeyFromSeed(seed)}, nil
}
