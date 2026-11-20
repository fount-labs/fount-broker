package coordinator

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"
	"unicode/utf8"
)

// A member's own new device, admitted at once with the member's passkey
// (launch-plan.md decision 19, docs/membership-list.md §2.3). The passkey is
// the one the admin-signed list names for the member (ListMember.Rec); the
// coordinator checks the assertion, and every client checks it again when it
// replays the log, so Fount's servers can't add a device with it.
//
//  1. The new device, signed in to the member's account and not yet listed,
//     asks for a challenge (POST /teams/{team}/passkey-join/challenge
//     {key, enc}). The coordinator answers a single-use nonce, kept in memory
//     for passkeyChallengeLifetime, and PasskeyJoinChallenge over the
//     coordinator, team, member, the log's head, the nonce and the device's
//     keys.
//  2. The member's passkey signs the challenge (WebAuthn get, rp fount.sh).
//  3. The device posts the assertion with its team inclusion for the next
//     entry (POST /teams/{team}/passkey-join). The coordinator appends a
//     passkey-join record whose proof is the nonce and the assertion, and
//     seals the device its wraps as for any admission.
//
// The head in the challenge makes an assertion good for one append, and the
// keys for one device. Every other device of the member, and the team's
// admins, are told after the fact, with Remove. It is the only way a
// member's new computer joins (decided 2026-11-19): the member's passkey is
// listed when they accept their invite (teaminvite.go), and one who lost it
// and every computer is invited again.

const (
	// PasskeyRPID is the passkey's relying party, as Desktop's native
	// passkey calls and the edge have it.
	PasskeyRPID = "fount.sh"
	// PasskeyJoinContext starts what a passkey join's challenge is a hash of.
	PasskeyJoinContext = "fount-team-passkey-join-v1\x00"

	passkeyChallengeLifetime = 5 * time.Minute
	passkeyNonceSize         = 32
	maxPasskeyBody           = 16 << 10
	// maxPasskeyChallenges bounds the challenges kept: per member, and in all.
	maxMemberPasskeyChallenges = 3
	maxPasskeyChallenges       = 1000
)

// PasskeyOrigins are the client data origins a passkey join accepts: the
// rp's, which is what macOS AuthenticationServices and Desktop's Windows
// webauthn.dll client data both carry.
var PasskeyOrigins = []string{"https://" + PasskeyRPID}

// PasskeyJoinChallenge is what the member's passkey signs for a new device:
// SHA-256 of the context, then the coordinator, team, member, the log's head
// (the record's prev), the nonce and the device's Ed25519 and X25519 keys,
// length-prefixed.
func PasskeyJoinChallenge(aud, team, member, prev string, nonce, key, enc []byte) ([]byte, error) {
	msg, err := lengthPrefixed(PasskeyJoinContext, []byte(aud), []byte(team), []byte(member), []byte(prev), nonce, key, enc)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(msg)
	return sum[:], nil
}

// PasskeyJoinProof is a passkey-join record's proof, each field base64url:
// the nonce the challenge was over and the passkey's assertion.
type PasskeyJoinProof struct {
	Nonce             string `json:"nonce"`
	Cred              string `json:"cred"`
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
}

// passkeyChallenge is one challenge handed to a device, until it is used.
type passkeyChallenge struct {
	Team, Member, Account, Device, Prev string
	Key, Enc, Nonce                     []byte
	Expires                             time.Time
}

// PasskeyChallenge is a challenge as the device that asked sees it.
type PasskeyChallenge struct {
	Member string `json:"member"`
	// Cred is the member's passkey's credential id, for allowCredentials.
	Cred  string `json:"cred"`
	Nonce string `json:"nonce"`
	// Seq and Head are the log's: the inclusion is for Seq+1.
	Seq       uint64    `json:"seq"`
	Head      string    `json:"head"`
	Challenge string    `json:"challenge"`
	ExpiresAt time.Time `json:"expiresAt"`
}

var (
	// ErrNoPasskey is a member the list names no passkey for.
	ErrNoPasskey = errors.New("no passkey is set up for you on this team; ask an admin to invite you again")
	// ErrPasskeyChallenge is a join with no live challenge: never asked,
	// used, or past its time.
	ErrPasskeyChallenge = errors.New("the passkey challenge is used or expired; try again")
)

// dropExpiredPasskeyChallenges forgets challenges past their time. Called
// with c.mu held.
func (c *Coordinator) dropExpiredPasskeyChallenges(now time.Time) {
	for id, ch := range c.passkeyChallenges {
		if !now.Before(ch.Expires) {
			delete(c.passkeyChallenges, id)
		}
	}
}

// StartPasskeyJoin is a not-yet-listed device of a member asking for a
// challenge for the member's passkey to sign.
func (c *Coordinator) StartPasskeyJoin(caller Caller, team string, key, enc []byte) (PasskeyChallenge, error) {
	if !ed25519.PublicKey(key).Equal(caller.DeviceKey) || deviceID(key) != caller.Device {
		return PasskeyChallenge{}, fmt.Errorf("%w: a device joins with its own key", ErrInvalid)
	}
	if err := checkX25519(enc); err != nil || len(enc) != 32 {
		return PasskeyChallenge{}, fmt.Errorf("%w: enc is a 32-byte X25519 key", ErrInvalid)
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.state.Teams[team]; !ok {
		return PasskeyChallenge{}, ErrNoTeam
	}
	st, err := c.teamState(team)
	if err != nil {
		return PasskeyChallenge{}, ErrNoTeam
	}
	i := slices.IndexFunc(st.members, func(m *Member) bool { return m.Account != "" && m.Account == caller.Account })
	if i < 0 {
		return PasskeyChallenge{}, ErrNoTeam
	}
	m := st.members[i]
	switch {
	case st.byDevice[caller.Device] != nil:
		return PasskeyChallenge{}, fmt.Errorf("%w: this device is admitted already", ErrListRefused)
	case m.Rec == nil:
		return PasskeyChallenge{}, fmt.Errorf("%w: %w", ErrListRefused, ErrNoPasskey)
	case len(m.Devices) >= MaxMemberDevices:
		return PasskeyChallenge{}, fmt.Errorf("%w: member %s has %d devices", ErrListRefused, m.ID, MaxMemberDevices)
	}
	c.dropExpiredPasskeyChallenges(now)
	mine := 0
	for _, ch := range c.passkeyChallenges {
		if ch.Team == team && ch.Member == m.ID {
			mine++
		}
	}
	if mine >= maxMemberPasskeyChallenges || len(c.passkeyChallenges) >= maxPasskeyChallenges {
		return PasskeyChallenge{}, fmt.Errorf("%w: too many passkey challenges are open; try again in a few minutes", ErrTooManyUngranted)
	}
	nonce := make([]byte, passkeyNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return PasskeyChallenge{}, err
	}
	challenge, err := PasskeyJoinChallenge(c.cfg.Audience, team, m.ID, st.head, nonce, key, enc)
	if err != nil {
		return PasskeyChallenge{}, err
	}
	ch := &passkeyChallenge{Team: team, Member: m.ID, Account: caller.Account, Device: caller.Device, Prev: st.head,
		Key: slices.Clone(key), Enc: slices.Clone(enc), Nonce: nonce, Expires: now.Add(passkeyChallengeLifetime)}
	c.passkeyChallenges[b64.EncodeToString(nonce)] = ch
	return PasskeyChallenge{Member: m.ID, Cred: m.Rec.Cred, Nonce: b64.EncodeToString(nonce), Seq: st.seq, Head: st.head,
		Challenge: b64.EncodeToString(challenge), ExpiresAt: ch.Expires.UTC()}, nil
}

// PasskeyJoinRequest is POST /v1/teams/{team}/passkey-join: the challenge's
// nonce, the passkey's assertion over it, and the device's inclusion for the
// next entry, every byte string base64url.
type PasskeyJoinRequest struct {
	Nonce             string `json:"nonce"`
	Cred              string `json:"cred"`
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
	Device            string `json:"device"`
}

// PasskeyJoin appends the passkey-join record for the caller's device: the
// one its challenge was for, with the inclusion for the record's entry. The
// challenge is used up whether or not the join goes through.
func (c *Coordinator) PasskeyJoin(caller Caller, team string, req PasskeyJoinRequest) (TeamLogView, error) {
	c.mu.Lock()
	ch := c.passkeyChallenges[req.Nonce]
	delete(c.passkeyChallenges, req.Nonce)
	c.mu.Unlock()
	if ch == nil || ch.Team != team || ch.Device != caller.Device || ch.Account != caller.Account || !time.Now().Before(ch.Expires) {
		return TeamLogView{}, fmt.Errorf("%w: %w", ErrNotFound, ErrPasskeyChallenge)
	}
	proof, err := json.Marshal(PasskeyJoinProof{Nonce: req.Nonce, Cred: req.Cred, AuthenticatorData: req.AuthenticatorData,
		ClientDataJSON: req.ClientDataJSON, Signature: req.Signature})
	if err != nil {
		return TeamLogView{}, err
	}
	rec := TeamRecord{Kind: RecordPasskeyJoin, Member: ch.Member, Account: caller.Account, Device: req.Device, Proof: proof}
	seq, err := c.appendRecord(caller, team, rec, func(st *teamState, m *Member) error {
		if subtle.ConstantTimeCompare([]byte(st.head), []byte(ch.Prev)) != 1 {
			return fmt.Errorf("%w: the team changed since the challenge; try again", ErrTeamStale)
		}
		d, err := parseTeamInclusion(req.Device, c.cfg.Audience, team, m.Account)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrListRefused, err)
		}
		if subtle.ConstantTimeCompare(d.Key, ch.Key) != 1 || subtle.ConstantTimeCompare(d.Enc, ch.Enc) != 1 {
			return fmt.Errorf("%w: the inclusion's keys aren't the ones the challenge was for", ErrListRefused)
		}
		r := rec
		r.Prev = st.head
		if _, err := checkPasskeyJoinProof(st, c.cfg.Audience, team, r, m); err != nil {
			return fmt.Errorf("%w: %v", ErrListRefused, err)
		}
		return nil
	})
	if err != nil {
		return TeamLogView{}, err
	}
	c.mu.Lock()
	v := c.teamLogView(team, 0)
	st, _ := c.teamState(team)
	var email string
	if m := st.byID[ch.Member]; m != nil {
		email = m.Email
	}
	c.mu.Unlock()
	c.deviceAdded(team, seq, email)
	return v, nil
}

// checkPasskeyJoinProof is what a client checks of a passkey-join record
// against the state before it, and reduceTeam on replay: the assertion is by
// the passkey the list names for the member, over PasskeyJoinChallenge for
// the record's prev and the admitted device's keys.
func checkPasskeyJoinProof(st *teamState, aud, team string, r TeamRecord, m *Member) (uint32, error) {
	var p PasskeyJoinProof
	if err := decodeStrictJSON(r.Proof, &p); err != nil {
		return 0, fmt.Errorf("a passkey-join record's proof: %v", err)
	}
	if m.Rec == nil || p.Cred != m.Rec.Cred {
		return 0, errors.New("a passkey-join record's passkey isn't the one the list names for its member")
	}
	pub, err := b64.DecodeString(m.Rec.Pub)
	if err != nil {
		return 0, errors.New("the member's passkey is malformed")
	}
	d, err := parseTeamInclusion(r.Device, aud, team, m.Account)
	if err != nil {
		return 0, err
	}
	nonce, nerr := b64.DecodeString(p.Nonce)
	auth, aerr := b64.DecodeString(p.AuthenticatorData)
	client, cerr := b64.DecodeString(p.ClientDataJSON)
	sig, serr := b64.DecodeString(p.Signature)
	if nerr != nil || aerr != nil || cerr != nil || serr != nil || len(nonce) != passkeyNonceSize {
		return 0, errors.New("a passkey-join record's proof is malformed")
	}
	challenge, err := PasskeyJoinChallenge(aud, team, m.ID, r.Prev, nonce, d.Key, d.Enc)
	if err != nil {
		return 0, err
	}
	if err := verifyAssertion(pub, passkeyAssertion{AuthenticatorData: auth, ClientDataJSON: client, Signature: sig}, challenge, PasskeyRPID, PasskeyOrigins); err != nil {
		return 0, err
	}
	return signCountAfter(st.passkeyCounts[m.Rec.Pub], auth)
}

// signCountAfter is the sign count after the flags of an assertion by a
// passkey whose last nonzero count in the log was prior: 0 throughout from a
// passkey that keeps none, as synced ones do; once one counts, it must rise,
// or the passkey was copied.
func signCountAfter(prior uint32, auth []byte) (uint32, error) {
	count := binary.BigEndian.Uint32(auth[33:37])
	if (count != 0 || prior != 0) && count <= prior {
		return 0, errors.New("the passkey's sign count didn't rise: it may have been copied")
	}
	return count, nil
}

// passkeyAssertion is a passkey get() result.
type passkeyAssertion struct {
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte
}

// verifyAssertion is the edge's narrow ES256 check (fount-mail-edge
// internal/webauthn), with the origin: the authenticator signed
// authenticatorData || SHA-256(clientDataJSON); authenticatorData is for
// rpID, with the user present and verified; clientDataJSON is a webauthn.get
// over challenge from one of origins, not cross-origin. The client data is
// read by exact key, the last of a repeated key winning, as Desktop's Rust
// copy (account/passkey_join.rs) reads it.
func verifyAssertion(pubSEC1 []byte, a passkeyAssertion, challenge []byte, rpID string, origins []string) error {
	if len(pubSEC1) != p256PublicSize || pubSEC1[0] != 4 {
		return errors.New("the passkey isn't a P-256 point")
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pubSEC1)
	if err != nil {
		return errors.New("the passkey isn't a P-256 point")
	}
	if len(a.AuthenticatorData) < 37 {
		return errors.New("the authenticator data is too short")
	}
	rp := sha256.Sum256([]byte(rpID))
	if subtle.ConstantTimeCompare(a.AuthenticatorData[:32], rp[:]) != 1 {
		return errors.New("the assertion is for another relying party")
	}
	const userPresent, userVerified = 0x01, 0x04
	if flags := a.AuthenticatorData[32]; flags&userPresent == 0 || flags&userVerified == 0 {
		return errors.New("the assertion has no user presence and verification")
	}
	// One flat object of strings, booleans and nulls, valid UTF-8 with no
	// escapes, so every JSON reader reads the same keys and values: a
	// platform's client data is that.
	var cd map[string]json.RawMessage
	if !utf8.Valid(a.ClientDataJSON) || bytes.IndexByte(a.ClientDataJSON, '\\') >= 0 || json.Unmarshal(a.ClientDataJSON, &cd) != nil || cd == nil {
		return errors.New("the client data doesn't parse")
	}
	for _, v := range cd {
		if v[0] != '"' && v[0] != 't' && v[0] != 'f' && v[0] != 'n' {
			return errors.New("the client data doesn't parse")
		}
	}
	str := func(key string) (string, bool) {
		raw, ok := cd[key]
		if !ok {
			return "", false
		}
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return "", false
		}
		return s, true
	}
	if typ, ok := str("type"); !ok || typ != "webauthn.get" {
		return errors.New("the client data isn't a webauthn.get")
	}
	if got, ok := str("challenge"); !ok || subtle.ConstantTimeCompare([]byte(got), []byte(base64.RawURLEncoding.EncodeToString(challenge))) != 1 {
		return errors.New("the assertion is over another challenge: the team may have changed; try again")
	}
	if origin, ok := str("origin"); !ok || !slices.Contains(origins, origin) {
		return errors.New("the assertion is from another origin")
	}
	if raw, ok := cd["crossOrigin"]; ok {
		var cross bool
		if json.Unmarshal(raw, &cross) != nil || cross {
			return errors.New("the assertion is cross-origin")
		}
	}
	clientHash := sha256.Sum256(a.ClientDataJSON)
	digest := sha256.Sum256(append(slices.Clone(a.AuthenticatorData), clientHash[:]...))
	if !ecdsa.VerifyASN1(pub, digest[:], a.Signature) {
		return errors.New("the passkey's signature doesn't verify")
	}
	return nil
}

func passkeyStatus(err error) int {
	switch {
	case errors.Is(err, ErrStaleCoordinator), errors.Is(err, ErrNotDurable):
		return http.StatusServiceUnavailable
	}
	return statusOf(err)
}

// startPasskeyJoin is POST /v1/teams/{team}/passkey-join/challenge {key, enc}.
func (a *api) startPasskeyJoin(rw http.ResponseWriter, r *http.Request) {
	var req joinKeys
	if err := decodeStrict(r.Body, maxPasskeyBody, &req); err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	key, kerr := b64.DecodeString(req.Key)
	enc, eerr := b64.DecodeString(req.Enc)
	if kerr != nil || eerr != nil || len(key) != ed25519.PublicKeySize {
		fail(rw, http.StatusBadRequest, fmt.Errorf("%w: key and enc are 32 bytes of base64url", ErrInvalid))
		return
	}
	v, err := a.c.StartPasskeyJoin(*a.caller, r.PathValue("team"), key, enc)
	if err != nil {
		fail(rw, passkeyStatus(err), err)
		return
	}
	reply(rw, http.StatusOK, v)
}

// passkeyJoin is POST /v1/teams/{team}/passkey-join.
func (a *api) passkeyJoin(rw http.ResponseWriter, r *http.Request) {
	var req PasskeyJoinRequest
	if err := decodeStrict(r.Body, maxPasskeyBody, &req); err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	v, err := a.c.PasskeyJoin(*a.caller, r.PathValue("team"), req)
	if err != nil {
		fail(rw, passkeyStatus(err), err)
		return
	}
	reply(rw, http.StatusOK, v)
}
