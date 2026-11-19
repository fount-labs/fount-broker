package coordinator

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// A member's passkey vouches for their own team (security review
// 2026-11-19, M3; decided 2026-11-19). A solo account's team id is its
// account id, and its first list is accepted from any device signed in to
// the account, so whoever can mint a sign-in for the account (fount-infra)
// could make that team first, with their own device in it. The member's
// passkey, which no server holds, signs the team's starting point: a
// passkey-vouch record whose proof is a WebAuthn assertion over
// PasskeyVouchChallenge, by the passkey the list names for the member. A new
// computer of the account joins its own team only if the team carries a vouch
// by the passkey it trusts (Desktop's team_log.rs and passkey_join.rs).
//
// The challenge has no nonce: the vouch is a statement about the team's
// first entry, which never changes, so one vouch per passkey is enough and a
// second by the same passkey is refused. The record is checked on append and
// on every replay, here and in Desktop.

// PasskeyVouchContext starts what a vouch's challenge is a hash of.
const PasskeyVouchContext = "fount-team-vouch-v1\x00"

// RecordPasskeyVouch is a member's passkey vouching for their own team.
const RecordPasskeyVouch = "passkey-vouch"

// PasskeyVouchChallenge is what the member's passkey signs to vouch for their
// own team: SHA-256 of the context, then the coordinator, team, member and
// the hash of the team's first entry (its first list), length-prefixed.
func PasskeyVouchChallenge(aud, team, member, start string) ([]byte, error) {
	msg, err := lengthPrefixed(PasskeyVouchContext, []byte(aud), []byte(team), []byte(member), []byte(start))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(msg)
	return sum[:], nil
}

// PasskeyVouchProof is a passkey-vouch record's proof, each field base64url:
// the passkey's assertion over PasskeyVouchChallenge.
type PasskeyVouchProof struct {
	Cred              string `json:"cred"`
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
}

// ErrVouched is a passkey that vouched for the team already.
var ErrVouched = errors.New("your passkey vouched for this team already")

// checkPasskeyVouchProof is what a client checks of a passkey-vouch record
// against the state before it, and reduceTeam on replay: the team is the
// member's own, and the assertion is by the passkey the list names for them
// over PasskeyVouchChallenge for the team's first entry. It returns the
// assertion's sign count, held to the same rise as a passkey join's.
func checkPasskeyVouchProof(st *teamState, aud, team string, r TeamRecord, m *Member) (uint32, error) {
	if m.Account == "" || team != m.Account {
		return 0, errors.New("a passkey vouches only for its member's own team")
	}
	if r.Device != "" {
		return 0, errors.New("a passkey-vouch admits no device")
	}
	var p PasskeyVouchProof
	if err := decodeStrictJSON(r.Proof, &p); err != nil {
		return 0, fmt.Errorf("a passkey-vouch record's proof: %v", err)
	}
	if m.Rec == nil || p.Cred != m.Rec.Cred {
		return 0, errors.New("a passkey-vouch record's passkey isn't the one the list names for its member")
	}
	if st.vouched[m.Rec.Pub] {
		return 0, ErrVouched
	}
	pub, err := b64.DecodeString(m.Rec.Pub)
	if err != nil {
		return 0, errors.New("the member's passkey is malformed")
	}
	auth, aerr := b64.DecodeString(p.AuthenticatorData)
	client, cerr := b64.DecodeString(p.ClientDataJSON)
	sig, serr := b64.DecodeString(p.Signature)
	if aerr != nil || cerr != nil || serr != nil || st.start == "" {
		return 0, errors.New("a passkey-vouch record's proof is malformed")
	}
	challenge, err := PasskeyVouchChallenge(aud, team, m.ID, st.start)
	if err != nil {
		return 0, err
	}
	if err := verifyAssertion(pub, passkeyAssertion{AuthenticatorData: auth, ClientDataJSON: client, Signature: sig}, challenge, PasskeyRPID, PasskeyOrigins); err != nil {
		return 0, err
	}
	return checkSignCount(st, m, auth)
}

// PasskeyVouchRequest is POST /v1/teams/{team}/passkey-vouch: the passkey's
// assertion over PasskeyVouchChallenge, every byte string base64url.
type PasskeyVouchRequest = PasskeyVouchProof

// PasskeyVouch appends a passkey-vouch record for the caller's member: the
// caller is a device of theirs the team admits, on their own team.
func (c *Coordinator) PasskeyVouch(caller Caller, team string, req PasskeyVouchRequest) (TeamLogView, error) {
	proof, err := json.Marshal(req)
	if err != nil {
		return TeamLogView{}, err
	}
	c.mu.Lock()
	st, err := c.teamState(team)
	var member string
	if err == nil {
		if _, m := st.device(caller.Device); m != nil && m.Account == caller.Account {
			member = m.ID
		}
	}
	c.mu.Unlock()
	if err != nil {
		return TeamLogView{}, ErrNoTeam
	}
	if member == "" {
		return TeamLogView{}, fmt.Errorf("%w: only a device the team admits vouches for it", ErrListRefused)
	}
	rec := TeamRecord{Kind: RecordPasskeyVouch, Member: member, Account: caller.Account, Proof: proof}
	if _, err := c.appendRecord(caller, team, rec, func(st *teamState, m *Member) error {
		if _, held := st.device(caller.Device); held != m {
			return fmt.Errorf("%w: only a device the team admits vouches for it", ErrListRefused)
		}
		r := rec
		r.Prev = st.head
		if _, err := checkPasskeyVouchProof(st, c.cfg.Audience, team, r, m); err != nil {
			return fmt.Errorf("%w: %v", ErrListRefused, err)
		}
		return nil
	}); err != nil {
		return TeamLogView{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.teamLogView(team, 0), nil
}

// passkeyVouch is POST /v1/teams/{team}/passkey-vouch.
func (a *api) passkeyVouch(rw http.ResponseWriter, r *http.Request) {
	var req PasskeyVouchRequest
	if err := decodeStrict(r.Body, maxPasskeyBody, &req); err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	v, err := a.c.PasskeyVouch(*a.caller, r.PathValue("team"), req)
	if err != nil {
		fail(rw, passkeyStatus(err), err)
		return
	}
	reply(rw, http.StatusOK, v)
}
