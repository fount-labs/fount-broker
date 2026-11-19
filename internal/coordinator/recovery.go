package coordinator

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"
)

// Passkey recovery on the team log (cloud-worker-devices.md §4,
// docs/membership-list.md §2.3, launch-plan.md decision 19). A member who
// lost every device gets back in with the recovery passkey the list names for
// them (ListMember.Rec), after a wait any listed device can cut short:
//
//  1. recovery-start: the new device, signed in to the member's account,
//     shows a WebAuthn assertion by the member's passkey over
//     RecoveryChallenge: the team, the member, the log's head and the new
//     device's key. The head makes the assertion good for that one append.
//     The record admits nothing; it starts a RecoveryWait.
//  2. recovery-cancel: a device admitted under the member, or under an admin,
//     signs RecoveryCancelContext over the team and the start's seq. The
//     recovery ends.
//  3. recovery-done: after the wait, uncancelled, the new device posts its
//     team inclusion for the record's own seq, with the key the start named.
//     It is admitted, and the coordinator seals it the DEK wraps of the
//     member's workers as for any admission. The lost devices stay listed
//     until a list removes them.
//
// On a team an admin needn't wait: a list naming the member's new device
// admits it at once (decision 19). That is an ordinary list.
//
// The passkey provider joins the trust for this: an attacker needs the
// passkey and a sign-in to the member's account, and every listed device
// sees the wait in the log and can cancel it.

const (
	// RecoveryWait is how long a recovery waits for a listed device to
	// cancel it.
	RecoveryWait = 72 * time.Hour
	// RecoveryRPID is the passkey's relying party, as the edge's recovery
	// passkey has it.
	RecoveryRPID = "fount.sh"

	recoveryChallengeContext = "fount-team-recovery-v1\x00"
	// RecoveryCancelContext is what a cancel's signature is over, before
	// the team and the start's seq, NUL-separated.
	RecoveryCancelContext = "fount-team-recovery-cancel-v1"

	maxRecoveryBody = 16 << 10
)

// recoveryClock is the time a recovery's wait is measured against; tests
// move it.
var recoveryClock = time.Now

var (
	// ErrRecoveryWaiting is a recovery-done before its wait is over.
	ErrRecoveryWaiting = errors.New("the recovery is still waiting")
	// ErrNoRecovery is a recovery that isn't waiting: none, cancelled,
	// done, or void because the list changed the member's passkey.
	ErrNoRecovery = errors.New("no such recovery waiting")
)

// RecoveryChallenge is what the member's passkey signs to start a recovery:
// SHA-256 of the context, the team, the member, the log's head hash and the
// new device's Ed25519 key.
func RecoveryChallenge(team, member, head string, deviceKey ed25519.PublicKey) []byte {
	h := sha256.New()
	h.Write([]byte(recoveryChallengeContext))
	for _, part := range []string{team, member, head} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	h.Write(deviceKey)
	return h.Sum(nil)
}

// RecoveryCancelMessage is what a cancel signs.
func RecoveryCancelMessage(team string, start uint64) []byte {
	return []byte(RecoveryCancelContext + "\x00" + team + "\x00" + strconv.FormatUint(start, 10))
}

// recoveryStartProof is a recovery-start record's proof, as stored: enough
// for a client to check the assertion against the list before it.
type recoveryStartProof struct {
	// Key is the new device's Ed25519 key, base64url; its id is derived.
	Key               string `json:"key"`
	Cred              string `json:"cred"`
	AuthenticatorData []byte `json:"authenticatorData"`
	ClientDataJSON    []byte `json:"clientDataJSON"`
	Signature         []byte `json:"signature"`
}

// recoveryCancelProof is a recovery-cancel's: the start it ends, and the
// signing device's signature over RecoveryCancelMessage.
type recoveryCancelProof struct {
	Start  uint64 `json:"start"`
	Device string `json:"device"`
	Sig    []byte `json:"sig"`
}

// recoveryDoneProof is a recovery-done's: the start it completes.
type recoveryDoneProof struct {
	Start uint64 `json:"start"`
}

// Recovery is one recovery as the log has it.
type Recovery struct {
	Start   uint64    `json:"start"`
	Member  string    `json:"member"`
	Account string    `json:"account"`
	Device  string    `json:"device"`
	Started time.Time `json:"started"`
	// EndsAt is when it may complete: Desktop's countdown.
	EndsAt time.Time `json:"endsAt"`
	// State is waiting, ready (the wait is over), cancelled, done or void.
	State string `json:"state"`
	// Cred is the passkey it started with, which must still be the
	// member's.
	Cred string `json:"-"`
	Key  []byte `json:"-"`
}

const (
	recoveryWaiting   = "waiting"
	recoveryReady     = "ready"
	recoveryCancelled = "cancelled"
	recoveryDone      = "done"
	recoveryVoid      = "void"
)

// recoveries reads every recovery in a team's log, as of now under st.
// Called with c.mu held.
func recoveries(t *Team, st *teamState, now time.Time) ([]Recovery, error) {
	var out []Recovery
	byStart := map[uint64]int{}
	for _, e := range t.Log {
		if e.Record == nil {
			continue
		}
		var r TeamRecord
		if err := json.Unmarshal(e.Record, &r); err != nil {
			return nil, err
		}
		switch r.Kind {
		case RecordRecoveryStart:
			var p recoveryStartProof
			if err := json.Unmarshal(r.Proof, &p); err != nil {
				return nil, err
			}
			key, err := b64.DecodeString(p.Key)
			if err != nil || len(key) != ed25519.PublicKeySize {
				return nil, errors.New("a recovery-start names no key")
			}
			started := time.Unix(r.At, 0).UTC()
			byStart[r.Seq] = len(out)
			out = append(out, Recovery{Start: r.Seq, Member: r.Member, Account: r.Account, Device: deviceID(key),
				Started: started, EndsAt: started.Add(RecoveryWait), State: recoveryWaiting, Cred: p.Cred, Key: key})
		case RecordRecoveryCancel, RecordRecoveryDone:
			var p recoveryDoneProof
			if err := json.Unmarshal(r.Proof, &p); err != nil {
				return nil, err
			}
			if i, ok := byStart[p.Start]; ok {
				out[i].State = map[string]string{RecordRecoveryCancel: recoveryCancelled, RecordRecoveryDone: recoveryDone}[r.Kind]
			}
		}
	}
	for i := range out {
		r := &out[i]
		if r.State != recoveryWaiting {
			continue
		}
		m := st.byID[r.Member]
		switch {
		case m == nil || m.Account != r.Account || m.Rec == nil || m.Rec.Cred != r.Cred:
			r.State = recoveryVoid
		case !now.Before(r.EndsAt):
			r.State = recoveryReady
		}
	}
	return out, nil
}

// StartRecovery appends a recovery-start for member, by the caller's new
// device, on the passkey's assertion over RecoveryChallenge at the log's
// head. It returns the recovery.
func (c *Coordinator) StartRecovery(caller Caller, team, member string, a passkeyAssertion) (Recovery, error) {
	if len(caller.DeviceKey) != ed25519.PublicKeySize {
		return Recovery{}, fmt.Errorf("%w: the channel names no device key", ErrListRefused)
	}
	proof := recoveryStartProof{Key: b64.EncodeToString(caller.DeviceKey), Cred: a.Cred,
		AuthenticatorData: a.AuthenticatorData, ClientDataJSON: a.ClientDataJSON, Signature: a.Signature}
	raw, err := json.Marshal(proof)
	if err != nil {
		return Recovery{}, err
	}
	rec := TeamRecord{Kind: RecordRecoveryStart, Member: member, Account: caller.Account, Proof: raw}
	var seq uint64
	_, err = c.appendRecord(caller, team, rec, func(st *teamState, m *Member) error {
		refuse := func(format string, args ...any) error {
			return fmt.Errorf("%w: %s", ErrListRefused, fmt.Sprintf(format, args...))
		}
		if m.Rec == nil || subtle.ConstantTimeCompare([]byte(m.Rec.Cred), []byte(a.Cred)) != 1 {
			return refuse("member %s has no recovery passkey %.40q", m.ID, a.Cred)
		}
		if st.byDevice[caller.Device] != nil {
			return refuse("device %s is admitted already", caller.Device)
		}
		all, err := recoveries(c.state.Teams[team], st, recoveryClock())
		if err != nil {
			return err
		}
		if slices.ContainsFunc(all, func(r Recovery) bool {
			return r.Member == m.ID && (r.State == recoveryWaiting || r.State == recoveryReady)
		}) {
			return refuse("member %s has a recovery waiting already", m.ID)
		}
		pub, err := b64.DecodeString(m.Rec.Pub)
		if err != nil {
			return refuse("member %s's passkey is malformed", m.ID)
		}
		challenge := RecoveryChallenge(team, m.ID, st.head, caller.DeviceKey)
		if err := verifyAssertion(pub, a, challenge, RecoveryRPID); err != nil {
			return refuse("%v", err)
		}
		seq = st.seq + 1
		return nil
	})
	if err != nil {
		return Recovery{}, err
	}
	return c.recovery(team, seq)
}

// CancelRecovery appends a recovery-cancel for the recovery started at
// start, signed by the caller's admitted device: the member's or an admin's.
func (c *Coordinator) CancelRecovery(caller Caller, team string, start uint64, sig []byte) (Recovery, error) {
	r, err := c.recovery(team, start)
	if err != nil {
		return Recovery{}, err
	}
	raw, err := json.Marshal(recoveryCancelProof{Start: start, Device: caller.Device, Sig: sig})
	if err != nil {
		return Recovery{}, err
	}
	rec := TeamRecord{Kind: RecordRecoveryCancel, Member: r.Member, Account: r.Account, Proof: raw}
	_, err = c.appendRecord(caller, team, rec, func(st *teamState, m *Member) error {
		d, by := st.device(caller.Device)
		switch {
		case by == nil || by.Account != caller.Account:
			return fmt.Errorf("%w: only a listed device cancels a recovery", ErrNotAdmin)
		case by.ID != m.ID && by.Role != RoleAdmin:
			return fmt.Errorf("%w: only the member's own devices or an admin's cancel their recovery", ErrNotAdmin)
		case !ed25519.Verify(d.Key, RecoveryCancelMessage(team, start), sig):
			return fmt.Errorf("%w: the cancel's signature doesn't verify", ErrListRefused)
		}
		return c.recoveryIs(team, st, start, recoveryWaiting, recoveryReady)
	})
	if err != nil {
		return Recovery{}, err
	}
	return c.recovery(team, start)
}

// FinishRecovery appends a recovery-done once the wait is over: it admits
// the caller's device, which must be the one the start named, on its
// inclusion for this record.
func (c *Coordinator) FinishRecovery(caller Caller, team string, start uint64, inclusion string) (Recovery, error) {
	r, err := c.recovery(team, start)
	if err != nil {
		return Recovery{}, err
	}
	raw, err := json.Marshal(recoveryDoneProof{Start: start})
	if err != nil {
		return Recovery{}, err
	}
	rec := TeamRecord{Kind: RecordRecoveryDone, Member: r.Member, Account: caller.Account, Device: inclusion, Proof: raw}
	_, err = c.appendRecord(caller, team, rec, func(st *teamState, m *Member) error {
		if err := c.recoveryIs(team, st, start, recoveryReady); err != nil {
			return err
		}
		if caller.Device != r.Device || subtle.ConstantTimeCompare(caller.DeviceKey, r.Key) != 1 {
			return fmt.Errorf("%w: the recovery was started by another device", ErrListRefused)
		}
		return nil
	})
	if err != nil {
		return Recovery{}, err
	}
	return c.recovery(team, start)
}

// recoveryIs checks that the recovery started at start is in one of states
// under st. Called with c.mu held.
func (c *Coordinator) recoveryIs(team string, st *teamState, start uint64, states ...string) error {
	all, err := recoveries(c.state.Teams[team], st, recoveryClock())
	if err != nil {
		return err
	}
	i := slices.IndexFunc(all, func(r Recovery) bool { return r.Start == start })
	switch {
	case i < 0:
		return ErrNoRecovery
	case all[i].State == recoveryWaiting && slices.Contains(states, recoveryReady) && !slices.Contains(states, recoveryWaiting):
		return fmt.Errorf("%w: until %s", ErrRecoveryWaiting, all[i].EndsAt.Format(time.RFC3339))
	case !slices.Contains(states, all[i].State):
		return fmt.Errorf("%w: it is %s", ErrNoRecovery, all[i].State)
	}
	return nil
}

// recovery is the recovery started at start, as the log has it now.
func (c *Coordinator) recovery(team string, start uint64) (Recovery, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.state.Teams[team]
	if !ok {
		return Recovery{}, ErrNoTeam
	}
	st, err := c.teamState(team)
	if err != nil {
		return Recovery{}, err
	}
	all, err := recoveries(t, st, recoveryClock())
	if err != nil {
		return Recovery{}, err
	}
	for _, r := range all {
		if r.Start == start {
			return r, nil
		}
	}
	return Recovery{}, ErrNoRecovery
}

// Recoveries is what the caller may see of a team's recoveries: all of
// them for a listed device, or the ones its own device started.
func (c *Coordinator) Recoveries(caller Caller, team string) ([]Recovery, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.state.Teams[team]
	if !ok {
		return nil, ErrNoTeam
	}
	st, err := c.teamState(team)
	if err != nil {
		return nil, ErrNoTeam
	}
	all, err := recoveries(t, st, recoveryClock())
	if err != nil {
		return nil, err
	}
	if m := st.byDevice[caller.Device]; m != nil && m.Account == caller.Account {
		return all, nil
	}
	mine := []Recovery{}
	for _, r := range all {
		if r.Device == caller.Device && r.Account == caller.Account {
			mine = append(mine, r)
		}
	}
	if len(mine) == 0 && !slices.ContainsFunc(st.members, func(m *Member) bool { return m.Account == caller.Account }) {
		return nil, ErrNoTeam
	}
	return mine, nil
}

// RecoverableTeam is a team where the caller's account is a member with a
// recovery passkey: what a device that lost the others recovers into.
type RecoverableTeam struct {
	Team   string `json:"team"`
	Member string `json:"member"`
	Cred   string `json:"cred"`
	// Seq and Head are the log's, which the challenge is over.
	Seq       uint64 `json:"seq"`
	Head      string `json:"head"`
	Challenge []byte `json:"challenge"`
}

// RecoverableTeams are the teams the caller's account can recover into.
func (c *Coordinator) RecoverableTeams(caller Caller) []RecoverableTeam {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []RecoverableTeam{}
	ids := make([]string, 0, len(c.state.Teams))
	for id := range c.state.Teams {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		st, err := c.teamState(id)
		if err != nil {
			continue
		}
		for _, m := range st.members {
			if m.Account == caller.Account && m.Rec != nil {
				out = append(out, RecoverableTeam{Team: id, Member: m.ID, Cred: m.Rec.Cred, Seq: st.seq, Head: st.head,
					Challenge: RecoveryChallenge(id, m.ID, st.head, caller.DeviceKey)})
			}
		}
	}
	return out
}

// passkeyAssertion is a passkey get() result, as Desktop forwards it.
type passkeyAssertion struct {
	Cred              string `json:"cred"`
	AuthenticatorData []byte `json:"authenticatorData"`
	ClientDataJSON    []byte `json:"clientDataJSON"`
	Signature         []byte `json:"signature"`
}

// verifyAssertion is the edge's narrow ES256 check (fount-mail-edge
// internal/webauthn): the authenticator signed authenticatorData ||
// SHA-256(clientDataJSON); clientDataJSON is a webauthn.get over challenge;
// authenticatorData is for rpID, with the user present and verified.
func verifyAssertion(pubSEC1 []byte, a passkeyAssertion, challenge []byte, rpID string) error {
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
	var cd struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(a.ClientDataJSON, &cd); err != nil {
		return errors.New("the client data doesn't parse")
	}
	if cd.Type != "webauthn.get" {
		return errors.New("the client data isn't a webauthn.get")
	}
	if subtle.ConstantTimeCompare([]byte(cd.Challenge), []byte(base64.RawURLEncoding.EncodeToString(challenge))) != 1 {
		return errors.New("the assertion is over another challenge: the log may have moved; sign again")
	}
	clientHash := sha256.Sum256(a.ClientDataJSON)
	digest := sha256.Sum256(append(slices.Clone(a.AuthenticatorData), clientHash[:]...))
	if !ecdsa.VerifyASN1(pub, digest[:], a.Signature) {
		return errors.New("the passkey's signature doesn't verify")
	}
	return nil
}

// The routes. Each is the channel's caller's; the records' proofs authorize
// them, not a role.
//
//	GET  /v1/recovery/teams                      the teams the caller's account can recover into, each with its challenge
//	GET  /v1/teams/{team}/recovery               the team's recoveries: all for a listed device, a new device's own
//	POST /v1/teams/{team}/recovery               {member, cred, authenticatorData, clientDataJSON, signature}: start
//	POST /v1/teams/{team}/recovery/{seq}/cancel  {sig}: cancel, by the member's or an admin's device
//	POST /v1/teams/{team}/recovery/{seq}/done    {device}: the new device's inclusion, after the wait
func (a *api) recoveryRoutes(mux router) {
	mux.HandleFunc("GET /v1/recovery/teams", a.recoverableTeams)
	mux.HandleFunc("GET /v1/teams/{team}/recovery", a.listRecoveries)
	mux.HandleFunc("POST /v1/teams/{team}/recovery", a.startRecovery)
	mux.HandleFunc("POST /v1/teams/{team}/recovery/{seq}/cancel", a.cancelRecovery)
	mux.HandleFunc("POST /v1/teams/{team}/recovery/{seq}/done", a.finishRecovery)
}

func recoveryStatus(err error) int {
	switch {
	case errors.Is(err, ErrNoRecovery):
		return http.StatusNotFound
	case errors.Is(err, ErrRecoveryWaiting):
		return http.StatusConflict
	case errors.Is(err, ErrStaleCoordinator):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrNotDurable):
		return http.StatusServiceUnavailable
	}
	return statusOf(err)
}

func (a *api) recoverableTeams(rw http.ResponseWriter, _ *http.Request) {
	reply(rw, http.StatusOK, map[string]any{"teams": a.c.RecoverableTeams(*a.caller)})
}

func (a *api) listRecoveries(rw http.ResponseWriter, r *http.Request) {
	all, err := a.c.Recoveries(*a.caller, r.PathValue("team"))
	if err != nil {
		fail(rw, recoveryStatus(err), err)
		return
	}
	reply(rw, http.StatusOK, map[string]any{"recoveries": all})
}

func (a *api) startRecovery(rw http.ResponseWriter, r *http.Request) {
	var req struct {
		Member string `json:"member"`
		passkeyAssertion
	}
	if err := decodeStrict(r.Body, maxRecoveryBody, &req); err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	rec, err := a.c.StartRecovery(*a.caller, r.PathValue("team"), req.Member, req.passkeyAssertion)
	if err != nil {
		fail(rw, recoveryStatus(err), err)
		return
	}
	reply(rw, http.StatusOK, rec)
}

func pathSeq(r *http.Request) (uint64, error) {
	n, err := strconv.ParseUint(r.PathValue("seq"), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: seq must be an entry number", ErrInvalid)
	}
	return n, nil
}

func (a *api) cancelRecovery(rw http.ResponseWriter, r *http.Request) {
	var req struct {
		Sig []byte `json:"sig"`
	}
	seq, err := pathSeq(r)
	if err == nil {
		err = decodeStrict(r.Body, maxRecoveryBody, &req)
	}
	if err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	rec, err := a.c.CancelRecovery(*a.caller, r.PathValue("team"), seq, req.Sig)
	if err != nil {
		fail(rw, recoveryStatus(err), err)
		return
	}
	reply(rw, http.StatusOK, rec)
}

func (a *api) finishRecovery(rw http.ResponseWriter, r *http.Request) {
	var req struct {
		Device string `json:"device"`
	}
	seq, err := pathSeq(r)
	if err == nil {
		err = decodeStrict(r.Body, maxRecoveryBody, &req)
	}
	if err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	rec, err := a.c.FinishRecovery(*a.caller, r.PathValue("team"), seq, req.Device)
	if err != nil {
		fail(rw, recoveryStatus(err), err)
		return
	}
	reply(rw, http.StatusOK, rec)
}
