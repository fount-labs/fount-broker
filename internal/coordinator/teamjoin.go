package coordinator

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"time"
)

// A second device of the same member (launch-plan decision 26,
// docs/membership-list.md §2.3, cloud-worker-devices.md §2.3). It doesn't
// join by email: the account's mailbox is often its sign-in too. Instead:
//
//  1. The new device, signed in to the member's account, asks to join
//     (POST /teams/{team}/joins {key, enc}). The coordinator answers a join
//     id and a nonce, and keeps the request for joinLifetime, in memory.
//  2. A device already admitted under the member lists the requests
//     (GET /teams/{team}/joins). Both devices show JoinCode over the join id,
//     nonce and the new keys; the person compares them.
//  3. The admitted device signs JoinMessage and posts it (…/approve).
//  4. The new device sees it approved (GET …/joins/{join}), signs its team
//     inclusion for the next entry and accepts (…/accept). The coordinator
//     appends a join record whose proof is the approval, which any client
//     checks against the state before it, and seals the new device its wraps.
//
// The other way in is the member's passkey, at once (passkeyjoin.go).

const (
	JoinContext     = "fount-team-join-v1\x00"
	JoinCodeContext = "fount-team-join-code-v1\x00"
	joinLifetime    = 15 * time.Minute
	joinNonceSize   = 32
	// maxJoins bounds the requests kept: per member, and in all.
	maxMemberJoins = 3
	maxJoins       = 1000
)

// JoinProof is a join record's proof: the approving device and its
// signature over JoinMessage.
type JoinProof struct {
	Join     string `json:"join"`
	Nonce    string `json:"nonce"`
	Approver string `json:"approver"`
	Sig      string `json:"sig"`
}

// JoinMessage is what an admitted device signs to approve a new one of its
// member's: the coordinator, team, member, request, and the new device's
// Ed25519 and X25519 keys.
func JoinMessage(aud, team, member, join string, nonce, key, enc []byte) ([]byte, error) {
	return lengthPrefixed(JoinContext, []byte(aud), []byte(team), []byte(member), []byte(join), nonce, key, enc)
}

// JoinCode is the six digits both devices show for a request, so the person
// can see the request the old device approves is the new device's.
func JoinCode(join string, nonce, key, enc []byte) string {
	msg, _ := lengthPrefixed(JoinCodeContext, []byte(join), nonce, key, enc)
	sum := sha256.Sum256(msg)
	return fmt.Sprintf("%06d", binary.BigEndian.Uint32(sum[:4])%1_000_000)
}

// joinRequest is one device asking to join as its account's member.
type joinRequest struct {
	ID, Team, Member, Account, Device string
	Key, Enc, Nonce                   []byte
	Expires                           time.Time
	Approver                          string
	Sig                               []byte
}

// JoinView is a join request as the member's admitted devices see it.
type JoinView struct {
	Join      string    `json:"join"`
	Device    string    `json:"device"`
	Key       string    `json:"key"`
	Enc       string    `json:"enc"`
	Nonce     string    `json:"nonce"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// JoinStatus is a request as the device that made it sees it.
type JoinStatus struct {
	Join      string    `json:"join"`
	Member    string    `json:"member"`
	Nonce     string    `json:"nonce"`
	State     string    `json:"state"` // waiting or approved
	ExpiresAt time.Time `json:"expiresAt"`
	// Seq and Head are the team's, for the inclusion the accept needs.
	Seq  uint64 `json:"seq"`
	Head string `json:"head"`
}

// dropExpiredJoins forgets requests past their time. Called with c.mu held.
func (c *Coordinator) dropExpiredJoins(now time.Time) {
	for id, j := range c.joins {
		if !now.Before(j.Expires) {
			delete(c.joins, id)
		}
	}
}

// StartJoin is a device asking to join as its account's member of team.
func (c *Coordinator) StartJoin(caller Caller, team string, key, enc []byte) (JoinStatus, error) {
	if !ed25519.PublicKey(key).Equal(caller.DeviceKey) || deviceID(key) != caller.Device {
		return JoinStatus{}, fmt.Errorf("%w: a device asks to join with its own key", ErrInvalid)
	}
	if len(enc) != 32 {
		return JoinStatus{}, fmt.Errorf("%w: enc is a 32-byte X25519 key", ErrInvalid)
	}
	if err := checkX25519(enc); err != nil {
		return JoinStatus{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.state.Teams[team]; !ok {
		return JoinStatus{}, ErrNoTeam
	}
	st, err := c.teamState(team)
	if err != nil {
		return JoinStatus{}, ErrNoTeam
	}
	var m *Member
	for _, o := range st.members {
		if o.Account != "" && o.Account == caller.Account {
			m = o
		}
	}
	if m == nil {
		return JoinStatus{}, ErrNoTeam
	}
	if _, holder := st.device(caller.Device); holder != nil {
		return JoinStatus{}, fmt.Errorf("%w: this device is admitted already", ErrListRefused)
	}
	if len(m.Devices) >= MaxMemberDevices {
		return JoinStatus{}, fmt.Errorf("%w: member %s has %d devices", ErrListRefused, m.ID, MaxMemberDevices)
	}
	c.dropExpiredJoins(now)
	mine := 0
	for _, j := range c.joins {
		if j.Team == team && j.Member == m.ID {
			mine++
		}
	}
	if mine >= maxMemberJoins || len(c.joins) >= maxJoins {
		return JoinStatus{}, fmt.Errorf("%w: too many devices are waiting to join; try again in a few minutes", ErrTooManyUngranted)
	}
	id, err := newID("jn")
	if err != nil {
		return JoinStatus{}, err
	}
	nonce := make([]byte, joinNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return JoinStatus{}, err
	}
	j := &joinRequest{ID: id, Team: team, Member: m.ID, Account: caller.Account, Device: caller.Device,
		Key: slices.Clone(key), Enc: slices.Clone(enc), Nonce: nonce, Expires: now.Add(joinLifetime)}
	c.joins[id] = j
	return c.joinStatus(j, st), nil
}

func (c *Coordinator) joinStatus(j *joinRequest, st *teamState) JoinStatus {
	state := "waiting"
	if j.Sig != nil {
		state = "approved"
	}
	return JoinStatus{Join: j.ID, Member: j.Member, Nonce: b64.EncodeToString(j.Nonce), State: state, ExpiresAt: j.Expires.UTC(), Seq: st.seq, Head: st.head}
}

// PendingJoins are the requests waiting for one of the caller's member's
// admitted devices.
func (c *Coordinator) PendingJoins(caller Caller, team string) ([]JoinView, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	m, _, err := c.requireMember(caller, team)
	if err != nil {
		return nil, err
	}
	c.dropExpiredJoins(time.Now())
	out := []JoinView{}
	for _, id := range slices.Sorted(maps.Keys(c.joins)) {
		j := c.joins[id]
		if j.Team == team && j.Member == m.ID && j.Sig == nil {
			out = append(out, JoinView{Join: j.ID, Device: j.Device, Key: b64.EncodeToString(j.Key), Enc: b64.EncodeToString(j.Enc), Nonce: b64.EncodeToString(j.Nonce), ExpiresAt: j.Expires.UTC()})
		}
	}
	return out, nil
}

// ApproveJoin records an admitted device's approval of a request of its own
// member's. The approval is checked again when the record is appended,
// against the state then.
func (c *Coordinator) ApproveJoin(caller Caller, team, join string, sig []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	m, _, err := c.requireMember(caller, team)
	if err != nil {
		return err
	}
	c.dropExpiredJoins(time.Now())
	j := c.joins[join]
	if j == nil || j.Team != team || j.Member != m.ID {
		return fmt.Errorf("%w: no such request to join; it may have expired", ErrNotFound)
	}
	if j.Sig != nil {
		return fmt.Errorf("%w: this request was approved already", ErrListRefused)
	}
	msg, err := JoinMessage(c.cfg.Audience, team, j.Member, j.ID, j.Nonce, j.Key, j.Enc)
	if err != nil {
		return err
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(caller.DeviceKey, msg, sig) {
		return fmt.Errorf("%w: the approval isn't this device's signature over the request", ErrListRefused)
	}
	j.Approver, j.Sig = caller.Device, slices.Clone(sig)
	return nil
}

// DenyJoin drops a request, for one of its member's admitted devices.
func (c *Coordinator) DenyJoin(caller Caller, team, join string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	m, _, err := c.requireMember(caller, team)
	if err != nil {
		return err
	}
	if j := c.joins[join]; j != nil && j.Team == team && j.Member == m.ID {
		delete(c.joins, join)
	}
	return nil
}

// JoinStatusOf is a request, for the device that made it.
func (c *Coordinator) JoinStatusOf(caller Caller, team, join string) (JoinStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dropExpiredJoins(time.Now())
	j := c.joins[join]
	if j == nil || j.Team != team || j.Device != caller.Device || j.Account != caller.Account {
		return JoinStatus{}, fmt.Errorf("%w: no such request to join; it may have expired", ErrNotFound)
	}
	st, err := c.teamState(team)
	if err != nil {
		return JoinStatus{}, err
	}
	return c.joinStatus(j, st), nil
}

// AcceptJoin appends the join record for an approved request: the device
// that made it, with its inclusion for the record's entry.
func (c *Coordinator) AcceptJoin(caller Caller, team, join, inclusion string) (TeamLogView, error) {
	c.mu.Lock()
	j := c.joins[join]
	var req joinRequest
	if j != nil {
		req = *j
	}
	c.mu.Unlock()
	if j == nil || req.Team != team || req.Device != caller.Device || req.Account != caller.Account || !time.Now().Before(req.Expires) {
		return TeamLogView{}, fmt.Errorf("%w: no such request to join; it may have expired", ErrNotFound)
	}
	if req.Sig == nil {
		return TeamLogView{}, fmt.Errorf("%w: no device of yours has approved this one yet", ErrListRefused)
	}
	proof, err := json.Marshal(JoinProof{Join: req.ID, Nonce: b64.EncodeToString(req.Nonce), Approver: req.Approver, Sig: b64.EncodeToString(req.Sig)})
	if err != nil {
		return TeamLogView{}, err
	}
	rec := TeamRecord{Kind: RecordJoin, Member: req.Member, Account: caller.Account, Device: inclusion, Proof: proof}
	seq, err := c.appendRecord(caller, team, rec, func(st *teamState, m *Member) error {
		d, err := parseTeamInclusion(inclusion, c.cfg.Audience, team, m.Account)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrListRefused, err)
		}
		if subtle.ConstantTimeCompare(d.Key, req.Key) != 1 || subtle.ConstantTimeCompare(d.Enc, req.Enc) != 1 {
			return fmt.Errorf("%w: the inclusion's keys aren't the ones approved", ErrListRefused)
		}
		return nil
	})
	if err != nil {
		return TeamLogView{}, err
	}
	c.mu.Lock()
	delete(c.joins, join)
	v := c.teamLogView(team, 0)
	c.mu.Unlock()
	c.admitted(team, seq)
	return v, nil
}

// checkJoinProof is what a client checks of a join record against the state
// before it, and reduceTeam on replay: the approver was admitted under the
// same member, and signed JoinMessage over the record's device's keys.
func checkJoinProof(st *teamState, aud, team string, r TeamRecord, m *Member) error {
	var p JoinProof
	if err := decodeStrictJSON(r.Proof, &p); err != nil {
		return fmt.Errorf("a join record's proof: %v", err)
	}
	approver, holder := st.device(p.Approver)
	if holder == nil || holder.ID != m.ID {
		return errors.New("a join record's approver isn't a device of its member")
	}
	d, err := parseTeamInclusion(r.Device, aud, team, m.Account)
	if err != nil {
		return err
	}
	nonce, nerr := b64.DecodeString(p.Nonce)
	sig, serr := b64.DecodeString(p.Sig)
	if nerr != nil || serr != nil || len(nonce) != joinNonceSize || checkID("join", p.Join) != nil {
		return errors.New("a join record's proof is malformed")
	}
	msg, err := JoinMessage(aud, team, m.ID, p.Join, nonce, d.Key, d.Enc)
	if err != nil {
		return err
	}
	if !ed25519.Verify(approver.Key, msg, sig) {
		return errors.New("a join record's approval isn't its approver's signature")
	}
	return nil
}

type joinKeys struct {
	Key string `json:"key"`
	Enc string `json:"enc"`
}

// startJoin is POST /v1/teams/{team}/joins {key, enc}.
func (a *api) startJoin(rw http.ResponseWriter, r *http.Request) {
	var req joinKeys
	if err := decodeStrict(r.Body, maxTeamBody, &req); err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	key, kerr := b64.DecodeString(req.Key)
	enc, eerr := b64.DecodeString(req.Enc)
	if kerr != nil || eerr != nil || len(key) != ed25519.PublicKeySize {
		fail(rw, http.StatusBadRequest, fmt.Errorf("%w: key and enc are 32 bytes of base64url", ErrInvalid))
		return
	}
	v, err := a.c.StartJoin(*a.caller, r.PathValue("team"), key, enc)
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusOK, v)
}

// pendingJoins is GET /v1/teams/{team}/joins.
func (a *api) pendingJoins(rw http.ResponseWriter, r *http.Request) {
	v, err := a.c.PendingJoins(*a.caller, r.PathValue("team"))
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusOK, map[string][]JoinView{"joins": v})
}

// approveJoin is POST /v1/teams/{team}/joins/{join}/approve {sig}.
func (a *api) approveJoin(rw http.ResponseWriter, r *http.Request) {
	var req struct {
		Sig string `json:"sig"`
	}
	if err := decodeStrict(r.Body, maxTeamBody, &req); err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	sig, err := b64.DecodeString(req.Sig)
	if err != nil {
		fail(rw, http.StatusBadRequest, fmt.Errorf("%w: sig is base64url", ErrInvalid))
		return
	}
	if err := a.c.ApproveJoin(*a.caller, r.PathValue("team"), r.PathValue("join"), sig); err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

// denyJoin is POST /v1/teams/{team}/joins/{join}/deny.
func (a *api) denyJoin(rw http.ResponseWriter, r *http.Request) {
	if err := a.c.DenyJoin(*a.caller, r.PathValue("team"), r.PathValue("join")); err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

// joinStatus is GET /v1/teams/{team}/joins/{join}.
func (a *api) joinStatus(rw http.ResponseWriter, r *http.Request) {
	v, err := a.c.JoinStatusOf(*a.caller, r.PathValue("team"), r.PathValue("join"))
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusOK, v)
}

// acceptJoin is POST /v1/teams/{team}/joins/{join}/accept {device}.
func (a *api) acceptJoin(rw http.ResponseWriter, r *http.Request) {
	var req struct {
		Device string `json:"device"`
	}
	if err := decodeStrict(r.Body, maxTeamBody, &req); err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	v, err := a.c.AcceptJoin(*a.caller, r.PathValue("team"), r.PathValue("join"), req.Device)
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusOK, v)
}
