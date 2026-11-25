package coordinator

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"
)

// Delayed recovery (security review 2026-11-23): an admin who lost every
// computer while the log still lists one of them gets back in with their
// passkey after a wait, as Apple's and Google's account recovery do.
//
// A device an admin's passkey added signs no list while any admin has a
// device a list included (teamsigner.go): that device includes it. When the
// only such devices are lost, the new one starts a recovery: a
// recovery-start record, its proof the device's own signature over
// RecoveryChallenge for the log's head. Every admin is emailed at once.
// RecoveryDelay after the record the device signs lists like a listed one,
// so it can sign the list that drops the lost computers and includes it.
//
// The delay is counted three ways, and all three must have passed: the
// list's iat against the record's at (which Desktop checks too), the
// coordinator's clock against at, and the coordinator's own count of the
// time since it took the record (RecoveryWait). Only the count holds up
// against the host: at and the clock are the guest's wall time, which the
// host sets, so a clock set back for the one request that writes the record
// would date it a week ago on a quiet team, and one set forward would end the
// wait at once (security review 2026-11-24, M3). The count adds up the
// process's monotonic clock between ticks of Run, at most recoveryTickEvery
// a tick, and is kept in the state: time the coordinator is down, or a state
// restored from before, only makes the wait longer. Desktop counts it again
// from when its listed devices first saw the log without the record
// (team_log.rs).
//
// Counting at most a tick a tick bounds the count by the rate Run's ticker
// fires, not by how far the clock moves: a host that leaps the guest's clock
// before each tick gains at most one tick a leap, so the wait runs at most
// as fast as the ticker does in real time, about 1x. What it doesn't bound
// is a host that runs the guest's whole clock fast (scaling its TSC or
// kvmclock without SecureTSC): the ticker fires faster with it, and the wait
// passes as fast as the host makes the guest's time pass. Only authenticated
// time (Roughtime) or SecureTSC would close that; until then Desktop's
// first-seen count is the backstop, weak for a device that reads rarely.
//
// A list ends every open recovery, as it ends what records admitted since
// the last one: it includes the device, which then signs as any listed one,
// or leaves it out, which removes it. During the wait only a listed admin
// device can sign a list, so any list proves an admin who could have
// included the device is there; cancelling is removing the device. A member
// invited again loses their devices, and their recovery with them. One
// recovery is open per member, a record is good for one append (its prev),
// and a recovery a list ended is gone: the next starts its wait again.

const (
	// RecordRecoveryStart is a passkey-admitted admin device starting its
	// wait to sign lists.
	RecordRecoveryStart = "recovery-start"
	// RecoveryContext starts what a recovery-start's device signs.
	RecoveryContext = "fount-team-recovery-start-v1\x00"
	// RecoveryDelay is how long after a recovery-start its device waits.
	RecoveryDelay = 7 * 24 * time.Hour
	// recoverySkew is how far a recovery-start's at may fall before the
	// times of the entries before it: a list's iat may be a device's clock,
	// up to grantSkew ahead of the coordinator's.
	recoverySkew = grantSkew

	// recoveryTickEvery is Run's tick, and the most one tick counts into
	// the open recoveries' waits, so the count runs at the tick rate, not
	// the clock's: a stalled process, or a monotonic clock the host leaps,
	// only makes the wait longer (2026-11-25 re-review, N2).
	// recoverySaveEvery is how much counted time goes unsaved before the
	// state is.
	recoveryTickEvery = runTickEvery
	recoverySaveEvery = 10 * time.Minute
)

// RecoveryWait is an open recovery's wait as the coordinator counted it: the
// recovery-start's entry and the time counted since it took it.
type RecoveryWait struct {
	Seq    uint64        `json:"seq"`
	Waited time.Duration `json:"waited"`
}

// RecoveryChallenge is what a recovering device signs, Ed25519: the context,
// then the coordinator, team, member, the log's head (the record's prev) and
// the device's id, length-prefixed.
func RecoveryChallenge(aud, team, member, prev, device string) ([]byte, error) {
	return lengthPrefixed(RecoveryContext, []byte(aud), []byte(team), []byte(member), []byte(prev), []byte(device))
}

// RecoveryProof is a recovery-start record's proof: the recovering device's
// id and its signature over RecoveryChallenge, base64url.
type RecoveryProof struct {
	Device string `json:"device"`
	Sig    string `json:"sig"`
}

// recovery is an open recovery: the record's entry, its device and time.
type recovery struct {
	Seq    uint64
	Device string
	At     int64
}

// checkRecoveryStart is what a client checks of a recovery-start record
// against the state before it, and reduceTeam on replay: the device is a
// passkey-admitted device of an admin member that no list included yet,
// some admin still has a listed device (else it signs at once), the member
// has no open recovery, the record's time doesn't fall before the entries
// before it, and the device signed RecoveryChallenge for the record's prev.
// It returns the device's id.
func checkRecoveryStart(st *teamState, aud, team string, r TeamRecord, m *Member) (string, error) {
	if r.Device != "" {
		return "", errors.New("a recovery-start admits no device")
	}
	var p RecoveryProof
	if err := decodeStrictJSON(r.Proof, &p); err != nil {
		return "", fmt.Errorf("a recovery-start record's proof: %v", err)
	}
	d, holder := st.device(p.Device)
	_, open := st.recoveries[m.ID]
	switch {
	case holder != m:
		return "", errors.New("a recovery-start's device isn't its member's")
	case m.Role != RoleAdmin:
		return "", errors.New("only an admin's device starts a recovery")
	case d.Since <= st.lastList || !st.passkeyAdmitted[d.ID]:
		return "", errors.New("only a device the member's passkey added, and no list included, starts a recovery")
	case !st.listedAdmin():
		return "", errors.New("no admin has a listed device, so the device signs lists at once")
	case open:
		return "", errors.New("the member has a recovery open")
	case r.At < st.lastAt-int64(recoverySkew/time.Second):
		return "", errors.New("a recovery-start's time is before the entry before it")
	}
	sig, err := b64.DecodeString(p.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return "", errors.New("a recovery-start record's proof is malformed")
	}
	msg, err := RecoveryChallenge(aud, team, m.ID, r.Prev, d.ID)
	if err != nil {
		return "", err
	}
	if !ed25519.Verify(d.Key, msg, sig) {
		return "", errors.New("a recovery-start isn't signed by its device")
	}
	return d.ID, nil
}

// recovered says whether device d of member m waited out a recovery for a
// list signed at iat, now, with w the wait the coordinator counted for it.
func (s *teamState) recovered(m *Member, d string, iat int64, now time.Time, w *RecoveryWait) bool {
	r, ok := s.recoveries[m.ID]
	delay := int64(RecoveryDelay / time.Second)
	return ok && r.Device == d && iat-r.At >= delay && now.Unix()-r.At >= delay &&
		w != nil && w.Seq == r.Seq && w.Waited >= RecoveryDelay
}

// tickRecoveryWaits counts the time since the last tick, by the process's
// monotonic clock (mono, time.Now in Run), into every open recovery's wait.
func (c *Coordinator) tickRecoveryWaits(mono time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.recoveryTick.IsZero() {
		c.recoveryTick = mono
		return
	}
	elapsed := mono.Sub(c.recoveryTick)
	c.recoveryTick = mono
	c.countRecoveryWaits(elapsed)
}

// countRecoveryWaits adds elapsed, at most recoveryTickEvery, to the wait of
// every recovery open on a team, starts a wait for a recovery that has none,
// and forgets the waits of recoveries a list ended. The state is saved once
// recoverySaveEvery is counted unsaved; a retired coordinator counts nothing.
// Called with c.mu held.
func (c *Coordinator) countRecoveryWaits(elapsed time.Duration) {
	if c.Retired() {
		return
	}
	elapsed = min(max(elapsed, 0), recoveryTickEvery)
	counted := false
	for id, t := range c.state.Teams {
		if len(t.RecoveryWaits) == 0 && t.state != nil && len(t.state.recoveries) == 0 {
			continue
		}
		st, err := c.teamState(id)
		if err != nil {
			continue
		}
		for member, w := range t.RecoveryWaits {
			if r, ok := st.recoveries[member]; !ok || r.Seq != w.Seq {
				delete(t.RecoveryWaits, member)
			}
		}
		for member, r := range st.recoveries {
			w := t.RecoveryWaits[member]
			if w == nil {
				if t.RecoveryWaits == nil {
					t.RecoveryWaits = map[string]*RecoveryWait{}
				}
				w = &RecoveryWait{Seq: r.Seq}
				t.RecoveryWaits[member] = w
			}
			w.Waited += elapsed
			counted = true
		}
	}
	if !counted {
		return
	}
	c.recoveryUnsaved += elapsed
	if c.recoveryUnsaved < recoverySaveEvery {
		return
	}
	if err := c.state.Save(c.cfg.StateDir); err != nil {
		log.Printf("coordinator: saving the recoveries' waits: %v", err)
		return
	}
	c.recoveryUnsaved = 0
}

// RecoveryRequest is POST /v1/teams/{team}/recovery-start: the head the device
// signed over, and its signature over RecoveryChallenge, base64url.
type RecoveryRequest struct {
	Prev string `json:"prev"`
	Sig  string `json:"sig"`
}

// StartRecovery appends a recovery-start record for the caller's device and
// emails every admin. It returns the team's log.
func (c *Coordinator) StartRecovery(caller Caller, team string, req RecoveryRequest) (TeamLogView, error) {
	proof, err := json.Marshal(RecoveryProof{Device: caller.Device, Sig: req.Sig})
	if err != nil {
		return TeamLogView{}, err
	}
	c.mu.Lock()
	var member string
	st, err := c.teamState(team)
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
		return TeamLogView{}, fmt.Errorf("%w: only a device the team admits starts a recovery", ErrListRefused)
	}
	rec := TeamRecord{Kind: RecordRecoveryStart, Member: member, Account: caller.Account, Proof: proof}
	seq, err := c.appendRecord(caller, team, rec, func(st *teamState, m *Member) error {
		if st.head != req.Prev {
			return fmt.Errorf("%w: the team changed since this device read it; try again", ErrTeamStale)
		}
		r := rec
		r.Prev, r.At = st.head, c.now().Unix()
		if _, err := checkRecoveryStart(st, c.cfg.Audience, team, r, m); err != nil {
			return fmt.Errorf("%w: %v", ErrListRefused, err)
		}
		return nil
	})
	if err != nil {
		return TeamLogView{}, err
	}
	c.mu.Lock()
	v := c.teamLogView(team, 0)
	var admins []string
	if st, err := c.teamState(team); err == nil {
		for _, m := range st.members {
			if m.Role == RoleAdmin && m.Email != "" {
				admins = append(admins, m.Email)
			}
		}
	}
	c.mu.Unlock()
	c.recoveryStarted(team, seq, admins)
	return v, nil
}

// startRecovery is POST /v1/teams/{team}/recovery-start.
func (a *api) startRecovery(rw http.ResponseWriter, r *http.Request) {
	var req RecoveryRequest
	if err := decodeStrict(r.Body, maxPasskeyBody, &req); err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	v, err := a.c.StartRecovery(*a.caller, r.PathValue("team"), req)
	if err != nil {
		fail(rw, passkeyStatus(err), err)
		return
	}
	reply(rw, http.StatusOK, v)
}
