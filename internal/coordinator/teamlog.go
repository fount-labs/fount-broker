package coordinator

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"
)

// A team's membership log (docs/membership-list.md §2): lists an admin
// device signed and records the coordinator wrote, one sequence, each naming
// the hash of the one before. Its state (members.go) decides who may act for
// the team's workers. An entry is appended only as the head's next, under the
// tree lock of every worker of the team, and acknowledged only once
// commitSecurity has made it durable.

// TeamRecordContext is what a record's hash is taken over, before its JSON.
const TeamRecordContext = "fount-team-record-v1\n"

// The record kinds (§2.3): an invite taken, which lists the member's passkey
// (teaminvite.go), and a member's new device added by that passkey
// (passkeyjoin.go). Each checks its proof and calls appendRecord.
//
// The six-digit code join is gone (decided 2026-11-19): a "join" record, and
// an invite record that lists no passkey, are refused on append and on
// replay alike.
const (
	RecordInvite      = "invite"
	RecordPasskeyJoin = "passkey-join"
)

// A member's passkey vouching for their own team (passkeyvouch.go), and a
// recovery-start (teamrecovery.go), admit no device.

// recordAdmits are the record kinds that admit a device.
var recordAdmits = map[string]bool{RecordInvite: true, RecordPasskeyJoin: true}

// recordKinds are the kinds a log holds.
var recordKinds = map[string]bool{RecordInvite: true, RecordPasskeyJoin: true, RecordPasskeyVouch: true, RecordRecoveryStart: true}

var (
	// ErrTeamStale is an entry that isn't the head's next: a replay, a list
	// signed over an older head, or a race another append won.
	ErrTeamStale = errors.New("the membership list isn't the next one")
	// ErrNotAdmin is a list signed by a device that isn't an admin's.
	ErrNotAdmin = errors.New("only an admin's device can change the team")
)

// Team is one team's log. Rotate are the workers whose address signing key
// must rotate at the edge because the team lost an admin (§5); lane M clears
// them.
type Team struct {
	ID     string      `json:"id"`
	Log    []TeamEntry `json:"log"`
	Rotate []string    `json:"rotate,omitempty"`
	// Billing is a firm team's subscription as fount-infra last answered
	// (teambilling.go).
	Billing *TeamBilling `json:"billing,omitempty"`
	// Owner is the account that made the team, whose budget its log counts
	// against (teamloglimits.go): a solo account's own, or the account a
	// firm team's id was minted for. teamOwner fills it in for a team made
	// before it was kept.
	Owner string `json:"owner,omitempty"`
	// RecoveryWaits are the open recoveries' waits by member, as this
	// coordinator counted them (teamrecovery.go).
	RecoveryWaits map[string]*RecoveryWait `json:"recoveryWaits,omitempty"`

	state *teamState
}

// TeamEntry is one entry of a team's log: a list's token as signed, or a
// record's JSON as written, and its hash.
type TeamEntry struct {
	Seq    uint64          `json:"seq"`
	List   string          `json:"list,omitempty"`
	Record json.RawMessage `json:"record,omitempty"`
	Hash   string          `json:"hash"`
}

// TeamRecord admits a device under one member, on a proof its kind's builder
// checked and every client checks again.
type TeamRecord struct {
	Kind    string `json:"kind"`
	Seq     uint64 `json:"seq"`
	Prev    string `json:"prev"`
	Member  string `json:"member"`
	Account string `json:"account"`
	// Device is the admitted device's team inclusion, for this record's Seq.
	Device string          `json:"device,omitempty"`
	At     int64           `json:"at"`
	Proof  json.RawMessage `json:"proof,omitempty"`
}

// teamState is the team's state, reduced from its log once and kept until
// the log moves. Called with c.mu held.
func (c *Coordinator) teamState(id string) (*teamState, error) {
	t, ok := c.state.Teams[id]
	if !ok {
		return nil, ErrNoTeam
	}
	if t.state == nil {
		st, err := reduceTeam(id, c.cfg.Audience, t.Log)
		if err != nil {
			return nil, fmt.Errorf("team %s's log: %w", id, err)
		}
		t.state = st
	}
	return t.state, nil
}

// reduceTeam replays a log: each entry's number, chain and hash, then the
// last list and the records after it. The log holds only entries that were
// checked when they were appended, so a failure here is a damaged volume.
func reduceTeam(team, aud string, log []TeamEntry) (*teamState, error) {
	st := newTeamState()
	for i, e := range log {
		if e.Seq != uint64(i+1) {
			return nil, fmt.Errorf("entry %d is numbered %d", i+1, e.Seq)
		}
		if err := st.apply(team, aud, e); err != nil {
			return nil, err
		}
	}
	return st, nil
}

func newTeamState() *teamState {
	return &teamState{usedInvites: map[string]bool{}, passkeyCounts: map[string]uint32{}, passkeyAdmitted: map[string]bool{}, recoveries: map[string]recovery{}, vouched: map[string]bool{}, byID: map[string]*Member{}, byDevice: map[string]*Member{}, workers: map[string]string{}}
}

// apply is reduceTeam's step: the state after entry, the next of s. reduceTeam
// is a fold of it, so the state after an append is its prior state's clone
// with the entry applied. A failure leaves s part-applied: apply to a clone.
func (s *teamState) apply(team, aud string, e TeamEntry) error {
	if e.Seq != s.seq+1 {
		return fmt.Errorf("entry %d is numbered %d", s.seq+1, e.Seq)
	}
	if s.deleted {
		return fmt.Errorf("entry %d follows the team's deletion", e.Seq)
	}
	var hash string
	switch {
	case e.List != "" && e.Record == nil:
		payload, _, err := splitToken(e.List)
		if err != nil {
			return fmt.Errorf("entry %d: %v", e.Seq, err)
		}
		l, err := decodeTeamList(payload)
		if err != nil {
			return fmt.Errorf("entry %d: %v", e.Seq, err)
		}
		if l.Seq != e.Seq || l.Prev != s.head || l.Team != team {
			return fmt.Errorf("entry %d doesn't follow the one before", e.Seq)
		}
		if err := s.applyList(l, aud); err != nil {
			return fmt.Errorf("entry %d: %v", e.Seq, err)
		}
		hash = entryHash(TeamListContext, payload)
	case e.Record != nil && e.List == "":
		var r TeamRecord
		if err := decodeStrictJSON(e.Record, &r); err != nil {
			return fmt.Errorf("entry %d: %v", e.Seq, err)
		}
		if r.Seq != e.Seq || r.Prev != s.head {
			return fmt.Errorf("entry %d doesn't follow the one before", e.Seq)
		}
		if err := s.applyRecord(r, team, aud); err != nil {
			return fmt.Errorf("entry %d: %v", e.Seq, err)
		}
		hash = entryHash(TeamRecordContext, e.Record)
	default:
		return fmt.Errorf("entry %d is neither a list nor a record", e.Seq)
	}
	if hash != e.Hash {
		return fmt.Errorf("entry %d's hash is wrong", e.Seq)
	}
	if e.Seq == 1 {
		s.start = hash
	}
	s.seq, s.head = e.Seq, hash
	return nil
}

// clone is a copy of s that apply may change without touching s: its own
// members, devices and maps. A member's invite, passkey and workers are
// replaced, never changed in place, so they are shared.
func (s *teamState) clone() *teamState {
	n := *s
	n.members = make([]*Member, len(s.members))
	n.byID = make(map[string]*Member, len(s.byID))
	copied := make(map[*Member]*Member, len(s.members))
	for i, m := range s.members {
		cm := *m
		cm.Devices = slices.Clone(m.Devices)
		n.members[i], n.byID[cm.ID], copied[m] = &cm, &cm, &cm
	}
	n.byDevice = make(map[string]*Member, len(s.byDevice))
	for id, m := range s.byDevice {
		n.byDevice[id] = copied[m]
	}
	n.workers, n.usedInvites, n.passkeyCounts = maps.Clone(s.workers), maps.Clone(s.usedInvites), maps.Clone(s.passkeyCounts)
	n.passkeyAdmitted, n.recoveries, n.vouched, n.former = maps.Clone(s.passkeyAdmitted), maps.Clone(s.recoveries), maps.Clone(s.vouched), maps.Clone(s.former)
	return &n
}

// applyList makes a list the state; what it leaves out is gone.
func (s *teamState) applyList(l TeamList, aud string) error {
	if l.Deleted {
		s.former = map[string]string{}
		for id, m := range s.byDevice {
			s.former[id] = m.Account
		}
		s.deleted = true
	}
	prior := s.byID
	s.members, s.byID, s.byDevice, s.workers = nil, map[string]*Member{}, map[string]*Member{}, map[string]string{}
	s.passkeyAdmitted, s.recoveries = map[string]bool{}, map[string]recovery{}
	s.name, s.lastList, s.lastAt = l.Name, l.Seq, max(s.lastAt, l.Iat)
	for _, w := range l.Workers {
		s.workers[w.ID] = w.DEK
	}
	for _, lm := range l.Members {
		m := &Member{ID: lm.ID, Account: lm.Account, Email: lm.Email, Role: lm.Role, Workers: lm.Workers, Invite: lm.Invite, Rec: lm.Rec}
		switch old := prior[lm.ID]; {
		case lm.Account == "":
		case old != nil && old.Account == lm.Account:
			m.Joined = old.Joined
		default:
			m.Joined = l.Seq
		}
		for _, token := range lm.Devices {
			d, err := parseTeamInclusion(token, aud, l.Team, lm.Account)
			if err != nil {
				return err
			}
			m.Devices = append(m.Devices, d)
			s.byDevice[d.ID] = m
		}
		s.members = append(s.members, m)
		s.byID[m.ID] = m
	}
	return nil
}

// applyRecord adds what a record admits.
func (s *teamState) applyRecord(r TeamRecord, team, aud string) error {
	m := s.byID[r.Member]
	if m == nil || !recordKinds[r.Kind] {
		return errors.New("a record for no member, or of no kind")
	}
	switch r.Kind {
	case RecordInvite:
		rec, count, err := checkInviteProof(s, aud, team, r, m)
		if err != nil {
			return err
		}
		m.Rec = rec
		if count != 0 {
			s.passkeyCounts[rec.Pub] = count
		}
		// A member invited again gets back in with this device alone: the
		// computers they had are removed, as if a list left them out.
		for _, d := range m.Devices {
			delete(s.byDevice, d.ID)
			delete(s.passkeyAdmitted, d.ID)
		}
		m.Devices = nil
		delete(s.recoveries, m.ID)
	case RecordPasskeyJoin:
		count, err := checkPasskeyJoinProof(s, aud, team, r, m)
		if err != nil {
			return err
		}
		if count != 0 {
			s.passkeyCounts[m.Rec.Pub] = count
		}
	case RecordPasskeyVouch:
		count, err := checkPasskeyVouchProof(s, aud, team, r, m)
		if err != nil {
			return err
		}
		if count != 0 {
			s.passkeyCounts[m.Rec.Pub] = count
		}
		s.vouched[m.Rec.Pub] = true
	case RecordRecoveryStart:
		device, err := checkRecoveryStart(s, aud, team, r, m)
		if err != nil {
			return err
		}
		s.recoveries[m.ID] = recovery{Seq: r.Seq, Device: device, At: r.At}
	}
	s.lastAt = max(s.lastAt, r.At)
	if r.Kind == RecordInvite {
		s.usedInvites[m.Invite.ID] = true
		if m.Account != r.Account {
			m.Joined = r.Seq
		}
		m.Invite, m.Account = nil, r.Account
	}
	if !recordAdmits[r.Kind] {
		return nil
	}
	d, err := parseTeamInclusion(r.Device, aud, team, m.Account)
	if err != nil {
		return err
	}
	if s.byDevice[d.ID] != nil || d.Since != r.Seq {
		return errors.New("a record admits a device twice, or on another entry's inclusion")
	}
	m.Devices = append(m.Devices, d)
	slices.SortFunc(m.Devices, func(a, b TeamDevice) int { return cmpString(a.ID, b.ID) })
	s.byDevice[d.ID] = m
	s.passkeyAdmitted[d.ID] = true
	return nil
}

func cmpString(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// lockTeam takes the tree lock of every worker of team and of extra, in id
// order, as view and change take them: a request in flight finishes under the
// state it was allowed by, and one after sees the new state. A worker that
// joins the team meanwhile can only do so by an append, which moves the head
// and makes this one stale. It returns the unlock.
func (c *Coordinator) lockTeam(team string, extra []string) func() {
	c.mu.Lock()
	ids := map[string]bool{}
	for id, w := range c.state.Workers {
		if w.Team == team && team != "" {
			ids[id] = true
		}
	}
	for _, id := range extra {
		if _, ok := c.state.Workers[id]; ok {
			ids[id] = true
		}
	}
	var locks []*sync.Mutex
	for _, id := range slices.Sorted(maps.Keys(ids)) {
		lock, ok := c.locks[id]
		if !ok {
			lock = &sync.Mutex{}
			c.locks[id] = lock
		}
		locks = append(locks, lock)
	}
	c.mu.Unlock()
	for _, l := range locks {
		l.Lock()
	}
	return func() {
		for i := len(locks) - 1; i >= 0; i-- {
			locks[i].Unlock()
		}
	}
}

// AppendTeamList appends a list an admin device signed to its team's log,
// with the DEK of each worker it adds to the team. It returns the team's log
// view as it now stands.
func (c *Coordinator) AppendTeamList(caller Caller, team, token string, deks map[string]DEK) (TeamLogView, error) {
	defer func() {
		for id := range deks {
			deks[id] = DEK{}
		}
	}()
	now := c.now()
	l, payload, err := parseTeamList(token, c.cfg.Audience, caller, team, now)
	if err != nil {
		return TeamLogView{}, err
	}
	var extra []string
	for _, w := range l.Workers {
		extra = append(extra, w.ID)
	}
	unlock := c.lockTeam(team, extra)
	defer unlock()
	c.mu.Lock()
	var prior *teamState
	if _, ok := c.state.Teams[team]; ok {
		if prior, err = c.teamState(team); err != nil {
			c.mu.Unlock()
			return TeamLogView{}, err
		}
	}
	// Who signs it, then the log's bounds and rates: they are cheap, and
	// checkList checks a signature for each device the list names. A
	// stranger hears only that it isn't theirs to change.
	if err := c.checkListSigner(prior, l, caller, now); err != nil {
		c.mu.Unlock()
		return TeamLogView{}, err
	}
	entry := TeamEntry{Seq: l.Seq, List: token, Hash: entryHash(TeamListContext, payload)}
	if err := c.teamLogRoom(caller, team, len(entry.List)+len(entry.Hash), l.Deleted, now); err != nil {
		c.mu.Unlock()
		return TeamLogView{}, err
	}
	if err := c.checkList(prior, l, caller, deks, now); err != nil {
		c.mu.Unlock()
		return TeamLogView{}, err
	}
	removed, err := c.commitEntry(team, prior, entry, deks)
	var view TeamLogView
	if err == nil {
		c.tookTeamLog(caller, team, now)
		view = c.teamLogView(team, l.Seq-1)
	}
	c.mu.Unlock()
	if err != nil {
		return TeamLogView{}, err
	}
	for _, w := range removed {
		c.deleteObjects(w)
	}
	return view, nil
}

// checkListSigner is the part of checkList that checks no signature: the
// order and the signer, by the state before the list or, for a team's
// first, by whose team it is. AppendTeamList runs it before the log's
// bounds (teamloglimits.go), so they are told to no one else. prior is nil
// for a team's first list. Called with c.mu held.
func (c *Coordinator) checkListSigner(prior *teamState, l TeamList, caller Caller, now time.Time) error {
	seq, head := uint64(0), ""
	if prior != nil {
		seq, head = prior.seq, prior.head
	}
	if prior != nil && prior.deleted {
		return ErrTeamDeleted
	}
	if l.Deleted && prior == nil {
		return fmt.Errorf("%w: a team's first list doesn't delete it", ErrListRefused)
	}
	if l.Seq != seq+1 || subtle.ConstantTimeCompare([]byte(l.Prev), []byte(head)) != 1 {
		return fmt.Errorf("%w: it is %d, and the team's last was %d", ErrTeamStale, l.Seq, seq)
	}
	// The signer: an admin of the caller's account, in the state before the
	// list or, for a team's first, in the list, which must be the caller's
	// own team of one or a firm team's id MintTeam made for the caller's
	// account.
	if prior == nil {
		if l.Team != caller.Account && c.state.TeamMints[l.Team] != caller.Account {
			return fmt.Errorf("%w: a team's first list is for the signer's own account or an id the coordinator made for it", ErrNotAdmin)
		}
		return nil
	}
	return prior.maySignLists(caller, l.Iat, now, c.state.Teams[l.Team].RecoveryWaits)
}

// revokesRemovedPasskey refuses a list that removes a device a record added
// with its member's passkey since the last list, a passkey join no list
// included yet or a recovering device, while it still names that passkey
// for the member (security review 2026-11-24, M4). Removing such a device is
// Remove on the new-computer notice and Cancel on a recovery: the passkey is
// how it came in, so a list that kept the passkey would let it join again at
// once, with wraps of the epoch made to cut it off, and start another
// recovery. The list clears the member's passkey or names another, which an
// admin's list sets (SetPasskey) or an invite taken again lists.
func revokesRemovedPasskey(prior *teamState, l TeamList, aud string) error {
	kept := map[string]bool{}
	recs := map[string]*ListRec{}
	for _, lm := range l.Members {
		recs[lm.ID] = lm.Rec
		for _, token := range lm.Devices {
			if d, err := parseTeamInclusion(token, aud, l.Team, lm.Account); err == nil {
				kept[d.ID] = true
			}
		}
	}
	for id := range prior.passkeyAdmitted {
		m := prior.byDevice[id]
		if m == nil || m.Rec == nil || kept[id] {
			continue
		}
		if rec := recs[m.ID]; rec != nil && rec.Pub == m.Rec.Pub {
			return fmt.Errorf("removing device %s, which member %s's passkey added, keeps that passkey, which would add it again; the list clears or replaces it", id, m.ID)
		}
	}
	return nil
}

// checkList is every check on a list against its team's state before it
// (§2.2): the order, the signer (checkListSigner), the devices, the
// accounts, the workers and, for a firm team, its seats (admission.go).
// prior is nil for a team's first list. Called with c.mu held.
func (c *Coordinator) checkList(prior *teamState, l TeamList, caller Caller, deks map[string]DEK, now time.Time) error {
	if err := c.checkListSigner(prior, l, caller, now); err != nil {
		return err
	}
	if prior == nil {
		if lm := listMemberOf(l, caller.Device, c.cfg.Audience); lm == nil || lm.Role != RoleAdmin || lm.Account != caller.Account {
			return fmt.Errorf("%w: a team's first list names its signer as an admin", ErrNotAdmin)
		}
	}
	refuse := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrListRefused, fmt.Sprintf(format, args...))
	}
	for _, lm := range l.Members {
		var old *Member
		if prior != nil {
			old = prior.byID[lm.ID]
		}
		if old != nil && old.Account != "" && lm.Account != old.Account {
			return refuse("member %s's account can't change", lm.ID)
		}
		if lm.Invite != nil && prior != nil && prior.usedInvites[lm.Invite.ID] {
			return refuse("invite %s was used", lm.Invite.ID)
		}
		// Accepting an invite again removes the member's computers, so an
		// admin's list can't open one on its signer's own member: their
		// passkey adds their next computer. One another admin opened, the
		// member's own lists keep.
		if prior != nil && lm.Invite != nil && lm.Account != "" && (old == nil || old.Invite == nil || *old.Invite != *lm.Invite) {
			if _, signer := prior.device(caller.Device); signer != nil && signer.ID == lm.ID {
				return refuse("you can't invite yourself again; add your new computer with your passkey")
			}
		}
		for _, token := range lm.Devices {
			d, err := parseTeamInclusion(token, c.cfg.Audience, l.Team, lm.Account)
			if err != nil {
				return refuse("%v", err)
			}
			var held TeamDevice
			var holder *Member
			if prior != nil {
				held, holder = prior.device(d.ID)
			}
			switch {
			case holder != nil && holder.ID != lm.ID:
				return refuse("device %s is member %s's", d.ID, holder.ID)
			case holder != nil && !sameDevice(held, d):
				return refuse("device %s keeps the inclusion it was admitted on, %d", d.ID, held.Since)
			case holder == nil && d.Since != l.Seq:
				return refuse("device %s's inclusion is for entry %d, and it must be for %d", d.ID, d.Since, l.Seq)
			}
		}
	}
	if prior != nil {
		if err := revokesRemovedPasskey(prior, l, c.cfg.Audience); err != nil {
			return refuse("%v", err)
		}
	}
	listed := map[string]bool{}
	for _, lw := range l.Workers {
		listed[lw.ID] = true
		if prior != nil {
			if held, ok := prior.workers[lw.ID]; ok {
				if held != lw.DEK {
					return refuse("worker %s's DEK can't change", lw.ID)
				}
				if _, ok := deks[lw.ID]; ok {
					return refuse("worker %s is the team's already, so takes no DEK", lw.ID)
				}
				continue
			}
		}
		w, ok := c.state.Workers[lw.ID]
		if !ok || w.Team != "" || w.WrappedDEK != nil || len(w.Devices) != 1 || w.ungrantedExpired(now) {
			return refuse("worker %s isn't one waiting to join a team", lw.ID)
		}
		// A solo account's team takes in a worker only from a signer with
		// a plan of its own (admission.go).
		if !caller.Paid && !isFirmTeam(l.Team) {
			return fmt.Errorf("%w: to add an email agent to your own team", ErrNoPlan)
		}
		if lm := listMemberOf(l, w.Devices[0].ID, c.cfg.Audience); lm == nil || lm.Role != RoleAdmin || lm.Account != w.Account {
			return refuse("worker %s was made by a device that isn't an admin's", lw.ID)
		}
		dek, ok := deks[lw.ID]
		if !ok {
			return refuse("worker %s comes with no DEK", lw.ID)
		}
		if subtle.ConstantTimeCompare([]byte(DEKCommitment(lw.ID, dek)), []byte(lw.DEK)) != 1 {
			return refuse("worker %s's DEK isn't the one the list signs", lw.ID)
		}
	}
	for id := range deks {
		if !listed[id] {
			return refuse("a DEK for %.40q, which the list doesn't name", id)
		}
	}
	return c.checkSeats(prior, l, now)
}

// listMemberOf is the member a list puts a device under, or nil.
func listMemberOf(l TeamList, device, aud string) *ListMember {
	for i, lm := range l.Members {
		for _, token := range lm.Devices {
			if d, err := parseTeamInclusion(token, aud, l.Team, lm.Account); err == nil && d.ID == device {
				return &l.Members[i]
			}
		}
	}
	return nil
}

// appendRecord appends a record to a team's log: rec's kind, member, account
// and, for a kind that admits one, device. It fills in the number, the chain
// and the time. proof checks rec's proof against the state before it, under
// the same locks, and is the caller's: the invite secret and verified email,
// a listed device's approval, the passkey. The caller is the device being
// admitted.
func (c *Coordinator) appendRecord(caller Caller, team string, rec TeamRecord, proof func(*teamState, *Member) error) (uint64, error) {
	unlock := c.lockTeam(team, nil)
	defer unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.state.Teams[team]; !ok {
		return 0, ErrNoTeam
	}
	prior, err := c.teamState(team)
	if err != nil {
		return 0, err
	}
	seq, err := c.appendRecordLocked(caller, team, prior, rec, proof)
	return seq, err
}

// appendRecordLocked is appendRecord with c.mu and the team's locks held.
func (c *Coordinator) appendRecordLocked(caller Caller, team string, prior *teamState, rec TeamRecord, proof func(*teamState, *Member) error) (uint64, error) {
	refuse := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrListRefused, fmt.Sprintf(format, args...))
	}
	if prior.deleted {
		return 0, ErrTeamDeleted
	}
	m := prior.byID[rec.Member]
	switch {
	case !recordKinds[rec.Kind]:
		return 0, refuse("no record kind %.20q", rec.Kind)
	case m == nil:
		return 0, refuse("no member %.40q", rec.Member)
	case m.Account != "" && rec.Account != m.Account:
		return 0, refuse("member %s is another account", m.ID)
	case m.Account == "" && rec.Kind != RecordInvite:
		return 0, refuse("member %s hasn't taken their invite", m.ID)
	case rec.Kind == RecordInvite && m.Invite == nil:
		return 0, refuse("member %s has no open invite", m.ID)
	case checkID("account", rec.Account) != nil:
		return 0, refuse("the record's account isn't an id")
	}
	if rec.Account != caller.Account {
		return 0, refuse("the record is for another account than the caller's")
	}
	for _, o := range prior.members {
		if o.Account == rec.Account && o.ID != m.ID {
			return 0, refuse("account %s is member %s", rec.Account, o.ID)
		}
	}
	rec.Seq, rec.Prev, rec.At = prior.seq+1, prior.head, c.now().Unix()
	if recordAdmits[rec.Kind] {
		d, err := parseTeamInclusion(rec.Device, c.cfg.Audience, team, rec.Account)
		switch {
		case err != nil:
			return 0, refuse("%v", err)
		case d.ID != caller.Device:
			return 0, refuse("a device admits only itself")
		case d.Since != rec.Seq:
			return 0, refuse("device %s's inclusion is for entry %d, and it must be for %d", d.ID, d.Since, rec.Seq)
		case prior.byDevice[d.ID] != nil && !(rec.Kind == RecordInvite && prior.byDevice[d.ID] == m):
			return 0, refuse("device %s is admitted already", d.ID)
		case rec.Kind != RecordInvite && len(m.Devices) >= MaxMemberDevices:
			return 0, refuse("member %s has %d devices", m.ID, MaxMemberDevices)
		}
	} else if rec.Device != "" {
		return 0, refuse("a %s admits no device", rec.Kind)
	}
	if proof == nil {
		return 0, refuse("a record needs its proof checked")
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		return 0, err
	}
	entry := TeamEntry{Seq: rec.Seq, Record: payload, Hash: entryHash(TeamRecordContext, payload)}
	now := c.now()
	if err := c.teamLogRoom(caller, team, len(entry.Record)+len(entry.Hash), false, now); err != nil {
		return 0, err
	}
	if err := proof(prior, m); err != nil {
		return 0, err
	}
	if _, err := c.commitEntry(team, prior, entry, nil); err != nil {
		return 0, err
	}
	c.tookTeamLog(caller, team, now)
	return rec.Seq, nil
}

// commitEntry appends entry to the team's log, makes each of its workers'
// devices and wraps follow the new state, deletes the workers it leaves out,
// marks rotation if it lost an admin, and commits. It returns the deleted
// workers, whose objects the caller deletes once it lets go of the locks.
// Called with c.mu and the team's tree locks held.
func (c *Coordinator) commitEntry(team string, prior *teamState, entry TeamEntry, deks map[string]DEK) ([]Worker, error) {
	t, existed := c.state.Teams[team]
	var log []TeamEntry
	if existed {
		log = slices.Clone(t.Log)
	}
	log = append(log, entry)
	// Only the new entry is checked again: prior is the log's state as
	// reduceTeam made it, or as this made it from its own prior.
	next := newTeamState()
	if prior != nil {
		next = prior.clone()
	}
	if err := next.apply(team, c.cfg.Audience, entry); err != nil {
		return nil, err
	}
	// Each worker of the team as it will stand, and each it leaves.
	changed := map[string]*Worker{}
	var rotated []string
	for _, id := range slices.Sorted(maps.Keys(next.workers)) {
		w := c.state.Workers[id]
		if w == nil {
			return nil, fmt.Errorf("worker %s is gone", id)
		}
		nw, err := c.followTeam(team, w, next, deks[id])
		if err != nil {
			return nil, err
		}
		changed[id] = nw
		if len(nw.DEKEpochs) > len(w.DEKEpochs) {
			rotated = append(rotated, id)
		}
	}
	var removed []Worker
	if prior != nil {
		for id := range prior.workers {
			if _, ok := next.workers[id]; ok {
				continue
			}
			if c.busy[id] {
				return nil, fmt.Errorf("worker %s: %w", id, ErrBusy)
			}
			if w := c.state.Workers[id]; w != nil {
				removed = append(removed, *w)
			}
		}
	}
	rotate := []string(nil)
	var billing *TeamBilling
	owner := c.teamOwner(team)
	if existed {
		rotate, billing = slices.Clone(t.Rotate), t.Billing
	}
	if billing != nil {
		b := *billing
		b.trackSeats(len(next.members), c.now().UTC())
		billing = &b
	}
	if lostAdmin(prior, next) {
		for id := range prior.workers {
			rotate = append(rotate, id)
		}
		for id := range next.workers {
			rotate = append(rotate, id)
		}
		slices.Sort(rotate)
		rotate = slices.Compact(rotate)
	}

	// Apply, keeping what to put back if the commit fails.
	oldWorkers := map[string]*Worker{}
	for id, nw := range changed {
		oldWorkers[id] = c.state.Workers[id]
		c.state.Workers[id] = nw
	}
	oldJobs := map[string]*Job{}
	for _, w := range removed {
		oldWorkers[w.ID] = c.state.Workers[w.ID]
		delete(c.state.Workers, w.ID)
		for id, j := range c.state.Jobs {
			if j.WorkerID == w.ID {
				oldJobs[id] = j
				delete(c.state.Jobs, id)
			}
		}
	}
	restoreReleases := c.releaseLocked(removed)
	c.state.Teams[team] = &Team{ID: team, Log: log, Rotate: rotate, Billing: billing, Owner: owner, state: next}
	mintedFor, minted := c.state.TeamMints[team]
	delete(c.state.TeamMints, team)
	if err := c.commitSecurity(); err != nil {
		restoreReleases()
		maps.Copy(c.state.Workers, oldWorkers)
		maps.Copy(c.state.Jobs, oldJobs)
		if existed {
			c.state.Teams[team] = t
		} else {
			delete(c.state.Teams, team)
		}
		if minted {
			c.state.TeamMints[team] = mintedFor
		}
		return nil, err
	}
	for _, w := range removed {
		delete(c.locks, w.ID)
	}
	c.resealAll(rotated)
	if c.mail != nil {
		// Who hears of the team's workers by email may have changed
		// (reviewers.go): their next mail pass sends the edge the list.
		for id := range next.workers {
			c.mail.kick(id)
		}
	}
	return removed, nil
}

// followTeam is w as the team's state next has it: in the team, with a wrap
// of its DEK for each device that reaches it. A wrap a device already has for
// the same X25519 key is kept. dek is a worker's new to the team; one already
// in it is unwrapped from the volume. When a device that reached it no longer
// does, the worker gets a new DEK epoch, and every device that reaches it a
// wrap of each epoch (dekepoch.go). Called with c.mu held.
func (c *Coordinator) followTeam(team string, w *Worker, next *teamState, dek DEK) (*Worker, error) {
	nw := *w
	if w.Team == "" {
		var err error
		if nw.WrappedDEK, err = c.cfg.Key.Wrap(w.ID, dek); err != nil {
			return nil, err
		}
		if nw.License == "" {
			nw.License = w.Account
		}
		nw.Team, nw.Account, nw.DEKCommitment = team, team, next.workers[w.ID]
	} else {
		held, err := c.cfg.Key.Unwrap(w.ID, w.WrappedDEK)
		if err != nil {
			return nil, err
		}
		dek = held
	}
	defer clear(dek[:])
	reachers := next.reachers(w.ID)
	if w.Team != "" && lostReach(w.Devices, reachers) {
		if err := c.newEpoch(&nw); err != nil {
			return nil, err
		}
	}
	ring := SingleKeyring(dek)
	if len(nw.DEKEpochs) > 0 {
		ring.Clear()
		var err error
		if ring, err = c.cfg.Key.Keyring(&nw); err != nil {
			return nil, err
		}
	}
	defer func() { ring.Clear() }()
	nw.Devices = nil
	for _, d := range reachers {
		var wrap []byte
		for _, old := range w.Devices {
			if old.ID == d.ID && old.Wrap != nil && subtle.ConstantTimeCompare(old.Enc, d.Enc) == 1 {
				wrap = old.Wrap
			}
		}
		if wrap == nil {
			var err error
			if wrap, err = SealWrap(d.Enc, nw.Account, w.ID, d.ID, dek); err != nil {
				return nil, err
			}
		}
		epochWraps, err := epochWrapsFor(w.Devices, d, nw.Account, w.ID, ring)
		if err != nil {
			return nil, err
		}
		nw.Devices = append(nw.Devices, Device{ID: d.ID, Key: d.Key, Enc: d.Enc, Wrap: wrap, EpochWraps: epochWraps})
	}
	return &nw, nil
}

// teamIDPrefix starts the id of a firm team, which the coordinator makes.
// A solo account's team id is its account id.
const teamIDPrefix = "tm"

// MintTeam makes a firm team's id for the caller's account to sign its first
// list for (§2.2): random, so no one can claim another's team, and never an
// identity provider's organisation id. fount-infra maps an organisation to
// it for billing alone. Until a first list is appended for it, asking again
// returns the same id, so an account holds one at a time, and an account
// makes at most maxTeamsPerAccount firm teams.
func (c *Coordinator) MintTeam(caller Caller) (string, error) {
	if err := checkID("account", caller.Account); err != nil {
		return "", err
	}
	if !caller.Paid {
		return "", fmt.Errorf("%w: to make a team", ErrNoPlan)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, id := range slices.Sorted(maps.Keys(c.state.TeamMints)) {
		if c.state.TeamMints[id] == caller.Account {
			return id, nil
		}
	}
	if n := c.firmTeamsOf(caller.Account); n >= maxTeamsPerAccount {
		return "", fmt.Errorf("%w: the account has made %d", ErrTeamLimit, n)
	}
	for {
		id, err := newID(teamIDPrefix)
		if err != nil {
			return "", err
		}
		if _, taken := c.state.Teams[id]; taken {
			continue
		}
		if _, taken := c.state.TeamMints[id]; taken {
			continue
		}
		if _, taken := c.state.Workers[id]; taken {
			continue
		}
		c.state.TeamMints[id] = caller.Account
		if err := c.state.Save(c.cfg.StateDir); err != nil {
			delete(c.state.TeamMints, id)
			return "", err
		}
		return id, nil
	}
}

// mintTeam is POST /v1/teams: a new firm team's id, {"team": id}.
func (a *api) mintTeam(rw http.ResponseWriter, r *http.Request) {
	id, err := a.c.MintTeam(*a.caller)
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusOK, map[string]string{"team": id})
}

// TeamLogView is a team's log after a point, and where it stands: what a
// client verifies from the last head it saw (§4.3).
type TeamLogView struct {
	Team    string      `json:"team"`
	Seq     uint64      `json:"seq"`
	Head    string      `json:"head"`
	Entries []TeamEntry `json:"entries"`
}

// teamLogView is the team's entries after since. Called with c.mu held.
func (c *Coordinator) teamLogView(team string, since uint64) TeamLogView {
	t := c.state.Teams[team]
	v := TeamLogView{Team: team, Entries: []TeamEntry{}}
	if t == nil {
		return v
	}
	v.Seq = uint64(len(t.Log))
	if v.Seq > 0 {
		v.Head = t.Log[v.Seq-1].Hash
	}
	if since < v.Seq {
		v.Entries = slices.Clone(t.Log[since:])
	}
	return v
}

const maxTeamBody = 512 << 10

// mayReadLog refuses a caller who may not read team's log: a device the
// team admits, or a device of the account whose own team it is, which reads
// it before it joins to see the member's passkey vouched for it
// (passkeyvouch.go). Called with c.mu held.
func (c *Coordinator) mayReadLog(caller Caller, team string) error {
	_, _, err := c.requireMember(caller, team)
	if err == nil {
		return nil
	}
	if _, ok := c.state.Teams[team]; ok {
		if st, serr := c.teamState(team); serr == nil && st.deleted {
			if acct, ok := st.former[caller.Device]; ok && acct == caller.Account {
				return nil
			}
			return ErrNoTeam
		}
	}
	if team != caller.Account {
		return err
	}
	st, serr := c.teamState(team)
	if serr != nil {
		return ErrNoTeam
	}
	for _, m := range st.members {
		if m.Account == caller.Account {
			return nil
		}
	}
	return ErrNoTeam
}

// teamLog is GET /v1/teams/{team}/log?since=N: the entries after N, for any
// device the team admits, and for the account's own team any device of the
// account.
func (a *api) teamLog(rw http.ResponseWriter, r *http.Request) {
	var since uint64
	if q := r.URL.Query(); q.Has("since") {
		n, err := strconv.ParseUint(q.Get("since"), 10, 64)
		if err != nil {
			fail(rw, http.StatusBadRequest, fmt.Errorf("%w: since must be an entry number", ErrInvalid))
			return
		}
		since = n
	}
	team := r.PathValue("team")
	a.c.mu.Lock()
	err := a.c.mayReadLog(*a.caller, team)
	var v TeamLogView
	if err == nil {
		v = a.c.teamLogView(team, since)
	}
	a.c.mu.Unlock()
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusOK, v)
}

// appendTeamList is POST /v1/teams/{team}/log: a list an admin device signed,
// with the DEK of each worker it adds to the team, base64, by id.
func (a *api) appendTeamList(rw http.ResponseWriter, r *http.Request) {
	var req struct {
		V    int               `json:"v"`
		List string            `json:"list"`
		DEKs map[string][]byte `json:"deks"`
	}
	if err := decodeStrict(r.Body, maxTeamBody, &req); err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	deks := map[string]DEK{}
	defer func() {
		for _, b := range req.DEKs {
			clear(b)
		}
	}()
	for id, b := range req.DEKs {
		dek, err := parseDEK(b)
		if err != nil || dek == nil {
			fail(rw, http.StatusBadRequest, fmt.Errorf("worker %.40q: dek must be %d bytes", id, KeySize))
			return
		}
		deks[id] = *dek
		clear(dek[:])
	}
	if req.V != TeamListVersion {
		fail(rw, http.StatusBadRequest, fmt.Errorf("list version %d: want %d", req.V, TeamListVersion))
		return
	}
	v, err := a.c.AppendTeamList(*a.caller, r.PathValue("team"), req.List, deks)
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusOK, v)
}

// retired is the v2 grant and revoke routes: Desktop signs the team's list
// now.
func (a *api) retired(rw http.ResponseWriter, _ *http.Request) {
	fail(rw, statusOf(ErrRetired), ErrRetired)
}
