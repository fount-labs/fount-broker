package coordinator

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Who may do what to a team's workers (docs/membership-list.md §3). Every
// client operation has a role in opRoles, keyed by its route pattern without
// the /v0 or /v1 prefix, or by a thread or worker operation's kind. A route
// or kind with none is refused. requireRole checks a caller against the
// worker's team's log as it stands. The coordinator's own operations (mail
// arriving, a job ending) act as anyDevice and need no role.

// roleCaller marks a route that checks its caller itself: making a worker
// before it has a team, making a firm team's id, the retired v2 grant routes.
const roleCaller Role = "caller"

var opRoles = map[string]Role{
	"POST /workers":                        roleCaller,
	"GET /workers":                         RoleReviewer,
	"POST /workers/{id}/grant":             roleCaller,
	"POST /workers/{id}/revoke":            roleCaller,
	"GET /workers/{id}":                    RoleReviewer,
	"PUT /workers/{id}/root/{path...}":     RoleAdmin,
	"GET /workers/{id}/files":              RoleReviewer,
	"GET /workers/{id}/files/{path...}":    RoleReviewer,
	"POST /workers/{id}/jobs":              RoleAdmin,
	"GET /jobs/{id}":                       RoleReviewer,
	"GET /workers/{id}/threads":            RoleReviewer,
	"GET /workers/{id}/threads/{tid}":      RoleReviewer,
	"POST /workers/{id}/threads/{tid}/ops": RoleReviewer,
	"POST /workers/{id}/ops":               RoleReviewer,
	"GET /workers/{id}/mail":               RoleReviewer,
	"PUT /workers/{id}/mail":               RoleAdmin,
	"POST /teams":                          roleCaller,
	"GET /teams/{team}/log":                RoleReviewer,
	"POST /teams/{team}/log":               RoleAdmin,
	// Taking a worker's threads, mail and files away (backupexport.go).
	"GET /workers/{id}/export": RoleAdmin,
	// A member's new device with their passkey (passkeyjoin.go): the device
	// isn't listed yet, so each route checks its caller and the record its
	// proof.
	"POST /teams/{team}/passkey-join/challenge": roleCaller,
	"POST /teams/{team}/passkey-join":           roleCaller,
	// Authorized by their proof: an invite's secret and verified email, or
	// the device's own request to join as its account's member.
	"GET /teams": roleCaller,
	"POST /teams/{team}/invites/{invite}/open":   roleCaller,
	"POST /teams/{team}/invites/{invite}/accept": roleCaller,
	"POST /teams/{team}/invites/{invite}/send":   RoleAdmin,
	"POST /teams/{team}/joins":                   roleCaller,
	"GET /teams/{team}/joins":                    RoleReviewer,
	"GET /teams/{team}/joins/{join}":             roleCaller,
	"POST /teams/{team}/joins/{join}/approve":    RoleReviewer,
	"POST /teams/{team}/joins/{join}/deny":       RoleReviewer,
	"POST /teams/{team}/joins/{join}/accept":     roleCaller,

	// A thread's work: any member who reaches the worker.
	"startThread":     RoleReviewer,
	"sendNote":        RoleReviewer,
	"cancelJob":       RoleReviewer,
	"acceptProposal":  RoleReviewer,
	"discardProposal": RoleReviewer,
	"approveDraft":    RoleReviewer,
	"discardDraft":    RoleReviewer,
	"sendAgain":       RoleReviewer,
	"keepFileAsCopy":  RoleReviewer,
	"redoOnLatest":    RoleReviewer,
	"answerQuestion":  RoleReviewer,
	"dismissQuestion": RoleReviewer,
	"forwardQuestion": RoleReviewer,
	"runHeldMail":     RoleReviewer,
	"markRead":        RoleReviewer,
	"claimDraft":      RoleReviewer,
	"releaseClaim":    RoleReviewer,

	// What leaves by email and to whom: the worker's settings.
	"addRequester":       RoleAdmin,
	"removeRequester":    RoleAdmin,
	"setRequesterMode":   RoleAdmin,
	"setDefaultMode":     RoleAdmin,
	"setAutoRun":         RoleAdmin,
	"setAcknowledge":     RoleAdmin,
	"pairingStart":       RoleAdmin,
	"pairingConfirm":     RoleAdmin,
	"routingSaved":       RoleAdmin,
	"setThreadReplyMode": RoleAdmin,

	"PUT /workers/{id}/threads/{tid}/drafts/{draft}/files/{path...}": RoleReviewer,
}

// opRole is the role an operation kind or route needs; ok is false for one
// with none, which is refused.
func opRole(kind string) (Role, bool) {
	r, ok := opRoles[kind]
	return r, ok
}

// routeKey is a route pattern as opRoles keys it: "GET /v1/workers/{id}" is
// "GET /workers/{id}".
func routeKey(pattern string) string {
	method, path, _ := strings.Cut(pattern, " ")
	if rest, ok := strings.CutPrefix(path, "/v1/"); ok {
		path = "/" + rest
	} else if rest, ok := strings.CutPrefix(path, "/v0/"); ok {
		path = "/" + rest
	}
	return method + " " + path
}

var (
	// ErrRole is a member whose role doesn't allow the operation on a worker
	// they reach, or an operation with no role.
	ErrRole = errors.New("your role doesn't allow this")
	// ErrNoTeam is a team the caller isn't a member of, or none.
	ErrNoTeam = errors.New("no such team")
)

// rank orders roles; anything else ranks above both, so nothing satisfies it.
func (r Role) rank() int {
	switch r {
	case RoleReviewer:
		return 1
	case RoleAdmin:
		return 2
	}
	return 99
}

// allows says whether a member with role r may do what needs need.
func (r Role) allows(need Role) bool {
	return (r == RoleAdmin || r == RoleReviewer) && r.rank() >= need.rank()
}

// Member is one member of a team as its log stands: the last list, plus the
// records after it.
type Member struct {
	ID, Account, Email string
	Role               Role
	// Workers are a reviewer's assignment, allWorkers for every one.
	Workers []string
	Devices []TeamDevice
	Invite  *ListInvite
	Rec     *ListRec
}

// teamState is a team's log reduced to who may act now. It is derived, never
// saved: reduceTeam makes it from the log.
type teamState struct {
	seq      uint64
	head     string
	name     string
	members  []*Member
	byID     map[string]*Member
	byDevice map[string]*Member
	// workers are the team's, each with its DEK commitment.
	workers map[string]string
	// usedInvites are the invites a record has taken, which no list may open
	// again.
	usedInvites map[string]bool
	// lastList is the seq of the last list (teamsigner.go).
	lastList uint64
	// passkeyCounts are each listed passkey's (by public key) last nonzero
	// sign count a passkey-join record carried: a later one must carry a
	// higher count, so a copied authenticator shows. A passkey that keeps no
	// count, as synced ones, carries 0 throughout.
	passkeyCounts map[string]uint32
}

// device is a device the state admits, and its member.
func (s *teamState) device(id string) (TeamDevice, *Member) {
	m := s.byDevice[id]
	if m == nil {
		return TeamDevice{}, nil
	}
	for _, d := range m.Devices {
		if d.ID == id {
			return d, m
		}
	}
	return TeamDevice{}, nil
}

// reachers are the devices that may act for a worker of the team, by member
// then device id.
func (s *teamState) reachers(workerID string) []TeamDevice {
	var out []TeamDevice
	for _, m := range s.members {
		if m.Account != "" && m.reaches(workerID) {
			out = append(out, m.Devices...)
		}
	}
	return out
}

// adminDevices are the devices of the team's admins, which a team worker's
// address keys are wrapped to (decision 25; lane A wraps them).
func (s *teamState) adminDevices() []TeamDevice {
	var out []TeamDevice
	for _, m := range s.members {
		if m.Role == RoleAdmin {
			out = append(out, m.Devices...)
		}
	}
	return out
}

// lostAdmin says whether next drops an admin of prev, lowers one to
// reviewer, or drops one of an admin's devices: each held the team workers'
// address keys, whose signing key must then rotate (§5).
func lostAdmin(prev, next *teamState) bool {
	if prev == nil {
		return false
	}
	for _, m := range prev.members {
		if m.Role != RoleAdmin {
			continue
		}
		if n := next.byID[m.ID]; n == nil || n.Role != RoleAdmin {
			return true
		}
		for _, d := range m.Devices {
			if _, n := next.device(d.ID); n == nil {
				return true
			}
		}
	}
	return false
}

// requireRole is the one check: the caller's device is admitted under a
// member of the caller's account in the worker's team, who reaches the worker
// with at least need. A worker the caller doesn't reach is ErrNoWorker, so it
// can't be told from a missing one; a member who reaches it with too low a
// role is ErrRole. A worker no list has put in a team yet is its creator's
// device's alone, with every role. Called with c.mu held.
func (c *Coordinator) requireRole(caller Caller, workerID string, need Role) (*Member, error) {
	w, ok := c.state.Workers[workerID]
	if !ok {
		return nil, ErrNoWorker
	}
	if w.Team == "" {
		if w.Account != caller.Account || !w.authorizes(caller.Device) {
			return nil, ErrNoWorker
		}
		if !RoleAdmin.allows(need) {
			return nil, fmt.Errorf("%w: no role %q", ErrRole, need)
		}
		return nil, nil
	}
	st, err := c.teamState(w.Team)
	if err != nil {
		return nil, ErrNoWorker
	}
	m := st.byDevice[caller.Device]
	if m == nil || m.Account != caller.Account || !m.reaches(workerID) {
		return nil, ErrNoWorker
	}
	if !m.Role.allows(need) {
		return nil, fmt.Errorf("%w: a %s can't", ErrRole, m.Role)
	}
	return m, nil
}

// requireMember is the caller's member in a team: its device admitted under
// a member of its account. Called with c.mu held.
func (c *Coordinator) requireMember(caller Caller, team string) (*Member, *teamState, error) {
	if _, ok := c.state.Teams[team]; !ok {
		return nil, nil, ErrNoTeam
	}
	st, err := c.teamState(team)
	if err != nil {
		return nil, nil, ErrNoTeam
	}
	m := st.byDevice[caller.Device]
	if m == nil || m.Account != caller.Account {
		return nil, nil, ErrNoTeam
	}
	return m, st, nil
}

// access is requireRole under c.mu: the worker as it stands, and the
// caller's role on it.
func (c *Coordinator) access(caller Caller, workerID string, need Role) (Worker, Role, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	m, err := c.requireRole(caller, workerID, need)
	if err != nil {
		return Worker{}, "", err
	}
	role := RoleAdmin
	if m != nil {
		role = m.Role
	}
	return *c.state.Workers[workerID], role, nil
}

// reachable are the workers the caller reaches, oldest first, with its role
// on each.
func (c *Coordinator) reachable(caller Caller) ([]Worker, []Role) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Worker
	for id, w := range c.state.Workers {
		if _, err := c.requireRole(caller, id, RoleReviewer); err == nil {
			out = append(out, *w)
		}
	}
	slices.SortFunc(out, func(a, b Worker) int { return cmp.Or(a.Created.Compare(b.Created), strings.Compare(a.ID, b.ID)) })
	roles := make([]Role, len(out))
	for i, w := range out {
		roles[i] = RoleAdmin
		if m, _ := c.requireRole(caller, w.ID, RoleReviewer); m != nil {
			roles[i] = m.Role
		}
	}
	return out, roles
}
