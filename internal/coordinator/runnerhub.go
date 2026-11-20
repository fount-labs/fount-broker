package coordinator

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fount-labs/fount-broker/internal/frame"
	"github.com/fount-labs/fount-broker/internal/jobwire"
	"github.com/fount-labs/fount-broker/internal/link"
)

// RunnerHub holds the links runner enclaves dialled in to the coordinator
// (launch plan work R): a runner can't be on the coordinator's measured
// egress allowlist when it may be stopped or not made yet, so it opens the
// link, and the coordinator sends a job over it as it would over one it
// dialled. Each link carries one job; a runner keeps a few parked, waiting,
// and dials another for each one a job takes.
//
// Both ends check each other as on a dialled link: the hub's Side checks the
// runner's document against the runner repo, and the runner checks the
// coordinator's. A parked link is handed out only within link.ParkFor less a
// minute of its handshake, and before its verification's freshness deadline.
//
// The hub answers on link.Path for link.DialInProtocol, on the listener the
// enclave's shim exposes. While nothing is parked the Pool hands out no slot
// (ReadyFor), so jobs and intake wait in the queue.
//
// Team runners (launch plan work R2, R3). Every team's runner runs the same
// measured release as the pool's; what makes one a team's is the name it
// links in with. The hub knows a runner by its attested link key, which is
// per boot, and groups its links by it. With TeamStage set, a runner whose
// first link is named runner-<TeamStage>-tm-<24 hex> is bound to team
// tm_<hex> for that key: the hub tells it so with a bind frame on each of its
// links (package jobwire), and hands its links only to that team's jobs.
// Every other name is a pool runner, for solo accounts. A later link from the
// same key under another name is refused, so a key is never rebound.
//
// Nothing attests the name: it comes from an unmeasured Tinfoil variable.
// A host that lies about it only sends a team's jobs to another genuine
// runner, which then serves that team alone this boot; the runner holds the
// binding too (package relay), and refuses any other account's job.
//
// Isolation groups (an ethical wall's own enclave within a team, a paid
// add-on) aren't modelled yet: the binding is to an account. A group would
// extend the name and the bind frame to an account and a group, and
// Placement to the group a job's worker is in.
type RunnerHub struct {
	Side *link.Side
	// Changed, if set, is called when a runner's first link parks, so queued
	// jobs and waiting intake get another look.
	Changed func()
	// TakeWait bounds how long Take waits for a parked link for a pool job.
	// Zero is DefaultTakeWait. A team's job waits for its runner as long as
	// the job may run (Take).
	TakeWait time.Duration
	// TeamStage, if set, turns team runners on: runners named
	// runner-<TeamStage>-tm-<24 hex> serve that team alone, and teams' jobs
	// go only to them. Empty puts every job on every runner, as before.
	TeamStage string

	mu      sync.Mutex
	parked  []*parkedLink
	runners map[string]*hubRunner
	// bindings are each runner key's name and account for its boot. They
	// outlive the key's links, so a runner that drops every link and dials
	// again can't come back under another name.
	bindings map[string]*runnerBinding
	// teams are each team's runner activity, for the control route.
	teams   map[string]*teamActivity
	arrived chan struct{} // closed and replaced when a link parks
	closed  bool
	ctx     context.Context
	cancel  context.CancelFunc
}

// runnerBinding is one runner key's boot: the name its first link gave, and the
// team that bound it to, or empty for the pool.
type runnerBinding struct {
	name, account string
	last          time.Time
}

// bindingKeep is how long a binding outlives its key's last link. A runner
// keeps spare links parked all its boot, so a key with no link for a day is
// a boot that ended.
const bindingKeep = 24 * time.Hour

// teamActivity is a team's runner activity since the coordinator started:
// its runner's first link of each boot, and its jobs' links taken and ended.
type teamActivity struct {
	linked, started, ended time.Time
}

// bindWriteTimeout bounds sending the bind frame on a new link.
const bindWriteTimeout = 10 * time.Second

// DefaultTakeWait is long enough for a runner to dial a new link when a job
// took its last parked one.
const DefaultTakeWait = 2 * time.Minute

// parkedLink is a link with no job yet. watch reads it until it's taken: a
// runner sends nothing on a parked link, so anything it reads ends it.
type parkedLink struct {
	conn    net.Conn
	runner  string // the hubRunner key
	account string // the team its runner is bound to, or empty for the pool
	release link.Release
	expires time.Time
	taken   bool
	watched chan error // the watch's end
}

// hubRunner is one runner boot, by its attested link key.
type hubRunner struct {
	Name string `json:"name,omitempty"` // its own claim, unattested; not shown for a team's
	// Team marks a team's runner. /status is public, so it names no team.
	Team    bool      `json:"team,omitempty"`
	Key     string    `json:"key"` // the attested link key's first bytes, hex
	Since   time.Time `json:"since"`
	Parked  int       `json:"parked"`
	Busy    int       `json:"busy"`
	account string
}

func NewRunnerHub(side *link.Side) *RunnerHub {
	ctx, cancel := context.WithCancel(context.Background())
	return &RunnerHub{Side: side, runners: map[string]*hubRunner{}, bindings: map[string]*runnerBinding{}, teams: map[string]*teamActivity{},
		arrived: make(chan struct{}), ctx: ctx, cancel: cancel}
}

// ErrRunnerRenamed is a link from a runner key that linked in before under
// another name: its binding is for the boot.
var ErrRunnerRenamed = errors.New("the runner linked in before under another name")

// teamIDPattern is a firm team's id as MintTeam makes it.
var teamIDPattern = regexp.MustCompile(`^` + teamIDPrefix + `_[0-9a-f]{24}$`)

// IsTeamID says whether account is a firm team's id.
func IsTeamID(account string) bool { return teamIDPattern.MatchString(account) }

// TeamRunnerName is team's runner's container name in stage: runner-<stage>-
// and the id with "_" as "-" (fount-infra docs/TEAM_RUNNERS.md).
func TeamRunnerName(stage, team string) string {
	return "runner-" + stage + "-" + strings.Replace(team, "_", "-", 1)
}

// teamOf is the team a runner's name binds it to, or empty for the pool.
func (h *RunnerHub) teamOf(name string) string {
	prefix := "runner-" + h.TeamStage + "-" + teamIDPrefix + "-"
	if h.TeamStage == "" || !strings.HasPrefix(name, prefix) {
		return ""
	}
	team := teamIDPrefix + "_" + name[len(prefix):]
	if !IsTeamID(team) {
		return ""
	}
	return team
}

// Placement is the team whose runner account's jobs go to, or empty for the
// pool: a team's jobs only to its own runner, a solo account's only to pool
// runners.
func (h *RunnerHub) Placement(account string) string {
	if h.TeamStage != "" && IsTeamID(account) {
		return account
	}
	return ""
}

// bind is key's binding, made from name on its first link. A key that linked
// before under another name is refused. It holds h.mu.
func (h *RunnerHub) bind(key, name string, now time.Time) (*runnerBinding, error) {
	for k, b := range h.bindings {
		if h.runners[k] == nil && now.Sub(b.last) > bindingKeep {
			delete(h.bindings, k)
		}
	}
	b := h.bindings[key]
	if b == nil {
		b = &runnerBinding{name: name, account: h.teamOf(name)}
		h.bindings[key] = b
		if b.account != "" {
			h.team(b.account).linked = now
		}
	} else if b.name != name {
		return nil, ErrRunnerRenamed
	}
	b.last = now
	return b, nil
}

// team is account's activity, made if new. It holds h.mu.
func (h *RunnerHub) team(account string) *teamActivity {
	t := h.teams[account]
	if t == nil {
		t = &teamActivity{}
		h.teams[account] = t
	}
	return t
}

var ErrNoRunnerLink = errors.New("no runner enclave has a link to the coordinator")

func (h *RunnerHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != link.Path {
		http.NotFound(w, r)
		return
	}
	name := r.Header.Get(link.NameHeader)
	if len(name) > 253 {
		name = name[:253]
	}
	conn, ok := link.Upgrade(w, r, link.DialInProtocol)
	if !ok {
		return
	}
	go h.admit(conn, name)
}

// admit runs the handshake on a runner's connection and parks it.
func (h *RunnerHub) admit(raw net.Conn, name string) {
	start := time.Now()
	conn, e, err := h.Side.ServerEndorsed(h.ctx, raw)
	if err != nil {
		raw.Close()
		log.Printf("runner link from %s (%q): %v", raw.RemoteAddr(), name, err)
		return
	}
	expires := start.Add(link.ParkFor - time.Minute)
	if !e.Fresh.IsZero() && e.Fresh.Before(expires) {
		expires = e.Fresh
	}
	key := hex.EncodeToString(e.Key[:8])
	h.mu.Lock()
	b, err := h.bind(key, name, time.Now().UTC())
	h.mu.Unlock()
	if err != nil {
		conn.Close()
		log.Printf("runner %s: refused a link named %q: %v", key, name, err)
		return
	}
	account := b.account
	if account != "" {
		conn.SetWriteDeadline(time.Now().Add(bindWriteTimeout))
		err := jobwire.Send(frame.NewWriter(conn), jobwire.Bind{Kind: jobwire.KindBind, Account: account}, nil)
		conn.SetWriteDeadline(time.Time{})
		if err != nil {
			conn.Close()
			log.Printf("runner %s: bind it to its team: %v", key, err)
			return
		}
	}
	p := &parkedLink{conn: conn, runner: key, account: account, release: e.Release, expires: expires, watched: make(chan error, 1)}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		conn.Close()
		return
	}
	r := h.runners[key]
	first := r == nil
	if first {
		r = &hubRunner{Name: name, Team: account != "", Key: key, Since: time.Now().UTC(), account: account}
		h.runners[key] = r
		if account != "" {
			log.Printf("runner %s linked in, bound to a team", key)
		} else {
			log.Printf("runner %s (%q) linked in", key, name)
		}
	}
	r.Parked++
	h.parked = append(h.parked, p)
	close(h.arrived)
	h.arrived = make(chan struct{})
	h.mu.Unlock()
	go h.watch(p)
	if first && h.Changed != nil {
		h.Changed()
	}
}

// watch reads a parked link until Take interrupts it. Anything else that
// ends the read, the runner closing, a dead link or bytes it shouldn't send,
// drops the link.
func (h *RunnerHub) watch(p *parkedLink) {
	var b [1]byte
	_, err := p.conn.Read(b[:])
	if err == nil {
		err = errors.New("the runner sent on a parked link")
	}
	h.mu.Lock()
	taken := p.taken
	if !taken {
		h.unpark(p, false)
	}
	h.mu.Unlock()
	if !taken {
		p.conn.Close()
	}
	p.watched <- err
}

// unpark removes p from the parked links, and counts it busy if it's taken
// for a job. It holds h.mu.
func (h *RunnerHub) unpark(p *parkedLink, busy bool) {
	i := slices.Index(h.parked, p)
	if i < 0 {
		return
	}
	h.parked = slices.Delete(h.parked, i, i+1)
	if busy {
		h.forget(p.runner, -1, 1)
		return
	}
	h.forget(p.runner, -1, 0)
}

// forget changes a runner's counts and drops it once it has no links. It
// holds h.mu.
func (h *RunnerHub) forget(key string, parked, busy int) {
	r := h.runners[key]
	if r == nil {
		return
	}
	r.Parked += parked
	r.Busy += busy
	if r.Parked == 0 && r.Busy == 0 {
		delete(h.runners, key)
		if b := h.bindings[key]; b != nil {
			b.last = time.Now().UTC()
		}
		if r.Team {
			log.Printf("runner %s, a team's, has no links left", key)
		} else {
			log.Printf("runner %s (%q) has no links left", key, r.Name)
		}
	}
}

// Ready reports whether any runner has a link, parked or carrying a job.
func (h *RunnerHub) Ready() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.runners) > 0
}

// ReadyFor reports whether a runner account's jobs may go to has a link,
// parked or carrying a job: the Pool's gate. A team with no runner linked has
// no room, so its jobs wait in the queue until its runner links in.
func (h *RunnerHub) ReadyFor(account string) bool {
	want := h.Placement(account)
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.runners {
		if r.account == want {
			return true
		}
	}
	return false
}

// Take hands out a parked link for one of account's jobs, from a runner its
// jobs may go to (Placement). Closing it ends the job's link.
//
// A pool job waits up to TakeWait. A team's job waits until ctx ends, which
// is the job's own timeout: the Pool gave it a slot only once the team's
// runner had linked in, and if that runner is gone again (stopped, or
// restarting, which with its harness pull takes minutes), the Lambda that
// starts team runners sees the job and starts it.
func (h *RunnerHub) Take(ctx context.Context, account string) (net.Conn, error) {
	want := h.Placement(account)
	wait := h.TakeWait
	if wait == 0 {
		wait = DefaultTakeWait
	}
	var timeout <-chan time.Time
	if want == "" {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		timeout = timer.C
	}
	for {
		h.mu.Lock()
		if h.closed {
			h.mu.Unlock()
			return nil, ErrNoRunnerLink
		}
		p := h.pick(want, time.Now())
		if p != nil {
			p.taken = true
			h.unpark(p, true)
			if want != "" {
				h.team(want).started = time.Now().UTC()
			}
		}
		arrived := h.arrived
		h.mu.Unlock()
		if p != nil {
			conn, err := h.claim(p)
			if err == nil {
				return conn, nil
			}
			log.Printf("runner %s: a parked link was gone: %v", p.runner, err)
			continue
		}
		select {
		case <-arrived:
		case <-timeout:
			return nil, fmt.Errorf("%w for %s", ErrNoRunnerLink, wait)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// pick is the newest parked link of a runner bound to want, which has the
// most time left, closing those past their time. It holds h.mu.
func (h *RunnerHub) pick(want string, now time.Time) *parkedLink {
	for i := len(h.parked) - 1; i >= 0; i-- {
		p := h.parked[i]
		if !now.Before(p.expires) {
			h.unpark(p, false)
			p.taken = true
			p.conn.Close()
			continue
		}
		if p.account == want {
			return p
		}
	}
	return nil
}

// claim stops p's watch and gives its link to a job, unless the watch had
// already seen it end.
func (h *RunnerHub) claim(p *parkedLink) (net.Conn, error) {
	p.conn.SetReadDeadline(time.Now())
	err := <-p.watched
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		p.conn.Close()
		h.done(p)
		return nil, err
	}
	p.conn.SetReadDeadline(time.Time{})
	return &busyLink{Conn: p.conn, enclave: p.enclave(), done: func() { h.done(p) }}, nil
}

func (h *RunnerHub) done(p *parkedLink) {
	h.mu.Lock()
	h.forget(p.runner, 0, -1)
	if p.account != "" {
		h.team(p.account).ended = time.Now().UTC()
	}
	h.mu.Unlock()
}

// busyLink is a taken link; closing it counts its job's end once.
type busyLink struct {
	net.Conn
	enclave RunnerEnclave
	once    sync.Once
	done    func()
}

// Where a job ran, as RunnerEnclave.Kind says it.
const (
	enclavePool = "pool"
	enclaveTeam = "team"
)

// RunnerEnclave is where a job ran, as its turn shows it: the shared pool's
// runner or the team's own, and the release the coordinator verified that
// runner runs when it linked in. It names no team.
type RunnerEnclave struct {
	Kind   string `json:"kind"`
	Repo   string `json:"repo,omitempty"`
	Tag    string `json:"tag,omitempty"`
	Digest string `json:"digest,omitempty"`
}

func (p *parkedLink) enclave() RunnerEnclave {
	kind := enclavePool
	if p.account != "" {
		kind = enclaveTeam
	}
	return RunnerEnclave{Kind: kind, Repo: p.release.Repo, Tag: p.release.Tag, Digest: p.release.Digest}
}

// EnclaveOf is where the job on conn, a link Take handed out, runs; false
// for any other connection.
func EnclaveOf(conn net.Conn) (RunnerEnclave, bool) {
	b, ok := conn.(*busyLink)
	if !ok {
		return RunnerEnclave{}, false
	}
	return b.enclave, true
}

func (b *busyLink) Close() error {
	err := b.Conn.Close()
	b.once.Do(b.done)
	return err
}

// RunnerStatus is one linked runner, as /status shows it.
type RunnerStatus = hubRunner

// Runners are the runners with links, oldest first. A team's is shown with
// no name, which would name the team.
func (h *RunnerHub) Runners() []RunnerStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]RunnerStatus, 0, len(h.runners))
	for _, r := range h.runners {
		s := *r
		if s.Team {
			s.Name = ""
		}
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b RunnerStatus) int { return a.Since.Compare(b.Since) })
	return out
}

// TeamLink is a team's runner as the hub sees it.
type TeamLink struct {
	// Connected is a runner bound to the team with a link open.
	Connected bool
	// Busy is the team's jobs on its runner's links now.
	Busy int
	// Last is the latest of its runner's first link of a boot and its jobs'
	// links taken and ended, since the coordinator started; zero if none.
	Last time.Time
}

// TeamLinks are the teams whose runners linked in since the coordinator
// started.
func (h *RunnerHub) TeamLinks() map[string]TeamLink {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]TeamLink, len(h.teams))
	for id, t := range h.teams {
		out[id] = TeamLink{Last: latest(t.linked, t.started, t.ended)}
	}
	for _, r := range h.runners {
		if r.account == "" {
			continue
		}
		l := out[r.account]
		l.Connected = true
		l.Busy += r.Busy
		out[r.account] = l
	}
	return out
}

func latest(ts ...time.Time) time.Time {
	var out time.Time
	for _, t := range ts {
		if t.After(out) {
			out = t
		}
	}
	return out
}

// Close drops every parked link and refuses new ones. Links carrying jobs
// end with their jobs.
func (h *RunnerHub) Close() {
	h.mu.Lock()
	h.closed = true
	parked := slices.Clone(h.parked)
	h.mu.Unlock()
	h.cancel()
	for _, p := range parked {
		p.conn.Close()
	}
}
