package coordinator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// Handler is the coordinator's dev API. It has no client authentication, so it
// must only listen on loopback; clients beyond it use the attested channel's
// AccountHandler. A worker with a device list, made over the channel, doesn't
// exist here, and a coordinator with the vault's wrapping key doesn't serve it
// at all.
//
//	POST /v0/workers                      {"account", "dek"?}: take in a worker
//	GET  /v0/workers/{id}                 the worker, without its key
//	PUT  /v0/workers/{id}/root/{path...}  write a file into the worker root
//	GET  /v0/workers/{id}/files?prefix=   list the worker's tree
//	GET  /v0/workers/{id}/files/{path...} read a file from the tree
//	POST /v0/workers/{id}/jobs            a JobSpec: queue a job (tests)
//	GET  /v0/jobs/{id}                    a job's state
//	GET  /v0/workers/{id}/threads         the worker's threads, newest first
//	GET  /v0/workers/{id}/threads/{tid}   a thread's display form; ?since=N, what changed after N
//	POST /v0/workers/{id}/threads/{tid}/ops  a thread operation (threadops.go)
//	POST /v0/workers/{id}/ops             a worker operation: startThread
//	PUT  /v0/workers/{id}/mail            {mailbox, requesters?}: the address and its keys, until A
//	GET  /v0/workers/{id}/mail            the worker's mail settings, without keys
func (c *Coordinator) Handler() http.Handler {
	a := &api{c: c}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v0/workers", a.createWorker)
	mux.HandleFunc("PUT /v0/workers/{id}/mail", a.putMailbox)
	a.routes(mux, "/v0")
	return mux
}

// AccountHandler is the API for one caller, as the attested client channel
// (package channel) serves it: the account and device are the ones the
// channel authenticated, never ones the client names. Only workers of that
// account that list that device exist here (grant.go). It is the dev API's
// operations under /v1, each needing the role opRoles gives it on the
// worker (members.go), plus:
//
//	POST /v1/workers                      {}: an empty worker, the caller's device's, until a list adds it to a team
//	GET  /v1/workers                      the workers the caller reaches
//	GET  /v1/teams/{team}/log?since=N     the team's membership log after entry N, for any member
//	POST /v1/teams/{team}/log             {"v":3,"list","deks"}: a list an admin device signed (teamlog.go)
//	GET  /v1/teams                        the teams the caller's account is a member of
//	POST /v1/teams/{team}/invites/{invite}/open|accept|send  an invite (teaminvite.go)
//	POST /v1/teams/{team}/joins, GET …/joins[/{join}], POST …/{join}/approve|deny|accept  a second device (teamjoin.go)
//	POST /v1/workers/{id}/grant, /revoke  the retired v2 grants: 410
//
// A caller without an account or device panics: it would be no one's API,
// and never the dev API's every account.
func (c *Coordinator) AccountHandler(caller Caller) http.Handler {
	if caller.Account == "" || caller.Device == "" {
		panic("coordinator: AccountHandler for no account or device")
	}
	a := &api{c: c, account: caller.Account, caller: &caller}
	mux := http.NewServeMux()
	a.accountRoutes(mux)
	return mux
}

// router is what registers a route: an http.ServeMux, or a test's list.
type router interface {
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
}

func (a *api) accountRoutes(mux router) {
	mux.HandleFunc("POST /v1/workers", a.createWorker)
	mux.HandleFunc("GET /v1/workers", a.listWorkers)
	mux.HandleFunc("POST /v1/workers/{id}/grant", a.retired)
	mux.HandleFunc("POST /v1/workers/{id}/revoke", a.retired)
	mux.HandleFunc("POST /v1/teams", a.mintTeam)
	mux.HandleFunc("GET /v1/teams/{team}/log", a.teamLog)
	mux.HandleFunc("POST /v1/teams/{team}/log", a.appendTeamList)
	mux.HandleFunc("GET /v1/teams", a.myTeams)
	mux.HandleFunc("POST /v1/teams/{team}/invites/{invite}/open", a.openInvite)
	mux.HandleFunc("POST /v1/teams/{team}/invites/{invite}/accept", a.acceptInvite)
	mux.HandleFunc("POST /v1/teams/{team}/invites/{invite}/send", a.sendInvite)
	mux.HandleFunc("POST /v1/teams/{team}/joins", a.startJoin)
	mux.HandleFunc("GET /v1/teams/{team}/joins", a.pendingJoins)
	mux.HandleFunc("GET /v1/teams/{team}/joins/{join}", a.joinStatus)
	mux.HandleFunc("POST /v1/teams/{team}/joins/{join}/approve", a.approveJoin)
	mux.HandleFunc("POST /v1/teams/{team}/joins/{join}/deny", a.denyJoin)
	mux.HandleFunc("POST /v1/teams/{team}/joins/{join}/accept", a.acceptJoin)
	a.routes(mux, "/v1")
}

// api serves both. caller is nil for the dev API, which takes the account
// from the request; otherwise every worker it touches must be account's and
// list caller's device.
type api struct {
	c       *Coordinator
	account string
	caller  *Caller
}

// device is the caller's device, which the coordinator checks again under
// the tree's lock, or anyDevice for the dev API.
func (a *api) device() string {
	if a.caller == nil {
		return anyDevice
	}
	return a.caller.Device
}

func (a *api) routes(mux router, prefix string) {
	mux.HandleFunc("GET "+prefix+"/workers/{id}", a.getWorker)
	mux.HandleFunc("PUT "+prefix+"/workers/{id}/root/{path...}", a.putFile)
	mux.HandleFunc("GET "+prefix+"/workers/{id}/files", a.listFiles)
	mux.HandleFunc("GET "+prefix+"/workers/{id}/files/{path...}", a.getFile)
	mux.HandleFunc("POST "+prefix+"/workers/{id}/jobs", a.enqueue)
	mux.HandleFunc("GET "+prefix+"/jobs/{id}", a.getJob)
	mux.HandleFunc("GET "+prefix+"/workers/{id}/threads", a.listThreads)
	mux.HandleFunc("GET "+prefix+"/workers/{id}/threads/{tid}", a.getThread)
	mux.HandleFunc("POST "+prefix+"/workers/{id}/threads/{tid}/ops", a.threadOp)
	mux.HandleFunc("POST "+prefix+"/workers/{id}/ops", a.workerOp)
	mux.HandleFunc("GET "+prefix+"/workers/{id}/mail", a.getMail)
}

// worker is the request's worker, if this API may touch it with the role
// its route needs. One the caller doesn't reach is ErrNoWorker, so a client
// can't tell it from one that doesn't exist; one it reaches with too low a
// role is ErrRole.
func (a *api) worker(r *http.Request) (Worker, error) {
	return a.workerByID(r, r.PathValue("id"))
}

func (a *api) workerByID(r *http.Request, id string) (Worker, error) {
	if a.caller != nil {
		need, ok := opRole(routeKey(r.Pattern))
		if !ok {
			return Worker{}, fmt.Errorf("%w: %s has no role", ErrRole, r.Pattern)
		}
		w, _, err := a.c.access(*a.caller, id, need)
		return w, err
	}
	w, err := a.c.Worker(id)
	if err != nil {
		return Worker{}, err
	}
	// The dev API never opens a worker a device list keeps: one made over
	// the client channel.
	if len(w.Devices) > 0 || w.Team != "" {
		return Worker{}, ErrNoWorker
	}
	return w, nil
}

// kindAllowed checks an operation's kind against the caller's role on the
// worker, as the route was. A kind with no role is refused.
func (a *api) kindAllowed(id, kind string) error {
	if a.caller == nil {
		return nil
	}
	need, ok := opRole(kind)
	if !ok {
		return fmt.Errorf("%w: the operation %.40q has no role", ErrRole, kind)
	}
	_, _, err := a.c.access(*a.caller, id, need)
	return err
}

const (
	maxCreateBody = 4 << 10
	maxGrantBody  = 32 << 10
	maxFileBody   = 64 << 20
)

type workerView struct {
	ID      string `json:"id"`
	Account string `json:"account"`
	Version uint64 `json:"version"`
	Created string `json:"created"`
	// The account API's alone: whether a list has put the worker in a team
	// with its DEK, the team, the caller's role on it, the DEK commitment the
	// list signed, the devices that reach the worker, and the caller's
	// device's wrap of the DEK.
	Granted       *bool    `json:"granted,omitempty"`
	Team          string   `json:"team,omitempty"`
	Role          Role     `json:"role,omitempty"`
	DEKCommitment string   `json:"dekCommitment,omitempty"`
	Devices       []string `json:"devices,omitempty"`
	Wrap          []byte   `json:"wrap,omitempty"`
}

func (a *api) viewOf(w Worker, role Role) workerView {
	v := workerView{ID: w.ID, Account: w.Account, Version: w.Version, Created: w.Created.Format("2006-01-02T15:04:05Z")}
	if a.caller == nil {
		return v
	}
	granted := w.WrappedDEK != nil
	v.Granted, v.Team, v.Role, v.DEKCommitment = &granted, w.Team, role, w.DEKCommitment
	for _, d := range w.Devices {
		v.Devices = append(v.Devices, d.ID)
		if d.ID == a.caller.Device {
			v.Wrap = d.Wrap
		}
	}
	return v
}

func (a *api) createWorker(rw http.ResponseWriter, r *http.Request) {
	if a.caller != nil {
		// No account and no DEK: the channel says whose worker it is, and
		// the DEK comes signed, in a grant.
		var req struct{}
		if err := decodeStrict(r.Body, maxCreateBody, &req); err != nil {
			fail(rw, http.StatusBadRequest, err)
			return
		}
		w, err := a.c.CreateWorkerFor(*a.caller)
		if err != nil {
			fail(rw, statusOf(err), err)
			return
		}
		reply(rw, http.StatusCreated, a.viewOf(w, RoleAdmin))
		return
	}
	// DEK is the worker's key, base64.
	var req struct {
		Account string `json:"account"`
		DEK     []byte `json:"dek"`
	}
	if err := decodeStrict(r.Body, maxCreateBody, &req); err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	dek, err := parseDEK(req.DEK)
	clear(req.DEK)
	if err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	if dek != nil {
		defer clear(dek[:])
	}
	w, err := a.c.CreateWorker(req.Account, dek)
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusCreated, a.viewOf(w, ""))
}

func parseDEK(b []byte) (*DEK, error) {
	if b == nil {
		return nil, nil
	}
	if len(b) != KeySize {
		return nil, fmt.Errorf("dek must be %d bytes", KeySize)
	}
	dek := new(DEK)
	copy(dek[:], b)
	return dek, nil
}

func (a *api) listWorkers(rw http.ResponseWriter, _ *http.Request) {
	views := []workerView{}
	workers, roles := a.c.reachable(*a.caller)
	for i, w := range workers {
		views = append(views, a.viewOf(w, roles[i]))
	}
	reply(rw, http.StatusOK, map[string][]workerView{"workers": views})
}

func (a *api) getWorker(rw http.ResponseWriter, r *http.Request) {
	if a.caller == nil {
		w, err := a.worker(r)
		if err != nil {
			fail(rw, statusOf(err), err)
			return
		}
		reply(rw, http.StatusOK, a.viewOf(w, ""))
		return
	}
	w, role, err := a.c.access(*a.caller, r.PathValue("id"), RoleReviewer)
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusOK, a.viewOf(w, role))
}

func (a *api) putFile(rw http.ResponseWriter, r *http.Request) {
	if _, err := a.worker(r); err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxFileBody+1))
	if err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	if len(data) > maxFileBody {
		fail(rw, http.StatusRequestEntityTooLarge, fmt.Errorf("files are at most %d bytes here", maxFileBody))
		return
	}
	if err := a.c.putFile(a.device(), r.PathValue("id"), r.PathValue("path"), data); err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

func (a *api) listFiles(rw http.ResponseWriter, r *http.Request) {
	if _, err := a.worker(r); err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	paths, err := a.c.listFiles(a.device(), r.PathValue("id"), r.URL.Query().Get("prefix"))
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	if paths == nil {
		paths = []string{}
	}
	reply(rw, http.StatusOK, map[string][]string{"paths": paths})
}

func (a *api) getFile(rw http.ResponseWriter, r *http.Request) {
	if _, err := a.worker(r); err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	data, err := a.c.readFile(a.device(), r.PathValue("id"), r.PathValue("path"))
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	rw.Header().Set("Content-Type", "application/octet-stream")
	rw.Header().Set("X-Content-Type-Options", "nosniff")
	rw.Write(data)
}

func (a *api) enqueue(rw http.ResponseWriter, r *http.Request) {
	if _, err := a.worker(r); err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	spec, err := ParseJobSpec(r.Body)
	if err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	j, err := a.c.enqueue(a.device(), r.PathValue("id"), spec)
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusAccepted, j)
}

func (a *api) getJob(rw http.ResponseWriter, r *http.Request) {
	j, err := a.c.Job(r.PathValue("id"))
	if err == nil {
		if _, werr := a.workerByID(r, j.WorkerID); errors.Is(werr, ErrNoWorker) {
			err = ErrNoJob
		} else {
			err = werr
		}
	}
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusOK, j)
}

func (a *api) listThreads(rw http.ResponseWriter, r *http.Request) {
	if _, err := a.worker(r); err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	threads, err := a.c.threads(a.device(), r.PathValue("id"))
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusOK, map[string][]ThreadSummary{"threads": threads})
}

// getThread is the whole thread, a ThreadView, or with ?since=N a
// ThreadChanges.
func (a *api) getThread(rw http.ResponseWriter, r *http.Request) {
	if _, err := a.worker(r); err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	var since *uint64
	if q := r.URL.Query(); q.Has("since") {
		n, err := strconv.ParseUint(q.Get("since"), 10, 64)
		if err != nil {
			fail(rw, http.StatusBadRequest, fmt.Errorf("%w: since must be a revision", ErrInvalid))
			return
		}
		since = &n
	}
	th, err := a.c.thread(a.device(), r.PathValue("id"), r.PathValue("tid"))
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	hideExpiredClaims(th, time.Now())
	if since != nil {
		reply(rw, http.StatusOK, th.changes(*since))
		return
	}
	reply(rw, http.StatusOK, th.view())
}

// threadOp answers 200 with the OpResult, a refusal included.
func (a *api) threadOp(rw http.ResponseWriter, r *http.Request) {
	if _, err := a.worker(r); err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	var env opEnvelope
	if err := decodeStrict(r.Body, maxOpBody, &env); err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	if err := a.kindAllowed(r.PathValue("id"), env.Kind); err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	result, err := a.c.applyThreadOp(a.device(), r.PathValue("id"), r.PathValue("tid"), env)
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusOK, result)
}

func (a *api) workerOp(rw http.ResponseWriter, r *http.Request) {
	if _, err := a.worker(r); err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	var env workerOpEnvelope
	if err := decodeStrict(r.Body, maxOpBody, &env); err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	if err := a.kindAllowed(r.PathValue("id"), env.Kind); err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	result, err := a.c.applyWorkerOp(a.device(), r.PathValue("id"), env)
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusOK, result)
}

func decodeStrict(body io.Reader, max int64, v any) error {
	data, err := io.ReadAll(io.LimitReader(body, max+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > max {
		return fmt.Errorf("body is over %d bytes", max)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after the object")
	}
	return nil
}

func statusOf(err error) int {
	switch {
	case errors.Is(err, ErrNoWorker), errors.Is(err, ErrNoJob), errors.Is(err, ErrNotFound), errors.Is(err, ErrNoThread),
		errors.Is(err, ErrNoTeam), errors.Is(err, ErrNoMailbox):
		return http.StatusNotFound
	case errors.Is(err, ErrWriteOnce), errors.Is(err, ErrNotGranted), errors.Is(err, ErrTeamStale), errors.Is(err, ErrBusy):
		return http.StatusConflict
	case errors.Is(err, ErrListRefused), errors.Is(err, ErrNotAdmin), errors.Is(err, ErrRole):
		return http.StatusForbidden
	case errors.Is(err, ErrRetired):
		return http.StatusGone
	case errors.Is(err, ErrTooManyUngranted):
		return http.StatusTooManyRequests
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrReserved):
		return http.StatusBadRequest
	case errors.Is(err, ErrUnsupported):
		return http.StatusNotImplemented
	default:
		return http.StatusInternalServerError
	}
}

func reply(rw http.ResponseWriter, status int, v any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	json.NewEncoder(rw).Encode(v)
}

func fail(rw http.ResponseWriter, status int, err error) {
	reply(rw, status, map[string]string{"error": err.Error()})
}
