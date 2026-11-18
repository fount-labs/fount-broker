package coordinator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Handler is the coordinator's dev API. It has no client authentication, so it
// must only listen on loopback; clients beyond it use the attested channel's
// AccountHandler.
//
//	POST /v0/workers                      {"account", "dek"?}: take in a worker
//	GET  /v0/workers/{id}                 the worker, without its key
//	PUT  /v0/workers/{id}/root/{path...}  write a file into the worker root
//	GET  /v0/workers/{id}/files?prefix=   list the worker's tree
//	GET  /v0/workers/{id}/files/{path...} read a file from the tree
//	POST /v0/workers/{id}/jobs            a JobSpec: queue a job
//	GET  /v0/jobs/{id}                    a job's state
func (c *Coordinator) Handler() http.Handler {
	a := &api{c: c}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v0/workers", a.createWorker)
	a.routes(mux, "/v0")
	return mux
}

// AccountHandler is the API for one account, as the attested client channel
// (package channel) serves it: the account is the one the channel
// authenticated, never one the client names. Another account's workers and
// jobs don't exist here. It is the dev API's operations under /v1, plus:
//
//	POST /v1/workers                      {"dek"?}: take in a worker for this account
//	GET  /v1/workers                      this account's workers
//	POST /v1/workers/{id}/grant           {"v":1,"dek"}: the DEK grant (§3.1 step 4); not built, 501
func (c *Coordinator) AccountHandler(account string) http.Handler {
	a := &api{c: c, account: account}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/workers", a.createWorker)
	mux.HandleFunc("GET /v1/workers", a.listWorkers)
	mux.HandleFunc("POST /v1/workers/{id}/grant", a.grant)
	a.routes(mux, "/v1")
	return mux
}

// api serves both. account is empty for the dev API, which takes the account
// from the request; otherwise every worker it touches must be that account's.
type api struct {
	c       *Coordinator
	account string
}

func (a *api) routes(mux *http.ServeMux, prefix string) {
	mux.HandleFunc("GET "+prefix+"/workers/{id}", a.getWorker)
	mux.HandleFunc("PUT "+prefix+"/workers/{id}/root/{path...}", a.putFile)
	mux.HandleFunc("GET "+prefix+"/workers/{id}/files", a.listFiles)
	mux.HandleFunc("GET "+prefix+"/workers/{id}/files/{path...}", a.getFile)
	mux.HandleFunc("POST "+prefix+"/workers/{id}/jobs", a.enqueue)
	mux.HandleFunc("GET "+prefix+"/jobs/{id}", a.getJob)
}

// worker is the request's worker, if this API may touch it. Another account's
// is ErrNoWorker, so a client can't tell it from one that doesn't exist.
func (a *api) worker(r *http.Request) (Worker, error) {
	return a.workerByID(r.PathValue("id"))
}

func (a *api) workerByID(id string) (Worker, error) {
	w, err := a.c.Worker(id)
	if err != nil {
		return Worker{}, err
	}
	if a.account != "" && w.Account != a.account {
		return Worker{}, ErrNoWorker
	}
	return w, nil
}

const (
	maxCreateBody = 4 << 10
	maxFileBody   = 64 << 20
)

type workerView struct {
	ID      string `json:"id"`
	Account string `json:"account"`
	Version uint64 `json:"version"`
	Created string `json:"created"`
}

func viewOf(w Worker) workerView {
	return workerView{ID: w.ID, Account: w.Account, Version: w.Version, Created: w.Created.Format("2006-01-02T15:04:05Z")}
}

func (a *api) createWorker(rw http.ResponseWriter, r *http.Request) {
	// DEK is the worker's key, base64: Desktop's when it moves a worker in.
	var dekField []byte
	account := a.account
	var err error
	if a.account == "" {
		var req struct {
			Account string `json:"account"`
			DEK     []byte `json:"dek"`
		}
		err = decodeStrict(r.Body, maxCreateBody, &req)
		account, dekField = req.Account, req.DEK
	} else {
		// No account field: the channel says whose worker it is.
		var req struct {
			DEK []byte `json:"dek"`
		}
		err = decodeStrict(r.Body, maxCreateBody, &req)
		dekField = req.DEK
	}
	if err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	dek, err := parseDEK(dekField)
	if err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	w, err := a.c.CreateWorker(account, dek)
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusCreated, viewOf(w))
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
	for _, w := range a.c.Workers(a.account) {
		views = append(views, viewOf(w))
	}
	reply(rw, http.StatusOK, map[string][]workerView{"workers": views})
}

// grant is where Desktop will grant a worker's DEK to the coordinator when it
// moves the worker in (m4-cloud-runners.md §3.1 step 4). The message is fixed
// so both ends can be built against it; taking it isn't built yet.
func (a *api) grant(rw http.ResponseWriter, r *http.Request) {
	var req struct {
		V   int    `json:"v"`
		DEK []byte `json:"dek"`
	}
	if err := decodeStrict(r.Body, maxCreateBody, &req); err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	if req.V != 1 {
		fail(rw, http.StatusBadRequest, fmt.Errorf("grant version %d: want 1", req.V))
		return
	}
	if len(req.DEK) != KeySize {
		fail(rw, http.StatusBadRequest, fmt.Errorf("dek must be %d bytes", KeySize))
		return
	}
	if _, err := a.worker(r); err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	fail(rw, http.StatusNotImplemented, errors.New("the DEK grant isn't built yet (m4-cloud-runners.md §3.1 step 4)"))
}

func (a *api) getWorker(rw http.ResponseWriter, r *http.Request) {
	w, err := a.worker(r)
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusOK, viewOf(w))
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
	if err := a.c.PutFile(r.PathValue("id"), r.PathValue("path"), data); err != nil {
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
	paths, err := a.c.ListFiles(r.PathValue("id"), r.URL.Query().Get("prefix"))
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
	data, err := a.c.ReadFile(r.PathValue("id"), r.PathValue("path"))
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
	j, err := a.c.Enqueue(r.PathValue("id"), spec)
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusAccepted, j)
}

func (a *api) getJob(rw http.ResponseWriter, r *http.Request) {
	j, err := a.c.Job(r.PathValue("id"))
	if err == nil {
		if _, werr := a.workerByID(j.WorkerID); errors.Is(werr, ErrNoWorker) {
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
	case errors.Is(err, ErrNoWorker), errors.Is(err, ErrNoJob), errors.Is(err, ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrWriteOnce):
		return http.StatusConflict
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrReserved):
		return http.StatusBadRequest
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
