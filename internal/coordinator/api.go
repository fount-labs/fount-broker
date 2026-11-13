package coordinator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Handler is the coordinator's dev API. It has no client authentication: the
// attested channel and signed client requests (m4-cloud-runners.md §3.5) come
// later, so it must only listen on loopback.
//
//	POST /v0/workers                      {"account", "dek"?}: take in a worker
//	GET  /v0/workers/{id}                 the worker, without its key
//	PUT  /v0/workers/{id}/root/{path...}  write a file into the worker root
//	GET  /v0/workers/{id}/files?prefix=   list the worker's tree
//	GET  /v0/workers/{id}/files/{path...} read a file from the tree
//	POST /v0/workers/{id}/jobs            a JobSpec: queue a job
//	GET  /v0/jobs/{id}                    a job's state
func (c *Coordinator) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v0/workers", c.createWorker)
	mux.HandleFunc("GET /v0/workers/{id}", c.getWorker)
	mux.HandleFunc("PUT /v0/workers/{id}/root/{path...}", c.putFile)
	mux.HandleFunc("GET /v0/workers/{id}/files", c.listFiles)
	mux.HandleFunc("GET /v0/workers/{id}/files/{path...}", c.getFile)
	mux.HandleFunc("POST /v0/workers/{id}/jobs", c.enqueue)
	mux.HandleFunc("GET /v0/jobs/{id}", c.getJob)
	return mux
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

func (c *Coordinator) createWorker(rw http.ResponseWriter, r *http.Request) {
	var req struct {
		Account string `json:"account"`
		// DEK is the worker's key, base64: Desktop's when it moves a worker in.
		DEK []byte `json:"dek"`
	}
	if err := decodeStrict(r.Body, maxCreateBody, &req); err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	var dek *DEK
	if req.DEK != nil {
		if len(req.DEK) != KeySize {
			fail(rw, http.StatusBadRequest, fmt.Errorf("dek must be %d bytes", KeySize))
			return
		}
		dek = new(DEK)
		copy(dek[:], req.DEK)
	}
	w, err := c.CreateWorker(req.Account, dek)
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusCreated, viewOf(w))
}

func (c *Coordinator) getWorker(rw http.ResponseWriter, r *http.Request) {
	w, err := c.Worker(r.PathValue("id"))
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusOK, viewOf(w))
}

func (c *Coordinator) putFile(rw http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(io.LimitReader(r.Body, maxFileBody+1))
	if err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	if len(data) > maxFileBody {
		fail(rw, http.StatusRequestEntityTooLarge, fmt.Errorf("files are at most %d bytes here", maxFileBody))
		return
	}
	if err := c.PutFile(r.PathValue("id"), r.PathValue("path"), data); err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

func (c *Coordinator) listFiles(rw http.ResponseWriter, r *http.Request) {
	paths, err := c.ListFiles(r.PathValue("id"), r.URL.Query().Get("prefix"))
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	if paths == nil {
		paths = []string{}
	}
	reply(rw, http.StatusOK, map[string][]string{"paths": paths})
}

func (c *Coordinator) getFile(rw http.ResponseWriter, r *http.Request) {
	data, err := c.ReadFile(r.PathValue("id"), r.PathValue("path"))
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	rw.Header().Set("Content-Type", "application/octet-stream")
	rw.Header().Set("X-Content-Type-Options", "nosniff")
	rw.Write(data)
}

func (c *Coordinator) enqueue(rw http.ResponseWriter, r *http.Request) {
	spec, err := ParseJobSpec(r.Body)
	if err != nil {
		fail(rw, http.StatusBadRequest, err)
		return
	}
	j, err := c.Enqueue(r.PathValue("id"), spec)
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusAccepted, j)
}

func (c *Coordinator) getJob(rw http.ResponseWriter, r *http.Request) {
	j, err := c.Job(r.PathValue("id"))
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
