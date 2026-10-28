// Package protocol defines the frame headers the app and the broker exchange.
//
// App to broker:
//
//	{"kind":"fetch","id":N,"dest":"tinfoil.chat_completions","accept":"text/event-stream"}  body: opaque request
//	{"kind":"cancel","id":N}
//	{"kind":"credential","id":N,"name":"license"}  body: the secret
//	{"kind":"status","id":N,"route":"tinfoil"}
//
// Broker to app:
//
//	{"kind":"ready","version":"…","protocol":1}
//	{"kind":"head","id":N,"status":200,"contentType":"text/event-stream"}
//	{"kind":"data","id":N}  body: a chunk of the response
//	{"kind":"end","id":N}
//	{"kind":"result","id":N}  body: JSON
//	{"kind":"error","id":N,"code":"…","message":"…"}
//
// A fetch gets one head, any number of data frames, then end or error. The
// other requests get one result or one error.
package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

const Version = 1

type Kind string

const (
	KindFetch      Kind = "fetch"
	KindCancel     Kind = "cancel"
	KindCredential Kind = "credential"
	KindStatus     Kind = "status"

	KindReady  Kind = "ready"
	KindHead   Kind = "head"
	KindData   Kind = "data"
	KindEnd    Kind = "end"
	KindResult Kind = "result"
	KindError  Kind = "error"
)

// Request is every header the app may send. Fields that don't apply to Kind
// must be empty.
type Request struct {
	Kind   Kind   `json:"kind"`
	ID     uint64 `json:"id"`
	Dest   string `json:"dest,omitempty"`
	Accept string `json:"accept,omitempty"`
	Name   string `json:"name,omitempty"`
	Route  string `json:"route,omitempty"`
}

// Reply is every header the broker sends.
type Reply struct {
	Kind        Kind   `json:"kind"`
	ID          uint64 `json:"id,omitempty"`
	Version     string `json:"version,omitempty"`
	Protocol    int    `json:"protocol,omitempty"`
	Status      int    `json:"status,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	Code        Code   `json:"code,omitempty"`
	Message     string `json:"message,omitempty"`
}

// Code tells the app what failed without it parsing a message.
type Code string

const (
	// CodeBadRequest: the app sent something the protocol doesn't allow.
	CodeBadRequest Code = "bad_request"
	// CodePolicy: the request is well formed but the policy refuses it.
	CodePolicy Code = "policy"
	// CodeCredential: the destination needs a credential the broker lacks.
	CodeCredential Code = "credential"
	// CodeAttestation: the enclave failed verification. Nothing was sent.
	CodeAttestation Code = "attestation"
	// CodeNetwork: the request could not be delivered or the response broke.
	CodeNetwork Code = "network"
	// CodeCancelled: the app cancelled the request.
	CodeCancelled Code = "cancelled"
)

var ErrMalformed = errors.New("malformed request")

// DecodeRequest parses a header strictly: unknown fields, trailing data, a
// missing ID and fields that don't belong to the kind are all rejected.
func DecodeRequest(header []byte) (Request, error) {
	dec := json.NewDecoder(bytes.NewReader(header))
	dec.DisallowUnknownFields()
	var r Request
	if err := dec.Decode(&r); err != nil {
		return Request{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if dec.More() {
		return Request{}, fmt.Errorf("%w: trailing data", ErrMalformed)
	}
	if r.ID == 0 {
		return Request{}, fmt.Errorf("%w: id is required", ErrMalformed)
	}
	extra := false
	switch r.Kind {
	case KindFetch:
		extra = r.Name != "" || r.Route != "" || r.Dest == ""
	case KindCancel:
		extra = r.Dest != "" || r.Accept != "" || r.Name != "" || r.Route != ""
	case KindCredential:
		extra = r.Dest != "" || r.Accept != "" || r.Route != "" || r.Name == ""
	case KindStatus:
		extra = r.Dest != "" || r.Accept != "" || r.Name != "" || r.Route == ""
	default:
		return Request{}, fmt.Errorf("%w: unknown kind %q", ErrMalformed, r.Kind)
	}
	if extra {
		return Request{}, fmt.Errorf("%w: fields don't match kind %q", ErrMalformed, r.Kind)
	}
	return r, nil
}
