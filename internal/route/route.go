// Package route holds the transports destinations travel over.
package route

import (
	"context"
	"errors"
	"net/http"

	"github.com/fount-labs/fount-broker/internal/policy"
)

// Request is one outbound call, already checked against the policy.
type Request struct {
	Dest       policy.Destination
	Accept     string
	Body       []byte
	Credential string
}

// Route sends requests for the destinations that name it.
type Route interface {
	Do(ctx context.Context, r Request) (*http.Response, error)
	// Status reports what the route has verified, as JSON-encodable data.
	Status(ctx context.Context) (any, error)
}

// ErrAttestation marks a failure to verify the remote end. Nothing was sent.
var ErrAttestation = errors.New("attestation failed")
