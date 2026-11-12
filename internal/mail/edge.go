package mail

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Edge is the transport to the edge's Device API.
type Edge interface {
	// Do sends req, which already carries any signature headers. Its URL is
	// relative to the edge's origin.
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
	// Base is the edge's origin, such as https://edge.example/.
	Base() string
	// AttestedSigningKey returns the message-signing key the edge's attestation
	// endorses for the boot now running, or nil if this transport doesn't attest.
	// An error means attestation failed and nothing may be trusted.
	AttestedSigningKey(ctx context.Context) (ed25519.PublicKey, error)
}

// ErrEdge is a Device API call that failed on the edge's side, or a response
// that doesn't have the shape the contract says.
var ErrEdge = errors.New("mail: edge")

// ErrNotFound is a 404 for a message or boot.
var ErrNotFound = errors.New("mail: not found")

const maxJSON = 4 << 20

type client struct {
	edge Edge
	now  func() time.Time
}

func (c *client) call(ctx context.Context, k *Keys, method, path, query string, limit int64) ([]byte, int, error) {
	url := c.edge.Base() + path[1:]
	if query != "" {
		url += "?" + query
	}
	req, err := http.NewRequestWithContext(ctx, method, url, http.NoBody)
	if err != nil {
		return nil, 0, err
	}
	if k != nil {
		signRequest(req.Header, k, method, path, nil, c.now())
	}
	resp, err := c.edge.Do(ctx, req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if int64(len(body)) > limit {
		return nil, resp.StatusCode, fmt.Errorf("%w: %s %s answered more than %d bytes", ErrEdge, method, path, limit)
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, resp.StatusCode, ErrNotFound
	case resp.StatusCode >= 300:
		return nil, resp.StatusCode, fmt.Errorf("%w: %s %s answered %d: %s", ErrEdge, method, path, resp.StatusCode, edgeMessage(body))
	}
	return body, resp.StatusCode, nil
}

// edgeMessage returns the edge's error text, bounded, for the app to show.
func edgeMessage(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		body = []byte(e.Error)
	}
	if len(body) > 200 {
		body = body[:200]
	}
	return strconv.Quote(string(body))
}

func strictJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrEdge, err)
	}
	if dec.More() {
		return fmt.Errorf("%w: trailing data", ErrEdge)
	}
	return nil
}

// Listed is one waiting message in GET /mail.
type Listed struct {
	ID   string `json:"id"`
	Size int64  `json:"size"`
}

// maxListed bounds a GET /mail listing. 2 GB of 4 KB messages is about half a
// million; a listing that long is broken.
const maxListed = 1 << 19

// Listing is GET /mail's answer.
type Listing struct {
	Messages []Listed `json:"messages"`
	// Whether the worker is paused (edge v0.2.1). Mail still arrives and is fetched while
	// it is. Nil when the edge didn't say, which the app treats as paused.
	Paused *bool `json:"paused,omitempty"`
}

func (c *client) list(ctx context.Context, k *Keys) (Listing, error) {
	body, _, err := c.call(ctx, k, "GET", "/mail", "", 64<<20)
	if err != nil {
		return Listing{}, err
	}
	var out Listing
	if err := strictJSON(body, &out); err != nil {
		return Listing{}, err
	}
	if len(out.Messages) > maxListed {
		return Listing{}, fmt.Errorf("%w: %d messages listed", ErrEdge, len(out.Messages))
	}
	for _, m := range out.Messages {
		if !validHex(m.ID, 16) {
			return Listing{}, fmt.Errorf("%w: listed id %q isn't an edge id", ErrEdge, m.ID)
		}
	}
	if out.Messages == nil {
		out.Messages = []Listed{}
	}
	return out, nil
}

func (c *client) get(ctx context.Context, k *Keys, id string) ([]byte, error) {
	body, _, err := c.call(ctx, k, "GET", "/mail/"+id, "", MaxObject)
	return body, err
}

func (c *client) delete(ctx context.Context, k *Keys, id string) error {
	_, _, err := c.call(ctx, k, "DELETE", "/mail/"+id, "", maxJSON)
	return err
}

// maxGapsPage is the edge's store.MaxGaps: a full page means there may be more.
const maxGapsPage = 256

func (c *client) gaps(ctx context.Context, k *Keys, after uint64) ([]string, error) {
	body, _, err := c.call(ctx, k, "GET", "/gaps", "after="+strconv.FormatUint(after, 10), maxJSON)
	if err != nil {
		return nil, err
	}
	var out struct {
		Records []string `json:"records"`
	}
	if err := strictJSON(body, &out); err != nil {
		return nil, err
	}
	if len(out.Records) > maxGapsPage {
		return nil, fmt.Errorf("%w: %d gap records in one page", ErrEdge, len(out.Records))
	}
	return out.Records, nil
}

// boot is the edge's GET /boots/{id} body (edge internal/store.Boot).
type boot struct {
	BootID     string `json:"boot_id"`
	SigningKey []byte `json:"signing_key"`
	StartedAt  int64  `json:"started_at"`
}

func (c *client) boot(ctx context.Context, id string) (boot, error) {
	body, _, err := c.call(ctx, nil, "GET", "/boots/"+id, "", maxJSON)
	if err != nil {
		return boot{}, err
	}
	var b boot
	if err := strictJSON(body, &b); err != nil {
		return boot{}, err
	}
	if b.BootID != id || len(b.SigningKey) != ed25519.PublicKeySize {
		return boot{}, fmt.Errorf("%w: boot record for %s is for %q or has no usable key", ErrEdge, id, b.BootID)
	}
	return b, nil
}

// BootKey is a boot's message-signing key and how the broker came to trust it.
type BootKey struct {
	Key ed25519.PublicKey
	// Attested is true when the edge's own attestation endorsed this key while
	// the broker was talking to that boot. Otherwise the key came only from
	// edge/boots in S3, which the storage host could plant (design §9).
	Attested bool
}

// boots caches boot keys. A key is never replaced once seen: a boot id that
// later names a different key is an anomaly, not an update.
type boots struct {
	mu   sync.Mutex
	keys map[string]BootKey
}

var ErrBootConflict = errors.New("mail: boot record changed its key")

func (c *client) bootKey(ctx context.Context, cache *boots, id string) (BootKey, error) {
	if !validHex(id, 16) {
		return BootKey{}, fmt.Errorf("%w: boot id %q", ErrMalformed, id)
	}
	// Every fetch re-checks attestation; the transport refuses on failure, and
	// so does this.
	attested, err := c.edge.AttestedSigningKey(ctx)
	if err != nil {
		return BootKey{}, err
	}
	cache.mu.Lock()
	k, ok := cache.keys[id]
	cache.mu.Unlock()
	if !ok {
		b, err := c.boot(ctx, id)
		if err != nil {
			return BootKey{}, err
		}
		k = BootKey{Key: ed25519.PublicKey(b.SigningKey)}
	}
	k.Attested = k.Attested || attested != nil && attested.Equal(k.Key)
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if prev, ok := cache.keys[id]; ok && !prev.Key.Equal(k.Key) {
		return BootKey{}, fmt.Errorf("%w: boot %s", ErrBootConflict, id)
	}
	cache.keys[id] = k
	return k, nil
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }
