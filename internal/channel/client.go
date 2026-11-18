package channel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/fount-labs/fount-broker/internal/link"
)

// ErrIdentity is a client without the credentials it needs. Nothing was
// dialled.
var ErrIdentity = errors.New("no identity for the coordinator")

// Client is the broker's end.
type Client struct {
	// Origin is the coordinator's, https://<domain>.
	Origin string
	// Check verifies the coordinator's document against the config repo it
	// must be a release of (link.TinfoilKeyChecker for KeyID), and returns the
	// key it endorses and until when.
	Check link.KeyChecker
	// Identity is read for each new connection, so a renewed credential
	// takes effect on the next one.
	Identity func() (Identity, error)

	// expiryMargin stands in for ExpiryMargin in tests.
	expiryMargin time.Duration

	// mu guards transport, the pool of channels for the current identity,
	// which Reset replaces.
	mu        sync.Mutex
	transport *http.Transport
	http      *http.Client
}

// ExpiryMargin is how long before its proof expires a client stops using a
// channel, so a request isn't cut off when the coordinator closes it then.
const ExpiryMargin = time.Minute

// Dial opens a channel and returns it, ready for HTTP, with the peer the
// coordinator says the client is. The channel closes, and refuses to send,
// at the coordinator's verification's freshness deadline or ExpiryMargin
// before the peer's Expires, whichever is first.
func (c *Client) Dial(ctx context.Context) (net.Conn, Peer, error) {
	id, err := c.Identity()
	if err != nil {
		return nil, Peer{}, fmt.Errorf("%w: %v", ErrIdentity, err)
	}
	ctx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer cancel()
	raw, err := link.DialUpgrade(ctx, c.Origin, Path, Protocol)
	if err != nil {
		return nil, Peer{}, err
	}
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	conn, peer, err := c.handshake(ctx, raw, id)
	if err != nil {
		raw.Close()
		return nil, Peer{}, err
	}
	if !stop() {
		raw.Close()
		return nil, Peer{}, ctx.Err()
	}
	return conn, peer, nil
}

func (c *Client) handshake(ctx context.Context, raw net.Conn, id Identity) (net.Conn, Peer, error) {
	var server ed25519.PublicKey
	now := time.Now()
	tc := tls.Client(raw, &tls.Config{
		MinVersion: tls.VersionTLS13,
		// The certificate is only a carrier for the key; the attestation
		// below is what vouches for it.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(certs [][]byte, _ [][]*x509.Certificate) error {
			if len(certs) != 1 {
				return fmt.Errorf("%w: %d certificates", ErrCoordinator, len(certs))
			}
			cert, err := x509.ParseCertificate(certs[0])
			if err != nil {
				return err
			}
			k, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok {
				return fmt.Errorf("%w: its key isn't Ed25519", ErrCoordinator)
			}
			server = k
			return nil
		},
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, Peer{}, fmt.Errorf("channel TLS: %w", err)
	}
	state := tc.ConnectionState()
	nonce, err := state.ExportKeyingMaterial(labelServer, nil, 32)
	if err != nil {
		return nil, Peer{}, err
	}
	binding, err := state.ExportKeyingMaterial(labelClient, nil, 32)
	if err != nil {
		return nil, Peer{}, err
	}
	doc, err := readMsg(tc, maxDocument)
	if err != nil {
		return nil, Peer{}, fmt.Errorf("the coordinator's attestation: %w", err)
	}
	endorsed, err := c.Check(doc, nonce)
	if err != nil {
		return nil, Peer{}, fmt.Errorf("%w: %v", ErrCoordinator, err)
	}
	if !endorsed.Fresh.IsZero() && !now.Before(endorsed.Fresh) {
		return nil, Peer{}, fmt.Errorf("%w: its attestation is no longer fresh", ErrCoordinator)
	}
	if !endorsed.Key.Equal(server) {
		return nil, Peer{}, fmt.Errorf("%w: its attestation endorses another key than its TLS one", ErrCoordinator)
	}
	h, err := json.Marshal(hello{
		Kind:       "hello",
		Credential: id.Credential,
		DeviceKey:  id.DeviceKey,
		Session:    id.Session,
		Binding:    ed25519.Sign(id.SessionKey, bindingMessage(binding)),
	})
	if err != nil {
		return nil, Peer{}, err
	}
	if err := writeMsg(tc, h); err != nil {
		return nil, Peer{}, err
	}
	raw2, err := readMsg(tc, maxAnswer)
	if err != nil {
		return nil, Peer{}, fmt.Errorf("the coordinator's answer: %w", err)
	}
	var a answer
	if err := json.Unmarshal(raw2, &a); err != nil {
		return nil, Peer{}, fmt.Errorf("the coordinator's answer: %w", err)
	}
	switch {
	case a.Kind == "refused":
		return nil, Peer{}, fmt.Errorf("%w: %.200s", ErrRefused, a.Reason)
	case a.Kind != "welcome" || a.Account == "":
		return nil, Peer{}, fmt.Errorf("the coordinator answered %q", a.Kind)
	}
	peer := Peer{Account: a.Account, Device: a.Device, Expires: time.Unix(a.Expires, 0)}
	return freshUntil(tc, c.usableUntil(endorsed.Fresh, peer.Expires, now)), peer, nil
}

// usableUntil is when a channel stops taking requests: the freshness
// deadline, or the margin before the coordinator closes it at expires; a
// channel shorter than the margin is used until expires.
func (c *Client) usableUntil(fresh, expires, now time.Time) time.Time {
	end := expires.Add(-or(c.expiryMargin, ExpiryMargin))
	if !end.After(now) {
		end = expires
	}
	if !fresh.IsZero() && fresh.Before(end) {
		return fresh
	}
	return end
}

// errStale is a write on a channel past its coordinator's freshness
// deadline or near its proof's expiry. Nothing is written, so the HTTP
// transport sends the request again on a new channel, which verifies the
// coordinator afresh with the identity then current.
var errStale = errors.New("the channel is past its coordinator's freshness deadline or its proof's expiry")

// freshConn is a channel that closes at fresh, usableUntil's. Writes check it
// too, since a pooled channel can be picked for a request just before its
// timer fires.
type freshConn struct {
	net.Conn
	fresh time.Time
	timer *time.Timer
}

func freshUntil(conn net.Conn, fresh time.Time) net.Conn {
	return &freshConn{Conn: conn, fresh: fresh, timer: time.AfterFunc(time.Until(fresh), func() { conn.Close() })}
}

func (c *freshConn) Write(p []byte) (int, error) {
	if !time.Now().Before(c.fresh) {
		c.Conn.Close()
		return 0, errStale
	}
	return c.Conn.Write(p)
}

func (c *freshConn) Close() error {
	c.timer.Stop()
	return c.Conn.Close()
}

// host stands for the coordinator in the URLs of requests on the channel,
// which reach it whatever they name.
const host = "coordinator"

// HTTP is a client whose connections are channels. Idle ones are kept, so a
// run of requests pays for one handshake.
func (c *Client) HTTP() *http.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.http == nil {
		c.http = &http.Client{
			Transport:     currentTransport{c},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return c.http
}

// currentTransport sends each request on the pool Reset last left, so a
// channel dialled before a Reset never carries a request after it.
type currentTransport struct{ c *Client }

func (t currentTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return t.c.current().RoundTrip(r)
}

func (c *Client) current() *http.Transport {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.transport == nil {
		c.transport = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				conn, _, err := c.Dial(ctx)
				return conn, err
			},
			ForceAttemptHTTP2:   false,
			MaxConnsPerHost:     4,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     10 * time.Minute,
			DisableCompression:  true,
		}
	}
	return c.transport
}

// Do sends one request of the account API: method and target as Check
// accepts them.
func (c *Client) Do(ctx context.Context, method, target string, body []byte) (*http.Response, error) {
	u, err := CheckRequest(method, target)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	return c.HTTP().Do(req)
}

// Reset starts a new pool of channels, for example after the credentials
// change: the next request dials with the identity then current. The old
// pool's idle channels close; one carrying a request finishes it and is
// never used again, closing when it idles out or its proof expires.
func (c *Client) Reset() {
	c.mu.Lock()
	old := c.transport
	c.transport = nil
	c.mu.Unlock()
	if old != nil {
		old.CloseIdleConnections()
	}
}
