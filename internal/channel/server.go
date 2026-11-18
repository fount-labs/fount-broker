package channel

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/fount-labs/fount-broker/internal/link"
)

// Server is the coordinator's end.
type Server struct {
	// Key is the enclave's attested fount-link key, which its TLS
	// certificate carries and its attestation endorses.
	Key      ed25519.PrivateKey
	Attester link.Attester
	// AccountKeys verify device credentials: fount-infra's signing key,
	// pinned in the coordinator's measured config.
	AccountKeys []*rsa.PublicKey
	// Handler serves one client's requests, for the account it proved.
	Handler func(Peer) http.Handler
	// MaxHandshakes bounds handshakes in progress, each of which asks the
	// attestation socket for a document; more are dropped. 0 is 16.
	MaxHandshakes int
	Now           func() time.Time
}

// Start serves channels until ctx ends, and returns the handler for Path,
// which takes each upgrade.
func (s *Server) Start(ctx context.Context) (http.Handler, error) {
	if len(s.Key) != ed25519.PrivateKeySize || s.Attester == nil || len(s.AccountKeys) == 0 || s.Handler == nil {
		return nil, errors.New("the client channel needs its key, attester, account keys and handler")
	}
	cert, err := link.Certificate(s.Key)
	if err != nil {
		return nil, err
	}
	up := link.NewUpgradeListener(addr{}, Path, Protocol)
	ready := newConnQueue()
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Context().Value(handlerKey{}).(http.Handler).ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       15 * time.Minute,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, handlerKey{}, c.(*serverConn).handler)
		},
	}
	context.AfterFunc(ctx, func() {
		up.Close()
		ready.Close()
		srv.Close()
	})
	go srv.Serve(ready)
	max := s.MaxHandshakes
	if max <= 0 {
		max = 16
	}
	slots := make(chan struct{}, max)
	go func() {
		for {
			raw, err := up.Accept()
			if err != nil {
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				raw.Close()
				continue
			}
			go func() {
				defer func() { <-slots }()
				c, err := s.handshake(ctx, cert, raw)
				if err != nil {
					raw.Close()
					if !errors.Is(err, errQuiet) {
						log.Printf("client channel: %v", err)
					}
					return
				}
				if !ready.put(c) {
					c.Close()
				}
			}()
		}
	}()
	return up, nil
}

type handlerKey struct{}

// errQuiet marks failures not worth a log line: TLS from scanners, and
// clients that hung up.
var errQuiet = errors.New("quiet")

func (s *Server) handshake(ctx context.Context, cert tls.Certificate, raw net.Conn) (*serverConn, error) {
	ctx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	tc := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("%w: TLS: %v", errQuiet, err)
	}
	state := tc.ConnectionState()
	nonce, err := state.ExportKeyingMaterial(labelServer, nil, 32)
	if err != nil {
		return nil, err
	}
	binding, err := state.ExportKeyingMaterial(labelClient, nil, 32)
	if err != nil {
		return nil, err
	}
	doc, err := s.Attester.Attest(ctx, nonce)
	if err != nil {
		return nil, fmt.Errorf("attesting: %w", err)
	}
	if err := writeMsg(tc, doc); err != nil {
		return nil, fmt.Errorf("%w: %v", errQuiet, err)
	}
	raw2, err := readMsg(tc, maxHello)
	if err != nil {
		return nil, fmt.Errorf("%w: the hello: %v", errQuiet, err)
	}
	var h hello
	if err := json.Unmarshal(raw2, &h); err != nil {
		return nil, fmt.Errorf("the hello: %w", err)
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	peer, err := verifyHello(h, binding, s.AccountKeys, now())
	if err != nil {
		a, _ := json.Marshal(answer{Kind: "refused", Reason: err.Error()})
		writeMsg(tc, a)
		return nil, fmt.Errorf("refused: %w", err)
	}
	a, err := json.Marshal(answer{Kind: "welcome", Account: peer.Account, Device: peer.Device, Expires: peer.Expires.Unix()})
	if err != nil {
		return nil, err
	}
	if err := writeMsg(tc, a); err != nil {
		return nil, fmt.Errorf("%w: %v", errQuiet, err)
	}
	if !stop() || ctx.Err() != nil {
		return nil, fmt.Errorf("%w: %v", errQuiet, context.DeadlineExceeded)
	}
	c := &serverConn{Conn: tc, handler: s.Handler(peer)}
	c.expiry = time.AfterFunc(peer.Expires.Sub(now()), func() { tc.Close() })
	return c, nil
}

// serverConn is an authenticated channel: its client's handler, and a timer
// that closes it when the client's proof runs out.
type serverConn struct {
	net.Conn
	handler http.Handler
	expiry  *time.Timer
}

func (c *serverConn) Close() error {
	if c.expiry != nil {
		c.expiry.Stop()
	}
	return c.Conn.Close()
}

// connQueue is a net.Listener of connections already through the handshake.
type connQueue struct {
	conns chan net.Conn
	once  sync.Once
	done  chan struct{}
}

func newConnQueue() *connQueue {
	return &connQueue{conns: make(chan net.Conn), done: make(chan struct{})}
}

func (q *connQueue) put(c net.Conn) bool {
	select {
	case q.conns <- c:
		return true
	case <-q.done:
		return false
	}
}

func (q *connQueue) Accept() (net.Conn, error) {
	select {
	case c := <-q.conns:
		return c, nil
	case <-q.done:
		return nil, net.ErrClosed
	}
}

func (q *connQueue) Close() error {
	q.once.Do(func() { close(q.done) })
	return nil
}

func (q *connQueue) Addr() net.Addr { return addr{} }

type addr struct{}

func (addr) Network() string { return "fount-client" }
func (addr) String() string  { return "fount-client" }
