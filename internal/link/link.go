// Package link is the attested channel between Fount Cloud's coordinator and a
// runner enclave's broker (m4-cloud-runners.md §5.1c). Jobs, their files and
// their credentials cross it, so each end proves to the other which release it
// runs before anything else is sent.
//
// Each enclave has a per-boot Ed25519 key, KeyID, generated inside it and
// endorsed by its Tinfoil attestation. A connection is mutual TLS 1.3 with
// self-signed certificates over those keys. Each side then asks its own
// enclave for an attestation document whose nonce is the TLS session's
// exporter, for its role, and sends it. The other side checks the document
// against the release it pins and that the key it endorses is the one the TLS
// peer proved it holds. The exporter ties the document to this session, so it
// can't be replayed or relayed into another.
//
// Once both have, each end pings the other while the link is up (keepalive.go).
//
// Which end dials is separate from which end sends jobs. A runner may open the
// connection (runners dial in, launch plan work R): it runs Client, and the
// coordinator runs Server on what it accepted, then sends jobs as before.
package link

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/fount-labs/fount-broker/internal/frame"
)

// KeyID is the attested key's id on both enclaves (tinfoil-config.yml's
// attested-keys).
const KeyID = "fount-link"

// HandshakeTimeout bounds TLS and both documents. The attestation socket can
// take a while to answer after boot.
const HandshakeTimeout = time.Minute

// An Attester produces this enclave's attestation document for a nonce.
type Attester interface {
	Attest(ctx context.Context, nonce []byte) ([]byte, error)
}

// A Checker verifies the peer's document for nonce against the release this
// side pins, and returns the link key it endorses.
type Checker func(doc, nonce []byte) (ed25519.PublicKey, error)

// An Endorsement is what a verified document vouches for: the peer's key,
// and Fresh, the verification's freshness deadline, at and after which it
// may authorize nothing new (tinfoil-go's FreshnessExpiresAt). Zero is no
// deadline, an unattested document's.
type Endorsement struct {
	Key   ed25519.PublicKey
	Fresh time.Time
}

// A KeyChecker is a Checker that also says how long its verification stays
// fresh.
type KeyChecker func(doc, nonce []byte) (Endorsement, error)

// Side is one end's key, how it attests, and how it checks the other end.
type Side struct {
	Key      ed25519.PrivateKey
	Attester Attester
	Check    Checker
	// Endorse, if set, replaces Check: it also says how long the
	// verification stays fresh, for an end that holds a link before using it.
	// Without it the link has no freshness deadline, as an unattested one.
	Endorse KeyChecker
}

var ErrPeer = errors.New("the link's peer didn't prove its release")

// Client runs the handshake on a connection this end dialled.
func (s *Side) Client(ctx context.Context, conn net.Conn) (net.Conn, error) {
	c, _, err := s.handshake(ctx, conn, true)
	return c, err
}

// Server runs the handshake on a connection this end accepted.
func (s *Side) Server(ctx context.Context, conn net.Conn) (net.Conn, error) {
	c, _, err := s.handshake(ctx, conn, false)
	return c, err
}

// ServerEndorsed is Server, and says what the peer's document vouched for:
// its key, and with Endorse set, until when.
func (s *Side) ServerEndorsed(ctx context.Context, conn net.Conn) (net.Conn, Endorsement, error) {
	return s.handshake(ctx, conn, false)
}

const (
	labelClient = "EXPORTER-fount-link client"
	labelServer = "EXPORTER-fount-link server"
)

func (s *Side) handshake(ctx context.Context, conn net.Conn, client bool) (net.Conn, Endorsement, error) {
	ctx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer cancel()
	cert, err := Certificate(s.Key)
	if err != nil {
		return nil, Endorsement{}, err
	}
	var peer ed25519.PublicKey
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		// The certificate is only a carrier for the key; the attestation below
		// is what vouches for it.
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) != 1 {
				return fmt.Errorf("%w: %d certificates", ErrPeer, len(raw))
			}
			c, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			k, ok := c.PublicKey.(ed25519.PublicKey)
			if !ok {
				return fmt.Errorf("%w: its key isn't Ed25519", ErrPeer)
			}
			peer = k
			return nil
		},
	}
	var tc *tls.Conn
	if client {
		tc = tls.Client(conn, cfg)
	} else {
		tc = tls.Server(conn, cfg)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, Endorsement{}, fmt.Errorf("link TLS: %w", err)
	}
	mine, theirs := labelServer, labelClient
	if client {
		mine, theirs = theirs, mine
	}
	state := tc.ConnectionState()
	myNonce, err := state.ExportKeyingMaterial(mine, nil, 32)
	if err != nil {
		return nil, Endorsement{}, err
	}
	peerNonce, err := state.ExportKeyingMaterial(theirs, nil, 32)
	if err != nil {
		return nil, Endorsement{}, err
	}
	doc, err := s.Attester.Attest(ctx, myNonce)
	if err != nil {
		return nil, Endorsement{}, fmt.Errorf("attesting this end: %w", err)
	}
	// Both ends write before they read, so the write can't wait on the read.
	sent := make(chan error, 1)
	go func() { sent <- frame.NewWriter(tc).Write(frame.Frame{Header: attestationHeader, Body: doc}) }()
	f, err := frame.Read(tc)
	if err != nil {
		return nil, Endorsement{}, fmt.Errorf("the peer's attestation: %w", err)
	}
	if err := <-sent; err != nil {
		return nil, Endorsement{}, fmt.Errorf("sending the attestation: %w", err)
	}
	var h struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal(f.Header, &h) != nil || h.Kind != "attestation" {
		return nil, Endorsement{}, fmt.Errorf("%w: it sent %q first", ErrPeer, f.Header)
	}
	var endorsed Endorsement
	if s.Endorse != nil {
		endorsed, err = s.Endorse(f.Body, peerNonce)
	} else {
		endorsed.Key, err = s.Check(f.Body, peerNonce)
	}
	if err != nil {
		return nil, Endorsement{}, fmt.Errorf("%w: %v", ErrPeer, err)
	}
	if !endorsed.Key.Equal(peer) {
		return nil, Endorsement{}, fmt.Errorf("%w: its attestation endorses another key than its TLS one", ErrPeer)
	}
	if ctx.Err() != nil {
		return nil, Endorsement{}, ctx.Err()
	}
	return keepalive(tc, PingInterval, IdleTimeout), endorsed, nil
}

var attestationHeader = []byte(`{"kind":"attestation"}`)

// Certificate is a self-signed certificate over an attested key: only a
// carrier for the key, which the attestation vouches for.
func Certificate(key ed25519.PrivateKey) (tls.Certificate, error) {
	if len(key) != ed25519.PrivateKeySize {
		return tls.Certificate{}, errors.New("the link needs its Ed25519 key")
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: KeyID},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
