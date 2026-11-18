// Package channel is the attested client channel between a Fount install and
// Fount Cloud's coordinator (m4-cloud-runners.md §2, §3.1): the way Desktop's
// broker reaches the workers, files and jobs a coordinator holds for an
// account, in place of the coordinator's bearer-token test API.
//
// It is the runner link's handshake (package link) with one end that no
// hardware vouches for. A connection crosses the coordinator's Tinfoil shim
// as an HTTP/1.1 upgrade to Protocol on Path, like the link. Inside it:
//
//  1. TLS 1.3. The coordinator's certificate carries its attested KeyID key,
//     its own and not the runner link's; the client sends none.
//  2. The coordinator sends an attestation document whose nonce is the
//     session's exporter (labelServer). The client checks it against the
//     coordinator's config repo, which it pins, and that the key it endorses
//     is the TLS one. Until then the client sends nothing, so a coordinator
//     that isn't a release of that repo never sees a credential. The client
//     sends no request on the channel at or after the verification's
//     freshness deadline, or within ExpiryMargin of the peer's Expires: it
//     closes the channel then, and the next request dials and verifies
//     afresh.
//  3. The client sends a hello: its device credential (fount-infra's, which
//     names the account), its device's public key, the device key's grant of a
//     session key (identity.go), and the session key's signature over the
//     session's other exporter (labelClient).
//  4. The coordinator checks the credential against fount-infra's public key,
//     pinned in its measured config, and that its claims include Cloud; that
//     the device key is the one the credential names; the grant; and the
//     binding. It answers with the account, which the client never states.
//
// The binding ties the hello to this TLS session, so it can't be replayed
// into another. The device credential alone, a bearer token the proxy also
// sees, opens nothing: the hello needs the device key's grant too.
//
// After that the connection carries HTTP/1.1, the coordinator's account API
// (coordinator.AccountHandler), for that account and device only. It closes
// when the credential, its paid period or the grant ends, whichever is first.
package channel

import (
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// Path is the coordinator's channel endpoint, listed in its shim paths.
const Path = "/fount-client"

// Protocol is the Upgrade token.
const Protocol = "fount-client/1"

// KeyID is the coordinator's attested key for the channel
// (tinfoil-config.yml's attested-keys). It is apart from the runner link's
// fount-link, so the key that does TLS with anyone on the internet isn't the
// one runners trust, and a client checks for this id, not just any key the
// enclave's document endorses.
const KeyID = "fount-client"

const (
	labelServer = "EXPORTER-fount-client server"
	labelClient = "EXPORTER-fount-client client"
	// bindingContext precedes the client exporter in what the session key
	// signs.
	bindingContext = "fount-client-binding-v1\n"
)

// HandshakeTimeout bounds TLS, the document and the hello. The attestation
// socket can take a while to answer after boot.
const HandshakeTimeout = time.Minute

// The coordinator gives an unauthenticated client StepTimeout for each of its
// steps, TLS and the hello, and DocumentTimeout to take the document, so a
// client that stalls holds a handshake slot for seconds; only the
// coordinator's own wait for the attestation socket has HandshakeTimeout.
const (
	StepTimeout     = 10 * time.Second
	DocumentTimeout = 30 * time.Second
)

var (
	// ErrCoordinator is a coordinator that didn't prove it runs a release of
	// the pinned repo. Nothing was sent to it.
	ErrCoordinator = errors.New("the coordinator didn't prove its release")
	// ErrRefused is a coordinator that refused this client's identity.
	ErrRefused = errors.New("the coordinator refused this client")
)

// Peer is who a channel's client proved to be.
type Peer struct {
	Account string
	Device  string
	// DeviceKey is the device's Ed25519 public key, whose id is Device. The
	// coordinator only has it.
	DeviceKey ed25519.PublicKey
	// Expires is when the credential or the session grant runs out; the
	// channel closes then.
	Expires time.Time
}

type hello struct {
	Kind       string `json:"kind"`
	Credential string `json:"credential"`
	DeviceKey  []byte `json:"device_key"`
	Session    string `json:"session"`
	Binding    []byte `json:"binding"`
}

type answer struct {
	Kind    string `json:"kind"` // welcome or refused
	Account string `json:"account,omitempty"`
	Device  string `json:"device,omitempty"`
	Expires int64  `json:"expires,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

func bindingMessage(exporter []byte) []byte {
	return append([]byte(bindingContext), exporter...)
}

// The handshake's messages are length-prefixed: a big-endian uint32, then the
// bytes. Each side bounds what it reads, so an unauthenticated client can't
// make the coordinator hold much.
const (
	maxHello    = 16 << 10
	maxAnswer   = 4 << 10
	maxDocument = 32 << 20
)

func writeMsg(w io.Writer, b []byte) error {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	_, err := w.Write(append(n[:], b...))
	return err
}

func readMsg(r io.Reader, max int) ([]byte, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size > uint32(max) {
		return nil, fmt.Errorf("a %d-byte message, over %d", size, max)
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

// verifyHello is the coordinator's check of a hello, given the session's
// client exporter.
func verifyHello(h hello, exporter []byte, keys []*rsa.PublicKey, cloudOnly bool, now time.Time) (Peer, error) {
	if h.Kind != "hello" {
		return Peer{}, fmt.Errorf("it sent %q, not a hello", h.Kind)
	}
	cred, err := VerifyAccountCredential(h.Credential, keys, now, cloudOnly)
	if err != nil {
		return Peer{}, fmt.Errorf("credential: %w", err)
	}
	if len(h.DeviceKey) != ed25519.PublicKeySize {
		return Peer{}, errors.New("the device key isn't Ed25519")
	}
	device := ed25519.PublicKey(h.DeviceKey)
	if DeviceID(device) != cred.Dev {
		return Peer{}, errors.New("the device key isn't the one the credential names")
	}
	grant, sessionKey, err := VerifySession(h.Session, device, now)
	if err != nil {
		return Peer{}, err
	}
	if !ed25519.Verify(sessionKey, bindingMessage(exporter), h.Binding) {
		return Peer{}, errors.New("the binding isn't the session key's, for this session")
	}
	return Peer{Account: cred.Acct, Device: cred.Dev, DeviceKey: device, Expires: time.Unix(min(cred.Exp, *cred.Pe, grant.Exp), 0)}, nil
}
