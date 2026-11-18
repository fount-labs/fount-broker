package coordinator

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

// A worker's grant is how Desktop moves it in (m4-cloud-runners.md §3.1 step
// 4) and who may act for it after. Over the client channel:
//
//  1. POST /v1/workers makes an empty worker with no DEK, which only the
//     channel's device may see: its creator.
//  2. POST /v1/workers/{id}/grant sends the worker's DEK with a grant signed
//     by the device key itself, not the broker's session key. The grant names
//     the worker, the DEK (by DEKCommitment), a sequence number one past the
//     worker's last, and the device keys that may act for the worker from now
//     on: the granting device and the admin devices it names. The signer must
//     be one of the worker's devices already. The coordinator wraps the DEK
//     and keeps the list, with an opaque copy of the DEK wrapped to each
//     device if Desktop sends one.
//  3. Another grant, with the same DEK and the next number, changes the list:
//     that is how devices are added and removed. A grant can't change the
//     DEK: every object of the worker's tree is sealed under it, so rotating
//     it means re-sealing the tree, which is an operation of its own (not
//     built). A re-sent first grant fails on its number, so nothing replays.
//  4. POST /v1/workers/{id}/revoke, signed the same way, moves the worker back
//     to Desktop: the coordinator forgets the worker, its DEK and its jobs, and
//     deletes its objects. Desktop reads what it keeps first.
//
// Every /v1 operation on a worker needs the channel's device to be on its
// list. A grant or revoke needs the device key's own signature. Reads, writes,
// listing and jobs are authorized by the channel's device alone (Caller.Device),
// which the broker proves with the session key the device key granted it, for
// up to channel.MaxSession: a broker's session key that leaks opens its
// device's workers until the session grant expires, but can't change who may
// act for them. The device list is what keeps fount-infra, which vouches for
// the device and its account each time it connects, from minting a new device
// that opens an account's workers.
const (
	GrantVersion = 1
	GrantType    = "fount-worker-grant"
	GrantContext = "fount-worker-grant-v1\n"

	OpGrant  = "grant"
	OpRevoke = "revoke"

	// MaxDevices bounds a worker's device list.
	MaxDevices = 16
	// A worker made over the channel and not yet granted holds a place in the
	// state for nothing: a device has at most MaxUngrantedPerDevice, an
	// account MaxUngrantedPerAccount, and each goes after UngrantedTTL.
	MaxUngrantedPerDevice  = 4
	MaxUngrantedPerAccount = 16
	UngrantedTTL           = 30 * time.Minute
	// MaxGrantAge is how long a signed grant stays good: Desktop signs it just
	// before it sends it.
	MaxGrantAge = time.Hour
	grantSkew   = 5 * time.Minute
	maxWrap     = 1 << 10

	dekCommitmentContext = "fount-worker-dek-v1\x00"
)

// GrantClaims are a grant's, signed Ed25519 by the device key over
// GrantContext followed by the claims bytes, and sent as base64url(claims)
// "." base64url(signature), like the channel's session grant.
type GrantClaims struct {
	V   int    `json:"v"`
	Typ string `json:"typ"`
	// Op is OpGrant or OpRevoke.
	Op     string `json:"op"`
	Acct   string `json:"acct"`
	Worker string `json:"worker"`
	// Dev is the signing device's id.
	Dev string `json:"dev"`
	Seq uint64 `json:"seq"`
	// DEK is DEKCommitment of the DEK sent with a grant.
	DEK string `json:"dek,omitempty"`
	// Devices are the Ed25519 public keys, raw, base64url, that may act for
	// the worker after a grant.
	Devices []string `json:"devices,omitempty"`
	Iat     int64    `json:"iat"`
}

// Caller is who a client channel proved to be: the account fount-infra
// vouched for, and the device whose key granted the channel's session.
type Caller struct {
	Account   string
	Device    string
	DeviceKey ed25519.PublicKey
}

// Device is one device that may act for a worker.
type Device struct {
	ID  string `json:"id"`
	Key []byte `json:"key"`
	// Wrap is the worker's DEK wrapped to this device by Desktop, which the
	// coordinator keeps for it and never opens: how an admin device gets the
	// key back without Desktop at hand.
	Wrap []byte `json:"wrap,omitempty"`
}

var (
	// ErrNotGranted is a worker made over the channel whose DEK hasn't come
	// yet: it has no files and runs no jobs.
	ErrNotGranted = errors.New("the worker has no DEK grant yet")
	// ErrGrantRefused is a grant whose signature or claims don't check out.
	ErrGrantRefused = errors.New("grant refused")
	// ErrGrantSeq is a grant that isn't the one after the worker's last: a
	// replay, or a race with another device.
	ErrGrantSeq = errors.New("the grant isn't the next one")
	// ErrDEKChanged is a grant with another DEK than the worker's.
	ErrDEKChanged = errors.New("a grant can't change the worker's DEK")
	// ErrBusy is a worker with a running job.
	ErrBusy = errors.New("the worker has a running job")
	// ErrTooManyUngranted is a device or account with as many ungranted
	// workers as it may have.
	ErrTooManyUngranted = errors.New("too many workers waiting for their DEK grant")
)

var b64 = base64.RawURLEncoding.Strict()

// deviceID is fount-infra's and the channel's id for a device key.
func deviceID(key ed25519.PublicKey) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:16])
}

// DEKCommitment is what a grant signs for its DEK: HMAC-SHA256 under the DEK
// of the worker's id. It binds the signature to the key without showing it.
func DEKCommitment(workerID string, dek DEK) string {
	m := hmac.New(sha256.New, dek[:])
	m.Write([]byte(dekCommitmentContext + workerID))
	return b64.EncodeToString(m.Sum(nil))
}

// SignGrant is Desktop's half: the device key signs claims, filling in their
// version, type and signer. Desktop does the same in Rust; this is the
// reference, and the tests'.
func SignGrant(device ed25519.PrivateKey, c GrantClaims) (string, error) {
	c.V, c.Typ, c.Dev = GrantVersion, GrantType, deviceID(device.Public().(ed25519.PublicKey))
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(device, append([]byte(GrantContext), payload...))
	return b64.EncodeToString(payload) + "." + b64.EncodeToString(sig), nil
}

// verifyGrant checks what a grant says on its own: that the caller's device
// key signed it, for this account, worker and op, lately. Whether the caller
// may act for the worker and the number is next are checked against the
// worker. It returns the devices a grant names.
func verifyGrant(token string, caller Caller, workerID, op string, now time.Time) (GrantClaims, []Device, error) {
	c, devices, err := parseGrant(token, caller, workerID, op, now)
	if err != nil {
		return GrantClaims{}, nil, fmt.Errorf("%w: %v", ErrGrantRefused, err)
	}
	return c, devices, nil
}

func parseGrant(token string, caller Caller, workerID, op string, now time.Time) (GrantClaims, []Device, error) {
	p, s, ok := strings.Cut(token, ".")
	if !ok || strings.Contains(s, ".") {
		return GrantClaims{}, nil, errors.New("malformed")
	}
	payload, err := b64.DecodeString(p)
	if err != nil || len(payload) == 0 {
		return GrantClaims{}, nil, errors.New("malformed")
	}
	sig, err := b64.DecodeString(s)
	if err != nil {
		return GrantClaims{}, nil, errors.New("malformed")
	}
	if len(caller.DeviceKey) != ed25519.PublicKeySize || !ed25519.Verify(caller.DeviceKey, append([]byte(GrantContext), payload...), sig) {
		return GrantClaims{}, nil, errors.New("the channel's device key didn't sign it")
	}
	var c GrantClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return GrantClaims{}, nil, errors.New("malformed")
	}
	switch {
	case c.V != GrantVersion || c.Typ != GrantType:
		return GrantClaims{}, nil, errors.New("malformed")
	case c.Op != op:
		return GrantClaims{}, nil, fmt.Errorf("it is a %q, not a %q", c.Op, op)
	case c.Dev != deviceID(caller.DeviceKey) || c.Dev != caller.Device:
		return GrantClaims{}, nil, errors.New("it names another device than its signer")
	case c.Acct != caller.Account:
		return GrantClaims{}, nil, errors.New("it is for another account")
	case c.Worker != workerID:
		return GrantClaims{}, nil, errors.New("it is for another worker")
	case c.Iat > now.Add(grantSkew).Unix():
		return GrantClaims{}, nil, errors.New("it is from the future")
	case c.Iat <= now.Add(-MaxGrantAge).Unix():
		return GrantClaims{}, nil, fmt.Errorf("it is over %s old", MaxGrantAge)
	}
	if op == OpRevoke {
		if c.DEK != "" || len(c.Devices) != 0 {
			return GrantClaims{}, nil, errors.New("a revoke names no DEK or devices")
		}
		return c, nil, nil
	}
	if len(c.Devices) == 0 || len(c.Devices) > MaxDevices {
		return GrantClaims{}, nil, fmt.Errorf("it must name 1 to %d devices", MaxDevices)
	}
	devices := make([]Device, 0, len(c.Devices))
	seen := map[string]bool{}
	for _, k := range c.Devices {
		key, err := b64.DecodeString(k)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return GrantClaims{}, nil, errors.New("a device key isn't 32 bytes of base64url")
		}
		id := deviceID(key)
		if seen[id] {
			return GrantClaims{}, nil, errors.New("it names a device twice")
		}
		seen[id] = true
		devices = append(devices, Device{ID: id, Key: key})
	}
	return c, devices, nil
}

// checkDEK is a grant's DEK against what it signed.
func checkDEK(c GrantClaims, workerID string, dek DEK) error {
	if subtle.ConstantTimeCompare([]byte(c.DEK), []byte(DEKCommitment(workerID, dek))) != 1 {
		return fmt.Errorf("%w: it signs another DEK than the one sent", ErrGrantRefused)
	}
	return nil
}

// withWraps gives each device the wrap Desktop sent for it. A grant's wraps
// replace the last grant's: Desktop sends every one it wants kept.
func withWraps(devices []Device, wraps map[string][]byte) error {
	for id, wrap := range wraps {
		i := -1
		for j := range devices {
			if devices[j].ID == id {
				i = j
			}
		}
		switch {
		case i < 0:
			return fmt.Errorf("%w: a wrap for device %.40q, which it doesn't name", ErrGrantRefused, id)
		case len(wrap) == 0 || len(wrap) > maxWrap:
			return fmt.Errorf("%w: a wrap is 1 to %d bytes", ErrGrantRefused, maxWrap)
		}
		devices[i].Wrap = wrap
	}
	return nil
}

// mayAct is authorizes, with anyDevice for the dev API and the coordinator's
// own jobs.
func (w *Worker) mayAct(device string) bool {
	return device == anyDevice || w.authorizes(device)
}

// authorizes says whether device may act for w over the client channel.
// A worker made by the dev API has no devices, so no channel opens it.
func (w *Worker) authorizes(device string) bool {
	for _, d := range w.Devices {
		if d.ID == device {
			return true
		}
	}
	return false
}

// CreateWorkerFor makes an empty worker for the caller's account, which only
// the caller's device may act for until it grants the worker's DEK. It goes
// after UngrantedTTL without a grant.
func (c *Coordinator) CreateWorkerFor(caller Caller) (Worker, error) {
	if len(caller.DeviceKey) != ed25519.PublicKeySize || deviceID(caller.DeviceKey) != caller.Device {
		return Worker{}, errors.New("the caller's device key isn't its device's")
	}
	if err := checkID("account", caller.Account); err != nil {
		return Worker{}, err
	}
	id, err := newID("w")
	if err != nil {
		return Worker{}, err
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireUngranted(now)
	device, account := 0, 0
	for _, w := range c.state.Workers {
		if w.WrappedDEK != nil || w.Account != caller.Account {
			continue
		}
		account++
		if w.authorizes(caller.Device) {
			device++
		}
	}
	if device >= MaxUngrantedPerDevice || account >= MaxUngrantedPerAccount {
		return Worker{}, ErrTooManyUngranted
	}
	w := &Worker{ID: id, Account: caller.Account, Devices: []Device{{ID: caller.Device, Key: caller.DeviceKey}}, Created: now.UTC()}
	c.state.Workers[id] = w
	if err := c.state.Save(c.cfg.StateDir); err != nil {
		delete(c.state.Workers, id)
		return Worker{}, err
	}
	return *w, nil
}

// ungrantedExpired says whether w is a worker made over the channel whose
// grant didn't come in time.
func (w *Worker) ungrantedExpired(now time.Time) bool {
	return w.WrappedDEK == nil && len(w.Devices) > 0 && !now.Before(w.Created.Add(UngrantedTTL))
}

// expireUngranted forgets every ungranted worker past UngrantedTTL. They
// have no objects and no jobs. The state is saved with the caller's change,
// or by ExpireUngranted. Called with c.mu held; it reports whether any went.
func (c *Coordinator) expireUngranted(now time.Time) bool {
	gone := false
	for id, w := range c.state.Workers {
		if w.ungrantedExpired(now) {
			delete(c.state.Workers, id)
			delete(c.locks, id)
			gone = true
		}
	}
	return gone
}

// ExpireUngranted forgets ungranted workers past UngrantedTTL; Run calls it.
func (c *Coordinator) ExpireUngranted() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.expireUngranted(time.Now()) {
		if err := c.state.Save(c.cfg.StateDir); err != nil {
			log.Printf("save state: %v", err)
		}
	}
}

// Grant takes a worker's DEK and device list from one of its devices, as
// above. It returns the worker as it now stands.
func (c *Coordinator) Grant(caller Caller, workerID string, dek DEK, token string, wraps map[string][]byte) (Worker, error) {
	defer clear(dek[:])
	now := time.Now()
	claims, devices, err := verifyGrant(token, caller, workerID, OpGrant, now)
	if err != nil {
		return Worker{}, err
	}
	if err := checkDEK(claims, workerID, dek); err != nil {
		return Worker{}, err
	}
	if err := withWraps(devices, wraps); err != nil {
		return Worker{}, err
	}
	lock, _, err := c.workerLock(workerID)
	if err != nil {
		return Worker{}, err
	}
	// The tree's lock first, as view and change take it, so a read or write
	// in progress finishes under the list it was allowed by, and one after
	// sees the new list.
	lock.Lock()
	defer lock.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if w, ok := c.state.Workers[workerID]; ok && w.ungrantedExpired(now) {
		return Worker{}, ErrNoWorker
	}
	w, err := c.grantee(caller, workerID, claims.Seq)
	if err != nil {
		return Worker{}, err
	}
	next := *w
	if w.WrappedDEK == nil {
		if next.WrappedDEK, err = c.cfg.Key.Wrap(workerID, dek); err != nil {
			return Worker{}, err
		}
	} else {
		held, err := c.cfg.Key.Unwrap(workerID, w.WrappedDEK)
		same := subtle.ConstantTimeCompare(held[:], dek[:]) == 1
		clear(held[:])
		if err != nil {
			return Worker{}, err
		}
		if !same {
			return Worker{}, ErrDEKChanged
		}
	}
	next.Devices, next.GrantSeq = devices, claims.Seq
	c.state.Workers[workerID] = &next
	if err := c.state.Save(c.cfg.StateDir); err != nil {
		c.state.Workers[workerID] = w
		return Worker{}, err
	}
	return next, nil
}

// Revoke moves a worker back to Desktop, on a revoke from one of its
// devices: the coordinator forgets it, its DEK and its jobs, then deletes its
// objects. A worker with a running job is ErrBusy; queued jobs go with it.
func (c *Coordinator) Revoke(caller Caller, workerID, token string) error {
	claims, _, err := verifyGrant(token, caller, workerID, OpRevoke, time.Now())
	if err != nil {
		return err
	}
	lock, _, err := c.workerLock(workerID)
	if err != nil {
		return err
	}
	// The tree's lock first, as view and change take it, so nothing reads or
	// commits the tree while it goes.
	lock.Lock()
	defer lock.Unlock()
	c.mu.Lock()
	w, err := c.grantee(caller, workerID, claims.Seq)
	if err == nil && c.busy[workerID] {
		err = ErrBusy
	}
	if err != nil {
		c.mu.Unlock()
		return err
	}
	jobs := map[string]*Job{}
	for id, j := range c.state.Jobs {
		if j.WorkerID == workerID {
			jobs[id] = j
			delete(c.state.Jobs, id)
		}
	}
	delete(c.state.Workers, workerID)
	if err := c.state.Save(c.cfg.StateDir); err != nil {
		c.state.Workers[workerID] = w
		for id, j := range jobs {
			c.state.Jobs[id] = j
		}
		c.mu.Unlock()
		return err
	}
	delete(c.locks, workerID)
	c.mu.Unlock()
	c.deleteObjects(*w)
	return nil
}

// grantee is the worker a grant or revoke from caller numbered seq may
// change. Called with c.mu held.
func (c *Coordinator) grantee(caller Caller, workerID string, seq uint64) (*Worker, error) {
	w, ok := c.state.Workers[workerID]
	if !ok || w.Account != caller.Account || !w.authorizes(caller.Device) {
		return nil, ErrNoWorker
	}
	if seq != w.GrantSeq+1 {
		return nil, fmt.Errorf("%w: it is %d, and the worker's last was %d", ErrGrantSeq, seq, w.GrantSeq)
	}
	return w, nil
}

// deleteObjects removes a revoked worker's objects. Its DEK is already gone
// from the volume, so what this misses can't be read, only stored.
func (c *Coordinator) deleteObjects(w Worker) {
	if w.WrappedDEK == nil {
		return
	}
	dek, err := c.cfg.Key.Unwrap(w.ID, w.WrappedDEK)
	if err != nil {
		return
	}
	t, err := LoadTree(c.cfg.Store, w.ID, dek, w.Version)
	clear(dek[:])
	if err != nil {
		return
	}
	for _, e := range t.manifest.Entries {
		_ = c.cfg.Store.Delete(w.ID, e.Object)
	}
	_ = c.cfg.Store.Delete(w.ID, manifestObject)
}
