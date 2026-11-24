package coordinator

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"time"
)

// How a worker comes to the coordinator over the client channel, and who may
// act for it after (docs/membership-list.md):
//
//  1. POST /v1/workers makes an empty worker with no DEK and no team, which
//     only the channel's device may see: its creator.
//  2. A list its team's admin device signed (teamlist.go) adds it to the team,
//     with its DEK, which the coordinator wraps under its wrapping key. From
//     then on its team's log decides who may act for it: every admin of the
//     team, and the reviewers the list assigns it, on the devices admitted
//     under them (members.go). The coordinator seals the DEK to each of those
//     devices itself and keeps the wraps in Worker.Devices, rederived each time
//     the log moves.
//  3. A list that leaves the worker out deletes it: the coordinator forgets
//     it, its DEK and its jobs, and deletes its objects.
//
// Every /v1 operation on a worker needs the channel's device to be admitted
// under a member of the channel's account who reaches the worker with the
// operation's role (opRoles). Reads, writes, listing and jobs are authorized
// by the channel's device (Caller.Device), which the broker proves with the
// session key the device key granted it, for up to channel.MaxSession: a
// broker's session key that leaks opens its device's workers until the
// session grant expires, but can't sign a list. The team's log is what keeps
// fount-infra, which vouches for the device and its account each time it
// connects, from minting a device or a member that opens a team's workers.
//
// The v2 grants that came before (a device list per worker, signed by any of
// its devices) are refused outright: POST /v1/workers/{id}/grant and /revoke
// answer ErrRetired.
const (
	// A worker made over the channel and not yet in a team holds a place in
	// the state for nothing: a device has at most MaxUngrantedPerDevice, an
	// account MaxUngrantedPerAccount, and each goes after UngrantedTTL.
	MaxUngrantedPerDevice  = 4
	MaxUngrantedPerAccount = 16
	UngrantedTTL           = 30 * time.Minute
	// MaxGrantAge is how long a signed list stays good: Desktop signs it just
	// before it sends it.
	MaxGrantAge = time.Hour
	grantSkew   = 5 * time.Minute

	dekCommitmentContext = "fount-worker-dek-v1\x00"
)

// Caller is who a client channel proved to be: the account fount-infra
// vouched for, and the device whose key granted the channel's session.
type Caller struct {
	Account   string
	Device    string
	DeviceKey ed25519.PublicKey
	// Email is the account's verified email, from the Cloud credential's
	// eml claim, or empty. An invite is accepted only for it.
	Email string
	// Paid says the caller's own credential entitles it to Cloud
	// (channel.Peer.Paid). A caller without it is admitted only where a
	// firm team's subscription covers it (admission.go).
	Paid bool
}

// Device is one device that may act for a worker: its Ed25519 key, its X25519
// key and the worker's DEK sealed to it (SealWrap), which the coordinator
// keeps for the device and hands it with the worker. Derived from the team's
// log (members.go); a worker not yet in a team lists only its creator, with
// no Enc or Wrap.
type Device struct {
	ID   string `json:"id"`
	Key  []byte `json:"key"`
	Enc  []byte `json:"enc,omitempty"`
	Wrap []byte `json:"wrap,omitempty"`
	// EpochWraps are its wraps of the worker's DEK epochs after the first.
	EpochWraps []EpochWrap `json:"epochWraps,omitempty"`
}

var (
	// ErrNotGranted is a worker made over the channel that no list has added
	// to a team yet: it has no DEK, no files and runs no jobs.
	ErrNotGranted = errors.New("the email agent isn't in a team yet")
	// ErrRetired is a v2 grant or revoke, which no worker takes any more.
	ErrRetired = errors.New("v2 grants are retired: sign the team's membership list")
	// ErrBusy is a worker with a running job.
	ErrBusy = errors.New("the email agent has a running job")
	// ErrTooManyUngranted is a device or account with as many workers
	// waiting for a team as it may have.
	ErrTooManyUngranted = errors.New("too many email agents waiting to join a team")
)

var b64 = base64.RawURLEncoding.Strict()

// deviceID is fount-infra's and the channel's id for a device key.
func deviceID(key ed25519.PublicKey) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:16])
}

// DEKCommitment is what a list signs for a worker's DEK: HMAC-SHA256 under the DEK
// of the worker's id. It binds the signature to the key without showing it.
func DEKCommitment(workerID string, dek DEK) string {
	m := hmac.New(sha256.New, dek[:])
	m.Write([]byte(dekCommitmentContext + workerID))
	return b64.EncodeToString(m.Sum(nil))
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
// the caller's device may act for until a list adds it to a team with its
// DEK. It goes after UngrantedTTL without one.
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
	if err := c.admitCreate(caller); err != nil {
		return Worker{}, err
	}
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

// ungrantedExpired says whether w is a worker made over the channel that no
// list added to a team in time.
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

// deleteObjects removes a deleted worker's objects. Its DEK is already gone
// from the volume, so what this misses can't be read, only stored.
func (c *Coordinator) deleteObjects(w Worker) {
	if w.WrappedDEK == nil {
		return
	}
	ring, err := c.cfg.Key.Keyring(&w)
	if err != nil {
		return
	}
	t, err := LoadTreeKeys(c.cfg.Store, w.ID, ring, w.Version)
	ring.Clear()
	if err != nil {
		return
	}
	for _, e := range t.manifest.Entries {
		_ = c.cfg.Store.Delete(w.ID, e.Object)
	}
	_ = c.cfg.Store.Delete(w.ID, manifestObject)
}
