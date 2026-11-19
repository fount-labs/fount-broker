package coordinator

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
)

// A worker's address keys (record/mail/mailbox.json) are the coordinator's
// alone (decision 25). The tree seals every object under the worker's DEK,
// which every device that reaches the worker holds, reviewers and removed
// members included; with the bucket, that DEK opened the address keys
// (security review 2026-11-19, H6). So mailbox.json is sealed a second time,
// inside its tree object, under a key only the coordinator has: HKDF-SHA256
// from its wrapping key, as the reply-token key is, per worker. It's derived,
// never stored, so it's in no tree, backup, export or mail setup.
//
// The object holds {"sealed": "<base64 nonce || AES-256-GCM>"} with the AAD
// aad(purposeTreeSecret, worker id, path). A mailbox.json from before is
// plain JSON; it's read as it is, and sealed the next time it's written
// (prepareMail writes it once per process).

const (
	treeSecretInfo    = "fount-coordinator/tree-secret-key/v1"
	purposeTreeSecret = "fount-coordinator/tree-secret/v1"
)

var errNoTreeSecret = errors.New("this tree was opened without the coordinator's secret key")

// treeSecret is the key a worker's coordinator-only files are sealed under.
func (c *Coordinator) treeSecret(workerID string) []byte {
	key, err := hkdf.Key(sha256.New, c.cfg.Key[:], nil, treeSecretInfo+"\x00"+workerID, KeySize)
	if err != nil {
		panic("hkdf: " + err.Error())
	}
	return key
}

type sealedSecret struct {
	Sealed []byte `json:"sealed"`
}

// sealSecret seals a coordinator-only file's contents for path.
func (t *Tree) sealSecret(path string, plain []byte) ([]byte, error) {
	if t.secret == nil {
		return nil, fmt.Errorf("%s: %w", path, errNoTreeSecret)
	}
	sealed, err := seal(t.secret, plain, aad(purposeTreeSecret, t.workerID, path))
	if err != nil {
		return nil, err
	}
	return json.Marshal(sealedSecret{Sealed: sealed})
}

// openSecret opens what sealSecret made, or passes through a file from
// before, reporting it as legacy.
func (t *Tree) openSecret(path string, data []byte) (plain []byte, legacy bool, err error) {
	var s sealedSecret
	if json.Unmarshal(data, &s) != nil || s.Sealed == nil {
		return data, true, nil
	}
	if t.secret == nil {
		return nil, false, fmt.Errorf("%s: %w", path, errNoTreeSecret)
	}
	plain, err = open(t.secret, s.Sealed, aad(purposeTreeSecret, t.workerID, path))
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", path, err)
	}
	return plain, false, nil
}

// mailboxLegacy reports whether t's mailbox.json is still sealed under the
// DEK alone.
func mailboxLegacy(t *Tree) bool {
	data, err := t.Read(mailboxPath)
	if err != nil {
		return false
	}
	_, legacy, _ := t.openSecret(mailboxPath, data)
	return legacy
}
