package coordinator

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// A team's membership list (docs/membership-list.md §2.2) is signed Ed25519 by
// an admin device over TeamListContext followed by the payload bytes, and sent
// as base64url(payload) "." base64url(signature), like the channel's session
// grant. The coordinator keeps the token as sent and hashes those bytes, so
// nothing is re-serialized.
//
// A device is listed only on its own team inclusion, signed the same way over
// TeamInclusionContext, which binds its X25519 key to its Ed25519 key, the
// coordinator, the team and the member's account, and says which log entry
// first admits it. So neither an admin device nor whoever controls
// fount-infra's device registry can list a device whose key they don't hold,
// and a removed device's old inclusion can't bring it back.
//
// Both are decoded strictly: unknown fields and duplicate keys anywhere are
// refused, so Desktop's serde and this decoder can't read two different
// payloads from one signature.
const (
	TeamListVersion = 3
	TeamListType    = "fount-team-members"
	TeamListContext = "fount-team-members-v3\n"

	TeamInclusionVersion = 1
	TeamInclusionType    = "fount-team-device"
	TeamInclusionContext = "fount-team-device-v1\n"

	// MaxMembers bounds a team's members, MaxMemberDevices each member's
	// devices and MaxTeamWorkers its workers.
	MaxMembers       = 50
	MaxMemberDevices = 8
	MaxTeamWorkers   = 64

	maxEmail        = 254
	maxTeamName     = 120
	maxPasskeyCred  = 1023
	p256PublicSize  = 65
	inviteCommitLen = sha256.Size
)

// Role is a member's: an admin reaches every worker of the team and may sign
// its list; a reviewer reaches the workers the list assigns them.
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleReviewer Role = "reviewer"
)

// allWorkers is a reviewer's assignment to every worker of the team.
const allWorkers = "*"

// TeamList is a list's payload.
type TeamList struct {
	V   int    `json:"v"`
	Typ string `json:"typ"`
	// Aud is the coordinator it is for (Config.Audience).
	Aud  string `json:"aud"`
	Team string `json:"team"`
	// Name is the team's name as its admins set it, shown on its workers.
	Name string `json:"name,omitempty"`
	// Seq is the log entry it is, and Prev the hash of the one before, empty
	// for the first.
	Seq  uint64 `json:"seq"`
	Prev string `json:"prev"`
	// Dev is the signing device's id.
	Dev     string       `json:"dev"`
	Iat     int64        `json:"iat"`
	Members []ListMember `json:"members"`
	Workers []ListWorker `json:"workers"`
	// Deleted ends the team (launch-plan X4): such a list names no member
	// and no worker, and is the log's last entry. A team of one isn't
	// deleted.
	Deleted bool `json:"deleted,omitempty"`
}

// ListMember is one member of a team.
type ListMember struct {
	ID string `json:"id"`
	// Account is empty only while the member is invited; Email is the
	// invite's address, lower-cased.
	Account string `json:"account,omitempty"`
	Email   string `json:"email,omitempty"`
	Role    Role   `json:"role"`
	// Workers are a reviewer's: allWorkers alone, or ids of the list's
	// workers. An admin has none.
	Workers []string `json:"workers,omitempty"`
	// Devices are the member's devices' team inclusions, by device id.
	Devices []string    `json:"devices,omitempty"`
	Invite  *ListInvite `json:"invite,omitempty"`
	Rec     *ListRec    `json:"rec,omitempty"`
}

// ListInvite is an open invite: Commit is base64url SHA-256 of the invite's
// secret (§2.3), which the invite record reveals, good until Exp.
type ListInvite struct {
	ID     string `json:"id"`
	Commit string `json:"commit"`
	Exp    int64  `json:"exp"`
}

// ListRec is a member's passkey, which admits a new device of theirs at once
// (passkeyjoin.go): its credential id and its ES256 public key, uncompressed,
// both base64url. The invitee makes it on accepting their invite, and the
// invite record carries it (teaminvite.go); a list after that carries it on,
// and an admin's list that names another is the only way to change it.
type ListRec struct {
	Cred string `json:"cred"`
	Pub  string `json:"pub"`
}

// ListWorker is one worker of the team and the commitment to its DEK.
type ListWorker struct {
	ID  string `json:"id"`
	DEK string `json:"dek"`
}

// TeamInclusion are what a device signs to be listed in a team.
type TeamInclusion struct {
	V    int    `json:"v"`
	Typ  string `json:"typ"`
	Aud  string `json:"aud"`
	Team string `json:"team"`
	Acct string `json:"acct"`
	// Dev is the device's id; Key its Ed25519 public key and Enc its X25519
	// public key, raw, base64url.
	Dev string `json:"dev"`
	Key string `json:"key"`
	Enc string `json:"enc"`
	// Seq is the log entry that first admits the device.
	Seq uint64 `json:"seq"`
}

// TeamDevice is a device a team's log admits.
type TeamDevice struct {
	ID        string
	Key       ed25519.PublicKey
	Enc       []byte
	Since     uint64
	Inclusion string
}

// ErrListRefused is a list or inclusion whose form or signature doesn't
// check out.
var ErrListRefused = errors.New("membership list refused")

// SignTeamList is Desktop's half: the admin device signs l, filling in its
// version, type and signer. Desktop does the same in Rust; this is the
// reference, and the tests'.
func SignTeamList(device ed25519.PrivateKey, l TeamList) (string, error) {
	l.V, l.Typ, l.Dev = TeamListVersion, TeamListType, deviceID(device.Public().(ed25519.PublicKey))
	return signToken(device, TeamListContext, l)
}

// SignTeamInclusion is the half of the device to be listed: its Ed25519 key
// signs c, filling in version, type, id and key; enc is its X25519 public key.
func SignTeamInclusion(device ed25519.PrivateKey, enc []byte, c TeamInclusion) (string, error) {
	if len(enc) != 32 {
		return "", errors.New("an X25519 public key is 32 bytes")
	}
	pub := device.Public().(ed25519.PublicKey)
	c.V, c.Typ, c.Dev, c.Key, c.Enc = TeamInclusionVersion, TeamInclusionType, deviceID(pub), b64.EncodeToString(pub), b64.EncodeToString(enc)
	return signToken(device, TeamInclusionContext, c)
}

func signToken(key ed25519.PrivateKey, context string, v any) (string, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(key, append([]byte(context), payload...))
	return b64.EncodeToString(payload) + "." + b64.EncodeToString(sig), nil
}

// splitToken is a token's payload and signature.
func splitToken(token string) (payload, sig []byte, err error) {
	p, s, ok := strings.Cut(token, ".")
	if !ok || strings.Contains(s, ".") {
		return nil, nil, errors.New("malformed")
	}
	if payload, err = b64.DecodeString(p); err != nil || len(payload) == 0 {
		return nil, nil, errors.New("malformed")
	}
	if sig, err = b64.DecodeString(s); err != nil || len(sig) != ed25519.SignatureSize {
		return nil, nil, errors.New("malformed")
	}
	return payload, sig, nil
}

// entryHash is a log entry's hash: SHA-256 of its context and its bytes,
// base64url.
func entryHash(context string, payload []byte) string {
	h := sha256.New()
	h.Write([]byte(context))
	h.Write(payload)
	return b64.EncodeToString(h.Sum(nil))
}

// decodeStrictJSON decodes one JSON object into v, refusing unknown fields,
// duplicate keys at any depth and anything after it.
func decodeStrictJSON(data []byte, v any) error {
	if err := noDuplicateKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after the object")
	}
	return nil
}

// noDuplicateKeys walks data's tokens and fails on an object with a key
// twice.
func noDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var walk func() error
	walk = func() error {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		switch t {
		case json.Delim('{'):
			seen := map[string]bool{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return err
				}
				key, _ := k.(string)
				if seen[key] {
					return fmt.Errorf("the key %.40q is there twice", key)
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		case json.Delim('['):
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		}
		return nil
	}
	return walk()
}

// parseTeamList checks what a list says on its own: that the caller's device
// key signed it, for this coordinator and team, lately, in a well-formed
// shape. Whether it follows the log, its signer is an admin and its devices
// fit are checked against the team (teamlog.go). It returns the list and the
// payload bytes it was signed over.
func parseTeamList(token, aud string, caller Caller, team string, now time.Time) (TeamList, []byte, error) {
	if aud == "" {
		return TeamList{}, nil, fmt.Errorf("%w: the coordinator has no audience to take lists for", ErrListRefused)
	}
	l, payload, err := parseTeamListToken(token, aud, caller, team, now)
	if err != nil {
		return TeamList{}, nil, fmt.Errorf("%w: %v", ErrListRefused, err)
	}
	return l, payload, nil
}

func parseTeamListToken(token, aud string, caller Caller, team string, now time.Time) (TeamList, []byte, error) {
	payload, sig, err := splitToken(token)
	if err != nil {
		return TeamList{}, nil, err
	}
	if len(caller.DeviceKey) != ed25519.PublicKeySize || !ed25519.Verify(caller.DeviceKey, append([]byte(TeamListContext), payload...), sig) {
		return TeamList{}, nil, errors.New("the channel's device key didn't sign it")
	}
	l, err := decodeTeamList(payload)
	if err != nil {
		return TeamList{}, nil, err
	}
	switch {
	case l.Aud != aud:
		return TeamList{}, nil, errors.New("it is for another coordinator")
	case l.Team != team:
		return TeamList{}, nil, errors.New("it is for another team")
	case l.Dev != deviceID(caller.DeviceKey) || l.Dev != caller.Device:
		return TeamList{}, nil, errors.New("it names another device than its signer")
	case l.Iat > now.Add(grantSkew).Unix():
		return TeamList{}, nil, errors.New("it is from the future")
	case l.Iat <= now.Add(-MaxGrantAge).Unix():
		return TeamList{}, nil, fmt.Errorf("it is over %s old", MaxGrantAge)
	}
	if err := l.checkShape(aud); err != nil {
		return TeamList{}, nil, err
	}
	return l, payload, nil
}

// decodeTeamList decodes a list's payload strictly. The log keeps only
// payloads it checked, so this is how it reads them back too.
func decodeTeamList(payload []byte) (TeamList, error) {
	var l TeamList
	if err := decodeStrictJSON(payload, &l); err != nil {
		return TeamList{}, fmt.Errorf("malformed: %v", err)
	}
	if l.V != TeamListVersion || l.Typ != TeamListType {
		return TeamList{}, errors.New("malformed: not a v3 team list")
	}
	return l, nil
}

// checkShape is every check on a list that needs nothing but the list.
func (l TeamList) checkShape(aud string) error {
	if err := checkID("team", l.Team); err != nil {
		return err
	}
	if !teamNameOK(l.Name) {
		return fmt.Errorf("its name is over %d characters, has controls or isn't trimmed", maxTeamName)
	}
	switch {
	case l.Seq == 0:
		return errors.New("its seq is 0")
	case (l.Seq == 1) != (l.Prev == ""):
		return errors.New("only the first entry has no prev")
	case l.Prev != "" && !isDigest(l.Prev):
		return errors.New("its prev isn't a hash")
	case l.Deleted && (len(l.Members) != 0 || len(l.Workers) != 0):
		return errors.New("a list that deletes its team names no member or worker")
	case l.Deleted && !strings.HasPrefix(l.Team, teamIDPrefix+"_"):
		return errors.New("only a firm team is deleted")
	case l.Deleted:
		return nil
	case len(l.Members) == 0 || len(l.Members) > MaxMembers:
		return fmt.Errorf("it must name 1 to %d members", MaxMembers)
	case len(l.Workers) > MaxTeamWorkers:
		return fmt.Errorf("it names over %d workers", MaxTeamWorkers)
	}
	workers := map[string]bool{}
	for i, w := range l.Workers {
		if err := checkID("worker", w.ID); err != nil {
			return err
		}
		if i > 0 && l.Workers[i-1].ID >= w.ID {
			return errors.New("its workers aren't sorted by id, once each")
		}
		if !isDigest(w.DEK) {
			return fmt.Errorf("worker %s's DEK commitment isn't a hash", w.ID)
		}
		workers[w.ID] = true
	}
	accounts, emails, devices, invites := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	admins := 0
	for i, m := range l.Members {
		if err := checkID("member", m.ID); err != nil {
			return err
		}
		if i > 0 && l.Members[i-1].ID >= m.ID {
			return errors.New("its members aren't sorted by id, once each")
		}
		if err := m.checkShape(workers); err != nil {
			return fmt.Errorf("member %s: %v", m.ID, err)
		}
		if m.Role == RoleAdmin {
			admins++
		}
		if m.Account != "" {
			if accounts[m.Account] {
				return fmt.Errorf("account %s is two members", m.Account)
			}
			accounts[m.Account] = true
		}
		if m.Email != "" {
			if emails[m.Email] {
				return fmt.Errorf("%s is two members", m.Email)
			}
			emails[m.Email] = true
		}
		if m.Invite != nil {
			if invites[m.Invite.ID] {
				return fmt.Errorf("invite %s is there twice", m.Invite.ID)
			}
			invites[m.Invite.ID] = true
		}
		prev := ""
		for _, token := range m.Devices {
			d, err := parseTeamInclusion(token, aud, l.Team, m.Account)
			if err != nil {
				return fmt.Errorf("member %s: %v", m.ID, err)
			}
			switch {
			case d.ID <= prev:
				return fmt.Errorf("member %s's devices aren't sorted by id, once each", m.ID)
			case devices[d.ID]:
				return fmt.Errorf("device %s is under two members", d.ID)
			case d.Since > l.Seq:
				return fmt.Errorf("device %s's inclusion is for entry %d", d.ID, d.Since)
			}
			prev, devices[d.ID] = d.ID, true
		}
	}
	if admins == 0 {
		return errors.New("it leaves the team with no admin")
	}
	return nil
}

func (m ListMember) checkShape(workers map[string]bool) error {
	switch {
	case m.Role != RoleAdmin && m.Role != RoleReviewer:
		return fmt.Errorf("no role %.20q", m.Role)
	case m.Account != "" && checkID("account", m.Account) != nil:
		return errors.New("its account isn't an id")
	case m.Email != "" && !isEmail(m.Email):
		return errors.New("its email isn't a lower-case address")
	case m.Account == "" && (m.Email == "" || m.Invite == nil):
		return errors.New("a member with no account needs an email and an invite")
	case m.Account == "" && len(m.Devices) > 0:
		return errors.New("a member with no account has no devices")
	case len(m.Devices) > MaxMemberDevices:
		return fmt.Errorf("over %d devices", MaxMemberDevices)
	case m.Invite != nil && m.Email == "":
		return errors.New("an invite needs an email")
	case m.Role == RoleAdmin && len(m.Workers) > 0:
		return errors.New("an admin reaches every worker, so names none")
	case m.Role == RoleReviewer && len(m.Workers) == 0:
		return errors.New("a reviewer reaches no worker")
	}
	if m.Role == RoleReviewer && !(len(m.Workers) == 1 && m.Workers[0] == allWorkers) {
		for i, w := range m.Workers {
			if !workers[w] {
				return fmt.Errorf("it reviews %.40q, which isn't the team's", w)
			}
			if i > 0 && m.Workers[i-1] >= w {
				return errors.New("its workers aren't sorted, once each")
			}
		}
	}
	if inv := m.Invite; inv != nil {
		if err := checkID("invite", inv.ID); err != nil {
			return err
		}
		commit, err := b64.DecodeString(inv.Commit)
		if err != nil || len(commit) != inviteCommitLen || inv.Exp <= 0 {
			return errors.New("its invite is malformed")
		}
	}
	if rec := m.Rec; rec != nil {
		if _, err := rec.public(); err != nil {
			return err
		}
	}
	return nil
}

// public is the passkey's SEC1 public key, once its credential id and key
// are of the shape a list allows.
func (rec ListRec) public() ([]byte, error) {
	cred, err := b64.DecodeString(rec.Cred)
	pub, perr := b64.DecodeString(rec.Pub)
	if err != nil || len(cred) == 0 || len(cred) > maxPasskeyCred || perr != nil || len(pub) != p256PublicSize || pub[0] != 4 {
		return nil, errors.New("its passkey is malformed")
	}
	return pub, nil
}

// parseTeamInclusion checks an inclusion's signature by the key it names and
// that it is for this coordinator, team and account.
func parseTeamInclusion(token, aud, team, account string) (TeamDevice, error) {
	payload, sig, err := splitToken(token)
	if err != nil {
		return TeamDevice{}, errors.New("an inclusion is malformed")
	}
	var c TeamInclusion
	if err := decodeStrictJSON(payload, &c); err != nil || c.V != TeamInclusionVersion || c.Typ != TeamInclusionType {
		return TeamDevice{}, errors.New("an inclusion is malformed")
	}
	key, err := b64.DecodeString(c.Key)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return TeamDevice{}, errors.New("an inclusion's key isn't 32 bytes of base64url")
	}
	enc, err := b64.DecodeString(c.Enc)
	if err != nil || len(enc) != 32 {
		return TeamDevice{}, errors.New("an inclusion's X25519 key isn't 32 bytes of base64url")
	}
	if err := checkX25519(enc); err != nil {
		return TeamDevice{}, fmt.Errorf("an inclusion's X25519 key: %w", err)
	}
	switch {
	case !ed25519.Verify(key, append([]byte(TeamInclusionContext), payload...), sig):
		return TeamDevice{}, errors.New("an inclusion isn't signed by the key it names")
	case c.Dev != deviceID(key):
		return TeamDevice{}, errors.New("an inclusion names another device than its key's")
	case c.Aud != aud:
		return TeamDevice{}, errors.New("an inclusion is for another coordinator")
	case c.Team != team:
		return TeamDevice{}, errors.New("an inclusion is for another team")
	case c.Acct != account:
		return TeamDevice{}, errors.New("an inclusion is for another account")
	case c.Seq == 0:
		return TeamDevice{}, errors.New("an inclusion is for entry 0")
	}
	return TeamDevice{ID: c.Dev, Key: key, Enc: enc, Since: c.Seq, Inclusion: token}, nil
}

func isDigest(s string) bool {
	b, err := b64.DecodeString(s)
	return err == nil && len(b) == sha256.Size
}

// isEmail is a loose check of an address as Clerk verified it: lower case, no
// spaces or controls, one @ with something either side.
func isEmail(s string) bool {
	local, domain, ok := strings.Cut(s, "@")
	return ok && local != "" && domain != "" && !strings.Contains(domain, "@") && len(s) <= maxEmail &&
		s == strings.ToLower(s) && !strings.ContainsFunc(s, func(r rune) bool { return r <= ' ' || r == 0x7f })
}

// teamNameOK says a team's name is at most maxTeamName characters, with no
// controls and no spaces at either end.
func teamNameOK(name string) bool {
	return utf8.ValidString(name) && utf8.RuneCountInString(name) <= maxTeamName && strings.TrimSpace(name) == name &&
		!strings.ContainsFunc(name, func(r rune) bool { return unicode.IsControl(r) })
}

// sameDevice says whether two admissions of one device are the same keys.
func sameDevice(a, b TeamDevice) bool {
	return a.ID == b.ID && subtle.ConstantTimeCompare(a.Key, b.Key) == 1 && subtle.ConstantTimeCompare(a.Enc, b.Enc) == 1 && a.Since == b.Since
}

// reaches says whether a member reaches a worker of the team.
func (m *Member) reaches(workerID string) bool {
	return m.Role == RoleAdmin || slices.Contains(m.Workers, allWorkers) || slices.Contains(m.Workers, workerID)
}
