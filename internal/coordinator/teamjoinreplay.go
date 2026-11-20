package coordinator

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// A join record: a member's new device approved, with a six-digit code, by
// another device of theirs. The code join is gone (decided 2026-11-19: every
// new computer joins with the member's passkey, passkeyjoin.go), so no join
// record is appended any more. One already in a log, which only dev logs
// have, still replays, so those teams keep working; what it was checked by
// is kept here, unchanged.

const (
	JoinContext   = "fount-team-join-v1\x00"
	joinNonceSize = 32
)

// JoinProof is a join record's proof: the approving device and its
// signature over JoinMessage.
type JoinProof struct {
	Join     string `json:"join"`
	Nonce    string `json:"nonce"`
	Approver string `json:"approver"`
	Sig      string `json:"sig"`
}

// JoinMessage is what an admitted device signed to approve a new one of its
// member's: the coordinator, team, member, request, and the new device's
// Ed25519 and X25519 keys.
func JoinMessage(aud, team, member, join string, nonce, key, enc []byte) ([]byte, error) {
	return lengthPrefixed(JoinContext, []byte(aud), []byte(team), []byte(member), []byte(join), nonce, key, enc)
}

// checkJoinProof is what reduceTeam checks of a join record against the
// state before it: the approver was admitted under the same member, and
// signed JoinMessage over the record's device's keys.
func checkJoinProof(st *teamState, aud, team string, r TeamRecord, m *Member) error {
	var p JoinProof
	if err := decodeStrictJSON(r.Proof, &p); err != nil {
		return fmt.Errorf("a join record's proof: %v", err)
	}
	approver, holder := st.device(p.Approver)
	if holder == nil || holder.ID != m.ID {
		return errors.New("a join record's approver isn't a device of its member")
	}
	d, err := parseTeamInclusion(r.Device, aud, team, m.Account)
	if err != nil {
		return err
	}
	nonce, nerr := b64.DecodeString(p.Nonce)
	sig, serr := b64.DecodeString(p.Sig)
	if nerr != nil || serr != nil || len(nonce) != joinNonceSize || checkID("join", p.Join) != nil {
		return errors.New("a join record's proof is malformed")
	}
	msg, err := JoinMessage(aud, team, m.ID, p.Join, nonce, d.Key, d.Enc)
	if err != nil {
		return err
	}
	if !ed25519.Verify(approver.Key, msg, sig) {
		return errors.New("a join record's approval isn't its approver's signature")
	}
	return nil
}

// joinKeys is a device's keys, as a passkey join's challenge asks for them.
type joinKeys struct {
	Key string `json:"key"`
	Enc string `json:"enc"`
}
