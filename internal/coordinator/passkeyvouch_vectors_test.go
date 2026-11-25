package coordinator

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// passkeyVouchVectors is testdata/team-passkey-vouch-vectors.json, for
// Desktop's Rust replay of a passkey-vouch record (account/team_log.rs): an
// account's own team's first list naming the owner's passkey, then the
// passkey's vouch for it, and entries 2 each client must refuse. ECDSA
// signatures are random, so the file is written once and then only checked;
// the challenge and the list are deterministic.
type passkeyVouchVectors struct {
	Comment        string `json:"comment"`
	Audience       string `json:"audience"`
	Team           string `json:"team"`
	Member         string `json:"member"`
	PasskeyPrivate string `json:"passkey_p256_private"`
	PasskeyCred    string `json:"passkey_cred"`
	PasskeyPub     string `json:"passkey_pub"`
	ChallengeMsg   string `json:"challenge_message"`
	Challenge      string `json:"challenge"`
	// Log is GET /v1/teams/{team}/log from 0: entry 1 the list, entry 2 the
	// passkey-vouch record.
	Log TeamLogView `json:"log"`
	// Refused are other entries 2, each to be refused, by why.
	Refused map[string]TeamEntry `json:"refused"`
	// Again is an entry 3 after Log: the same passkey vouching again.
	Again TeamEntry `json:"again"`
}

const passkeyVouchVectorsPath = "testdata/team-passkey-vouch-vectors.json"

func makePasskeyVouchVectors(t *testing.T) passkeyVouchVectors {
	t.Helper()
	owner := ed25519.NewKeyFromSeed(seq(0x02))
	pk, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), seq(0x42))
	if err != nil {
		t.Fatal(err)
	}
	pkPub, _ := pk.PublicKey.Bytes()
	v := passkeyVouchVectors{
		Comment:  "A passkey-vouch record (internal/coordinator/passkeyvouch.go) as a client replays it. Bytes are hex unless named base64url. Test keys only. Rewrite (new signatures): PASSKEY_VOUCH_VECTORS_WRITE=1 go test -run TestPasskeyVouchVectors ./internal/coordinator",
		Audience: "https://coordinator.example", Team: "acct_vouch", Member: "m_owner",
		PasskeyPrivate: hex.EncodeToString(seq(0x42)), PasskeyCred: b64.EncodeToString(seq(0xe2)[:16]), PasskeyPub: b64.EncodeToString(pkPub),
	}
	ownerIncl, err := SignTeamInclusion(owner, seq(0x22), TeamInclusion{Aud: v.Audience, Team: v.Team, Acct: v.Team, Seq: 1})
	if err != nil {
		t.Fatal(err)
	}
	list, err := SignTeamList(owner, TeamList{Aud: v.Audience, Team: v.Team, Seq: 1, Iat: 1798761600,
		Members: []ListMember{{ID: v.Member, Account: v.Team, Role: RoleAdmin, Devices: []string{ownerIncl}, Rec: &ListRec{Cred: v.PasskeyCred, Pub: v.PasskeyPub}}},
		Workers: []ListWorker{}})
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := splitToken(list)
	if err != nil {
		t.Fatal(err)
	}
	first := TeamEntry{Seq: 1, List: list, Hash: entryHash(TeamListContext, payload)}
	msg, _ := lengthPrefixed(PasskeyVouchContext, []byte(v.Audience), []byte(v.Team), []byte(v.Member), []byte(first.Hash))
	v.ChallengeMsg = hex.EncodeToString(msg)
	challenge, _ := PasskeyVouchChallenge(v.Audience, v.Team, v.Member, first.Hash)
	v.Challenge = hex.EncodeToString(challenge)

	type assertion struct {
		key    *ecdsa.PrivateKey
		cred   string
		flags  byte
		client string
		count  uint32
		seq    uint64
		prev   string
		device string
	}
	clientOf := func(challenge []byte, origin string) string {
		return `{"type":"webauthn.get","challenge":"` + base64.RawURLEncoding.EncodeToString(challenge) + `","origin":"` + origin + `"}`
	}
	entry := func(a assertion) TeamEntry {
		rp := sha256.Sum256([]byte(PasskeyRPID))
		auth := binary.BigEndian.AppendUint32(append(rp[:], a.flags), a.count)
		ch := sha256.Sum256([]byte(a.client))
		digest := sha256.Sum256(append(append([]byte{}, auth...), ch[:]...))
		sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		proof, _ := json.Marshal(PasskeyVouchProof{Cred: a.cred, AuthenticatorData: b64.EncodeToString(auth),
			ClientDataJSON: b64.EncodeToString([]byte(a.client)), Signature: b64.EncodeToString(sig)})
		raw, _ := json.Marshal(TeamRecord{Kind: RecordPasskeyVouch, Seq: a.seq, Prev: a.prev, Member: v.Member, Account: v.Team, Device: a.device, At: 1798762000 + int64(a.seq), Proof: proof})
		return TeamEntry{Seq: a.seq, Record: raw, Hash: entryHash(TeamRecordContext, raw)}
	}
	good := assertion{key: pk, cred: v.PasskeyCred, flags: 0x1d, client: clientOf(challenge, PasskeyOrigins[0]), count: 0, seq: 2, prev: first.Hash}
	second := entry(good)
	v.Log = TeamLogView{Team: v.Team, Seq: 2, Head: second.Hash, Entries: []TeamEntry{first, second}}

	unlisted, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), seq(0x52))
	if err != nil {
		t.Fatal(err)
	}
	otherStart, _ := PasskeyVouchChallenge(v.Audience, v.Team, v.Member, "")
	otherMember, _ := PasskeyVouchChallenge(v.Audience, v.Team, "m_other", first.Hash)
	otherTeam, _ := PasskeyVouchChallenge(v.Audience, "acct_other", v.Member, first.Hash)
	joinShaped, _ := PasskeyJoinChallenge(v.Audience, v.Team, v.Member, first.Hash, seq(0xc2), seq(0x62), seq(0x82))
	with := func(f func(*assertion)) assertion {
		a := good
		f(&a)
		return a
	}
	v.Refused = map[string]TeamEntry{
		"unlisted_passkey": entry(with(func(a *assertion) { a.key = unlisted })),
		"another_cred":     entry(with(func(a *assertion) { a.cred = b64.EncodeToString(seq(0xf2)[:16]) })),
		"wrong_origin":     entry(with(func(a *assertion) { a.client = clientOf(challenge, "https://evil.example") })),
		"another_start":    entry(with(func(a *assertion) { a.client = clientOf(otherStart, PasskeyOrigins[0]) })),
		"another_member":   entry(with(func(a *assertion) { a.client = clientOf(otherMember, PasskeyOrigins[0]) })),
		"another_team":     entry(with(func(a *assertion) { a.client = clientOf(otherTeam, PasskeyOrigins[0]) })),
		"a_join_challenge": entry(with(func(a *assertion) { a.client = clientOf(joinShaped, PasskeyOrigins[0]) })),
		"not_verified":     entry(with(func(a *assertion) { a.flags = 0x01 })),
		"with_a_device":    entry(with(func(a *assertion) { a.device = ownerIncl })),
	}
	v.Again = entry(assertion{key: pk, cred: v.PasskeyCred, flags: 0x1d, client: clientOf(challenge, PasskeyOrigins[0]), seq: 3, prev: second.Hash})
	return v
}

func TestPasskeyVouchVectors(t *testing.T) {
	if os.Getenv("PASSKEY_VOUCH_VECTORS_WRITE") != "" {
		out, _ := json.Marshal(makePasskeyVouchVectors(t))
		if err := os.WriteFile(passkeyVouchVectorsPath, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(passkeyVouchVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var v passkeyVouchVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	made := makePasskeyVouchVectors(t)
	if v.Challenge != made.Challenge || v.ChallengeMsg != made.ChallengeMsg || v.Log.Entries[0].Hash != made.Log.Entries[0].Hash || v.PasskeyPub != made.PasskeyPub {
		t.Fatal("the vectors' deterministic values changed")
	}
	st, err := reduceTeam(v.Team, v.Audience, v.Log.Entries)
	if err != nil {
		t.Fatalf("the vector log: %v", err)
	}
	if st.head != v.Log.Head || !st.vouched[v.PasskeyPub] {
		t.Fatal("the vector log isn't vouched for")
	}
	if len(v.Refused) == 0 {
		t.Fatal("no refused vectors")
	}
	for name, e := range v.Refused {
		if _, err := reduceTeam(v.Team, v.Audience, []TeamEntry{v.Log.Entries[0], e}); err == nil {
			t.Errorf("%s: replayed", name)
		}
	}
	if _, err := reduceTeam(v.Team, v.Audience, append(v.Log.Entries[:2:2], v.Again)); err == nil {
		t.Error("again: replayed")
	}
}
