package coordinator

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

// passkeyJoinVectors is testdata/team-passkey-join-vectors.json, for
// Desktop's Rust replay of a passkey-join record (account/team_log.rs): a
// team's first list naming the owner's passkey, then a record admitting the
// owner's new computer with it, and records for that same entry each client
// must refuse. ECDSA signatures are random, so the file is written once and
// then only checked; the challenge and the list are deterministic.
type passkeyJoinVectors struct {
	Comment   string `json:"comment"`
	Audience  string `json:"audience"`
	Team      string `json:"team"`
	OwnerSeed string `json:"owner_ed25519_seed"`
	NewSeed   string `json:"new_ed25519_seed"`
	NewX25519 string `json:"new_x25519_private"`
	NewDevice string `json:"new_device"`
	Member    string `json:"member"`
	// The passkey: its P-256 private scalar, credential id and public key.
	PasskeyPrivate string `json:"passkey_p256_private"`
	PasskeyCred    string `json:"passkey_cred"`
	PasskeyPub     string `json:"passkey_pub"`
	Nonce          string `json:"nonce"`
	ChallengeMsg   string `json:"challenge_message"`
	Challenge      string `json:"challenge"`
	// Log is GET /v1/teams/{team}/log from 0: entry 1 the list, entry 2 the
	// passkey-join record.
	Log TeamLogView `json:"log"`
	// Refused are other entries 2, each to be refused, by why.
	Refused map[string]TeamEntry `json:"refused"`
	// Third is an entry 3 after Log, a passkey join of another device whose
	// sign count (8) rose past entry 2's (7); SameCount is that join with
	// count 7, to be refused.
	Third     TeamEntry `json:"third"`
	SameCount TeamEntry `json:"same_count"`
}

const passkeyJoinVectorsPath = "testdata/team-passkey-join-vectors.json"

func makePasskeyJoinVectors(t *testing.T) passkeyJoinVectors {
	t.Helper()
	owner := ed25519.NewKeyFromSeed(seq(0x01))
	newKey := ed25519.NewKeyFromSeed(seq(0x61))
	newEnc, err := ecdh.X25519().NewPrivateKey(seq(0x81))
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), seq(0x41))
	if err != nil {
		t.Fatal(err)
	}
	pkPub, _ := pk.PublicKey.Bytes()
	v := passkeyJoinVectors{
		Comment:  "A passkey-join record (internal/coordinator/passkeyjoin.go) as a client replays it. Bytes are hex unless named base64url. Test keys only. Rewrite (new signatures): PASSKEY_JOIN_VECTORS_WRITE=1 go test -run TestPasskeyJoinVectors ./internal/coordinator",
		Audience: "https://coordinator.example", Team: "acct_passkey",
		OwnerSeed: hex.EncodeToString(seq(0x01)), NewSeed: hex.EncodeToString(seq(0x61)), NewX25519: hex.EncodeToString(newEnc.Bytes()),
		NewDevice: deviceID(newKey.Public().(ed25519.PublicKey)), Member: "m_owner",
		PasskeyPrivate: hex.EncodeToString(seq(0x41)), PasskeyCred: b64.EncodeToString(seq(0xe1)[:16]), PasskeyPub: b64.EncodeToString(pkPub),
		Nonce: hex.EncodeToString(seq(0xc1)),
	}
	ownerIncl, err := SignTeamInclusion(owner, seq(0x21), TeamInclusion{Aud: v.Audience, Team: v.Team, Acct: v.Team, Seq: 1})
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
	newPub, newEncPub := newKey.Public().(ed25519.PublicKey), newEnc.PublicKey().Bytes()
	msg, _ := lengthPrefixed(PasskeyJoinContext, []byte(v.Audience), []byte(v.Team), []byte(v.Member), []byte(first.Hash), seq(0xc1), newPub, newEncPub)
	v.ChallengeMsg = hex.EncodeToString(msg)
	challenge, _ := PasskeyJoinChallenge(v.Audience, v.Team, v.Member, first.Hash, seq(0xc1), newPub, newEncPub)
	v.Challenge = hex.EncodeToString(challenge)
	newIncl, err := SignTeamInclusion(newKey, newEncPub, TeamInclusion{Aud: v.Audience, Team: v.Team, Acct: v.Team, Seq: 2})
	if err != nil {
		t.Fatal(err)
	}

	type assertion struct {
		key       *ecdsa.PrivateKey
		cred      string
		challenge []byte
		flags     byte
		client    string
		count     uint32
		seq       uint64
		prev      string
	}
	clientOf := func(challenge []byte, origin, extra string) string {
		return `{"type":"webauthn.get","challenge":"` + base64.RawURLEncoding.EncodeToString(challenge) + `","origin":"` + origin + `"` + extra + `}`
	}
	entry := func(a assertion, device string) TeamEntry {
		rp := sha256.Sum256([]byte(PasskeyRPID))
		auth := binary.BigEndian.AppendUint32(append(rp[:], a.flags), a.count)
		ch := sha256.Sum256([]byte(a.client))
		digest := sha256.Sum256(append(append([]byte{}, auth...), ch[:]...))
		sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		sig = highS(t, sig)
		proof, _ := json.Marshal(PasskeyJoinProof{Nonce: b64.EncodeToString(seq(0xc1)), Cred: a.cred, AuthenticatorData: b64.EncodeToString(auth),
			ClientDataJSON: b64.EncodeToString([]byte(a.client)), Signature: b64.EncodeToString(sig)})
		raw, _ := json.Marshal(TeamRecord{Kind: RecordPasskeyJoin, Seq: a.seq, Prev: a.prev, Member: v.Member, Account: v.Team, Device: device, At: 1798762000 + int64(a.seq), Proof: proof})
		return TeamEntry{Seq: a.seq, Record: raw, Hash: entryHash(TeamRecordContext, raw)}
	}
	good := assertion{key: pk, cred: v.PasskeyCred, challenge: challenge, flags: 0x1d, client: clientOf(challenge, "https://fount.sh", ""), count: 7, seq: 2, prev: first.Hash}
	second := entry(good, newIncl)
	v.Log = TeamLogView{Team: v.Team, Seq: 2, Head: second.Hash, Entries: []TeamEntry{first, second}}

	other := ed25519.NewKeyFromSeed(seq(0x71))
	otherIncl, err := SignTeamInclusion(other, seq(0x91), TeamInclusion{Aud: v.Audience, Team: v.Team, Acct: v.Team, Seq: 2})
	if err != nil {
		t.Fatal(err)
	}
	unlisted, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), seq(0x51))
	if err != nil {
		t.Fatal(err)
	}
	otherHead, _ := PasskeyJoinChallenge(v.Audience, v.Team, v.Member, "", seq(0xc1), newPub, newEncPub)
	with := func(f func(*assertion)) assertion {
		a := good
		f(&a)
		return a
	}
	v.Refused = map[string]TeamEntry{
		"another_device":   entry(good, otherIncl),
		"unlisted_passkey": entry(with(func(a *assertion) { a.key = unlisted }), newIncl),
		"another_cred":     entry(with(func(a *assertion) { a.cred = b64.EncodeToString(seq(0xf1)[:16]) }), newIncl),
		"wrong_origin":     entry(with(func(a *assertion) { a.client = clientOf(challenge, "https://evil.example", "") }), newIncl),
		"cross_origin":     entry(with(func(a *assertion) { a.client = clientOf(challenge, "https://fount.sh", `,"crossOrigin":true`) }), newIncl),
		"another_head":     entry(with(func(a *assertion) { a.client = clientOf(otherHead, "https://fount.sh", "") }), newIncl),
		"not_verified":     entry(with(func(a *assertion) { a.flags = 0x01 }), newIncl),
		"escaped":          entry(with(func(a *assertion) { a.client = clientOf(challenge, "https://fount.sh", `,"x":"a\/b"`) }), newIncl),
		"origin_key_case": entry(with(func(a *assertion) {
			a.client = `{"type":"webauthn.get","challenge":"` + base64.RawURLEncoding.EncodeToString(challenge) + `","Origin":"https://fount.sh"}`
		}), newIncl),
		"nested": entry(with(func(a *assertion) {
			a.client = clientOf(challenge, "https://fount.sh", `,"tokenBinding":{"status":"present"}`)
		}), newIncl),
		"number": entry(with(func(a *assertion) { a.client = clientOf(challenge, "https://fount.sh", `,"n":1e400`) }), newIncl),
		"origin_repeated": entry(with(func(a *assertion) {
			a.client = clientOf(challenge, "https://fount.sh", `,"origin":"https://evil.example"`)
		}), newIncl),
	}
	thirdKey := ed25519.NewKeyFromSeed(seq(0xa1))
	thirdEnc := seq(0xb1)
	thirdIncl, err := SignTeamInclusion(thirdKey, thirdEnc, TeamInclusion{Aud: v.Audience, Team: v.Team, Acct: v.Team, Seq: 3})
	if err != nil {
		t.Fatal(err)
	}
	thirdCh, _ := PasskeyJoinChallenge(v.Audience, v.Team, v.Member, second.Hash, seq(0xc1), thirdKey.Public().(ed25519.PublicKey), thirdEnc)
	third := assertion{key: pk, cred: v.PasskeyCred, flags: 0x1d, client: clientOf(thirdCh, "https://fount.sh", ""), count: 8, seq: 3, prev: second.Hash}
	v.Third = entry(third, thirdIncl)
	third.count = 7
	v.SameCount = entry(third, thirdIncl)
	return v
}

// highS is sig with s above n/2, which ECDSA verifies as well: so the
// vectors check that both sides accept either.
func highS(t *testing.T, sig []byte) []byte {
	t.Helper()
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &parsed); err != nil {
		t.Fatal(err)
	}
	n := elliptic.P256().Params().N
	if parsed.S.Cmp(new(big.Int).Rsh(n, 1)) <= 0 {
		parsed.S = new(big.Int).Sub(n, parsed.S)
	}
	out, err := asn1.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPasskeyJoinVectors(t *testing.T) {
	if os.Getenv("PASSKEY_JOIN_VECTORS_WRITE") != "" {
		// Compact: an entry's hash is over its record's bytes as written.
		out, _ := json.Marshal(makePasskeyJoinVectors(t))
		if err := os.WriteFile(passkeyJoinVectorsPath, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(passkeyJoinVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var v passkeyJoinVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	made := makePasskeyJoinVectors(t)
	// What is deterministic is unchanged.
	if v.Challenge != made.Challenge || v.ChallengeMsg != made.ChallengeMsg || v.Log.Entries[0].Hash != made.Log.Entries[0].Hash || v.PasskeyPub != made.PasskeyPub || v.NewDevice != made.NewDevice {
		t.Fatal("the vectors' deterministic values changed")
	}
	st, err := reduceTeam(v.Team, v.Audience, v.Log.Entries)
	if err != nil {
		t.Fatalf("the vector log: %v", err)
	}
	if st.head != v.Log.Head || st.byDevice[v.NewDevice] == nil {
		t.Fatal("the vector log doesn't admit the new device")
	}
	if len(v.Refused) == 0 {
		t.Fatal("no refused vectors")
	}
	if _, err := reduceTeam(v.Team, v.Audience, append(v.Log.Entries[:2:2], v.Third)); err != nil {
		t.Fatalf("a rising count: %v", err)
	}
	if _, err := reduceTeam(v.Team, v.Audience, append(v.Log.Entries[:2:2], v.SameCount)); err == nil {
		t.Error("same_count: replayed")
	}
	for name, e := range v.Refused {
		if _, err := reduceTeam(v.Team, v.Audience, []TeamEntry{v.Log.Entries[0], e}); err == nil {
			t.Errorf("%s: replayed", name)
		}
	}
}
