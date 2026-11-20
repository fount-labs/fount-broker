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
	"slices"
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

	// The passkey an invitee lists on accepting (teaminvite.go), the same
	// passkey as above. InviteLog is a log from 0: entry 1 a list inviting
	// InviteMember, entry 2 the invite record by InviteAccount's new device
	// (the new keys above) listing the passkey (sign count 3), entry 3 a
	// passkey join of a third device by that passkey (count 4). InviteRefused
	// are other entries 2, each to be refused, among them one with no passkey,
	// as before passkey-only joins. InviteAgain is an entry 4, a list inviting
	// InviteMember again, and InviteBack an entry 5, the invite record of a
	// fourth device with a new passkey: it removes both of the member's
	// devices and lists the new passkey, and leaves the owner's alone.
	InviteMember       string               `json:"invite_member"`
	InviteAccount      string               `json:"invite_account"`
	InviteEmail        string               `json:"invite_email"`
	InviteID           string               `json:"invite_id"`
	InviteSecret       string               `json:"invite_secret"`
	InviteChallengeMsg string               `json:"invite_challenge_message"`
	InviteChallenge    string               `json:"invite_challenge"`
	InviteLog          TeamLogView          `json:"invite_log"`
	InviteRefused      map[string]TeamEntry `json:"invite_refused"`
	InviteAgain        TeamEntry            `json:"invite_again"`
	InviteBack         TeamEntry            `json:"invite_back"`
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
	makeInvitePasskeyVectors(t, &v, owner, ownerIncl, pk, unlisted, newKey, newEncPub, clientOf)
	return v
}

func makeInvitePasskeyVectors(t *testing.T, v *passkeyJoinVectors, owner ed25519.PrivateKey, ownerIncl string, pk, unlisted *ecdsa.PrivateKey,
	newKey ed25519.PrivateKey, newEncPub []byte, clientOf func([]byte, string, string) string) {
	t.Helper()
	v.InviteMember, v.InviteAccount, v.InviteEmail, v.InviteID = "m_ann", "acct_ann", "ann@firm.example", "i_0123456789abcdef"
	secret := seq(0xd1)
	v.InviteSecret = hex.EncodeToString(secret)
	commit, err := InviteCommit(v.Team, v.InviteMember, v.InviteID, secret)
	if err != nil {
		t.Fatal(err)
	}
	list, err := SignTeamList(owner, TeamList{Aud: v.Audience, Team: v.Team, Seq: 1, Iat: 1798761600,
		Members: []ListMember{
			{ID: v.InviteMember, Email: v.InviteEmail, Role: RoleReviewer, Workers: []string{allWorkers}, Invite: &ListInvite{ID: v.InviteID, Commit: commit, Exp: 1798848000}},
			{ID: v.Member, Account: v.Team, Role: RoleAdmin, Devices: []string{ownerIncl}},
		},
		Workers: []ListWorker{}})
	if err != nil {
		t.Fatal(err)
	}
	payload, _, _ := splitToken(list)
	first := TeamEntry{Seq: 1, List: list, Hash: entryHash(TeamListContext, payload)}
	newPub := newKey.Public().(ed25519.PublicKey)
	msg, _ := lengthPrefixed(InvitePasskeyContext, []byte(v.Audience), []byte(v.Team), []byte(v.InviteMember), []byte(v.InviteID), newPub, newEncPub)
	v.InviteChallengeMsg = hex.EncodeToString(msg)
	challenge, _ := InvitePasskeyChallenge(v.Audience, v.Team, v.InviteMember, v.InviteID, newPub, newEncPub)
	v.InviteChallenge = hex.EncodeToString(challenge)
	newIncl, err := SignTeamInclusion(newKey, newEncPub, TeamInclusion{Aud: v.Audience, Team: v.Team, Acct: v.InviteAccount, Seq: 2})
	if err != nil {
		t.Fatal(err)
	}
	pubOf := func(k *ecdsa.PrivateKey) string { b, _ := k.PublicKey.Bytes(); return b64.EncodeToString(b) }
	type accept struct {
		key       *ecdsa.PrivateKey
		rec       *ListRec
		challenge []byte
		client    string
		flags     byte
		count     uint32
		noSig     bool
	}
	sign := func(a accept) (string, string, string) {
		rp := sha256.Sum256([]byte(PasskeyRPID))
		auth := binary.BigEndian.AppendUint32(append(rp[:], a.flags), a.count)
		ch := sha256.Sum256([]byte(a.client))
		digest := sha256.Sum256(append(append([]byte{}, auth...), ch[:]...))
		sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		if a.noSig {
			sig = nil
		}
		return b64.EncodeToString(auth), b64.EncodeToString([]byte(a.client)), b64.EncodeToString(sig)
	}
	rec := &ListRec{Cred: v.PasskeyCred, Pub: v.PasskeyPub}
	inviteEntry := func(a *accept, device string) TeamEntry {
		p := InviteProof{Invite: v.InviteID, Secret: b64.EncodeToString(secret), Email: v.InviteEmail}
		if a != nil {
			p.Rec = a.rec
			if a.key != nil {
				p.AuthenticatorData, p.ClientDataJSON, p.Signature = sign(*a)
			}
		}
		proof, _ := json.Marshal(p)
		raw, _ := json.Marshal(TeamRecord{Kind: RecordInvite, Seq: 2, Prev: first.Hash, Member: v.InviteMember, Account: v.InviteAccount, Device: device, At: 1798762002, Proof: proof})
		return TeamEntry{Seq: 2, Record: raw, Hash: entryHash(TeamRecordContext, raw)}
	}
	good := accept{key: pk, rec: rec, challenge: challenge, client: clientOf(challenge, "https://fount.sh", ""), flags: 0x1d, count: 3}
	with := func(f func(*accept)) *accept {
		a := good
		f(&a)
		return &a
	}
	second := inviteEntry(&good, newIncl)

	thirdKey := ed25519.NewKeyFromSeed(seq(0xa1))
	thirdEnc := seq(0xb1)
	thirdIncl, err := SignTeamInclusion(thirdKey, thirdEnc, TeamInclusion{Aud: v.Audience, Team: v.Team, Acct: v.InviteAccount, Seq: 3})
	if err != nil {
		t.Fatal(err)
	}
	joinCh, _ := PasskeyJoinChallenge(v.Audience, v.Team, v.InviteMember, second.Hash, seq(0xc1), thirdKey.Public().(ed25519.PublicKey), thirdEnc)
	auth, client, sig := sign(accept{key: pk, client: clientOf(joinCh, "https://fount.sh", ""), flags: 0x1d, count: 4})
	jp, _ := json.Marshal(PasskeyJoinProof{Nonce: b64.EncodeToString(seq(0xc1)), Cred: v.PasskeyCred, AuthenticatorData: auth, ClientDataJSON: client, Signature: sig})
	raw, _ := json.Marshal(TeamRecord{Kind: RecordPasskeyJoin, Seq: 3, Prev: second.Hash, Member: v.InviteMember, Account: v.InviteAccount, Device: thirdIncl, At: 1798762003, Proof: jp})
	third := TeamEntry{Seq: 3, Record: raw, Hash: entryHash(TeamRecordContext, raw)}
	v.InviteLog = TeamLogView{Team: v.Team, Seq: 3, Head: third.Hash, Entries: []TeamEntry{first, second, third}}

	other := ed25519.NewKeyFromSeed(seq(0x71))
	otherIncl, err := SignTeamInclusion(other, seq(0x91), TeamInclusion{Aud: v.Audience, Team: v.Team, Acct: v.InviteAccount, Seq: 2})
	if err != nil {
		t.Fatal(err)
	}
	anotherInvite, _ := InvitePasskeyChallenge(v.Audience, v.Team, v.InviteMember, "i_fedcba9876543210", newPub, newEncPub)
	v.InviteRefused = map[string]TeamEntry{
		"another_device":        inviteEntry(&good, otherIncl),
		"another_invite":        inviteEntry(with(func(a *accept) { a.client = clientOf(anotherInvite, "https://fount.sh", "") }), newIncl),
		"unlisted_key":          inviteEntry(with(func(a *accept) { a.rec = &ListRec{Cred: v.PasskeyCred, Pub: pubOf(unlisted)} }), newIncl),
		"signed_by_unlisted":    inviteEntry(with(func(a *accept) { a.key = unlisted }), newIncl),
		"wrong_origin":          inviteEntry(with(func(a *accept) { a.client = clientOf(challenge, "https://evil.example", "") }), newIncl),
		"cross_origin":          inviteEntry(with(func(a *accept) { a.client = clientOf(challenge, "https://fount.sh", `,"crossOrigin":true`) }), newIncl),
		"not_verified":          inviteEntry(with(func(a *accept) { a.flags = 0x01 }), newIncl),
		"escaped":               inviteEntry(with(func(a *accept) { a.client = clientOf(challenge, "https://fount.sh", `,"x":"a\/b"`) }), newIncl),
		"no_signature":          inviteEntry(with(func(a *accept) { a.noSig = true }), newIncl),
		"assertion_without_rec": inviteEntry(with(func(a *accept) { a.rec = nil }), newIncl),
		"malformed_rec":         inviteEntry(with(func(a *accept) { a.rec = &ListRec{Cred: v.PasskeyCred, Pub: b64.EncodeToString([]byte{4, 1, 2})} }), newIncl),
		"no_passkey":            inviteEntry(nil, newIncl),
	}

	// Invited again: the owner's list at 4 reopens an invite on m_ann, now
	// bound to InviteAccount with two devices, and a fourth device takes it
	// with a new passkey.
	againSecret := seq(0xe1)
	againCommit, _ := InviteCommit(v.Team, v.InviteMember, "i_again0123456789", againSecret)
	again, err := SignTeamList(owner, TeamList{Aud: v.Audience, Team: v.Team, Seq: 4, Prev: third.Hash, Iat: 1798762004,
		Members: []ListMember{
			{ID: v.InviteMember, Account: v.InviteAccount, Email: v.InviteEmail, Role: RoleReviewer, Workers: []string{allWorkers}, Rec: rec,
				Devices: []string{newIncl, thirdIncl}, Invite: &ListInvite{ID: "i_again0123456789", Commit: againCommit, Exp: 1798848000}},
			{ID: v.Member, Account: v.Team, Role: RoleAdmin, Devices: []string{ownerIncl}},
		},
		Workers: []ListWorker{}})
	if err != nil {
		t.Fatal(err)
	}
	againPayload, _, _ := splitToken(again)
	v.InviteAgain = TeamEntry{Seq: 4, List: again, Hash: entryHash(TeamListContext, againPayload)}
	backKey := ed25519.NewKeyFromSeed(seq(0xf1))
	backEnc := seq(0x51)
	backIncl, err := SignTeamInclusion(backKey, backEnc, TeamInclusion{Aud: v.Audience, Team: v.Team, Acct: v.InviteAccount, Seq: 5})
	if err != nil {
		t.Fatal(err)
	}
	backPk, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), seq(0x61))
	if err != nil {
		t.Fatal(err)
	}
	backCh, _ := InvitePasskeyChallenge(v.Audience, v.Team, v.InviteMember, "i_again0123456789", backKey.Public().(ed25519.PublicKey), backEnc)
	backRec := &ListRec{Cred: b64.EncodeToString(seq(0x42)[:16]), Pub: pubOf(backPk)}
	bauth, bclient, bsig := sign(accept{key: backPk, client: clientOf(backCh, "https://fount.sh", ""), flags: 0x1d, count: 1})
	bp, _ := json.Marshal(InviteProof{Invite: "i_again0123456789", Secret: b64.EncodeToString(againSecret), Email: v.InviteEmail,
		InvitePasskey: InvitePasskey{Rec: backRec, AuthenticatorData: bauth, ClientDataJSON: bclient, Signature: bsig}})
	raw, _ = json.Marshal(TeamRecord{Kind: RecordInvite, Seq: 5, Prev: v.InviteAgain.Hash, Member: v.InviteMember, Account: v.InviteAccount, Device: backIncl, At: 1798762005, Proof: bp})
	v.InviteBack = TeamEntry{Seq: 5, Record: raw, Hash: entryHash(TeamRecordContext, raw)}
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

	// The invite's passkey.
	if v.InviteChallenge != made.InviteChallenge || v.InviteChallengeMsg != made.InviteChallengeMsg || v.InviteLog.Entries[0].Hash != made.InviteLog.Entries[0].Hash {
		t.Fatal("the invite vectors' deterministic values changed")
	}
	st, err = reduceTeam(v.Team, v.Audience, v.InviteLog.Entries)
	if err != nil {
		t.Fatalf("the invite vector log: %v", err)
	}
	if m := st.byID[v.InviteMember]; st.head != v.InviteLog.Head || m.Rec == nil || m.Rec.Pub != v.PasskeyPub || len(m.Devices) != 2 {
		t.Fatal("the invite vector log doesn't list the passkey and admit both devices")
	}
	if len(v.InviteRefused) == 0 {
		t.Fatal("no refused invite vectors")
	}
	for name, e := range v.InviteRefused {
		if _, err := reduceTeam(v.Team, v.Audience, []TeamEntry{v.InviteLog.Entries[0], e}); err == nil {
			t.Errorf("invite %s: replayed", name)
		}
	}
	if _, ok := v.InviteRefused["no_passkey"]; !ok {
		t.Fatal("no invite_refused no_passkey vector")
	}
	st, err = reduceTeam(v.Team, v.Audience, append(slices.Clone(v.InviteLog.Entries), v.InviteAgain, v.InviteBack))
	if err != nil {
		t.Fatalf("invite_back: %v", err)
	}
	m := st.byID[v.InviteMember]
	if len(m.Devices) != 1 || m.Rec == nil || m.Rec.Pub == v.PasskeyPub || len(st.byID[v.Member].Devices) != 1 || len(st.byDevice) != 2 {
		t.Fatal("invite_back doesn't leave the member only the new device and the new passkey")
	}
}
