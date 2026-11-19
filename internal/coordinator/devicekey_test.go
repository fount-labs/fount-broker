package coordinator

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/cryptotest"
	"time"
)

func TestAWrapOpensOnlyForItsDeviceWorkerAndDEK(t *testing.T) {
	me, other := newTestDevice(t), newTestDevice(t)
	dek := mustDEK(t)
	const worker = "w_0123456789abcdef01234567"
	wrap := me.wrap(t, "acme", worker, dek)
	commitment := DEKCommitment(worker, dek)
	if len(wrap) != WrapSize {
		t.Fatalf("a wrap of %d bytes", len(wrap))
	}
	if got, err := OpenWrap(me.enc.Bytes(), "acme", worker, me.id(), commitment, wrap); err != nil || got != dek {
		t.Fatalf("open: %v", err)
	}
	if again := me.wrap(t, "acme", worker, dek); bytes.Equal(again, wrap) {
		t.Error("two wraps are the same bytes")
	}
	tampered := bytes.Clone(wrap)
	tampered[len(tampered)-1] ^= 1
	otherDEK := mustDEK(t)
	for _, tc := range []struct {
		name                         string
		priv                         []byte
		account, worker, dev, commit string
		wrap                         []byte
	}{
		{"another device's key", other.enc.Bytes(), "acme", worker, me.id(), commitment, wrap},
		{"another account", me.enc.Bytes(), "other", worker, me.id(), commitment, wrap},
		{"another worker", me.enc.Bytes(), "acme", "w_0123456789abcdef01234568", me.id(), commitment, wrap},
		{"another device id", me.enc.Bytes(), "acme", worker, other.id(), commitment, wrap},
		{"another commitment", me.enc.Bytes(), "acme", worker, me.id(), DEKCommitment(worker, otherDEK), wrap},
		{"tampered", me.enc.Bytes(), "acme", worker, me.id(), commitment, tampered},
		{"short", me.enc.Bytes(), "acme", worker, me.id(), commitment, wrap[:WrapSize-1]},
	} {
		if _, err := OpenWrap(tc.priv, tc.account, tc.worker, tc.dev, tc.commit, tc.wrap); err == nil {
			t.Errorf("%s opened", tc.name)
		}
	}
	// A wrap made with the right AAD but of another DEK than the commitment.
	if _, err := OpenWrap(me.enc.Bytes(), "acme", worker, me.id(), commitment, sealAs(t, me, "acme", worker, commitment, otherDEK)); err == nil {
		t.Error("a wrap of another DEK than its commitment opened")
	}
}

// sealAs seals dek under the AAD of commitment, which needn't be dek's.
func sealAs(t *testing.T, d testDevice, account, workerID, commitment string, dek DEK) []byte {
	t.Helper()
	aad, _ := wrapAAD(account, workerID, d.id(), commitment)
	pk, _ := wrapSuite.kem.NewPublicKey(d.enc.PublicKey().Bytes())
	enc, s, err := hpkeSender(pk)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := s.Seal(aad, dek[:])
	if err != nil {
		t.Fatal(err)
	}
	return append(enc, ct...)
}

// teamVectors is testdata/team-vectors.json, for Desktop's Rust port: fixed
// keys, the team inclusion and list they sign (Ed25519 is deterministic, so
// the tokens are too), the list's hash, and a wrap to open. HPKE's ephemeral
// key is random, so a port's own wraps are checked by opening them, not by
// their bytes.
type teamVectors struct {
	Comment        string `json:"comment"`
	Ed25519Seed    string `json:"ed25519_seed"`
	Ed25519Public  string `json:"ed25519_public"`
	X25519Private  string `json:"x25519_private"`
	X25519Public   string `json:"x25519_public"`
	Device         string `json:"device"`
	Audience       string `json:"audience"`
	Team           string `json:"team"`
	Account        string `json:"account"`
	Worker         string `json:"worker"`
	DEK            string `json:"dek"`
	DEKCommitment  string `json:"dek_commitment"`
	InclusionClaim string `json:"inclusion_claims"`
	Inclusion      string `json:"inclusion"`
	ListClaims     string `json:"list_claims"`
	List           string `json:"list"`
	ListHash       string `json:"list_hash"`
	WrapInfo       string `json:"wrap_info"`
	WrapAAD        string `json:"wrap_aad"`
	Wrap           string `json:"wrap"`
}

const teamVectorsPath = "testdata/team-vectors.json"

func seq(from byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = from + byte(i)
	}
	return b
}

// makeTeamVectors makes the vectors from fixed keys, all but the wrap, whose
// ephemeral key comes from a seeded cryptotest source.
func makeTeamVectors(t *testing.T) teamVectors {
	t.Helper()
	cryptotest.SetGlobalRandom(t, 1)
	key := ed25519.NewKeyFromSeed(seq(0x01))
	enc, err := ecdh.X25519().NewPrivateKey(seq(0x21))
	if err != nil {
		t.Fatal(err)
	}
	var dek DEK
	copy(dek[:], seq(0x41))
	v := teamVectors{
		Comment:     "Team inclusion, team list and DEK wrap vectors (internal/coordinator/teamlist.go, devicekey.go). Bytes are hex. Test keys only. Rewrite: TEAM_VECTORS_WRITE=1 go test -run TestTeamVectors ./internal/coordinator",
		Ed25519Seed: hex.EncodeToString(seq(0x01)), Ed25519Public: hex.EncodeToString(key.Public().(ed25519.PublicKey)),
		X25519Private: hex.EncodeToString(enc.Bytes()), X25519Public: hex.EncodeToString(enc.PublicKey().Bytes()),
		Device: deviceID(key.Public().(ed25519.PublicKey)), Audience: "https://coordinator.example", Team: "acct_vectors", Account: "acct_vectors", Worker: "w_0123456789abcdef01234567",
		DEK: hex.EncodeToString(dek[:]), WrapInfo: WrapInfo,
	}
	v.DEKCommitment = DEKCommitment(v.Worker, dek)
	if v.Inclusion, err = SignTeamInclusion(key, enc.PublicKey().Bytes(), TeamInclusion{Aud: v.Audience, Team: v.Team, Acct: v.Account, Seq: 1}); err != nil {
		t.Fatal(err)
	}
	v.InclusionClaim = claimsOf(v.Inclusion)
	if v.List, err = SignTeamList(key, TeamList{Aud: v.Audience, Team: v.Team, Seq: 1, Iat: 1798761600,
		Members: []ListMember{{ID: "m_owner", Account: v.Account, Email: "owner@example.com", Role: RoleAdmin, Devices: []string{v.Inclusion}}},
		Workers: []ListWorker{{ID: v.Worker, DEK: v.DEKCommitment}}}); err != nil {
		t.Fatal(err)
	}
	v.ListClaims = claimsOf(v.List)
	v.ListHash = entryHash(TeamListContext, []byte(v.ListClaims))
	aad, _ := wrapAAD(v.Team, v.Worker, v.Device, v.DEKCommitment)
	v.WrapAAD = hex.EncodeToString(aad)
	wrap, err := SealWrap(enc.PublicKey().Bytes(), v.Team, v.Worker, v.Device, dek)
	if err != nil {
		t.Fatal(err)
	}
	v.Wrap = hex.EncodeToString(wrap)
	return v
}

func claimsOf(token string) string {
	claims, _ := b64.DecodeString(token[:strings.IndexByte(token, '.')])
	return string(claims)
}

func TestTeamVectors(t *testing.T) {
	made := makeTeamVectors(t)
	if os.Getenv("TEAM_VECTORS_WRITE") != "" {
		out, _ := json.MarshalIndent(made, "", "  ")
		os.MkdirAll(filepath.Dir(teamVectorsPath), 0o755)
		if err := os.WriteFile(teamVectorsPath, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(teamVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var v teamVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	// Everything but the wrap is deterministic, so it must match.
	made.Wrap, made.Comment = v.Wrap, v.Comment
	if made != v {
		t.Fatalf("the vectors changed:\n%+v\nwant\n%+v", made, v)
	}
	priv, _ := hex.DecodeString(v.X25519Private)
	wrap, _ := hex.DecodeString(v.Wrap)
	dek, err := OpenWrap(priv, v.Team, v.Worker, v.Device, v.DEKCommitment, wrap)
	if err != nil || hex.EncodeToString(dek[:]) != v.DEK {
		t.Fatalf("the vector wrap: %v", err)
	}
	if _, err := parseTeamInclusion(v.Inclusion, v.Audience, v.Team, v.Account); err != nil {
		t.Fatalf("the vector inclusion: %v", err)
	}
	pub, _ := hex.DecodeString(v.Ed25519Public)
	caller := Caller{Account: v.Account, Device: v.Device, DeviceKey: pub}
	if _, _, err := parseTeamListToken(v.List, v.Audience, caller, v.Team, time.Unix(1798761600, 0)); err != nil {
		t.Fatalf("the vector list: %v", err)
	}
}

func TestALowOrderX25519KeyIsRefused(t *testing.T) {
	c, _ := newTestCoordinator(t, "ok", 0)
	me, other := newTestDevice(t), newTestDevice(t)
	tt := soloTeam(t, c, "acme", me)
	for _, point := range []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000000",
		"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
		"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"0000000000000000000000000000000000000000000000000000000000000080",
	} {
		enc, _ := hex.DecodeString(point)
		if err := checkX25519(enc); err == nil {
			t.Errorf("%s passed", point)
		}
		l := tt.list()
		bad, err := signToken(other.key, TeamInclusionContext, TeamInclusion{V: TeamInclusionVersion, Typ: TeamInclusionType, Aud: testAudience, Team: "acme", Acct: "other",
			Dev: other.id(), Key: other.b64(), Enc: b64.EncodeToString(enc), Seq: l.Seq})
		if err != nil {
			t.Fatal(err)
		}
		l.Members = append(l.Members, ListMember{ID: "m_reviewer", Account: "other", Role: RoleReviewer, Workers: []string{allWorkers}, Devices: []string{bad}})
		if err := tt.pushList(me.caller("acme"), me.sign(t, l), l, nil); !errors.Is(err, ErrListRefused) || !strings.Contains(err.Error(), "low-order") {
			t.Errorf("%s: %v", point, err)
		}
	}
	if err := checkX25519(other.enc.PublicKey().Bytes()); err != nil {
		t.Errorf("a real key: %v", err)
	}
	tt.set("m_reviewer", "other", RoleReviewer, other)
	if err := tt.push(me, "acme", nil); err != nil {
		t.Errorf("the list with real keys: %v", err)
	}
}
