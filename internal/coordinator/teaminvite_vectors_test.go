package coordinator

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// teamInviteVectors is testdata/team-invite-vectors.json, for Desktop's Rust
// port of the formats this lane added: an invite's commit and code, a list
// with a team name and an open invite, a join's message, code and approval,
// and a signed draft approval. Ed25519 is deterministic, so every value is.
type teamInviteVectors struct {
	Comment  string `json:"comment"`
	Audience string `json:"audience"`
	Team     string `json:"team"`
	// The admin (and, for the join, the approving device) and the new device.
	AdminSeed     string `json:"admin_ed25519_seed"`
	AdminDevice   string `json:"admin_device"`
	NewSeed       string `json:"new_ed25519_seed"`
	NewX25519     string `json:"new_x25519_private"`
	NewKey        string `json:"new_ed25519_public"`
	NewEnc        string `json:"new_x25519_public"`
	NewDevice     string `json:"new_device"`
	Member        string `json:"member"`
	Email         string `json:"email"`
	Invite        string `json:"invite"`
	InviteSecret  string `json:"invite_secret"`
	InviteCommit  string `json:"invite_commit"`
	InviteCode    string `json:"invite_code"`
	InviteMessage string `json:"invite_commit_message"`
	ListClaims    string `json:"list_claims"`
	List          string `json:"list"`
	InviteProof   string `json:"invite_proof"`
	Join          string `json:"join"`
	JoinNonce     string `json:"join_nonce"`
	JoinMessage   string `json:"join_message"`
	JoinCode      string `json:"join_code"`
	JoinSig       string `json:"join_sig"`
	JoinProof     string `json:"join_proof"`
	// The approval is signed by the admin's device.
	ApprovalClaims string `json:"approval_claims"`
	Approval       string `json:"approval"`
}

const teamInviteVectorsPath = "testdata/team-invite-vectors.json"

func makeTeamInviteVectors(t *testing.T) teamInviteVectors {
	t.Helper()
	admin := ed25519.NewKeyFromSeed(seq(0x01))
	newKey := ed25519.NewKeyFromSeed(seq(0x61))
	newEnc, err := ecdh.X25519().NewPrivateKey(seq(0x81))
	if err != nil {
		t.Fatal(err)
	}
	v := teamInviteVectors{
		Comment:  "Invite, join and draft-approval vectors (internal/coordinator/teaminvite.go, teamjoin.go, approvalsig.go). Bytes are hex unless named base64url. Test keys only. Rewrite: TEAM_INVITE_VECTORS_WRITE=1 go test -run TestTeamInviteVectors ./internal/coordinator",
		Audience: "https://coordinator.example", Team: "acct_vectors",
		AdminSeed: hex.EncodeToString(seq(0x01)), AdminDevice: deviceID(admin.Public().(ed25519.PublicKey)),
		NewSeed: hex.EncodeToString(seq(0x61)), NewX25519: hex.EncodeToString(newEnc.Bytes()),
		NewKey: hex.EncodeToString(newKey.Public().(ed25519.PublicKey)), NewEnc: hex.EncodeToString(newEnc.PublicKey().Bytes()),
		NewDevice: deviceID(newKey.Public().(ed25519.PublicKey)),
		Member:    "m_ann", Email: "ann@firm.example", Invite: "i_0123456789abcdef",
		InviteSecret: hex.EncodeToString(seq(0xa1)), Join: "jn_0123456789abcdef01234567", JoinNonce: hex.EncodeToString(seq(0xc1)),
	}
	secret := seq(0xa1)
	if v.InviteCommit, err = InviteCommit(v.Team, v.Member, v.Invite, secret); err != nil {
		t.Fatal(err)
	}
	msg, _ := lengthPrefixed(InviteCommitContext, []byte(v.Team), []byte(v.Member), []byte(v.Invite), secret)
	v.InviteMessage = hex.EncodeToString(msg)
	v.InviteCode = InviteCode(v.Team, v.Member, v.Invite, secret)
	adminIncl, err := SignTeamInclusion(admin, seq(0x21), TeamInclusion{Aud: v.Audience, Team: v.Team, Acct: v.Team, Seq: 1})
	if err != nil {
		t.Fatal(err)
	}
	if v.List, err = SignTeamList(admin, TeamList{Aud: v.Audience, Team: v.Team, Name: "Acme & Co — Tax", Seq: 1, Iat: 1798761600,
		Members: []ListMember{
			{ID: v.Member, Email: v.Email, Role: RoleReviewer, Workers: []string{allWorkers}, Invite: &ListInvite{ID: v.Invite, Commit: v.InviteCommit, Exp: 1798848000}},
			{ID: "m_owner", Account: v.Team, Email: "owner@firm.example", Role: RoleAdmin, Devices: []string{adminIncl}},
		},
		Workers: []ListWorker{}}); err != nil {
		t.Fatal(err)
	}
	v.ListClaims = claimsOf(v.List)
	p, _ := json.Marshal(InviteProof{Invite: v.Invite, Secret: b64.EncodeToString(secret), Email: v.Email})
	v.InviteProof = string(p)
	nonce := seq(0xc1)
	newPub, newEncPub := newKey.Public().(ed25519.PublicKey), newEnc.PublicKey().Bytes()
	jm, err := JoinMessage(v.Audience, v.Team, v.Member, v.Join, nonce, newPub, newEncPub)
	if err != nil {
		t.Fatal(err)
	}
	v.JoinMessage = hex.EncodeToString(jm)
	v.JoinCode = JoinCode(v.Join, nonce, newPub, newEncPub)
	sig := ed25519.Sign(admin, jm)
	v.JoinSig = hex.EncodeToString(sig)
	jp, _ := json.Marshal(JoinProof{Join: v.Join, Nonce: b64.EncodeToString(nonce), Approver: v.AdminDevice, Sig: b64.EncodeToString(sig)})
	v.JoinProof = string(jp)
	if v.Approval, err = SignApproval(admin, ApprovalClaims{Aud: v.Audience, Worker: "w_0123456789abcdef01234567", Thread: "thr_0123456789abcdef01234567",
		Draft: "e_0123456789abcdef", DraftRev: 2, To: []string{"dana@client.example", "lee@client.example"}, Subject: "Re: Q3 close",
		Text: sha256Hex([]byte("Hi Dana,\n\nThe Q3 close is attached.\n")), Files: []ApprovedFile{{Path: "out/q3.xlsx", SHA256: sha256Hex([]byte("q3"))}}, Iat: 1798761600}); err != nil {
		t.Fatal(err)
	}
	v.ApprovalClaims = claimsOf(v.Approval)
	return v
}

func TestTeamInviteVectors(t *testing.T) {
	made := makeTeamInviteVectors(t)
	if os.Getenv("TEAM_INVITE_VECTORS_WRITE") != "" {
		out, _ := json.MarshalIndent(made, "", "  ")
		if err := os.WriteFile(teamInviteVectorsPath, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(teamInviteVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var v teamInviteVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if made != v {
		t.Fatalf("the vectors changed:\n%+v\nwant\n%+v", made, v)
	}
	// What each is checked by.
	pub, _ := hex.DecodeString(v.NewKey)
	adminPub := ed25519.NewKeyFromSeed(seq(0x01)).Public().(ed25519.PublicKey)
	l, _, err := parseTeamListToken(v.List, v.Audience, Caller{Account: v.Team, Device: v.AdminDevice, DeviceKey: adminPub}, v.Team, time.Unix(1798761600, 0))
	if err != nil || l.Name != "Acme & Co — Tax" {
		t.Fatalf("the vector list: %v", err)
	}
	jm, _ := hex.DecodeString(v.JoinMessage)
	sig, _ := hex.DecodeString(v.JoinSig)
	if !ed25519.Verify(adminPub, jm, sig) || len(pub) != 32 {
		t.Fatal("the join signature")
	}
	want := approvedAs{worker: "w_0123456789abcdef01234567", thread: "thr_0123456789abcdef01234567", draft: "e_0123456789abcdef", draftRev: 2,
		to: []string{"Lee@client.example", "dana@client.example"}, subject: "Re: Q3 close", text: sha256Hex([]byte("Hi Dana,\n\nThe Q3 close is attached.\n")),
		files: []ApprovedFile{{Path: "out/q3.xlsx", SHA256: sha256Hex([]byte("q3"))}}}
	if err := verifyApproval(v.Approval, adminPub, v.AdminDevice, v.Audience, want, time.Unix(1798761600, 0)); err != nil {
		t.Fatalf("the vector approval: %v", err)
	}
	want.text = sha256Hex([]byte("edited"))
	if err := verifyApproval(v.Approval, adminPub, v.AdminDevice, v.Audience, want, time.Unix(1798761600, 0)); err == nil {
		t.Fatal("an approval verified for other text")
	}
}
