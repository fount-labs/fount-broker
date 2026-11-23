package coordinator

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// recoveryVectors is testdata/team-recovery-vectors.json, for Desktop's Rust
// copy of RecoveryChallenge and its check of a recovery-start's signature
// (account/team_log.rs). Ed25519 is deterministic, so the file is the same
// every run.
type recoveryVectors struct {
	Comment    string `json:"comment"`
	Audience   string `json:"audience"`
	Team       string `json:"team"`
	Member     string `json:"member"`
	Prev       string `json:"prev"`
	DeviceSeed string `json:"device_seed"`
	Device     string `json:"device"`
	Message    string `json:"message"`
	// Proof is the record's proof, as the coordinator writes it.
	Proof string `json:"proof"`
}

const recoveryVectorsPath = "testdata/team-recovery-vectors.json"

func makeRecoveryVectors(t *testing.T) recoveryVectors {
	t.Helper()
	key := ed25519.NewKeyFromSeed(seq(0x07))
	v := recoveryVectors{
		Comment:  "A recovery-start's signature (internal/coordinator/teamrecovery.go). Bytes are hex unless named base64url. Test keys only. Rewrite: RECOVERY_VECTORS_WRITE=1 go test -run TestRecoveryVectors ./internal/coordinator",
		Audience: "https://coordinator.example", Team: "tm_0123456789abcdef01234567", Member: "m_owner",
		Prev: b64.EncodeToString(seq(0x90)), DeviceSeed: hex.EncodeToString(seq(0x07)), Device: deviceID(key.Public().(ed25519.PublicKey)),
	}
	msg, err := RecoveryChallenge(v.Audience, v.Team, v.Member, v.Prev, v.Device)
	if err != nil {
		t.Fatal(err)
	}
	v.Message = hex.EncodeToString(msg)
	proof, _ := json.Marshal(RecoveryProof{Device: v.Device, Sig: b64.EncodeToString(ed25519.Sign(key, msg))})
	v.Proof = string(proof)
	return v
}

func TestRecoveryVectors(t *testing.T) {
	got, _ := json.MarshalIndent(makeRecoveryVectors(t), "", "  ")
	got = append(got, '\n')
	if os.Getenv("RECOVERY_VECTORS_WRITE") != "" {
		if err := os.WriteFile(recoveryVectorsPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(recoveryVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("the recovery vectors changed: Desktop's copy must change with them")
	}
}
