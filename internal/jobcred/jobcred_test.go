package jobcred

import (
	"crypto/ed25519"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func minter(t *testing.T) *Minter {
	t.Helper()
	key, secret, err := DevKeys(filepath.Join(t.TempDir(), "job-signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	return &Minter{Key: key, CacheSecret: secret, Lifetime: 35 * time.Minute, Now: func() time.Time { return time.Unix(1_800_000_000, 0) }}
}

func TestAJobCredentialNamesOneJobAndExpires(t *testing.T) {
	m := minter(t)
	creds, err := m.Mint("acct_1", "w_1", "j_1")
	if err != nil {
		t.Fatal(err)
	}
	pub := m.Key.Public().(ed25519.PublicKey)
	c, err := Verify(creds["license"], pub, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if c.Acct != "acct_1" || c.Worker != "w_1" || c.Job != "j_1" || c.Exp-c.Iat != 35*60 {
		t.Errorf("claims %+v", c)
	}
	if _, err := Verify(creds["license"], pub, time.Unix(1_800_000_000+35*60, 0)); err == nil || err.Error() != "expired" {
		t.Errorf("expired credential: %v", err)
	}
	other, _, _ := DevKeys(filepath.Join(t.TempDir(), "other.key"))
	if _, err := Verify(creds["license"], other.Public().(ed25519.PublicKey), time.Unix(1_800_000_000, 0)); err == nil {
		t.Error("another coordinator's key verified it")
	}
	// A changed claim breaks the signature.
	payload, sig, _ := strings.Cut(creds["license"], ".")
	if _, err := Verify(encode([]byte(strings.Replace(decode(t, payload), "acct_1", "acct_2", 1)))+"."+sig, pub, time.Unix(1_800_000_000, 0)); err == nil {
		t.Error("a forged account verified")
	}
}

func TestTheCacheSecretIsPerAccount(t *testing.T) {
	m := minter(t)
	a1, _ := m.Mint("acct_1", "w_1", "j_1")
	a1again, _ := m.Mint("acct_1", "w_2", "j_2")
	a2, _ := m.Mint("acct_2", "w_3", "j_3")
	if a1["tinfoil_cache_secret"] != a1again["tinfoil_cache_secret"] || a1["tinfoil_cache_secret"] == a2["tinfoil_cache_secret"] {
		t.Errorf("cache secrets %q %q %q", a1["tinfoil_cache_secret"], a1again["tinfoil_cache_secret"], a2["tinfoil_cache_secret"])
	}
	if len(a1["tinfoil_cache_secret"]) != 64 {
		t.Errorf("cache secret %q isn't 256 bits of hex", a1["tinfoil_cache_secret"])
	}
}

func TestMintRefusesLongOrUnscopedCredentials(t *testing.T) {
	m := minter(t)
	if _, err := m.Mint("acct_1", "", "j_1"); err == nil {
		t.Error("minted without a worker")
	}
	m.Lifetime = MaxLifetime + time.Second
	if _, err := m.Mint("acct_1", "w_1", "j_1"); err == nil {
		t.Error("minted past the longest lifetime")
	}
}

func TestDevKeysAreKept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k")
	k1, s1, _ := DevKeys(path)
	k2, s2, _ := DevKeys(path)
	if !k1.Equal(k2) || string(s1) != string(s2) {
		t.Error("the dev keys changed between reads")
	}
}

func decode(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The vector fount-infra's proxy-server/job-auth.test.ts verifies, so the two
// sides can't drift apart.
func TestTheProxysVector(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	key := ed25519.NewKeyFromSeed(seed)
	m := &Minter{Key: key, CacheSecret: make([]byte, 32), Lifetime: 35 * time.Minute, Now: func() time.Time { return time.Unix(1_800_000_000, 0) }}
	creds, err := m.Mint("acct_1", "w_1", "j_1")
	if err != nil {
		t.Fatal(err)
	}
	const (
		public = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
		token  = "eyJ2IjoxLCJ0eXAiOiJmb3VudC1qb2IiLCJhY2N0IjoiYWNjdF8xIiwid2tyIjoid18xIiwiam9iIjoial8xIiwiaWF0IjoxODAwMDAwMDAwLCJleHAiOjE4MDAwMDIxMDAsImtpZCI6IkE2RUh2X1BPRUw0ZGNOMFk1MHZBbVdmazFqQ2JwUTFmSGR5R1pCSlZNYmcifQ.NYx62Q2FCMwMnnfbx50c2GC-ZAdtatgSyq7ZsrHIoAX7i2V9RKQBPHQ842_uHhEyKYGferri4845N_bzJoCXCQ"
	)
	if PublicKey(key) != public || creds["license"] != token {
		t.Errorf("the vector changed: update job-auth.test.ts too\n%s\n%s", PublicKey(key), creds["license"])
	}
}
