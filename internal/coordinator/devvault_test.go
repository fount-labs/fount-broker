package coordinator

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/fount-labs/fount-broker/internal/mail"
)

func TestFileVaultKeepsTheCountAcrossGenerations(t *testing.T) {
	pub, authority, _ := ed25519.GenerateKey(nil)
	path := filepath.Join(t.TempDir(), "vault", "dev-vault.json")
	ctx := context.Background()
	a := &FileVault{Path: path, Authority: authority}
	g1, err := a.Boot()
	if err != nil {
		t.Fatal(err)
	}
	if g1.G.Number != 1 {
		t.Fatalf("first generation %d", g1.G.Number)
	}
	cert, err := mail.ReadGenerationCertificate(g1.G.Certificate, pub)
	if err != nil || cert.Generation != 1 || !ed25519.PublicKey(cert.CoordinatorKey).Equal(g1.G.Key.Public()) {
		t.Fatalf("certificate %+v, %v", cert, err)
	}
	if err := a.CompareAndSwap(ctx, 1, 0, 3); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ gen, prev, next uint64 }{{1, 2, 4}, {1, 3, 3}, {1, 3, 2}} {
		if err := a.CompareAndSwap(ctx, c.gen, c.prev, c.next); !errors.Is(err, ErrVaultCount) {
			t.Errorf("CompareAndSwap%v = %v, want ErrVaultCount", c, err)
		}
	}

	// Another process on the same file: a new generation, the same count.
	b := &FileVault{Path: path, Authority: authority}
	g2, err := b.Boot()
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := b.Load(ctx); got != (VaultCount{Generation: 2, Count: 3}) || g2.G.Number != 2 {
		t.Fatalf("after the second boot: %+v, generation %d", got, g2.G.Number)
	}
	if err := a.CompareAndSwap(ctx, 1, 3, 4); !errors.Is(err, ErrVaultGeneration) {
		t.Fatalf("the old generation's swap = %v, want ErrVaultGeneration", err)
	}
	if err := b.CompareAndSwap(ctx, 2, 3, 4); err != nil {
		t.Fatal(err)
	}
	if got, _ := a.Load(ctx); got.Count != 4 {
		t.Fatalf("the first process reads %+v", got)
	}

	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Load(ctx); err == nil {
		t.Fatal("a corrupt vault file loaded")
	}
}
