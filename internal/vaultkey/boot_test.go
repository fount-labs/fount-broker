package vaultkey

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/fount-labs/fount-mail-vault/wire"

	"github.com/fount-labs/fount-broker/internal/coordinator"
	"github.com/fount-labs/fount-broker/internal/vaultkey/cloudvaulttest"
)

func TestFetchBootsAGenerationAndKeepsTheBucketCredentials(t *testing.T) {
	p := newPair(t)
	cloud := cloudvaulttest.Start(t)
	creds := &wire.S3Credentials{AccessKeyID: "AKIDVAULT", SecretAccessKey: "from-the-vault"}
	p.a.cloud, p.a.s3 = cloud, creds
	a := p.a.serve(t)
	src := p.source(a.URL)
	src.Authority, src.Boot = cloud.AuthorityKey(), true

	got, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Key != p.want(t) || got.S3 == nil || *got.S3 != *creds {
		t.Fatalf("fetched %+v", got)
	}
	g := got.Generation
	if g == nil || g.Number != 1 {
		t.Fatalf("generation %+v", g)
	}
	cert, err := wire.VerifyGenerationCertificate(g.Certificate, cloud.AuthorityKey())
	if err != nil || !ed25519.PublicKey(cert.CoordinatorKey).Equal(g.Key.Public()) {
		t.Fatalf("the certificate doesn't name this boot's key: %v", err)
	}

	// The counter takes this boot's key, and a second boot fences it.
	counter, err := NewCounter(cloud.Vaults(), cloud.AuthorityKey(), &coordinator.FixedGeneration{G: *g})
	if err != nil {
		t.Fatal(err)
	}
	if err := counter.CompareAndSwap(context.Background(), 1, 0, 1); err != nil {
		t.Fatal(err)
	}
	again, err := src.Fetch(context.Background())
	if err != nil || again.Generation.Number != 2 {
		t.Fatalf("a second boot: %+v %v", again, err)
	}
	if err := counter.CompareAndSwap(context.Background(), 1, 1, 2); !errors.Is(err, coordinator.ErrVaultGeneration) {
		t.Fatalf("generation 1 after generation 2: %v", err)
	}
	if st, err := counter.Load(context.Background()); err != nil || st != (coordinator.VaultCount{Generation: 2, Count: 1}) {
		t.Fatalf("after the second boot: %+v %v", st, err)
	}

	// A dry run's pull boots nothing.
	src.Boot = false
	dry, err := src.Fetch(context.Background())
	if err != nil || dry.Generation != nil || cloud.State().Generation != 2 {
		t.Fatalf("a pull without a boot: %+v %v, vault at %+v", dry, err, cloud.State())
	}
}

// A boot proves the coordinator holds its transfer key (fount-mail-vault
// review C1), and still boots at a vault from before the proof.
func TestFetchProvesTheTransferKey(t *testing.T) {
	for _, old := range []bool{false, true} {
		p := newPair(t)
		cloud := cloudvaulttest.Start(t)
		p.a.cloud, p.a.oldBoot = cloud, old
		src := p.source(p.a.serve(t).URL)
		src.Authority, src.Boot = cloud.AuthorityKey(), true
		if got, err := src.Fetch(context.Background()); err != nil || got.Generation == nil {
			t.Fatalf("a boot at a vault (old %t): %+v %v", old, got, err)
		}
	}
	// A coordinator whose document endorses a key it doesn't hold.
	p := newPair(t)
	p.a.cloud = cloudvaulttest.Start(t)
	src := p.source(p.a.serve(t).URL)
	src.Authority, src.Boot = p.a.cloud.AuthorityKey(), true
	src.Transfer = newKey(t)
	src.Attester = fakeAttester{p.coordinator}
	if _, err := src.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "refused at boot proof") {
		t.Fatalf("a boot without the transfer key: %v", err)
	}
}

func TestFetchRefusesACertificateNotUnderItsAuthority(t *testing.T) {
	p := newPair(t)
	p.a.cloud = cloudvaulttest.Start(t)
	a := p.a.serve(t)
	src := p.source(a.URL)
	other, _, _ := ed25519.GenerateKey(nil)
	src.Authority, src.Boot = other, true
	if _, err := src.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("a certificate under another authority: %v", err)
	}
	// A vault that isn't a Cloud vault refuses the boot.
	p.a.cloud = nil
	src.Authority = ed25519.PublicKey(make([]byte, 32))
	if _, err := src.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "refused at boot") {
		t.Fatalf("a boot at a mail vault: %v", err)
	}
	// Boot without an authority isn't a source.
	src.Authority = nil
	if _, err := src.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "authority") {
		t.Fatalf("a boot without an authority: %v", err)
	}
}
