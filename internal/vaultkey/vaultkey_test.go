package vaultkey

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-vault/wire"

	"github.com/fount-labs/fount-broker/internal/coordinator"
	"github.com/fount-labs/fount-broker/internal/vaultkey/cloudvaulttest"
)

// fakeDoc stands in for an attestation document: the nonce it answers and the
// key it endorses, in the clear. Hardware is the only thing it leaves out.
type fakeDoc struct {
	Nonce string `json:"nonce"`
	Key   []byte `json:"key"`
}

type fakeAttester struct{ key *ecdh.PrivateKey }

func (a fakeAttester) Attest(_ context.Context, nonce []byte) ([]byte, error) {
	return json.Marshal(fakeDoc{Nonce: hex.EncodeToString(nonce), Key: a.key.PublicKey().Bytes()})
}

// fakeCheck accepts documents for the right nonce that endorse a trusted key:
// the stand-in for "a release of this repo".
func fakeCheck(trusted ...*ecdh.PublicKey) wire.HolderCheck {
	return func(doc, nonce []byte) (*ecdh.PublicKey, error) {
		var d fakeDoc
		if err := json.Unmarshal(doc, &d); err != nil {
			return nil, err
		}
		if d.Nonce != hex.EncodeToString(nonce) {
			return nil, errors.New("the document answers another nonce")
		}
		key, err := wire.ParseRawKey(d.Key)
		if err != nil {
			return nil, err
		}
		for _, t := range trusted {
			if t.Equal(key) {
				return key, nil
			}
		}
		return nil, errors.New("not a release of the pinned repo")
	}
}

func newKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// fakeVault speaks the mail vault's side of the pull, with wire's own box.
type fakeVault struct {
	key    *ecdh.PrivateKey
	keyset *wire.Keyset
	// trusts checks the requester's document, as a vault checks EDGE_REPO.
	trusts wire.HolderCheck
	// sealWith, when set, seals with another key than the one the document
	// endorses.
	sealWith *ecdh.PrivateKey
	// cloud, when set, boots generations as a Cloud vault does; s3 rides in
	// the payload.
	cloud *cloudvaulttest.Pair
	s3    *wire.S3Credentials

	mu     sync.Mutex
	nonces map[string]bool
	pulls  atomic.Int32
}

func (v *fakeVault) serve(t *testing.T) *httptest.Server {
	t.Helper()
	v.nonces = map[string]bool{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /transfer/begin", func(w http.ResponseWriter, _ *http.Request) {
		n, _ := wire.RandomNonce()
		v.mu.Lock()
		v.nonces[hex.EncodeToString(n)] = true
		v.mu.Unlock()
		json.NewEncoder(w).Encode(wire.BeginResponse{Nonce: hex.EncodeToString(n)})
	})
	mux.HandleFunc("POST /transfer/finish", func(w http.ResponseWriter, r *http.Request) {
		v.pulls.Add(1)
		var req wire.FinishRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		v.mu.Lock()
		ok := v.nonces[req.Nonce]
		delete(v.nonces, req.Nonce)
		v.mu.Unlock()
		issued, _ := wire.DecodeNonce(req.Nonce)
		answer, err := wire.DecodeNonce(req.AnswerNonce)
		if !ok || err != nil {
			http.Error(w, "bad nonce", http.StatusForbidden)
			return
		}
		attested := issued
		if len(req.CoordinatorKey) > 0 {
			attested = wire.BootNonce(issued, req.CoordinatorKey)
		}
		requester, err := v.trusts(req.Document, attested)
		if err != nil {
			http.Error(w, "refused at verify: "+err.Error(), http.StatusForbidden)
			return
		}
		p := wire.Payload{Keyset: v.keyset.MarshalBinary(), S3: v.s3}
		if len(req.CoordinatorKey) > 0 {
			if v.cloud == nil {
				http.Error(w, "refused at boot: not a Cloud vault", http.StatusForbidden)
				return
			}
			if p.GenerationCertificate, _, err = v.cloud.Boot(req.CoordinatorKey); err != nil {
				http.Error(w, "booting a generation: "+err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
		payload, _ := json.Marshal(p)
		sealer := v.key
		if v.sealWith != nil {
			sealer = v.sealWith
		}
		nonces := wire.Nonces{Issued: issued, Answer: answer}
		sealed, err := wire.Seal(wire.PurposeKeyset, sealer, requester, nonces, payload)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		doc, _ := fakeAttester{v.key}.Attest(r.Context(), answer)
		json.NewEncoder(w).Encode(wire.FinishResponse{Document: doc, HolderKey: sealer.PublicKey().Bytes(), Sealed: sealed})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

type pair struct {
	keyset      *wire.Keyset
	a, b        *fakeVault
	coordinator *ecdh.PrivateKey
}

func newPair(t *testing.T) *pair {
	t.Helper()
	ks, err := wire.Generate()
	if err != nil {
		t.Fatal(err)
	}
	p := &pair{keyset: ks, coordinator: newKey(t)}
	trusts := fakeCheck(p.coordinator.PublicKey())
	p.a = &fakeVault{key: newKey(t), keyset: ks, trusts: trusts}
	p.b = &fakeVault{key: newKey(t), keyset: ks, trusts: trusts}
	return p
}

func (p *pair) source(vaults ...string) *Source {
	return &Source{
		Vaults:     vaults,
		Commitment: p.keyset.Commitment(),
		Transfer:   p.coordinator,
		Attester:   fakeAttester{p.coordinator},
		Check:      fakeCheck(p.a.key.PublicKey(), p.b.key.PublicKey()),
		Client:     &http.Client{Timeout: 5 * time.Second},
	}
}

// want is the key Derive makes from the pair's keyset, from a copy, since
// Derive clears what it reads.
func (p *pair) want(t *testing.T) [32]byte {
	t.Helper()
	copied, err := wire.ParseKeyset(p.keyset.MarshalBinary())
	if err != nil {
		t.Fatal(err)
	}
	key, err := Derive(copied)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestFetchTakesTheCommittedKeyset(t *testing.T) {
	p := newPair(t)
	a := p.a.serve(t)
	got, err := p.source(a.URL).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Key != p.want(t) || got.Vault != a.URL || got.Commitment != p.keyset.Commitment() {
		t.Fatalf("got key %s from %s with %s", KeyID(&got.Key), got.Vault, got.Commitment)
	}
	if got.Key == p.keyset.AddressMACKey || got.Key == p.keyset.RoutingDataKey {
		t.Fatal("the wrapping key is one of the keyset's keys, not derived")
	}
}

func TestFetchFallsBackToTheOtherVault(t *testing.T) {
	p := newPair(t)
	down := p.a.serve(t)
	down.Close()
	b := p.b.serve(t)
	got, err := p.source(down.URL, b.URL).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Vault != b.URL || got.Key != p.want(t) {
		t.Fatalf("got the key from %s", got.Vault)
	}
}

func TestFetchRefuses(t *testing.T) {
	cases := map[string]func(t *testing.T, p *pair, s *Source){
		"another keyset than the commitment": func(t *testing.T, p *pair, _ *Source) {
			other, _ := wire.Generate()
			p.a.keyset = other
		},
		"a vault that isn't a release of the vault repo": func(t *testing.T, p *pair, s *Source) {
			s.Check = fakeCheck(p.b.key.PublicKey())
		},
		"a box sealed by another key than the attested one": func(t *testing.T, p *pair, _ *Source) {
			p.a.sealWith = newKey(t)
		},
		"a coordinator the vault doesn't trust": func(t *testing.T, p *pair, s *Source) {
			p.a.trusts = fakeCheck(newKey(t).PublicKey())
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			p := newPair(t)
			a := p.a.serve(t)
			s := p.source(a.URL)
			change(t, p, s)
			if got, err := s.Fetch(context.Background()); err == nil {
				t.Fatalf("took key %s", KeyID(&got.Key))
			}
		})
	}
}

func TestASourceNeedsEverythingThatAuthenticatesTheKey(t *testing.T) {
	p := newPair(t)
	for name, change := range map[string]func(s *Source){
		"no vaults":     func(s *Source) { s.Vaults = nil },
		"no check":      func(s *Source) { s.Check = nil },
		"no commitment": func(s *Source) { s.Commitment = "" },
		"bad commitment": func(s *Source) {
			s.Commitment = strings.ToUpper(s.Commitment)
		},
		"no transfer key": func(s *Source) { s.Transfer = nil },
	} {
		s := p.source("https://vault.invalid")
		change(s)
		if _, err := s.Fetch(context.Background()); err == nil {
			t.Errorf("%s: fetched", name)
		}
		if _, err := s.Wait(context.Background(), Backoff{First: time.Millisecond, Most: time.Millisecond}, nil); err == nil {
			t.Errorf("%s: waited", name)
		}
	}
}

// Both vaults down: Wait keeps asking until one is back.
func TestWaitOutlastsBothVaultsDown(t *testing.T) {
	p := newPair(t)
	var up atomic.Bool
	real := p.a.serve(t)
	gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		proxy(w, r, real.URL)
	}))
	t.Cleanup(gate.Close)

	var failures atomic.Int32
	failed := func(error) {
		if failures.Add(1) == 3 {
			up.Store(true)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := p.source(gate.URL, "http://127.0.0.1:1").Wait(ctx, Backoff{First: time.Millisecond, Most: 4 * time.Millisecond}, failed)
	if err != nil {
		t.Fatal(err)
	}
	if got.Key != p.want(t) || failures.Load() != 3 {
		t.Fatalf("got the key after %d failed rounds", failures.Load())
	}
}

func TestWaitEndsWithItsContext(t *testing.T) {
	p := newPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	failed := func(error) { cancel() }
	_, err := p.source("http://127.0.0.1:1").Wait(ctx, Backoff{First: time.Hour, Most: time.Hour}, failed)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait returned %v", err)
	}
}

func proxy(w http.ResponseWriter, r *http.Request, base string) {
	var body bytes.Buffer
	body.ReadFrom(r.Body)
	resp, err := http.Post(base+r.URL.Path, "application/json", &body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
	var out bytes.Buffer
	out.ReadFrom(resp.Body)
	w.Write(out.Bytes())
}

func TestDeriveIsStableAndClearsTheKeyset(t *testing.T) {
	ks, _ := wire.Generate()
	raw := ks.MarshalBinary()
	one, _ := wire.ParseKeyset(raw)
	two, _ := wire.ParseKeyset(raw)
	k1, err := Derive(one)
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := Derive(two)
	if k1 != k2 {
		t.Fatal("one keyset made two wrapping keys")
	}
	if one.AddressMACKey != ([32]byte{}) || one.RoutingDataKey != ([32]byte{}) {
		t.Fatal("Derive left the keyset's keys in memory")
	}
	other, _ := wire.Generate()
	if k3, _ := Derive(other); k3 == k1 {
		t.Fatal("two keysets made one wrapping key")
	}
	if KeyID(&k1) == KeyID(&coordinator.WrappingKey{}) || len(KeyID(&k1)) != 16 {
		t.Fatalf("key ID %q", KeyID(&k1))
	}
}

func TestParseVaults(t *testing.T) {
	got, err := ParseVaults(" cloud-vault-a.fount.containers.tinfoil.dev, cloud-vault-b.fount.containers.tinfoil.dev ,")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, " ") != "https://cloud-vault-a.fount.containers.tinfoil.dev https://cloud-vault-b.fount.containers.tinfoil.dev" {
		t.Fatalf("got %v", got)
	}
	for _, bad := range []string{"", " , ", "https://vault-a", "vault-a:443", "vault-a/x"} {
		if _, err := ParseVaults(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}
