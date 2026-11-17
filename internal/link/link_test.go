package link

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// pair runs the handshake over a pipe and returns both ends' results.
func pair(t *testing.T, client, server *Side) (cErr, sErr error) {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	done := make(chan error, 1)
	go func() {
		sc, err := server.Server(context.Background(), b)
		if err == nil {
			// The channel carries data once it's up.
			buf := make([]byte, 5)
			if _, err = io.ReadFull(sc, buf); err == nil && string(buf) != "hello" {
				err = errors.New("garbled")
			}
		}
		if err != nil {
			b.Close()
		}
		done <- err
	}()
	cc, err := client.Client(context.Background(), a)
	if err == nil {
		_, err = cc.Write([]byte("hello"))
	}
	if err != nil {
		a.Close()
	}
	return err, <-done
}

func plain(t *testing.T) *Side {
	t.Helper()
	s, err := Unattested()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestBothEndsProveTheirKeys(t *testing.T) {
	if cErr, sErr := pair(t, plain(t), plain(t)); cErr != nil || sErr != nil {
		t.Fatalf("client %v, server %v", cErr, sErr)
	}
}

// liar attests a key it doesn't hold the TLS side of: an enclave's document
// replayed by someone else.
type liar struct{ key ed25519.PublicKey }

func (l liar) Attest(ctx context.Context, nonce []byte) ([]byte, error) {
	return unattested{l.key}.Attest(ctx, nonce)
}

func TestAPeerWhoseDocumentEndorsesAnotherKeyIsRefused(t *testing.T) {
	enclave := plain(t)
	impostor := plain(t)
	impostor.Attester = liar{enclave.Key.Public().(ed25519.PublicKey)}
	_, sErr := pair(t, impostor, plain(t))
	if !errors.Is(sErr, ErrPeer) {
		t.Fatalf("the server took an impostor client: %v", sErr)
	}
	cErr, _ := pair(t, plain(t), impostor)
	if !errors.Is(cErr, ErrPeer) {
		t.Fatalf("the client took an impostor server: %v", cErr)
	}
}

// replay attests with a document made for another session's nonce.
type replay struct{ doc []byte }

func (r replay) Attest(context.Context, []byte) ([]byte, error) { return r.doc, nil }

func TestADocumentFromAnotherSessionIsRefused(t *testing.T) {
	server := plain(t)
	old, _ := server.Attester.Attest(context.Background(), make([]byte, 32))
	server.Attester = replay{old}
	cErr, _ := pair(t, plain(t), server)
	if !errors.Is(cErr, ErrPeer) {
		t.Fatalf("a replayed document passed: %v", cErr)
	}
}

func TestACheckerThatRefusesTheReleaseFailsTheLink(t *testing.T) {
	client := plain(t)
	client.Check = func([]byte, []byte) (ed25519.PublicKey, error) { return nil, errors.New("built from another repo") }
	cErr, _ := pair(t, client, plain(t))
	if !errors.Is(cErr, ErrPeer) {
		t.Fatalf("%v", cErr)
	}
}

func TestLoadKeyReadsTinfoilsPEM(t *testing.T) {
	dir := t.TempDir()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	os.MkdirAll(filepath.Join(dir, KeyID), 0o700)
	os.WriteFile(filepath.Join(dir, KeyID, "private_key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	got, err := LoadKey(dir)
	if err != nil || !got.Equal(key) {
		t.Fatalf("%v", err)
	}
}
