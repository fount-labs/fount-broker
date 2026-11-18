//go:build dev

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

func TestDevBuildsTakeAnUnattestedChannel(t *testing.T) {
	infra, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&infra.PublicKey)
	t.Setenv(accountKeysEnv, base64.StdEncoding.EncodeToString(der))
	s, err := clientFlags{listen: ":8791", attestation: attestUnattested}.server()
	if err != nil || s == nil || len(s.AccountKeys) != 1 {
		t.Fatalf("%v %v", s, err)
	}
}
