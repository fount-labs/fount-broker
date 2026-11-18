//go:build !dev

package main

import "testing"

func TestReleaseBuildsRefuseAnUnattestedChannel(t *testing.T) {
	if _, _, err := clientAttestation(attestUnattested); err == nil {
		t.Fatal("a release build took --client-attestation unattested")
	}
}
