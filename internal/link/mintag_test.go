package link

import (
	"errors"
	"strings"
	"testing"
)

// releasing is an unattested side whose checker says the peer runs tag, as
// a Tinfoil checker reports a verified release.
func releasing(t *testing.T, tag string) *Side {
	t.Helper()
	s := plain(t)
	s.Endorse = func(doc, nonce []byte) (Endorsement, error) {
		key, err := checkUnattested(doc, nonce)
		return Endorsement{Key: key, Release: Release{Repo: "fount-labs/fount-cloud-runner", Tag: tag}}, err
	}
	return s
}

// The 11-24 broker review's L15: with a minimum release, each end refuses a
// peer whose release is older or has no tag; without one, any is taken.
func TestAMinimumReleaseRefusesOlderPeers(t *testing.T) {
	for tag, ok := range map[string]bool{"v0.6.0": true, "v0.10.1": true, "v1.0.0": true, "v0.5.9": false, "v0.6.0-rc.1": false, "": false, "latest": false} {
		server := releasing(t, tag)
		if err := server.RequireMinTag("v0.6.0"); err != nil {
			t.Fatal(err)
		}
		_, sErr := pair(t, plain(t), server)
		if ok != (sErr == nil) || (!ok && !errors.Is(sErr, ErrPeer)) {
			t.Errorf("a peer on %q: %v", tag, sErr)
		}
		// The Check a Side without Endorse would use refuses it too.
		check := server.Check
		server.Endorse = nil
		server.Check = check
		if _, sErr := pair(t, plain(t), server); ok != (sErr == nil) {
			t.Errorf("Check, a peer on %q: %v", tag, sErr)
		}
	}
	if _, sErr := pair(t, plain(t), releasing(t, "v0.0.1")); sErr != nil {
		t.Fatalf("no minimum refused %v", sErr)
	}
}

func TestAMinimumReleaseMustBeAFullTag(t *testing.T) {
	for _, bad := range []string{"0.6.0", "v0.6", "v1", "latest", ""} {
		if err := releasing(t, "v1.0.0").RequireMinTag(bad); err == nil {
			t.Errorf("minimum %q taken", bad)
		}
	}
	if err := plain(t).RequireMinTag("v0.6.0"); err == nil || !strings.Contains(err.Error(), "reports the peer's release") {
		t.Fatalf("an unattested side took a minimum: %v", err)
	}
}
