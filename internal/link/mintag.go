package link

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"golang.org/x/mod/semver"
)

// RequireMinTag makes s refuse a peer whose verified release is older than
// min, a semantic version tag such as v0.6.0, or has no tag at all: a peer
// on an unattested link, or a release tagged otherwise (broker review L15).
// Without it, any release of the pinned repository is taken until its
// attestation's freshness lapses, old ones with fixed holes included. The
// flag that sets min is in the enclave's measured config, so a host can't
// lower it.
func (s *Side) RequireMinTag(min string) error {
	if !semver.IsValid(min) || semver.Canonical(min) != min {
		return fmt.Errorf("minimum release %q: a semantic version tag, vMAJOR.MINOR.PATCH", min)
	}
	if s.Endorse == nil {
		return errors.New("a minimum release needs a checker that reports the peer's release")
	}
	endorse := s.Endorse
	checked := func(doc, nonce []byte) (Endorsement, error) {
		e, err := endorse(doc, nonce)
		if err != nil {
			return Endorsement{}, err
		}
		if err := atLeast(e.Release, min); err != nil {
			return Endorsement{}, err
		}
		return e, nil
	}
	s.Endorse = checked
	s.Check = func(doc, nonce []byte) (ed25519.PublicKey, error) {
		e, err := checked(doc, nonce)
		return e.Key, err
	}
	return nil
}

// atLeast is nil when r's tag is a semantic version no older than min.
func atLeast(r Release, min string) error {
	switch {
	case r.Tag == "":
		return fmt.Errorf("the peer's release has no tag, and at least %s is required", min)
	case !semver.IsValid(r.Tag):
		return fmt.Errorf("the peer's release %.80q isn't a semantic version, and at least %s is required", r.Tag, min)
	case semver.Compare(r.Tag, min) < 0:
		return fmt.Errorf("the peer runs %s, older than the %s required", r.Tag, min)
	}
	return nil
}
