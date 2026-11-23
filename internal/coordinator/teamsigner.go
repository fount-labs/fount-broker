package coordinator

import (
	"fmt"
	"time"
)

// Who may sign a team's lists (security review 2026-11-19, H3).
//
// A device a record admitted (an invite, a passkey join, or any kind a
// record admits by) reaches the team's workers at once, but it signs no
// list until a list, signed by an admin's device that a list admitted,
// includes it. Else accepting an admin invite, or a join slipped past an
// admin, would let the new device sign a list that drops every other admin
// before anyone could see it. The rule keys on how the device came in, not
// on the record's kind, so a new admitting kind is held to it too.
//
// One exception: a device the member's own passkey added (a passkey-join
// record, or an invite record, which carries the assertion of the passkey it
// lists) signs lists at once when no admin, the member included, has a
// device a list included. Then no one could ever include it, and an admin
// whose every device was removed (by a list, or by accepting an invite
// again) would be locked out of their own team; the passkey is the admin's
// own, and the record that admitted the device carries its assertion, which
// every client checks again. While any admin has such a device, even the
// member's own, the H3 rule stands: that device includes the new one, so
// one phished passkey assertion can't sign a list that drops the owner's
// computers (security review 2026-11-23).
//
// A list includes every device the team keeps, so the devices a list
// admitted are those whose inclusion is for that list or an earlier entry;
// one a record admitted since has an inclusion for the record's entry,
// after the last list. Desktop's team_log.rs keeps the same rule.
//
// While an admin has such a device, one their passkey added may start a
// recovery instead, and signs RecoveryDelay later unless a list ends it
// first (teamrecovery.go).

// maySignLists refuses caller as a list's signer in s: it must be a device
// of an admin of the caller's account, and one a list included or, when no
// admin has such a device, one their passkey added, or one whose recovery
// waited RecoveryDelay by the list's iat and now.
func (s *teamState) maySignLists(caller Caller, iat int64, now time.Time) error {
	d, m := s.device(caller.Device)
	switch {
	case m == nil || m.Role != RoleAdmin || m.Account != caller.Account:
		return ErrNotAdmin
	case d.Since <= s.lastList:
		return nil
	case s.passkeyAdmitted[d.ID] && !s.listedAdmin():
		return nil
	case s.passkeyAdmitted[d.ID] && s.recovered(m, d.ID, iat, now):
		return nil
	}
	return fmt.Errorf("%w: a device a record admitted signs no list until a list includes it", ErrNotAdmin)
}

// listedAdmin reports whether an admin has a device a list included: one
// who can include an admin's new devices.
func (s *teamState) listedAdmin() bool {
	for _, m := range s.members {
		if m.Role != RoleAdmin {
			continue
		}
		for _, d := range m.Devices {
			if d.Since <= s.lastList {
				return true
			}
		}
	}
	return false
}
