package coordinator

import "fmt"

// Who may sign a team's lists (security review 2026-11-19, H3).
//
// A device a record admitted (an invite, a join, a passkey join, or any kind
// a record admits by) reaches the team's workers at once, but it signs no
// list until a list, signed by an admin's device that a list admitted,
// includes it. Else accepting an admin invite, or a join slipped past an
// admin, would let the new device sign a list that drops every other admin
// before anyone could see it. The rule keys on how the device came in, not
// on the record's kind, so a new admitting kind is held to it too.
//
// One exception: a device the member's own passkey added (a passkey-join
// record) signs lists at once when no other admin has a device a list
// included. Then no one else could ever include it, and an admin who lost
// every computer would be locked out of their own team; the passkey is the
// admin's own, and the record that admitted the device carries its
// assertion, which every client checks again. With another such admin, the
// H3 rule stands: that admin includes the new device.
//
// A list includes every device the team keeps, so the devices a list
// admitted are those whose inclusion is for that list or an earlier entry;
// one a record admitted since has an inclusion for the record's entry,
// after the last list. Desktop's team_log.rs keeps the same rule.

// maySignLists refuses caller as a list's signer in s: it must be a device
// of an admin of the caller's account, and one a list included or, for the
// team's only admin, their passkey added.
func (s *teamState) maySignLists(caller Caller) error {
	d, m := s.device(caller.Device)
	switch {
	case m == nil || m.Role != RoleAdmin || m.Account != caller.Account:
		return ErrNotAdmin
	case d.Since <= s.lastList:
		return nil
	case s.passkeyJoined[d.ID] && !s.otherListedAdmin(m):
		return nil
	}
	return fmt.Errorf("%w: a device a record admitted signs no list until a list includes it", ErrNotAdmin)
}

// otherListedAdmin reports whether an admin other than m has a device a list
// included: one who can include m's new devices.
func (s *teamState) otherListedAdmin(m *Member) bool {
	for _, o := range s.members {
		if o == m || o.Role != RoleAdmin {
			continue
		}
		for _, d := range o.Devices {
			if d.Since <= s.lastList {
				return true
			}
		}
	}
	return false
}
