package coordinator

import "fmt"

// Who may sign a team's lists (security review 2026-11-19, H3).
//
// A device a record admitted (an invite, a join, a recovery, or any kind a
// record admits by) reaches the team's workers at once, but it signs no
// list until a list, signed by an admin's device that a list admitted,
// includes it. Else accepting an admin invite, or a join slipped past an
// admin, would let the new device sign a list that drops every other admin
// before anyone could see it. The rule keys on how the device came in, not
// on the record's kind, so a new admitting kind is held to it too.
//
// A list includes every device the team keeps, so the devices a list
// admitted are those whose inclusion is for that list or an earlier entry;
// one a record admitted since has an inclusion for the record's entry,
// after the last list.

// maySignLists refuses caller as a list's signer in s: it must be a device
// of an admin of the caller's account, and one a list included.
func (s *teamState) maySignLists(caller Caller) error {
	d, m := s.device(caller.Device)
	switch {
	case m == nil || m.Role != RoleAdmin || m.Account != caller.Account:
		return ErrNotAdmin
	case d.Since > s.lastList:
		return fmt.Errorf("%w: a device a record admitted signs no list until a list includes it", ErrNotAdmin)
	}
	return nil
}
