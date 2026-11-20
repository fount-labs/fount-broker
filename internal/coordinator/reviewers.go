package coordinator

import (
	"slices"
	"strings"
)

// Who hears of a worker's drafts, questions and problems by email
// (decision 27: every reviewer is notified). The edge mails only a worker's
// proven owners, so a team member's address is on the edge's owner list
// too: the mail loop adds each member who reaches the worker, by their
// invite's address, as a notice owner (MailSettings.NoticeOwners,
// mailpush.go). The edge then proves them as it proves any owner, with its
// "Reply to turn on email updates" mail and its wait, and tells the owners it
// has proved. Being a notice owner lets the edge mail them and nothing else:
// their email starts no work, as they aren't requesters, and an approval by
// email checks again that they still review the worker (sendapproval.go).

// reviewers are the addresses a notice goes to: the owner, then each member
// who reaches the worker, by member. Only addresses on the edge's owner list
// are listed, so a member the edge hasn't taken yet hears of it in the app
// alone. Each address is lower-case and listed once.
func (c *Coordinator) reviewers(workerID string, rs *replySettings, s *MailSettings) []string {
	var out []string
	add := func(addr string) {
		addr = strings.ToLower(strings.TrimSpace(addr))
		if addr != "" && !slices.Contains(out, addr) && s.mailable(addr) {
			out = append(out, addr)
		}
	}
	add(rs.Owner)
	for _, a := range c.memberAddresses(workerID) {
		add(a)
	}
	return out
}

// memberAddresses are the addresses of the team members who reach the
// worker and have joined, by member, lower-case, each once.
func (c *Coordinator) memberAddresses(workerID string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	w, ok := c.state.Workers[workerID]
	if !ok || w.Team == "" {
		return nil
	}
	st, err := c.teamState(w.Team)
	if err != nil {
		return nil
	}
	var out []string
	for _, m := range st.members {
		addr := strings.ToLower(strings.TrimSpace(m.Email))
		if addr != "" && m.Account != "" && len(m.Devices) > 0 && m.reaches(workerID) && !slices.Contains(out, addr) {
			out = append(out, addr)
		}
	}
	return out
}

// memberID is the id of the team member whose address is addr, on a team
// worker, or empty.
func (c *Coordinator) memberID(workerID, addr string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	w, ok := c.state.Workers[workerID]
	if !ok || w.Team == "" {
		return ""
	}
	st, err := c.teamState(w.Team)
	if err != nil {
		return ""
	}
	for _, m := range st.members {
		if m.Email != "" && m.Account != "" && strings.EqualFold(m.Email, addr) {
			return m.ID
		}
	}
	return ""
}

// edgeMaxOwners is the most owners the edge takes on one list.
const edgeMaxOwners = 256

// nextNoticeOwners is the notice owners the next routing write carries,
// given those the edge took last and the members who should be: those
// taken who still should be, then at most one new one. A new owner the edge
// hasn't taken could be refused by its daily new-owner cap, which would hold
// up the whole list, requesters too; one at a time, a refusal costs only
// that one (sendRouting drops it and tries again later). more says members
// remain to add after this write. The list stays within the edge's limit.
func nextNoticeOwners(taken, wanted []string, requesters int) (next []string, more bool) {
	room := edgeMaxOwners - requesters
	for _, a := range taken {
		if slices.Contains(wanted, a) && len(next) < room {
			next = append(next, a)
		}
	}
	added := false
	for _, a := range wanted {
		if slices.Contains(next, a) {
			continue
		}
		if added || len(next) >= room {
			return next, len(next) < room
		}
		next, added = append(next, a), true
	}
	return next, false
}
