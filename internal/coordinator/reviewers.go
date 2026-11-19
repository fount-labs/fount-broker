package coordinator

import (
	"slices"
	"strings"
)

// reviewers are the addresses a draft's notice goes to (decision 27: every
// reviewer is notified): the owner, then each member who reaches the worker,
// by member. Only addresses the edge sends to are listed: /send goes only to
// a worker's proven owners, its requesters, so a member whose address isn't
// one hears of drafts in the app alone. Each address is lower-case and listed
// once.
func (c *Coordinator) reviewers(workerID string, rs *replySettings, s *MailSettings) []string {
	var out []string
	add := func(addr string) {
		addr = strings.ToLower(strings.TrimSpace(addr))
		if addr != "" && !slices.Contains(out, addr) && s.requester(addr) != nil {
			out = append(out, addr)
		}
	}
	add(rs.Owner)
	c.mu.Lock()
	defer c.mu.Unlock()
	w, ok := c.state.Workers[workerID]
	if !ok || w.Team == "" {
		return out
	}
	st, err := c.teamState(w.Team)
	if err != nil {
		return out
	}
	for _, m := range st.members {
		if m.Account != "" && len(m.Devices) > 0 && m.reaches(workerID) {
			add(m.Email)
		}
	}
	return out
}
