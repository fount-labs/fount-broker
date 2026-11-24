package coordinator

import (
	"fmt"
	"maps"
	"math/rand/v2"
	"reflect"
	"slices"
	"testing"
)

// checkTeamStates fails t if any team's kept state isn't what replaying its
// log from the start makes: commitEntry applies each append to its prior
// state alone, and this holds it to reduceTeam over every test's logs.
func checkTeamStates(t testing.TB, c *Coordinator) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, team := range c.state.Teams {
		// A test that sets a state with no log stands in for one.
		if team.state == nil || len(team.Log) == 0 {
			continue
		}
		st, err := reduceTeam(id, c.cfg.Audience, team.Log)
		if err != nil {
			t.Errorf("team %s's log doesn't replay: %v", id, err)
			continue
		}
		if !reflect.DeepEqual(st, team.state) {
			t.Errorf("team %s's kept state isn't its log's replay", id)
		}
	}
}

// Applying each entry to a clone of the state before it is replaying the log
// from the start, and leaves the state before it as it was: over lists that
// add, drop and change members and devices and end the team, and over the
// records of the passkey-join, invite and vouch vectors.
func TestApplyingEachEntryToItsPriorIsTheReplay(t *testing.T) {
	jv, vv := makePasskeyJoinVectors(t), makePasskeyVouchVectors(t)
	team, log := randomListLog(t)
	logs := []struct {
		team, aud string
		log       []TeamEntry
	}{
		{team, testAudience, log},
		{jv.Team, jv.Audience, jv.Log.Entries},
		{jv.Team, jv.Audience, append(slices.Clone(jv.Log.Entries[:2]), jv.Third)},
		{jv.Team, jv.Audience, append(slices.Clone(jv.InviteLog.Entries), jv.InviteAgain, jv.InviteBack)},
		{vv.Team, vv.Audience, vv.Log.Entries},
	}
	for i, l := range logs {
		st := newTeamState()
		for n, e := range l.log {
			before, err := reduceTeam(l.team, l.aud, l.log[:n])
			if err != nil {
				t.Fatalf("log %d, entries to %d: %v", i, n, err)
			}
			want, err := reduceTeam(l.team, l.aud, l.log[:n+1])
			if err != nil {
				t.Fatalf("log %d, entries to %d: %v", i, n+1, err)
			}
			next := st.clone()
			if err := next.apply(l.team, l.aud, e); err != nil {
				t.Fatalf("log %d, entry %d: %v", i, e.Seq, err)
			}
			if !reflect.DeepEqual(next, want) {
				t.Fatalf("log %d, entry %d: applied to its prior, the state isn't the replay", i, e.Seq)
			}
			if !reflect.DeepEqual(st, before) {
				t.Fatalf("log %d, entry %d: applying it changed the state before it", i, e.Seq)
			}
			st = next
		}
	}
}

// randomListLog is a team's log of lists that change it at random, ending
// with its deletion, and the team.
func randomListLog(t *testing.T) (string, []TeamEntry) {
	c, _ := newTestCoordinator(t, "ok", 0)
	r := rand.New(rand.NewPCG(1, 2))
	admin := newTestDevice(t)
	team, err := c.MintTeam(admin.caller("owner"))
	if err != nil {
		t.Fatal(err)
	}
	tt := newTestTeam(t, c, team)
	tt.set("m_owner", "owner", RoleAdmin, admin)
	next := 0
	for range 60 {
		ids := slices.Sorted(maps.Keys(tt.members))
		id := ids[r.IntN(len(ids))]
		switch op := r.IntN(6); {
		case op == 0 && len(ids) < MaxMembers:
			next++
			var devices []testDevice
			for range r.IntN(3) {
				devices = append(devices, newTestDevice(t))
			}
			tt.set(fmt.Sprintf("m_%03d", next), fmt.Sprintf("acct_%03d", next), []Role{RoleAdmin, RoleReviewer}[r.IntN(2)], devices...)
		case op == 1 && id != "m_owner":
			tt.drop(id)
		case op == 2 && id != "m_owner":
			tt.update(id, func(m *ListMember) {
				m.Role = map[Role]Role{RoleAdmin: RoleReviewer, RoleReviewer: RoleAdmin}[m.Role]
				m.Workers = nil
				if m.Role == RoleReviewer {
					m.Workers = []string{allWorkers}
				}
			})
		case op == 3 && len(tt.devices[id]) < MaxMemberDevices:
			tt.devices[id] = append(tt.devices[id], newTestDevice(t))
		case op == 4 && id != "m_owner" && len(tt.devices[id]) > 0:
			tt.devices[id] = tt.devices[id][1:]
		default:
			tt.update(id, func(m *ListMember) { m.Email = fmt.Sprintf("%s.%d@example.com", id, r.IntN(1000)) })
		}
		c.mu.Lock()
		c.logRate = teamLogRate{}
		c.mu.Unlock()
		if err := tt.push(admin, "owner", nil); err != nil {
			t.Fatal(err)
		}
	}
	end := deleteList(tt)
	if err := tt.pushList(admin.caller("owner"), admin.sign(t, end), end, nil); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return team, slices.Clone(c.state.Teams[team].Log)
}
