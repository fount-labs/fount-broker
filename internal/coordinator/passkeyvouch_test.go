package coordinator

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// vouchFor is pk's vouch for team's start as member.
func vouchFor(t *testing.T, f teamFixture, pk testPasskey, member string, o ceremony) PasskeyVouchRequest {
	t.Helper()
	f.c.mu.Lock()
	st, err := f.c.teamState("acme")
	f.c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	ch, err := PasskeyVouchChallenge(testAudience, "acme", member, st.start)
	if err != nil {
		t.Fatal(err)
	}
	a := pk.assertRaw(t, ch, o)
	return PasskeyVouchRequest{Cred: pk.cred, AuthenticatorData: b64.EncodeToString(a.AuthenticatorData),
		ClientDataJSON: b64.EncodeToString(a.ClientDataJSON), Signature: b64.EncodeToString(a.Signature)}
}

// M3: the member's passkey vouches for their own team, once, from a device
// the team admits; every client checks the record again.
func TestAPasskeyVouchesForItsMembersOwnTeam(t *testing.T) {
	f := newTeamFixture(t)
	pk := newTestPasskey(t)
	f.tt.update("m_owner", func(m *ListMember) { m.Rec = pk.rec(t) })
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	stranger := newTestDevice(t)
	if _, err := f.c.PasskeyVouch(stranger.caller("acme"), "acme", vouchFor(t, f, pk, "m_owner", ceremony{})); !errors.Is(err, ErrListRefused) {
		t.Fatalf("a device the team doesn't admit: %v", err)
	}
	if _, err := f.c.PasskeyVouch(f.owner.caller("acme"), "acme", vouchFor(t, f, newTestPasskey(t), "m_owner", ceremony{})); !errors.Is(err, ErrListRefused) {
		t.Fatalf("an unlisted passkey: %v", err)
	}
	if _, err := f.c.PasskeyVouch(f.owner.caller("acme"), "acme", vouchFor(t, f, pk, "m_owner", ceremony{origin: "https://evil.example"})); !errors.Is(err, ErrListRefused) {
		t.Fatalf("another origin: %v", err)
	}
	v, err := f.c.PasskeyVouch(f.owner.caller("acme"), "acme", vouchFor(t, f, pk, "m_owner", ceremony{}))
	if err != nil {
		t.Fatal(err)
	}
	st, err := reduceTeam("acme", testAudience, f.team(t).Log)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !st.vouched[pk.rec(t).Pub] || st.seq != v.Seq {
		t.Fatal("the team isn't vouched for after the record")
	}
	if _, err := f.c.PasskeyVouch(f.owner.caller("acme"), "acme", vouchFor(t, f, pk, "m_owner", ceremony{})); !errors.Is(err, ErrListRefused) || !strings.Contains(err.Error(), "already") {
		t.Fatalf("a second vouch by the same passkey: %v", err)
	}
}

// A passkey vouches only for its member's own team: dev's on acme's is
// refused, so a vouch says "this account's team is mine", nothing wider.
func TestAPasskeyVouchesOnlyForItsOwnAccountsTeam(t *testing.T) {
	f := newTeamFixture(t)
	pk := newTestPasskey(t)
	f.tt.update("m_admin", func(m *ListMember) { m.Rec = pk.rec(t) })
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.PasskeyVouch(f.admin.caller("dev"), "acme", vouchFor(t, f, pk, "m_admin", ceremony{})); !errors.Is(err, ErrListRefused) {
		t.Fatalf("a vouch for another account's team: %v", err)
	}
}

// A new computer of the account reads its own team's log before it joins,
// to check the vouch; any other team's stays closed to it.
func TestANewComputerReadsOnlyItsOwnTeamsLogBeforeJoining(t *testing.T) {
	f := newTeamFixture(t)
	newOwner, newDev := newTestDevice(t), newTestDevice(t)
	get := func(d testDevice, account string) int {
		srv := f.api(t, d, account)
		resp, err := http.Get(srv.URL + "/v1/teams/acme/log")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get(newOwner, "acme"); code != http.StatusOK {
		t.Fatalf("the account's own team: %d", code)
	}
	if code := get(newDev, "dev"); code != http.StatusNotFound {
		t.Fatalf("another account's team, before joining: %d", code)
	}
	if code := get(newTestDevice(t), "nobody"); code != http.StatusNotFound {
		t.Fatalf("a stranger: %d", code)
	}
}
