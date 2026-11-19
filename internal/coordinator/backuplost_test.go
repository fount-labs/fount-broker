package coordinator

import (
	"errors"
	"testing"
)

// A swap the vault made whose answer was lost: the next change finds the
// vault ahead by the count this generation sent, takes it as its own, and
// goes on, rather than retiring as if another coordinator had moved it.
func TestALostCountAnswerDoesntRetireTheCoordinator(t *testing.T) {
	v := newVaultRig(t, nil)
	c := v.boot(t.TempDir())
	me, rev := newTestDevice(t), newTestDevice(t)
	tt := soloTeam(t, c, "acme", me)
	v.vault.FailSwap = func(_, _, next uint64) error {
		// Called with the vault's lock held: count it, then lose the
		// answer.
		v.vault.count = next
		v.vault.FailSwap = nil
		return errors.New("the vault's answer timed out")
	}
	tt.set("m_rev", "maria", RoleReviewer, rev)
	if err := tt.push(me, "acme", nil); !errors.Is(err, ErrNotDurable) {
		t.Fatal(err)
	}
	if v.count().Count != 2 {
		t.Fatalf("the vault has %+v", v.count())
	}
	if err := tt.push(me, "acme", nil); err != nil {
		t.Fatalf("the next change: %v", err)
	}
	if c.Retired() || v.count().Count != 3 {
		t.Fatalf("retired %v, vault %+v", c.Retired(), v.count())
	}
}
