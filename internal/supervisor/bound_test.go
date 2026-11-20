package supervisor

import "testing"

func TestABoundRunnerTakesOneAccountForTheBoot(t *testing.T) {
	s := &Server{}
	if !s.admits("acct1", false) || !s.admits("acct2", false) {
		t.Fatal("an unbound runner refused a job")
	}
	if !s.admits("tm_a", true) {
		t.Fatal("the binding job was refused")
	}
	for _, c := range []struct {
		account string
		bound   bool
		ok      bool
	}{{"tm_a", false, true}, {"tm_a", true, true}, {"tm_b", true, false}, {"acct1", false, false}} {
		if got := s.admits(c.account, c.bound); got != c.ok {
			t.Errorf("%s bound %t: admitted %t", c.account, c.bound, got)
		}
	}
}
