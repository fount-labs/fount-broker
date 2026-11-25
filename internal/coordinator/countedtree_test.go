package coordinator

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// countedRig is a mail rig with backups on, whose volume a test can copy
// and put back, as a host replaying the disk would.
type countedRig struct {
	*mailRig
	v *vaultRig
}

func newCountedRig(t *testing.T) *countedRig {
	t.Helper()
	r := newMailRig(t, MailConfig{})
	v := newVaultRig(t, r.edge.authority)
	v.key = r.key
	r.backup = v.backups(v.next())
	r.start()
	return &countedRig{mailRig: r, v: v}
}

// snapshot copies the volume and the store.
func (r *countedRig) snapshot() string {
	r.t.Helper()
	dst := r.t.TempDir()
	for _, sub := range []string{"state", "objects"} {
		if err := os.CopyFS(filepath.Join(dst, sub), os.DirFS(filepath.Join(r.dir, sub))); err != nil {
			r.t.Fatal(err)
		}
	}
	return dst
}

// replay stops the coordinator, puts snap back as the volume and boots it
// under a new generation.
func (r *countedRig) replay(snap string) error {
	r.t.Helper()
	r.cancel()
	r.c.running.Wait()
	r.cancel = nil
	for _, sub := range []string{"state", "objects"} {
		if err := os.RemoveAll(filepath.Join(r.dir, sub)); err != nil {
			r.t.Fatal(err)
		}
		if err := os.CopyFS(filepath.Join(r.dir, sub), os.DirFS(filepath.Join(snap, sub))); err != nil {
			r.t.Fatal(err)
		}
	}
	r.backup = r.v.backups(r.v.next())
	return r.startErr()
}

// A change that takes something away is counted by the vault before it is
// acknowledged, so a disk replayed to before it is refused; one that gives
// something isn't counted (broker review M1).
func TestAChangeThatTakesAwayIsCountedBeforeItIsAcknowledged(t *testing.T) {
	r := newCountedRig(t)
	w, _ := r.worker()
	before := r.v.count().Count
	snap := r.snapshot()

	if res := r.workerOp(w.ID, "op_pause", "setPaused", switchArgs{On: true}); !res.OK {
		t.Fatalf("setPaused: %+v", res)
	}
	paused := r.v.count()
	if paused.Count != before+1 {
		t.Fatalf("pausing mail left the vault at %d, from %d", paused.Count, before)
	}
	r.c.mu.Lock()
	version, counted := r.c.state.Workers[w.ID].Version, r.c.state.Counted[w.ID]
	digest := securityDigest(r.c.state)
	r.c.mu.Unlock()
	if counted != version || digest != paused.Digest {
		t.Fatalf("the count binds version %d, the tree is at %d", counted, version)
	}
	// Giving back isn't counted.
	if res := r.workerOp(w.ID, "op_unpause", "setPaused", switchArgs{On: false, BaseRevision: 1}); !res.OK {
		t.Fatalf("setPaused off: %+v", res)
	}
	if got := r.v.count().Count; got != paused.Count {
		t.Fatalf("unpausing moved the vault to %d", got)
	}
	if res := r.workerOp(w.ID, "op_auto_off", "setAutoRun", switchArgs{On: false, BaseRevision: 1}); !res.OK {
		t.Fatalf("setAutoRun off: %+v", res)
	}
	if got := r.v.count().Count; got != paused.Count+1 {
		t.Fatalf("turning automatic runs off left the vault at %d", got)
	}

	if err := r.replay(snap); !errors.Is(err, ErrVolumeRolledBack) {
		t.Fatalf("a disk replayed to before the pause: %v", err)
	}
}

// Lowering a thread's reply mode and discarding a draft are counted.
func TestLoweringAThreadAndDiscardingADraftAreCounted(t *testing.T) {
	r := newCountedRig(t)
	s := sendRigOn(t, r.mailRig, modeFull)
	th, e := s.drafted()
	before := r.v.count().Count
	if res := r.threadOp(s.w.ID, th.ID, "op_discard", "discardDraft", map[string]string{"draftId": e.ID}); !res.OK {
		t.Fatalf("discardDraft: %+v", res)
	}
	if got := r.v.count().Count; got != before+1 {
		t.Fatalf("discarding left the vault at %d, from %d", got, before)
	}
	if res := r.threadOp(s.w.ID, th.ID, "op_lower", "setThreadReplyMode", map[string]string{"mode": modeOff}); !res.OK {
		t.Fatalf("setThreadReplyMode: %+v", res)
	}
	if got := r.v.count().Count; got != before+2 {
		t.Fatalf("lowering the thread left the vault at %d, from %d", got, before)
	}
	if res := r.workerOp(s.w.ID, "op_default", "setDefaultMode", defaultModeArgs{Mode: modeNotify, Owner: "dana@example.com", BaseRevision: 1}); !res.OK {
		t.Fatalf("setDefaultMode: %+v", res)
	}
	if got := r.v.count().Count; got != before+3 {
		t.Fatalf("lowering the default mode left the vault at %d, from %d", got, before)
	}
}

// The mail ledger's progress is counted, at most once every
// ledgerCountEvery, by the mail loop.
func TestTheMailLedgersProgressIsCounted(t *testing.T) {
	r := newCountedRig(t)
	w, mb := r.worker()
	before := r.v.count().Count
	id := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Q3"})
	r.pass()
	waitJob(t, r.c, mailJobID(id))
	first := r.v.count().Count
	if first != before+1 {
		t.Fatalf("the ledger's progress left the vault at %d, from %d", first, before)
	}
	r.c.mu.Lock()
	counted := r.c.state.Counted[w.ID]
	r.c.mu.Unlock()
	if counted == 0 {
		t.Fatal("the count doesn't bind the worker's tree")
	}
	id2 := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Q4"})
	r.pass()
	waitJob(t, r.c, mailJobID(id2))
	if got := r.v.count().Count; got != first {
		t.Fatalf("a second message within %s moved the vault to %d", ledgerCountEvery, got)
	}
	r.c.countLedger(time.Now().Add(ledgerCountEvery))
	if got := r.v.count().Count; got != first+1 {
		t.Fatalf("after %s the vault is at %d", ledgerCountEvery, got)
	}
}

// A volume behind the newest backup of it, at the vault's count, was
// replayed: it boots as a restore, with its earlier mail held.
func TestAVolumeBehindTheNewestBackupRunsAsARestore(t *testing.T) {
	r := newCountedRig(t)
	w, mb := r.worker()
	snap := r.snapshot()
	if err := r.c.PutFile(w.ID, "files/after.md", []byte("a plain change")); err != nil {
		t.Fatal(err)
	}
	newest, err := r.c.Backup(t.Context())
	if err != nil || newest == "" {
		t.Fatalf("backup: %q %v", newest, err)
	}
	// A plain restart isn't a replay.
	r.backup = r.v.backups(r.v.next())
	r.start()
	r.c.mu.Lock()
	mark := r.c.state.Restored
	r.c.mu.Unlock()
	if mark != nil {
		t.Fatalf("a restart marked the volume restored: %+v", mark)
	}

	id := r.edge.deliver(mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Q3"})
	if err := r.replay(snap); err != nil {
		t.Fatalf("booting the replayed volume: %v", err)
	}
	r.c.mu.Lock()
	mark = r.c.state.Restored
	r.c.mu.Unlock()
	if mark == nil || !strings.HasPrefix(mark.Root, backupRootPrefix) {
		t.Fatalf("the replayed volume isn't marked restored: %+v", mark)
	}
	r.pass()
	if got := r.ledger(w.ID).Acted[id]; got.Outcome != outcomeHeld {
		t.Fatalf("mail from before the replay was %+v, not held", got)
	}
}

func TestTheDigestCoversCountedTreesOnlyWhenThereAreAny(t *testing.T) {
	st := &State{Workers: map[string]*Worker{}, Teams: map[string]*Team{"acme": {}}, TeamMints: map[string]string{}}
	base := securityDigest(st)
	st.Saves, st.TeamMints["t_x"] = 7, "acct"
	if securityDigest(st) != base {
		t.Fatal("a plain save's fields moved the digest")
	}
	st.Counted = map[string]uint64{}
	if securityDigest(st) != base {
		t.Fatal("an empty Counted moved the digest of a state counted before it")
	}
	st.Counted["w_a"] = 3
	withA := securityDigest(st)
	st.Counted["w_a"] = 4
	if withA == base || securityDigest(st) == withA {
		t.Fatal("the digest doesn't bind the counted tree versions")
	}
}
