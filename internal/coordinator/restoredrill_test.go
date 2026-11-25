package coordinator

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/fount-labs/fount-mail-vault/wire"

	"github.com/fount-labs/fount-broker/internal/mail"
	"github.com/fount-labs/fount-broker/internal/vaultkey/cloudvaulttest"
)

// restoreRunbookDrill is docs/backups.md's restore, rehearsed end to end on
// bucket, against the Cloud vault pair's counter over its wire protocol: a
// coordinator with mail makes real state (a team, a worker with a mailbox,
// a file, mail worked into a thread with a draft), backs up, and loses its
// volume. The runbook's steps then run in order on a fresh one: a dry run,
// which moves nothing; a restore of a backup from before a security change,
// refused; a restore of the newest, which brings back every byte of state
// and every file. The restored coordinator then works: its mail isn't run
// again, the draft sends once, new mail runs, and it counts in the vault
// under its generation, which fences the one it replaced.
//
// TestTheRestoreRunbookDrill runs it through the S3 client.
func restoreRunbookDrill(t *testing.T, bucket BackupBucket) {
	ctx := context.Background()
	r := newMailRig(t, MailConfig{})
	pair := cloudvaulttest.Start(t)
	// The edge has the vault's authority key as COORDINATOR_AUTHORITY_KEY.
	pair.Authority = r.edge.authority
	boot := func() *FixedGeneration {
		t.Helper()
		pub, priv, _ := ed25519.GenerateKey(nil)
		cert, n, err := pair.Boot(pub)
		if err != nil {
			t.Fatal(err)
		}
		return &FixedGeneration{G: mail.Generation{Number: n, Certificate: cert, Key: priv}}
	}
	counter := func(g *FixedGeneration) *WireCounter {
		return &WireCounter{Client: &wire.CounterClient{Vaults: pair.Vaults(), Authority: pair.AuthorityKey(), Client: http.DefaultClient}, Gen: g}
	}
	serve := func(g *FixedGeneration) {
		t.Helper()
		r.backup = &BackupConfig{Bucket: bucket, Counter: counter(g), Generations: g}
		r.cfg = MailConfig{Send: true, Generations: g}
		r.start()
		if !r.c.startGeneration(ctx) {
			t.Fatalf("generation %d wasn't presented to the edge", g.G.Number)
		}
	}

	// Real state, under generation 1.
	g1 := boot()
	serve(g1)
	s := sendRigOn(t, r, modeNotify)
	me, rev := newTestDevice(t), newTestDevice(t)
	tt := soloTeam(t, r.c, "acme", me)
	const memo = "Q3 close: the accruals are in the shared drive."
	if err := r.c.PutFile(s.w.ID, "files/memo.md", []byte(memo)); err != nil {
		t.Fatal(err)
	}
	th, e := s.drafted()
	messageID := s.draft(th.ID, e.ID).MessageID
	older, err := r.c.Backup(ctx)
	if err != nil || older == "" {
		t.Fatalf("backup: %q %v", older, err)
	}
	// A security change after it puts it below the vault's counter.
	tt.set("m_rev", "maria", RoleReviewer, rev)
	if err := tt.push(me, "acme", nil); err != nil {
		t.Fatal(err)
	}
	if err := r.c.PutFile(s.w.ID, "files/after.md", []byte("written after the security change")); err != nil {
		t.Fatal(err)
	}
	newest, err := r.c.Backup(ctx)
	if err != nil || newest == "" || newest == older {
		t.Fatalf("backup: %q %v", newest, err)
	}
	// Two team changes, and the mail ledger's progress, which the mail
	// loop counts too (broker review M1).
	counted := pair.State()
	if counted.Generation != 1 || counted.Count < 2 {
		t.Fatalf("the vault has %+v", counted)
	}
	want := drillView(t, r.c)
	r.runner.mu.Lock()
	ran := len(r.runner.prompts)
	r.runner.mu.Unlock()

	// The bucket holds ciphertext only.
	keys, err := bucket.List(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		data, err := bucket.Get(ctx, k)
		if err != nil {
			t.Fatal(err)
		}
		for _, plain := range []string{memo, "dana@example.com", "Q3 close", "reconciled", s.w.Account} {
			if bytes.Contains(data, []byte(plain)) {
				t.Fatalf("bucket object %s holds %q in the clear", k, plain)
			}
		}
	}

	// The volume is lost.
	r.cancel()
	r.c.running.Wait()
	r.cancel = nil
	if err := os.RemoveAll(r.dir); err != nil {
		t.Fatal(err)
	}
	r.dir = t.TempDir()
	r.store = &crashStore{Store: DirStore{Root: filepath.Join(r.dir, "objects")}}
	stateDir := filepath.Join(r.dir, "state")
	restore := func(root string, g *FixedGeneration, dry bool) (RestoreResult, error) {
		o := RestoreOptions{Bucket: bucket, Counter: counter(g), Key: r.key, Root: root, DryRun: dry}
		if !dry {
			o.Generations, o.StateDir, o.Store = g, stateDir, r.store
		}
		return Restore(ctx, o)
	}
	empty := func(step string) {
		t.Helper()
		if ents, err := os.ReadDir(r.dir); err != nil || len(ents) != 0 {
			t.Fatalf("%s wrote the volume: %v %v", step, ents, err)
		}
	}

	// 1. The dry run: whole, and nothing moved.
	res, err := restore("", nil, true)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if res.Root != newest || !res.DryRun || res.Workers != 1 || res.Objects == 0 || res.SecuritySeq != counted.Count || res.StoppedJobs != 0 {
		t.Fatalf("dry run %+v", res)
	}
	if _, err := restore(older, nil, true); !errors.Is(err, ErrBackupRolledBack) {
		t.Fatalf("a dry run of the backup below the counter: %v", err)
	}
	empty("the dry run")
	if pair.State() != counted {
		t.Fatalf("the dry run moved the vault to %+v", pair.State())
	}

	// 2. The restore, under a new generation. The older backup is refused
	// and leaves the volume empty for the newest.
	g2 := boot()
	if _, err := restore(older, g2, false); !errors.Is(err, ErrBackupRolledBack) {
		t.Fatalf("restoring the backup below the counter: %v", err)
	}
	empty("a refused restore")
	if res, err = restore("", g2, false); err != nil {
		t.Fatal(err)
	}
	// The restore is itself counted, one past the root's change.
	if res.Root != newest || res.Generation != 2 || res.SecuritySeq != counted.Count+1 || res.StoppedJobs != 0 || pair.State().Count != counted.Count+1 {
		t.Fatalf("restored %+v", res)
	}
	if _, err := restore("", g2, false); !errors.Is(err, ErrRestoreOverVolume) {
		t.Fatalf("a second restore onto the volume: %v", err)
	}
	serve(g2)
	got := drillView(t, r.c)
	for _, k := range slices.Sorted(maps.Keys(want)) {
		if got[k] != want[k] {
			t.Errorf("after the restore %s is\n%s\nwant\n%s", k, got[k], want[k])
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("after the restore %s is new", k)
		}
	}
	if b, err := r.c.ReadFile(s.w.ID, "root/files/memo.md"); err != nil || string(b) != memo {
		t.Fatalf("the memo after the restore: %q %v", b, err)
	}

	// The restored coordinator works. Mail it had worked isn't run again.
	r.pass()
	r.pass()
	r.runner.mu.Lock()
	again := len(r.runner.prompts) - ran
	r.runner.mu.Unlock()
	if again != 0 {
		t.Fatalf("%d jobs ran again after the restore", again)
	}
	// The draft is approved and goes out once, as it was written.
	th, err = r.c.thread(anyDevice, s.w.ID, th.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d := s.draft(th.ID, e.ID); d.State != draftPending || d.MessageID != messageID {
		t.Fatalf("the restored draft: %+v", d)
	}
	if res := s.approve(th, e, "op_ok", 1); !res.OK {
		t.Fatalf("approving the restored draft: %+v", res)
	}
	r.pass()
	if n := s.send.count(s.send.delivered, messageID); n != 1 {
		t.Fatalf("the restored draft was delivered %d times", n)
	}
	if d := s.draft(th.ID, e.ID); d.Send == nil || d.Send.State != sendSent {
		t.Fatalf("the restored draft's send: %+v", d.Send)
	}
	m := r.edge.deliver(s.mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Q4 close"})
	r.pass()
	waitJob(t, r.c, mailJobID(m))
	if r.ledger(s.w.ID).Acted[m].Outcome != outcomeJob {
		t.Fatal("mail after the restore wasn't run")
	}

	// It counts under generation 2, and generation 1 is fenced.
	tt.c = r.c
	tt.set("m_rev2", "ana", RoleReviewer, newTestDevice(t))
	if err := tt.push(me, "acme", nil); err != nil {
		t.Fatalf("a security change after the restore: %v", err)
	}
	st := pair.State()
	if st.Generation != 2 || st.Count < counted.Count+2 {
		t.Fatalf("after the restore the vault has %+v", st)
	}
	if err := counter(g1).CompareAndSwap(ctx, 1, st.Count, st.Count+1); !errors.Is(err, ErrVaultGeneration) {
		t.Fatalf("generation 1 counting after the restore: %v", err)
	}
	// Now even the backup it was restored from is a rollback.
	if _, err := restore(newest, nil, true); !errors.Is(err, ErrBackupRolledBack) {
		t.Fatalf("the restored-from backup after a counted change: %v", err)
	}
}

// drillView is what a restore must bring back: state.json as the
// coordinator holds it, less the restore's own mark, and the hash of every
// file in every worker's tree.
func drillView(t *testing.T, c *Coordinator) map[string]string {
	t.Helper()
	c.mu.Lock()
	st := *c.state
	// The restore marks the volume and counts itself, and saves it.
	st.Restored, st.SecuritySeq, st.SecurityGen, st.Saves = nil, 0, 0, 0
	state, err := json.MarshalIndent(st, "", " ")
	ids := slices.Sorted(maps.Keys(c.state.Workers))
	c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{"state.json": string(state)}
	for _, id := range ids {
		if err := c.view(id, anyDevice, func(tr *Tree) error {
			for p := range tr.manifest.Entries {
				data, err := tr.Read(p)
				if err != nil {
					return err
				}
				out[id+"/"+p] = sha256Hex(data)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	return out
}
