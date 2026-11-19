package coordinator

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// The restore drill ("Durable storage" step 2): a reply in flight, a backup
// from before it went out and before more mail was worked, the volume lost,
// the edge rebooted, the backup restored under a new generation. The reply
// goes out once, nothing runs twice, mail is fetched again, and the lost
// coordinator, still running somewhere, is stopped.
func TestTheRestoreDrill(t *testing.T) {
	ctx := context.Background()
	r := newMailRig(t, MailConfig{})
	v := newVaultRig(t, r.edge.authority)
	v.key = r.key
	g1 := v.next()
	r.backup = v.backups(g1)
	r.cfg = MailConfig{Send: true, Generations: g1}
	r.start()
	if !r.c.startGeneration(ctx) {
		t.Fatal("the generation wasn't presented")
	}
	s := sendRigOn(t, r, modeNotify)
	me := newTestDevice(t)
	soloTeam(t, r.c, "acme", me)

	// A reply approved and about to go.
	th, e := s.drafted()
	if res := s.approve(th, e, "op_ok", 1); !res.OK {
		t.Fatalf("approve: %+v", res)
	}
	b1, err := r.c.Backup(ctx)
	if err != nil || b1 == "" {
		t.Fatalf("backup: %q %v", b1, err)
	}
	messageID := s.draft(th.ID, e.ID).MessageID
	// It goes out, and the coordinator stops before it records so.
	r.store.arm()
	r.pass()
	if n := s.send.count(s.send.delivered, messageID); n != 1 {
		t.Fatalf("delivered %d times before the loss", n)
	}
	// More mail is worked after the backup.
	m2 := r.edge.deliver(s.mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Q4 close"})
	r.pass()
	waitJob(t, r.c, mailJobID(m2))
	if r.ledger(s.w.ID).Acted[m2].Outcome != outcomeJob {
		t.Fatal("the second email wasn't run")
	}
	r.runner.mu.Lock()
	ran := len(r.runner.prompts)
	r.runner.mu.Unlock()
	lost := r.c

	// The volume is lost; the edge reboots, keeping its mail and sent
	// records.
	r.dir = t.TempDir()
	r.store = &crashStore{Store: DirStore{Root: filepath.Join(r.dir, "objects")}}
	before := r.edge.listCalls(s.mb.MailboxID)
	old := r.edge.srv
	r.edge.srv = httptest.NewServer(http.HandlerFunc(r.edge.serve))
	t.Cleanup(r.edge.srv.Close)
	old.Close()

	g2 := v.next()
	res, err := Restore(ctx, RestoreOptions{Bucket: v.bucket, Counter: v.vault, Generations: g2, Key: r.key,
		StateDir: filepath.Join(r.dir, "state"), Store: r.store, Root: b1})
	if err != nil {
		t.Fatal(err)
	}
	if res.Root != b1 || res.Workers != 1 {
		t.Fatalf("restored %+v", res)
	}
	r.backup = v.backups(g2)
	r.cfg.Generations = g2
	r.cancel = nil // the lost coordinator keeps running
	r.start()
	if !r.c.startGeneration(ctx) {
		t.Fatal("the restored coordinator's generation wasn't presented")
	}
	r.pass()
	r.pass()

	// The reply went out once: the journal asked the edge first.
	if n := s.send.count(s.send.delivered, messageID); n != 1 {
		t.Fatalf("delivered %d times, want once", n)
	}
	if n := s.send.count(s.send.posts, messageID); n != 1 {
		t.Fatalf("posted %d times: the restored coordinator should have asked first", n)
	}
	if d := s.draft(th.ID, e.ID); d.Send.State != sendSent {
		t.Fatalf("after the restore: %+v", d.Send)
	}
	// The mail was fetched again; the email worked after the backup is
	// held for a person, not run again.
	if r.edge.listCalls(s.mb.MailboxID) <= before {
		t.Fatal("the mailbox wasn't listed again")
	}
	acted, ok := r.ledger(s.w.ID).Acted[m2]
	if !ok || acted.Outcome == outcomeJob {
		t.Fatalf("the second email after the restore: %+v %v", acted, ok)
	}
	r.runner.mu.Lock()
	again := len(r.runner.prompts) - ran
	r.runner.mu.Unlock()
	if again != 0 {
		t.Fatalf("%d jobs ran again", again)
	}
	// Mail after the restore runs as ever.
	m3 := r.edge.deliver(s.mb, email{from: "dana@example.com", to: testWorkerAddr, subject: "Q1 close"})
	r.pass()
	if r.ledger(s.w.ID).Acted[m3].Outcome != outcomeJob {
		t.Fatal("new mail after the restore wasn't run")
	}
	waitJob(t, r.c, mailJobID(m3))

	// The lost coordinator stops at the edge's fence and the vault's.
	lost.mail.mu.Lock()
	lost.mail.lastSweep = lost.mail.lastSweep.AddDate(-1, 0, 0)
	lost.mail.mu.Unlock()
	lost.mailPass(ctx, lost.mail.lastSweep.AddDate(2, 0, 0))
	if !lost.Retired() {
		t.Fatal("the lost coordinator kept going after the edge's fence")
	}
	if err := soloTeamErr(t, lost, "acme2", newTestDevice(t)); !errors.Is(err, ErrStaleCoordinator) {
		t.Fatalf("the lost coordinator appended: %v", err)
	}
	if v.count().Generation != 2 {
		t.Fatalf("the vault has %+v", v.count())
	}
	srv := httptest.NewServer(lost.AccountHandler(me.caller("acme")))
	defer srv.Close()
	if code, _ := do(t, srv, "GET", "/v1/teams/acme/log", ""); code != http.StatusServiceUnavailable {
		t.Fatalf("the lost coordinator served: %d", code)
	}
}

func soloTeamErr(t *testing.T, c *Coordinator, account string, me testDevice) error {
	tt := newTestTeam(t, c, account)
	tt.set("m_owner", account, RoleAdmin, me)
	return tt.push(me, account, nil)
}

// A restore fails the turns the backup owed instead of running them: they
// may have run since.
func TestARestoreFailsTheJobsTheBackupOwed(t *testing.T) {
	v := newVaultRig(t, nil)
	c := v.boot(t.TempDir())
	w, err := c.CreateWorker("acct_1", nil)
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.state.Seq++
	c.state.Jobs["job_q"] = &Job{ID: "job_q", WorkerID: w.ID, Seq: c.state.Seq, State: JobRunning}
	err = c.state.Save(c.cfg.StateDir)
	c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Backup(context.Background()); err != nil {
		t.Fatal(err)
	}
	restored, res, err := v.restore("")
	if err != nil {
		t.Fatal(err)
	}
	j, err := restored.Job("job_q")
	if err != nil || j.State != JobFailed || j.Error != restoredJobError || res.StoppedJobs != 1 {
		t.Fatalf("job %+v %v, result %+v", j, err, res)
	}
}
