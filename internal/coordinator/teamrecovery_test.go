package coordinator

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// recoveryFixture is the fixture's team with the owner its only admin, with
// a passkey and a listed device, and a laptop the passkey added: the owner
// lost the listed one. at moves the coordinator's clock.
type recoveryFixture struct {
	teamFixture
	pk     testPasskey
	laptop testDevice
	at     *time.Time
}

func newRecoveryFixture(t *testing.T) recoveryFixture {
	t.Helper()
	f := newTeamFixture(t)
	at := time.Now()
	f.c.setClock(func() time.Time { return at })
	pk := newTestPasskey(t)
	f.tt.update("m_owner", func(m *ListMember) { m.Rec = pk.rec(t) })
	f.tt.update("m_admin", func(m *ListMember) { m.Role, m.Workers = RoleReviewer, []string{allWorkers} })
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	laptop := newTestDevice(t)
	ownerPasskeyJoin(t, f, pk, laptop)
	r := recoveryFixture{teamFixture: f, pk: pk, laptop: laptop, at: &at}
	if err := r.pushAs(laptop, "acme", []testDevice{f.owner, laptop}); !errors.Is(err, ErrNotAdmin) {
		t.Fatalf("a passkey-joined device with the owner's listed one: %v", err)
	}
	return r
}

// wait moves the coordinator's clock by d and counts d into the open
// recoveries' waits, as Run's ticks do while d passes.
func (r recoveryFixture) wait(d time.Duration) {
	*r.at = r.at.Add(d)
	r.c.mu.Lock()
	defer r.c.mu.Unlock()
	for ; d > 0; d -= recoveryTickEvery {
		r.c.countRecoveryWaits(min(d, recoveryTickEvery))
	}
}

// cancel is Cancel on the recovery from the owner's listed device: the list
// drops the laptop and the passkey that added it.
func (r recoveryFixture) cancel() error {
	r.tt.update("m_owner", func(m *ListMember) { m.Rec = nil })
	return r.pushAs(r.owner, "acme", []testDevice{r.owner})
}

// start has d start a recovery for its member over the log's head.
func (r recoveryFixture) start(t *testing.T, d testDevice, account, member string) error {
	t.Helper()
	_, head := r.tt.head()
	msg, err := RecoveryChallenge(testAudience, "acme", member, head, d.id())
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.c.StartRecovery(d.caller(account), "acme", RecoveryRequest{Prev: head, Sig: b64.EncodeToString(ed25519.Sign(d.key, msg))})
	return err
}

// pushAs signs the next list as by, now by the coordinator's clock, with the
// owner's devices set to owner's.
func (r recoveryFixture) pushAs(by testDevice, account string, owner []testDevice) error {
	r.tt.devices["m_owner"] = owner
	seq, _ := r.tt.head()
	for _, d := range owner {
		if _, ok := r.tt.since[d.id()]; !ok && d.id() == r.laptop.id() {
			r.tt.since[d.id()] = r.laptopSeq(seq)
		}
	}
	l := r.tt.list()
	l.Iat = r.at.Unix()
	return r.tt.pushList(by.caller(account), by.sign(r.tt.t, l), l, nil)
}

// laptopSeq is the entry that admitted the laptop.
func (r recoveryFixture) laptopSeq(head uint64) uint64 {
	r.c.mu.Lock()
	defer r.c.mu.Unlock()
	st, _ := r.c.teamState("acme")
	if d, m := st.device(r.laptop.id()); m != nil {
		return d.Since
	}
	return head + 1
}

func TestARecoveringDeviceSignsAfterTheDelayAndDropsTheLostOne(t *testing.T) {
	r := newRecoveryFixture(t)
	if err := r.start(t, r.laptop, "acme", "m_owner"); err != nil {
		t.Fatalf("starting a recovery: %v", err)
	}
	r.wait(RecoveryDelay - time.Minute)
	if err := r.pushAs(r.laptop, "acme", []testDevice{r.laptop}); !errors.Is(err, ErrNotAdmin) {
		t.Fatalf("before the delay: %v", err)
	}
	r.wait(2 * time.Minute)
	if err := r.pushAs(r.laptop, "acme", []testDevice{r.laptop}); err != nil {
		t.Fatalf("after the delay, dropping the lost device: %v", err)
	}
	if err := r.pushAs(r.owner, "acme", []testDevice{r.owner, r.laptop}); !errors.Is(err, ErrNotAdmin) {
		t.Fatalf("the lost device after it was dropped: %v", err)
	}
	if err := r.pushAs(r.laptop, "acme", []testDevice{r.laptop}); err != nil {
		t.Fatalf("the recovered device, listed now: %v", err)
	}
}

// Security review 2026-11-24, M3 (TestProbeRecoveryClockRollbackSkipsDelay,
// flipped): on a team quiet for 8 days, the coordinator's clock is set back
// for the one request that writes the recovery-start, so its at is the last
// entry's time. By at, iat and the clock the wait is over a minute later; by
// the coordinator's own count it has just begun.
func TestABackdatedClockDoesntShortenARecovery(t *testing.T) {
	r := newRecoveryFixture(t)
	quiet := *r.at
	r.wait(8 * 24 * time.Hour)
	real := *r.at
	*r.at = quiet
	if err := r.start(t, r.laptop, "acme", "m_owner"); err != nil {
		t.Fatalf("starting a recovery under a clock set back: %v", err)
	}
	*r.at = real
	r.wait(time.Minute)
	if err := r.pushAs(r.laptop, "acme", []testDevice{r.laptop}); !errors.Is(err, ErrNotAdmin) {
		t.Fatalf("a minute after a backdated recovery-start: %v", err)
	}
	r.wait(RecoveryDelay - 2*time.Minute)
	if err := r.pushAs(r.laptop, "acme", []testDevice{r.laptop}); !errors.Is(err, ErrNotAdmin) {
		t.Fatalf("a minute short of the counted wait: %v", err)
	}
	r.wait(2 * time.Minute)
	if err := r.pushAs(r.laptop, "acme", []testDevice{r.laptop}); err != nil {
		t.Fatalf("after the counted wait: %v", err)
	}
}

// A clock set forward ends no wait either, and one tick counts at most
// recoveryTickEvery however far the monotonic clock leapt.
func TestAClockSetForwardDoesntEndARecovery(t *testing.T) {
	r := newRecoveryFixture(t)
	if err := r.start(t, r.laptop, "acme", "m_owner"); err != nil {
		t.Fatal(err)
	}
	*r.at = r.at.Add(RecoveryDelay + time.Hour)
	r.c.tickRecoveryWaits(time.Now())
	r.c.tickRecoveryWaits(time.Now().Add(RecoveryDelay + time.Hour))
	if err := r.pushAs(r.laptop, "acme", []testDevice{r.laptop}); !errors.Is(err, ErrNotAdmin) {
		t.Fatalf("a clock and a monotonic clock that leapt a week: %v", err)
	}
	if w := r.team(t).RecoveryWaits["m_owner"]; w == nil || w.Waited != recoveryTickEvery {
		t.Fatalf("the counted wait after one leap: %+v", w)
	}
}

// The 2026-11-25 re-review's N2 probe, flipped: a host that leaps the
// guest's monotonic clock 2 minutes before every tick used to gain 2
// minutes a tick, 24 times real time. Now each tick counts at most
// recoveryTickEvery, so over a day of such ticks the wait counts at most a
// day: the rate is the ticker's, about 1x, not the clock's.
func TestALeapingClockCountsNoFasterThanTheTicks(t *testing.T) {
	r := newRecoveryFixture(t)
	if err := r.start(t, r.laptop, "acme", "m_owner"); err != nil {
		t.Fatal(err)
	}
	mono := time.Now()
	r.c.tickRecoveryWaits(mono)
	ticks := int(24 * time.Hour / recoveryTickEvery)
	for range ticks {
		mono = mono.Add(2 * time.Minute)
		r.c.tickRecoveryWaits(mono)
	}
	w := r.team(t).RecoveryWaits["m_owner"]
	if real := time.Duration(ticks) * recoveryTickEvery; w == nil || w.Waited > real {
		t.Fatalf("%d ticks a day apart counted %+v, over the %s they took", ticks, w, real)
	}
	// Ticks that come late count as one tick each: the wait runs slow.
	before := w.Waited
	mono = mono.Add(time.Hour)
	r.c.tickRecoveryWaits(mono)
	if got := r.team(t).RecoveryWaits["m_owner"].Waited - before; got != recoveryTickEvery {
		t.Fatalf("a tick an hour late counted %s", got)
	}
}

// The counted wait is kept in the state, so a restart doesn't reset it, and
// it is forgotten once a list ends its recovery.
func TestARecoveryWaitIsKeptAndForgotten(t *testing.T) {
	r := newRecoveryFixture(t)
	if err := r.start(t, r.laptop, "acme", "m_owner"); err != nil {
		t.Fatal(err)
	}
	r.wait(recoverySaveEvery)
	loaded, err := LoadState(r.c.cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if w := loaded.Teams["acme"].RecoveryWaits["m_owner"]; w == nil || w.Waited != recoverySaveEvery {
		t.Fatalf("the saved wait: %+v", w)
	}
	if err := r.cancel(); err != nil {
		t.Fatal(err)
	}
	r.wait(time.Minute)
	if w := r.team(t).RecoveryWaits; len(w) != 0 {
		t.Fatalf("waits after a list ended the recovery: %v", w)
	}
}

// The list's iat counts as well as the coordinator's clock: a list signed
// before the delay is refused even if it arrives after.
func TestARecoveringDevicesListMustBeSignedAfterTheDelay(t *testing.T) {
	r := newRecoveryFixture(t)
	if err := r.start(t, r.laptop, "acme", "m_owner"); err != nil {
		t.Fatal(err)
	}
	r.wait(RecoveryDelay + time.Minute)
	r.tt.devices["m_owner"] = []testDevice{r.laptop}
	r.tt.since[r.laptop.id()] = r.laptopSeq(0)
	l := r.tt.list()
	l.Iat = r.at.Add(-2 * time.Minute).Unix()
	if err := r.tt.pushList(r.laptop.caller("acme"), r.laptop.sign(t, l), l, nil); !errors.Is(err, ErrNotAdmin) {
		t.Fatalf("a list signed before the delay: %v", err)
	}
}

func TestAListedDeviceCancelsARecoveryByRemovingTheDevice(t *testing.T) {
	r := newRecoveryFixture(t)
	if err := r.start(t, r.laptop, "acme", "m_owner"); err != nil {
		t.Fatal(err)
	}
	r.wait(time.Hour)
	// Security review 2026-11-24, M4: Cancel revokes the passkey that added
	// the device, in the same list, or the passkey would add it straight
	// back.
	if err := r.pushAs(r.owner, "acme", []testDevice{r.owner}); !errors.Is(err, ErrListRefused) || !strings.Contains(err.Error(), "keeps that passkey") {
		t.Fatalf("cancelling a recovery but keeping the passkey: %v", err)
	}
	if err := r.cancel(); err != nil {
		t.Fatalf("the owner's listed device removing the recovering one: %v", err)
	}
	r.wait(RecoveryDelay)
	if err := r.pushAs(r.laptop, "acme", []testDevice{r.laptop}); !errors.Is(err, ErrNotAdmin) {
		t.Fatalf("a removed recovering device: %v", err)
	}
	again := newTestDevice(t)
	if _, err := r.c.StartPasskeyJoin(again.caller("acme"), "acme", again.pub(), again.enc.PublicKey().Bytes()); !errors.Is(err, ErrNoPasskey) {
		t.Fatalf("the revoked passkey joining again: %v", err)
	}

	// An admin lists the passkey again: it adds the device back, the old
	// recovery is gone, and a new one waits again from its own start.
	r.tt.devices["m_owner"] = []testDevice{r.owner}
	r.tt.update("m_owner", func(m *ListMember) { m.Rec = r.pk.rec(t) })
	if err := r.pushAs(r.owner, "acme", []testDevice{r.owner}); err != nil {
		t.Fatal(err)
	}
	ownerPasskeyJoin(t, r.teamFixture, r.pk, again)
	r.laptop = again
	if err := r.pushAs(again, "acme", []testDevice{again}); !errors.Is(err, ErrNotAdmin) {
		t.Fatalf("a device re-added after a cancelled recovery: %v", err)
	}
	if err := r.start(t, again, "acme", "m_owner"); err != nil {
		t.Fatal(err)
	}
	r.wait(RecoveryDelay / 2)
	if err := r.pushAs(again, "acme", []testDevice{again}); !errors.Is(err, ErrNotAdmin) {
		t.Fatalf("a new recovery half way: %v", err)
	}
}

// A list that includes the recovering device ends its recovery too: it is
// listed, and signs as any listed device.
func TestAListIncludingTheRecoveringDeviceEndsItsRecovery(t *testing.T) {
	r := newRecoveryFixture(t)
	if err := r.start(t, r.laptop, "acme", "m_owner"); err != nil {
		t.Fatal(err)
	}
	if err := r.pushAs(r.owner, "acme", []testDevice{r.owner, r.laptop}); err != nil {
		t.Fatal(err)
	}
	r.c.mu.Lock()
	st, _ := r.c.teamState("acme")
	open := len(st.recoveries)
	r.c.mu.Unlock()
	if open != 0 {
		t.Fatal("a list left a recovery open")
	}
	if err := r.pushAs(r.laptop, "acme", []testDevice{r.owner, r.laptop}); err != nil {
		t.Fatal(err)
	}
}

func TestOneRecoveryIsOpenPerMember(t *testing.T) {
	r := newRecoveryFixture(t)
	if err := r.start(t, r.laptop, "acme", "m_owner"); err != nil {
		t.Fatal(err)
	}
	if err := r.start(t, r.laptop, "acme", "m_owner"); !errors.Is(err, ErrListRefused) {
		t.Fatalf("the same device again: %v", err)
	}
	phone := newTestDevice(t)
	ownerPasskeyJoin(t, r.teamFixture, r.pk, phone)
	if err := r.start(t, phone, "acme", "m_owner"); !errors.Is(err, ErrListRefused) {
		t.Fatalf("another device of the member while one is open: %v", err)
	}
}

func TestOnlyAPasskeyAddedAdminDeviceStartsARecovery(t *testing.T) {
	r := newRecoveryFixture(t)
	// A listed device needs none.
	if err := r.start(t, r.owner, "acme", "m_owner"); !errors.Is(err, ErrListRefused) {
		t.Fatalf("a listed device: %v", err)
	}
	// A reviewer's passkey-added device.
	pk := newTestPasskey(t)
	r.tt.update("m_reviewer", func(m *ListMember) { m.Rec = pk.rec(t) })
	if err := r.pushAs(r.owner, "acme", []testDevice{r.owner, r.laptop}); err != nil {
		t.Fatal(err)
	}
	tab := newTestDevice(t)
	ch, err := r.c.StartPasskeyJoin(tab.caller("maria"), "acme", tab.pub(), tab.enc.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.PasskeyJoin(tab.caller("maria"), "acme", pk.request(t, ch, mustB64(t, ch.Challenge), tab, "acme", "maria", ceremony{})); err != nil {
		t.Fatal(err)
	}
	if err := r.start(t, tab, "maria", "m_reviewer"); !errors.Is(err, ErrListRefused) {
		t.Fatalf("a reviewer's device: %v", err)
	}
	// A device that isn't the team's.
	stranger := newTestDevice(t)
	if err := r.start(t, stranger, "acme", "m_owner"); !errors.Is(err, ErrListRefused) {
		t.Fatalf("a device the team doesn't admit: %v", err)
	}
}

// With no admin left with a listed device, the passkey's device signs at
// once, so a recovery is refused as needless.
func TestNoRecoveryWhenNoAdminHasAListedDevice(t *testing.T) {
	f := newTeamFixture(t)
	pk := newTestPasskey(t)
	f.tt.update("m_owner", func(m *ListMember) { m.Rec = pk.rec(t) })
	f.tt.update("m_admin", func(m *ListMember) { m.Role, m.Workers = RoleReviewer, []string{allWorkers} })
	f.tt.devices["m_owner"] = nil
	if err := f.tt.push(f.owner, "acme", nil); err != nil {
		t.Fatal(err)
	}
	desk := newTestDevice(t)
	ownerPasskeyJoin(t, f, pk, desk)
	r := recoveryFixture{teamFixture: f, laptop: desk, at: new(time.Time)}
	if err := r.start(t, desk, "acme", "m_owner"); !errors.Is(err, ErrListRefused) {
		t.Fatalf("a recovery with no listed admin: %v", err)
	}
}

func TestARecoveryStartCantBeReplayedOrForged(t *testing.T) {
	r := newRecoveryFixture(t)
	_, head := r.tt.head()
	msg, _ := RecoveryChallenge(testAudience, "acme", "m_owner", head, r.laptop.id())
	sig := b64.EncodeToString(ed25519.Sign(r.laptop.key, msg))

	// Signed by another key.
	other := newTestDevice(t)
	forged := b64.EncodeToString(ed25519.Sign(other.key, msg))
	if _, err := r.c.StartRecovery(r.laptop.caller("acme"), "acme", RecoveryRequest{Prev: head, Sig: forged}); !errors.Is(err, ErrListRefused) {
		t.Fatalf("a signature by another key: %v", err)
	}
	if _, err := r.c.StartRecovery(r.laptop.caller("acme"), "acme", RecoveryRequest{Prev: head, Sig: sig}); err != nil {
		t.Fatal(err)
	}
	// The same signature again: its head is gone.
	if _, err := r.c.StartRecovery(r.laptop.caller("acme"), "acme", RecoveryRequest{Prev: head, Sig: sig}); !errors.Is(err, ErrTeamStale) {
		t.Fatalf("a replayed recovery: %v", err)
	}
	// After a list ends it, the old signature is still over an old head.
	if err := r.pushAs(r.owner, "acme", []testDevice{r.owner, r.laptop}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.StartRecovery(r.laptop.caller("acme"), "acme", RecoveryRequest{Prev: head, Sig: sig}); !errors.Is(err, ErrTeamStale) {
		t.Fatalf("a recovery reused after a list: %v", err)
	}
}

// On replay, a recovery-start whose time falls before the entry before it is
// refused: the coordinator can't backdate one past the log.
func TestABackdatedRecoveryStartBreaksTheLog(t *testing.T) {
	r := newRecoveryFixture(t)
	r.wait(time.Hour)
	if err := r.start(t, r.laptop, "acme", "m_owner"); err != nil {
		t.Fatal(err)
	}
	team := r.team(t)
	log := append([]TeamEntry(nil), team.Log...)
	last := log[len(log)-1]
	var rec TeamRecord
	if err := json.Unmarshal(last.Record, &rec); err != nil {
		t.Fatal(err)
	}
	if _, err := reduceTeam("acme", testAudience, log); err != nil {
		t.Fatalf("the log as kept: %v", err)
	}
	rec.At -= int64(RecoveryDelay / time.Second)
	payload, _ := json.Marshal(rec)
	log[len(log)-1] = TeamEntry{Seq: last.Seq, Record: payload, Hash: entryHash(TeamRecordContext, payload)}
	if _, err := reduceTeam("acme", testAudience, log); err == nil {
		t.Fatal("a backdated recovery-start replayed")
	}
}

// A recovery's notice goes to the owner and each admin, with how to cancel.
func TestARecoveryNoticeGoesToTheOwnerAndTheAdmins(t *testing.T) {
	r := newSendRig(t, modeNotify)
	ctx := context.Background()
	for _, to := range []string{"", "ann@example.com", "dana@example.com"} {
		if err := r.c.notify(ctx, "acct/recovery_started/7/"+to, noticeRecoveryStarted, r.w.Account, r.w.ID, time.Time{}, to); err != nil {
			t.Fatal(err)
		}
	}
	r.pass()
	for _, to := range []string{"dana@example.com", "ann@example.com"} {
		sent := r.send.sentTo(to, "Someone is recovering access to Acme")
		if len(sent) != 1 || !strings.Contains(string(r.send.raw[sent[0]]), "If this wasn't you, cancel it") || !strings.Contains(string(r.send.raw[sent[0]]), "Cancelling also turns that passkey off") {
			t.Fatalf("%s: %v", to, sent)
		}
	}
}
