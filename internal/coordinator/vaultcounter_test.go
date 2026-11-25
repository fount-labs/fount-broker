package coordinator

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-vault/wire"

	"github.com/fount-labs/fount-broker/internal/mail"
	"github.com/fount-labs/fount-broker/internal/mail/mailtest"
	"github.com/fount-labs/fount-broker/internal/vaultkey/cloudvaulttest"
)

// cloudRig is vaultRig against the Cloud vault pair's real wire protocol:
// generations certified by its authority, and WireCounter.
type cloudRig struct {
	t      *testing.T
	pair   *cloudvaulttest.Pair
	states bool
	bucket *MemBucket
	key    WrappingKey
}

func (r *cloudRig) boot() *FixedGeneration {
	r.t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	cert, n, err := r.pair.Boot(pub)
	if err != nil {
		r.t.Fatal(err)
	}
	return &FixedGeneration{G: mail.Generation{Number: n, Certificate: cert, Key: priv}}
}

func (r *cloudRig) counter(g *FixedGeneration) *WireCounter {
	return &WireCounter{Client: &wire.CounterClient{Vaults: r.pair.Vaults(), Authority: r.pair.AuthorityKey(), Client: http.DefaultClient}, Gen: g, States: r.states}
}

func (r *cloudRig) open(dir string, g *FixedGeneration) *Coordinator {
	r.t.Helper()
	c, err := New(Config{
		StateDir: filepath.Join(dir, "state"), WorkDir: filepath.Join(dir, "work"),
		Store: DirStore{Root: filepath.Join(dir, "objects")}, Key: r.key, Pool: NewPool(1, 2, nil),
		Runner: LocalRunner{Command: []string{"true"}}, Audience: testAudience,
		Backup: &BackupConfig{Bucket: r.bucket, Counter: r.counter(g), Generations: g},
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return c
}

func (r *cloudRig) newest() string {
	r.t.Helper()
	return (&vaultRig{t: r.t, bucket: r.bucket}).newest()
}

func (r *cloudRig) restore(root string, g *FixedGeneration) (string, RestoreResult, error) {
	dir := r.t.TempDir()
	res, err := Restore(context.Background(), RestoreOptions{Bucket: r.bucket, Counter: r.counter(g), Generations: g, Key: r.key,
		StateDir: filepath.Join(dir, "state"), Store: DirStore{Root: filepath.Join(dir, "objects")}, Root: root})
	return dir, res, err
}

// The whole of decision 18 against the vault's wire protocol: a security
// change is counted in the vault before it's acknowledged; a lost answer is
// retried; one vault down holds changes back without retiring anyone; a
// restore boots a new generation, which fences the old coordinator at the
// vault and at the edge; and a backup below the count is refused.
func TestTheCloudVaultCountsFencesAndRefusesRollback(t *testing.T) {
	key, err := NewWrappingKey()
	if err != nil {
		t.Fatal(err)
	}
	r := &cloudRig{t: t, pair: cloudvaulttest.Start(t), bucket: NewMemBucket(), key: key}
	g1 := r.boot()
	c1 := r.open(t.TempDir(), g1)
	me, rev, rev2 := newTestDevice(t), newTestDevice(t), newTestDevice(t)
	tt := soloTeam(t, c1, "acme", me)
	if st := r.pair.State(); st != (wire.CounterState{Generation: 1, Count: 1}) {
		t.Fatalf("after the first change the vault has %+v", st)
	}
	older := r.newest()

	// The first vault takes the swap and its answer is lost; the client
	// asks the second, which answers the same swap ok.
	r.pair.LoseSwap.Store(true)
	tt.set("m_rev", "maria", RoleReviewer, rev)
	if err := tt.push(me, "acme", nil); err != nil {
		t.Fatalf("a change whose first answer was lost: %v", err)
	}
	if st := r.pair.State(); st.Count != 2 {
		t.Fatalf("the vault has %+v", st)
	}

	// One vault down: nothing is counted, and nobody is retired. The load
	// before the change already fails, so no sequence number is spent.
	r.pair.Down(1, true)
	tt.set("m_rev2", "ana", RoleReviewer, rev2)
	if err := tt.push(me, "acme", nil); !errors.Is(err, ErrNotDurable) {
		t.Fatalf("a change with one vault down: %v", err)
	}
	if c1.Retired() || r.pair.State().Count != 2 {
		t.Fatalf("one vault down: retired %t, vault %+v", c1.Retired(), r.pair.State())
	}
	r.pair.Down(1, false)
	if err := tt.push(me, "acme", nil); err != nil {
		t.Fatal(err)
	}
	counted := r.pair.State().Count
	if counted != 3 || logSeq(c1, "acme") != 3 {
		t.Fatalf("vault %d, log %d", counted, logSeq(c1, "acme"))
	}

	// A restore boots generation 2. A backup from before the removals is
	// refused; the newest is taken.
	g2 := r.boot()
	if _, _, err := r.restore(older, g2); !errors.Is(err, ErrBackupRolledBack) {
		t.Fatalf("restoring a backup below the count: %v", err)
	}
	dir2, res, err := r.restore("", g2)
	if err != nil {
		t.Fatal(err)
	}
	// The restore counts itself.
	if res.SecuritySeq != counted+1 || r.pair.State().Count != counted+1 {
		t.Fatalf("restored security change %d, counted %d", res.SecuritySeq, counted)
	}
	counted++
	c2 := r.open(dir2, g2)
	if logSeq(c2, "acme") != 3 {
		t.Fatalf("the restored log is at %d", logSeq(c2, "acme"))
	}

	// Generation 1 is fenced at the vault: its next change retires it.
	tt.set("m_rev3", "joe", RoleReviewer, newTestDevice(t))
	if err := tt.push(me, "acme", nil); !errors.Is(err, ErrStaleCoordinator) || !c1.Retired() {
		t.Fatalf("generation 1 changing after generation 2 booted: %v", err)
	}
	// Its own key can't swap under generation 2 either.
	forged := &WireCounter{Client: r.counter(nil).Client, Gen: &FixedGeneration{G: mail.Generation{Number: 2, Key: g1.G.Key}}}
	if err := forged.CompareAndSwap(context.Background(), 2, counted, counted+1); !errors.Is(err, ErrVaultGeneration) {
		t.Fatalf("generation 1's key under generation 2: %v", err)
	}
	if r.pair.State() != (wire.CounterState{Generation: 2, Count: counted}) {
		t.Fatalf("the vault has %+v", r.pair.State())
	}

	// And at the edge, which has the vault's authority key.
	edge := mailtest.NewCoordination(r.pair.AuthorityKey())
	present := func(g *FixedGeneration) int {
		body, _ := json.Marshal(map[string]string{"certificate": g.G.Certificate})
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/coordinator/generation", bytes.NewReader(body))
		ts, nonce := time.Now().Unix(), hex.EncodeToString(g.G.Key[:16])+strconv.Itoa(len(edge.Calls()))
		pub := g.G.Key.Public().(ed25519.PublicKey)
		req.Header.Set("Fount-Key-Id", hex.EncodeToString(pub))
		req.Header.Set("Fount-Timestamp", strconv.FormatInt(ts, 10))
		req.Header.Set("Fount-Nonce", nonce)
		req.Header.Set("Fount-Signature", base64.StdEncoding.EncodeToString(ed25519.Sign(g.G.Key, []byte(mail.Canonical(http.MethodPost, "/coordinator/generation", body, ts, nonce)))))
		if !edge.Serve(w, req, body, func(string) ed25519.PublicKey { return nil }) {
			t.Fatal("the edge doesn't serve /coordinator/generation")
		}
		return w.Code
	}
	if code := present(g1); code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("the edge took generation 1 with %d", code)
	}
	if code := present(g2); code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("the edge took generation 2 with %d", code)
	}
	if code := present(g1); code != http.StatusConflict || edge.Generation() != 2 {
		t.Fatalf("the edge answered generation 1 after 2 with %d, at %d", code, edge.Generation())
	}
}

// A dry run reads the counter and moves nothing.
func TestWireCounterWithoutAGenerationOnlyLoads(t *testing.T) {
	key, _ := NewWrappingKey()
	r := &cloudRig{t: t, pair: cloudvaulttest.Start(t), bucket: NewMemBucket(), key: key}
	g1 := r.boot()
	c := r.counter(nil)
	if got, err := c.Load(context.Background()); err != nil || got != (VaultCount{Generation: 1}) {
		t.Fatal(got, err)
	}
	if err := c.CompareAndSwap(context.Background(), 1, 0, 1); err == nil || errors.Is(err, ErrVaultGeneration) {
		t.Fatalf("a dry run's swap: %v", err)
	}
	if err := r.counter(g1).CompareAndSwap(context.Background(), 1, 3, 4); !errors.Is(err, ErrVaultCount) {
		t.Fatalf("a swap from the wrong count: %v", err)
	}
	r.pair.Down(0, true)
	r.pair.Down(1, true)
	if _, err := c.Load(context.Background()); err == nil || errors.Is(err, ErrVaultGeneration) || errors.Is(err, ErrVaultCount) {
		t.Fatalf("both vaults down: %v", err)
	}
}

// Counter version 2 over the wire: each count names its state and writer,
// a fork of the volume at the count is refused, and so is a fork's backup.
func TestTheCloudVaultCountsTheState(t *testing.T) {
	key, _ := NewWrappingKey()
	r := &cloudRig{t: t, pair: cloudvaulttest.Start(t), bucket: NewMemBucket(), key: key, states: true}
	dir := t.TempDir()
	c1 := r.open(dir, r.boot())
	soloTeam(t, c1, "acme", newTestDevice(t))
	st := r.pair.State()
	if st.Count != 1 || st.Writer != 1 || !wire.ValidStateDigest(st.StateDigest) {
		t.Fatalf("after the first change the vault has %+v", st)
	}
	vol, err := LoadState(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	if securityDigest(vol) != st.StateDigest {
		t.Fatal("the vault counted another state than the volume's")
	}
	vol.Teams["acme"].Rotate = []string{"w_other"}
	fork := t.TempDir()
	if err := os.MkdirAll(filepath.Join(fork, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := vol.Save(filepath.Join(fork, "state")); err != nil {
		t.Fatal(err)
	}
	g := r.boot()
	_, err = New(Config{
		StateDir: filepath.Join(fork, "state"), WorkDir: filepath.Join(fork, "work"),
		Store: DirStore{Root: filepath.Join(fork, "objects")}, Key: r.key, Pool: NewPool(1, 2, nil),
		Runner: LocalRunner{Command: []string{"true"}}, Audience: testAudience,
		Backup: &BackupConfig{Bucket: r.bucket, Counter: r.counter(g), Generations: g},
	})
	if !errors.Is(err, ErrVolumeRolledBack) {
		t.Fatalf("a fork of the volume at the count: %v", err)
	}
	// The restore of the real backup counts itself under the new writer.
	if _, res, err := r.restore("", g); err != nil || res.SecuritySeq != 2 {
		t.Fatalf("restoring the counted backup: %+v %v", res, err)
	}
	if st := r.pair.State(); st.Count != 2 || st.Writer != g.G.Number {
		t.Fatalf("after the restore the vault has %+v", st)
	}
}
