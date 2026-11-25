package coordinator

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"maps"
	"slices"
)

const securityDigestLabel = "fount-coordinator-security/v1\x00"

// securityDigest is what the vault's count binds a volume to (broker review
// H2): the security sequence, the generation that made it, and every team's
// log head and rotation marks, and each worker's tree version at its last
// counted change (countedtree.go). Those change only through commitSecurity,
// so a plain Save (billing, mints, workers, jobs, recovery waits) leaves it
// as counted; anything a plain Save writes must stay out of it, or the next
// boot reads that volume as a fork. A log's entries chain by hash, so its
// length and last hash commit to it.
func securityDigest(st *State) string {
	h := sha256.New()
	h.Write([]byte(securityDigestLabel))
	u := func(n uint64) { h.Write(binary.BigEndian.AppendUint64(nil, n)) }
	s := func(v string) { u(uint64(len(v))); h.Write([]byte(v)) }
	u(st.SecuritySeq)
	u(st.SecurityGen)
	ids := slices.Sorted(maps.Keys(st.Teams))
	u(uint64(len(ids)))
	for _, id := range ids {
		t := st.Teams[id]
		s(id)
		u(uint64(len(t.Log)))
		head := ""
		if len(t.Log) > 0 {
			head = t.Log[len(t.Log)-1].Hash
		}
		s(head)
		u(uint64(len(t.Rotate)))
		for _, w := range t.Rotate {
			s(w)
		}
	}
	// Appended only when there are any, so a state counted before workers'
	// changes were has the digest it was counted with.
	if len(st.Counted) > 0 {
		s("counted")
		workers := slices.Sorted(maps.Keys(st.Counted))
		u(uint64(len(workers)))
		for _, id := range workers {
			s(id)
			u(st.Counted[id])
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// countState moves the vault's count from prev to st's sequence, bound to
// st when the counter keeps states.
func countState(ctx context.Context, counter VaultCounter, generation, prev uint64, st *State) error {
	if sc, ok := counter.(StateCounter); ok {
		return sc.CompareAndSwapState(ctx, generation, prev, st.SecuritySeq, securityDigest(st))
	}
	return counter.CompareAndSwap(ctx, generation, prev, st.SecuritySeq)
}

// sameState is whether st is the state the vault counted at count: always
// when the vault keeps no digest for it.
func sameState(count VaultCount, st *State) bool {
	return count.Digest == "" || (st.SecuritySeq == count.Count && securityDigest(st) == count.Digest)
}
