package mail

import (
	"fmt"
	"maps"
	"slices"
)

// Ledger accounts for one mailbox's sequence numbers (design §9). Every number
// from 1 up to the highest one seen must end up either delivered (a message
// with a valid signature was fetched) or accounted (a signed gap record). One
// that is neither is missing, which is how withheld mail shows. A number seen
// twice for different messages means the edge's counter was rolled back.
type Ledger struct {
	// Delivered maps a sequence to the edge id of the message that held it.
	Delivered map[uint64]string `json:"delivered"`
	// Accounted maps a sequence to the edge id and reason of its gap record.
	Accounted map[uint64]Accounted `json:"accounted"`
	// Anomalies are permanent: once seen, they stay until the user resolves them
	// in the app.
	Anomalies []Anomaly `json:"anomalies"`
}

type Accounted struct {
	EdgeID string `json:"edge_id"`
	Reason string `json:"reason"`
}

// Anomaly is something only a misbehaving edge or storage host causes.
type Anomaly struct {
	Kind     string `json:"kind"`
	Sequence uint64 `json:"sequence,omitempty"`
	Detail   string `json:"detail"`
}

const (
	AnomalyReuse     = "sequence_reused"
	AnomalyWrongKey  = "wrong_public_key"
	AnomalyBadRecord = "bad_gap_record"
)

func newLedger() *Ledger {
	return &Ledger{Delivered: map[uint64]string{}, Accounted: map[uint64]Accounted{}}
}

func (l *Ledger) anomaly(a Anomaly) {
	if !slices.Contains(l.Anomalies, a) {
		l.Anomalies = append(l.Anomalies, a)
	}
}

// Deliver records a verified message. It reports false if the sequence already
// belonged to another message, or to a gap record for another message.
func (l *Ledger) Deliver(seq uint64, edgeID string) bool {
	if prev, ok := l.Delivered[seq]; ok && prev != edgeID {
		l.anomaly(Anomaly{Kind: AnomalyReuse, Sequence: seq, Detail: fmt.Sprintf("messages %s and %s both hold this sequence", prev, edgeID)})
		return false
	}
	if a, ok := l.Accounted[seq]; ok && a.EdgeID != edgeID {
		l.anomaly(Anomaly{Kind: AnomalyReuse, Sequence: seq, Detail: fmt.Sprintf("message %s holds a sequence a %s record gave to %s", edgeID, a.Reason, a.EdgeID)})
		return false
	}
	l.Delivered[seq] = edgeID
	return true
}

// Account records a verified gap record, with the same reuse check.
func (l *Ledger) Account(r GapRecord) bool {
	if prev, ok := l.Delivered[r.Sequence]; ok && prev != r.EdgeID {
		l.anomaly(Anomaly{Kind: AnomalyReuse, Sequence: r.Sequence, Detail: fmt.Sprintf("a %s record names %s, but message %s holds this sequence", r.Reason, r.EdgeID, prev)})
		return false
	}
	if prev, ok := l.Accounted[r.Sequence]; ok && prev.EdgeID != r.EdgeID {
		l.anomaly(Anomaly{Kind: AnomalyReuse, Sequence: r.Sequence, Detail: fmt.Sprintf("two records name %s and %s", prev.EdgeID, r.EdgeID)})
		return false
	}
	l.Accounted[r.Sequence] = Accounted{EdgeID: r.EdgeID, Reason: r.Reason}
	return true
}

// High is the highest sequence the ledger knows of.
func (l *Ledger) High() uint64 {
	var hi uint64
	for s := range l.Delivered {
		hi = max(hi, s)
	}
	for s := range l.Accounted {
		hi = max(hi, s)
	}
	return hi
}

// Floor is the highest sequence below which every number is resolved. GET /gaps
// pages from it.
func (l *Ledger) Floor() uint64 {
	var f uint64
	for l.resolved(f + 1) {
		f++
	}
	return f
}

func (l *Ledger) resolved(seq uint64) bool {
	_, d := l.Delivered[seq]
	_, a := l.Accounted[seq]
	return d || a
}

// Missing lists the unresolved numbers below High, lowest first, up to limit.
func (l *Ledger) Missing(limit int) []uint64 {
	out := []uint64{}
	for s := l.Floor() + 1; s < l.High() && len(out) < limit; s++ {
		if !l.resolved(s) {
			out = append(out, s)
		}
	}
	return out
}

// merge folds in a ledger the app saved earlier. Facts from both are kept, so a
// restored copy can only add what this one lacks; a conflict becomes an anomaly.
func (l *Ledger) merge(o *Ledger) {
	for _, s := range slices.Sorted(maps.Keys(o.Delivered)) {
		l.Deliver(s, o.Delivered[s])
	}
	for _, s := range slices.Sorted(maps.Keys(o.Accounted)) {
		a := o.Accounted[s]
		l.Account(GapRecord{Sequence: s, EdgeID: a.EdgeID, Reason: a.Reason})
	}
	for _, a := range o.Anomalies {
		l.anomaly(a)
	}
}
