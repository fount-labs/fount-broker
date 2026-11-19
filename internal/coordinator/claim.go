package coordinator

import (
	"fmt"
	"time"
)

// A claim is a label (launch-plan decision 27): "Maria is reviewing" on a
// draft's row, for claimLifetime. It clears the other reviewers' notices of
// the draft and blocks nothing: anyone may still approve, and the first
// approval wins (decision 5). A claim on a claimed draft takes it over.
//
//	claimDraft    {draftId}
//	releaseClaim  {draftId}   the claimer's own; anyone else's is left

const claimLifetime = 30 * time.Minute

// draftClaim is who claimed a draft, until when.
type draftClaim struct {
	By        string    `json:"by"`
	Member    string    `json:"member,omitempty"`
	Device    string    `json:"device"`
	At        time.Time `json:"at"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type claimArgs struct {
	DraftID string `json:"draftId"`
	release bool
}

// parseClaimOp decodes claimDraft and releaseClaim, or reports the kind
// isn't one.
func parseClaimOp(env opEnvelope) (any, bool, error) {
	if env.Kind != "claimDraft" && env.Kind != "releaseClaim" {
		return nil, false, nil
	}
	var a claimArgs
	if err := decodeArgs(env.Args, &a); err != nil {
		return nil, true, err
	}
	a.release = env.Kind == "releaseClaim"
	return a, true, checkID("draft", a.DraftID)
}

func (a claimArgs) applyDraft(c *Coordinator, _ *Tree, th *threadRecord, device string, rev uint64, now time.Time) ([]string, effects, error) {
	e, err := pendingDraftEntry(th, a.DraftID)
	if err != nil {
		return nil, effects{}, err
	}
	d := e.Draft
	if a.release {
		if d.Claim == nil || d.Claim.Device != device {
			return nil, effects{}, nil
		}
		d.Claim, e.Rev = nil, rev
		return []string{e.ID}, effects{}, nil
	}
	cl := &draftClaim{By: c.approverName(th.WorkerID, device), Device: device, At: now, ExpiresAt: now.Add(claimLifetime)}
	if m := c.memberOf(th.WorkerID, device); m != nil {
		cl.Member = m.ID
	}
	if d.Claim.active(now) && d.Claim.Device != device {
		if err := th.event(rev, now, "claim_taken", map[string]string{"draftId": e.ID, "from": d.Claim.By, "to": cl.By}); err != nil {
			return nil, effects{}, fmt.Errorf("claim: %w", err)
		}
	}
	d.Claim, e.Rev = cl, rev
	return []string{e.ID}, effects{}, nil
}

// active says cl is a claim still in force at now.
func (cl *draftClaim) active(now time.Time) bool {
	return cl != nil && now.Before(cl.ExpiresAt)
}

// hideExpiredClaims drops, from a thread about to be shown, claims past their
// time: a claim lapses by itself, with no write.
func hideExpiredClaims(th *threadRecord, now time.Time) {
	for i := range th.Entries {
		if d := th.Entries[i].Draft; d != nil && d.Claim != nil && !d.Claim.active(now) {
			d.Claim = nil
		}
	}
}
