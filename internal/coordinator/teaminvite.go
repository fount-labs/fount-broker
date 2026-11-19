package coordinator

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Invites (launch-plan decision 26, docs/membership-list.md §2.3). An admin
// device lists the invitee as a member with no account: their email, a role
// and an open invite {id, commit, exp}. The commit is a hash of a secret the
// admin device made, which reaches the invitee in a link's fragment and never
// fount-infra:
//
//	commit = base64url(SHA-256(lengthPrefixed(InviteCommitContext, team, member, invite id, secret)))
//
// The invitee's device, signed in, shows the secret here over the attested
// channel. The coordinator checks the open invite, the secret, the expiry and
// that the Cloud credential's verified email is the invite's, then appends an
// invite record that binds the member to the caller's account and admits the
// caller's device, and seals it the DEK of each worker the member reaches. The
// record keeps the secret, so the invite is used: the log is the used-token
// store, and a restore can't reopen it (§4.2). Nobody needs to be online but
// the invitee.

const (
	InviteCommitContext = "fount-team-invite-v1\x00"
	InviteSecretSize    = 32
	// InviteCodePrefix starts an invite code: fi1.<team>.<member>.<invite>.<secret>.
	InviteCodePrefix = "fi1"
	// InviteLink is where an invite code goes, in the fragment.
	InviteLink = "https://fount.sh/join#"
)

// InviteCommit is the commitment a list carries for an invite's secret.
func InviteCommit(team, member, invite string, secret []byte) (string, error) {
	if len(secret) != InviteSecretSize {
		return "", fmt.Errorf("an invite secret is %d bytes", InviteSecretSize)
	}
	msg, err := lengthPrefixed(InviteCommitContext, []byte(team), []byte(member), []byte(invite), secret)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(msg)
	return b64.EncodeToString(sum[:]), nil
}

// InviteCode is what the invitee pastes or the link carries.
func InviteCode(team, member, invite string, secret []byte) string {
	return strings.Join([]string{InviteCodePrefix, team, member, invite, b64.EncodeToString(secret)}, ".")
}

// InviteProof is an invite record's proof: the secret, revealed now that it
// is used, and the verified email it was used under.
type InviteProof struct {
	Invite string `json:"invite"`
	Secret string `json:"secret"`
	Email  string `json:"email"`
}

// inviteRequest is what the invitee's device sends: the invite's member and
// secret, and to accept, its team inclusion for the record's entry.
type inviteRequest struct {
	Member string `json:"member"`
	Secret string `json:"secret"`
	Device string `json:"device,omitempty"`
	Worker string `json:"worker,omitempty"`
}

// checkInvite is every check on an invite but the device: the member has
// this open invite, the secret is its, it hasn't expired, and the caller's
// verified email is the invite's. The caller's account being another
// member's is appendRecord's. Called with c.mu held.
func checkInvite(st *teamState, team, member, invite string, secret []byte, caller Caller, now time.Time) (*Member, error) {
	refuse := func(why string) error { return fmt.Errorf("%w: %s", ErrListRefused, why) }
	m := st.byID[member]
	if st.usedInvites[invite] {
		return nil, refuse("this invite was used already")
	}
	if m == nil || m.Invite == nil || m.Invite.ID != invite {
		return nil, refuse("no such invite: it was cancelled, or the link is wrong")
	}
	commit, err := InviteCommit(team, member, invite, secret)
	if err != nil || subtle.ConstantTimeCompare([]byte(commit), []byte(m.Invite.Commit)) != 1 {
		return nil, refuse("the invite's secret is wrong: check the link")
	}
	if now.Unix() >= m.Invite.Exp {
		return nil, refuse("this invite expired: ask an admin for a new one")
	}
	if caller.Email == "" {
		return nil, refuse("your sign-in has no verified email, so the invite can't be checked")
	}
	if subtle.ConstantTimeCompare([]byte(caller.Email), []byte(m.Email)) != 1 {
		return nil, refuse("this invite is for another email than the one you signed in with")
	}
	return m, nil
}

func parseSecret(s string) ([]byte, error) {
	secret, err := b64.DecodeString(s)
	if err != nil || len(secret) != InviteSecretSize {
		return nil, fmt.Errorf("%w: the invite's secret is %d bytes of base64url", ErrInvalid, InviteSecretSize)
	}
	return secret, nil
}

// InviteView is what opening an invite shows the invitee before they accept:
// the invite, and the team's log, for their device to check from its start.
type InviteView struct {
	Team   string      `json:"team"`
	Member string      `json:"member"`
	Email  string      `json:"email"`
	Role   Role        `json:"role"`
	Exp    int64       `json:"exp"`
	Log    TeamLogView `json:"log"`
}

// OpenInvite checks an invite without using it.
func (c *Coordinator) OpenInvite(caller Caller, team, invite, member string, secret []byte) (InviteView, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.state.Teams[team]; !ok {
		return InviteView{}, ErrNoTeam
	}
	st, err := c.teamState(team)
	if err != nil {
		return InviteView{}, err
	}
	m, err := checkInvite(st, team, member, invite, secret, caller, time.Now())
	if err != nil {
		return InviteView{}, err
	}
	return InviteView{Team: team, Member: m.ID, Email: m.Email, Role: m.Role, Exp: m.Invite.Exp, Log: c.teamLogView(team, 0)}, nil
}

// AcceptInvite uses an invite: the record binds its member to the caller's
// account and admits the caller's device, whose inclusion is for the
// record's entry.
func (c *Coordinator) AcceptInvite(caller Caller, team, invite, member string, secret []byte, inclusion string) (TeamLogView, error) {
	proof, err := json.Marshal(InviteProof{Invite: invite, Secret: b64.EncodeToString(secret), Email: caller.Email})
	if err != nil {
		return TeamLogView{}, err
	}
	rec := TeamRecord{Kind: RecordInvite, Member: member, Account: caller.Account, Device: inclusion, Proof: proof}
	seq, err := c.appendRecord(caller, team, rec, func(st *teamState, _ *Member) error {
		_, err := checkInvite(st, team, member, invite, secret, caller, time.Now())
		return err
	})
	if err != nil {
		return TeamLogView{}, err
	}
	c.admitted(team, seq)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.teamLogView(team, 0), nil
}

// checkInviteProof is what a client checks of an invite record against the
// state before it, and what reduceTeam checks on replay: the proof names the
// member's open invite, its secret is the commit's, it was used before it
// expired, for the member's email.
func checkInviteProof(st *teamState, team string, r TeamRecord, m *Member) error {
	var p InviteProof
	if err := decodeStrictJSON(r.Proof, &p); err != nil {
		return fmt.Errorf("an invite record's proof: %v", err)
	}
	secret, err := b64.DecodeString(p.Secret)
	if err != nil || m.Invite == nil || m.Invite.ID != p.Invite {
		return errors.New("an invite record's proof names no open invite")
	}
	commit, err := InviteCommit(team, m.ID, p.Invite, secret)
	switch {
	case err != nil || commit != m.Invite.Commit:
		return errors.New("an invite record's secret isn't its invite's")
	case r.At >= m.Invite.Exp:
		return errors.New("an invite record is after its invite expired")
	case p.Email != m.Email:
		return errors.New("an invite record is for another email than its invite's")
	}
	return nil
}

// inviteMailText is the invite email (decision 26 step 2): who invites, as
// what, the link and the code, and that it works once, for that address,
// until it expires.
func inviteMailText(firm, email string, role Role, code string, exp time.Time) string {
	var b strings.Builder
	what := "review its work"
	if role == RoleAdmin {
		what = "review its work and manage it"
	}
	fmt.Fprintf(&b, "%s invited you to %s in Fount.\n\n", firm, what)
	b.WriteString("Open this link on a computer with Fount installed:\n" + InviteLink + code + "\n\n")
	b.WriteString("Or, in Fount, choose Join a team and paste this code:\n" + code + "\n\n")
	fmt.Fprintf(&b, "The invite works once, for %s, until %s.\n", email, exp.UTC().Format("2 Jan 2006 15:04 MST"))
	return b.String()
}

// InviteSend is how emailing an invite went: the send record, and its state
// after the first attempt, or "sending" if that took longer than
// inviteSendWait. A refusal (failed) carries its code and message, and the
// admin copies the link instead.
type InviteSend struct {
	SendID  string `json:"sendId"`
	State   string `json:"state"`
	Code    OpCode `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// inviteSendWait bounds how long SendInvite waits for the first attempt.
var inviteSendWait = 20 * time.Second

// SendInvite emails an open invite from a team worker's address, for an
// admin who has its secret: the coordinator only mails an invite whose secret
// it can check. The worker is the one named, or the team's first with an
// address. It goes through the send journal once per invite, and waits for
// the journal's first attempt, so the admin hears the edge's answer and not
// only that the email was queued. Asking again for the same invite answers
// with its record's state.
//
// /send goes only to an address the worker's owners proved they read, so an
// invite is posted on the edge's coordinator route instead (POST
// /coordinator/invite, signed by the generation key): one plain-text message
// to one address, at most 20 a day per worker. A refusal fails the record
// with the edge's code, and the admin copies the link instead.
func (c *Coordinator) SendInvite(ctx context.Context, caller Caller, team, invite, member string, secret []byte, workerID string) (InviteSend, error) {
	if c.sender == nil {
		return InviteSend{}, fmt.Errorf("%w: this coordinator doesn't send mail", ErrUnsupported)
	}
	c.mu.Lock()
	me, st, err := c.requireMember(caller, team)
	var m Member
	var candidates []string
	if err == nil && me.Role != RoleAdmin {
		err = fmt.Errorf("%w: only an admin sends invites", ErrRole)
	}
	if err == nil {
		inv := st.byID[member]
		if inv == nil || inv.Invite == nil || inv.Invite.ID != invite {
			err = fmt.Errorf("%w: no such open invite", ErrNotFound)
		} else if commit, cerr := InviteCommit(team, member, invite, secret); cerr != nil || subtle.ConstantTimeCompare([]byte(commit), []byte(inv.Invite.Commit)) != 1 {
			err = fmt.Errorf("%w: that isn't the invite's secret", ErrListRefused)
		} else {
			m = *inv
			m.Invite = &ListInvite{ID: inv.Invite.ID, Commit: inv.Invite.Commit, Exp: inv.Invite.Exp}
		}
	}
	if err == nil {
		for _, id := range slices.Sorted(maps.Keys(st.workers)) {
			if workerID == "" || id == workerID {
				if w := c.state.Workers[id]; w != nil && w.Mailbox != "" {
					candidates = append(candidates, id)
				}
			}
		}
		if len(candidates) == 0 {
			err = fmt.Errorf("%w: no worker of the team has an address to send from", ErrNoMailbox)
		}
	}
	c.mu.Unlock()
	if err != nil {
		return InviteSend{}, err
	}
	if time.Now().Unix() >= m.Invite.Exp {
		return InviteSend{}, fmt.Errorf("%w: this invite expired", ErrListRefused)
	}
	from := candidates[0]
	id := c.sendID(from, sendKindNotice, "invite", team, invite)
	code := InviteCode(team, member, invite, secret)
	err = c.change(from, anyDevice, func(t *Tree) error {
		if t.Has(sendPath(id)) {
			return nil
		}
		mb, err := loadMailbox(t)
		if err != nil {
			return err
		}
		rs, err := loadReplySettings(t)
		if err != nil {
			return err
		}
		firm := rs.firm(mb)
		text := inviteMailText(firm, m.Email, m.Role, code, time.Unix(m.Invite.Exp, 0)) + "\n" + footer(firm, false) + "\n"
		part := c.derivedPart(messageIDInfo, from, sendKindNotice, "invite", team, invite)
		r := &sendRecord{ID: id, Kind: sendKindInvite, Attempt: 1, State: sendSending, To: []string{m.Email},
			MessageID: messageID(part, strings.ToLower(part[:16]), domainOf(mb.Address))}
		raw, err := c.buildOut(t, nil, mb, r, []string{sendKindNotice, "invite", team, invite}, "Join "+firm+" in Fount", "", nil, text, nil, time.Now().UTC())
		if err != nil {
			return err
		}
		_, err = c.stageSend(t, from, r, raw)
		return err
	})
	if err != nil {
		return InviteSend{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, inviteSendWait)
	defer cancel()
	c.firstAttempt(ctx, from)
	out := InviteSend{SendID: id, State: sendSending}
	err = c.view(from, anyDevice, func(t *Tree) error {
		rec, err := loadSend(t, id)
		if err != nil {
			return err
		}
		out.State = rec.State
		if rec.Error != nil {
			out.Code, out.Message = rec.Error.Code, rec.Error.Message
		}
		return nil
	})
	return out, err
}

// firstAttempt runs workerID's due sends now, under its mail lock, as the mail
// pass would, until ctx ends. A send still waiting to be tried again stays
// for the mail pass.
func (c *Coordinator) firstAttempt(ctx context.Context, workerID string) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		if c.mail != nil {
			lock := c.mail.workerSync(workerID)
			lock.Lock()
			defer lock.Unlock()
			w, err := c.Worker(workerID)
			if err == nil && ctx.Err() == nil {
				err = c.enrollMail(ctx, w)
			}
			if err != nil {
				log.Printf("worker %s: sends: %v", workerID, err)
				return
			}
		}
		if ctx.Err() != nil {
			return
		}
		if err := c.runSends(ctx, workerID); err != nil {
			log.Printf("worker %s: sends: %v", workerID, err)
		}
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// admitted tells the team's owner that a device joined (decision 26 step 5):
// content-free, from the team's lead worker. The window to cancel is any
// admin's next list, which removes the device by leaving it out; Desktop
// shows recent admissions in the members dialog with Remove beside them.
func (c *Coordinator) admitted(team string, seq uint64) {
	if c.sender == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		lead, err := c.noticeLead(team)
		if err != nil || lead == "" {
			return
		}
		key := team + "/" + noticeMemberJoined + "/" + strconv.FormatUint(seq, 10)
		if err := c.NotifyOwner(ctx, key, noticeMemberJoined, team, lead, time.Time{}); err != nil {
			log.Printf("team %s: couldn't tell the owner entry %d admitted a device: %v", team, seq, err)
		}
	}()
}

const noticeMemberJoined = "member_joined"

// TeamMembership is one team the caller's account is a member of.
type TeamMembership struct {
	Team   string `json:"team"`
	Name   string `json:"name,omitempty"`
	Member string `json:"member"`
	Role   Role   `json:"role"`
	// Admitted says whether the caller's device is admitted; a device that
	// isn't joins with one that is (teamjoin.go).
	Admitted bool `json:"admitted"`
}

// Memberships are the teams whose state lists the caller's account, by
// team id: what a new device of the account asks to know where to join.
func (c *Coordinator) Memberships(caller Caller) []TeamMembership {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []TeamMembership{}
	for _, id := range slices.Sorted(maps.Keys(c.state.Teams)) {
		st, err := c.teamState(id)
		if err != nil {
			continue
		}
		for _, m := range st.members {
			if m.Account != "" && m.Account == caller.Account {
				_, holder := st.device(caller.Device)
				out = append(out, TeamMembership{Team: id, Name: st.name, Member: m.ID, Role: m.Role, Admitted: holder == m})
			}
		}
	}
	return out
}

func (a *api) myTeams(rw http.ResponseWriter, _ *http.Request) {
	reply(rw, http.StatusOK, map[string][]TeamMembership{"teams": a.c.Memberships(*a.caller)})
}

func (a *api) inviteRequest(rw http.ResponseWriter, r *http.Request) (inviteRequest, []byte, bool) {
	var req inviteRequest
	if err := decodeStrict(r.Body, maxTeamBody, &req); err != nil {
		fail(rw, http.StatusBadRequest, err)
		return req, nil, false
	}
	secret, err := parseSecret(req.Secret)
	if err == nil {
		err = checkID("member", req.Member)
	}
	if err == nil {
		err = checkID("invite", r.PathValue("invite"))
	}
	if err != nil {
		fail(rw, http.StatusBadRequest, err)
		return req, nil, false
	}
	return req, secret, true
}

// openInvite is POST /v1/teams/{team}/invites/{invite}/open {member, secret}.
func (a *api) openInvite(rw http.ResponseWriter, r *http.Request) {
	req, secret, ok := a.inviteRequest(rw, r)
	if !ok {
		return
	}
	defer clear(secret)
	v, err := a.c.OpenInvite(*a.caller, r.PathValue("team"), r.PathValue("invite"), req.Member, secret)
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusOK, v)
}

// acceptInvite is POST /v1/teams/{team}/invites/{invite}/accept {member,
// secret, device}.
func (a *api) acceptInvite(rw http.ResponseWriter, r *http.Request) {
	req, secret, ok := a.inviteRequest(rw, r)
	if !ok {
		return
	}
	v, err := a.c.AcceptInvite(*a.caller, r.PathValue("team"), r.PathValue("invite"), req.Member, secret, req.Device)
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusOK, v)
}

// sendInvite is POST /v1/teams/{team}/invites/{invite}/send {member, secret,
// worker?}, an admin's. It answers InviteSend once the first attempt is done,
// or after inviteSendWait.
func (a *api) sendInvite(rw http.ResponseWriter, r *http.Request) {
	req, secret, ok := a.inviteRequest(rw, r)
	if !ok {
		return
	}
	defer clear(secret)
	if req.Worker != "" {
		if err := checkID("worker", req.Worker); err != nil {
			fail(rw, http.StatusBadRequest, err)
			return
		}
	}
	sent, err := a.c.SendInvite(r.Context(), *a.caller, r.PathValue("team"), r.PathValue("invite"), req.Member, secret, req.Worker)
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	reply(rw, http.StatusOK, sent)
}
