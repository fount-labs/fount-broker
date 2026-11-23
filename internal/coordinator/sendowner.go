package coordinator

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"
)

// Account notices (decision 10): past due, lapsed, the hold ending, bouncing
// and resumed, for the mail plumbing lane's OwnerNotices. Every worker of an
// account asks for the same Key, so one worker sends it: the account's first
// worker, by id, whose reply settings name an owner. Its send record's id is
// derived from the Key, so a retry is the same record.

var accountNoticeText = map[string][2]string{
	"past_due":    {"Payment failed for %s", "Fount couldn't take the payment for %s. Its email agents keep running%s. Update the payment in Fount."},
	"lapsed":      {"%s is paused", "%s's payment lapsed, so its email agents are paused. Their incoming mail is held%s. Renew in Fount to resume them."},
	"hold_ending": {"%s's held mail will start bouncing", "%s's email agents are paused, and their held mail starts bouncing%s. Renew in Fount to keep it."},
	"bouncing":    {"%s's mail is bouncing", "%s's email agents are paused, and mail sent to them now bounces. Renew in Fount to resume them."},
	"resumed":     {"%s is running again", "%s's payment went through, so its email agents are running again."},
	// An admission (teaminvite.go): someone took an invite, or a member
	// added a device.
	noticeMemberJoined: {"A new device joined %s", "Someone joined %s in Fount, by an invite or as a member's new device. If you didn't expect it, an admin can remove them in Fount, under Members.%s"},
	// A member's passkey added a computer of theirs (passkeyjoin.go).
	noticeDeviceAdded: {"New computer added to %s", "A new computer was added to %s in Fount with a member's passkey. If it wasn't you, remove it in Fount: on another of your computers, or an admin can under Members.%s"},
	// A passkey-added admin computer started its wait to sign the team's
	// changes (teamrecovery.go).
	noticeRecoveryStarted: {"Someone is recovering access to %s", "Someone is recovering access to %s in Fount from a new computer, with an admin's passkey. In 7 days it can change the team, unless someone cancels it. If this wasn't you, cancel it in Fount, under Members, from a computer of yours the team already had.%s"},
	// A member invited again took it on a new computer (teaminvite.go).
	noticeMemberBack: {"New computer added to %s", "A member invited again joined %s in Fount on a new computer, with a new passkey. Their old computers were removed. If it wasn't you, an admin can remove it in Fount, under Members.%s"},
}

// ownerNotices is the mail loop's OwnerNotices (lapse.go) on NotifyOwner.
type ownerNotices struct{ c *Coordinator }

func (a ownerNotices) Notify(ctx context.Context, n OwnerNotice) error {
	return a.c.NotifyOwner(ctx, n.Key, string(n.Kind), n.Account, n.WorkerID, n.Until)
}

// NotifyOwner sends account's notice of kind once per key, from the
// account's lead worker to its owner and, on a team, every admin.
func (c *Coordinator) NotifyOwner(ctx context.Context, key, kind, account, workerID string, until time.Time) error {
	_, err := c.notifyAdmins(ctx, key, kind, account, workerID, until, nil)
	return err
}

// notifyAdmins sends account's notice of kind from workerID, when it is the
// account's lead worker, or from the lead when workerID is empty: to the
// owner under key, and under key/<address> to each of the team's admins
// (noticeAdmins) and extra. It returns the addresses it reached. When it
// reaches no one, as when no worker of the account has a mailbox, it raises
// noticeUnsent.
func (c *Coordinator) notifyAdmins(ctx context.Context, key, kind, account, workerID string, until time.Time, extra []string) ([]string, error) {
	if _, ok := accountNoticeText[kind]; !ok {
		return nil, fmt.Errorf("%w: no notice %q", ErrInvalid, kind)
	}
	if c.sender == nil {
		return nil, nil
	}
	lead, err := c.noticeLead(account)
	if err != nil {
		return nil, err
	}
	if lead == "" {
		c.noticeUnsent(key, kind, account, "no email agent of the account has a mailbox and an owner")
		return nil, nil
	}
	if workerID != "" && lead != workerID {
		return nil, nil
	}
	to := append(c.noticeAdmins(account), extra...)
	for i := range to {
		to[i] = strings.ToLower(to[i])
	}
	slices.Sort(to)
	var reached []string
	var errs []error
	for _, addr := range append([]string{""}, slices.Compact(to)...) {
		k := key
		if addr != "" {
			k = key + "/" + addr
		}
		got, err := c.sendAccountNotice(k, kind, lead, until, addr)
		if err != nil {
			errs = append(errs, err)
		} else if got != "" {
			reached = append(reached, got)
		}
	}
	err = errors.Join(errs...)
	if len(reached) == 0 {
		why := "every address failed"
		if err != nil {
			why += ": " + err.Error()
		}
		c.noticeUnsent(key, kind, account, why)
	}
	return reached, err
}

// noticeAdmins are the addresses of team's admins who joined, beside its
// owner: none when team isn't a team or has one member, so a solo account's
// notices go to its owner alone.
func (c *Coordinator) noticeAdmins(team string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.state.Teams[team]; !ok {
		return nil
	}
	st, err := c.teamState(team)
	if err != nil {
		log.Printf("team %s: its admins aren't told: %v", team, err)
		return nil
	}
	var out []string
	joined := 0
	for _, m := range st.members {
		if m.Account == "" {
			continue
		}
		joined++
		if m.Role == RoleAdmin && m.Email != "" {
			out = append(out, m.Email)
		}
	}
	if joined < 2 {
		return nil
	}
	return out
}

// notify is NotifyOwner to the address to alone, or the owner when to is
// empty.
func (c *Coordinator) notify(ctx context.Context, key, kind, account, workerID string, until time.Time, to string) error {
	if _, ok := accountNoticeText[kind]; !ok {
		return fmt.Errorf("%w: no notice %q", ErrInvalid, kind)
	}
	if c.sender == nil {
		return nil
	}
	lead, err := c.noticeLead(account)
	if err != nil || lead != workerID {
		return err
	}
	_, err = c.sendAccountNotice(key, kind, workerID, until, to)
	return err
}

// sendAccountNotice stages the notice of kind under key from workerID to the
// address to, or its owner when to is empty, once. It returns the address,
// or empty when to is the owner, who has their own.
func (c *Coordinator) sendAccountNotice(key, kind, workerID string, until time.Time, to string) (string, error) {
	words := accountNoticeText[kind]
	sent := ""
	err := c.change(workerID, anyDevice, func(t *Tree) error {
		rs, err := loadReplySettings(t)
		if err != nil || rs.Owner == "" {
			return err
		}
		if to == "" {
			to = rs.Owner
		} else if strings.EqualFold(to, rs.Owner) {
			return nil
		}
		id := c.sendID(workerID, sendKindNotice, "account", key)
		if t.Has(sendPath(id)) {
			sent = to
			return nil
		}
		mb, err := loadMailbox(t)
		if err != nil {
			return err
		}
		firm, when := rs.firm(mb), ""
		if !until.IsZero() {
			when = " until " + until.UTC().Format("2 Jan 2006")
		}
		body := fmt.Sprintf(words[1], firm, when)
		if kind == "bouncing" || kind == "resumed" {
			body = fmt.Sprintf(words[1], firm)
		}
		text := body + "\n\n" + footer(firm, false) + "\n"
		part := c.derivedPart(messageIDInfo, workerID, sendKindNotice, "account", key)
		r := &sendRecord{ID: id, Kind: sendKindNotice, Attempt: 1, State: sendSending, To: []string{to},
			MessageID: messageID(part, strings.ToLower(part[:16]), domainOf(mb.Address))}
		raw, err := c.buildOut(t, nil, mb, r, []string{sendKindNotice, "account", key}, fmt.Sprintf(words[0], firm), "", nil, text, nil, time.Now().UTC())
		if err != nil {
			return err
		}
		if _, err := c.stageSend(t, workerID, r, raw); err != nil {
			return err
		}
		sent = to
		return nil
	})
	return sent, err
}

// noticeLead is the worker that sends account's notices.
func (c *Coordinator) noticeLead(account string) (string, error) {
	c.mu.Lock()
	var ids []string
	for id, w := range c.state.Workers {
		if w.Account == account {
			ids = append(ids, id)
		}
	}
	c.mu.Unlock()
	slices.Sort(ids)
	for _, id := range ids {
		var owner string
		err := c.view(id, anyDevice, func(t *Tree) error {
			rs, err := loadReplySettings(t)
			if err == nil && rs.Owner != "" && t.Has(mailboxPath) {
				owner = rs.Owner
			}
			return err
		})
		if errors.Is(err, ErrNoWorker) {
			continue
		}
		if err != nil {
			return "", err
		}
		if owner != "" {
			return id, nil
		}
	}
	return "", nil
}
