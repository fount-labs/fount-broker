package coordinator

import (
	"context"
	"errors"
	"fmt"
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
	"past_due":    {"Payment failed for %s", "Fount couldn't take the payment for %s. Its workers keep running%s. Update the payment in Fount."},
	"lapsed":      {"%s is paused", "%s's payment lapsed, so its workers are paused. Their incoming mail is held%s. Renew in Fount to resume them."},
	"hold_ending": {"%s's held mail will start bouncing", "%s's workers are paused, and their held mail starts bouncing%s. Renew in Fount to keep it."},
	"bouncing":    {"%s's mail is bouncing", "%s's workers are paused, and mail sent to them now bounces. Renew in Fount to resume them."},
	"resumed":     {"%s is running again", "%s's payment went through, so its workers are running again."},
}

// NotifyOwner is OwnerNotices.Notify, field for field: an adapter
// `func (a ownerNotices) Notify(ctx, n) error { return a.c.NotifyOwner(ctx,
// n.Key, string(n.Kind), n.Account, n.WorkerID, n.Until) }` plugs it in.
func (c *Coordinator) NotifyOwner(ctx context.Context, key, kind, account, workerID string, until time.Time) error {
	words, ok := accountNoticeText[kind]
	if !ok {
		return fmt.Errorf("%w: no notice %q", ErrInvalid, kind)
	}
	if c.cfg.Mail.Send == nil {
		return nil
	}
	lead, err := c.noticeLead(account)
	if err != nil || lead != workerID {
		return err
	}
	return c.change(workerID, anyDevice, func(t *Tree) error {
		id := c.sendID(workerID, sendKindNotice, "account", key)
		if t.Has(sendPath(id)) {
			return nil
		}
		rs, err := loadReplySettings(t)
		if err != nil || rs.Owner == "" {
			return err
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
		r := &sendRecord{ID: id, Kind: sendKindNotice, Attempt: 1, State: sendSending, To: []string{rs.Owner},
			MessageID: messageID(part, strings.ToLower(part[:16]), domainOf(mb.Address))}
		raw, err := c.buildOut(t, nil, mb, r, []string{sendKindNotice, "account", key}, fmt.Sprintf(words[0], firm), "", nil, text, nil, time.Now().UTC())
		if err != nil {
			return err
		}
		_, err = c.stageSend(t, workerID, r, raw)
		return err
	})
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
