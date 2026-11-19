package coordinator

import (
	"cmp"
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/fount-labs/fount-broker/internal/mail"
)

// The send journal (decision 14; launch-plan H). Every email the coordinator
// sends is a record in the worker's tree, with its exact bytes beside it:
//
//	record/mail/sends/<id>.json  the record
//	record/mail/sends/<id>.eml   the bytes, built once when the record is made
//	record/mail/outbox.json      the records "sending", for the driver
//
// A record moves through these states, each written in a tree change:
//
//	draft ──approve──▶ sending ──▶ sent | partly_sent | failed | maybe_sent
//	draft ──discard──▶ discarded
//	failed ──sendAgain──▶ sending (the same bytes, the same Message-ID)
//	maybe_sent ──sendAgain{duplicateOk}──▶ a new record, attempt+1, a new Message-ID
//
// "sending" is committed before anything is posted. The driver (runSends)
// then asks the edge what it knows of the Message-ID (POST /sent/query) before
// every post, so a crash after a post and before "sent" was written, or a
// restore, finds the send instead of making a second one: none or retryable
// posts the same bytes again; done records the edge's results; in_doubt (the
// edge stopped mid-send and won't send that ID again) is maybe_sent, which is
// never resent under that ID. Notices and acknowledgements are records too,
// made "sending" at once: nothing a person approves, nothing a job wrote.

const (
	sendsDir   = prefixMailRecord + "sends/"
	outboxPath = prefixMailRecord + "outbox.json"

	sendKindReply  = "reply"
	sendKindNotice = "notice"
	sendKindAck    = "ack"

	// A record's states. sent, partly_sent, maybe_sent and failed are
	// Desktop's SendState.
	sendDraft     = "draft"
	sendSending   = "sending"
	sendSent      = "sent"
	sendPartly    = "partly_sent"
	sendMaybe     = "maybe_sent"
	sendFailed    = "failed"
	sendDiscarded = "discarded"

	// A recipient's delivery, Desktop's DeliveryStatus.
	deliverySent     = "sent"
	deliveryRefused  = "refused"
	deliveryDeferred = "deferred"
	deliveryMaybe    = "maybe_sent"
	deliveryNotSent  = "not_sent"

	// maxSendTries bounds the posts of one record whose recipients the
	// recipient's server keeps deferring; after it they are deferred.
	maxSendTries = 6

	sendIDInfo   = "fount-coordinator/send-id/v1"
	sendSealInfo = "fount-coordinator/send-seal/v1"
)

// sendBackoff is how long a record waits after its tries'th failed attempt.
var sendBackoff = func(tries int) time.Duration {
	d := 30 * time.Second << min(tries, 5)
	return min(d, 10*time.Minute)
}

type sendRecord struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	ThreadID string `json:"threadId"`
	// A reply's draft and its revision, and which attempt at it this is: 1,
	// then one more for each new Message-ID sendAgain made.
	DraftID   string `json:"draftId,omitempty"`
	DraftRev  int    `json:"draftRev,omitempty"`
	Attempt   int    `json:"attempt"`
	MessageID string `json:"messageId"`
	// Hash is the bytes' SHA-256, hex: what an approval binds and what the
	// edge reports back.
	Hash  string   `json:"hash"`
	To    []string `json:"to"`
	State string   `json:"state"`
	// Approval is who approved a reply; Seal is the coordinator's MAC over
	// the record's identity, hash and approval, which the driver checks
	// before it posts.
	Approval *approval    `json:"approval,omitempty"`
	Seal     string       `json:"seal,omitempty"`
	Delivery []delivered  `json:"delivery,omitempty"`
	Error    *sendFailure `json:"error,omitempty"`
	Tries    int          `json:"tries"`
	NextAt   time.Time    `json:"nextAt,omitzero"`
	Created  time.Time    `json:"createdAt"`
	Updated  time.Time    `json:"updatedAt"`
	SentAt   time.Time    `json:"sentAt,omitzero"`
}

// delivered is one recipient's outcome, Desktop's Delivered.
type delivered struct {
	Address string `json:"address"`
	Status  string `json:"status"`
	Detail  string `json:"detail,omitempty"`
}

// sendFailure is why a send didn't fully go: a §6 code and its message.
type sendFailure struct {
	Code    OpCode `json:"code"`
	Message string `json:"message"`
}

// approval is a reply's approval: by whom, how, and of which bytes.
type approval struct {
	// By is the member's email, or the device id with no team.
	By     string    `json:"by"`
	Device string    `json:"device,omitempty"`
	Via    string    `json:"via"` // "app" or "email"
	At     time.Time `json:"at"`
	Hash   string    `json:"hash"`
	// AgentTextHash and SentTextHash are thread-operations.md §4.3's.
	AgentTextHash string `json:"agentTextHash"`
	SentTextHash  string `json:"sentTextHash"`
	// An email approval's aligned DKIM domain and the edge id of the reply
	// that approved.
	DKIM  string `json:"dkim,omitempty"`
	Email string `json:"email,omitempty"`
}

func sendPath(id string) string  { return sendsDir + id + ".json" }
func sendBytes(id string) string { return sendsDir + id + ".eml" }

func loadSend(t *Tree, id string) (*sendRecord, error) {
	if checkID("send", id) != nil {
		return nil, ErrNotFound
	}
	var r sendRecord
	ok, err := readJSON(t, sendPath(id), &r)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotFound
	}
	return &r, nil
}

func loadOutbox(t *Tree) ([]string, error) {
	var ids []string
	_, err := readJSON(t, outboxPath, &ids)
	return ids, err
}

// sendID is the record id for what parts name: derived, so making the same
// notice or acknowledgement twice finds the first.
func (c *Coordinator) sendID(workerID string, parts ...string) string {
	return "snd_" + c.derivedPart(sendIDInfo, append([]string{workerID}, parts...)...)
}

func (c *Coordinator) sealOf(workerID string, r *sendRecord) string {
	parts := []string{workerID, r.ID, r.Kind, r.ThreadID, r.MessageID, r.Hash}
	if a := r.Approval; a != nil {
		parts = append(parts, a.By, a.Via, a.Hash)
	}
	return c.derivedPart(sendSealInfo, parts...)
}

// stageSend writes r and its bytes, and puts it in the outbox if it is
// sending. A record that is already there is left as it is: ok is false.
func (c *Coordinator) stageSend(t *Tree, workerID string, r *sendRecord, raw []byte) (bool, error) {
	if t.Has(sendPath(r.ID)) {
		return false, nil
	}
	r.Hash = sha256Hex(raw)
	if r.State == sendSending {
		r.Seal = c.sealOf(workerID, r)
	}
	if err := t.Write(sendBytes(r.ID), raw); err != nil {
		return false, err
	}
	return true, c.saveSend(t, r)
}

// saveSend writes r and keeps the outbox to the records sending.
func (c *Coordinator) saveSend(t *Tree, r *sendRecord) error {
	if err := writeJSON(t, sendPath(r.ID), r); err != nil {
		return err
	}
	ids, err := loadOutbox(t)
	if err != nil {
		return err
	}
	has := slices.Contains(ids, r.ID)
	switch {
	case r.State == sendSending && !has:
		ids = append(ids, r.ID)
	case r.State != sendSending && has:
		ids = slices.DeleteFunc(ids, func(id string) bool { return id == r.ID })
	default:
		return nil
	}
	return writeJSON(t, outboxPath, ids)
}

// startSending moves a record to sending, sealed, for the driver.
func (c *Coordinator) startSending(t *Tree, workerID string, r *sendRecord, now time.Time) error {
	r.State, r.Tries, r.NextAt, r.Error, r.Delivery, r.Updated = sendSending, 0, time.Time{}, nil, nil, now
	r.Seal = c.sealOf(workerID, r)
	return c.saveSend(t, r)
}

// sendOutcome is what one attempt found: a final state with its deliveries,
// or a time to try again.
type sendOutcome struct {
	state    string
	delivery []delivered
	failure  *sendFailure
	retry    time.Duration
	// posted says a post reached the edge, so the record counts a try.
	posted bool
}

// runSends drives workerID's outbox: each record due is checked against the
// edge, posted if the edge hasn't it, and its outcome written. It runs from
// the mail pass, under the worker's mail lock, so one worker's sends run one
// at a time.
func (c *Coordinator) runSends(ctx context.Context, workerID string) error {
	sender := c.sender
	if sender == nil {
		return nil
	}
	type due struct {
		rec *sendRecord
		raw []byte
	}
	var list []due
	var keys *mail.Keys
	now := time.Now().UTC()
	err := c.view(workerID, anyDevice, func(t *Tree) error {
		ids, err := loadOutbox(t)
		if err != nil || len(ids) == 0 {
			return err
		}
		mb, err := loadMailbox(t)
		if err != nil {
			return err
		}
		if keys, err = mb.keys(); err != nil {
			return err
		}
		for _, id := range ids {
			r, err := loadSend(t, id)
			if err != nil {
				return err
			}
			if r.State != sendSending || r.NextAt.After(now) {
				continue
			}
			raw, err := t.Read(sendBytes(id))
			if err != nil {
				return err
			}
			list = append(list, due{r, raw})
		}
		return nil
	})
	if err != nil || len(list) == 0 {
		return err
	}
	var errs []error
	for _, d := range list {
		if ctx.Err() != nil {
			break
		}
		out := c.attemptSend(ctx, sender, keys, workerID, d.rec, d.raw)
		if err := c.recordOutcome(workerID, d.rec.ID, out); err != nil {
			errs = append(errs, fmt.Errorf("send %s: %w", d.rec.ID, err))
		}
	}
	return errors.Join(errs...)
}

// attemptSend is one try at r: the query, then a post if the edge hasn't
// the message or asks for it again.
func (c *Coordinator) attemptSend(ctx context.Context, sender MailSender, keys *mail.Keys, workerID string, r *sendRecord, raw []byte) sendOutcome {
	if sha256Hex(raw) != r.Hash || !hmac.Equal([]byte(r.Seal), []byte(c.sealOf(workerID, r))) {
		// The bytes or the approval aren't what was approved: never post.
		return sendOutcome{state: sendFailed, failure: failure(CodeBadMessage)}
	}
	q, err := sender.QuerySent(ctx, keys, r.MessageID)
	if err != nil {
		return sendOutcome{retry: sendBackoff(r.Tries)}
	}
	switch q.State {
	case sentDone:
		if !strings.EqualFold(q.SHA256, r.Hash) {
			return maybeSent(r)
		}
		return settleResults(r, q.Results, false)
	case sentInDoubt:
		return maybeSent(r)
	case sentInProgress:
		return sendOutcome{retry: 30 * time.Second}
	case sentRetryable:
		if !strings.EqualFold(q.SHA256, r.Hash) {
			return maybeSent(r)
		}
	case sentNone:
	default:
		return sendOutcome{retry: sendBackoff(r.Tries)}
	}
	results, err := sender.Send(ctx, keys, raw)
	if err != nil {
		return refusedSend(err, r)
	}
	out := settleResults(r, results, true)
	out.posted = true
	return out
}

// settleResults turns the edge's results into a state. Recipients deferred
// are tried again until maxSendTries.
func settleResults(r *sendRecord, results []RecipientResult, posted bool) sendOutcome {
	byAddr := map[string]RecipientResult{}
	for _, res := range results {
		byAddr[strings.ToLower(res.Recipient)] = res
	}
	var out sendOutcome
	var sent, refusedN, deferred, unknown int
	for _, to := range r.To {
		res, ok := byAddr[to]
		d := delivered{Address: to, Detail: cut(res.Detail, 300)}
		switch {
		case !ok:
			d.Status = deliveryNotSent
			deferred++
		case res.Status == resultSent:
			d.Status = deliverySent
			sent++
		case res.Status == resultPermanent:
			d.Status = deliveryRefused
			refusedN++
		case res.Status == resultTemporary:
			d.Status = deliveryDeferred
			deferred++
		default:
			d.Status = deliveryMaybe
			unknown++
		}
		out.delivery = append(out.delivery, d)
	}
	tries := r.Tries
	if posted {
		tries++
	}
	switch {
	case unknown > 0:
		out.state, out.failure = sendMaybe, failure(CodeMaybeSent)
	case deferred > 0 && tries < maxSendTries:
		out.retry = sendBackoff(tries)
	case sent == len(r.To):
		out.state = sendSent
	case sent > 0:
		out.state, out.failure = sendPartly, failure(CodeSendFailed)
	default:
		out.state, out.failure = sendFailed, failure(CodeSendFailed)
	}
	return out
}

func maybeSent(r *sendRecord) sendOutcome {
	out := sendOutcome{state: sendMaybe, failure: failure(CodeMaybeSent)}
	for _, to := range r.To {
		out.delivery = append(out.delivery, delivered{Address: to, Status: deliveryMaybe})
	}
	return out
}

func failure(code OpCode) *sendFailure {
	return &sendFailure{Code: code, Message: opMessages[code]}
}

// refusedSend is a post that failed: a transport failure is tried again,
// after the query; each refusal the edge names becomes its §6 code.
func refusedSend(err error, r *sendRecord) sendOutcome {
	se := asSendError(err)
	if se == nil {
		// The post may or may not have reached the edge; the next try's
		// query says which.
		return sendOutcome{retry: sendBackoff(r.Tries), posted: true}
	}
	final := func(code OpCode) sendOutcome {
		out := sendOutcome{state: sendFailed, failure: failure(code)}
		for _, to := range r.To {
			out.delivery = append(out.delivery, delivered{Address: to, Status: deliveryNotSent})
		}
		return out
	}
	switch se.Status {
	case 409:
		if se.Code == "send_in_doubt" {
			return maybeSent(r)
		}
		// A send of it in progress, or the ID taken by
		// other bytes. The next try's query tells them apart: a hash that
		// isn't ours is maybe_sent, and the ID is never posted again.
		return sendOutcome{retry: sendBackoff(r.Tries), posted: true}
	case 503:
		return sendOutcome{retry: sendBackoff(r.Tries)}
	case 429:
		return final(CodeSendLimit)
	case 403:
		msg := strings.ToLower(se.Message)
		switch {
		case strings.Contains(msg, "lapse"):
			return final(CodeMailLapsed)
		case strings.Contains(msg, "pause"):
			return final(CodeWorkerPaused)
		}
		return final(CodeRecipientNotAllowed)
	case 404:
		return final(CodeNoMailbox)
	case 501:
		return final(CodeSendingOff)
	case 400, 413:
		return final(CodeBadMessage)
	}
	if se.Status >= 500 {
		return sendOutcome{retry: sendBackoff(r.Tries), posted: true}
	}
	return final(CodeSendFailed)
}

// recordOutcome writes what an attempt found, if the record is still the
// one tried, and mirrors it onto a reply's draft. A refused recipient tells
// the owner (decision 10).
func (c *Coordinator) recordOutcome(workerID, id string, out sendOutcome) error {
	return c.change(workerID, anyDevice, func(t *Tree) error {
		r, err := loadSend(t, id)
		if err != nil {
			return err
		}
		if r.State != sendSending {
			return nil
		}
		now := time.Now().UTC()
		r.Updated = now
		if out.posted {
			r.Tries++
		}
		if out.state == "" {
			r.NextAt = now.Add(out.retry)
			if out.delivery != nil {
				r.Delivery = out.delivery
			}
			return c.saveSend(t, r)
		}
		r.State, r.Delivery, r.Error, r.NextAt = out.state, out.delivery, out.failure, time.Time{}
		if out.state == sendSent || out.state == sendPartly {
			r.SentAt = now
		}
		if err := c.saveSend(t, r); err != nil {
			return err
		}
		if r.Kind == sendKindReply {
			if err := c.mirrorSend(t, r, now); err != nil {
				return err
			}
		}
		bounced := slices.ContainsFunc(r.Delivery, func(d delivered) bool { return d.Status == deliveryRefused })
		if r.Kind != sendKindNotice && (bounced || r.State == sendMaybe || r.State == sendFailed) {
			return c.problemNotice(t, workerID, r.ThreadID, noticeBounced, r.ID, now)
		}
		return nil
	})
}

// mirrorSend shows a reply's send state on its draft entry.
func (c *Coordinator) mirrorSend(t *Tree, r *sendRecord, now time.Time) error {
	th, err := loadThread(t, r.ThreadID)
	if errors.Is(err, ErrNoThread) {
		return nil
	}
	if err != nil {
		return err
	}
	e := th.entry(r.DraftID)
	if e == nil || e.Draft == nil || e.Draft.SendID != r.ID {
		return nil
	}
	rev := th.Revision + 1
	e.Draft.Send, e.Rev = r.view(), rev
	if r.State != sendSending && r.State != sendSent {
		if err := th.event(rev, now, "send_"+r.State, map[string]string{"sentId": r.ID}); err != nil {
			return err
		}
	}
	th.finish(rev, now)
	return saveThread(t, th)
}

// sendView is a send's state as a draft shows it: Desktop's SendStatusView,
// with every recipient's delivery.
type sendView struct {
	SentID   string      `json:"sentId"`
	State    string      `json:"state"`
	Message  string      `json:"message,omitempty"`
	Code     OpCode      `json:"code,omitempty"`
	Missing  []delivered `json:"missing,omitempty"`
	Delivery []delivered `json:"delivery,omitempty"`
}

func (r *sendRecord) view() *sendView {
	v := &sendView{SentID: r.ID, State: r.State, Delivery: r.Delivery}
	if r.Error != nil {
		v.Code, v.Message = r.Error.Code, r.Error.Message
	}
	for _, d := range r.Delivery {
		if d.Status != deliverySent {
			v.Missing = append(v.Missing, d)
		}
	}
	return v
}

// Acknowledge is the coordinator's own Acknowledger (decision 8): the fixed
// acknowledgement, a template and no model call, as a journal record whose
// id and Message-ID come from the edge id, so a retry finds the first.
func (c *Coordinator) Acknowledge(_ context.Context, req AckRequest) error {
	return c.change(req.WorkerID, anyDevice, func(t *Tree) error {
		id := c.sendID(req.WorkerID, sendKindAck, req.EdgeID)
		if t.Has(sendPath(id)) {
			return nil
		}
		th, err := loadThread(t, req.ThreadID)
		if errors.Is(err, ErrNoThread) {
			return nil
		}
		if err != nil {
			return err
		}
		mb, err := loadMailbox(t)
		if err != nil {
			return err
		}
		rs, err := loadReplySettings(t)
		if err != nil {
			return err
		}
		subject, inReplyTo, refs := th.Subject, "", []string(nil)
		if e := th.mailOn(req.EdgeID); e != nil {
			subject, inReplyTo, refs = cmp.Or(e.Mail.Subject, th.Subject), e.Mail.MessageID, e.Mail.references()
		}
		text := "Received. We'll reply after review.\n\n" + footer(rs.firm(mb), false) + "\n"
		r := &sendRecord{ID: id, Kind: sendKindAck, ThreadID: th.ID, Attempt: 1, State: sendSending, To: []string{req.To}}
		raw, err := c.buildOut(t, th, mb, r, []string{sendKindAck, req.EdgeID}, replySubject(subject), inReplyTo, refs, text, nil, time.Now().UTC())
		if err != nil {
			return err
		}
		_, err = c.stageSend(t, req.WorkerID, r, raw)
		return err
	})
}

// buildOut builds r's bytes: its Message-ID from parts and the thread's reply
// token, from the worker's address. It fills r.MessageID, r.To and r.Created.
func (c *Coordinator) buildOut(t *Tree, th *threadRecord, mb *Mailbox, r *sendRecord, parts []string, subject, inReplyTo string, refs []string, text string, files []outFile, now time.Time) ([]byte, error) {
	keys, err := mb.keys()
	if err != nil {
		return nil, err
	}
	domain := domainOf(mb.Address)
	if th == nil {
		// An account notice belongs to no thread; its caller set its
		// Message-ID, and a reply to it is a new request.
		if r.MessageID == "" {
			return nil, errors.New("an email on no thread needs its Message-ID")
		}
	} else if r.MessageID == "" {
		handle, err := threadHandle(t, th)
		if err != nil {
			return nil, err
		}
		token, err := mail.MintReplyToken(keys, handle)
		if err != nil {
			return nil, err
		}
		r.MessageID = messageID(c.derivedPart(messageIDInfo, append([]string{th.WorkerID}, parts...)...), token, domain)
	}
	to, err := recipients(r.To, domain)
	if err != nil {
		return nil, err
	}
	r.To, r.Created, r.Updated = to, now, now
	return buildMessage(outgoing{
		From: mb.Address, To: to, Subject: subject, Date: now, MessageID: r.MessageID,
		InReplyTo: inReplyTo, References: refs, Text: text, Files: files,
	})
}
