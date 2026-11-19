package coordinator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// markRead is the read state of a thread, per device (each member's devices
// are their own), outside the thread's revision: reading a thread changes
// nothing anyone else sees, so it neither moves the revision nor takes a base
// revision, and needs no op log, as marking read twice is marking it read.
// Desktop sends {opId, threadId, kind:"markRead", args:{}}.
//
// A thread is unread on a device when something that asks for attention
// happened after the revision the device last read: its status moved (a job
// finished, a question was asked, mail was held), or mail or a question entry
// arrived or changed. A job's own progress doesn't, and a device's own
// operation marks the thread read at the revision it made.

// readsDir holds each thread's read state, <thread id>.json: device to the
// revision it read.
const readsDir = prefixRecord + "reads/"

type threadRead struct {
	Revision uint64    `json:"revision"`
	At       time.Time `json:"at"`
}

func readsPath(threadID string) string { return readsDir + threadID + ".json" }

func loadReads(t *Tree, threadID string) (map[string]threadRead, error) {
	reads := map[string]threadRead{}
	if _, err := readJSON(t, readsPath(threadID), &reads); err != nil {
		return nil, err
	}
	return reads, nil
}

// unread says whether th asked for attention after device last read it.
func unread(reads map[string]threadRead, device string, th *threadRecord) bool {
	return reads[device].Revision < th.attentionRev()
}

// attentionRev is the last revision at which th asked for attention.
func (th *threadRecord) attentionRev() uint64 {
	rev := th.StatusAt
	for _, e := range th.Entries {
		if e.Kind == entryMail || e.Kind == entryQuestion {
			rev = max(rev, e.Rev)
		}
	}
	return rev
}

// markReadAt records that device read the thread at rev, unless it already
// read it at rev or later.
func markReadAt(t *Tree, threadID, device string, rev uint64, now time.Time) error {
	reads, err := loadReads(t, threadID)
	if err != nil {
		return err
	}
	if reads[device].Revision >= rev {
		return nil
	}
	reads[device] = threadRead{Revision: rev, At: now.UTC()}
	return writeJSON(t, readsPath(threadID), reads)
}

// applyMarkRead records that device read the thread at its current revision.
func (c *Coordinator) applyMarkRead(device, workerID, threadID string, env opEnvelope) (OpResult, error) {
	if err := checkID("op", env.OpID); err != nil {
		return OpResult{}, err
	}
	if env.ThreadID != threadID {
		return OpResult{}, fmt.Errorf("%w: the envelope's threadId isn't the path's", ErrInvalid)
	}
	if len(env.Args) > 0 {
		dec := json.NewDecoder(bytes.NewReader(env.Args))
		dec.DisallowUnknownFields()
		var none struct{}
		if err := dec.Decode(&none); err != nil {
			return OpResult{}, fmt.Errorf("%w: markRead takes no args", ErrInvalid)
		}
	}
	var result OpResult
	err := c.change(workerID, device, func(t *Tree) error {
		th, err := loadThread(t, threadID)
		if errors.Is(err, ErrNoThread) {
			result = refused(0, CodeNotFound)
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := c.follow(t, th); err != nil {
			return err
		}
		result = OpResult{OK: true, Revision: th.Revision}
		return markReadAt(t, threadID, device, th.Revision, time.Now())
	})
	return result, err
}
