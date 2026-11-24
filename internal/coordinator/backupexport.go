package coordinator

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Export: a worker's threads, mail and files, as a folder a person keeps
// (launch-plan.md "Durable storage", leaving Cloud). It is a tar; Desktop
// unpacks it into the folder the person picks:
//
//	fount-export.json   what this is: the worker, when, and what each folder holds
//	files/              the worker's files, as its workspace has them
//	threads/<id>.json   each thread as the app shows it
//	mail/address.json   the worker's address (not its keys)
//	mail/held/          mail held for a person, as received
//	mail/sent/          the send journal: every reply and what became of it
//	sessions/           the workspace's .fount folder: sessions and transcripts
//	jobs/               each job's events and proposed versions
//	record/             the rest of the worker's records, as stored
//
// The search index is left out: it is rebuilt from the files.

// ExportIndex is fount-export.json.
type ExportIndex struct {
	Format     int               `json:"format"`
	Worker     string            `json:"worker"`
	Address    string            `json:"address,omitempty"`
	ExportedAt time.Time         `json:"exportedAt"`
	Version    uint64            `json:"version"`
	Threads    int               `json:"threads"`
	Files      int               `json:"files"`
	Folders    map[string]string `json:"folders"`
}

const exportFormat = 1

// exportMove maps where a path is in the tree to where it goes in the export,
// first match wins.
var exportMove = []struct{ from, to string }{
	{prefixRoot, "files/"},
	{heldMailDir, "mail/held/"},
	{sendsDir, "mail/sent/"},
	{prefixFount, "sessions/"},
	{prefixJobs, "jobs/"},
	{prefixRecord, "record/"},
}

// exportPath is where the tree's path p goes, or "" when it's left out.
func exportPath(p string) string {
	switch {
	case p == mailboxPath, strings.HasPrefix(p, prefixIndex), strings.HasPrefix(p, threadsDir):
		// The mailbox has keys; threads are written as views.
		return ""
	}
	for _, m := range exportMove {
		if rest, ok := strings.CutPrefix(p, m.from); ok {
			return m.to + rest
		}
	}
	return "record/other/" + p
}

// ExportWorker writes the worker's export, as a tar, for device. It reads the
// tree under the worker's lock into memory, so a slow download doesn't hold
// the worker up.
func (c *Coordinator) ExportWorker(device, workerID string) ([]byte, error) {
	if c.Retired() {
		return nil, ErrStaleCoordinator
	}
	lock, w, err := c.workerLock(workerID)
	if err != nil {
		return nil, err
	}
	lock.Lock()
	defer lock.Unlock()
	t, err := c.loadTree(w, device)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	now := time.Now().UTC()
	add := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: now, Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	addJSON := func(name string, v any) error {
		data, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		return add(name, data)
	}
	idx := ExportIndex{Format: exportFormat, Worker: w.ID, ExportedAt: now, Version: t.Version(), Folders: map[string]string{
		"files":    "the email agent's files",
		"threads":  "each thread, as the app shows it",
		"mail":     "the email agent's address, mail held for a person, and every reply sent",
		"sessions": "the workspace's sessions and transcripts",
		"jobs":     "each job's events and proposed file versions",
		"record":   "the rest of the email agent's records",
	}}
	if mb, err := loadMailbox(t); err == nil {
		idx.Address = mb.Address
		if err := addJSON("mail/address.json", map[string]string{"address": mb.Address, "mailboxId": mb.MailboxID}); err != nil {
			return nil, err
		}
	}
	for _, id := range threadIDs(t) {
		th, err := loadThread(t, id)
		if err != nil {
			return nil, err
		}
		if err := addJSON("threads/"+id+".json", th.view()); err != nil {
			return nil, err
		}
		idx.Threads++
	}
	paths := t.List("")
	slices.Sort(paths)
	for _, p := range paths {
		to := exportPath(p)
		if to == "" {
			continue
		}
		data, err := t.Read(p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if err := add(to, data); err != nil {
			return nil, err
		}
		if strings.HasPrefix(p, prefixRoot) {
			idx.Files++
		}
	}
	if err := addJSON("fount-export.json", idx); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// exportWorker is GET {prefix}/workers/{id}/export: an admin's, since it
// takes everything the worker holds.
func (a *api) exportWorker(rw http.ResponseWriter, r *http.Request) {
	w, err := a.worker(r)
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	data, err := a.c.ExportWorker(a.device(), w.ID)
	if err != nil {
		fail(rw, statusOf(err), err)
		return
	}
	rw.Header().Set("Content-Type", "application/x-tar")
	rw.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="fount-worker-%s.tar"`, w.ID))
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write(data)
}
