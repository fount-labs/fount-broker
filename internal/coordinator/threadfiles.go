package coordinator

import (
	"cmp"
	"errors"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
)

// What the agent reads of the threads beside their message folders (§5.5):
// threads/index.md, one line per thread, and each thread's thread.md, one
// line per message. Both are written into each job's copy from the thread
// records, never kept. Everything in them came from mail, so like the rest of
// threads/ it's data.

// threadListings is index.md and every thread's thread.md, by path in the
// worker root.
func threadListings(t *Tree) map[string][]byte {
	var threads []*threadRecord
	for _, id := range threadIDs(t) {
		th, err := loadThread(t, id)
		if err != nil || th.Folder == "" {
			continue
		}
		threads = append(threads, th)
	}
	slices.SortFunc(threads, func(a, b *threadRecord) int {
		return cmp.Or(cmp.Compare(folderNumber(a.Folder), folderNumber(b.Folder)), strings.Compare(a.Folder, b.Folder))
	})
	out := map[string][]byte{}
	var index strings.Builder
	index.WriteString("# Threads\n\nOne line per thread: its folder, subject, people and last message.\n\n")
	for _, th := range threads {
		msgs := th.messages(t)
		if len(msgs) == 0 && th.Origin != "app" {
			// A thread whose mail is all held: its subject is a stranger's,
			// which no job reads (mailFolderPath).
			continue
		}
		last := th.UpdatedAt
		if len(msgs) > 0 {
			last = msgs[len(msgs)-1].at
		}
		fmt.Fprintf(&index, "- %s: %s; %s; last %s\n", codeSpan(th.Folder+"/"), oneLine(th.Subject), th.people(), last.UTC().Format("2006-01-02"))
		out[th.rootThreadDir()+"thread.md"] = th.threadMD(msgs)
	}
	out["threads/index.md"] = []byte(index.String())
	return out
}

// listedMessage is one message folder in the worker root.
type listedMessage struct {
	folder string
	at     time.Time
	line   string
}

// messages are th's message folders in the worker root, in order: mail that
// may run (held mail is in the record) and replies sent.
func (th *threadRecord) messages(t *Tree) []listedMessage {
	var out []listedMessage
	for _, e := range th.Entries {
		switch {
		case e.Kind == entryMail && e.Mail.Folder != "" && e.Mail.Held != heldWaiting && e.Mail.Held != heldAdded:
			m := e.Mail
			from := m.Sender
			if name := oneLine(m.SenderName); name != "" {
				from = name + " <" + m.Sender + ">"
			}
			at := time.UnixMilli(m.ReceivedAt).UTC()
			line := "from " + cmp.Or(from, "an unknown sender") + ", " + at.Format("2006-01-02 15:04") + " UTC"
			out = append(out, listedMessage{m.Folder, at, line + attachmentCount(t, prefixRoot+th.rootThreadDir()+m.Folder+"/attachments/")})
		case e.Kind == entryDraft && e.Draft.Folder != "":
			d := e.Draft
			at := e.At
			if d.Approval != nil {
				at = d.Approval.At
			}
			line := "reply to " + strings.Join(d.To, ", ") + ", " + at.UTC().Format("2006-01-02 15:04") + " UTC"
			out = append(out, listedMessage{d.Folder, at, line + attachmentCount(t, prefixRoot+th.rootThreadDir()+d.Folder+"/attachments/")})
		}
	}
	slices.SortStableFunc(out, func(a, b listedMessage) int { return cmp.Compare(folderNumber(a.folder), folderNumber(b.folder)) })
	return out
}

func (th *threadRecord) threadMD(msgs []listedMessage) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", cmp.Or(oneLine(th.Subject), noSubject))
	fmt.Fprintf(&b, "- Folder: %s\n- People: %s\n\n## Messages\n\n", codeSpan(th.rootThreadDir()), th.people())
	if len(msgs) == 0 {
		b.WriteString("No messages yet.\n")
	}
	for _, m := range msgs {
		fmt.Fprintf(&b, "- %s: %s\n", codeSpan(m.folder+"/"), m.line)
	}
	return []byte(b.String())
}

func (th *threadRecord) people() string {
	if len(th.Participants) == 0 {
		return "no one by email"
	}
	return oneLine(strings.Join(th.Participants, ", "))
}

func attachmentCount(t *Tree, dir string) string {
	switch n := len(t.List(dir)); n {
	case 0:
		return ""
	case 1:
		return ", 1 attachment"
	default:
		return fmt.Sprintf(", %d attachments", n)
	}
}

// folderNumber is the number a thread or message folder's name starts with.
func folderNumber(folder string) int {
	n, _ := strconv.Atoi(strings.SplitN(folder, " ", 2)[0])
	return n
}

// codeSpan is s in backticks, with more of them if s has one.
func codeSpan(s string) string {
	if strings.Contains(s, "`") {
		return "`` " + s + " ``"
	}
	return "`" + s + "`"
}

// writeReplyFolder makes a reply just approved its message folder in the
// thread, "<nn> <date> Reply": message.md as sent and its files under
// attachments/, each under its own name, numbered when two share one.
func writeReplyFolder(t *Tree, th *threadRecord, d *draftEntry, now time.Time) error {
	if d.Folder != "" || th.Folder == "" {
		return nil
	}
	folder := th.takeMessageFolder(now, replyWho, "")
	dir := prefixRoot + th.rootThreadDir() + folder + "/"
	from := ""
	if mb, err := loadMailbox(t); err == nil {
		from = mb.Address
	} else if !errors.Is(err, ErrNoMailbox) {
		return err
	}
	var sent []string
	taken := map[string]bool{}
	for _, p := range d.Files {
		data, err := t.Read(p)
		if err != nil {
			return err
		}
		name := uniqueName(path.Base(p), taken)
		if err := t.Write(dir+"attachments/"+name, data); err != nil {
			return err
		}
		sent = append(sent, dir+"attachments/"+name)
	}
	var b strings.Builder
	b.WriteString("```text\n")
	if from != "" {
		b.WriteString("From: " + from + "\n")
	}
	b.WriteString("To: " + strings.Join(d.To, ", ") + "\n")
	b.WriteString("Date: " + now.UTC().Format(time.RFC1123Z) + "\n")
	b.WriteString("Subject: " + oneLine(d.Subject) + "\n")
	if d.MessageID != "" {
		b.WriteString("Message-ID: " + d.MessageID + "\n")
	}
	b.WriteString("```\n\n")
	b.WriteString(strings.TrimSpace(d.Text) + "\n")
	if len(sent) > 0 {
		b.WriteString("\nAttached:\n")
		for _, p := range sent {
			b.WriteString("- " + codeSpan("attachments/"+path.Base(p)) + "\n")
		}
	}
	if err := t.Write(dir+"message.md", []byte(b.String())); err != nil {
		return err
	}
	d.Folder, d.SentFiles = folder, sent
	return nil
}

// uniqueName is name, or "name (2).ext" and on when taken has it.
func uniqueName(name string, taken map[string]bool) string {
	out := name
	ext := path.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	if stem == "" {
		stem, ext = name, ""
	}
	for i := 2; taken[strings.ToLower(out)]; i++ {
		out = fmt.Sprintf("%s (%d)%s", stem, i, ext)
	}
	taken[strings.ToLower(out)] = true
	return out
}
