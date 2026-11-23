package coordinator

import (
	"fmt"
	"strings"
	"time"
	"unicode"
)

// Readable names (m4-cloud-runners.md §5.5, "Readable names"). Every folder
// the agent sees is named for people: a thread is "<n> <subject>", a message
// "<nn> <date> <who>". The IDs the coordinator keys them by (thr_…, the
// edge's message ID, jm_…) stay in its records. A name comes from mail, so
// it's cleaned, and it's fixed when its folder is made: citations stay valid.

const (
	maxSubjectName = 40
	maxWhoName     = 30
	noSubject      = "No subject"
	noSender       = "Unknown sender"
	replyWho       = "Reply"
	// threadCountPath is the worker's thread counter: the n of the last
	// thread folder made, so a number is never given twice.
	threadCountPath = prefixRecord + "threadcount.json"
)

// cleanName drops control and format characters (bidi marks among them),
// `/ \ : * ? " < > |` and leading dots, collapses whitespace, and cuts at a
// word to max characters. Trailing dots go too: Windows can't keep them in a
// folder name on Desktop's copy. Empty when nothing is left.
func cleanName(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r):
			return ' '
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), r == unicode.ReplacementChar, strings.ContainsRune(`/\:*?"<>|`, r):
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	s = strings.TrimLeft(s, ". ")
	if r := []rune(s); len(r) > max {
		cut := string(r[:max])
		if next := r[max]; next != ' ' {
			if i := strings.LastIndexByte(cut, ' '); i > 0 {
				cut = cut[:i]
			}
		}
		s = cut
	}
	return strings.TrimRight(s, ". ")
}

// threadFolderName is "<n> <subject>": n alone makes it unique.
func threadFolderName(n int, subject string) string {
	name := cleanName(subject, maxSubjectName)
	if name == "" {
		name = noSubject
	}
	return fmt.Sprintf("%d %s", n, name)
}

// messageFolderName is "<nn> <date> <who>": nn counts the thread's messages
// from 01, date is the UTC day, who the sender's name, else their address,
// or Reply for mail out.
func messageFolderName(nn int, at time.Time, name, address string) string {
	who := cleanName(name, maxWhoName)
	if who == "" {
		who = cleanName(address, maxWhoName)
	}
	if who == "" {
		who = noSender
	}
	return fmt.Sprintf("%02d %s %s", nn, at.UTC().Format("2006-01-02"), who)
}

// newThreadFolder takes the worker's next thread number for a thread titled
// title.
func newThreadFolder(t *Tree, title string) (string, error) {
	var count struct {
		Threads int `json:"threads"`
	}
	if _, err := readJSON(t, threadCountPath, &count); err != nil {
		return "", err
	}
	count.Threads++
	if err := writeJSON(t, threadCountPath, count); err != nil {
		return "", err
	}
	return threadFolderName(count.Threads, title), nil
}

// nextMessageFolder is the name the thread's next message folder gets,
// without taking it.
func (th *threadRecord) nextMessageFolder(at time.Time, name, address string) string {
	return messageFolderName(th.Messages+1, at, name, address)
}

// takeMessageFolder names the thread's next message folder and counts it.
func (th *threadRecord) takeMessageFolder(at time.Time, name, address string) string {
	folder := th.nextMessageFolder(at, name, address)
	th.Messages++
	return folder
}

// rootThreadDir is the thread's folder in the worker root, a root-relative
// path ending in "/".
func (th *threadRecord) rootThreadDir() string {
	return "threads/" + th.Folder + "/"
}

// oneLine is text for a generated listing: one line, no control or format
// characters.
func oneLine(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r):
			return ' '
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r):
			return -1
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}
