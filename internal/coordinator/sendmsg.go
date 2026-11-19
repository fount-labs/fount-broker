package coordinator

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// A worker email's bytes, as Desktop's mail/send/message.rs and body.rs make
// them: a plain-text body from the agent's markdown, citations as numbered
// notes over a Sources list, the files the email carries, and the footer
// (decision 13). The bytes are built once, when a draft or notice is made, and
// kept; a send posts exactly them (decision 14). The HTML part Desktop adds
// isn't built here yet: Cloud's emails are text/plain.

const (
	// maxRecipients is message.rs's MAX_RECIPIENTS.
	maxRecipients = 10
	// maxAttachmentBytes is message.rs's MAX_ATTACHMENT_BYTES: what fits a
	// 25 MiB message once base64 has grown it.
	maxAttachmentBytes = 19 << 20
	maxMessageBytes    = 25 << 20
	maxReferences      = 128
	// privacyLink is the footer's.
	privacyLink = "https://fount.sh/privacy"
)

// outgoing is one email to build.
type outgoing struct {
	From       string
	To         []string
	Subject    string
	Date       time.Time
	MessageID  string // with its angle brackets
	InReplyTo  string // with its angle brackets, or empty
	References []string
	Text       string
	Files      []outFile
}

type outFile struct {
	Name string
	Data []byte
}

// recipients is to lowercased, trimmed and without repeats, or an error for
// none, too many, or one at the worker's own mail domain.
func recipients(to []string, workerDomain string) ([]string, error) {
	var out []string
	for _, a := range to {
		addr, err := mailAddress(a)
		if err != nil {
			return nil, err
		}
		if strings.EqualFold(domainOf(addr), workerDomain) {
			return nil, refusal{code: CodeFountboxAddress}
		}
		if !slices.Contains(out, addr) {
			out = append(out, addr)
		}
	}
	switch {
	case len(out) == 0:
		return nil, fmt.Errorf("%w: an email needs a recipient", ErrInvalid)
	case len(out) > maxRecipients:
		return nil, fmt.Errorf("%w: at most %d recipients", ErrInvalid, maxRecipients)
	}
	return out, nil
}

// buildMessage is o as RFC 5322 bytes with CRLF line ends.
func buildMessage(o outgoing) ([]byte, error) {
	if len(o.Text) > maxNoteText+4096 {
		return nil, refusal{code: CodeTextTooLong}
	}
	total := 0
	for _, f := range o.Files {
		total += len(f.Data)
	}
	if total > maxAttachmentBytes {
		return nil, refusal{code: CodeAttachmentsTooLarge}
	}
	var b bytes.Buffer
	header := func(name, value string) { b.WriteString(name + ": " + value + "\r\n") }
	header("From", o.From)
	header("To", strings.Join(o.To, ", "))
	b.WriteString(subjectHeader(o.Subject))
	header("Date", o.Date.UTC().Format(time.RFC1123Z))
	header("Message-ID", o.MessageID)
	if o.InReplyTo != "" {
		header("In-Reply-To", o.InReplyTo)
	}
	if refs := o.References; len(refs) > 0 {
		if len(refs) > maxReferences {
			refs = append([]string{refs[0]}, refs[len(refs)-maxReferences+1:]...)
		}
		b.WriteString(fold("References", refs))
	}
	header("MIME-Version", "1.0")
	text := strings.ReplaceAll(strings.ReplaceAll(o.Text, "\r\n", "\n"), "\r", "\n")
	if len(o.Files) == 0 {
		writeTextPart(&b, text)
	} else {
		sum := sha256.Sum256([]byte(o.MessageID))
		boundary := "fount-" + hex.EncodeToString(sum[:12])
		header("Content-Type", `multipart/mixed; boundary="`+boundary+`"`)
		b.WriteString("\r\n")
		b.WriteString("--" + boundary + "\r\n")
		writeTextPart(&b, text)
		for _, f := range o.Files {
			b.WriteString("\r\n--" + boundary + "\r\n")
			writeFilePart(&b, f)
		}
		b.WriteString("\r\n--" + boundary + "--\r\n")
	}
	if b.Len() > maxMessageBytes {
		return nil, refusal{code: CodeAttachmentsTooLarge}
	}
	return b.Bytes(), nil
}

func writeTextPart(b *bytes.Buffer, text string) {
	if plain7bit(text) {
		b.WriteString("Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\n")
		b.WriteString(strings.ReplaceAll(text, "\n", "\r\n"))
		if !strings.HasSuffix(text, "\n") {
			b.WriteString("\r\n")
		}
		return
	}
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
	w := quotedprintable.NewWriter(b)
	w.Write([]byte(strings.ReplaceAll(text, "\n", "\r\n")))
	w.Close()
	b.WriteString("\r\n")
}

// plain7bit is text whose every line is at most 78 printable ASCII
// characters, which goes as it is.
func plain7bit(text string) bool {
	for line := range strings.SplitSeq(text, "\n") {
		if len(line) > 78 {
			return false
		}
		for i := 0; i < len(line); i++ {
			if c := line[i]; (c < 0x20 && c != '\t') || c > 0x7e {
				return false
			}
		}
		if strings.HasPrefix(line, "From ") || line == "." {
			return false
		}
	}
	return true
}

func writeFilePart(b *bytes.Buffer, f outFile) {
	ctype := mime.TypeByExtension(strings.ToLower(path.Ext(f.Name)))
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	if i := strings.Index(ctype, ";"); i >= 0 {
		ctype = ctype[:i]
	}
	b.WriteString("Content-Type: " + ctype + "\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	b.WriteString("Content-Disposition: attachment; " + filenameParam(f.Name) + "\r\n\r\n")
	enc := base64.StdEncoding.EncodeToString(f.Data)
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	if enc != "" {
		b.WriteString(enc + "\r\n")
	}
}

// filenameParam is filename="…" for a plain ASCII name, else RFC 2231's
// filename*=UTF-8”….
func filenameParam(name string) string {
	ascii := true
	for i := 0; i < len(name); i++ {
		if c := name[i]; c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			ascii = false
		}
	}
	if ascii {
		return `filename="` + name + `"`
	}
	return "filename*=UTF-8''" + strings.ReplaceAll(url.PathEscape(name), "+", "%2B")
}

// subjectHeader is the Subject line: ASCII folded at 78, anything else as
// RFC 2047 base64 words of at most 39 bytes each.
func subjectHeader(subject string) string {
	subject = strings.Join(strings.Fields(subject), " ")
	ascii := true
	for i := 0; i < len(subject); i++ {
		if subject[i] < 0x20 || subject[i] > 0x7e {
			ascii = false
		}
	}
	if ascii {
		return fold("Subject", strings.Fields(subject))
	}
	var words []string
	for rest := subject; rest != ""; {
		n := 0
		for n < len(rest) {
			_, size := utf8.DecodeRuneInString(rest[n:])
			if n+size > 39 {
				break
			}
			n += size
		}
		words = append(words, "=?UTF-8?B?"+base64.StdEncoding.EncodeToString([]byte(rest[:n]))+"?=")
		rest = rest[n:]
	}
	return fold("Subject", words)
}

// fold writes name: words, breaking lines before 78 characters.
func fold(name string, words []string) string {
	var b strings.Builder
	line := name + ":"
	b.WriteString(line)
	n := len(line)
	for _, w := range words {
		if n+1+len(w) > 78 && n > len(name)+1 {
			b.WriteString("\r\n")
			n = 0
		}
		b.WriteString(" " + w)
		n += 1 + len(w)
	}
	b.WriteString("\r\n")
	return b.String()
}

// replySubject is "Re: " and the subject it answers, once.
func replySubject(subject string) string {
	subject = strings.Join(strings.Fields(subject), " ")
	if len(subject) >= 3 && strings.EqualFold(subject[:3], "re:") {
		return subject
	}
	return "Re: " + subject
}

// renderBody is the agent's markdown as the email's text: each citation
// [[path?page=N|alias]] becomes [n] over a Sources list, the files carried
// are listed, and the footer closes it.
func renderBody(markdown string, attached []string, footer string) string {
	text, sources := markCitations(markdown)
	sections := []string{strings.TrimRight(text, " \t\n")}
	if len(attached) > 0 {
		lines := []string{"Attached"}
		for _, name := range attached {
			lines = append(lines, "- "+name)
		}
		sections = append(sections, strings.Join(lines, "\n"))
	}
	if len(sources) > 0 {
		lines := []string{"Sources"}
		for i, s := range sources {
			lines = append(lines, fmt.Sprintf("[%d] %s", i+1, s))
		}
		sections = append(sections, strings.Join(lines, "\n"))
	}
	sections = append(sections, footer)
	return strings.Join(sections, "\n\n") + "\n"
}

// markCitations numbers each citation by first appearance; one source cited
// twice keeps its number. Embeds (![[…]]) and citations with no path stay
// as written. Unlike body.rs it doesn't skip code spans.
func markCitations(markdown string) (string, []string) {
	markdown = strings.NewReplacer("【【", "[[", "】】", "]]").Replace(markdown)
	var keys, sources []string
	var out strings.Builder
	i := 0
	for {
		found := strings.Index(markdown[i:], "[[")
		if found < 0 {
			break
		}
		start := i + found
		out.WriteString(markdown[i:start])
		end := strings.Index(markdown[start+2:], "]]")
		if end < 0 || strings.HasSuffix(markdown[:start], "!") || strings.Contains(markdown[start+2:start+2+end], "\n") {
			out.WriteString("[[")
			i = start + 2
			continue
		}
		end += start + 2
		content := strings.TrimSpace(markdown[start+2 : end])
		label, ok := sourceLabel(content)
		if !ok {
			out.WriteString(markdown[start : end+2])
			i = end + 2
			continue
		}
		key := content
		if k, _, found := strings.Cut(content, "|"); found {
			key = strings.TrimSpace(k)
		}
		n := slices.Index(keys, key) + 1
		if n == 0 {
			keys, sources = append(keys, key), append(sources, label)
			n = len(keys)
		}
		fmt.Fprintf(&out, "[%d]", n)
		i = end + 2
	}
	out.WriteString(markdown[i:])
	return out.String(), sources
}

// sourceLabel is body.rs's source_label: "Q3 report (q3.pdf), page 4".
func sourceLabel(content string) (string, bool) {
	reference, alias := content, ""
	if r, a, ok := cutLast(content, "|"); ok {
		reference, alias = r, strings.TrimSpace(a)
	}
	p, query, _ := strings.Cut(reference, "?")
	p = strings.TrimRight(strings.TrimSpace(p), "/")
	name := strings.TrimSpace(p[strings.LastIndexByte(p, '/')+1:])
	if name == "" {
		return "", false
	}
	label := name
	if alias != "" && alias != name {
		label = alias + " (" + name + ")"
	}
	param := func(key string) string {
		for pair := range strings.SplitSeq(query, "&") {
			k, v, ok := strings.Cut(pair, "=")
			if ok && strings.EqualFold(strings.TrimSpace(k), key) && strings.TrimSpace(v) != "" {
				if d, err := url.QueryUnescape(strings.TrimSpace(v)); err == nil {
					return d
				}
				return strings.TrimSpace(v)
			}
		}
		return ""
	}
	if page := param("page"); page != "" && strings.Trim(page, "0123456789") == "" && strings.Trim(page, "0") != "" {
		label += ", page " + page
	}
	if lines := param("lines"); lines != "" {
		if a, b, ok := strings.Cut(lines, "-"); ok {
			label += ", lines " + strings.TrimSpace(a) + "–" + strings.TrimSpace(b)
		} else {
			label += ", line " + lines
		}
	}
	lower := strings.ToLower(name)
	spreadsheet := strings.HasSuffix(lower, ".xlsx") || strings.HasSuffix(lower, ".xls") || strings.HasSuffix(lower, ".csv")
	switch sheet, cell := param("sheet"), param("cell"); {
	case sheet != "" && cell != "":
		label += ", " + sheet + "!" + cell
	case sheet != "":
		label += ", sheet " + sheet
	case cell != "" && spreadsheet:
		label += ", " + cell
	case cell != "":
		label += ", cell " + cell
	}
	return label, true
}

func cutLast(s, sep string) (string, string, bool) {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}

// footer is decision 13's: who the email is from, that an AI assistant
// drafted it and, for a reply, that a person reviewed it, and the privacy
// link. A reply's bytes carry the reviewed line from the start: nothing a
// job drafts leaves without a person approving it.
func footer(firm string, reviewed bool) string {
	lines := []string{"--", "Sent by " + firm + " with Fount."}
	if reviewed {
		lines = append(lines, "Drafted by an AI assistant and reviewed by a person before it was sent.")
	} else {
		lines = append(lines, "Written by Fount automatically, without a person reviewing it.")
	}
	lines = append(lines, "How Fount handles your data: "+privacyLink)
	return strings.Join(lines, "\n")
}

// Message-IDs (decision 14) are fm.<26>.<token>@<domain>, the shape the reply
// token is read from (internal/mail replytoken.go). The 26 characters are
// derived, not drawn: an HMAC under a key from the wrapping key, which only
// the coordinator holds (decision 25), over what the email is, so a retry
// rebuilds the same ID and a member holding the worker's DEK can't mint one.
const (
	messageIDInfo  = "fount-coordinator/message-id/v1"
	approvalIDInfo = "fount-coordinator/approval-token/v1"
)

var crockford = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)

// derivedPart is 26 Crockford base32 characters, 130 bits of
// HMAC-SHA256(HKDF(wrapping key, info), parts joined by NUL).
func (c *Coordinator) derivedPart(info string, parts ...string) string {
	key, err := hkdf.Key(sha256.New, c.cfg.Key[:], nil, info, 32)
	if err != nil {
		panic("hkdf: " + err.Error())
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(strings.Join(parts, "\x00")))
	return crockford.EncodeToString(m.Sum(nil)[:17])[:26]
}

// messageID is the Message-ID for what parts name, carrying the thread's
// reply token.
func messageID(part, token, domain string) string {
	return "<fm." + part + "." + token + "@" + domain + ">"
}

// fountLink is a thread's link in the app (F).
func fountLink(workerID, threadID string) string {
	return "fount://worker/" + workerID + "/thread/" + threadID
}

// angled is a Message-ID in its angle brackets, or empty.
func angled(id string) string {
	id = strings.TrimSpace(id)
	if id == "" || strings.ContainsAny(id, " \t\r\n") {
		return ""
	}
	if !strings.HasPrefix(id, "<") {
		id = "<" + strings.TrimSuffix(id, ">") + ">"
	}
	return id
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
