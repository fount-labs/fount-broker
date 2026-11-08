package verify

import (
	"bytes"
	"errors"
	"strings"
)

// field is one header field as it appears in the message.
type field struct {
	Name  string // as written
	Value string // unfolded, trimmed
}

const (
	maxFields      = 1000
	maxHeaderBytes = 1 << 20
)

var errHeader = errors.New("message header is malformed")

// splitHeader returns the top-level header fields of raw, in order. It never
// interprets a value.
func splitHeader(raw []byte) ([]field, error) {
	end := bytes.Index(raw, []byte("\r\n\r\n"))
	if end < 0 {
		if !bytes.HasSuffix(raw, []byte("\r\n")) {
			return nil, errHeader
		}
		end = len(raw) - 2 // headers only, no body
	}
	if end > maxHeaderBytes {
		return nil, errHeader
	}
	var out []field
	for _, line := range strings.Split(string(raw[:end]), "\r\n") {
		if line == "" {
			return nil, errHeader
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(out) == 0 {
				return nil, errHeader
			}
			out[len(out)-1].Value += " " + strings.TrimSpace(line)
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || name == "" || strings.ContainsAny(name, " \t") {
			return nil, errHeader
		}
		out = append(out, field{Name: name, Value: strings.TrimSpace(value)})
		if len(out) > maxFields {
			return nil, errHeader
		}
	}
	for i := range out {
		out[i].Value = strings.TrimSpace(out[i].Value)
	}
	return out, nil
}

// all returns the values of every field named name, case-insensitively.
func all(fields []field, name string) []string {
	var out []string
	for _, f := range fields {
		if strings.EqualFold(f.Name, name) {
			out = append(out, f.Value)
		}
	}
	return out
}

// tags parses a DKIM tag-list (RFC 6376 §3.2): "k=v; k=v". Whitespace inside a
// value is kept for the caller to strip where the RFC says to.
func tags(s string) (map[string]string, bool) {
	out := map[string]string{}
	for part := range strings.SplitSeq(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return nil, false
		}
		if _, dup := out[k]; dup {
			return nil, false
		}
		out[k] = strings.TrimSpace(v)
	}
	return out, true
}

func stripSpace(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, s)
}
