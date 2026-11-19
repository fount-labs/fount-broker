package mail

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"slices"
	"strings"
)

// Reply tokens (Fount Mail design §12–13). Each worker thread has one token,
// carried in each worker email's Message-ID as <fm.<26>.<token>@<domain>>, so a
// reply carries it back in In-Reply-To and References. Emails sent before that
// carried it in a Reply-To of <local>+<token>@<domain>, so the recipient's +tag
// is still read. The broker checks the token, so a reply joins a thread only if
// it answers, or was addressed with, that thread's token. The edge never reads
// it, so it holds no token key.
//
//	k     = Keys.TokenKey when set (a Cloud worker's, decision 25), else
//	        HKDF-SHA256(ikm = the address's Ed25519 seed, salt = nil, info = replyTokenInfo), 32 bytes
//	mac   = HMAC-SHA256(k, "reply" || handle)[:5]
//	token = lowercase unpadded base32 of handle(5) || mac(5), 16 characters
//
// A Desktop worker's tokens come from its signing seed, which only its device
// holds. A Cloud worker's address keys are wrapped to every admin device, so
// its tokens come from TokenKey, which the coordinator derives from its own
// wrapping key and never stores or hands out: a removed admin's copy of the
// signing seed can't forge one, and rotating the signing key needs no old seed.
// A key with TokenKey never falls back to the seed.
//
// The handle is the app's name for the thread. The app puts the token only in
// the Message-IDs of the emails it sends.
const (
	replyTokenInfo = "fount reply token v1"
	replyHandleLen = 5
	replyMACLen    = 5
	replyTokenLen  = 16
)

var replyB32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// ReplyToken is what get found in the recipient's +tag or the reply's signed
// In-Reply-To and References: the thread handle when the token is this
// address's, or why it isn't.
type ReplyToken struct {
	Handle string `json:"handle,omitempty"`
	Error  string `json:"error,omitempty"`
}

const (
	replyTokenMalformed = "the reply token is malformed"
	replyTokenMismatch  = "the reply token doesn't match this address"
)

// TokenKeySize is the length of Keys.TokenKey.
const TokenKeySize = 32

func replyKey(k *Keys) ([]byte, error) {
	if k.TokenKey != nil {
		if len(k.TokenKey) != TokenKeySize {
			return nil, ErrBadKeys
		}
		return k.TokenKey, nil
	}
	return hkdf.Key(sha256.New, k.Signing.Seed(), nil, replyTokenInfo, 32)
}

func replyMAC(key, handle []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("reply"))
	m.Write(handle)
	return m.Sum(nil)[:replyMACLen]
}

// MintReplyToken returns the token for handle, 10 lowercase hex characters.
func MintReplyToken(k *Keys, handle string) (string, error) {
	if !validHex(handle, replyHandleLen) {
		return "", ErrRequest
	}
	h, _ := hex.DecodeString(handle)
	key, err := replyKey(k)
	if err != nil {
		return "", err
	}
	return replyB32.EncodeToString(append(h, replyMAC(key, h)...)), nil
}

// CheckReplyToken reads the +tag of an envelope recipient. It returns nil when
// the local part has no tag. Case is ignored, since mail servers may change it.
func CheckReplyToken(k *Keys, recipient string) *ReplyToken {
	at := strings.LastIndexByte(recipient, '@')
	if at < 0 {
		at = len(recipient)
	}
	_, tag, ok := strings.Cut(recipient[:at], "+")
	if !ok {
		return nil
	}
	return checkToken(k, tag)
}

// checkToken checks one token against this address's key, ignoring case.
func checkToken(k *Keys, tag string) *ReplyToken {
	if len(tag) != replyTokenLen {
		return &ReplyToken{Error: replyTokenMalformed}
	}
	b, err := replyB32.DecodeString(strings.ToLower(tag))
	if err != nil || len(b) != replyHandleLen+replyMACLen {
		return &ReplyToken{Error: replyTokenMalformed}
	}
	key, err := replyKey(k)
	if err != nil {
		return &ReplyToken{Error: replyTokenMismatch}
	}
	h := b[:replyHandleLen]
	if !hmac.Equal(b[replyHandleLen:], replyMAC(key, h)) {
		return &ReplyToken{Error: replyTokenMismatch}
	}
	return &ReplyToken{Handle: hex.EncodeToString(h)}
}

// The random part of a worker email's Message-ID, fm.<26>.<token>@<domain>. It
// keeps every email's ID its own.
const replyIDRandomLen = 26

// CheckReplyTokenHeaders reads the tokens in the Message-IDs a reply answers:
// the In-Reply-To and References the sender check read. It uses them only when
// an aligned signature covers both, since a header anyone could have typed
// proves nothing. domain is the mail domain, from the envelope recipient.
//
// When the passing tokens name several threads, the parent's wins: an
// In-Reply-To token, else the last References one. It returns nil when there
// are no token IDs, and the first failure when none pass. IDs without a token,
// fm.<26>@<domain> from before tokens moved there, aren't token IDs.
func CheckReplyTokenHeaders(k *Keys, check *EdgeCheck, domain string) *ReplyToken {
	if check == nil || !threadHeadersSigned(check) {
		return nil
	}
	var first *ReplyToken
	var parent, last string
	for i, value := range []string{check.Headers.InReplyTo, check.Headers.References} {
		for _, id := range msgIDs(value) {
			tag, ok := replyIDToken(id, domain)
			if !ok {
				continue
			}
			t := checkToken(k, tag)
			switch {
			case t.Handle == "":
				if first == nil {
					first = t
				}
			case i == 0:
				parent = t.Handle
			default:
				last = t.Handle
			}
		}
	}
	switch {
	case parent != "":
		return &ReplyToken{Handle: parent}
	case last != "":
		return &ReplyToken{Handle: last}
	}
	return first
}

// threadHeadersSigned is true when an aligned signature leaves neither
// In-Reply-To nor References unsigned.
func threadHeadersSigned(c *EdgeCheck) bool {
	if !c.Aligned {
		return false
	}
	for _, s := range c.DKIM {
		if s.Aligned && !slices.Contains(s.Unsigned, "in-reply-to") && !slices.Contains(s.Unsigned, "references") {
			return true
		}
	}
	return false
}

// msgIDs are the ids in a msg-id list: what's inside each <…>, or the pieces
// between whitespace and commas when there are no brackets (message-format.md
// §6.1).
func msgIDs(s string) []string {
	if !strings.Contains(s, "<") {
		return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n' })
	}
	var ids []string
	for {
		_, rest, ok := strings.Cut(s, "<")
		if !ok {
			return ids
		}
		id, rest, ok := strings.Cut(rest, ">")
		if !ok {
			return ids
		}
		ids = append(ids, id)
		s = rest
	}
}

// replyIDToken is the token part of fm.<26>.<token>@<domain>. A token part of
// the wrong shape is still returned, so it fails as malformed.
func replyIDToken(id, domain string) (string, bool) {
	at := strings.LastIndexByte(id, '@')
	if at < 0 || domain == "" || !strings.EqualFold(id[at+1:], domain) {
		return "", false
	}
	parts := strings.Split(id[:at], ".")
	if len(parts) != 3 || parts[0] != "fm" || len(parts[1]) != replyIDRandomLen || parts[2] == "" {
		return "", false
	}
	return parts[2], true
}
