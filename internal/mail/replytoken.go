package mail

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"strings"
)

// Reply tokens (Fount Mail design §12–13). Each worker thread has one token,
// carried in the recipient address as <local>+<token>@<domain>. The edge
// routes on the address; the broker checks the token, so a reply joins a
// thread only if it was addressed with that thread's token.
//
//	k     = HKDF-SHA256(ikm = the address's Ed25519 seed, salt = nil, info = replyTokenInfo), 32 bytes
//	mac   = HMAC-SHA256(k, "reply" || handle)[:5]
//	token = lowercase unpadded base32 of handle(5) || mac(5), 16 characters
//
// The handle is the app's name for the thread. The app puts the token only in
// the address it sends from; records never hold it.
const (
	replyTokenInfo = "fount reply token v1"
	replyHandleLen = 5
	replyMACLen    = 5
	replyTokenLen  = 16
)

var replyB32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// ReplyToken is what get found in the recipient's +tag: the thread handle when
// the token is this address's, or why it isn't.
type ReplyToken struct {
	Handle string `json:"handle,omitempty"`
	Error  string `json:"error,omitempty"`
}

const (
	replyTokenMalformed = "the reply token is malformed"
	replyTokenMismatch  = "the reply token doesn't match this address"
)

func replyKey(k *Keys) ([]byte, error) {
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
