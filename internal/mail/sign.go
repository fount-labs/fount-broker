package mail

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Canonical is the string a Device API request signature covers (edge
// internal/deviceapi): method, path without the query, the body's SHA-256, the
// unix-seconds timestamp and the nonce, newline-separated.
func Canonical(method, path string, body []byte, ts int64, nonce string) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf("%s\n%s\n%s\n%d\n%s", method, path, hex.EncodeToString(sum[:]), ts, nonce)
}

// signRequest adds the address-class signature headers. The key id is
// hex(mailbox id), which is the M2 identity model (design §4).
func signRequest(h http.Header, k *Keys, method, path string, body []byte, now time.Time) {
	ts := now.Unix()
	nonce := rand.Text()
	sig := ed25519.Sign(k.Signing, []byte(Canonical(method, path, body, ts, nonce)))
	h.Set("Fount-Key-Id", hex.EncodeToString(k.MailboxID))
	h.Set("Fount-Timestamp", strconv.FormatInt(ts, 10))
	h.Set("Fount-Nonce", nonce)
	h.Set("Fount-Signature", base64.StdEncoding.EncodeToString(sig))
}
