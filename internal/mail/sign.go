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

// CanonicalGeneration is Canonical for a request that carries
// Fount-Generation: the edge appends "\n<generation>". Generation 0 is no
// header, and the string is Canonical's.
func CanonicalGeneration(method, path string, body []byte, ts int64, nonce string, generation uint64) string {
	s := Canonical(method, path, body, ts, nonce)
	if generation > 0 {
		s += "\n" + strconv.FormatUint(generation, 10)
	}
	return s
}

// HeaderGeneration names the coordinator generation a request is made under
// (edge DESIGN.md §8). The signature covers it.
const HeaderGeneration = "Fount-Generation"

// signRequest adds the address-class signature headers. The key id is
// hex(mailbox id), which is the M2 identity model (design §4). A generation
// above 0 is sent in Fount-Generation and signed.
func signRequest(h http.Header, k *Keys, method, path string, body []byte, now time.Time, generation uint64) {
	sign(h, k.Signing, hex.EncodeToString(k.MailboxID), method, path, body, now, generation)
}

func sign(h http.Header, key ed25519.PrivateKey, keyID, method, path string, body []byte, now time.Time, generation uint64) {
	ts := now.Unix()
	nonce := rand.Text()
	sig := ed25519.Sign(key, []byte(CanonicalGeneration(method, path, body, ts, nonce, generation)))
	h.Set("Fount-Key-Id", keyID)
	h.Set("Fount-Timestamp", strconv.FormatInt(ts, 10))
	h.Set("Fount-Nonce", nonce)
	h.Set("Fount-Signature", base64.StdEncoding.EncodeToString(sig))
	if generation > 0 {
		h.Set(HeaderGeneration, strconv.FormatUint(generation, 10))
	}
}
