package mail

import "encoding/hex"

// validHex reports whether s is exactly n bytes of lowercase hex.
func validHex(s string, n int) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == n && hex.EncodeToString(b) == s
}
