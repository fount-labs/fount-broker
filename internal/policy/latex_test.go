package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestLatexIndexMatchesItsDigest(t *testing.T) {
	sum := sha256.Sum256(latexIndex)
	if got := hex.EncodeToString(sum[:]); got != LatexIndexSHA256 {
		t.Fatalf("embedded index has digest %s, want %s", got, LatexIndexSHA256)
	}
	files, err := latexFiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 100_000 {
		t.Fatalf("index lists %d files", len(files))
	}
	for _, name := range []string{"SHA256SUM", "latex.ltx", "amsmath.sty"} {
		if _, ok := latexRange(name); !ok {
			t.Errorf("%s is not in the index", name)
		}
	}
}
