package policy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// LaTeX support files come from the Tectonic project's TeX Live bundle: one
// tar file, read a file at a time with Range requests. The relay that
// Tectonic starts from redirects here; the broker names the host directly so
// nothing can redirect it.
const (
	LatexBase   = "https://data1b.fullyjustified.net/"
	LatexBundle = "tlextras-2022.0r0.tar"
)

// latexIndex is the bundle's index: each file's name, offset and length in
// the tar. A file name is all the app can choose, and the broker turns it
// into the byte range listed here.
//
//go:embed latex/tlextras-2022.0r0.tar.index.gz
var latexIndex []byte

// LatexIndexSHA256 is the digest of latexIndex, which the latex.index
// destination serves to the app.
const LatexIndexSHA256 = "979a52178eb353c803dde1f66efe43ff7ae2ab908000323d4fef29e98e382ebd"

type byteRange struct{ offset, length int64 }

var latexFiles = sync.OnceValues(func() (map[string]byteRange, error) {
	gz, err := gzip.NewReader(bytes.NewReader(latexIndex))
	if err != nil {
		return nil, err
	}
	files := map[string]byteRange{}
	lines := bufio.NewScanner(gz)
	for lines.Scan() {
		bits := strings.Fields(lines.Text())
		if len(bits) != 3 {
			return nil, fmt.Errorf("latex index: malformed line %q", lines.Text())
		}
		offset, err1 := strconv.ParseInt(bits[1], 10, 64)
		length, err2 := strconv.ParseInt(bits[2], 10, 64)
		if err1 != nil || err2 != nil || offset < 0 || length < 0 {
			return nil, fmt.Errorf("latex index: malformed line %q", lines.Text())
		}
		if length > 0 {
			files[bits[0]] = byteRange{offset, length}
		}
	}
	return files, lines.Err()
})

// latexRange is the Range header for one file in the bundle. Empty files
// have no range and aren't listed: the app doesn't ask for them.
func latexRange(name string) (string, bool) {
	files, err := latexFiles()
	if err != nil {
		return "", false
	}
	r, ok := files[name]
	if !ok {
		return "", false
	}
	return fmt.Sprintf("bytes=%d-%d", r.offset, r.offset+r.length-1), true
}

func init() {
	Destinations["latex.index"] = Destination{
		Route:  RouteLatex,
		Method: "GET",
		Path:   LatexBundle + ".index.gz",
		Accept: []string{""},
		Body:   Body{Kind: BodyNone},
		SHA256: LatexIndexSHA256,
	}
	// One file from the bundle, named in the request's path.
	Destinations["latex.file"] = Destination{
		Route:  RouteLatex,
		Method: "GET",
		Path:   LatexBundle,
		Accept: []string{""},
		Body:   Body{Kind: BodyNone},
		Range:  latexRange,
	}
}
