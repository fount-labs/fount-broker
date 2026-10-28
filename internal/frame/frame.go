// Package frame reads and writes the broker's wire format over a byte stream.
//
// A frame is a JSON header and an opaque body, each prefixed by its length as
// a big-endian uint32:
//
//	[u32 header length][header JSON][u32 body length][body]
//
// The header is the only part the broker parses. The body is passed through
// without being read, so an inference payload never touches a parser.
package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

const (
	// MaxHeader bounds the JSON header. Headers carry IDs, enum values and a
	// few short strings; anything larger is malformed.
	MaxHeader = 64 << 10
	// MaxBody bounds one body. A chat request with attached images is the
	// largest expected payload.
	MaxBody = 64 << 20
)

var ErrTooLarge = errors.New("frame exceeds size limit")

// Frame is one message: a header to decode and an opaque body.
type Frame struct {
	Header []byte
	Body   []byte
}

// Read reads one frame. It returns io.EOF only when the stream ends cleanly
// between frames.
func Read(r io.Reader) (Frame, error) {
	header, err := readPart(r, MaxHeader)
	if err != nil {
		return Frame{}, err
	}
	body, err := readPart(r, MaxBody)
	if err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return Frame{}, err
	}
	return Frame{Header: header, Body: body}, nil
}

func readPart(r io.Reader, limit uint32) ([]byte, error) {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n > limit {
		return nil, fmt.Errorf("%w: %d > %d bytes", ErrTooLarge, n, limit)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return buf, nil
}

// Writer writes whole frames, safe for concurrent use.
type Writer struct {
	mu sync.Mutex
	w  io.Writer
}

func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

func (w *Writer) Write(f Frame) error {
	if len(f.Header) > MaxHeader || len(f.Body) > MaxBody {
		return ErrTooLarge
	}
	buf := make([]byte, 0, 8+len(f.Header)+len(f.Body))
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(f.Header)))
	buf = append(buf, f.Header...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(f.Body)))
	buf = append(buf, f.Body...)
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := w.w.Write(buf)
	return err
}
