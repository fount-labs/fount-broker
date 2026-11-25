package frame

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	frames := []Frame{
		{Header: []byte(`{"kind":"ready"}`)},
		{Header: []byte(`{"id":1}`), Body: []byte("opaque \x00 bytes")},
	}
	for _, f := range frames {
		if err := w.Write(f); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range frames {
		got, err := Read(&buf)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Header, want.Header) || !bytes.Equal(got.Body, want.Body) {
			t.Fatalf("got %q/%q, want %q/%q", got.Header, got.Body, want.Header, want.Body)
		}
	}
	if _, err := Read(&buf); !errors.Is(err, io.EOF) {
		t.Fatalf("clean end: got %v, want io.EOF", err)
	}
}

func TestRejectsOversizedHeaderBeforeAllocating(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(binary.BigEndian.AppendUint32(nil, MaxHeader+1))
	if _, err := Read(&buf); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
}

func TestRejectsOversizedBody(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(binary.BigEndian.AppendUint32(nil, 2))
	buf.WriteString("{}")
	buf.Write(binary.BigEndian.AppendUint32(nil, MaxBody+1))
	if _, err := Read(&buf); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
}

func TestTruncatedFrameIsUnexpectedEOF(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(binary.BigEndian.AppendUint32(nil, 10))
	buf.WriteString("{}")
	if _, err := Read(&buf); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v, want io.ErrUnexpectedEOF", err)
	}

	buf.Reset()
	buf.Write(binary.BigEndian.AppendUint32(nil, 2))
	buf.WriteString("{}")
	if _, err := Read(&buf); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("missing body: got %v, want io.ErrUnexpectedEOF", err)
	}
}

// A peer that declares a large body and sends none of it costs a small
// buffer, not the body it declared.
func TestADeclaredLengthAllocatesOnlyWhatCame(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(binary.BigEndian.AppendUint32(nil, 2))
	buf.WriteString("{}")
	buf.Write(binary.BigEndian.AppendUint32(nil, MaxBody))
	buf.Write(make([]byte, 100<<10))
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := Read(&buf); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v, want io.ErrUnexpectedEOF", err)
	}
	runtime.ReadMemStats(&after)
	if got := after.TotalAlloc - before.TotalAlloc; got > 1<<20 {
		t.Fatalf("a %d-byte declared body with 100 KiB sent allocated %d bytes", MaxBody, got)
	}
}

func TestReadMaxBoundsTheBody(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.Write(Frame{Header: []byte(`{}`), Body: make([]byte, 300<<10)}); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	if _, err := ReadMax(bytes.NewReader(raw), 256<<10); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
	f, err := ReadMax(bytes.NewReader(raw), 512<<10)
	if err != nil || len(f.Body) != 300<<10 {
		t.Fatalf("got %d bytes, %v", len(f.Body), err)
	}
}
