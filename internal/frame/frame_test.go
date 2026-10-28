package frame

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
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
