package jobwire

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/fount-labs/fount-broker/internal/frame"
)

func TestDecodeJobPerHop(t *testing.T) {
	body := []byte(`{"sessionId":"s"}`)
	cases := []struct {
		name   string
		header string
		body   []byte
		hop    Hop
		ok     bool
	}{
		{"coordinator", `{"kind":"job","account":"acct_1","credentials":{"license":"L"}}`, body, FromCoordinator, true},
		{"coordinator, no credentials", `{"kind":"job","account":"a"}`, body, FromCoordinator, true},
		{"coordinator names the sandbox", `{"kind":"job","id":"j-1","account":"a"}`, body, FromCoordinator, false},
		{"unknown credential", `{"kind":"job","account":"a","credentials":{"aws":"x"}}`, body, FromCoordinator, false},
		{"broker", `{"kind":"job","id":"j-0a1b","account":"a"}`, body, FromBroker, true},
		{"credentials reach the supervisor", `{"kind":"job","id":"j-1","account":"a","credentials":{"license":"L"}}`, body, FromBroker, false},
		{"empty credentials reach the supervisor", `{"kind":"job","id":"j-1","account":"a","credentials":{}}`, body, FromBroker, false},
		{"broker without an id", `{"kind":"job","account":"a"}`, body, FromBroker, false},
		{"id climbs", `{"kind":"job","id":"../x","account":"a"}`, body, FromBroker, false},
		{"id upper case", `{"kind":"job","id":"J1","account":"a"}`, body, FromBroker, false},
		{"account with a slash", `{"kind":"job","account":"a/b"}`, body, FromCoordinator, false},
		{"no account", `{"kind":"job"}`, body, FromCoordinator, false},
		{"unknown field", `{"kind":"job","account":"a","memory":9}`, body, FromCoordinator, false},
		{"trailing data", `{"kind":"job","account":"a"}{}`, body, FromCoordinator, false},
		{"not a job", `{"kind":"workspace","account":"a"}`, body, FromCoordinator, false},
		{"no job file", `{"kind":"job","account":"a"}`, nil, FromCoordinator, false},
		{"job file too big", `{"kind":"job","account":"a"}`, make([]byte, MaxJobFile+1), FromCoordinator, false},
		{"intake", `{"kind":"job","mode":"intake","account":"a"}`, nil, FromCoordinator, true},
		{"intake from the broker", `{"kind":"job","mode":"intake","id":"j-1","account":"a"}`, nil, FromBroker, true},
		{"intake with credentials", `{"kind":"job","mode":"intake","account":"a","credentials":{"license":"L"}}`, nil, FromCoordinator, false},
		{"intake with empty credentials", `{"kind":"job","mode":"intake","account":"a","credentials":{}}`, nil, FromCoordinator, false},
		{"intake with a job file", `{"kind":"job","mode":"intake","account":"a"}`, body, FromCoordinator, false},
		{"unknown mode", `{"kind":"job","mode":"shell","account":"a"}`, body, FromCoordinator, false},
	}
	for _, c := range cases {
		_, err := DecodeJob(frame.Frame{Header: []byte(c.header), Body: c.body}, c.hop)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestStreamReadsOneKindToItsEnd(t *testing.T) {
	var buf bytes.Buffer
	w := frame.NewWriter(&buf)
	data := strings.Repeat("x", 3*chunk+5)
	c := Chunks{W: w, Kind: KindWorkspace}
	io.WriteString(c, data)
	c.Close()
	Send(w, Reply{Kind: KindIndex}, []byte("i"))
	Send(w, Reply{Kind: KindIndex}, nil)
	Send(w, Reply{Kind: KindError, Message: "sandbox gone"}, nil)

	got, err := io.ReadAll(&Stream{R: &buf, Kind: KindWorkspace})
	if err != nil || string(got) != data {
		t.Fatalf("%d bytes, %v", len(got), err)
	}
	if got, err := io.ReadAll(&Stream{R: &buf, Kind: KindIndex}); err != nil || string(got) != "i" {
		t.Fatalf("%q %v", got, err)
	}
	_, err = io.ReadAll(&Stream{R: &buf, Kind: KindIndex})
	var remote *Remote
	if !errors.As(err, &remote) || remote.Message != "sandbox gone" {
		t.Fatalf("%v", err)
	}
}

func TestStreamRefusesAnotherKindOrACutStream(t *testing.T) {
	var buf bytes.Buffer
	w := frame.NewWriter(&buf)
	Send(w, Reply{Kind: KindWorkspace}, []byte("w"))
	Send(w, Reply{Kind: KindIndex}, []byte("i"))
	if _, err := io.ReadAll(&Stream{R: &buf, Kind: KindWorkspace}); !errors.Is(err, ErrMalformed) {
		t.Errorf("%v", err)
	}
	buf.Reset()
	Send(w, Reply{Kind: KindWorkspace}, []byte("w"))
	if _, err := io.ReadAll(&Stream{R: &buf, Kind: KindWorkspace}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("%v", err)
	}
}

func FuzzDecodeJob(f *testing.F) {
	f.Add([]byte(`{"kind":"job","account":"a","credentials":{"license":"L"}}`), []byte("{}"))
	f.Add([]byte(`{"kind":"job","id":"j-1","account":"a"}`), []byte("{}"))
	f.Fuzz(func(t *testing.T, header, body []byte) {
		for _, hop := range []Hop{FromCoordinator, FromBroker} {
			j, err := DecodeJob(frame.Frame{Header: header, Body: body}, hop)
			if err != nil {
				continue
			}
			if hop == FromBroker && (j.Credentials != nil || !idPattern.MatchString(j.ID)) {
				t.Fatalf("broker hop let through %+v", j)
			}
			if hop == FromCoordinator && j.ID != "" {
				t.Fatalf("coordinator hop let through %+v", j)
			}
		}
	})
}

func TestBindFrames(t *testing.T) {
	ok := frame.Frame{Header: []byte(`{"kind":"bind","account":"tm_0123456789abcdef01234567"}`)}
	if FrameKind(ok.Header) != KindBind {
		t.Fatal("kind")
	}
	if a, err := DecodeBind(ok); err != nil || a != "tm_0123456789abcdef01234567" {
		t.Fatalf("%q %v", a, err)
	}
	for _, bad := range []frame.Frame{
		{Header: []byte(`{"kind":"bind","account":""}`)},
		{Header: []byte(`{"kind":"bind","account":"a b"}`)},
		{Header: []byte(`{"kind":"bind","account":"tm_x","extra":1}`)},
		{Header: ok.Header, Body: []byte("x")},
		{Header: []byte(`{"kind":"job","account":"tm_x"}`)},
	} {
		if _, err := DecodeBind(bad); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", bad.Header, err)
		}
	}
	// The coordinator binds with a bind frame, never a job's field.
	j := frame.Frame{Header: []byte(`{"kind":"job","account":"a","bound":true}`), Body: []byte("{}")}
	if _, err := DecodeJob(j, FromCoordinator); !errors.Is(err, ErrMalformed) {
		t.Fatalf("bound from the coordinator: %v", err)
	}
	if got, err := DecodeJob(frame.Frame{Header: []byte(`{"kind":"job","id":"j-1","account":"a","bound":true}`), Body: []byte("{}")}, FromBroker); err != nil || !got.Bound {
		t.Fatalf("%+v %v", got, err)
	}
}
