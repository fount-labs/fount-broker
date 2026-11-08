package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/fount-labs/fount-broker/internal/mail"
	"github.com/fount-labs/fount-broker/internal/protocol"
	"github.com/fount-labs/fount-broker/internal/route"
)

type fakeMail struct {
	keys []byte
	err  error
	got  []string
}

func (f *fakeMail) SetKeys(body []byte) error {
	if string(body) == "bad" {
		return mail.ErrBadKeys
	}
	f.keys = body
	return nil
}

func (f *fakeMail) Handle(_ context.Context, op, mailbox, path string, body []byte) (any, error) {
	f.got = append(f.got, op+" "+mailbox+" "+path+" "+string(body))
	if f.err != nil {
		return nil, f.err
	}
	return map[string]string{"op": op}, nil
}

func TestMailRequests(t *testing.T) {
	m := &fakeMail{}
	s := start(t, &fakeRoute{}, func(b *Broker) { b.Mail = m })

	s.send(`{"kind":"credential","id":1,"name":"mail_keys"}`, `{"addresses":[]}`)
	if r, _ := s.recv(); r.Kind != protocol.KindResult || string(m.keys) != `{"addresses":[]}` {
		t.Fatalf("mail_keys: %+v", r)
	}
	if _, ok := s.vault.Get("mail_keys"); ok {
		t.Fatal("mail_keys went to the vault")
	}
	s.send(`{"kind":"credential","id":2,"name":"mail_keys"}`, "bad")
	if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodeBadRequest {
		t.Fatalf("bad mail_keys: %+v", r)
	}

	s.send(`{"kind":"mail","id":3,"op":"get","mailbox":"ab","path":"cd"}`, "")
	r, body := s.recv()
	var out map[string]string
	json.Unmarshal(body, &out)
	if r.Kind != protocol.KindResult || r.ID != 3 || out["op"] != "get" || m.got[0] != "get ab cd " {
		t.Fatalf("get: %+v %s %v", r, body, m.got)
	}

	id := 10
	for err, code := range map[error]protocol.Code{
		fmt.Errorf("x: %w", mail.ErrRequest):      protocol.CodeBadRequest,
		mail.ErrNoKeys:                            protocol.CodeCredential,
		mail.ErrNotFound:                          protocol.CodeNotFound,
		mail.ErrSignature:                         protocol.CodeIntegrity,
		mail.ErrWrongKey:                          protocol.CodeIntegrity,
		fmt.Errorf("%w: x", route.ErrAttestation): protocol.CodeAttestation,
		fmt.Errorf("%w: 500", mail.ErrEdge):       protocol.CodeNetwork,
		errors.New("connection refused"):          protocol.CodeNetwork,
	} {
		m.err = err
		id++
		s.send(fmt.Sprintf(`{"kind":"mail","id":%d,"op":"list","mailbox":"ab"}`, id), "")
		if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != code {
			t.Errorf("%v: got %+v, want %s", err, r, code)
		}
	}
}

func TestMailWithoutAService(t *testing.T) {
	s := start(t, &fakeRoute{})
	s.send(`{"kind":"mail","id":1,"op":"list","mailbox":"ab"}`, "")
	if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodePolicy {
		t.Fatalf("got %+v", r)
	}
	s.send(`{"kind":"credential","id":2,"name":"mail_keys"}`, "{}")
	if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodePolicy {
		t.Fatalf("got %+v", r)
	}
}
