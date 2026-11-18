package broker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/fount-labs/fount-broker/internal/channel"
	"github.com/fount-labs/fount-broker/internal/protocol"
)

type fakeCloud func(ctx context.Context, method, target string, body []byte) (*http.Response, error)

func (f fakeCloud) Do(ctx context.Context, method, target string, body []byte) (*http.Response, error) {
	return f(ctx, method, target, body)
}

func TestACloudRequestStreamsLikeAFetch(t *testing.T) {
	s := start(t, nil, func(b *Broker) {
		b.Cloud = fakeCloud(func(_ context.Context, method, target string, body []byte) (*http.Response, error) {
			if _, err := channel.CheckRequest(method, target); err != nil {
				return nil, err
			}
			return &http.Response{StatusCode: 201, Header: http.Header{"Content-Type": {"application/json"}},
				Body: io.NopCloser(strings.NewReader(method + " " + target + " " + string(body)))}, nil
		})
	})
	s.send(`{"kind":"cloud","id":1,"op":"POST","path":"v1/workers"}`, `{}`)
	head, _ := s.recv()
	if head.Kind != protocol.KindHead || head.Status != 201 || head.ContentType != "application/json" {
		t.Fatalf("head %+v", head)
	}
	data, body := s.recv()
	if data.Kind != protocol.KindData || string(body) != "POST v1/workers {}" {
		t.Fatalf("data %+v %q", data, body)
	}
	if end, _ := s.recv(); end.Kind != protocol.KindEnd {
		t.Fatalf("end %+v", end)
	}

	s.send(`{"kind":"cloud","id":2,"op":"DELETE","path":"v1/workers"}`, ``)
	if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodePolicy {
		t.Fatalf("an operation the API lacks: %+v", r)
	}
}

func TestCloudFailuresHaveTheirCodes(t *testing.T) {
	for _, c := range []struct {
		err  error
		want protocol.Code
	}{
		{fmt.Errorf("%w: no session", channel.ErrIdentity), protocol.CodeCredential},
		{fmt.Errorf("%w: expired", channel.ErrRefused), protocol.CodeCredential},
		{fmt.Errorf("%w: another repo", channel.ErrCoordinator), protocol.CodeAttestation},
		{errors.New("connection reset"), protocol.CodeNetwork},
	} {
		s := start(t, nil, func(b *Broker) {
			b.Cloud = fakeCloud(func(context.Context, string, string, []byte) (*http.Response, error) { return nil, c.err })
		})
		s.send(`{"kind":"cloud","id":1,"op":"GET","path":"v1/workers"}`, ``)
		if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != c.want {
			t.Errorf("%v: %+v, want %s", c.err, r, c.want)
		}
	}
	s := start(t, nil)
	s.send(`{"kind":"cloud","id":1,"op":"GET","path":"v1/workers"}`, ``)
	if r, _ := s.recv(); r.Kind != protocol.KindError || r.Code != protocol.CodePolicy {
		t.Errorf("no Cloud: %+v", r)
	}
}
