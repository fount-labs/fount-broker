package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"

	"github.com/fount-labs/fount-broker/internal/frame"
	"github.com/fount-labs/fount-broker/internal/mail"
)

// The verifier and the broker speak frames (package frame) over the child's
// stdin and stdout. Every header is a msg:
//
//	broker -> verifier  {"kind":"check","sender":…,"recipient":…,"received_at":ms,
//	                     "client_ip":…,"client_ip_source":…,"helo":…}  body: the raw message
//	verifier -> broker  {"kind":"dns","id":N,"type":"TXT","name":"…"}
//	broker -> verifier  {"kind":"dns","id":N}  body: JSON array of each resolver's response, base64
//	                    {"kind":"dns","id":N,"error":"…"}
//	verifier -> broker  {"kind":"result"}  body: the Verdict as JSON
//	                    {"kind":"error","error":"…"}
type msg struct {
	Kind       string `json:"kind"`
	ID         uint64 `json:"id,omitempty"`
	Type       string `json:"type,omitempty"`
	Name       string `json:"name,omitempty"`
	Error      string `json:"error,omitempty"`
	Sender     string `json:"sender,omitempty"`
	Recipient  string `json:"recipient,omitempty"`
	ReceivedAt int64  `json:"received_at,omitempty"`
	ClientIP   string `json:"client_ip,omitempty"`
	IPSource   string `json:"client_ip_source,omitempty"`
	HELO       string `json:"helo,omitempty"`
}

func decodeMsg(h []byte) (msg, error) {
	dec := json.NewDecoder(bytes.NewReader(h))
	dec.DisallowUnknownFields()
	var m msg
	if err := dec.Decode(&m); err != nil {
		return msg{}, err
	}
	if dec.More() {
		return msg{}, errors.New("trailing data")
	}
	return m, nil
}

func writeMsg(w *frame.Writer, m msg, body []byte) error {
	h, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return w.Write(frame.Frame{Header: h, Body: body})
}

// Limits on one check.
const (
	// Timeout covers starting the process, every DNS answer and the verdict.
	Timeout = 30 * time.Second
	// MaxQueries is above what DKIM (8 signatures), DMARC (2) and SPF (10
	// lookups, each up to an A and an AAAA) can need.
	MaxQueries = 48
	maxVerdict = 1 << 20
	maxStderr  = 4 << 10
)

// Asker fetches one question from the resolvers.
type Asker interface {
	Ask(ctx context.Context, qtype, name string) ([][]byte, error)
}

// Process runs the verifier as a child process per message and answers its DNS
// questions. It implements mail.Checker.
type Process struct {
	// Command returns the verifier's command, not yet started. Its stdin and
	// stdout are the frame stream.
	Command func(ctx context.Context) *exec.Cmd
	DNS     Asker
}

// Check runs one message through a fresh verifier. A crash, a timeout, a
// question outside the policy or a malformed verdict are all failures.
func (p *Process) Check(ctx context.Context, in mail.CheckInput) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	cmd := p.Command(ctx)
	cmd.WaitDelay = time.Second
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr := &capped{max: maxStderr}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("verifier didn't start: %w", err)
	}
	verdict, runErr := p.converse(ctx, stdin, stdout, in)
	stdin.Close()
	if runErr != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	switch {
	case ctx.Err() != nil:
		return nil, fmt.Errorf("verifier timed out: %w", ctx.Err())
	case runErr != nil:
		return nil, fmt.Errorf("verifier: %w%s", runErr, stderr.suffix())
	case waitErr != nil:
		return nil, fmt.Errorf("verifier exited: %w%s", waitErr, stderr.suffix())
	}
	return verdict, nil
}

func (p *Process) converse(ctx context.Context, stdin io.Writer, stdout io.Reader, in mail.CheckInput) (json.RawMessage, error) {
	w := frame.NewWriter(stdin)
	check := msg{
		Kind: "check", Sender: in.Sender, Recipient: in.Recipient, ReceivedAt: in.ReceivedAt.UnixMilli(),
		ClientIP: in.ClientIP, IPSource: in.ClientIPSource, HELO: in.HELO,
	}
	if err := writeMsg(w, check, in.Raw); err != nil {
		return nil, err
	}
	queries := 0
	for {
		f, err := frame.Read(stdout)
		if err != nil {
			return nil, fmt.Errorf("reading its output: %w", err)
		}
		m, err := decodeMsg(f.Header)
		if err != nil {
			return nil, fmt.Errorf("bad frame: %w", err)
		}
		switch m.Kind {
		case "dns":
			queries++
			if queries > MaxQueries {
				return nil, fmt.Errorf("more than %d DNS questions", MaxQueries)
			}
			if !ValidQuery(m.Type, m.Name) || len(f.Body) != 0 {
				return nil, fmt.Errorf("DNS question %s %q isn't allowed", m.Type, m.Name)
			}
			reply := msg{Kind: "dns", ID: m.ID}
			var body []byte
			answers, err := p.DNS.Ask(ctx, m.Type, m.Name)
			if err != nil {
				reply.Error = err.Error()
			} else if body, err = json.Marshal(answers); err != nil {
				return nil, err
			}
			if err := writeMsg(w, reply, body); err != nil {
				return nil, err
			}
		case "result":
			if len(f.Body) > maxVerdict || !json.Valid(f.Body) {
				return nil, errors.New("the verdict isn't JSON")
			}
			return json.RawMessage(f.Body), nil
		case "error":
			return nil, errors.New(m.Error)
		default:
			return nil, fmt.Errorf("unexpected %q frame", m.Kind)
		}
	}
}

// capped keeps the start of what the child writes to stderr.
type capped struct {
	mu  sync.Mutex
	max int
	buf bytes.Buffer
}

func (c *capped) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := c.max - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (c *capped) suffix() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.buf.Len() == 0 {
		return ""
	}
	return ": " + string(bytes.TrimSpace(c.buf.Bytes()))
}

// Run is the verifier's main: one check over r and w, then exit.
func Run(r io.Reader, w io.Writer) error {
	out := frame.NewWriter(w)
	f, err := frame.Read(r)
	if err != nil {
		return err
	}
	m, err := decodeMsg(f.Header)
	if err != nil || m.Kind != "check" {
		return fmt.Errorf("first frame isn't a check")
	}
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()

	var (
		mu      sync.Mutex
		nextID  uint64
		waiting = map[uint64]chan msgBody{}
	)
	readErr := make(chan error, 1)
	go func() {
		for {
			f, err := frame.Read(r)
			if err != nil {
				readErr <- err
				cancel()
				return
			}
			m, err := decodeMsg(f.Header)
			if err != nil || m.Kind != "dns" {
				readErr <- fmt.Errorf("unexpected frame from the broker")
				cancel()
				return
			}
			mu.Lock()
			ch := waiting[m.ID]
			delete(waiting, m.ID)
			mu.Unlock()
			if ch != nil {
				ch <- msgBody{m, f.Body}
			}
		}
	}()
	ask := func(ctx context.Context, qtype, name string) ([][]byte, error) {
		ch := make(chan msgBody, 1)
		mu.Lock()
		nextID++
		id := nextID
		waiting[id] = ch
		err := writeMsg(out, msg{Kind: "dns", ID: id, Type: qtype, Name: name}, nil)
		mu.Unlock()
		if err != nil {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case reply := <-ch:
			if reply.m.Error != "" {
				return nil, errors.New(reply.m.Error)
			}
			var answers [][]byte
			if err := json.Unmarshal(reply.body, &answers); err != nil {
				return nil, err
			}
			return answers, nil
		}
	}
	in := Input{Raw: f.Body, Sender: m.Sender, Recipient: m.Recipient, ClientIP: m.ClientIP, ClientIPSource: m.IPSource, HELO: m.HELO}
	if m.ReceivedAt != 0 {
		in.ReceivedAt = time.UnixMilli(m.ReceivedAt)
	}
	v, err := Check(ctx, in, remoteResolver{ask: ask})
	mu.Lock()
	defer mu.Unlock()
	if err != nil {
		return writeMsg(out, msg{Kind: "error", Error: err.Error()}, nil)
	}
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeMsg(out, msg{Kind: "result"}, body)
}

type msgBody struct {
	m    msg
	body []byte
}
