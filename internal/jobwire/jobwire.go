// Package jobwire carries one Cloud job from the coordinator, through the
// runner enclave's broker, to the supervisor, and its results back
// (m4-cloud-runners.md §5.1c). A job is one connection of package frame's
// frames.
//
// Coordinator to supervisor:
//
//	{"kind":"job","mode":"…","account":"…","credentials":{"license":"…"}}  body: fount-runner's job file, unread
//	{"kind":"workspace"}  body: the next piece of the workspace as a filetree stream; an empty body ends it
//	{"kind":"index"}      the kept index, the same way
//
// An intake job ("mode":"intake") has no job file, no credentials and no
// index: its first frame's body is empty, and its workspace is the email's
// intake folder (message.eml, check.json, request.json, instructions.md).
//
// Supervisor to coordinator:
//
//	{"kind":"stdout"}, {"kind":"stderr"}  body: the runner's output as it comes
//	{"kind":"exit","exitCode":0,"seconds":1.5,"peakBytes":N,"oomKills":0}
//	{"kind":"workspace"} …  an agent job's workspace once its sandbox is gone,
//	                        or an intake job's out/ folder
//	{"kind":"index"} …      or, from the index step, the index it built
//	{"kind":"end"}
//	{"kind":"error","message":"…"}  in place of anything still to come
//
// The broker reads only the first frame. It keeps the credentials for the
// job's own broker socket, adds the job's "id", and relays the rest unread. The
// coordinator cancels a job by closing the connection.
//
// On a link a team's runner dialled in (launch plan work R2), the coordinator
// first sends, before any job:
//
//	{"kind":"bind","account":"tm_…"}  no body
//
// The runner serves that account alone for the rest of its boot: a later bind
// to another account, or a job for another, is refused. It tells the
// supervisor with "bound":true on each job, and the supervisor locks the
// same way. A pool runner gets no bind frame and serves any account.
package jobwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"

	"github.com/fount-labs/fount-broker/internal/frame"
	"github.com/fount-labs/fount-broker/internal/policy"
)

type Kind string

const (
	KindJob       Kind = "job"
	KindWorkspace Kind = "workspace"
	KindIndex     Kind = "index"
	KindStdout    Kind = "stdout"
	KindStderr    Kind = "stderr"
	KindExit      Kind = "exit"
	KindEnd       Kind = "end"
	KindError     Kind = "error"
	KindBind      Kind = "bind"
)

// Mode is what a job's sandbox does (m4-cloud-runners.md §5.5).
type Mode string

const (
	// ModeAgent runs the agent. It gets the kept index read-only, and only its
	// workspace comes back.
	ModeAgent Mode = ""
	// ModeIndex brings the kept index up to date with the workspace and runs
	// nothing else. Only the index comes back.
	ModeIndex Mode = "index"
	// ModeIntake parses one received email: fount-runner --mode intake, with
	// no keys, no network and no index. Only its out/ folder comes back, as a
	// workspace stream.
	ModeIntake Mode = "intake"
)

// Sends is the trees the coordinator streams in after the first frame, in
// order.
func (m Mode) Sends() []Kind {
	if m == ModeIntake {
		return []Kind{KindWorkspace}
	}
	return []Kind{KindWorkspace, KindIndex}
}

// Returns is the one tree a job of this mode sends back.
func (m Mode) Returns() Kind {
	if m == ModeIndex {
		return KindIndex
	}
	return KindWorkspace
}

// Job is the first frame's header.
type Job struct {
	Kind Kind `json:"kind"`
	Mode Mode `json:"mode,omitempty"`
	// ID names the job's sandbox and socket. The broker picks it; the
	// coordinator never sends one.
	ID      string `json:"id,omitempty"`
	Account string `json:"account"`
	// Credentials are the job's tokens, by the broker's credential names. The
	// broker keeps them and never relays them, so a sandbox never holds them.
	Credentials map[string]string `json:"credentials,omitempty"`
	// Bound is the broker telling the supervisor its runner serves Account
	// alone this boot. Only the broker sends it.
	Bound bool `json:"bound,omitempty"`
}

// Bind is the frame that binds a runner to one account for its boot.
type Bind struct {
	Kind    Kind   `json:"kind"`
	Account string `json:"account"`
}

// FrameKind is a header's kind, read loosely: which decoder to use.
func FrameKind(header []byte) Kind {
	var k struct {
		Kind Kind `json:"kind"`
	}
	json.Unmarshal(header, &k)
	return k.Kind
}

// DecodeBind reads a bind frame strictly.
func DecodeBind(f frame.Frame) (string, error) {
	var b Bind
	dec := json.NewDecoder(bytes.NewReader(f.Header))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return "", fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if dec.More() || b.Kind != KindBind || len(f.Body) != 0 {
		return "", fmt.Errorf("%w: not a bind frame", ErrMalformed)
	}
	if !accountPattern.MatchString(b.Account) {
		return "", fmt.Errorf("%w: account %q", ErrMalformed, b.Account)
	}
	return b.Account, nil
}

// MaxJobFile bounds the first frame's body, fount-runner's job file.
const MaxJobFile = 1 << 20

var (
	idPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	accountPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

var ErrMalformed = errors.New("malformed job")

// Hop is who sent a Job.
type Hop int

const (
	// FromCoordinator: no ID, and credentials the broker knows.
	FromCoordinator Hop = iota
	// FromBroker: an ID, and no credentials at all.
	FromBroker
)

// DecodeJob reads the first frame strictly: unknown fields, trailing data, a
// field the hop mustn't send and any value out of its pattern are refused.
func DecodeJob(f frame.Frame, hop Hop) (Job, error) {
	var j Job
	dec := json.NewDecoder(bytes.NewReader(f.Header))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&j); err != nil {
		return Job{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if dec.More() {
		return Job{}, fmt.Errorf("%w: trailing data", ErrMalformed)
	}
	if j.Kind != KindJob {
		return Job{}, fmt.Errorf("%w: first frame is %q, not a job", ErrMalformed, j.Kind)
	}
	if j.Mode != ModeAgent && j.Mode != ModeIndex && j.Mode != ModeIntake {
		return Job{}, fmt.Errorf("%w: mode %q", ErrMalformed, j.Mode)
	}
	if !accountPattern.MatchString(j.Account) {
		return Job{}, fmt.Errorf("%w: account %q", ErrMalformed, j.Account)
	}
	if j.Mode == ModeIntake {
		// Intake reads a stranger's email: it holds nothing to steal.
		if len(f.Body) != 0 {
			return Job{}, fmt.Errorf("%w: intake takes no job file", ErrMalformed)
		}
		if j.Credentials != nil {
			return Job{}, fmt.Errorf("%w: intake takes no credentials", ErrMalformed)
		}
	} else if len(f.Body) == 0 || len(f.Body) > MaxJobFile {
		return Job{}, fmt.Errorf("%w: job file must be 1 to %d bytes", ErrMalformed, MaxJobFile)
	}
	switch hop {
	case FromCoordinator:
		if j.ID != "" {
			return Job{}, fmt.Errorf("%w: the coordinator doesn't name the sandbox", ErrMalformed)
		}
		if j.Bound {
			return Job{}, fmt.Errorf("%w: the coordinator binds a runner with a bind frame", ErrMalformed)
		}
		for name := range j.Credentials {
			if !policy.KnownCredential(name) {
				return Job{}, fmt.Errorf("%w: unknown credential %q", ErrMalformed, name)
			}
		}
	case FromBroker:
		if !idPattern.MatchString(j.ID) {
			return Job{}, fmt.Errorf("%w: id %q", ErrMalformed, j.ID)
		}
		if j.Credentials != nil {
			return Job{}, fmt.Errorf("%w: credentials never reach the supervisor", ErrMalformed)
		}
	}
	return j, nil
}

// Reply is every header the supervisor sends.
type Reply struct {
	Kind      Kind    `json:"kind"`
	ExitCode  int     `json:"exitCode,omitempty"`
	Seconds   float64 `json:"seconds,omitempty"`
	PeakBytes int64   `json:"peakBytes,omitempty"`
	OOMKills  int64   `json:"oomKills,omitempty"`
	Message   string  `json:"message,omitempty"`
}

// Send writes one frame.
func Send(w *frame.Writer, header any, body []byte) error {
	h, err := json.Marshal(header)
	if err != nil {
		return err
	}
	return w.Write(frame.Frame{Header: h, Body: body})
}

const chunk = 1 << 20

// Chunks is an io.Writer that sends each write as frames of kind. Close ends
// a stream that the other side reads with Stream.
type Chunks struct {
	W    *frame.Writer
	Kind Kind
}

func (c Chunks) Write(p []byte) (int, error) {
	for off := 0; off < len(p); off += chunk {
		if err := Send(c.W, Reply{Kind: c.Kind}, p[off:min(off+chunk, len(p))]); err != nil {
			return off, err
		}
	}
	return len(p), nil
}

func (c Chunks) Close() error { return Send(c.W, Reply{Kind: c.Kind}, nil) }

// Stream reads the bodies of consecutive frames of kind as one stream, until
// an empty one. Any other frame fails it; an error frame fails it with the
// sender's message.
type Stream struct {
	R    io.Reader
	Kind Kind

	buf  []byte
	done bool
}

func (s *Stream) Read(p []byte) (int, error) {
	for len(s.buf) == 0 {
		if s.done {
			return 0, io.EOF
		}
		f, err := frame.Read(s.R)
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
		r, err := DecodeReply(f.Header)
		if err != nil {
			return 0, err
		}
		if err := r.Err(); err != nil {
			return 0, err
		}
		if r.Kind != s.Kind {
			return 0, fmt.Errorf("%w: %q frame inside the %s stream", ErrMalformed, r.Kind, s.Kind)
		}
		s.buf, s.done = f.Body, len(f.Body) == 0
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

// Drain reads the stream to its end, so the frames after it can be read.
func (s *Stream) Drain() error {
	_, err := io.Copy(io.Discard, s)
	return err
}

// Remote is the error the other end reported.
type Remote struct{ Message string }

func (e *Remote) Error() string { return e.Message }

// Err is the error an error frame carries, or nil.
func (r Reply) Err() error {
	if r.Kind == KindError {
		return &Remote{Message: r.Message}
	}
	return nil
}

var replyKinds = []Kind{KindWorkspace, KindIndex, KindStdout, KindStderr, KindExit, KindEnd, KindError}

// DecodeReply reads any header after the first, strictly.
func DecodeReply(header []byte) (Reply, error) {
	var r Reply
	dec := json.NewDecoder(bytes.NewReader(header))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Reply{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if dec.More() || !slices.Contains(replyKinds, r.Kind) {
		return Reply{}, fmt.Errorf("%w: frame %q", ErrMalformed, r.Kind)
	}
	return r, nil
}
