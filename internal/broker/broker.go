// Package broker serves the app's requests over a frame stream.
package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"maps"
	"net/http"
	"slices"
	"sync"

	"github.com/fount-labs/fount-broker/internal/frame"
	"github.com/fount-labs/fount-broker/internal/mail"
	"github.com/fount-labs/fount-broker/internal/policy"
	"github.com/fount-labs/fount-broker/internal/protocol"
	"github.com/fount-labs/fount-broker/internal/route"
)

// chunkSize bounds each data frame, so a streamed reply reaches the app as it
// arrives rather than in one piece.
const chunkSize = 32 << 10

// Broker dispatches requests to routes. Requests run concurrently; replies to
// different requests may interleave.
type Broker struct {
	version string
	routes  map[string]route.Route
	vault   *Vault
	// ProxyURL is announced in the ready frame; see package proxy.
	ProxyURL string
	// Mail serves mail requests and holds the mail_keys credential. Nil
	// refuses both.
	Mail MailService

	out *frame.Writer

	mu       sync.Mutex
	inflight map[uint64]context.CancelFunc
	wg       sync.WaitGroup
}

// MailService is package mail's Service.
type MailService interface {
	SetKeys(body []byte) error
	Handle(ctx context.Context, op, mailbox, path string, body []byte) (any, error)
	Passthrough(ctx context.Context, op, mailbox, path string, headers map[string]string, body []byte) (*mail.Result, error)
}

func New(version string, routes map[string]route.Route, vault *Vault) *Broker {
	return &Broker{version: version, routes: routes, vault: vault, inflight: map[uint64]context.CancelFunc{}}
}

// Serve announces readiness on w, then serves frames from r until r ends. A
// malformed frame stream is fatal: the app and broker disagree on framing and
// nothing after it can be trusted. A malformed request inside a good frame
// only fails that request.
func (b *Broker) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	b.out = frame.NewWriter(w)
	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		b.wg.Wait()
	}()
	if err := b.reply(protocol.Reply{Kind: protocol.KindReady, Version: b.version, Protocol: protocol.Version, Proxy: b.ProxyURL}, nil); err != nil {
		return err
	}
	for {
		f, err := frame.Read(r)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading frame: %w", err)
		}
		req, err := protocol.DecodeRequest(f.Header)
		if err != nil {
			var id struct{ ID uint64 }
			_ = json.Unmarshal(f.Header, &id)
			b.fail(id.ID, protocol.CodeBadRequest, err)
			continue
		}
		b.dispatch(ctx, req, f.Body)
	}
}

func (b *Broker) dispatch(ctx context.Context, req protocol.Request, body []byte) {
	switch req.Kind {
	case protocol.KindCancel:
		b.mu.Lock()
		cancel := b.inflight[req.ID]
		b.mu.Unlock()
		if cancel != nil {
			cancel()
		}
	case protocol.KindCredential:
		if req.Name == policy.CredentialMailKeys {
			if b.Mail == nil {
				b.fail(req.ID, protocol.CodePolicy, errors.New("mail isn't available in this build"))
			} else if err := b.Mail.SetKeys(body); err != nil {
				b.fail(req.ID, protocol.CodeBadRequest, err)
			} else {
				b.result(req.ID, map[string]bool{"ok": true})
			}
			return
		}
		if !policy.KnownCredential(req.Name) {
			b.fail(req.ID, protocol.CodePolicy, fmt.Errorf("unknown credential %q", req.Name))
			return
		}
		b.vault.Set(policy.Credential(req.Name), string(body))
		b.result(req.ID, map[string]bool{"ok": true})
	case protocol.KindFetch, protocol.KindStatus, protocol.KindMail:
		reqCtx, ok := b.track(ctx, req.ID)
		if !ok {
			b.fail(req.ID, protocol.CodeBadRequest, fmt.Errorf("request %d is already in flight", req.ID))
			return
		}
		b.wg.Go(func() {
			defer b.untrack(req.ID)
			switch req.Kind {
			case protocol.KindFetch:
				b.fetch(reqCtx, req, body)
			case protocol.KindMail:
				b.mail(reqCtx, req, body)
			default:
				b.status(reqCtx, req)
			}
		})
	}
}

func (b *Broker) track(ctx context.Context, id uint64) (context.Context, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, dup := b.inflight[id]; dup {
		return nil, false
	}
	ctx, cancel := context.WithCancel(ctx)
	b.inflight[id] = cancel
	return ctx, true
}

func (b *Broker) untrack(id uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if cancel := b.inflight[id]; cancel != nil {
		cancel()
		delete(b.inflight, id)
	}
}

func (b *Broker) fetch(ctx context.Context, req protocol.Request, body []byte) {
	dest, ok := policy.Destinations[req.Dest]
	if !ok {
		b.fail(req.ID, protocol.CodePolicy, fmt.Errorf("unknown destination %q", req.Dest))
		return
	}
	if !slices.Contains(dest.Accept, req.Accept) {
		b.fail(req.ID, protocol.CodePolicy, fmt.Errorf("accept %q is not allowed for %s", req.Accept, req.Dest))
		return
	}
	switch {
	case dest.Range != nil:
		r, ok := dest.Range(req.Path)
		if !ok {
			b.fail(req.ID, protocol.CodePolicy, fmt.Errorf("path %q is not allowed for %s", req.Path, req.Dest))
			return
		}
		headers := maps.Clone(dest.Headers)
		if headers == nil {
			headers = map[string]string{}
		}
		headers["Range"] = r
		dest.Headers = headers
	case req.Path != "" || dest.PathPattern != nil:
		if dest.PathPattern == nil || !dest.PathPattern.MatchString(req.Path) {
			b.fail(req.ID, protocol.CodePolicy, fmt.Errorf("path %q is not allowed for %s", req.Path, req.Dest))
			return
		}
		dest.Path += req.Path
	}
	if req.Headers != nil || dest.ClientHeaders != nil {
		headers, err := clientHeaders(dest, req.Headers)
		if err != nil {
			b.fail(req.ID, protocol.CodePolicy, fmt.Errorf("%s: %w", req.Dest, err))
			return
		}
		dest.Headers = headers
	}
	if err := dest.Body.Check(body); err != nil {
		b.fail(req.ID, protocol.CodePolicy, fmt.Errorf("%s: %w", req.Dest, err))
		return
	}
	rt := b.routes[dest.Route]
	if rt == nil {
		b.fail(req.ID, protocol.CodePolicy, fmt.Errorf("route %q is not available", dest.Route))
		return
	}
	var secret string
	if dest.Credential != policy.CredentialNone {
		if secret, ok = b.vault.Get(dest.Credential); !ok {
			b.fail(req.ID, protocol.CodeCredential, fmt.Errorf("%s needs the %s credential", req.Dest, dest.Credential))
			return
		}
	}
	resp, err := rt.Do(ctx, route.Request{Dest: dest, Accept: req.Accept, Body: body, Credential: secret})
	if err != nil {
		b.failSend(ctx, req.ID, err)
		return
	}
	defer resp.Body.Close()
	// A server that ignores Range sends the whole resource; for the LaTeX
	// bundle that's 2.9 GB.
	if dest.Range != nil && resp.StatusCode != http.StatusPartialContent {
		b.fail(req.ID, protocol.CodeNetwork, fmt.Errorf("%s answered %d to a range request", req.Dest, resp.StatusCode))
		return
	}
	head := protocol.Reply{Kind: protocol.KindHead, ID: req.ID, Status: resp.StatusCode, ContentType: resp.Header.Get("Content-Type")}
	if resp.ContentLength > 0 {
		head.ContentLength = resp.ContentLength
	}
	if err := b.reply(head, nil); err != nil {
		return
	}
	digest := sha256.New()
	if err := b.stream(req.ID, resp, digest); err != nil {
		b.failSend(ctx, req.ID, err)
		return
	}
	// Only a successful response is the pinned file; an error page is passed
	// through as it is, and its status already says it failed.
	if dest.SHA256 != "" && resp.StatusCode == http.StatusOK {
		if got := hex.EncodeToString(digest.Sum(nil)); got != dest.SHA256 {
			b.fail(req.ID, protocol.CodeIntegrity, fmt.Errorf("%s has digest %s, want %s", req.Dest, got, dest.SHA256))
			return
		}
	}
	_ = b.reply(protocol.Reply{Kind: protocol.KindEnd, ID: req.ID}, nil)
}

// clientHeaders checks the app's headers against dest.ClientHeaders, which it
// must send all of and nothing else, and returns dest's headers with them
// added. The destination's own headers win.
func clientHeaders(dest policy.Destination, sent map[string]string) (map[string]string, error) {
	if len(dest.ClientHeaders) == 0 {
		return nil, errors.New("this destination takes no headers")
	}
	for name := range sent {
		if dest.ClientHeaders[name] == nil {
			return nil, fmt.Errorf("header %q is not allowed", name)
		}
	}
	headers := make(map[string]string, len(dest.ClientHeaders)+len(dest.Headers))
	for name, pattern := range dest.ClientHeaders {
		v, ok := sent[name]
		if !ok {
			return nil, fmt.Errorf("header %q is required", name)
		}
		if !pattern.MatchString(v) {
			return nil, fmt.Errorf("header %q doesn't match %s", name, pattern)
		}
		headers[name] = v
	}
	maps.Copy(headers, dest.Headers)
	return headers, nil
}

func (b *Broker) stream(id uint64, resp *http.Response, digest hash.Hash) error {
	buf := make([]byte, chunkSize)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			digest.Write(buf[:n])
			if werr := b.reply(protocol.Reply{Kind: protocol.KindData, ID: id}, buf[:n]); werr != nil {
				return werr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (b *Broker) status(ctx context.Context, req protocol.Request) {
	rt := b.routes[req.Route]
	if rt == nil || !slices.Contains(policy.Routes, req.Route) {
		b.fail(req.ID, protocol.CodePolicy, fmt.Errorf("unknown route %q", req.Route))
		return
	}
	s, err := rt.Status(ctx)
	if err != nil {
		b.failSend(ctx, req.ID, err)
		return
	}
	b.result(req.ID, s)
}

func (b *Broker) mail(ctx context.Context, req protocol.Request, body []byte) {
	if b.Mail == nil {
		b.fail(req.ID, protocol.CodePolicy, errors.New("mail isn't available in this build"))
		return
	}
	var v any
	var err error
	switch {
	case req.Op == mail.OpLicenseEntitlement:
		b.licenseEntitlement(ctx, req, body)
		return
	case mail.IsPassthrough(req.Op):
		v, err = b.Mail.Passthrough(ctx, req.Op, req.Mailbox, req.Path, req.Headers, body)
	case req.Headers != nil:
		err = fmt.Errorf("%w: only pre-signed ops take headers", mail.ErrRequest)
	default:
		v, err = b.Mail.Handle(ctx, req.Op, req.Mailbox, req.Path, body)
	}
	if err != nil {
		b.fail(req.ID, mailCode(ctx, err), err)
		return
	}
	b.result(req.ID, v)
}

// licenseEntitlement asks Fount's API for an entitlement bound to the app's
// device key, with the license credential the broker holds as Bearer. Any
// status comes back as a mail.Result, so the app can tell a refused credential
// from a broken network.
func (b *Broker) licenseEntitlement(ctx context.Context, req protocol.Request, body []byte) {
	if req.Mailbox != "" || req.Path != "" || req.Headers != nil {
		b.fail(req.ID, protocol.CodeBadRequest, errors.New("license_entitlement takes no mailbox, path or headers"))
		return
	}
	deviceKey, err := mail.LicenseEntitlementRequest(body)
	if err != nil {
		b.fail(req.ID, protocol.CodeBadRequest, err)
		return
	}
	dest := policy.LicenseEntitlement
	secret, ok := b.vault.Get(dest.Credential)
	if !ok {
		b.fail(req.ID, protocol.CodeCredential, fmt.Errorf("license_entitlement needs the %s credential", dest.Credential))
		return
	}
	out, err := json.Marshal(map[string]string{"deviceKey": deviceKey})
	if err != nil {
		b.fail(req.ID, protocol.CodeBadRequest, err)
		return
	}
	if err := dest.Body.Check(out); err != nil {
		b.fail(req.ID, protocol.CodePolicy, fmt.Errorf("license_entitlement: %w", err))
		return
	}
	rt := b.routes[dest.Route]
	if rt == nil {
		b.fail(req.ID, protocol.CodePolicy, fmt.Errorf("route %q is not available", dest.Route))
		return
	}
	resp, err := rt.Do(ctx, route.Request{Dest: dest, Accept: "application/json", Body: out, Credential: secret})
	if err != nil {
		b.failSend(ctx, req.ID, err)
		return
	}
	res, err := mail.ReadResult(resp)
	if err != nil {
		b.failSend(ctx, req.ID, err)
		return
	}
	b.result(req.ID, res)
}

func mailCode(ctx context.Context, err error) protocol.Code {
	for _, c := range []struct {
		err  error
		code protocol.Code
	}{
		{mail.ErrRequest, protocol.CodeBadRequest},
		{mail.ErrNoKeys, protocol.CodeCredential},
		{mail.ErrNotFound, protocol.CodeNotFound},
		{route.ErrAttestation, protocol.CodeAttestation},
		{mail.ErrSignature, protocol.CodeIntegrity},
		{mail.ErrWrongKey, protocol.CodeIntegrity},
		{mail.ErrWrongMailbox, protocol.CodeIntegrity},
		{mail.ErrDecrypt, protocol.CodeIntegrity},
		{mail.ErrMalformed, protocol.CodeIntegrity},
		{mail.ErrRecord, protocol.CodeIntegrity},
		{mail.ErrBootConflict, protocol.CodeIntegrity},
	} {
		if errors.Is(err, c.err) {
			return c.code
		}
	}
	if ctx.Err() != nil {
		return protocol.CodeCancelled
	}
	return protocol.CodeNetwork
}

func (b *Broker) result(id uint64, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		b.fail(id, protocol.CodeBadRequest, err)
		return
	}
	_ = b.reply(protocol.Reply{Kind: protocol.KindResult, ID: id}, body)
}

func (b *Broker) failSend(ctx context.Context, id uint64, err error) {
	switch {
	case ctx.Err() != nil:
		b.fail(id, protocol.CodeCancelled, ctx.Err())
	case errors.Is(err, route.ErrAttestation):
		b.fail(id, protocol.CodeAttestation, err)
	default:
		b.fail(id, protocol.CodeNetwork, err)
	}
}

func (b *Broker) fail(id uint64, code protocol.Code, err error) {
	_ = b.reply(protocol.Reply{Kind: protocol.KindError, ID: id, Code: code, Message: err.Error()}, nil)
}

func (b *Broker) reply(r protocol.Reply, body []byte) error {
	header, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return b.out.Write(frame.Frame{Header: header, Body: body})
}
