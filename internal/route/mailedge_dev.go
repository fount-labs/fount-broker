//go:build dev

package route

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"net/http"
	"time"
)

// DevMailEdge reaches a dev edge at base without attestation or certificate
// checks. Only a -tags dev build can name one (policy.MailEdgeDev).
type DevMailEdge struct {
	base   string
	client *http.Client
}

func NewDevMailEdge(base string) *DevMailEdge {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return &DevMailEdge{base: base, client: &http.Client{Transport: t, Timeout: 2 * time.Minute}}
}

func (d *DevMailEdge) Base() string { return d.base }
func (d *DevMailEdge) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	return d.client.Do(req.WithContext(ctx))
}
func (d *DevMailEdge) AttestedSigningKey(context.Context) (ed25519.PublicKey, error) { return nil, nil }
