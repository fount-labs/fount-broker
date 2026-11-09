//go:build dev

// Command mail-e2e drives a -tags dev fount-broker's mail route against the live
// attested edge with a real dev mailbox. It reads the mailbox's key file (fount
// src-tauri/src/mail/keystore.rs FileStore format) and a license file, hands
// both to the broker as credentials, and runs only read-only or idempotent ops.
// It never prints key material, the license or the entitlement token.
//
//	go build -tags dev -o /tmp/fb ./cmd/fount-broker
//	go run -tags dev ./cmd/mail-e2e -broker /tmp/fb -keys ADDRESS.json -license LICENSE \
//	    -api https://…/prod -owner you@example.com -boots ID,ID
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/fount-labs/fount-broker/internal/frame"
	"github.com/fount-labs/fount-broker/internal/mail"
	"github.com/fount-labs/fount-broker/internal/protocol"
	"github.com/fount-labs/fount-broker/internal/route"
)

// storedAddress is fount's keystore StoredAddress. Byte fields are std base64.
type storedAddress struct {
	Address        string `json:"address"`
	MailboxID      string `json:"mailbox_id"`
	DecryptionKey  []byte `json:"decryption_key"`
	SigningKey     []byte `json:"signing_key"`
	OwnerChangeKey []byte `json:"owner_change_key"`
	PasskeyPublic  []byte `json:"passkey_public"`
}

type session struct {
	w      *frame.Writer
	r      *bufio.Reader
	nextID uint64
}

func (s *session) send(req protocol.Request, body []byte) (protocol.Reply, []byte) {
	s.nextID++
	req.ID = s.nextID
	h, err := json.Marshal(req)
	if err != nil {
		log.Fatal(err)
	}
	if err := s.w.Write(frame.Frame{Header: h, Body: body}); err != nil {
		log.Fatal(err)
	}
	for {
		f, err := frame.Read(s.r)
		if err != nil {
			log.Fatalf("reading reply: %v", err)
		}
		var rep protocol.Reply
		if err := json.Unmarshal(f.Header, &rep); err != nil {
			log.Fatal(err)
		}
		if rep.ID == req.ID {
			return rep, f.Body
		}
	}
}

func signed(key ed25519.PrivateKey, keyID, method, path string, body []byte, ent string) map[string]string {
	ts := time.Now().Unix()
	nonce := hex.EncodeToString(randBytes(16))
	sig := ed25519.Sign(key, []byte(mail.Canonical(method, path, body, ts, nonce)))
	h := map[string]string{
		mail.HeaderTimestamp: strconv.FormatInt(ts, 10),
		mail.HeaderNonce:     nonce,
		mail.HeaderSignature: base64.StdEncoding.EncodeToString(sig),
	}
	if keyID != "" {
		h[mail.HeaderKeyID] = keyID
	}
	if ent != "" {
		h[mail.HeaderEntitlement] = ent
	}
	return h
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	return b
}

func show(name string, rep protocol.Reply, body []byte) {
	if rep.Kind == protocol.KindError {
		fmt.Printf("%-22s error code=%s message=%q\n", name, rep.Code, rep.Message)
		return
	}
	fmt.Printf("%-22s %s %s\n", name, rep.Kind, bytes.TrimSpace(body))
}

func main() {
	brokerBin := flag.String("broker", "", "a -tags dev fount-broker binary")
	keysFile := flag.String("keys", "", "the address's keystore file")
	licenseFile := flag.String("license", "", "a file holding the dev license key")
	api := flag.String("api", "", "the dev Fount API base, for license_entitlement")
	owner := flag.String("owner", "", "the mailbox's one routing owner, re-sent at version 1")
	bootIDs := flag.String("boots", "", "comma-separated boot ids to look up on the edge directly")
	flag.Parse()
	log.SetFlags(0)

	raw, err := os.ReadFile(*keysFile)
	if err != nil {
		log.Fatal(err)
	}
	var addr storedAddress
	if err := json.Unmarshal(raw, &addr); err != nil {
		log.Fatalf("keys file: %v", err)
	}
	if len(addr.SigningKey) != ed25519.SeedSize || len(addr.OwnerChangeKey) != ed25519.SeedSize || len(addr.DecryptionKey) != 32 {
		log.Fatal("keys file: unexpected key lengths")
	}
	signing := ed25519.NewKeyFromSeed(addr.SigningKey)
	ownerChange := ed25519.NewKeyFromSeed(addr.OwnerChangeKey)
	mbox := addr.MailboxID
	fmt.Printf("address %s mailbox %s\n", addr.Address, mbox)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// The edge directly, through the broker's attested transport.
	edge := route.NewMailEdge()
	start := time.Now()
	attested, err := edge.AttestedSigningKey(ctx)
	if err != nil {
		fmt.Printf("%-22s FAIL %v\n", "attest", err)
	} else {
		fmt.Printf("%-22s ok in %s, mail-sign %s\n", "attest", time.Since(start).Round(time.Millisecond), hex.EncodeToString(attested))
	}
	direct := func(name, method, path string) {
		req, _ := http.NewRequestWithContext(ctx, method, edge.Base()+path[1:], http.NoBody)
		resp, err := edge.Do(ctx, req)
		if err != nil {
			fmt.Printf("%-22s FAIL %v\n", name, err)
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		out := strings.TrimSpace(string(b))
		var bt struct {
			BootID     string `json:"boot_id"`
			SigningKey []byte `json:"signing_key"`
			StartedAt  int64  `json:"started_at"`
		}
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if resp.StatusCode == 200 && dec.Decode(&bt) == nil && len(bt.SigningKey) == ed25519.PublicKeySize {
			out = fmt.Sprintf("boot %s key %s started %s attested=%v", bt.BootID, hex.EncodeToString(bt.SigningKey),
				time.Unix(bt.StartedAt, 0).UTC().Format(time.RFC3339), attested != nil && attested.Equal(ed25519.PublicKey(bt.SigningKey)))
		}
		fmt.Printf("%-22s %d %s\n", name, resp.StatusCode, out)
	}
	direct("health", "GET", "/health")
	direct("unsigned GET /mail", "GET", "/mail")
	direct("boot (nonexistent)", "GET", "/boots/"+hex.EncodeToString(randBytes(16)))
	for _, id := range strings.Split(*bootIDs, ",") {
		if id != "" {
			direct("boot "+id[:8], "GET", "/boots/"+id)
		}
	}

	// The broker, as the app drives it.
	cmd := exec.CommandContext(ctx, *brokerBin)
	cmd.Env = []string{"FOUNT_BROKER_FOUNT_API=" + *api, "HOME=" + os.Getenv("HOME"), "PATH=" + os.Getenv("PATH")}
	cmd.Stderr = os.Stderr
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	s := &session{w: frame.NewWriter(stdin), r: bufio.NewReader(stdout)}
	f, err := frame.Read(s.r)
	if err != nil {
		log.Fatal(err)
	}
	var ready protocol.Reply
	_ = json.Unmarshal(f.Header, &ready)
	fmt.Printf("%-22s version=%s protocol=%d\n", "broker ready", ready.Version, ready.Protocol)

	license, err := os.ReadFile(*licenseFile)
	if err != nil {
		log.Fatal(err)
	}
	rep, body := s.send(protocol.Request{Kind: protocol.KindCredential, Name: "license"}, bytes.TrimSpace(license))
	show("credential license", rep, body)
	keysBody, _ := json.Marshal(map[string]any{"addresses": []map[string]any{{
		"mailbox_id": mbox, "signing_key": addr.SigningKey, "decryption_key": addr.DecryptionKey,
	}}})
	rep, body = s.send(protocol.Request{Kind: protocol.KindCredential, Name: "mail_keys"}, keysBody)
	show("credential mail_keys", rep, body)

	m := func(op, path string) (protocol.Reply, []byte) {
		return s.send(protocol.Request{Kind: protocol.KindMail, Op: op, Mailbox: mbox, Path: path}, nil)
	}
	rep, body = m("list", "")
	show("list", rep, body)
	rep, body = m("gaps", "")
	show("gaps", rep, body)
	rep, ledger := m("ledger", "")
	show("ledger", rep, ledger)
	rep, body = s.send(protocol.Request{Kind: protocol.KindMail, Op: "restore", Mailbox: mbox}, ledger)
	show("restore", rep, body)
	rep, body = m("ledger", "")
	show("ledger after restore", rep, body)
	fmt.Printf("%-22s %v\n", "ledger round trip", bytes.Equal(bytes.TrimSpace(ledger), bytes.TrimSpace(body)))
	rep, body = m("get", hex.EncodeToString(randBytes(16)))
	show("get (nonexistent)", rep, body)
	other := hex.EncodeToString(randBytes(32))
	rep, body = s.send(protocol.Request{Kind: protocol.KindMail, Op: "list", Mailbox: other}, nil)
	show("list (no keys)", rep, body)

	// Entitlement through the broker, which adds the license.
	devKey, _ := json.Marshal(map[string]string{"deviceKey": base64.StdEncoding.EncodeToString(signing.Public().(ed25519.PublicKey))})
	rep, body = s.send(protocol.Request{Kind: protocol.KindMail, Op: "license_entitlement"}, devKey)
	var lr struct {
		Status int `json:"status"`
		Body   struct {
			Entitlement string `json:"entitlement"`
		} `json:"body"`
	}
	var ent string
	if rep.Kind == protocol.KindResult && json.Unmarshal(body, &lr) == nil && lr.Body.Entitlement != "" {
		ent = lr.Body.Entitlement
		claims := "?"
		if p, _, ok := strings.Cut(ent, "."); ok {
			if j, err := base64.RawURLEncoding.DecodeString(p); err == nil {
				var c struct {
					V   int   `json:"v"`
					Iat int64 `json:"iat"`
					Exp int64 `json:"exp"`
				}
				if json.Unmarshal(j, &c) == nil {
					claims = fmt.Sprintf("v=%d iat=%s exp=%s", c.V, time.Unix(c.Iat, 0).UTC().Format(time.RFC3339), time.Unix(c.Exp, 0).UTC().Format(time.RFC3339))
				}
			}
		}
		fmt.Printf("%-22s result status=%d entitlement %s (token not shown)\n", "license_entitlement", lr.Status, claims)
	} else if rep.Kind == protocol.KindError {
		show("license_entitlement", rep, body)
	} else {
		fmt.Printf("%-22s result status=%d (no entitlement)\n", "license_entitlement", lr.Status)
	}

	handle := strings.TrimSuffix(addr.Address, "@fountbox.com")
	if ent != "" {
		rep, body = s.send(protocol.Request{Kind: protocol.KindMail, Op: "handle", Path: handle,
			Headers: signed(signing, "", "GET", "/handle/"+handle, nil, ent)}, nil)
		show("handle "+handle, rep, body)
		free := "zz-unused-" + hex.EncodeToString(randBytes(4))
		rep, body = s.send(protocol.Request{Kind: protocol.KindMail, Op: "handle", Path: free,
			Headers: signed(signing, "", "GET", "/handle/"+free, nil, ent)}, nil)
		show("handle (unused)", rep, body)
	}

	routing, _ := json.Marshal(map[string]any{"version": 1, "owners": []string{*owner}})
	rep, body = s.send(protocol.Request{Kind: protocol.KindMail, Op: "routing", Mailbox: mbox,
		Headers: signed(ownerChange, mbox, "PUT", "/routing", routing, "")}, routing)
	show("routing v1 resend", rep, body)

	if ent != "" {
		renew := []byte("{}")
		rep, body = s.send(protocol.Request{Kind: protocol.KindMail, Op: "renew", Mailbox: mbox,
			Headers: signed(signing, mbox, "POST", "/entitlement", renew, ent)}, renew)
		show("renew", rep, body)
		hd := signed(signing, mbox, "POST", "/entitlement", renew, ent)
		rep, body = s.send(protocol.Request{Kind: protocol.KindMail, Op: "renew", Mailbox: mbox, Headers: hd}, renew)
		show("renew again", rep, body)
		rep, body = s.send(protocol.Request{Kind: protocol.KindMail, Op: "renew", Mailbox: mbox, Headers: hd}, renew)
		show("renew (replayed nonce)", rep, body)
	}

	stdin.Close()
	_ = cmd.Wait()
}
