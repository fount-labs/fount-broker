//go:build dev

// Command mail-peek lists one address's mail at the live edge through a -tags dev
// fount-broker: only the read ops list and gaps. It never prints key material.
//
//	go build -tags dev -o /tmp/fb-dev ./cmd/fount-broker
//	go run -tags dev ./cmd/mail-peek -broker /tmp/fb-dev -keys address_X.json
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/fount-labs/fount-broker/internal/frame"
	"github.com/fount-labs/fount-broker/internal/protocol"
)

type storedAddress struct {
	Address       string `json:"address"`
	MailboxID     string `json:"mailbox_id"`
	DecryptionKey []byte `json:"decryption_key"`
	SigningKey    []byte `json:"signing_key"`
}

func main() {
	brokerBin := flag.String("broker", "", "a -tags dev fount-broker binary")
	keysFile := flag.String("keys", "", "the address's keystore file")
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
	fmt.Printf("address %s mailbox %s\n", addr.Address, addr.MailboxID)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, *brokerBin)
	cmd.Env = []string{"HOME=" + os.Getenv("HOME"), "PATH=" + os.Getenv("PATH")}
	cmd.Stderr = os.Stderr
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	w, r := frame.NewWriter(stdin), bufio.NewReader(stdout)
	if _, err := frame.Read(r); err != nil {
		log.Fatal(err)
	}
	var id uint64
	send := func(name string, req protocol.Request, body []byte) {
		id++
		req.ID = id
		h, _ := json.Marshal(req)
		if err := w.Write(frame.Frame{Header: h, Body: body}); err != nil {
			log.Fatal(err)
		}
		for {
			f, err := frame.Read(r)
			if err != nil {
				log.Fatalf("reading reply: %v", err)
			}
			var rep protocol.Reply
			_ = json.Unmarshal(f.Header, &rep)
			if rep.ID != id {
				continue
			}
			if rep.Kind == protocol.KindError {
				fmt.Printf("%-10s error code=%s message=%q\n", name, rep.Code, rep.Message)
			} else if name != "mail_keys" {
				fmt.Printf("%-10s %s\n", name, bytes.TrimSpace(f.Body))
			}
			return
		}
	}
	keys, _ := json.Marshal(map[string]any{"addresses": []map[string]any{{
		"mailbox_id": addr.MailboxID, "signing_key": addr.SigningKey, "decryption_key": addr.DecryptionKey,
	}}})
	send("mail_keys", protocol.Request{Kind: protocol.KindCredential, Name: "mail_keys"}, keys)
	send("list", protocol.Request{Kind: protocol.KindMail, Op: "list", Mailbox: addr.MailboxID}, nil)
	send("gaps", protocol.Request{Kind: protocol.KindMail, Op: "gaps", Mailbox: addr.MailboxID}, nil)
	_ = stdin.Close()
	_ = cmd.Wait()
}
