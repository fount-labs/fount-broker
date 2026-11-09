package main

import (
	"github.com/fount-labs/fount-broker/internal/mail"
	"github.com/fount-labs/fount-broker/internal/mail/verify"
	"github.com/fount-labs/fount-broker/internal/policy"
)

// newMail builds the mail service: the edge transport, and the verifier this
// same binary runs as a child.
func newMail() (*mail.Service, error) {
	cmd, err := verify.SelfCommand()
	if err != nil {
		return nil, err
	}
	return mail.New(mailEdge(), &verify.Process{Command: cmd, DNS: verify.NewDoH(policy.MailDNSResolvers)}), nil
}
