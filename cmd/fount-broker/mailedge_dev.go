//go:build dev

package main

import (
	"github.com/fount-labs/fount-broker/internal/mail"
	"github.com/fount-labs/fount-broker/internal/policy"
	"github.com/fount-labs/fount-broker/internal/route"
)

func mailEdge() mail.Edge {
	if base := policy.MailEdgeDev(); base != "" {
		return route.NewDevMailEdge(base)
	}
	return route.NewMailEdge()
}
