//go:build !dev

package main

import (
	"github.com/fount-labs/fount-broker/internal/mail"
	"github.com/fount-labs/fount-broker/internal/route"
)

func mailEdge() mail.Edge { return route.NewMailEdge() }
