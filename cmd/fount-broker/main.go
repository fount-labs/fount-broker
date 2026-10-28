// Command fount-broker is Fount's only route to the network. The app starts it
// as a child process and speaks frames over its stdin and stdout; see package
// protocol. It exits when stdin closes, so it never outlives the app.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/fount-labs/fount-broker/internal/broker"
	"github.com/fount-labs/fount-broker/internal/policy"
	"github.com/fount-labs/fount-broker/internal/route"
)

// version is set at release build time with -ldflags "-X main.version=…".
var version = "dev"

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetPrefix("fount-broker: ")
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println(version)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	vault := broker.NewVault()
	tinfoil := route.NewTinfoil(policy.TinfoilProxyBase(), func() string {
		s, _ := vault.Get(policy.CredentialTinfoilCacheSecret)
		return s
	})
	vault.OnChange(policy.CredentialTinfoilCacheSecret, tinfoil.Reset)

	b := broker.New(version, map[string]route.Route{policy.RouteTinfoil: tinfoil}, vault)
	if err := b.Serve(ctx, os.Stdin, os.Stdout); err != nil {
		log.Fatal(err)
	}
}
