// Command fount-broker is Fount's only route to the network. The app starts it
// as a child process and speaks frames over its stdin and stdout; see package
// protocol. It exits when stdin closes, so it never outlives the app. It also
// runs a loopback tunnel for Python's package manager; see package proxy.
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
	"github.com/fount-labs/fount-broker/internal/proxy"
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

	routes := map[string]route.Route{
		policy.RouteTinfoil: tinfoil,
		policy.RouteTinfoilWebSearch: route.NewTinfoilEnclave(
			policy.TinfoilWebSearchHost, policy.TinfoilWebSearchRepo, policy.FountProxyBase()),
		policy.RouteFountAPI:    route.NewHTTPS(policy.FountAPIBase(), nil),
		policy.RouteFountProxy:  route.NewHTTPS(policy.FountProxyBase(), nil),
		policy.RouteModels:      route.NewHTTPS(policy.ModelsBase, func() any { return policy.ModelFiles }),
		policy.RouteOpenRouter:  route.NewHTTPS(policy.OpenRouterBase, nil),
		policy.RouteHuggingFace: route.NewHTTPS(policy.HuggingFaceBase, func() any { return policy.VisionModels }, policy.HuggingFaceRedirectHosts...),
		policy.RouteUpdates:     route.NewHTTPS(policy.UpdatesBase, nil, policy.UpdatesRedirectHosts...),
		policy.RouteLatex:       route.NewHTTPS(policy.LatexBase, nil),
	}
	b := broker.New(version, routes, vault)
	// Chat and the rest work without the tunnel, so failing to open it only
	// leaves uv without a way out.
	if tunnel, err := proxy.Listen(policy.PythonPackageHosts); err != nil {
		log.Printf("package tunnel unavailable: %v", err)
	} else {
		go func() {
			if err := tunnel.Serve(ctx); err != nil {
				log.Printf("package tunnel stopped: %v", err)
			}
		}()
		b.ProxyURL = tunnel.URL()
	}
	if err := b.Serve(ctx, os.Stdin, os.Stdout); err != nil {
		log.Fatal(err)
	}
}
