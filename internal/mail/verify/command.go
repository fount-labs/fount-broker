package verify

import (
	"context"
	"os"
	"os/exec"
)

// Subcommand is the argument that makes the broker binary run as the verifier.
const Subcommand = "mail-verify"

// SelfCommand returns a Command that starts this binary as the verifier, with
// an empty environment, under the platform's confinement (see confine_*.go).
func SelfCommand() (func(ctx context.Context) *exec.Cmd, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) *exec.Cmd {
		name, args := confine(exe, Subcommand)
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env = []string{}
		cmd.Dir = "/"
		return cmd
	}, nil
}
