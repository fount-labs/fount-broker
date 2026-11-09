//go:build !darwin

package verify

// Confined is false here: the verifier is a separate process with no keys and
// an empty environment, but nothing stops it opening a socket. The broker
// still never gives it anything but the message and DNS answers.
const Confined = false

func confine(exe string, args ...string) (string, []string) { return exe, args }
