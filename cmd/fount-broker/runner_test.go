package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunnerIsReadyOnlyOnceTheSupervisorTakesConnections(t *testing.T) {
	// t.TempDir is too long a path for a Unix socket on macOS.
	dir, err := os.MkdirTemp("", "ps")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "supervisor.sock")
	s := &pullStatus{State: "pulling", Since: time.Now(), supervisor: path}

	if s.ready() || s.State != "pulling" {
		t.Fatalf("ready while pulling: %q", s.State)
	}
	s.done(time.Second)
	if s.ready() || s.State != "starting" || s.Supervisor == "" {
		t.Fatalf("ready with no supervisor: %q %q", s.State, s.Supervisor)
	}

	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if !s.ready() || s.Supervisor != "" {
		t.Fatalf("not ready with the supervisor up: %q %q", s.State, s.Supervisor)
	}

	l.Close()
	if s.ready() || s.State != "starting" {
		t.Fatalf("still ready once the supervisor is gone: %q", s.State)
	}
}
