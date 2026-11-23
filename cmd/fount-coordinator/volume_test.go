package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fount-labs/fount-broker/internal/coordinator"
	"github.com/fount-labs/fount-broker/internal/volume"
)

func TestVolumeFlags(t *testing.T) {
	for _, c := range []struct {
		f  volumeFlags
		ok bool
	}{
		{volumeFlags{}, true},
		{volumeFlags{name: "state", mode: keyVault}, true},
		{volumeFlags{name: "state", mode: keyDev, authority: "env:SEED"}, true},
		{volumeFlags{name: "state", mode: keyDev}, false},
		{volumeFlags{name: "state", mode: keyDev, authority: "/state/seed"}, false},
		{volumeFlags{name: "State", mode: keyVault}, false},
		{volumeFlags{name: "../x", mode: keyVault}, false},
	} {
		if err := c.f.check(); (err == nil) != c.ok {
			t.Errorf("%+v: %v", c.f, err)
		}
	}
}

func TestDevVolumeKeyIsTheSeeds(t *testing.T) {
	seed := bytes.Repeat([]byte{3}, 32)
	t.Setenv("SEED", base64.StdEncoding.EncodeToString(seed))
	key, err := volumeFlags{name: "state", mode: keyDev, authority: "env:SEED"}.devKey()
	if err != nil || !bytes.Equal(key, coordinator.DevVolumeKey(seed)) {
		t.Fatalf("%v", err)
	}
	if key, _ := (volumeFlags{name: "state", mode: keyVault}).devKey(); key != nil {
		t.Fatal("the vault's volume waits for the wrapping key")
	}
}

// replies answers each operation in turn, the next for every connection.
func replies(answers ...string) func(context.Context, string) (net.Conn, error) {
	var i atomic.Int32
	return func(context.Context, string) (net.Conn, error) {
		n := int(i.Add(1)) - 1
		if n >= len(answers) || answers[n] == "" {
			return nil, errors.New("no such socket")
		}
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			server.Read(make([]byte, 1024))
			server.Write([]byte(answers[n]))
		}()
		return client, nil
	}
}

func volumeState(t *testing.T, s *keyStatus) volumeStatus {
	t.Helper()
	var jobs atomic.Pointer[coordinator.Coordinator]
	w := httptest.NewRecorder()
	statusAPI(s, &jobs, nil).ServeHTTP(w, httptest.NewRequest("GET", "/status", nil))
	var got struct {
		Volume volumeStatus `json:"volume"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return got.Volume
}

func TestOpenVolumeReportsOnStatus(t *testing.T) {
	ctx := context.Background()
	newStatus := func() *keyStatus { return &keyStatus{Mode: keyVault, vol: volumeStatus{State: "none"}} }
	if got := volumeState(t, newStatus()); got.State != "none" {
		t.Fatalf("no --volume: %+v", got)
	}

	// The socket isn't there yet, then a blank disk.
	s := newStatus()
	f := volumeFlags{name: "state", dial: replies("", "rejected", "ok")}
	if err := f.open(ctx, make([]byte, 32), s); err != nil {
		t.Fatal(err)
	}
	if got := volumeState(t, s); got.State != string(volume.Initialized) || got.LastError != "" {
		t.Fatalf("initialized: %+v", got)
	}

	// Another coordinator's disk: final, and said so.
	s = newStatus()
	f.dial = replies("rejected", "rejected")
	if err := f.open(ctx, make([]byte, 32), s); !errors.Is(err, volume.ErrRefused) {
		t.Fatalf("refused: %v", err)
	}
	if got := volumeState(t, s); got.State != "refused" || !strings.Contains(got.LastError, "another key") {
		t.Fatalf("refused: %+v", got)
	}

	// openVolume then waits, rather than exit into a restart loop.
	ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	f.dial = replies("rejected", "rejected")
	if err := openVolume(ctx, f, make([]byte, 32), newStatus()); err != nil || ctx.Err() == nil {
		t.Fatalf("openVolume returned %v before it was stopped", err)
	}
}
