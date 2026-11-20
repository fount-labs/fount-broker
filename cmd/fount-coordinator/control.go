package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fount-labs/fount-broker/internal/coordinator"
)

// controlTokenEnv is the control plane's bearer token for /control/runners
// (fount-infra docs/TEAM_RUNNERS.md): the coordinator's Tinfoil secret, also
// in Secrets Manager as fount/coordinator-control-token-<stage>.
const controlTokenEnv = "FOUNT_CONTROL_TOKEN"

// minControlToken is 16 random bytes as hex, at the least.
const minControlToken = 32

var stagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)

// checkTeamStage checks --team-runner-stage.
func checkTeamStage(stage string, dialIn bool) error {
	if stage == "" {
		return nil
	}
	if !dialIn {
		return errors.New("--team-runner-stage needs --runners-dial-in")
	}
	if !stagePattern.MatchString(stage) {
		return fmt.Errorf("--team-runner-stage %q: lower-case letters, digits and -", stage)
	}
	return nil
}

// controlAPI is GET /control/runners: each team's runner, its queue and its
// last activity, for the control plane that starts and stops team runners.
// It reveals how many teams have work and when, so it is behind the token,
// compared in constant time. Without $FOUNT_CONTROL_TOKEN there is no route
// (nil): the path is a 404, as on a coordinator with no team runners. Until
// the coordinator runs it answers 503, which the control plane counts as
// unread.
func controlAPI(token, stage string, hub *coordinator.RunnerHub, jobs *atomic.Pointer[coordinator.Coordinator]) (http.Handler, error) {
	if token == "" {
		return nil, nil
	}
	if len(token) < minControlToken {
		return nil, fmt.Errorf("$%s must be at least %d characters of a random value", controlTokenEnv, minControlToken)
	}
	if hub == nil || stage == "" {
		return nil, fmt.Errorf("$%s needs --runners-dial-in and --team-runner-stage", controlTokenEnv)
	}
	want := []byte("Bearer " + token)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /control/runners", func(w http.ResponseWriter, r *http.Request) {
		got := []byte(strings.TrimSpace(r.Header.Get("Authorization")))
		if subtle.ConstantTimeCompare(got, want) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "the control route needs its bearer token", http.StatusUnauthorized)
			return
		}
		c := jobs.Load()
		if c == nil {
			http.Error(w, "the coordinator is waiting for its wrapping key", http.StatusServiceUnavailable)
			return
		}
		body, err := json.Marshal(map[string]any{"runners": c.TeamRunners(stage, hub.TeamLinks(), time.Now())})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(append(body, '\n'))
	})
	return mux, nil
}

// withControl serves control's routes ahead of h's, when there are any.
func withControl(h, control http.Handler) http.Handler {
	if control == nil {
		return h
	}
	mux := http.NewServeMux()
	mux.Handle("/control/", control)
	mux.Handle("/", h)
	return mux
}

func controlToken() string { return os.Getenv(controlTokenEnv) }
