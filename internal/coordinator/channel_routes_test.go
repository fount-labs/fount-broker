package coordinator

import (
	"strings"
	"testing"

	"github.com/fount-labs/fount-broker/internal/channel"
)

// notFromDesktop are the account API's routes Desktop doesn't call, so the
// channel needn't carry them.
var notFromDesktop = map[string]string{
	"GET /workers/{id}/export": "the export runs in the coordinator's own tooling, not Desktop",
}

// TestDesktopsRoutesPassTheChannel: every route opRoles names that Desktop
// calls is one the broker's channel carries, so none is refused in
// production before the coordinator sees it.
func TestDesktopsRoutesPassTheChannel(t *testing.T) {
	sample := strings.NewReplacer(
		"/jobs/{id}", "/jobs/j_0123456789abcdef01234567",
		"{id}", "w_0123456789abcdef01234567",
		"{tid}", "thr_0123456789abcdef01234567",
		"{draft}", "ent_0123456789abcdef01234567",
		"{team}", "acct_acme",
		"{invite}", "inv_1",
		"{path...}", "root/a b.md",
	)
	seen := 0
	for key := range opRoles {
		method, path, ok := strings.Cut(key, " ")
		if !ok || !strings.HasPrefix(path, "/") {
			continue // an operation kind, not a route
		}
		if _, skip := notFromDesktop[key]; skip {
			continue
		}
		seen++
		target := "v1" + sample.Replace(path)
		if strings.Contains(path, "/drafts/{draft}/files/") {
			target += "?rev=1"
		}
		if _, err := channel.CheckRequest(method, target); err != nil {
			t.Errorf("%s isn't carried by the channel: %v", key, err)
		}
	}
	if seen < 25 {
		t.Fatalf("only %d routes checked", seen)
	}
}
