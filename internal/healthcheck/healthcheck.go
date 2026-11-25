// Package healthcheck is an enclave container's healthcheck, so its image needs
// no HTTP client.
package healthcheck

import (
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"strings"
	"time"
)

// maxBody bounds the reason a failed check prints.
const maxBody = 1 << 10

// Check gets url, which must be http on loopback, and fails unless it answers
// 200.
func Check(url string) error {
	u, err := neturl.Parse(url)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(u.Hostname()); u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("health checks only http://127.0.0.1, not %s", url)
	}
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// The body says why: on Tinfoil a failed healthcheck's output is a
		// failed deploy's error.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		why := strings.TrimSpace(strings.ToValidUTF8(string(body), "?"))
		if why == "" {
			return fmt.Errorf("%s: %s", url, resp.Status)
		}
		return fmt.Errorf("%s: %s: %s", url, resp.Status, why)
	}
	return nil
}
