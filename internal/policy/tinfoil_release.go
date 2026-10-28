//go:build !dev

package policy

// TinfoilProxyBase is the proxy release builds send inference through.
func TinfoilProxyBase() string { return tinfoilProxyBase }
