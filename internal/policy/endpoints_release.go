//go:build !dev

package policy

func FountAPIBase() string   { return fountAPIBase }
func FountProxyBase() string { return fountProxyBase }

func MailEdgeDev() string { return "" }

func CoordinatorDev() (origin, repo string) { return "", "" }

func harnessRegistryDev() string { return "" }
