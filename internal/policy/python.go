package policy

// PythonPackageHosts are the hosts the package tunnel reaches, on port 443
// only. uv, Python's package manager, gets packages from PyPI's index and file
// host, and Python itself from GitHub releases (python-build-standalone),
// which GitHub redirects to its asset hosts.
//
// The tunnel carries TLS end to end, so the broker sees only these names: it
// can't limit which paths on them are fetched.
var PythonPackageHosts = []string{
	"pypi.org",
	"files.pythonhosted.org",
	"github.com",
	"release-assets.githubusercontent.com",
	"objects.githubusercontent.com",
}
