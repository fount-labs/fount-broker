package policy

import "regexp"

// Fount's releases on GitHub. GitHub answers both requests with a redirect to
// its asset host, so the route follows redirects to UpdatesRedirectHosts and
// nowhere else.
const UpdatesBase = "https://github.com/fount-labs/fount/releases/"

var UpdatesRedirectHosts = []string{"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}

func init() {
	// The manifest of the latest release: its version, and each platform's
	// package URL and signature. The app checks each package against the
	// updater key compiled into it before installing.
	Destinations["updates.manifest"] = Destination{
		Route:  RouteUpdates,
		Method: "GET",
		Path:   "latest/download/latest.json",
		Accept: []string{"", "application/json"},
		Body:   Body{Kind: BodyNone},
	}
	// One release's update package, named as the release workflow names it.
	Destinations["updates.package"] = Destination{
		Route:       RouteUpdates,
		Method:      "GET",
		Path:        "download/",
		PathPattern: updatePackagePattern,
		Accept:      []string{"", "application/octet-stream"},
		Body:        Body{Kind: BodyNone},
	}
}

var updatePackagePattern = regexp.MustCompile(`^v\d+\.\d+\.\d+/Fount_\d+\.\d+\.\d+_(aarch64\.app\.tar\.gz|x64-setup\.exe)$`)
