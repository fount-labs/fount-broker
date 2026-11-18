package policy

// Fount Cloud's coordinator, reached over the attested client channel
// (package channel): CoordinatorOrigin is its origin, and CoordinatorRepo the
// config repo whose releases it must run. Both are empty, and Cloud refused,
// until the real coordinators' config repo exists. fount-labs/fount-cloud-coordinator
// is the test coordinator's, whose wrapping key is the dev one; it is never
// pinned here.
const (
	CoordinatorOrigin = ""
	CoordinatorRepo   = ""
)
