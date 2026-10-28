#!/usr/bin/env bash
# Builds the release binaries into dist/. CI runs this for every tag; run it
# yourself at the same tag to check that a release was built from this source.
#
# Usage:  scripts/build-release.sh vX.Y.Z
#
# The output is byte-for-byte reproducible: paths, build IDs and VCS stamps
# are stripped, and the Go toolchain is pinned to the version in go.mod.

set -euo pipefail

VERSION="${1:?usage: scripts/build-release.sh vX.Y.Z}"
cd "$(dirname "$0")/.."

export GOTOOLCHAIN="go$(sed -n 's/^go //p' go.mod)"
export CGO_ENABLED=0 GOFLAGS=

rm -rf dist
mkdir dist

build() {
    local triple=$1 goos=$2 goarch=$3 ext=$4
    GOOS=$goos GOARCH=$goarch go build -trimpath -buildvcs=false \
        -ldflags "-s -w -buildid= -X main.version=$VERSION" \
        -o "dist/fount-broker-$triple$ext" ./cmd/fount-broker
}

build aarch64-apple-darwin      darwin  arm64 ""
build x86_64-pc-windows-msvc    windows amd64 .exe
build x86_64-unknown-linux-gnu  linux   amd64 ""
build aarch64-unknown-linux-gnu linux   arm64 ""

(cd dist && shasum -a 256 *)
