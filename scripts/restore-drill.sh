#!/usr/bin/env bash
# The coordinator's restore drill (docs/backups.md, "Rehearsing a restore"), on this machine: no
# AWS, no vault, no mail edge. It backs real state up to an S3 bucket over HTTP, loses the volume,
# and runs the runbook's dry run, restore and restart, in the package and on the binary.
#
#   scripts/restore-drill.sh          the drill, under the race detector
#   scripts/restore-drill.sh -v       with the coordinators' logs
set -euo pipefail
cd "$(dirname "$0")/.."
exec go test -count=1 -race -run '^TestTheRestoreRunbook' "$@" ./internal/coordinator ./cmd/fount-coordinator
