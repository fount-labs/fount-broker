#!/usr/bin/env bash
# Starts one job in the fount-runner image, for the dev coordinator:
#
#   fount-coordinator --dir /tmp/coord -- scripts/dev-runner.sh
#
# The coordinator adds --workspace, --job, --data and --index; this mounts those
# folders into the image, offline. The image comes from the Fount repo's
# scripts/runner-image.sh. Docker Desktop's kernel has no Landlock, so scripts run
# fenced by seccomp only (SCRIPT_CONFINEMENT=best-effort).
set -euo pipefail

IMAGE="${RUNNER_IMAGE:-fount-runner:debug-arm64}"
PLATFORM="${RUNNER_PLATFORM:-linux/arm64}"
CONFINEMENT="${SCRIPT_CONFINEMENT:-best-effort}"

while [ $# -gt 0 ]; do
  case "$1" in
    --workspace) WORKSPACE="$2" ;;
    --job) JOB="$2" ;;
    --data) DATA="$2" ;;
    --index) INDEX="$2" ;;
    *) echo "dev-runner.sh: unexpected argument $1" >&2; exit 2 ;;
  esac
  shift 2
done

exec docker run --rm --platform "$PLATFORM" --network none \
  -v "$WORKSPACE:/work" -v "$DATA:/data" -v "$INDEX:/index" -v "$JOB:/job.json:ro" \
  "$IMAGE" --workspace /work --job /job.json --index /index --script-confinement "$CONFINEMENT"
