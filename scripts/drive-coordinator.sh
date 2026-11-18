#!/usr/bin/env bash
# Drives a deployed coordinator enclave's test API (deploy/coordinator) from this machine: the
# runner's nine smoke jobs one at a time, then the ramp of fount m4-cloud-runners.md §5.2a, a job
# mix at RAMP levels at once. Each job's steps (index, agent) come back with their time, memory
# peak and OOM kills, which the ramp summarises per level. Test data only.
#
#   COORDINATOR=https://<domain> drive-coordinator.sh            smoke jobs, then the ramp
#   SMOKE=0 RAMP="8 16" COORDINATOR=... drive-coordinator.sh     the ramp only, at 8 then 16
#   REAL=1 ACCOUNT=<id> COORDINATOR=... drive-coordinator.sh     real-model jobs: no scripts
#
# REAL=1 sends each job without its script, so the runner calls the model through the proxy with
# the job's credential; ACCOUNT must then be one the proxy entitles. Real jobs have their own
# prompts (real_job), each finishing on its own; transcripts aren't checked, only that it finished.
#
# The bearer token is read from $FOUNT_TEST_API_TOKEN_FILE (default ~/.config/fount/test-api-token)
# and never printed. All jobs are one account's: the pool gives a runner to one account at a time.
set -euo pipefail

API="${COORDINATOR:?set COORDINATOR to https://<coordinator domain>}"
TOKEN_FILE="${FOUNT_TEST_API_TOKEN_FILE:-$HOME/.config/fount/test-api-token}"
ROOT="${FOUNT_ROOT:-$HOME/Desktop/code/fount}"
FIXTURES="$ROOT/src-tauri/crates/fount-runner/tests/fixtures"
SMOKE="${SMOKE:-1}"
RAMP="${RAMP-8 16 24 32}"
ACCOUNT="${ACCOUNT:-acct_drive_$(date +%s)}"
REAL="${REAL:-0}"
[ -s "$TOKEN_FILE" ] || { echo "no token in $TOKEN_FILE" >&2; exit 1; }
HEADERS="$(mktemp)"
trap 'rm -f "$HEADERS"' EXIT
chmod 600 "$HEADERS"
printf 'Authorization: Bearer %s\n' "$(tr -d '\n' < "$TOKEN_FILE")" > "$HEADERS"

api() { curl -sf --max-time 120 -H @"$HEADERS" "$@"; }
curl -sf --max-time 10 "$API/health" > /dev/null || { echo "$API/health doesn't answer" >&2; exit 1; }
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H @"$HEADERS" "$API/v0/jobs/none")
[ "$code" = 404 ] || { echo "the test API answered $code to the token (want 404 for a job that doesn't exist)" >&2; exit 1; }

worker() { api -X POST "$API/v0/workers" -d "{\"account\":\"$ACCOUNT\"}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])'; }
# put <worker> <file> <path>
put() { api -X PUT --data-binary "@$2" "$API/v0/workers/$1/root/$3" > /dev/null; }
# putText <worker> <path> <text>
putText() { printf '%s' "$3" | api -X PUT --data-binary @- "$API/v0/workers/$1/root/$2" > /dev/null; }
# enqueue <worker> <fixture>: prints the job id.
enqueue() {
  python3 - "$FIXTURES/$2" <<'PY' | api -X POST "$API/v0/workers/$1/jobs" -d @- | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])'
import json, sys
f = json.load(open(sys.argv[1]))
print(json.dumps({"threadId": "t1", "sessionId": f["sessionId"], "instruction": f["prompt"], "config": f["config"], "script": f["script"]}))
PY
}
# real_job <worker> <kind>: puts the kind's inputs and enqueues its prompt for the real model,
# with write-job.json's config. Prints the job id.
real_job() {
  local prompt
  case "$2" in
    write) prompt='Write hello.md with a two-line greeting for the team.' ;;
    python)
      putText "$1" data/sales.csv $'region,amount\nNorth,120\nSouth,80\nEast,45\n'
      prompt='Use Python to total the amount column of data/sales.csv, and write the total to total.txt.' ;;
    reads)
      putText "$1" data/sales.csv $'region,amount\nNorth,120\nSouth,80\n'
      putText "$1" pages/about.html $'<html><body><p>The quarterly total was 200.</p></body></html>\n'
      putText "$1" mail/letter.eml $'From: ana@example.com\nSubject: Q3 numbers\n\nThe letter body says hello.\n'
      prompt='Look around the workspace: find the quarterly total, and say what the letter asks.' ;;
    pdf)
      put "$1" "$ROOT/e2e/fixtures/runner-memo.pdf" runner-memo.pdf
      prompt='What does page 2 of runner-memo.pdf say?' ;;
    docx)
      put "$1" "$ROOT/e2e/fixtures/notes-visibility.docx" notes-visibility.docx
      prompt='Read notes-visibility.docx and list its footnotes in summary.md.' ;;
    xlsx)
      put "$1" "$ROOT/e2e/fixtures/Blank.xlsx" Blank.xlsx
      prompt='Put 41 in A1 and a formula A1+1 in B1 of Blank.xlsx.' ;;
    *) echo "no real job $2" >&2; return 1 ;;
  esac
  python3 - "$FIXTURES/write-job.json" "$prompt" "$2" <<'PY' | api -X POST "$API/v0/workers/$1/jobs" -d @- | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])'
import json, sys, uuid
f = json.load(open(sys.argv[1]))
print(json.dumps({"threadId": "t-" + sys.argv[3], "sessionId": str(uuid.uuid4()), "instruction": sys.argv[2], "config": f["config"]}))
PY
}
# wait_job <job>: prints the final state as JSON.
wait_job() {
  local state
  while :; do
    state=$(api "$API/v0/jobs/$1")
    case "$state" in *'"state":"queued"'*|*'"state":"running"'*) sleep 2 ;; *) echo "$state"; return ;; esac
  done
}
# said <worker> <text>: the worker's transcripts hold text.
said() {
  local p
  for p in $(api "$API/v0/workers/$1/files?prefix=fount/conversations/" | python3 -c 'import json,sys; print("\n".join(json.load(sys.stdin)["paths"]))'); do
    api "$API/v0/workers/$1/files/$p" | grep -qF "$2" && return 0
  done
  echo "  MISSING in transcript: $2"; return 1
}
summary() {
  python3 -c '
import json, sys
j = json.load(sys.stdin)
def step(s):
    oom = " %d OOM" % s["oomKills"] if s.get("oomKills") else ""
    return "%s %.1fs %d MiB%s" % (s["mode"], s["seconds"], s["peakMiB"], oom)
steps = ", ".join(step(s) for s in j.get("steps", []))
print(j["state"], j.get("error", ""), "|", steps)'
}

FAIL=0
REAL_MIX=(write python write reads pdf docx write xlsx)
if [ "$REAL" = 1 ] && [ "$SMOKE" = 1 ]; then
  echo "== one real-model job of each kind, one at a time"
  for kind in write python reads pdf docx xlsx; do
    W=$(worker); started=$(date +%s)
    state=$(wait_job "$(real_job "$W" "$kind")")
    echo "$kind: $(( $(date +%s) - started ))s wall, $(echo "$state" | summary)"
    case "$state" in *'"state":"finished"'*) ;; *) FAIL=1 ;; esac
  done
elif [ "$SMOKE" = 1 ]; then
  W=$(worker)
  run() {
    local started=$(date +%s) job state
    job=$(enqueue "$W" "$1")
    state=$(wait_job "$job")
    echo "$1: $(( $(date +%s) - started ))s wall, $(echo "$state" | summary)"
    case "$state" in *'"state":"finished"'*) ;; *) FAIL=1 ;; esac
    shift
    local t; for t in "$@"; do said "$W" "$t" || FAIL=1; done
  }
  echo "== the nine smoke jobs, one at a time"
  run write-job.json
  run python-job.json 'rows: 5'
  run confine-job.json 'socket-inet: denied' 'write-workspace: allowed'
  put "$W" "$ROOT/e2e/fixtures/Blank.xlsx" Blank.xlsx
  run xlsx-job.json 'B1 = 42'
  put "$W" "$ROOT/e2e/fixtures/notes-visibility.docx" notes-visibility.docx
  run docx-job.json 'footnote #f1: Prepared per SEC guidance.'
  put "$W" "$ROOT/e2e/fixtures/runner-memo.pdf" runner-memo.pdf
  run pdf-job.json 'The runner read page two of this memo.'
  putText "$W" data/sales.csv $'region,amount\nNorth,120\nSouth,80\n'
  putText "$W" pages/about.html $'<html><body><h1>About us</h1><p>The quarterly total was 200.</p></body></html>\n'
  putText "$W" mail/letter.eml $'From: ana@example.com\nTo: ops@example.com\nSubject: Q3 numbers\n\nThe letter body says hello.\n'
  run reads-job.json 'quarterly total' 'Q3 numbers' 'The letter body says hello.'
  putText "$W" nb/analysis.ipynb '{"cells": [{"cell_type": "markdown", "metadata": {}, "source": ["# Quarterly check"]}, {"cell_type": "code", "execution_count": 1, "metadata": {}, "source": ["total = 120 + 80\n", "print(total)"], "outputs": [{"output_type": "stream", "name": "stdout", "text": ["200\n"]}]}], "metadata": {}, "nbformat": 4, "nbformat_minor": 5}'
  putText "$W" report.typ $'#set page(paper: "a6")\n= Report\n#include "part.typ"\n#pagebreak()\nThe end.\n'
  putText "$W" part.typ $'The quarterly total was 200.\n'
  run typst-notebook-job.json 'Quarterly check' 'Compilation successful' 'Pages: 2'
  putText "$W" mail/governance.md $'# Governance\n\nThe directors convene on the first Tuesday of each quarter, at 9am in Room 4.\n'
  run search-job.json '/work/mail/governance.md'
fi

# The ramp's mix, roughly mail's: mostly agent jobs, some with a document to index or edit.
MIX=(write-job.json python-job.json write-job.json reads-job.json pdf-job.json docx-job.json write-job.json xlsx-job.json)
# level <n>: n workers, each one job from the mix, all queued at once.
level() {
  local n=$1 i w fixture ws=() fixtures=() jobs=() started
  if [ "$REAL" = 1 ]; then
    for i in $(seq 0 $((n - 1))); do ws+=("$(worker)"); done
    started=$(date +%s)
    for i in "${!ws[@]}"; do jobs+=("$(real_job "${ws[$i]}" "${REAL_MIX[$((i % ${#REAL_MIX[@]}))]}")"); done
  else
  for i in $(seq 0 $((n - 1))); do
    fixture=${MIX[$((i % ${#MIX[@]}))]}
    w=$(worker)
    case "$fixture" in
      pdf-job.json) put "$w" "$ROOT/e2e/fixtures/runner-memo.pdf" runner-memo.pdf ;;
      docx-job.json) put "$w" "$ROOT/e2e/fixtures/notes-visibility.docx" notes-visibility.docx ;;
      xlsx-job.json) put "$w" "$ROOT/e2e/fixtures/Blank.xlsx" Blank.xlsx ;;
      reads-job.json)
        putText "$w" data/sales.csv $'region,amount\nNorth,120\nSouth,80\n'
        putText "$w" pages/about.html $'<html><body><p>The quarterly total was 200.</p></body></html>\n'
        putText "$w" mail/letter.eml $'From: ana@example.com\nSubject: Q3 numbers\n\nThe letter body says hello.\n' ;;
    esac
    ws+=("$w"); fixtures+=("$fixture")
  done
  started=$(date +%s)
  for i in "${!ws[@]}"; do jobs+=("$(enqueue "${ws[$i]}" "${fixtures[$i]}")"); done
  fi
  local out="" state
  for j in "${jobs[@]}"; do
    state=$(wait_job "$j")
    case "$state" in *'"state":"finished"'*) ;; *) FAIL=1 ;; esac
    out+="$state"$'\n'
  done
  local wall=$(( $(date +%s) - started ))
  printf '%s' "$out" | python3 -c '
import json, sys
n, wall = sys.argv[1], sys.argv[2]
jobs = [json.loads(l) for l in sys.stdin if l.strip()]
failed = [j for j in jobs if j["state"] != "finished"]
steps = [s for j in jobs for s in j.get("steps", [])]
def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))] if xs else 0
for mode in ("index", "agent"):
    ss = [s for s in steps if s["mode"] == mode]
    if ss:
        secs, peaks = [s["seconds"] for s in ss], [s["peakMiB"] for s in ss]
        print(f"  {mode}: {len(ss)} steps, p50 {pct(secs, 50):.1f}s p95 {pct(secs, 95):.1f}s, peak p95 {pct(peaks, 95)} MiB max {max(peaks)} MiB")
from datetime import datetime
def t(v): return datetime.fromisoformat(v.replace("Z", "+00:00"))
waits = [(t(j["started"]) - t(j["queued"])).total_seconds() for j in jobs if j.get("started")]
latency = [(t(j["ended"]) - t(j["queued"])).total_seconds() for j in jobs if j.get("ended")]
if latency:
    print(f"  queued to ended: p50 {pct(latency, 50):.1f}s p95 {pct(latency, 95):.1f}s max {max(latency):.1f}s; queue wait max {max(waits):.1f}s")
oom = sum(s.get("oomKills", 0) for s in steps)
print(f"{n} at once: {wall}s wall, {len(failed)} failed, {oom} OOM kills")
for j in failed:
    print("  failed:", j["id"], j.get("error", ""))
' "$n" "$wall"
}
if [ -n "$RAMP" ]; then
  echo "== the ramp"
  for n in $RAMP; do level "$n"; done
fi

[ "$FAIL" = 0 ] && echo "all checks passed" || { echo "some checks failed"; exit 1; }
