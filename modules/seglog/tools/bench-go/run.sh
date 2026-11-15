#!/usr/bin/env bash
# seglog vs other logs: every scenario, every implementation, interleaved
# per round so machine load hits all of them alike. Prints raw TSV lines
# (one per run); take the minimum time per row.
#
#   modules/seglog/tools/bench-go/run.sh [rounds]
#
# The Zig side is `zig build bench-seglog -- <scenario> <dir> ...` (always
# ReleaseFast, built on the first call and cached after); needs go and the
# module cache `go.mod`/`go.sum` pin (GOPROXY=off, as the other go_bench tools).
# Scratch goes to .zig-cache/seglog-bench (a real disk; never tmpfs).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd) # the zig-libs checkout
rounds=${1:-3}
scratch=$root/.zig-cache/seglog-bench
mkdir -p "$scratch"
(cd "$here" && GOPROXY=off go build -o "$scratch/bench-go" .)
gob=$scratch/bench-go

one() { # impl scenario payload records [batch]
  local impl=$1; shift
  local dir=$scratch/run-$$
  # The build runner forwards the program's stdout; keep only the TSV row.
  if [ "$impl" = seglog ]; then (cd "$root" && zig build bench-seglog -- "$1" "$dir" "${@:2}" 2>&1 | grep -E '^seglog'); else "$gob" "$impl" "$1" "$dir" "${@:2}"; fi
}

for r in $(seq "$rounds"); do
  for impl in seglog tidwall wlog; do
    one "$impl" append 155 2000
    one "$impl" append 4096 1000
    one "$impl" batch 155 1000000 1000
    one "$impl" batch 4096 100000 100
    one "$impl" read 155 1000000
    one "$impl" read 4096 100000
    one "$impl" open 155 1000000
    one "$impl" open 4096 100000
  done
done
