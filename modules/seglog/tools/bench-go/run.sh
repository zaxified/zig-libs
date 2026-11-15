#!/usr/bin/env bash
# seglog vs other logs: every scenario, every implementation, interleaved
# per round so machine load hits all of them alike. Prints raw TSV lines
# (one per run); take the minimum time per row.
#
#   seglog/tools/bench-go/run.sh [rounds]     # from egw-hub/, after
#   zig build seglog-bench -Doptimize=ReleaseFast
#
# Scratch goes to egw-hub/.zig-cache/seglog-bench (a real disk; never tmpfs).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
hub=$(cd "$here/../../.." && pwd)
rounds=${1:-3}
scratch=$hub/.zig-cache/seglog-bench
mkdir -p "$scratch"
(cd "$here" && go build -o "$scratch/bench-go" .)
zigb=$hub/zig-out/bin/seglog-bench
gob=$scratch/bench-go

one() { # impl scenario payload records [batch]
  local impl=$1; shift
  local dir=$scratch/run-$$
  if [ "$impl" = seglog ]; then "$zigb" "$1" "$dir" "${@:2}"; else "$gob" "$impl" "$1" "$dir" "${@:2}"; fi
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
