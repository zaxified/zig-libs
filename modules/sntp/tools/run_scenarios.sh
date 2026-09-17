#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# WHY THIS EXISTS: drives the module's `query` against the hostile `stub.py` on
# 127.0.0.1 with an ephemeral port, one scenario per run. Never touches a real
# NTP server -- the audit proved that with `strace` and the property is worth
# keeping, because a verification tool that quietly reaches the public internet
# is not one you can run in CI or on a plane.
#
#   modules/sntp/tools/run_scenarios.sh                 # every scenario
#   modules/sntp/tools/run_scenarios.sh correct li3     # only these
#
# Expects `client` built next to BASE (see README.md):
#   CLIENT=<scratch>/client modules/sntp/tools/run_scenarios.sh
#
# ⚠ Four scenarios changed meaning since the audit, and the run is worth reading
# for exactly that: `li3` (F7), `zero_t2` (F3), `mac68` and `long1024` (F2) were
# all ACCEPTED then and must be REJECTED now. A scenario that still reports
# ACCEPTED is a regression, not a pass.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
BASE="${BASE:-$REPO/.zig-cache/sntp-scenarios}"
CLIENT="${CLIENT:-$BASE/client}"
STUB="$HERE/stub.py"

if [ ! -x "$CLIENT" ]; then
  echo "no client binary at $CLIENT -- build it first (see tools/README.md)" >&2
  exit 2
fi
mkdir -p "$BASE"

SCENARIOS="${*:-correct zero_origin foreign_origin origin_hi_only origin_lo_only mode3 kod stratum16 li3 far_future zero_t2 mac68 long1024 short40 wrongport flood_then_correct silent}"

rc=0
for s in $SCENARIOS; do
  python3 "$STUB" "$s" > "$BASE/.stub.port" 2> "$BASE/.stub.err" &
  stub_pid=$!
  PORT=""
  for _ in $(seq 1 100); do
    PORT=$(head -1 "$BASE/.stub.port" 2>/dev/null)
    [ -n "$PORT" ] && break
    sleep 0.05
  done
  if [ -z "$PORT" ]; then
    echo "$s: stub failed to bind"
    kill "$stub_pid" 2>/dev/null
    rc=1
    continue
  fi
  TMO=3000
  [ "$s" = "silent" ] && TMO=1500
  printf '%-20s ' "$s"
  "$CLIENT" 127.0.0.1 "$PORT" "$TMO" 2>&1 | tail -1
  sed 's/^/                     | /' "$BASE/.stub.err"
  kill "$stub_pid" 2>/dev/null
  wait "$stub_pid" 2>/dev/null
done
rm -f "$BASE/.stub.port" "$BASE/.stub.err"
exit $rc
