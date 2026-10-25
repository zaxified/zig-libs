#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# rosedb v2.4.0: append K random bytes to the active .SEG after a clean close ->
# Open panics (the probe prints the panic and exits 3). Backs the kv "Ahead"
# claim on torn tails. Needs the probes built by ../run.sh.
# usage: bash repro/rosedb_garbage_panic.sh [K [SEED]]
set -u
K=${1:-13}; SEED=${2:-1}
here=$(cd "$(dirname "$0")" && pwd)
w=$(cd "$here/../../../../.." && pwd)/.zig-cache/kv-lead-probe
d=$w/repro-rosedb
mkdir -p "$d"
for f in "$d"/*; do [ -e "$f" ] && rm "$f"; done
"$w/bin/rosedb" write "$d" 1000 0
python3 -I -c "import random,sys; open(sys.argv[1] + '/000000001.SEG','ab').write(random.Random($SEED).randbytes($K))" "$d"
"$w/bin/rosedb" check "$d" 1000
rc=$?
for f in "$d"/*; do [ -e "$f" ] && rm "$f"; done
rmdir "$d"
exit $rc
