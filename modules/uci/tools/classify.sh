#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Differential WITH classification -- the distinction that makes this worth
# running next to the in-tree grammar capture. `grammar_capture.txt` pins the
# VERDICT (loads or is refused); this pins the DATA, and VALUE-DIVERGE (both
# parsers accept, and disagree about what they parsed) is the dangerous class
# neither the verdict capture nor the module's own tests can see.
#
# Distinguishes the cases that matter from the ones that don't:
#   SAME          identical structural dump
#   BOTH-REJECT   both parsers reject (wording differs — not a divergence)
#   MODULE-ACCEPTS-LIBUCI-REJECTS   fail-open vs. the reference
#   MODULE-REJECTS-LIBUCI-ACCEPTS   valid config file refused
#   VALUE-DIVERGE both accept, different data  <-- the dangerous class
#
#   classify.sh <probe-dir>
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
BASE="${BASE:-$REPO/.zig-cache/uci-differential}"
ORACLE="$BASE/out/oracle_dump"
MODULE="$BASE/out/module_dump"
CONFDIR="$BASE/ref/root/etc/config"
mkdir -p "$CONFDIR"
dir="${1:?usage: classify.sh <probe-dir>}"

declare -A n
for f in "$dir"/*; do
    [ -f "$f" ] || continue
    name=$(basename "$f")
    cp "$f" "$CONFDIR/probe"
    o=$("$ORACLE" "$CONFDIR" probe 2>&1)
    m=$("$MODULE" < "$f" 2>&1)
    oe=0; me=0
    [[ "$o" == ERR* ]] && oe=1
    [[ "$m" == ERR* ]] && me=1
    if [ "$o" == "$m" ]; then                     k=SAME
    elif [ $oe -eq 1 ] && [ $me -eq 1 ];  then    k=BOTH-REJECT
    elif [ $oe -eq 1 ] && [ $me -eq 0 ];  then    k=MODULE-ACCEPTS-LIBUCI-REJECTS
    elif [ $oe -eq 0 ] && [ $me -eq 1 ];  then    k=MODULE-REJECTS-LIBUCI-ACCEPTS
    else                                          k=VALUE-DIVERGE
    fi
    n[$k]=$(( ${n[$k]:-0} + 1 ))
    if [ "$k" != SAME ] && [ "$k" != BOTH-REJECT ] || [ -n "${VERBOSE:-}" ]; then
        printf '%-31s %s\n' "$k" "$name"
        printf '   libuci: %s\n' "$(echo "$o" | tr '\n' '|')"
        printf '   module: %s\n' "$(echo "$m" | tr '\n' '|')"
    fi
done
rm -f "$CONFDIR/probe"
echo "== totals =="
for k in SAME BOTH-REJECT MODULE-ACCEPTS-LIBUCI-REJECTS MODULE-REJECTS-LIBUCI-ACCEPTS VALUE-DIVERGE; do
    printf '%-31s %d\n' "$k" "${n[$k]:-0}"
done
