#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Raw differential: feed each probe to both dumpers, report AGREE / DIFFER.
#
# Feeds each probe file to both dumpers and reports AGREE / DIFFER.
#
#   diff_run.sh <probe-dir>
#
# Env:
#   BASE  scratch root holding out/oracle_dump, out/module_dump and ref/root
#         (default: <repo>/.zig-cache/uci-differential, derived from this
#         script's own location)
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
BASE="${BASE:-$REPO/.zig-cache/uci-differential}"
ORACLE="$BASE/out/oracle_dump"
MODULE="$BASE/out/module_dump"
CONFDIR="$BASE/ref/root/etc/config"
mkdir -p "$CONFDIR"

dir="${1:?usage: diff_run.sh <probe-dir>}"
agree=0; differ=0
for f in "$dir"/*; do
    [ -f "$f" ] || continue
    name=$(basename "$f")
    cp "$f" "$CONFDIR/probe"
    o=$("$ORACLE" "$CONFDIR" probe 2>&1)
    m=$("$MODULE" < "$f" 2>&1)
    if [ "$o" == "$m" ]; then
        agree=$((agree+1))
        [ -n "${VERBOSE:-}" ] && printf 'AGREE  %s\n' "$name"
    else
        differ=$((differ+1))
        printf 'DIFFER %s\n' "$name"
        printf '  input : %s\n' "$(od -c "$f" | head -4 | tr '\n' '|')"
        printf '  libuci: %s\n' "$(echo "$o" | tr '\n' '|')"
        printf '  module: %s\n' "$(echo "$m" | tr '\n' '|')"
    fi
done
rm -f "$CONFDIR/probe"
printf '\n== %d agree, %d differ ==\n' "$agree" "$differ"
