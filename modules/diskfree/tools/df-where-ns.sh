#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Hard path -> mount cases for `df-where-diff.sh`, run inside `unshare -rm` (a user
# + mount namespace: no real root, nothing on the host changes). Builds a tree of
# tmpfs mounts under a scratch directory and compares, per file, GNU
# `df --output=target FILE` with `lookup.containing` over /proc/self/mounts.
#
#   stacked      tmpfs mounted twice on the same directory
#   bind         a same-device bind mount of a mounted directory
#   space        a mount point with a space in its name (\040 in the table)
#   hidden       /h/inner mounted, then /h mounted over it (a later ANCESTOR)
#   trailing /   the query path ends in a slash
#
# Args: $1 = df_where binary, $2 = scratch directory (must exist, empty).
# Exit 1 on any DIFF.
set -uo pipefail
BIN=$1; ROOT=$(cd "$2" && pwd)
cd "$ROOT"
mkdir -p a bind "sp ace" h/inner h2
mount -t tmpfs tmpfs a
mount -t tmpfs tmpfs a                 # stacked on the first
mount --bind a bind                    # same device as the stack's top
mount -t tmpfs tmpfs "sp ace"
mount -t tmpfs tmpfs h/inner
mount -t tmpfs tmpfs h                 # covers h/inner
mkdir -p a/d "sp ace/d" h/new
touch a/f bind/f "sp ace/f" h/f h/new/f
diff=0; same=0
check() { # label query-path
    local q=$2 canon want got
    canon=$(realpath -- "$q")
    want=$(df --output=target -- "$q" 2>/dev/null | tail -n 1)
    got=$("$BIN" where "$canon" | cut -f1)
    if [[ $want == "$got" ]]; then same=$((same + 1)); echo "SAME  $1: $got"
    else diff=$((diff + 1)); echo "DIFF  $1: module '$got'  df '$want'  ($q)"; fi
}
check stacked "$ROOT/a/f"
check stacked-dir "$ROOT/a/d"
check stacked-trailing-slash "$ROOT/a/d/"
check bind "$ROOT/bind/f"
check space "$ROOT/sp ace/f"
check space-dir "$ROOT/sp ace/d/"
check hidden-ancestor "$ROOT/h/f"
check hidden-ancestor-deeper "$ROOT/h/new/f"
# The covered directory no longer exists in the covering filesystem, so df has no answer
# for it; the module must still name the covering mount, not the hidden one.
got=$("$BIN" where "$ROOT/h/inner/x" | cut -f1)
if [[ $got == "$ROOT/h" ]]; then same=$((same + 1)); echo "SAME  hidden-ancestor-covered-path: $got"
else diff=$((diff + 1)); echo "DIFF  hidden-ancestor-covered-path: module '$got' expected '$ROOT/h'"; fi
check outside "$ROOT/h2"
echo "ns-cases: $same SAME, $diff DIFF (df: $(df --version | head -n 1))"
echo "--- what table.collect lists for these mounts (the covered h/inner must be absent)"
"$BIN" list-all | grep -F "$ROOT" | sed "s|$ROOT|.|"
[[ $diff -eq 0 ]]
