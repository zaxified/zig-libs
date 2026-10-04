#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Differential oracle: GNU coreutils `df` vs this module, mount by mount.
#
# `df` is driven only through its public output (`-B1 --output=…`), one call
# per mount point so a target name with blanks cannot shift a column; the
# module through `tools/df_dump.zig` (its `query` + the `Usage` helpers).
# Per mount, the verdict is
#
#   SAME       every column equal
#   DRIFT      size and inode totals equal, used/avail moved between the two
#              reads by at most DRIFT_MAX bytes (a live filesystem, e.g. /tmp)
#   DIFF       anything else — a real disagreement
#   SKIP       df refused the target (permission, vanished mount) or the
#              module returned an error
#
# Exit status 1 if any DIFF. Needs GNU `df` (coreutils ≥ 8.21 for --output)
# and `zig`; no privilege. Run from the repository root:
#
#     modules/diskfree/tools/df-diff.sh            # every mount in /proc/self/mounts
#     modules/diskfree/tools/df-diff.sh / /tmp     # chosen paths
#
# Kept per CONVENTIONS.md §9 (a differential oracle driving a foreign
# implementation through its public interface). Not wired into `zig build`:
# a consumer's `zig build test-diskfree` must not depend on a host tool.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../../.." && pwd)
OUT=${OUT:-$REPO/.zig-cache/diskfree-df-diff}
DRIFT_MAX=${DRIFT_MAX:-16777216}
mkdir -p "$OUT"
zig build-exe -OReleaseSafe --dep diskfree \
    -Mroot="$REPO/modules/diskfree/tools/df_dump.zig" \
    -Mdiskfree="$REPO/modules/diskfree/src/root.zig" \
    --cache-dir "$REPO/.zig-cache" -femit-bin="$OUT/df_dump" >/dev/null

"$OUT/df_dump" "$@" > "$OUT/module.tsv"
same=0; drift=0; diff=0; skip=0
while IFS=$'\t' read -r -a f; do
    if [[ ${f[0]} == ERR* ]]; then skip=$((skip + 1)); echo "SKIP  module ${f[0]}  ${f[1]}"; continue; fi
    path=${f[7]}
    if ! row=$(df -B1 --output=size,used,avail,itotal,iused,iavail,pcent -- "$path" 2>/dev/null | tail -n 1); then
        skip=$((skip + 1)); echo "SKIP  df refused  $path"; continue
    fi
    read -r -a d <<< "$row"
    # df prints "-" for inode columns it has no number for; the module 0.
    for i in 3 4 5; do [[ ${d[$i]} == - ]] && d[$i]=0; done
    mine="${f[0]} ${f[1]} ${f[2]} ${f[3]} ${f[4]} ${f[5]} ${f[6]}"
    theirs="${d[0]} ${d[1]} ${d[2]} ${d[3]} ${d[4]} ${d[5]} ${d[6]}"
    if [[ $mine == "$theirs" ]]; then
        same=$((same + 1)); continue
    fi
    du=$(( ${f[1]} - ${d[1]} )); da=$(( ${f[2]} - ${d[2]} ))
    if [[ ${f[0]} == "${d[0]}" && ${f[3]} == "${d[3]}" && ${du#-} -le $DRIFT_MAX && ${da#-} -le $DRIFT_MAX ]]; then
        drift=$((drift + 1)); echo "DRIFT used ${du} avail ${da}  $path"
    else
        diff=$((diff + 1)); echo "DIFF  module: $mine"; echo "      df:     $theirs  $path"
    fi
done < "$OUT/module.tsv"
echo "df-diff: $same SAME, $drift DRIFT, $diff DIFF, $skip SKIP ($(df --version | head -n 1))"
[[ $diff -eq 0 ]]
