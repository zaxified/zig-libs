#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Differential oracle: GNU coreutils `df` vs this module for
#   (1) path -> containing mount  (`df --output=target PATH`  vs  lookup.containing)
#   (2) the default listing       (`df --output=target`       vs  table.readTable)
#
# `df` is driven only through its public output. Verdicts:
#   (1) per path SAME / DIFF; paths are canonicalised first (`realpath`), because
#       the module is lexical and does not follow symlinks (SPEC "Lexical, by design").
#   (2) df-only rows (in df's listing, not ours) must be NONE; module-only rows are
#       listed: df 9.7 on the development host hides squashfs loop mounts and devtmpfs by default (a black-box fact, cause not established; the module lists every mount with blocks, the
#       caller filters on Row.fs_type).
# Exit 1 on any (1) DIFF or any df-only row.
#
#     modules/diskfree/tools/df-where-diff.sh [PATH...]     # default: a spread of paths
#
# Kept per CONVENTIONS.md section 9 (a differential oracle over a foreign tool's
# public interface). Not wired into `zig build`.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../../.." && pwd)
OUT=${OUT:-$REPO/.zig-cache/diskfree-df-where}
mkdir -p "$OUT"
zig build-exe -OReleaseSafe --dep diskfree \
    -Mroot="$REPO/modules/diskfree/tools/df_where.zig" \
    -Mdiskfree="$REPO/modules/diskfree/src/root.zig" \
    --cache-dir "$REPO/.zig-cache" -femit-bin="$OUT/df_where" >/dev/null

paths=("$@")
if [[ ${#paths[@]} -eq 0 ]]; then
    paths=(/ /etc/passwd /tmp /var/tmp /dev/null /dev/shm /proc/version /sys/kernel /run /boot "$HOME" "$REPO/build.zig" /usr/bin /snap /var/lib /home /snap/bare/5 /sys/firmware/efi/efivars)
fi
canon=()
for p in "${paths[@]}"; do
    [[ -e $p ]] || continue
    canon+=("$(realpath -- "$p")")
done

"$OUT/df_where" where "${canon[@]}" > "$OUT/where.tsv"
same=0; diff=0
while IFS=$'\t' read -r mp path; do
    want=$(df --output=target -- "$path" 2>/dev/null | tail -n 1 || true)
    if [[ $mp == "$want" ]]; then same=$((same + 1)); else diff=$((diff + 1)); echo "DIFF  module: $mp  df: $want  $path"; fi
done < "$OUT/where.tsv"
echo "where: $same SAME, $diff DIFF over ${#canon[@]} paths ($(df --version | head -n 1))"

# (3) mount flags: Usage.flags vs python's os.statvfs(PATH).f_flag (the same f_flags word via libc).
"$OUT/df_where" flags "${canon[@]}" > "$OUT/flags.tsv"
fsame=0; fdiff=0
while IFS=$'\t' read -r fl path; do
    py=$(python3 -I -c 'import os,sys; print(os.statvfs(sys.argv[1]).f_flag)' "$path")
    if [[ $fl == "$py" ]]; then fsame=$((fsame + 1)); else fdiff=$((fdiff + 1)); echo "FLAGS DIFF module: $fl python: $py  $path"; fi
done < "$OUT/flags.tsv"
echo "flags: $fsame SAME, $fdiff DIFF"

# (4) the listing. Default view: the module side applies `table.df_default_skip`
# (squashfs, devtmpfs: types this df build leaves out of its default view, found
# by experiment); `-a` against include_pseudo. tools/list_check.py fails on a df-only
# row and on any module-only row that is not a repeated device (a bind mount).
"$OUT/df_where" list | sort > "$OUT/module-list.txt"
df --output=target | tail -n +2 | sort > "$OUT/df-list.txt"
"$OUT/df_where" list-all | sort > "$OUT/module-all.txt"
df -a --output=target | tail -n +2 | sort > "$OUT/df-all.txt"
lfail=0
python3 -I "$REPO/modules/diskfree/tools/list_check.py" default "$OUT/module-list.txt" "$OUT/df-list.txt" || lfail=1
python3 -I "$REPO/modules/diskfree/tools/list_check.py" all "$OUT/module-all.txt" "$OUT/df-all.txt" || lfail=1

# (5) hard cases in a user+mount namespace (no root; the host is untouched).
nsdir=$(mktemp -d "$REPO/.zig-cache/df-where-ns.XXXXXX")
unshare -rm "$REPO/modules/diskfree/tools/df-where-ns.sh" "$OUT/df_where" "$nsdir" || lfail=1
rmdir "$nsdir" 2>/dev/null || true
[[ $diff -eq 0 && $fdiff -eq 0 && $lfail -eq 0 ]]
