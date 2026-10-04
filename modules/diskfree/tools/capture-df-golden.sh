#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Capture `src/testdata/df_golden.txt`: for each mount point, the raw
# `statfs` numbers as coreutils `stat -f` prints them, then what GNU `df`
# prints for the same filesystem — both taken until two `stat -f` reads
# around the `df` call agree, so a live filesystem cannot drift between them.
# The test builds a `Usage` from the raw numbers and must reproduce `df`'s
# columns exactly (`Usage.totalBytes`/`usedBytes`/`availableBytes`/
# `usePercent`, inode counts).
#
#   modules/diskfree/tools/capture-df-golden.sh / /boot/efi … > modules/diskfree/src/testdata/df_golden.txt
#
# Line format (tab-separated):
#   bsize frsize blocks bfree bavail files ffree | size used avail itotal iused iavail pcent | type
# No privilege needed. Kept per CONVENTIONS.md §9 (the recipe of committed goldens).
set -euo pipefail
export LC_ALL=C
echo "# captured $(date -u +%Y-%m-%d) with $(df --version | head -n 1) and $(stat --version | head -n 1)"
for m in "$@"; do
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        a=$(stat -f -c '%s %S %b %f %a %c %d' -- "$m")
        d=$(df -B1 --output=size,used,avail,itotal,iused,iavail,pcent -- "$m" | tail -n 1)
        b=$(stat -f -c '%s %S %b %f %a %c %d' -- "$m")
        [[ $a == "$b" ]] && break
    done
    [[ $a == "$b" ]] || { echo "unstable: $m" >&2; continue; }
    t=$(stat -f -c '%T' -- "$m")
    # shellcheck disable=SC2086
    printf '%s\t|\t%s\t|\t%s\n' "$(echo $a)" "$(echo $d)" "$t"
done
