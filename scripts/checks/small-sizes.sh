#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# The size half of the `small` lane (CONVENTIONS.md §4.2): build every
# `modules/<m>/tools/sizeprobe.zig` at ReleaseSmall under `-Dprofile=default`
# and `-Dprofile=small`, and hold each probe's gain (default bytes − small
# bytes, stripped) to the floor in scripts/checks/small-size-expected.tsv.
#
# What it catches: a knob that silently stopped saving -- a refactor that
# instantiates the big path again, a dispatch that no longer reaches the
# option. NOT an exact-byte assertion: the absolute sizes move with every
# toolchain or std change, the floor is set at about half the gain measured
# when the knob landed, so only "the knob stopped working" trips it.
#
# Native target on purpose: on an ADX/BMI2 CPU montint emits per-slot
# straight-line asm, which is where rsa's knob saves most; CI's amd64 runners
# have both. Usage:
#     scripts/checks/small-sizes.sh            # check against the floors
#     scripts/checks/small-sizes.sh --measure  # print the table, check nothing
#
# Silent on success except the table on stdout: scripts/test.sh's `step`
# treats ANY stderr as a failure.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
EXPECTED=scripts/checks/small-size-expected.tsv
OUT=.zig-cache/small-sizes
measure=0
[[ "${1:-}" == --measure ]] && measure=1

for p in default small; do
    if ! log=$(zig build sizeprobes -Doptimize=ReleaseSmall "-Dprofile=$p" -p "$OUT/$p" --summary none 2>&1); then
        echo "small-sizes: building the size probes under -Dprofile=$p failed:" >&2
        echo "$log" >&2
        exit 1
    fi
done

fail=0
declare -A floor=()
while IFS=$'\t' read -r m f _; do
    [[ -z "$m" || "$m" == \#* ]] && continue
    floor["$m"]="$f"
done <"$EXPECTED"

printf '%-12s %10s %10s %10s %10s\n' module default small gain floor
for bin in "$OUT"/default/sizeprobe/sizeprobe-*; do
    [[ -e "$bin" ]] || { echo "small-sizes: no size probe was built" >&2; exit 1; }
    m="${bin##*/sizeprobe-}"
    d=$(stat -c %s "$bin")
    s=$(stat -c %s "$OUT/small/sizeprobe/sizeprobe-$m")
    gain=$((d - s))
    printf '%-12s %10d %10d %10d %10s\n' "$m" "$d" "$s" "$gain" "${floor[$m]:-none}"
    (( measure )) && continue
    if [[ -z "${floor[$m]:-}" ]]; then
        echo "small-sizes: $m has a size probe but no row in $EXPECTED" >&2
        fail=1
    elif (( gain < floor[$m] )); then
        echo "small-sizes: $m: -Dprofile=small saves $gain B, below the floor ${floor[$m]} B -- a knob stopped working, or re-measure and lower the floor in a commit that says why" >&2
        fail=1
    fi
done
exit $fail
