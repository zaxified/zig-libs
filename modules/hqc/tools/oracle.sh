#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Build the HQC differential oracle for all 3 parameter sets, in the `ref` and
# `avx256` lanes.
#
# WHY THIS EXISTS. This module's own tests replay vectors that were frozen once.
# That catches a regression against the past; it cannot answer "what does the
# other implementation do for THIS input". `oracle_hqc.c` answers exactly that,
# and building it in both reference lanes means the two lanes can also be held
# against each other — a disagreement there is the reference's problem, not ours,
# and the distinction matters when a vector fails.
#
# WHAT IT NEEDS. `gcc` and the reference checkout built in both lanes; see
# `README.md` here for the recipe and the tag trap. $HQC_CREF overrides the
# location.
#
# WHAT IT PRODUCES. $HQC_CREF/bin/oracle_<lane>_hqc-<v>. Each takes either a
# 96-hex-character seed or `--kat N`, and prints `seed/pk/sk/ct/ss = <HEX>` in
# the same field names the official .rsp files use, so the two can be diffed
# directly.
set -e

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
R="${HQC_CREF:-$REPO/.zig-cache/hqc-cref}"
S="$R/hqc-v5.0.0"

[ -d "$S" ] || { echo "oracle.sh: no reference checkout at $S — see README.md" >&2; exit 2; }

OUT="$R/bin"; mkdir -p "$OUT"

for v in 1 3 5; do
  gcc -std=c99 -O2 \
    -I$S/src/common -I$S/src/common/hqc-$v -I$S/src/ref -I$S/src/ref/hqc-$v -I$S/lib/fips202 \
    "$HERE/oracle_hqc.c" "$S/build-ref/src/libhqc_${v}_ref.a" "$S/build-ref/lib/libfips202.a" \
    -o "$OUT/oracle_ref_hqc-$v"
  gcc -std=c99 -O2 -mavx -mavx2 -mbmi -mpclmul \
    -I$S/src/common -I$S/src/common/hqc-$v -I$S/src/x86_64/common -I$S/src/x86_64/common/hqc-$v \
    -I$S/src/x86_64/avx256 -I$S/src/x86_64/avx256/hqc-$v -I$S/lib/fips202 \
    "$HERE/oracle_hqc.c" "$S/build-avx256/src/libhqc_${v}_x86_64.a" "$S/build-avx256/lib/libfips202.a" \
    -o "$OUT/oracle_avx256_hqc-$v"
done
echo "built oracles:"; ls -1 "$OUT" | grep oracle
