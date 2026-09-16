#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Build + run the standalone HQC benchmark for all 3 parameter sets in 3 build
# lanes (ref, avx256, native).
#
# WHY THIS EXISTS. The reference's published numbers were measured on someone
# else's machine, so comparing this module against them compares two CPUs, not
# two implementations. This builds the C reference HERE, with the same compiler
# and on the same core, so the only difference left is the code.
#
# WHAT IT NEEDS. `gcc`, and the reference checkout built in both lanes — see
# `README.md` in this directory for the exact clone/cmake recipe and for why the
# tag matters. Point $HQC_CREF at it; it defaults to the disposable location the
# README uses. Nothing is copied out of that tree: it is compiled and linked.
#
# WHAT IT PRODUCES. $HQC_CREF/bin/bench_<lane>_hqc-<v> for lane in
# {ref,avx256,native} and v in {1,3,5}. Run one pinned to a core:
#
#     taskset -c 1 "$HQC_CREF/bin/bench_avx256_hqc-1"
#
# Each prints min/median/max/mean+-sd over SAMPLES samples of INNER back-to-back
# calls, in ns/op and TSC cycles/op (see bench_hqc.c).
set -e

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
R="${HQC_CREF:-$REPO/.zig-cache/hqc-cref}"
S="$R/hqc-v5.0.0"

[ -d "$S" ] || { echo "bench.sh: no reference checkout at $S — see README.md" >&2; exit 2; }

OUT="$R/bin"; mkdir -p "$OUT"

build_one() {  # $1=lane $2=variant(1|3|5) $3=libsuffix $4=builddir  $5..=extra flags
  local lane=$1 v=$2 suf=$3 bd=$4; shift 4
  local inc
  if [ "$suf" = "ref" ]; then
    inc="-I$S/src/common -I$S/src/common/hqc-$v -I$S/src/ref -I$S/src/ref/hqc-$v"
  else
    inc="-I$S/src/common -I$S/src/common/hqc-$v -I$S/src/x86_64/common -I$S/src/x86_64/common/hqc-$v -I$S/src/x86_64/avx256 -I$S/src/x86_64/avx256/hqc-$v"
  fi
  gcc -std=c99 -O3 "$@" $inc -I$S/lib/fips202 \
      "$HERE/bench_hqc.c" "$S/$bd/src/libhqc_${v}_${suf}.a" "$S/$bd/lib/libfips202.a" -lm \
      -o "$OUT/bench_${lane}_hqc-$v"
}

for v in 1 3 5; do
  build_one ref     $v ref    build-ref
  build_one avx256  $v x86_64 build-avx256 -funroll-all-loops -mavx -mavx2 -mbmi -mpclmul
  build_one native  $v x86_64 build-avx256 -march=native -funroll-all-loops
done
echo "built:"; ls -1 "$OUT"
