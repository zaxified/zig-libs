#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Shrink slippage: does a shrinker keep the failure it started from? The
# property is `twoBugsCheck` in `src/shrink.zig` (deep: >= 16 bytes summing
# to >= 1500; shallow: starts with a zero). Our side is the test
# `lead: a Deep input shrinks to a Deep input ...`; this script runs the two
# foreign ones over 20 seeds each and prints one line per run:
#   tool  seed  first-failure  reported-failure  reported-length
#
#   proptest 1.11.0 (reference)  TestRunner::run, default Config
#   libFuzzer (LLVM, fastest)    -minimize_crash=1 from a random deep input,
#                                plain, with ASan, and with ASan +
#                                dedup_token_length=3 and =10 (libFuzzer
#                                stops minimizing when the first and the
#                                new crash's DEDUP_TOKEN differ; only a
#                                sanitizer prints one, and its first three
#                                frames are libFuzzer's own crash handler)
#
# Needs cargo (the crates pinned in proptest_rust/Cargo.lock), clang with
# its libFuzzer runtime, python3 (stdlib). Run from the repository root.
# Scratch goes to .zig-cache/slip.
set -euo pipefail

here=modules/testkit/tools
work=.zig-cache/slip
mkdir -p "$work"

cargo build --release --locked --offline --quiet \
    --manifest-path "$here/proptest_rust/Cargo.toml" --target-dir .zig-cache/proptest_rust
.zig-cache/proptest_rust/release/slip | sed 's/^/proptest\t/'

clang -O1 -g -fsanitize=fuzzer "$here/libfuzzer_c/slip.c" -o "$work/slip-plain"
clang -O1 -g -fsanitize=fuzzer,address "$here/libfuzzer_c/slip.c" -o "$work/slip-asan"

# One random deep input per seed: uniform length 0..64, uniform bytes, the
# first draw that fails deep (as the driver's first failing seed).
classify() {
    python3 -I -c '
import sys
b = open(sys.argv[1], "rb").read()
if len(b) >= 2 and b[0] == 0: c = "shallow"
elif len(b) >= 16 and sum(b) >= 1500: c = "deep"
else: c = "pass"
print(c, len(b), sep="\t")' "$1"
}

# One seed, all four libFuzzer variants. A crash costs libFuzzer about
# 0.6 s of sleeping in its handler, so the seeds run side by side.
one_seed() {
    local seed=$1 v bin opts out
    python3 -I -c '
import random, sys
r = random.Random(int(sys.argv[1]))
while True:
    b = bytes(r.randrange(256) for _ in range(r.randint(0, 64)))
    if len(b) >= 2 and b[0] == 0: continue
    if len(b) >= 16 and sum(b) >= 1500: break
open(sys.argv[2], "wb").write(b)' "$seed" "$work/start-$seed"
    for v in plain asan asan-dedup3 asan-dedup10; do
        bin=$work/slip-${v%-dedup*}
        opts=
        case $v in *-dedup*) opts=dedup_token_length=${v##*-dedup} ;; esac
        out=$work/min-$v-$seed
        rm -f "$out"
        ASAN_OPTIONS=$opts "$bin" -minimize_crash=1 -runs=200000 -seed=$((seed + 1)) \
            -exact_artifact_path="$out" "$work/start-$seed" > "$work/log-$v-$seed" 2>&1 || true
        if [ ! -f "$out" ]; then
            echo "slip.sh: libFuzzer ($v, seed $seed) wrote no artifact, see $work/log-$v-$seed" >&2
            cp "$work/start-$seed" "$out"
        fi
        printf 'libfuzzer-%s\t%s\tdeep\t%s\n' "$v" "$seed" "$(classify "$out")"
    done > "$work/res-$seed"
}

rm -f "$work"/res-*
pids=()
for seed in $(seq 0 19); do one_seed "$seed" & pids+=($!); done
failed=0
for p in "${pids[@]}"; do wait "$p" || failed=1; done
[ "$failed" = 0 ] || { echo "slip.sh: a seed's run failed" >&2; exit 1; }
for seed in $(seq 0 19); do cat "$work/res-$seed"; done | sort -s -k1,1
n=$(cat "$work"/res-* | wc -l)
[ "$n" = 80 ] || { echo "slip.sh: $n libFuzzer rows, expected 80" >&2; exit 1; }
