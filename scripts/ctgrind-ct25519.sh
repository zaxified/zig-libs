#!/usr/bin/env bash
# ctgrind-ct25519.sh — reproduce ct25519/SPEC.md's constant-time claim under
# valgrind/memcheck, and print the full control table instead of asserting a
# single number.
#
# The claim (`modules/ct25519/SPEC.md` "Constant-time check", cited from
# `modules/voprf/SPEC.md`'s "Side channels" section): `ct25519.mul` and its
# `mulRistretto*` wrappers execute the same sequence of operations for every
# scalar, where std's `Ristretto255.mul`/`Edwards25519.mul` end their ladder
# with `try q.rejectIdentity()` — a genuine branch on a scalar-derived value
# (`edwards25519.zig`'s `pcMul16`, `if (p.x.isZero()) return
# error.IdentityElement;`).
#
# `modules/ct25519/src/ctgrind_harness.zig` is the program this drives: it
# taints a runtime scalar with `MAKE_MEM_UNDEFINED`, forces a volatile reload
# (so the optimizer cannot keep a defined register copy), then routes it
# through either `ct25519.mulRistrettoBase` (--target ct25519, what all nine
# of `voprf`'s secret-scalar call sites reduce to) or
# `std.crypto.ecc.Ristretto255.mul` (--target std, the negative control this
# module exists to replace), and finally prints the result through
# `std.debug.print` — deliberately NOT constant-time — as a propagation
# witness: a zero count in the code under test only means something if the
# taint demonstrably reached somewhere observable.
#
# ── the trap this script exists to not fall into ───────────────────────────
# `std.valgrind.doClientRequest` opens with
# `if (!builtin.valgrind_support) return default;`, and that flag is off by
# default outside Debug. A ReleaseFast binary built WITHOUT `-fvalgrind` is
# therefore a SILENT NO-OP under valgrind: `MAKE_MEM_UNDEFINED` never fires,
# so every row reads zero regardless of what the code does. This script
# builds the harness both ways and reports the no-switch row as its own line
# so that trap shows up as a measurement, not as an unstated assumption.
#
# Usage:
#     scripts/ctgrind-ct25519.sh
#
# Needs `valgrind` on PATH; the build goes through `scripts/capped`. Takes
# ~10s. Not part of `zig build test` — memcheck's context count is valgrind's
# own output, not something a Zig test can observe.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v valgrind >/dev/null 2>&1; then
    echo "ctgrind-ct25519: valgrind not found on PATH — install it or run this on a host that has it (no auto-install)." >&2
    exit 2
fi

HARNESS="modules/ct25519/src/ctgrind_harness.zig"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "Building harness (ReleaseFast, with and without -fvalgrind)..." >&2
scripts/capped zig build-exe "$HARNESS" -OReleaseFast -fno-strip -fvalgrind -femit-bin="$WORKDIR/vg_yes" >&2
scripts/capped zig build-exe "$HARNESS" -OReleaseFast -fno-strip -fno-valgrind -femit-bin="$WORKDIR/vg_no" >&2

# Count valgrind ERROR blocks whose stack contains $2, treating the blank
# "==pid==" separator lines memcheck prints between errors as paragraph
# breaks. Counting BLOCKS (not lines) matters: a single context's stack
# often names the target file on more than one frame (e.g. std's `pcMul16`
# AND its `mul` wrapper both live in `edwards25519.zig`), so a plain
# `grep -c` over lines double-counts relative to what "N contexts" means.
count_contexts_in() {
    local log="$1" pattern="$2"
    sed -E 's/^==[0-9]+==[[:space:]]*$//' "$log" \
        | awk -v RS='' -v pat="$pattern" 'BEGIN { c = 0 } $0 ~ pat { c++ } END { print c + 0 }'
}

# Runs one (binary, target, taint) combination under memcheck and prints
# "total_contexts|in_target_contexts|exit_code".
run_one() {
    local bin="$1" target="$2" taint="$3" file_pattern="$4"
    local log="$WORKDIR/log_$(basename "$bin")_${target}_${taint}.txt"
    set +e
    valgrind --tool=memcheck --error-exitcode=99 --num-callers=20 \
        "$bin" "$target" "$taint" >"$log" 2>&1
    local rc=$?
    set -e
    local total
    total=$(grep -oE 'errors from [0-9]+ contexts' "$log" | grep -oE '[0-9]+' | head -1 || true)
    total="${total:-0}"
    local in_target
    in_target=$(count_contexts_in "$log" "$file_pattern")
    echo "${total}|${in_target}|${rc}"
}

CT25519_FILE='root[.]zig'
STD_FILE='edwards25519[.]zig|ristretto255[.]zig|curve25519[.]zig'

declare -a ROWS

for target in ct25519 std; do
    if [[ "$target" == "ct25519" ]]; then file_pat="$CT25519_FILE"; label="ct25519/root.zig"; else file_pat="$STD_FILE"; label="std 25519"; fi

    r1=$(run_one "$WORKDIR/vg_yes" "$target" yes "$file_pat")
    ROWS+=("ReleaseFast|yes|yes|$target|$label|$r1|")

    r2=$(run_one "$WORKDIR/vg_yes" "$target" no "$file_pat")
    ROWS+=("ReleaseFast|yes|no|$target|$label|$r2|control")

    r3=$(run_one "$WORKDIR/vg_no" "$target" yes "$file_pat")
    ROWS+=("ReleaseFast|no|yes|$target|$label|$r3|trap")
done

printf '%-11s %-11s %-8s %-9s %-16s %8s %8s %5s\n' \
    "build" "-fvalgrind" "tainted" "target" "in" "total" "in-file" "exit"
printf '%s\n' "-----------------------------------------------------------------------------------"
for row in "${ROWS[@]}"; do
    IFS='|' read -r build vg taint target label total in_target rc note <<<"$row"
    printf '%-11s %-11s %-8s %-9s %-16s %8s %8s %5s %s\n' \
        "$build" "$vg" "$taint" "$target" "$label" "$total" "$in_target" "$rc" "$note"
done

echo
echo "Reproduce a single row directly, e.g. the claim itself:" >&2
echo "  scripts/capped zig build-exe $HARNESS -OReleaseFast -fno-strip -fvalgrind -femit-bin=/tmp/ct25519_ctgrind" >&2
echo "  valgrind --tool=memcheck --error-exitcode=99 /tmp/ct25519_ctgrind ct25519 yes" >&2
