#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# check-fp-freedom.sh — prove that `falcon`'s signing and key-generation paths
# contain no native, variable-latency floating-point instruction.
#
# WHY THIS EXISTS
# ---------------
# The first audit of `falcon` raised a HIGH: the reference sampler's secret-
# dependent arithmetic must not run on hardware FP, whose latency varies with
# operand values. The fix was `src/fpr.zig` — an integer emulation of the
# handful of double operations the signer needs (`add`, `mul`, `div`, `sqrt`,
# rounding), written so that every one is data-independent.
#
# Nothing guarded that fix. Replacing the body of `fpr.div` with a native `/`
# leaves the entire suite green and the KATs byte-exact, because the emulation
# is bit-for-bit identical to IEEE-754 — value tests CANNOT see the difference,
# which is the whole point of the emulation and also why no value test can
# defend it. `falcon` is not on the ctgrind gate either (it appears in neither
# `scripts/checks/ctgrind.sh` nor `scripts/checks/ctgrind-expected.tsv`), so the property was
# held in place by a paragraph of SPEC.md and by nothing else.
#
# SPEC.md did record an `objdump` run as evidence. A sentence describing a
# command someone ran once is not a gate: by the time it was re-run it had gone
# stale (it claimed the hits were confined to "exactly two functions"; there
# are four). This script is that sentence made executable.
#
# WHAT IT PROVES, AND WHAT IT DOES NOT
# ------------------------------------
# Proves: no variable-latency FP mnemonic reaches the compiled artifact outside
# test-only symbols. Does NOT prove: anything about branch structure or
# table-index structure in `gaussian0`/`berExp`/`sampler` — that is a different
# property and needs ctgrind, which `falcon` still does not have.

set -euo pipefail

cd "$(dirname "$0")/../.."

# Deliberately NOT ${TMPDIR}: this emits a ~6 MB binary, /tmp is tmpfs (RAM),
# and the repo rule puts build scratch a rebuild can reproduce in .zig-cache.
OUT=".zig-cache/check-fp-freedom"
mkdir -p "$OUT"
BIN="$OUT/falcon-rf"

# ReleaseFast on purpose: the shipping mode, and the one where a compiler is
# freest to rewrite the emulation back into hardware instructions.
# ⚠ `falcon`'s TEST dependencies have to be wired here too. This step compiles
# the module's test binary, so `build.zig`'s `test_deps` apply — and when
# falcon's fuzz corpus started importing `testkit` (2026-09-07), a bare
# `-Mroot=` failed with "no module named 'testkit' available within module
# 'root'". The gate is about the shipped floating-point surface, not about the
# dependency list, so it should follow whatever the module's tests need rather
# than force them to stay import-free.
zig test -femit-bin="$BIN" -OReleaseFast --test-no-exec \
    --dep testkit \
    -Mroot=modules/falcon/src/root.zig \
    -Mtestkit=modules/testkit/src/root.zig

# Scalar and AVX-encoded floating-point COMPUTE mnemonics. Moves
# (`movsd`/`movaps`) and XOR-zeroing (`vxorps`) are data-independent and
# deliberately not listed.
# POSIX ERE — no \s, no \b: `awk` treats those as plain letters and the check
# then matches nothing, which is how this was first written and why the
# vacuity guard below exists.
FP_RE='^[ \t]+[0-9a-f]+:[ \t]+v?(add|sub|mul|div|sqrt|round|ucomis|comis|cvtsi2s|cvttsd2si|cvttss2si|cvtsd2si|cvtss2si|max|min)(sd|ss|pd|ps)([ \t]|$)'

# Walk the disassembly, remembering the enclosing symbol, and report every
# offending (symbol, mnemonic) pair.
objdump -d --no-show-raw-insn "$BIN" \
| awk -v re="$FP_RE" '
    /^[0-9a-f]+ <.*>:$/ { sym = $2; gsub(/^</, "", sym); gsub(/>:$/, "", sym); next }
    $0 ~ re {
        mnem = $2
        print sym "\t" mnem
    }
' | sort -u > "$OUT/hits.tsv"

# A symbol is allowed to contain hardware FP only if it is a test — the `fpr`
# suite cross-checks the emulation against real hardware on purpose, which is
# exactly why the naive "no FP anywhere" form of this check cannot be used.
# Matching is anchored on Zig's mangled test-symbol shape.
ALLOW_RE='(^|[.])test[.]|test[.]"|[.]test$'

BAD=$(awk -F'\t' -v allow="$ALLOW_RE" '$1 !~ allow' "$OUT/hits.tsv" || true)

TOTAL=$(wc -l < "$OUT/hits.tsv")
ALLOWED=$(awk -F'\t' -v allow="$ALLOW_RE" '$1 ~ allow' "$OUT/hits.tsv" | wc -l)

echo "check-fp-freedom: $TOTAL (symbol, mnemonic) pairs carry hardware FP; $ALLOWED are in test symbols."

if [ -n "$BAD" ]; then
    echo
    echo "FAIL: hardware floating point reached a NON-TEST symbol in falcon."
    echo "Falcon's secret-dependent arithmetic must run on the integer emulation"
    echo "in modules/falcon/src/fpr.zig, whose whole purpose is that its timing"
    echo "does not depend on operand values."
    echo
    printf '%s\n' "$BAD" | sed 's/^/  /'
    exit 1
fi

# The allow-list must not be vacuously satisfied: if the disassembly yields no
# hits at all, something changed about how the binary is built (or objdump
# failed) and this gate would pass while proving nothing.
if [ "$TOTAL" -eq 0 ]; then
    echo "FAIL: no floating-point instruction found ANYWHERE, not even in the"
    echo "fpr hardware cross-check tests, which are supposed to contain some."
    echo "That means this gate is not looking at what it thinks it is."
    exit 1
fi

echo "check-fp-freedom: OK — every hardware FP instruction is confined to test symbols."
