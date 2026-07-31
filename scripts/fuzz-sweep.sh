#!/usr/bin/env bash
# First-ever coverage-guided fuzz sweep over zig-libs.
#
# `--fuzz` needs `--release=safe` (NOT `-Doptimize=ReleaseSafe`) — in Debug the
# test runner itself crashes. It then runs forever, so each module gets a fixed
# window and is killed.
#
#   exit 124  -> the window expired with no crash        = clean for that budget
#   exit 0    -> the module finished, i.e. it never entered the fuzz loop
#   anything  -> a real finding: the log is kept
#
# Everything runs through scripts/capped, so a runaway allocation is killed by
# its own cgroup instead of the machine.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$(cd "$SCRIPT_DIR/.." && pwd)"

BUDGET="${1:-40}"
OUT="${FUZZ_OUT:-${TMPDIR:-/tmp}/zig-libs-fuzz}"
mkdir -p "$OUT"
: > "$OUT/summary.tsv"
: > "$OUT/findings.txt"

# Modules that actually have a fuzz harness. Derived, never hardcoded, so
# the sweep cannot silently stop covering a module that grows one.
mapfile -t MODS < <(grep -rl 'testing\.fuzz(' modules/*/src/*.zig 2>/dev/null |
    sed 's|modules/||; s|/src/.*||' | sort -u)
total=${#MODS[@]}

# ⭐ WARM THE BUILD CACHE FIRST, or the budget is a lie. Each module's window
# is spent on `zig build`, COMPILE INCLUDED — so a module with a slow
# ReleaseSafe build gets a fraction of its nominal seconds actually fuzzing,
# and reports "clean" for a sweep that barely ran. Measured on `imap`: a
# planted 1-byte trigger was NOT found in 45s cold and WAS found within 60s
# once the build was cached.
#
# This is a different failure from NEVER-FUZZED below. That one catches a run
# that never reached the loop at all; it cannot see one that reached it with
# five seconds left, which looks identical to a clean result.
echo "warming $total ReleaseSafe builds so the budget is spent fuzzing, not compiling..."
warm_start=$(date +%s)
for m in "${MODS[@]}"; do
    ./scripts/capped zig build "test-$m" --release=safe > /dev/null 2>&1 ||
        echo "  warm FAILED: $m (its window will include a compile)"
done
echo "warmed in $(( $(date +%s) - warm_start ))s"
echo

i=0
for m in "${MODS[@]}"; do
    i=$((i + 1))
    log="$OUT/$m.log"
    start=$(date +%s)
    timeout "$BUDGET" ./scripts/capped zig build "test-$m" --fuzz --release=safe > "$log" 2>&1
    rc=$?
    dur=$(( $(date +%s) - start ))

    # ⭐ The EXIT CODE CANNOT BE THE SIGNAL. A fuzz crash is reported and the
    # build keeps running (the web server stays up), so `timeout` still kills it
    # with 124 — exactly as if nothing had been found. Verified by planting an
    # unconditional panic: full trace in the log, exit still 124. Detection has
    # to read the log.
    if grep -qE ' [0-9]+ crash|terminated with signal|thread [0-9]+ panic' "$log"; then
        verdict="FINDING"
    else
        # Did the module even REACH the fuzz loop? With a warm cache the only
        # thing before it is the module's own unit tests, and for a heavy module
        # those alone can outlast a short budget — which would otherwise be
        # recorded as "clean" while nothing was ever fuzzed.
        case $rc in
            124) if grep -q 'Build Summary' "$log"; then verdict="clean"; else verdict="NEVER-FUZZED"; fi ;;
            0)   verdict="NO-FUZZ-LOOP" ;;
            137) verdict="OOM-KILLED" ;;
            *)   verdict="EXIT-$rc" ;;
        esac
    fi

    # ⭐ PRESERVE THE CRASHING INPUT, not just the trace. The Zig fuzzer writes
    # it to .zig-cache/f/crash, and the NEXT module's run overwrites it — so a
    # sweep that kept only the log left a finding that could not be reproduced
    # except by fuzzing until it happened again. Worse, the traces are built in
    # ReleaseSafe and their line attribution is inlined-away: `json5`'s pointed
    # at a guarded expression and at a COMMENT line, so the input is the only
    # reliable evidence of what actually failed.
    if [[ "$verdict" == "FINDING" && -f .zig-cache/f/crash ]]; then
        cp .zig-cache/f/crash "$OUT/$m.crash-input"
        echo "  saved crashing input -> $OUT/$m.crash-input"
    fi

    printf '%s\t%s\t%s\t%s\n' "$m" "$rc" "$dur" "$verdict" >> "$OUT/summary.tsv"
    if [[ "$verdict" != "clean" ]]; then
        {
            echo "=== $m (exit $rc, ${dur}s, $verdict) ==="
            tail -40 "$log"
            echo
        } >> "$OUT/findings.txt"
    fi
    echo "[$i/$total] $m -> $verdict (${dur}s)"
done

echo
echo "=== SWEEP DONE ==="
awk -F'\t' '{c[$4]++} END {for (v in c) printf "%-14s %d\n", v, c[v]}' "$OUT/summary.tsv"
