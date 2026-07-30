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
