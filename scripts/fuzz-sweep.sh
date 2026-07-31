#!/usr/bin/env bash
# First-ever coverage-guided fuzz sweep over zig-libs.
#
# `--fuzz` needs `--release=safe` (NOT `-Doptimize=ReleaseSafe`) — in Debug the
# test runner itself crashes. It then runs forever, so each module gets a fixed
# window and is killed.
#
#   exit 124  -> the window expired with no crash        = clean for that budget
#   exit 0    -> the module finished, i.e. it never entered the fuzz loop
#   exit 15   -> the cgroup OOM-killed it (see oomKilled below — NOT 137)
#   anything  -> a real finding: the log is kept
#
# Everything runs through scripts/capped, so a runaway allocation is killed by
# its own cgroup instead of the machine. NEVER run the fuzz command without it:
# outside a scope the kernel's GLOBAL oom-killer picks its victim by size, and
# under an IDE that victim is the editor. That is not hypothetical — it killed
# VS Code on 2026-07-31 during exactly this script's follow-up diagnosis.
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
#
# Naming modules after the budget restricts the run to those — the whole sweep
# is 2+ hours, which is too slow a loop to check a change to this script
# against. Every verdict path below was confirmed that way (see the OOM and
# NEVER-FUZZED notes), so keep the filter working.
mapfile -t ALL_MODS < <(grep -rl 'testing\.fuzz(' modules/*/src/*.zig 2>/dev/null |
    sed 's|modules/||; s|/src/.*||' | sort -u)
shift || true
if [[ $# -gt 0 ]]; then
    MODS=()
    for want in "$@"; do
        found=0
        for have in "${ALL_MODS[@]}"; do
            [[ "$have" == "$want" ]] && { MODS+=("$want"); found=1; break; }
        done
        (( found )) || echo "  skipping '$want': no testing.fuzz( harness in modules/$want/src/"
    done
    (( ${#MODS[@]} )) || { echo "no named module has a fuzz harness"; exit 2; }
else
    MODS=("${ALL_MODS[@]}")
fi
total=${#MODS[@]}

# ⭐ A CGROUP OOM-KILL REPORTS 15, NOT 137. `scripts/capped` runs the command
# under `systemd-run --user --scope`, and when the scope hits MemoryMax systemd
# terminates it and reports SIGTERM's 15 — so the obvious `137) OOM-KILLED`
# branch could never fire, and every runaway was filed as a generic EXIT-15.
# `dataset` sat in the results as an unexplained EXIT-15 until the kernel log
# was read; the script never said "out of memory" at all.
#
# 15 alone is not proof (a plain SIGTERM is also 15), so ask the kernel rather
# than infer: an OOM inside a scope logs `oom-kill:` with
# `constraint=CONSTRAINT_MEMCG` and a `run-p<pid>` memcg. When journalctl is
# unavailable the answer is "unknown", never a false "clean".
oomKilled() { # $1 = epoch seconds the run started
    journalctl --since "@$1" --no-pager -k 2>/dev/null |
        grep -qE 'oom-kill:.*CONSTRAINT_MEMCG.*run-p[0-9]+'
}

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

# ⭐ THE BUDGET IS PER MODULE, because the fuzz loop does not start until the
# module's own unit tests have finished. `http` and `threshold_ecdsa` both came
# back NEVER-FUZZED at 45s: their suites alone outlast the whole window, so a
# single global number cannot give every module the same amount of FUZZING.
#
# Rather than hardcode exceptions that rot as suites grow, measure it. The warm
# pass above has already cached each build, so a second run times the unit
# tests alone — the exact quantity being subtracted from the budget — and each
# module's window becomes BUDGET + that. A module whose suite grows past its
# window fixes itself on the next sweep.
declare -A PRETIME
echo "measuring each suite's own runtime (the part that is not fuzzing)..."
for m in "${MODS[@]}"; do
    t0=$(date +%s)
    ./scripts/capped zig build "test-$m" --release=safe > /dev/null 2>&1
    PRETIME[$m]=$(( $(date +%s) - t0 ))
done
slow=$(for m in "${MODS[@]}"; do printf '%s\t%s\n' "${PRETIME[$m]}" "$m"; done |
    sort -rn | awk -v b="$BUDGET" '$1 * 2 >= b {printf "%s(%ss) ", $2, $1}')
[[ -n "$slow" ]] && echo "  suites eating a big share of a ${BUDGET}s budget: $slow"
echo

i=0
for m in "${MODS[@]}"; do
    i=$((i + 1))
    log="$OUT/$m.log"
    window=$(( BUDGET + ${PRETIME[$m]:-0} ))
    start=$(date +%s)
    timeout "$window" ./scripts/capped zig build "test-$m" --fuzz --release=safe > "$log" 2>&1
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
            15)  if oomKilled "$start"; then verdict="OOM-KILLED"; else verdict="EXIT-15-SIGTERM"; fi ;;
            *)   verdict="EXIT-$rc" ;;
        esac
    fi

    # An OOM is a finding about the module, not a flaw in the run: something
    # sized an allocation from input it had not bounded. Say so where it will
    # be read, next to the trace, instead of leaving a bare exit code.
    if [[ "$verdict" == "OOM-KILLED" ]]; then
        echo "  OOM: killed by its cgroup after ${dur}s — an allocation was sized from unbounded input" >> "$log"
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

    printf '%s\t%s\t%s\t%s\t%s\n' "$m" "$rc" "$dur" "$verdict" "window=${window}s(suite ${PRETIME[$m]:-?}s)" >> "$OUT/summary.tsv"
    if [[ "$verdict" != "clean" ]]; then
        {
            echo "=== $m (exit $rc, ${dur}s, $verdict) ==="
            tail -40 "$log"
            echo
        } >> "$OUT/findings.txt"
    fi
    echo "[$i/$total] $m -> $verdict (${dur}s of ${window}s)"
done

echo
echo "=== SWEEP DONE ==="
awk -F'\t' '{c[$4]++} END {for (v in c) printf "%-14s %d\n", v, c[v]}' "$OUT/summary.tsv"
