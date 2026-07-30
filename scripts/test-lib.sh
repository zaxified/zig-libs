# Shared helpers for test.sh. Sourced; not executable on its own.
#
# Style note: no `declare -A` anywhere in these scripts, on purpose — macOS
# ships bash 3.2 (no associative arrays), where `declare -A` evaluates the
# key as arithmetic and errors out. "Sets" of module names are represented
# as space-padded strings (" a b c ") and tested with a `case " $s " in`
# glob, which works on any bash. See bxp/scripts/test-lib.sh for the sibling
# implementation this one is patterned after.

# Sub-second timing via bash 5+ EPOCHREALTIME; fall back to whole seconds.
# EPOCHREALTIME honours the locale's decimal point (e.g. "1.234,56" in
# cs_CZ), which awk would parse as an integer — normalise comma -> period.
if [[ -n "${EPOCHREALTIME-}" ]]; then
    _now() { local v="$EPOCHREALTIME"; printf '%s\n' "${v//,/.}"; }
else
    _now() { date +%s; }
fi

: "${ZIGLIBS_TEST_T0:=}"

_ZL_LINE_W=70
_ZL_OK_COL=61   # column where the "O" of OK lands

# ── memory cap ────────────────────────────────────────────────────────────
# Every command `step` runs goes inside a transient cgroup with a hard memory
# limit, so a runaway test is killed by ITS OWN cgroup's OOM killer. Without
# this the kernel's global OOM killer chooses instead, and it picks by size —
# on a dev box that is the editor, not the 200-line test that caused it. This
# host has no swap, so there is no soft landing: the global killer fires within
# seconds of the limit being crossed.
#
# A test that exceeds the cap therefore shows up as one red step (SIGKILL,
# exit 137) rather than as a dead desktop. Set ZIGLIBS_MEM_MAX to another
# systemd size (e.g. 24G) to raise it, or to "off" to disable the wrapper.
#
# The 12G default is measured, not guessed: a full `zig build test` over every
# module peaks at 4.1 GiB for the WHOLE parallel build (largest single test
# binary: 115 MB MaxRSS). So the default leaves ~3x headroom over a legitimate
# full run while still catching the kind of runaway that motivated this — a
# test binary at 15.4 GB RSS. Re-measure before lowering it; the ReleaseFast
# lane compiles through LLVM and is heavier per process than the Debug lane
# this figure comes from.
#
# Requires cgroup v2 with the `memory` controller delegated to the user
# manager — true under any modern systemd, and probed for below rather than
# assumed, so this degrades to a plain exec on hosts (macOS, CI containers,
# non-systemd Linux) that cannot do it.
# Probed once (a systemd-run round trip is not free); the LIMIT is read per
# step, so ZIGLIBS_MEM_MAX can be changed after this file is sourced.
_ZL_CAP_OK=0
if command -v systemd-run >/dev/null 2>&1 &&
    systemd-run --user --scope -q --collect -- true >/dev/null 2>&1; then
    _ZL_CAP_OK=1
fi

# Populates _ZL_CAP with the wrapper argv for the current limit, or empties
# it. An array, not an echoed string, so nothing is ever word-split.
_ZL_CAP=()
_zl_cap_argv() {
    _ZL_CAP=()
    local max="${ZIGLIBS_MEM_MAX:-12G}"
    [[ $_ZL_CAP_OK -eq 1 && "$max" != "off" ]] || return 0
    _ZL_CAP=(systemd-run --user --scope -q --collect
        -p "MemoryMax=$max" -p MemorySwapMax=0 --)
}

# section "changed"  ->  "\nchanged ────────────────────────────────────"
section() {
    local title="$1"
    local head="$title "
    local pad=$(( _ZL_LINE_W - ${#head} ))
    (( pad < 3 )) && pad=3
    echo
    printf '%s' "$head"
    printf '─%.0s' $(seq 1 $pad)
    echo
}

# step "label" cmd args...
# Runs cmd, capturing stdout and stderr SEPARATELY. On success with empty
# stderr, prints "  <label> .... OK   X.Xs". Any stderr is treated as a real
# problem even when the command exits 0 — a module's tests are silent by
# default (ZIG_LIBS_VERBOSE_SKIP=0), so stderr output here means something
# unexpected printed (a stray debug print, a warning, a forgotten verbose
# skip) — the run is downgraded to FAIL and both streams are replayed.
# On a genuine nonzero exit, replays both streams and exits with that code.
step() {
    local label="$1"; shift
    local out err
    out=$(mktemp)
    err=$(mktemp)
    local t0 t1 dur rc=0
    t0=$(_now)
    # ${arr[@]+"${arr[@]}"} — expands to nothing when _ZL_CAP is empty, on
    # bash 3.2 too, where a bare "${arr[@]}" on an empty array is an error.
    _zl_cap_argv
    ${_ZL_CAP[@]+"${_ZL_CAP[@]}"} "$@" >"$out" 2>"$err" || rc=$?
    t1=$(_now)
    dur=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.1f", b-a}')

    if [[ $rc -eq 0 && ! -s "$err" ]]; then
        local dots_n=$(( _ZL_OK_COL - 5 - ${#label} ))
        (( dots_n < 3 )) && dots_n=3
        local dots
        dots=$(printf '.%.0s' $(seq 1 $dots_n))
        printf '  %s %s OK %6ss\n' "$label" "$dots" "$dur"
        rm -f "$out" "$err"
        return 0
    fi

    if [[ $rc -eq 0 ]]; then
        # Exit 0 but stderr wrote something — treat as a failure so it can
        # never pass silently in CI or a work loop.
        rc=1
        echo "  $label ... OK-but-stderr -> treated as FAIL (${dur}s)"
    else
        echo "  $label ... FAIL (${dur}s)"
    fi
    if [[ $rc -eq 137 && $_ZL_CAP_OK -eq 1 ]]; then
        # 137 = SIGKILL. Inside the cap that is nearly always the cgroup OOM
        # killer, and the raw number tells you nothing on its own.
        echo "  -> SIGKILL: almost certainly exceeded ZIGLIBS_MEM_MAX=${ZIGLIBS_MEM_MAX:-12G}."
        echo "     Shrink the test's footprint; raise the cap only if it is genuinely that large."
    fi
    echo
    if [[ -s "$out" ]]; then
        echo "--- stdout ---" >&2
        cat "$out" >&2
    fi
    if [[ -s "$err" ]]; then
        echo "--- stderr ---" >&2
        cat "$err" >&2
    fi
    rm -f "$out" "$err"
    exit "$rc"
}

# Bottom rule + total wall time. No-op if ZIGLIBS_TEST_T0 was never set.
summary() {
    [[ -z "$ZIGLIBS_TEST_T0" ]] && return 0
    local t1 total
    t1=$(_now)
    total=$(awk -v a="$ZIGLIBS_TEST_T0" -v b="$t1" 'BEGIN{printf "%.1f", b-a}')
    echo
    printf '─%.0s' $(seq 1 $_ZL_LINE_W)
    echo
    local left='  Total'
    local right="${total}s"
    local pad=$(( _ZL_LINE_W - ${#left} - ${#right} ))
    (( pad < 1 )) && pad=1
    printf '%s%*s%s\n' "$left" $pad '' "$right"
}
