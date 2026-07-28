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
    "$@" >"$out" 2>"$err" || rc=$?
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
