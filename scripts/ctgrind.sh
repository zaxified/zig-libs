#!/usr/bin/env bash
# ctgrind.sh — run every committed constant-time harness under
# valgrind/memcheck and print the full control table, instead of asserting a
# single number.
#
# Usage:
#     scripts/ctgrind.sh                    # every module with a harness
#     scripts/ctgrind.sh ct25519 ed448      # just these
#     scripts/ctgrind.sh --stacks ecvrf     # …and dump each row's memcheck log
#     scripts/ctgrind.sh --pattern 'root[.]zig' ecvrf
#                                           # …re-attribute the in-file column
#     scripts/ctgrind.sh --check            # compare against the expected table
#
# Needs `valgrind` on PATH; builds go through `scripts/capped`. Not part of
# `zig build test` — memcheck's context count is valgrind's own verdict, not
# something a Zig test can observe. What the gate DOES run is `zig build
# check-ctgrind`, which only compiles the harnesses so they cannot rot into
# unbuildable recipes. See `scripts/README.md` § Constant-time harnesses.
#
# ── the trap this script exists to not fall into ───────────────────────────
# `std.valgrind.doClientRequest` opens with
# `if (!builtin.valgrind_support) return default;`, and that flag is off by
# default outside Debug. A ReleaseFast binary built WITHOUT `-fvalgrind` is
# therefore a SILENT NO-OP under valgrind: `MAKE_MEM_UNDEFINED` never fires,
# so every row reads zero regardless of what the code does. Every (mode,
# target) triple below is printed as three rows — the claim, an UNTAINTED
# negative control, and a no-`-fvalgrind` trap — so a zero is only ever read
# next to the two rows that give it meaning.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

EXPECTED_FILE="$SCRIPT_DIR/ctgrind-expected.tsv"

# ── per-module configuration ───────────────────────────────────────────────
#
# TARGETS  — the harness's first argv, one entry per code path it can drive.
# MODES    — optimize modes worth measuring. ReleaseFast only, except
#            `chachapoly`, whose whole claim is that the property holds at
#            ReleaseFast and measurably NOT below it (its lane-parallel MAC
#            uses checked `*`/`+`, which Debug/ReleaseSafe lower to overflow
#            branches on secret-derived values). Everywhere else those same
#            safety checks merely flood the report — `ct25519` measured 89 956
#            errors from 1000 contexts at ReleaseSafe, valgrind's own
#            --error-limit cutoff — so the claim is stated for ReleaseFast.
# PATTERN  — regex selecting the frames whose file the claim is ABOUT. The
#            `--pattern` flag overrides it, which is how any attribution in a
#            SPEC.md can be re-checked rather than believed.
ALL_MODULES=(chachapoly ct25519 decaf448 ecvrf ed448 k256 montint)

declare -A TARGETS=(
    [chachapoly]="poly1305"
    [ct25519]="ct25519 std"
    [decaf448]="scalarmul"
    [ecvrf]="prove"
    [ed448]="full ladder"
    [k256]="field mul comb sign"
    [montint]="small portable asmcore"
)
declare -A MODES=(
    [chachapoly]="ReleaseFast ReleaseSafe Debug"
    [ct25519]="ReleaseFast"
    [decaf448]="ReleaseFast"
    [ecvrf]="ReleaseFast"
    [ed448]="ReleaseFast"
    [k256]="ReleaseFast"
    [montint]="ReleaseFast"
)
# Keyed "<module>/<target>".
declare -A PATTERN=(
    [chachapoly/poly1305]='poly1305[.]zig'
    [ct25519/ct25519]='root[.]zig'
    [ct25519/std]='edwards25519[.]zig|ristretto255[.]zig|curve25519[.]zig'
    [decaf448/scalarmul]='element[.]zig|ed448[.]zig|field[.]zig|scalar[.]zig'
    [ecvrf/prove]='ecvrf[.]zig'
    [ed448/full]='ed448[.]zig|field[.]zig|x448[.]zig|scalar[.]zig'
    [ed448/ladder]='ed448[.]zig|field[.]zig|scalar[.]zig'
    # k256's own sources. `fast_core.zig` is in the field/mul/comb/sign
    # patterns because `field_asm_active` routes every `Fe.mul`/`Fe.sq` into
    # its inline asm on amd64 — memcheck sees that block as ordinary machine
    # code, so its "zero branches" contract is measured, not assumed. `sign`
    # deliberately does NOT list `scalar[.]zig`: k256's scalar.zig is a bare
    # re-export of std's, whose file has the same basename, and lumping them
    # together would attribute std's secret-key canonicality check to k256.
    [k256/field]='field[.]zig|fast_core[.]zig'
    [k256/mul]='group[.]zig|field[.]zig|fast_core[.]zig'
    [k256/comb]='group[.]zig|field[.]zig|fast_core[.]zig'
    [k256/sign]='sign[.]zig|group[.]zig|field[.]zig|fast_core[.]zig'
    # montint: `montint.zig` is the portable CIOS + powMont, `asm_core.zig` the
    # gated amd64 core, `limbs.zig` the add/sub/select primitives underneath
    # both. All three are montint's own files; nothing in std shares a basename
    # with them.
    [montint/small]='montint[.]zig|limbs[.]zig|asm_core[.]zig'
    [montint/portable]='montint[.]zig|limbs[.]zig|asm_core[.]zig'
    [montint/asmcore]='montint[.]zig|limbs[.]zig|asm_core[.]zig'
)
declare -A LABEL=(
    [chachapoly/poly1305]='poly1305.zig'
    [ct25519/ct25519]='ct25519/root.zig'
    [ct25519/std]='std 25519'
    [decaf448/scalarmul]='decaf448+ed448'
    [ecvrf/prove]='ecvrf.zig'
    [ed448/full]='ed448 src'
    [ed448/ladder]='ed448 src'
    [k256/field]='k256 field+asm'
    [k256/mul]='k256 group+field'
    [k256/comb]='k256 group+field'
    [k256/sign]='k256 src'
    [montint/small]='montint src'
    [montint/portable]='montint src'
    [montint/asmcore]='montint src'
)

# ── arguments ──────────────────────────────────────────────────────────────
SHOW_STACKS=0
DO_CHECK=0
PATTERN_OVERRIDE=""
MODULES=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --stacks) SHOW_STACKS=1; shift ;;
        --check) DO_CHECK=1; shift ;;
        --pattern) PATTERN_OVERRIDE="${2:?--pattern needs a regex}"; shift 2 ;;
        -h|--help) sed -n '2,30p' "${BASH_SOURCE[0]}"; exit 0 ;;
        -*) echo "ctgrind: unknown flag $1" >&2; exit 2 ;;
        *) MODULES+=("$1"); shift ;;
    esac
done
if [[ ${#MODULES[@]} -eq 0 ]]; then MODULES=("${ALL_MODULES[@]}"); fi
for m in "${MODULES[@]}"; do
    [[ -n "${TARGETS[$m]:-}" ]] || { echo "ctgrind: no harness for module '$m'" >&2; exit 2; }
done

if ! command -v valgrind >/dev/null 2>&1; then
    echo "ctgrind: valgrind not found on PATH — install it or run this on a host that has it (no auto-install)." >&2
    exit 2
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# ── build ──────────────────────────────────────────────────────────────────
# One build per (mode, -fvalgrind) pair, covering every requested module.
MODFLAGS=()
for m in "${MODULES[@]}"; do MODFLAGS+=("-Dctgrind-module=$m"); done

needed_modes() {
    local out=()
    for m in "${MODULES[@]}"; do
        for mode in ${MODES[$m]}; do
            local seen=0
            for o in ${out[@]+"${out[@]}"}; do [[ "$o" == "$mode" ]] && seen=1; done
            [[ $seen -eq 0 ]] && out+=("$mode")
        done
    done
    printf '%s\n' ${out[@]+"${out[@]}"}
}

mapfile -t BUILD_MODES < <(needed_modes)
for mode in "${BUILD_MODES[@]}"; do
    for vg in true false; do
        echo "Building ctgrind harnesses ($mode, -fvalgrind=$vg)..." >&2
        scripts/capped zig build ctgrind \
            "-Doptimize=$mode" "-Dctgrind-valgrind=$vg" \
            "${MODFLAGS[@]}" -p "$WORKDIR/$mode-$vg" >&2
    done
done

# ── measurement ────────────────────────────────────────────────────────────
# Count valgrind ERROR blocks whose stack contains $2, treating the blank
# "==pid==" separator lines memcheck prints between errors as paragraph
# breaks. Counting BLOCKS (not lines) matters: a single context's stack often
# names the target file on more than one frame (e.g. std's `pcMul16` AND its
# `mul` wrapper both live in `edwards25519.zig`), so a plain `grep -c` over
# lines double-counts relative to what "N contexts" means.
count_contexts_in() {
    local log="$1" pattern="$2"
    sed -E 's/^==[0-9]+==[[:space:]]*$//' "$log" \
        | awk -v RS='' -v pat="$pattern" 'BEGIN { c = 0 } $0 ~ pat { c++ } END { print c + 0 }'
}

# Runs one (module, mode, valgrind-switch, target, taint) combination under
# memcheck and prints "total_contexts|in_target_contexts|exit_code|logpath".
run_one() {
    local module="$1" mode="$2" vg="$3" target="$4" taint="$5" file_pattern="$6"
    local bin="$WORKDIR/$mode-$vg/ctgrind/ctgrind-$module"
    local log="$WORKDIR/log_${module}_${mode}_${vg}_${target}_${taint}.txt"
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
    echo "${total}|${in_target}|${rc}|${log}"
}

ACTUAL="$WORKDIR/actual.tsv"
: >"$ACTUAL"

printf '%-11s %-11s %-11s %-8s %-10s %-16s %8s %8s %5s %s\n' \
    "module" "build" "-fvalgrind" "tainted" "target" "in" "total" "in-file" "exit" "note"
printf '%s\n' "--------------------------------------------------------------------------------------------------------"

for m in "${MODULES[@]}"; do
    for mode in ${MODES[$m]}; do
        for target in ${TARGETS[$m]}; do
            key="$m/$target"
            pat="${PATTERN_OVERRIDE:-${PATTERN[$key]}}"
            lbl="${LABEL[$key]}"
            [[ -n "$PATTERN_OVERRIDE" ]] && lbl="(--pattern)"
            for combo in "true yes " "true no control" "false yes trap"; do
                read -r vg taint note <<<"$combo"
                IFS='|' read -r total in_file rc log < <(run_one "$m" "$mode" "$vg" "$target" "$taint" "$pat")
                printf '%-11s %-11s %-11s %-8s %-10s %-16s %8s %8s %5s %s\n' \
                    "$m" "$mode" "$vg" "$taint" "$target" "$lbl" "$total" "$in_file" "$rc" "$note"
                printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                    "$m" "$mode" "$vg" "$taint" "$target" "$total" "$in_file" "$rc" >>"$ACTUAL"
                if [[ $SHOW_STACKS -eq 1 ]]; then
                    echo "----- $m $mode -fvalgrind=$vg taint=$taint target=$target -----"
                    cat "$log"
                    echo "----- end -----"
                fi
            done
        done
    done
done

[[ $DO_CHECK -eq 0 ]] && exit 0

# ── --check ────────────────────────────────────────────────────────────────
# Deliberately NOT a diff of exact totals. The `total` column includes the
# harness's own non-constant-time formatter and whatever std internals it
# reaches, so it moves with a zig or valgrind upgrade for reasons that say
# nothing about the module — and a check that goes red for the wrong reason
# gets muted, which is worse than no check. What is asserted is exactly what
# the claims rest on:
#
#   * every UNTAINTED control row is 0            (counts are taint-caused)
#   * every no-`-fvalgrind` trap row is 0         (the switch really is load-bearing)
#   * the claim row's in-file count EQUALS the expected value (0 for a module
#     claiming no secret-dependent branch; a stated small number where the
#     module documents which validations it keeps)
#   * the claim row's total is at least `total_min` (>0 wherever a propagation
#     witness is required, so a zero cannot mean "the taint never arrived")
echo
fail=0
while IFS=$'\t' read -r em emode etarget etotal_min ein_file; do
    [[ "$em" =~ ^# ]] && continue
    [[ -z "$em" ]] && continue
    line=$(awk -F'\t' -v m="$em" -v mo="$emode" -v t="$etarget" \
        '$1==m && $2==mo && $3=="true" && $4=="yes" && $5==t { print }' "$ACTUAL")
    if [[ -z "$line" ]]; then
        # Not measured in this invocation (a module subset was requested).
        continue
    fi
    IFS=$'\t' read -r _ _ _ _ _ total in_file _ <<<"$line"
    # `N` pins an exact count; `>=N` / `<=N` pin only the direction. Exact is
    # for the numbers a SPEC.md states as a fact about the module (ed448's
    # three `Fe.invert` validations, ecvrf's three try-and-increment
    # branches, and every claimed zero). A bound is for counts that a
    # compiler or std change legitimately moves — the ReleaseSafe/Debug
    # overflow-check floods, and std's own `rejectIdentity` context that
    # ct25519's negative control depends on merely EXISTING.
    case "$ein_file" in
        ">="*) if [[ "$in_file" -lt "${ein_file#>=}" ]]; then
                   echo "FAIL $em/$emode/$etarget: in-file contexts $in_file, expected $ein_file" >&2; fail=1
               fi ;;
        "<="*) if [[ "$in_file" -gt "${ein_file#<=}" ]]; then
                   echo "FAIL $em/$emode/$etarget: in-file contexts $in_file, expected $ein_file" >&2; fail=1
               fi ;;
        *) if [[ "$in_file" != "$ein_file" ]]; then
               echo "FAIL $em/$emode/$etarget: in-file contexts $in_file, expected $ein_file" >&2; fail=1
           fi ;;
    esac
    if [[ "$total" -lt "$etotal_min" ]]; then
        echo "FAIL $em/$emode/$etarget: total contexts $total < required minimum $etotal_min (propagation witness did not fire)" >&2
        fail=1
    fi
done <"$EXPECTED_FILE"

while IFS=$'\t' read -r am amode avg ataint atarget atotal _ _; do
    if [[ "$ataint" == "no" && "$atotal" != "0" ]]; then
        echo "FAIL $am/$amode/$atarget: untainted control reported $atotal contexts, expected 0" >&2
        fail=1
    fi
    if [[ "$avg" == "false" && "$atotal" != "0" ]]; then
        echo "FAIL $am/$amode/$atarget: no-fvalgrind trap reported $atotal contexts, expected 0" >&2
        fail=1
    fi
done <"$ACTUAL"

if [[ $fail -eq 0 ]]; then
    echo "ctgrind --check: OK (controls 0, traps 0, in-file counts as recorded in scripts/ctgrind-expected.tsv)"
else
    echo "ctgrind --check: FAILED — see above. Re-measure, then update scripts/ctgrind-expected.tsv AND the module's SPEC.md table together." >&2
fi
exit $fail
