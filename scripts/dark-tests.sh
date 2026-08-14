#!/usr/bin/env bash
# Find tests that exist on disk but never run — "dark" tests.
#
# In Zig a re-export (`pub const frame = @import("frame.zig");`) does NOT pull
# that file's tests into the test binary. Something must REFERENCE a decl of
# that file from code the test binary analyses — the usual forms being a
# `test { _ = frame; }` aggregator or `std.testing.refAllDecls(@This())`.
#
# When nothing does, the file's tests are dark: never compiled, never run, and
# **invisible**. A suite total counts the tests that ran, so missing tests do
# not show up as a failure, a skip, or a warning. `websocket` shipped this way
# and ran ZERO of its 52 tests — one of which did not even compile. Later
# `ratelimit/src/conn.zig` was reachable only through `pub const` aliases and
# `zig build test-ratelimit` reported `18/18 passed`, exit 0, with an entire
# new suite absent.
#
# ⭐ WHY THIS IS A SCRIPT AND NOT A `check-catalog` RULE. A static check was
# tried first and abandoned: it flagged `ebpf`, `jwe` and `conntrack`, all three
# false. Zig pulls a file in on ANY reference to any of its decls — through a
# re-export chain (`pub const ecdhes = alg.ecdhes;`), or from inside an ordinary
# named test that merely touches a re-exported constant. Recognising that
# statically means reimplementing semantic analysis. Asking the compiler what it
# actually ran is exact, and the only cost is time.
#
# ─────────────────────────────────────────────────────────────────────────────
# ⭐ WHAT IS COMPARED, AND WHY IT IS EXACT EQUALITY
#
# The run side is the `(N total)` field of the build summary's run-test line,
# NOT the pass count:
#
#     +- run test 41 pass (41 total) 9ms MaxRSS:5M
#     +- run test 38 pass 3 skipped (41 total) 12ms MaxRSS:5M
#
# The pass count is what the previous version of this script read, and it is the
# wrong quantity: a module with skips looks permanently short, so a genuinely
# dark file inside such a module disappears into that noise. `(N total)` is the
# number of test declarations the binary was built from, which is exactly what
# the disk count is trying to predict, so the two can be required to be EQUAL.
# A ratio threshold cannot express that — `ratelimit` had 21 on disk and 18
# running, nowhere near "less than half", so the old `disk/2` rule passed it.
#
# The disk side is `^test ` over every `.zig` file under `modules/<m>/src`,
# RECURSIVELY. Both halves of that are load-bearing:
#
#   * `^test ` is EXACT here, not an upper bound. Zig has no block comments, a
#     `//` comment cannot start at column 0 with the word `test`, every line of
#     a multi-line string literal starts with `\\`, and a test declaration is a
#     container-level declaration, which `zig fmt` puts at column 0. The gate
#     runs `zig fmt --check` over `modules`, so the formatting premise is
#     enforced, not assumed. Verified over the whole tree: no indented `test "`
#     or `test {` declaration exists, and no `^test ` line is anything but a
#     declaration. Exact equality needs an exact declared count, so this is a
#     precondition of the rule, not a nicety.
#   * RECURSIVE, because `src/*.zig` is not the whole module:
#     `modules/protobuf/src/testdata/golden_bytes.zig` is `@import`ed by
#     `golden_test.zig` and is therefore as much a part of the compilation as
#     any top-level file. It happens to hold no tests today; a non-recursive
#     count would silently stop covering it the day it does.
#
# A module MAY legitimately own `.zig` sources under `src/` that its own
# compilation never analyses — a generator input, a fixture written in Zig but
# consumed as text. Nothing in the tree does today (measured 2026-08-11 across
# every module in the collection: declared == `(N total)`), so rather than weaken the
# rule for a hypothesis, such a module gets an explicit row in DECLARED_EXEMPT
# below, with the count and the reason written down. Silence is the thing to
# avoid: an unexplained shortfall must not be indistinguishable from a dark file.
#
# ─────────────────────────────────────────────────────────────────────────────
# COST, AND WHY THE GATE DOES NOT CALL THE DEFAULT MODE
#
# Zig does NOT cache test *run* steps. Measured on this repo: the same
# `zig build test-bech32 test-decimal … --summary all` takes 13.3 s twice in a
# row, with `compile test … cached` and the run steps re-executing every time.
# So "run every module's suite again to count its tests" costs a second full
# test run — it would roughly double `scripts/test.sh all`.
#
# The summary the gate needs is already printed by the gate's own run, so
# `scripts/test.sh` passes `--summary all`, keeps that output, and hands it here
# with `--summary <file>`. That mode reads a log and runs nothing, so the check
# costs milliseconds. The default mode (build it myself) exists for running this
# by hand and for `zig build check-dark-tests`; it is honest work, not a cache
# hit, and it is deliberately NOT what the gate invokes.
#
#   usage:
#     scripts/dark-tests.sh [module...]              build + check (default: all)
#     scripts/dark-tests.sh --summary FILE [mod...]  check an existing
#                                                    `--summary all` build log
#
# With `--summary`, any module names given are the set the log is REQUIRED to
# account for: a module that produced no run-test line at all is a failure, not
# a module to quietly skip. Without them, whatever the log contains is checked.
#
# Exit 1 if any module's run total differs from its declared count.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/test-lib.sh"
cd "$REPO_ROOT"

# Modules that own `.zig` sources under `src/` which their own compilation
# deliberately does not analyse. One row per module:
#
#     <module>|<declared tests not compiled>|<reason>
#
# EMPTY ON PURPOSE, and that is a measurement rather than an assumption: as of
# 2026-08-11 every module in the collection satisfied declared == `(N total)`
# exactly. ⚠ Modules have been added since, and this sentence does not cover
# them — the gate recomputes live per run, so a green run is the current claim
# and this date is only when the table was last known to be complete. A row here
# is a claim that must be justified in its reason field; adding one to silence a
# red gate without understanding why the count moved is the failure mode this
# whole script exists to prevent.
DECLARED_EXEMPT=""

summary_file=""
if [[ ${1:-} == "--summary" ]]; then
    summary_file="${2:-}"
    [[ -n "$summary_file" ]] || { echo "dark-tests: --summary needs a file" >&2; exit 2; }
    [[ -r "$summary_file" ]] || { echo "dark-tests: cannot read '$summary_file'" >&2; exit 2; }
    shift 2
fi

mods=("$@")

# ── produce the build summary ────────────────────────────────────────────────
if [[ -z "$summary_file" ]]; then
    if [[ ${#mods[@]} -eq 0 ]]; then
        mapfile -t mods < <(zig build module-graph 2>/dev/null | cut -f1)
    fi
    [[ ${#mods[@]} -eq 0 ]] && { echo "dark-tests: no modules — is 'zig build module-graph' working?" >&2; exit 1; }

    # Same plain/netns partition scripts/test.sh uses, from the same list, for
    # the same reason: `zig build test-netlink` on a bare dev host FAILS rather
    # than skipping, and a module whose build failed produces no count line.
    plain=(); netns=()
    for m in "${mods[@]}"; do
        case " $NETNS_MODULES " in
            *" $m "*) netns+=("test-$m") ;;
            *) plain+=("test-$m") ;;
        esac
    done

    summary_file="$(mktemp)"
    trap 'rm -f "$summary_file"' EXIT
    if [[ ${#plain[@]} -gt 0 ]]; then
        "$SCRIPT_DIR/capped" zig build "${plain[@]}" --summary all >>"$summary_file" 2>&1
    fi
    if [[ ${#netns[@]} -gt 0 ]]; then
        if command -v unshare >/dev/null 2>&1 && unshare -rn true >/dev/null 2>&1; then
            "$SCRIPT_DIR/capped" unshare -rn zig build "${netns[@]}" --summary all >>"$summary_file" 2>&1
        else
            "$SCRIPT_DIR/capped" zig build "${netns[@]}" --summary all >>"$summary_file" 2>&1
        fi
    fi
fi

# ── parse the summary ────────────────────────────────────────────────────────
# Top-level step lines sit at column 0 (`test-bech32 success`); everything below
# them is indented or starts with `+-`. A step's run-test lines are the ones
# between it and the next column-0 step line. They are SUMMED rather than
# head -1'd: nothing in build.zig produces two test binaries for one module
# today (one `addTest` + one `addRunArtifact` per module), but a `head -1` would
# under-count silently the day something does, and under-counting here reads as
# "dark".
#
# Note both fields are taken from the same line, so a module that is red for an
# ordinary reason (`run test 40 pass 1 failed (41 total)`) still reports its
# correct total; this check is about presence, not about passing.
ran_tsv="$(awk '
    /^test-[^ ]+ / { mod = substr($1, 6); seen[mod] = 1; next }
    mod != "" && /run test / && match($0, /\([0-9]+ total\)/) {
        # RLENGTH spans "(" + digits + " total)", i.e. digits = RLENGTH - 8.
        total[mod] += substr($0, RSTART + 1, RLENGTH - 8)
        lines[mod] += 1
    }
    END { for (m in seen) printf "%s\t%d\t%d\n", m, total[m], lines[m] }
' "$summary_file")"

lookup_ran() { awk -F'\t' -v m="$1" '$1 == m { print $2; found = 1 } END { if (!found) print "-" }' <<< "$ran_tsv"; }
lookup_lines() { awk -F'\t' -v m="$1" '$1 == m { print $3 }' <<< "$ran_tsv"; }

# One row per line, `<module>|<count>|<reason>`; the reason may contain spaces,
# so this reads LINES rather than word-splitting.
exempt_for() {
    local m="$1" row rest
    while IFS= read -r row; do
        [[ -z "$row" ]] && continue
        [[ "${row%%|*}" == "$m" ]] || continue
        rest="${row#*|}"
        printf '%s' "${rest%%|*}"
        return
    done <<< "$DECLARED_EXEMPT"
    printf '0'
}

# Which modules to judge: the ones asked for, else the ones the log mentions.
if [[ ${#mods[@]} -eq 0 ]]; then
    mapfile -t mods < <(cut -f1 <<< "$ran_tsv" | LC_ALL=C sort)
fi
[[ ${#mods[@]} -eq 0 ]] && { echo "dark-tests: the build summary named no test step — was it produced with --summary all?" >&2; exit 1; }

bad=0
multi=0
for m in "${mods[@]}"; do
    [[ -z "$m" ]] && continue
    disk=$(find "modules/$m/src" -type f -name '*.zig' -exec grep -hc '^test ' {} + 2>/dev/null |
        awk '{ s += $1 } END { print s + 0 }')
    ran=$(lookup_ran "$m")
    n_lines=$(lookup_lines "$m")
    [[ ${n_lines:-0} -gt 1 ]] && multi=$((multi + 1))
    exempt=$(exempt_for "$m")

    if [[ "$ran" == "-" ]]; then
        echo "NO RESULT  $m — $disk test block(s) on disk, but the build summary has no \`run test … (N total)\` line for step test-$m. Either the step was never requested, or its suite did not run."
        bad=$((bad + 1))
        continue
    fi

    want=$((disk - exempt))
    if [[ $ran -ne $want ]]; then
        if [[ $ran -lt $want ]]; then
            echo "DARK       $m — $disk test block(s) on disk$( [[ $exempt -gt 0 ]] && echo " ($exempt exempt)"), $ran ran. $((want - ran)) test(s) are in files nothing references. Add a \`test { _ = <file>; }\` aggregator to modules/$m/src/root.zig (see modules/bech32/src/root.zig)."
        else
            echo "OVER-COUNT $m — $disk test block(s) on disk$( [[ $exempt -gt 0 ]] && echo " ($exempt exempt)"), $ran ran. More tests ran than are declared: the run side is right and the disk count is wrong, so fix the count here, do not add an exemption."
        fi
        bad=$((bad + 1))
    fi
done

echo
echo "dark-tests: checked ${#mods[@]} module(s), $bad violation(s)$( [[ $multi -gt 0 ]] && echo ", $multi with more than one run-test line (summed)")"
[[ $bad -eq 0 ]] || exit 1
