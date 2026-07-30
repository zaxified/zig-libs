#!/usr/bin/env bash
# Find modules whose tests never run.
#
# In Zig a re-export (`pub const frame = @import("frame.zig");`) does NOT pull
# that file's tests into the test binary. Something must REFERENCE a decl of
# that file from code the test binary analyses — the usual forms being a
# `test { _ = frame; }` aggregator or `std.testing.refAllDecls(@This())`.
#
# When nothing does, the file's tests are dark: never compiled, never run, and
# **invisible**. A suite total counts the tests that ran, so missing tests do
# not show up as a failure, a skip, or a warning. `websocket` shipped this way
# and ran ZERO of its 52 tests — one of which did not even compile.
#
# ⭐ WHY THIS IS A SCRIPT AND NOT A `check-catalog` RULE. A static check was
# tried first and abandoned: it flagged `ebpf`, `jwe` and `conntrack`, all three
# false. Zig pulls a file in on ANY reference to any of its decls — through a
# re-export chain (`pub const ecdhes = alg.ecdhes;`), or from inside an ordinary
# named test that merely touches a re-exported constant. Recognising that
# statically means reimplementing semantic analysis. Asking the compiler what it
# actually ran is exact, and the only cost is time.
#
#   usage: scripts/dark-tests.sh [module...]     (default: every module)
#
# Exit 1 if any module runs zero tests while its sources hold test blocks.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

if [[ $# -gt 0 ]]; then
    mods=("$@")
else
    mapfile -t mods < <(zig build module-graph 2>/dev/null | cut -f1)
fi
[[ ${#mods[@]} -eq 0 ]] && { echo "dark-tests: no modules — is 'zig build module-graph' working?" >&2; exit 1; }

dark=0
short=0
for m in "${mods[@]}"; do
    # Test blocks present in the sources. An upper bound, not an exact count:
    # `test` in a comment or a string inflates it, which is why a SHORTFALL is
    # only reported, while zero-ran is the hard failure.
    disk=$(cat "modules/$m/src"/*.zig 2>/dev/null | grep -c '^test ')
    ran=$(./scripts/capped zig build "test-$m" --summary all 2>&1 |
        grep -oE 'run test [0-9]+ pass' | grep -oE '[0-9]+' | head -1)
    ran=${ran:-0}

    if [[ $disk -gt 0 && $ran -eq 0 ]]; then
        echo "DARK    $m — $disk test block(s) on disk, 0 ran. Add a \`test { _ = <file>; }\` aggregator to modules/$m/src/root.zig (see modules/bech32/src/root.zig)."
        dark=$((dark + 1))
    elif [[ $disk -gt 0 && $ran -lt $((disk / 2)) ]]; then
        echo "SHORT   $m — $disk on disk, $ran ran. Worth a look."
        short=$((short + 1))
    fi
done

echo
echo "checked ${#mods[@]} module(s): $dark dark, $short short"
[[ $dark -eq 0 ]] || exit 1
