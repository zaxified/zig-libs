#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""check-example-assert — an example may not check anything with `std.debug.assert`.

WHY THIS EXISTS
---------------
`build.zig` builds each module's example with `.optimize = optimize` — the
optimize mode of the whole run — and `scripts/test.sh` does not merely BUILD the
examples, it RUNS them (`run-examples`) "in this lane's optimize mode". One of
the documented lane shapes, spelled out at the top of `scripts/test.sh` itself,
is `-Doptimize=ReleaseFast`.

`std.debug.assert` is compiled out in `ReleaseFast`. So in a release lane every
assertion in every example evaporated, each example ran to completion, printed
its success lines, exited 0, and the step went green having checked nothing.
The step exists precisely because "compiling an example cannot see the class of
defect examples exist to find" (`build.zig`, at the `run-example-*` wiring) —
and in the release lane it degraded back to a compile, without saying so.

Measured across the collection on 2026-09-05: **593 `std.debug.assert` sites in
63 of the 230 examples.**

This is not a theoretical loss of coverage. A single `run-examples` pass on
2026-08-23 found a dangling slice in `btcp2p`, a leak in `ethfrag`, a union read
through the wrong tag in `iec104`, and 12 examples that had never been run at
all. For those 63 modules that detection power was zero in a release lane.

And the failure is worse than "the check did not run". Three examples compared
their output against an EXTERNAL oracle (`sealedbox` against libsodium,
`ripemd160` against `openssl dgst`, `bip340` against its reference vectors)
through `std.debug.assert`. In `ReleaseFast` those examples PRINTED that the
oracle agreed while no comparison happened — verified on `sealedbox` on
2026-09-05 by deliberately breaking a constant: the example still exited 0 and
still claimed the oracle matched. An example that asserts is not merely unheard
in release, it affirmatively states something untrue.

The estimate that preceded the measurement said "two modules". It was under by
a factor of thirty. That is the reason this is a gate and not a review note.

WHAT IT CHECKS
--------------
The literal text `std.debug.assert` must not appear anywhere under
`modules/*/example/`. Comments included, deliberately: the finding's own
evidence line is `rg 'std.debug.assert' modules/*/example/`, and a future
auditor re-running it must get zero rather than a screenful of prose about the
rule. Example doc comments say "a debug-only assert" instead; the API name is
spelled out here, in the one file whose subject it is.

THE REPLACEMENT
---------------
Each converted example carries a container-scope helper:

    fn must(ok: bool, src: std.builtin.SourceLocation) void {
        if (!ok) std.debug.panic("example check failed at {s}:{d}", .{ src.file, src.line });
    }

and every site reads `must(<the same condition>, @src());`. `std.debug.panic`
is present in every optimize mode, so the check is real in the lane that
ships; `@src()` is comptime and costs the reader nothing over the assert it
replaced. Where the enclosing function already returns an error union,
`if (!cond) return error.Something;` is equally good and some examples use it
(`jsonshape`, `testkit`) — what is forbidden is only the mechanism that
disappears.

⛔ WHAT IT DOES NOT DO
---------------------
* It does not look outside `modules/*/example/`. `std.debug.assert` inside a
  module's own `src/` is a different question with a different answer: there it
  documents an invariant the caller must not break, and Debug/ReleaseSafe
  builds enforce it. This gate takes no position on that use.
* It does not check that an example's checks are WORTH anything. `must(true,
  @src())` passes this gate. Only reading the example, or mutating the module
  under it, can say whether the condition discriminates — and the campaign that
  produced this gate found several examples whose checks could not fail.
* It does not see `unreachable`, `catch unreachable`, or a bare `if (x) {}`
  with an empty body — the other shapes that check nothing in release.
  `unreachable` in particular is UB in `ReleaseFast`, which is strictly worse
  than an assert, and one example (`jsonshape`) had it. A separate gate would
  be needed; this one anchors on a single unambiguous string.
* It does not run anything. An example that compiles, is gated by this, and is
  still never executed in any lane is a gap in `scripts/test.sh`, not here.
"""
import subprocess
import sys
from pathlib import Path

NEEDLE = "std.debug.assert"
REPLACEMENT = """    fn must(ok: bool, src: std.builtin.SourceLocation) void {
        if (!ok) std.debug.panic("example check failed at {s}:{d}", .{ src.file, src.line });
    }

then `must(<condition>, @src());` at the site, or, in a function that already
returns an error union, `if (!<condition>) return error.Something;`."""


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    examples = sorted(root.glob("modules/*/example/**/*.zig"))
    if not examples:
        print("check-example-assert: no modules/*/example/ sources found — "
              "run this from the repository, or the example layout has moved")
        return 1

    hits = []
    for path in examples:
        for n, line in enumerate(path.read_text().split("\n"), 1):
            if NEEDLE in line:
                hits.append((path.relative_to(root), n, line.strip()))

    if hits:
        for rel, n, text in hits:
            print(f"{rel}:{n}: {text}")
        print()
        print(f"{len(hits)} `{NEEDLE}` site(s) in {len({h[0] for h in hits})} example(s).")
        print()
        print("`scripts/test.sh` RUNS the examples in the lane's own optimize mode, and")
        print("`-Doptimize=ReleaseFast` compiles `std.debug.assert` out. In that lane the")
        print("example prints that it passed while checking nothing — and three examples")
        print("compared against an external oracle this way, so they printed that the")
        print("oracle agreed when no comparison had happened. Use a check that survives:")
        print()
        print(REPLACEMENT)
        return 1

    # A gate whose subject has vanished should say so rather than pass quietly:
    # if `modules/*/example/` ever stops being where examples live, the zero
    # above is about an empty set, not about a clean tree.
    n_helpers = subprocess.run(
        ["rg", "-l", "-e", r"fn must\(ok: bool, src: std\.builtin\.SourceLocation\)",
         str(root / "modules")], capture_output=True, text=True).stdout.split()
    print(f"check-example-assert: {len(examples)} example sources, no `{NEEDLE}`; "
          f"{len(n_helpers)} carry the surviving-check helper")
    return 0


if __name__ == "__main__":
    sys.exit(main())
