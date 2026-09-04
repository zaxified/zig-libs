#!/usr/bin/env python3
"""check-skip-as-pass — a test that decides to skip must actually skip.

WHY THIS EXISTS
---------------
`zig test` counts a plain `return;` as a PASS. So the shape

    if (verboseSkip()) std.debug.print("... SKIPPED: no socket ...", .{});
    return;

reports the test as *passing* while printing that it did not run. `testkit.skip`
was written to replace exactly that pattern — its own doc comment says so — and
the first audit of `testkit` (2026-09-04) found **11 instances still in the
tree**, across nftables, ebpf and bacnet. Measured on one of them beforehand:

    $ ZIG_LIBS_VERBOSE_SKIP=1 zig build test-nftables -Dtest-filter=…
    JSON<->native consistency test SKIPPED: the kernel refused the batch
    Build Summary: 3/3 steps succeeded; 2/2 tests passed

It prints SKIPPED and is counted as a pass. After the fix the same command
reports `1 pass, 1 skip`, and the whole module went from 94 passing to
`90 pass, 4 skip`. `scripts/test.sh`'s skip line — whose own header says it
"MATTERS MORE THAN THE TIMES" — had nothing to count, so a host that cannot run
a privileged test reported full coverage.

WHAT IT CHECKS — two shapes, both measured in the wild
------------------------------------------------------
1. Inside a `test` block that calls `verboseSkip()`, a statement that is exactly
   `return;`. Eight of the eleven had this form.
2. A *helper* function that calls `verboseSkip()` and has a `return null;` in the
   same body. That is how the other three hid: `liveSocket` printed "SKIPPED"
   and returned `null`, and three tests wrote `liveSocket(…) orelse return;` —
   the decision and the swallowed return lived in different functions, so a
   test-block-scoped rule cannot see it. Such a helper should return an error
   union and `return testkit.skip(…)`.

⛔ WHAT IT CANNOT SEE
--------------------
A skip that never announces itself. A silent `return;` on a missing
precondition is the same defect and this gate is blind to it by construction —
it anchors on `verboseSkip`, which is the only machine-readable marker the
convention gives it. It also does not look at `example/` code, where "skipped"
in a message usually describes the DATA, not the test.
"""
import re
import subprocess
import sys
from pathlib import Path

NEAR = 8  # lines: how close the skip announcement must be to the return
TEST_RE = re.compile(r'\s*test\s+["\w]')
BARE_RETURN_RE = re.compile(r'^\s*return;\s*$')
RETURN_NULL_RE = re.compile(r'^\s*return null;\s*$')
FN_RE = re.compile(r'^\s*(pub\s+)?fn\s+(\w+)')


def blocks(lines, start_re):
    """Yield (header_index, [(lineno, text), …]) for each brace-balanced block."""
    for i, line in enumerate(lines):
        if not start_re.match(line):
            continue
        depth, started, body = 0, False, []
        for j in range(i, len(lines)):
            depth += lines[j].count("{") - lines[j].count("}")
            body.append((j + 1, lines[j]))
            if lines[j].count("{"):
                started = True
            if started and depth <= 0:
                break
        yield i, body


def main() -> int:
    out = subprocess.run(
        ["rg", "-l", "verboseSkip", "modules"], capture_output=True, text=True
    ).stdout.split()
    files = [f for f in out if f.endswith(".zig") and "/example/" not in f and "/testkit/" not in f]

    hits = []
    for f in files:
        lines = Path(f).read_text().split("\n")
        for _, body in blocks(lines, TEST_RE):
            text = "\n".join(t for _, t in body)
            if "verboseSkip" not in text:
                continue
            # The anti-pattern is ADJACENT: announce the skip, then return.
            # A bare `return` far from any skip decision is an ordinary early
            # exit — `snmp`'s live test returns after proving the USM exchange
            # when the agent's VACM policy denies the rest, and calling that a
            # skip would erase what it did verify. Anchor on the neighbourhood,
            # not on the block.
            for idx, (ln, t) in enumerate(body):
                if not BARE_RETURN_RE.match(t):
                    continue
                near = "\n".join(x[1] for x in body[max(0, idx - NEAR):idx])
                if "verboseSkip" in near:
                    hits.append((f, ln, "a test announces a skip and then returns plainly, which is a PASS"))
        for _, body in blocks(lines, FN_RE):
            text = "\n".join(t for _, t in body)
            if "verboseSkip" not in text:
                continue
            for ln, t in body:
                if RETURN_NULL_RE.match(t):
                    hits.append((f, ln, "a helper announces a skip and returns null; its callers' `orelse return` is a PASS"))

    # The env-var NAME is held by convention alone: `testkit` declares it,
    # `scripts/test-lib.sh` and the docs spell it out, and nothing connects the
    # two. Renaming the constant would silently disconnect every skip
    # diagnostic in the collection from the variable operators actually set.
    # A grep is not circular here, because the two spellings live in different
    # languages in different trees.
    declared = re.search(
        r'verbose_skip_env\s*=\s*"([^"]+)"', Path("modules/testkit/src/root.zig").read_text()
    )
    if not declared:
        print("modules/testkit/src/root.zig: verbose_skip_env is gone or renamed")
        return 1
    name = declared.group(1)
    if name not in Path("scripts/test-lib.sh").read_text():
        print(f"scripts/test-lib.sh does not mention {name}, which testkit declares")
        return 1

    if hits:
        for f, ln, why in sorted(hits):
            print(f"{f}:{ln}: {why}")
        print()
        print("A test that reports \"skipped\" and returns plainly is counted as PASSED.")
        print("Use `return testkit.skip(\"...\", .{...});` — one statement that cannot")
        print("fall through to the assertions it was meant to skip.")
        return 1

    print(f"check-skip-as-pass: {len(files)} files, every announced skip actually skips; {name} spelled alike in both trees")
    return 0


if __name__ == "__main__":
    sys.exit(main())
