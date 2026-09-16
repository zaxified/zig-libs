#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""M10, re-run — and the reason it needed one.

WHY THIS EXISTS. `mutate.py`'s M10 deletes the randomness comparison. That
leaves `digest` computed and unused, which Zig rejects, so the first attempt
came back BUILD-ERROR — not "the suite caught it", not "the suite missed it",
but no verdict at all. ⭐ A mutation that does not compile is a MISSING ROW, and
counting it as either outcome is how a mutation report flatters or slanders a
suite. This removes the whole block instead, so the mutant builds and the row
can actually be obtained.

It is kept rather than folded into `mutate.py` because it is the evidence that
M10's row was measured rather than assumed.

WHAT IT NEEDS. A `zig` on PATH, and a repository `git worktree` can check out.

    python3 mutate_m10.py

⚠ Like `mutate.py`, it mutates the DETACHED WORKTREE under
`.zig-cache/drand-mutate/wt` and never the tracked tree (2026-09-16). It reuses
that file's `ensure_worktree()` rather than restating it, so the rule has one
implementation instead of two that can drift apart. Until that date both of
these patched `modules/drand/src` in place and leaned on a `finally`.

WHAT IT PRODUCES. One verdict line — SURVIVED or CAUGHT — plus the suite's own
summary line and the first error, if any.
"""
import os, subprocess, sys, time

# One implementation of the worktree rule, not two. Importing `mutate` is
# side-effect free: its `main()` sits under `if __name__ == "__main__"`.
from mutate import WT, ensure_worktree

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
F = os.path.join(WT, "modules/drand/src/verify.zig")

OLD = """    if (round.randomness) |claimed| {
        var digest: [32]u8 = undefined;
        Sha256.hash(round.signatureBytes(), &digest, .{});
        if (!std.mem.eql(u8, &digest, &claimed)) return error.RandomnessMismatch;
    }
"""
NEW = """    if (round.randomness) |claimed| {
        _ = claimed;
    }
"""

ensure_worktree()

s = open(F).read()
if s.count(OLD) != 1:
    print(f"REFUSING: the anchor appears {s.count(OLD)} times, expected exactly 1 — "
          f"the source moved and this mutation no longer says what it used to")
    sys.exit(1)

rc = 0
try:
    open(F, "w").write(s.replace(OLD, NEW))
    t0 = time.time()
    p = subprocess.run(["zig", "build", "test-drand", "-Doptimize=ReleaseFast",
                        "--summary", "all", "--cache-dir",
                        os.path.join(ROOT, ".zig-cache/drand-mutate/M10b")],
                       cwd=WT, capture_output=True, text=True, timeout=1800)
    out = p.stdout + p.stderr
    survived = p.returncode == 0
    print("M10b verdict:", "SURVIVED" if survived else "CAUGHT",
          f"({time.time()-t0:.0f}s)")
    for line in out.splitlines():
        if "tests passed" in line or "pass" in line and "test drand" in line:
            print("   ", line.strip())
        if line.strip().startswith("error:"):
            print("   ", line.strip()[:160])
    # SURVIVED means the randomness check is unprotected by the suite. Say so in
    # the exit code too, so a scripted run cannot read this as a pass.
    rc = 1 if survived else 0
finally:
    # Restore inside the WORKTREE; the tracked tree was never written to.
    subprocess.run(["git", "-C", WT, "checkout", "--", "modules/drand/src/verify.zig"])

sys.exit(rc)
