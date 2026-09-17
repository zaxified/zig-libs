#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fault injection: would this module's suite notice if a guard were weakened?

    modules/ethfrag/tools/mutate.py             # the whole table
    modules/ethfrag/tools/mutate.py --only M8   # rows whose id contains "M8"
    modules/ethfrag/tools/mutate.py --controls  # only the controls

RED   = the suite noticed (the guard is pinned by a test)
GREEN = the suite passed with the guard weakened (it is INVISIBLE to the tests)

Most rows WEAKEN rather than delete. That distinction earned its keep here: the
audit's eight survivors were all weakenings, and five of them were carried
through to a demonstrated memory-safety defect (see `consequence.zig`) --
delivered frames carrying uninitialised heap, and two panics on `@memcpy`.

⚠ THE SCRATCH COPY IS THE WHOLE src/ TREE. `root.zig` reaches
`kernel_oracle.zig` (`root.zig:1758`) and that file imports back
(`kernel_oracle.zig:162`). Copying `root.zig` alone does not build. The
single-file modules migrated earlier in this campaign never had to care; `xml`
taught this the hard way when `@embedFile` bound its copy to DATA as well.

⚠ EVERY VARIANT GETS ITS OWN --cache-dir. A shared one served a STALE binary
elsewhere in this campaign and turned 18 mutations into false PASSes.

⚠ THE COMMAND LINE ROTS SEPARATELY FROM THE ANCHORS. The audit runner drove a
bare `zig test root.zig`. Measured 2026-09-17: it fails at `root.zig:1504` with
`no module named 'testkit'`; with `--dep testkit` the suite is 42/42. A dry run
cannot see this -- 12 of the audit's 16 anchors still matched exactly once.

⚠ THREE ANCHORS ROTTED, ALL THREE BECAUSE THE FINDING WAS FIXED:
  * `M1`/`M8` named the overlap scan. F8+F9 replaced the linear walk with
    SORTED intervals and `lowerBound`, so there is no longer one loop to
    weaken: there is a predecessor check (`root.zig:609`) and a successor loop
    (`:621`). `M8`'s original "compare only the LAST interval" has no meaning
    against a sorted structure -- the equivalent is to switch off ONE SIDE.
  * `M4b` named the timeout comparison, which F2 rewrote when it added the
    absolute lifetime cap (`created_ns`/`lifetimeCap`) beside the idle check.
  That is the fourth time in this campaign an anchor aged because the module
  got better rather than because a file grew.

⚠ FOUR ROWS ARE NEW, and the audit could not have had them: `EmptyNonFinalFragment`
(F1), the two `noinline` guard markers F6 added so fuzz reach could be measured
by function rather than by line, and the absolute lifetime cap (F2).

⚠ BROKEN IS NOT RED. A mutant that fails to compile ran nothing; scoring it as
"the suite noticed" would report a measurement that never happened.

⚠ TWO CONTROLS POINTING OPPOSITE WAYS. `NC-no-edit` must come back GREEN (the
unmutated suite passes). `PC-overlap` deletes the overlap guard outright and
must come back RED. The audit runner had only the first kind and no exit code.
"""
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
SRC_DIR = ROOT / "modules/ethfrag/src"
TESTKIT = ROOT / "modules/testkit/src/root.zig"
WORK = ROOT / f".zig-cache/ethfrag-mutate/run-{os.getpid()}"

# (id, description, needle, replacement, expect)
MUT = [
    ('NC-no-edit', 'negative control: no edit at all', None, None, 'GREEN'),
    ('PC-overlap', 'positive control: drop the predecessor overlap check',
     "        if (idx > 0 and intervalOverlaps(hdr.offset, hdr.length, frag_end, entry.intervals.items[idx - 1])) {",
     "        if (false and intervalOverlaps(hdr.offset, hdr.length, frag_end, entry.intervals.items[idx - 1])) {", 'RED'),

    # ⚠ RE-DERIVED. `intervalOverlaps` is a top-level fn (four-space body), and
    # F1 put the zero-length special case above this line.
    # ⚠ The `+1` goes on the FIRST term. Putting it on the second (`end >
    # iv.offset + 1`) does not weaken the shape `F3/M1-shape` tests --
    # [9,19) against [0,10) still reads `19 > 1` -- so that mutation came back
    # GREEN while the guard was in fact pinned. A mutation that the targeted
    # test cannot distinguish is not evidence of a gap; it is a weak mutation.
    ('M1', 'overlap guard: allow ONE overlapping byte',
     "    return @as(usize, offset) < iv_end and end > @as(usize, iv.offset);",
     "    return @as(usize, offset) + 1 < iv_end and end > @as(usize, iv.offset);", 'RED'),
    ('M2', 'drop the max_frame_len bound check entirely',
     "        if (frag_end > self.config.max_frame_len) return error.OutOfBounds;",
     "        if (false) return error.OutOfBounds;", 'RED'),
    ('M2b', 'max_frame_len bound moved by ONE',
     "        if (frag_end > self.config.max_frame_len) return error.OutOfBounds;",
     "        if (frag_end > self.config.max_frame_len + 1) return error.OutOfBounds;", 'RED'),
    ('M3', 'remove the max_inflight table cap',
     "if (!self.entries.contains(hdr.frag_id) and self.entries.count() >= self.config.max_inflight) {\n            _ = self.expireOlderThan(now_ns);",
     "if (false) {\n            _ = self.expireOlderThan(now_ns);", 'RED'),
    ('M4a', "remove insert()'s inline staleness check",
     "            if (now_ns -| e.last_seen_ns > self.config.timeout_ns) self.dropEntry(hdr.frag_id);",
     "            if (false and now_ns -| e.last_seen_ns > self.config.timeout_ns) self.dropEntry(hdr.frag_id);", 'RED'),
    # ⚠ RE-DERIVED against the post-F2 expiry, which now has two halves.
    ('M4b', 'idle timeout comparison moved by ONE (>= instead of >)',
     "            const idle_expired = now_ns -| kv.value_ptr.last_seen_ns > self.config.timeout_ns;",
     "            const idle_expired = now_ns -| kv.value_ptr.last_seen_ns >= self.config.timeout_ns;", 'GREEN'),
    ('M5', 'max_fragments_per_datagram cap moved by ONE',
     "if (entry.intervals.items.len >= self.config.max_fragments_per_datagram) {",
     "if (entry.intervals.items.len > self.config.max_fragments_per_datagram) {", 'RED'),
    ('M6', 'retroactive bounds check weakened by ONE',
     "                    if (@as(usize, iv.offset) + @as(usize, iv.length) > frag_end) {",
     "                    if (@as(usize, iv.offset) + @as(usize, iv.length) > frag_end + 1) {", 'RED'),
    # ⚠ `if (false)` orphans the loop capture `iv` and the mutant will not
    # compile -- BROKEN, not RED. Spend the value instead.
    ('M6b', 'retroactive bounds check removed',
     "                    if (@as(usize, iv.offset) + @as(usize, iv.length) > frag_end) {",
     "                    if (iv.offset != iv.offset) {", 'RED'),
    ('M7', 'contradictory more=false: only reject a LARGER second claim',
     "                if (t != frag_end) {",
     "                if (t < frag_end) {", 'RED'),
    # ⚠ RE-DERIVED. The audit's "compare only the LAST interval" cannot be
    # expressed against a sorted list; switching off the SUCCESSOR half is the
    # equivalent blind spot (an overlap with an interval that sorts after the
    # new fragment goes unseen).
    ('M8', 'overlap guard: check only the predecessor, never the successors',
     "            if (intervalOverlaps(hdr.offset, hdr.length, frag_end, entry.intervals.items[succ])) {",
     "            if (false and intervalOverlaps(hdr.offset, hdr.length, frag_end, entry.intervals.items[succ])) {", 'RED'),
    ('M9', 'completion test loosened: covered >= total_len',
     "            if (entry.covered == t) {",
     "            if (entry.covered >= t) {", 'GREEN'),
    # ⚠ `if (false)` orphans the `if (entry.total_len) |t|` capture.
    ('M10', 'forward bounds check vs total_len removed',
     "            if (frag_end > t) {\n                self.dropEntry(hdr.frag_id);\n                return error.OutOfBounds;",
     "            if (t != t) {\n                self.dropEntry(hdr.frag_id);\n                return error.OutOfBounds;", 'RED'),
    # ⚠ `if (false)` orphans both `flags` and `reserved`.
    ('M11', 'Header.decode: ignore reserved bits instead of rejecting',
     "        if (flags & ~flag_more != 0 or reserved != 0) return error.InvalidHeader;",
     "        if (flags != flags or reserved != reserved) return error.InvalidHeader;", 'RED'),
    ('M12', 'LengthMismatch: accept trailing bytes (only reject too-few)',
     "        if (payload.len != hdr.length) return error.LengthMismatch;",
     "        if (payload.len < hdr.length) return error.LengthMismatch;", 'RED'),

    # ── rows the audit could not have had: these guards did not exist ────────
    ('M13-new', 'F1: accept a non-final ZERO-LENGTH fragment again',
     "        if (hdr.length == 0 and hdr.more) return error.EmptyNonFinalFragment;",
     "        if (false) return error.EmptyNonFinalFragment;", 'RED'),
    # ⚠ `= false` orphans `lifetime_cap`, computed one scope up.
    ('M14-new', 'F2: remove the absolute lifetime cap, leaving only idle time',
     "            const lifetime_expired = now_ns -| kv.value_ptr.created_ns > lifetime_cap;",
     "            const lifetime_expired = lifetime_cap != lifetime_cap;", 'RED'),
    ('M15-new', 'F6: never report TableFull (the guard marker never fires)',
     "                return guardTableFull();",
     "                if (false) return guardTableFull();", 'RED'),
    ('M16-new', 'F6: never report TooManyFragments',
     "            return guardTooManyFragments();",
     "            if (false) return guardTooManyFragments();", 'RED'),
]


def build_and_run(d):
    """Build and run the mutated copy. Returns (verdict, detail)."""
    r = subprocess.run(
        ["zig", "test",
         # ⚠ own cache dir per variant -- see the module docstring.
         "--cache-dir", str(d / "zc"),
         "--dep", "testkit",
         "-Mroot=" + str(d / "src" / "root.zig"),
         "-Mtestkit=" + str(TESTKIT)],
        capture_output=True, text=True, timeout=3600)
    out = r.stdout + r.stderr
    if "no module named" in out or "unable to open" in out:
        first = next((l.strip() for l in out.splitlines() if "error:" in l), "")
        return "BROKEN", "the runner could not build at all: " + first[:110]
    if r.returncode == 0:
        return "GREEN", ""
    detail = next((l.strip() for l in out.splitlines()
                   if "passed;" in l and "failed" in l), "")
    if detail:
        return "RED", detail
    if "signal ABRT" in out or "panic:" in out:
        return "RED", "PANIC (the mutant aborted at runtime)"
    # ⚠ A mutant that does not COMPILE is not a caught mutation: nothing ran.
    ce = next((l.strip() for l in out.splitlines()
               if ": error: " in l and l.split(":")[0].endswith(".zig")), "")
    if ce:
        return "BROKEN", "the mutant did not compile: " + ce[:100]
    return "RED", ""


def main():
    only = None
    if "--only" in sys.argv:
        only = sys.argv[sys.argv.index("--only") + 1]
    table = [m for m in MUT if m[0].startswith(("NC-", "PC-"))]
    if "--controls" not in sys.argv:
        table += [m for m in MUT
                  if not m[0].startswith(("NC-", "PC-"))
                  and (not only or only in m[0])]

    WORK.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("ZIGLIBS_MEM_MAX", "4G")
    pristine = (SRC_DIR / "root.zig").read_text()
    bad_anchor, mismatched, broken, results = [], [], [], []
    try:
        for mid, desc, needle, repl, expect in table:
            d = WORK / mid
            if d.exists():
                shutil.rmtree(d)
            # ⚠ the WHOLE src/ tree -- root.zig and kernel_oracle.zig import
            # each other; copying one of them builds nothing.
            shutil.copytree(SRC_DIR, d / "src",
                            ignore=shutil.ignore_patterns(".zig-cache", "__pycache__"))
            target = d / "src" / "root.zig"
            if needle is not None:
                n = pristine.count(needle)
                if n != 1:
                    kind = "PATCH-MISS" if n == 0 else f"AMBIGUOUS({n})"
                    bad_anchor.append((mid, kind))
                    print(f"  {mid:<10} {kind:<14} {desc}", flush=True)
                    continue
                target.write_text(pristine.replace(needle, repl, 1))
                if target.read_text() == pristine:
                    bad_anchor.append((mid, "DID-NOT-LAND"))
                    print(f"  {mid:<10} DID-NOT-LAND   {desc}", flush=True)
                    continue

            verdict, detail = build_and_run(d)
            results.append((mid, verdict, expect))
            mark = ""
            if verdict == "BROKEN" and expect != "BROKEN":
                broken.append(mid)
            elif expect and verdict != expect:
                mark = f"  ⛔ expected {expect}"
                mismatched.append((mid, verdict, expect))
            print(f"  {mid:<10} {verdict:<14} {desc}{mark}", flush=True)
            if detail:
                print(f"      {detail}", flush=True)
    finally:
        shutil.rmtree(WORK, ignore_errors=True)

    green = [r for r in results
             if r[1] == "GREEN" and not r[0].startswith(("NC-", "PC-"))]
    # ⚠ Count BROKEN from the rows, not from `broken` (which holds only the
    # unpinned ones) -- a summary must agree with its own output.
    n_broken = sum(1 for r in results if r[1] == "BROKEN")
    print(f"\n{len(results)} rows: "
          f"{sum(1 for r in results if r[1] == 'RED')} RED, "
          f"{sum(1 for r in results if r[1] == 'GREEN')} GREEN, "
          f"{n_broken} BROKEN ({len(broken)} unpinned), "
          f"{len(bad_anchor)} anchor problems")
    if green:
        print("\nGuards the suite did NOT notice:")
        for mid, _, _ in green:
            print(f"   {mid}")
        print("\n⭐ Feed each to `consequence.zig` against a mutant copy: a GREEN row "
              "is a missing test, and what it BUYS an attacker is the severity.")

    rc = 0
    if broken:
        print(f"\n⛔ {len(broken)} UNPINNED row(s) could not BUILD -- a defect in this "
              f"runner, not a verdict about the module.", file=sys.stderr)
        rc = 1
    if bad_anchor:
        print(f"\n⛔ {len(bad_anchor)} anchor(s) no longer name a unique site, or did "
              f"not land. A row that was not applied is MISSING, not passing.",
              file=sys.stderr)
        rc = 1
    if mismatched:
        print(f"\n⛔ {len(mismatched)} row(s) came back against their pinned verdict.",
              file=sys.stderr)
        rc = 1
    nc = [r for r in results if r[0].startswith("NC-")]
    pc = [r for r in results if r[0].startswith("PC-")]
    if not nc or any(v != "GREEN" for _, v, _ in nc):
        print("\n⛔ THE NEGATIVE CONTROL DID NOT COME BACK GREEN (or never ran): the "
              "unmutated suite does not pass, so nothing here measures the module.",
              file=sys.stderr)
        rc = 1
    if not pc or any(v != "RED" for _, v, _ in pc):
        print("\n⛔ THE POSITIVE CONTROL SURVIVED (or never ran). Every row above is "
              "meaningless.", file=sys.stderr)
        rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
