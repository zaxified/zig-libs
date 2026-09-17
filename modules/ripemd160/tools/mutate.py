#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fault injection: would this module's suite notice if a constant were wrong?

    modules/ripemd160/tools/mutate.py              # the whole table
    modules/ripemd160/tools/mutate.py --only PAD   # rows whose label contains "PAD"
    modules/ripemd160/tools/mutate.py --controls   # only the controls

RED   = the suite noticed (the constant is pinned by a test)
GREEN = the suite passed with the constant wrong (it is INVISIBLE to the tests)

A hash has no branches worth weakening: every mutation here is a single wrong
TOKEN in a table, a rotation amount, a round function, an endianness or a
padding bound. That is the whole attack surface of a correct implementation.

⚠ Every row copies the LIVE `modules/ripemd160/src/root.zig` into a per-process
scratch tree and mutates the copy. Never a snapshot of its own -- the audit's
own copy (`rmd.zig`) is today 465 lines against the live 632, missing all three
fixes this module received, so anything measured against it would be a
statement about code that no longer exists (CONVENTIONS.md §9).

⚠ EVERY VARIANT GETS ITS OWN --cache-dir. A shared one served a STALE binary
elsewhere in this campaign and turned 18 mutations into false PASSes.

⚠ THE COMMAND LINE ROTS SEPARATELY FROM THE ANCHORS, and only running catches
it. The audit runner drove a bare `zig test m.zig`. Measured 2026-09-17 against
the live module: it fails at `root.zig:517` with `no module named 'testkit'`;
with `--dep testkit` the same suite is `13/13, rc=0`. A dry run cannot see this
-- all 32 of the audit's anchors still match their site exactly once, because
they aim at the constant TABLES, which the `inline for` rewrite never touched.

⚠ BROKEN IS NOT RED. A mutant that fails to compile ran nothing; scoring it as
"the suite noticed" would report a measurement that never happened.

⚠ TWO CONTROLS, AND THEY POINT OPPOSITE WAYS. `NC-no-edit` must come back GREEN
(an unmutated suite passes -- if it does not, the runner is broken). `PC-broken-IV`
must come back RED (a corrupted IV must be caught -- if it survives, the runner
is measuring nothing and every row above it is meaningless). The audit's runner
had only the first kind and no exit code at all.
"""
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
SRC = ROOT / "modules/ripemd160/src/root.zig"
TESTKIT = ROOT / "modules/testkit/src/root.zig"
WORK = ROOT / f".zig-cache/ripemd160-mutate/run-{os.getpid()}"

# (label, needle, replacement, expect)
#
# `expect` is None until measured. The audit's verdicts are NOT copied forward:
# its two real survivors were F1 (the padding spill) and F8 (the drain guard),
# and BOTH have since been fixed and pinned by a named test -- so those two rows
# turning RED is exactly what proves the fixes work.
MUT = [
    ('NC-no-edit (negative control: expect GREEN)', None, None, 'GREEN'),
    ('PC-broken-IV h[0] 0x67452301 -> 0x67452300',
     "0x67452301, 0xEFCDAB89", "0x67452300, 0xEFCDAB89", 'RED'),
    ('K_GROUP[1]  0x5A827999 -> ...98', "0x5A827999", "0x5A827998", 'RED'),
    ('K_GROUP[4]  0xA953FD4E -> ...4F', "0xA953FD4E", "0xA953FD4F", 'RED'),
    ('KP_GROUP[0] 0x50A28BE6 -> ...E7', "0x50A28BE6", "0x50A28BE7", 'RED'),
    ('KP_GROUP[4] 0x00000000 -> ...01',
     "0x7A6D76E9, 0x00000000", "0x7A6D76E9, 0x00000001", 'RED'),
    ('R[0]  0 -> 1  (left word-select, group 0)',
     "    0, 1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,",
     "    1, 1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,", 'RED'),
    ('R[79] 13 -> 12 (left word-select, group 4)',
     "    4, 0,  5,  9,  7,  12, 2,  10, 14, 1, 3,  8,  11, 6,  15, 13,",
     "    4, 0,  5,  9,  7,  12, 2,  10, 14, 1, 3,  8,  11, 6,  15, 12,", 'RED'),
    ('RP[0] 5 -> 6  (right word-select)',
     "    5,  14, 7,  0, 9, 2,  11, 4,  13, 6,  15, 8,  1,  10, 3,  12,",
     "    6,  14, 7,  0, 9, 2,  11, 4,  13, 6,  15, 8,  1,  10, 3,  12,", 'RED'),
    ('RP[79] 11 -> 10 (right word-select, group 4)',
     "    12, 15, 10, 4, 1, 5,  8,  7,  6,  2,  13, 14, 0,  3,  9,  11,",
     "    12, 15, 10, 4, 1, 5,  8,  7,  6,  2,  13, 14, 0,  3,  9,  10,", 'RED'),
    ('S[0]  11 -> 12 (left rotate amount)',
     "    11, 14, 15, 12, 5,  8,  7,  9,  11, 13, 14, 15, 6,  7,  9,  8,",
     "    12, 14, 15, 12, 5,  8,  7,  9,  11, 13, 14, 15, 6,  7,  9,  8,", 'RED'),
    ('S[79] 6 -> 5   (left rotate amount, group 4)',
     "    9,  15, 5,  11, 6,  8,  13, 12, 5,  12, 13, 14, 11, 8,  5,  6,",
     "    9,  15, 5,  11, 6,  8,  13, 12, 5,  12, 13, 14, 11, 8,  5,  5,", 'RED'),
    ('SP[0] 8 -> 9   (right rotate amount)',
     "    8,  9,  9,  11, 13, 15, 15, 5,  7,  7,  8,  11, 14, 14, 12, 6,",
     "    9,  9,  9,  11, 13, 15, 15, 5,  7,  7,  8,  11, 14, 14, 12, 6,", 'RED'),
    ('SP[79] 11 -> 10 (right rotate amount, group 4)',
     "    8,  5,  12, 9,  12, 5,  14, 6,  8,  13, 6,  5,  15, 13, 11, 11,",
     "    8,  5,  12, 9,  12, 5,  14, 6,  8,  13, 6,  5,  15, 13, 11, 10,", 'RED'),
    ('roundFn f3  (x | ~y) ^ z -> (x | y) ^ z',
     "2 => (x | ~y) ^ z,", "2 => (x | y) ^ z,", 'RED'),
    ('roundFn f5  x ^ (y | ~z) -> x ^ (y | z)',
     "4 => x ^ (y | ~z),", "4 => x ^ (y | z),", 'RED'),
    ('right line mirror  groupp = 4 - group -> group',
     "const groupp: u3 = 4 - group;", "const groupp: u3 = group;", 'RED'),
    ('rotl(c,10) -> rotl(c,11) (left line)',
     "dd = math.rotl(u32, c, 10);", "dd = math.rotl(u32, c, 11);", 'RED'),
    ('rotl(cc,10) -> rotl(cc,11) (right line)',
     "ddd = math.rotl(u32, cc, 10);", "ddd = math.rotl(u32, cc, 11);", 'RED'),
    ('final combine: h[3] = h[4]+a+bb -> h[4]+a+cc',
     "d.h[3] = d.h[4] +% a +% bb;", "d.h[3] = d.h[4] +% a +% cc;", 'RED'),
    ('kp indexed by groupp instead of group',
     "const kp = KP_GROUP[group];", "const kp = KP_GROUP[groupp];", 'RED'),
    # ⚠ Audit F1 lived here: `< 7` survived the whole suite AND 300069 --fuzz
    # runs, because it is wrong only at length ≡ 56 (mod 64) and the KATs had
    # 55 but not 56. A KAT for 56 was added; this row must now be RED.
    ('PAD SPILL: 64 - buf_len < 8  ->  < 7',
     "if (64 - d.buf_len < 8) {", "if (64 - d.buf_len < 7) {", 'RED'),
    ('PAD SPILL: 64 - buf_len < 8  ->  < 9',
     "if (64 - d.buf_len < 8) {", "if (64 - d.buf_len < 9) {", 'RED'),
    ('PAD SPILL: 64 - buf_len < 8  ->  <= 8',
     "if (64 - d.buf_len < 8) {", "if (64 - d.buf_len <= 8) {", 'RED'),
    ('terminator 0x80 -> 0x81',
     "d.buf[d.buf_len] = 0x80;", "d.buf[d.buf_len] = 0x81;", 'RED'),
    # ⚠ Audit F8 lived here: `> 64` left buf_len == 64 and wrote d.buf[64] --
    # a panic in Debug, a SILENT wrong digest in ReleaseFast. An assert and a
    # call-order test were added; this row must now be RED too.
    ('drain guard  >= 64  ->  > 64',
     "d.buf_len + b.len >= 64", "d.buf_len + b.len > 64", 'RED'),
    ('length suffix .little -> .big',
     "mem.writeInt(u64, d.buf[56..64], bit_len, .little);",
     "mem.writeInt(u64, d.buf[56..64], bit_len, .big);", 'RED'),
    ('message words readInt .little -> .big',
     "x[i] = mem.readInt(u32, block[i * 4 ..][0..4], .little);",
     "x[i] = mem.readInt(u32, block[i * 4 ..][0..4], .big);", 'RED'),
    ('digest out writeInt .little -> .big',
     "mem.writeInt(u32, out[4 * i ..][0..4], word, .little);",
     "mem.writeInt(u32, out[4 * i ..][0..4], word, .big);", 'RED'),
    ('drop the tail @memset in final()',
     "@memset(d.buf[d.buf_len..], 0);", "@memset(d.buf[d.buf_len..][0..0], 0);", 'RED'),
    ('bit_len  *% 8  ->  *% 4',
     "const bit_len: u64 = d.total_len *% 8;",
     "const bit_len: u64 = d.total_len *% 4;", 'RED'),
    ('total_len +%= b.len  ->  +%= off',
     "d.total_len +%= b.len;", "d.total_len +%= off;", 'RED'),
    ('hash160: drop the SHA-256 stage',
     "Ripemd160.hash(&sha, out, .{});", "Ripemd160.hash(data, out, .{});", 'RED'),
]


def build_and_run(d):
    """Build and run the mutated copy. Returns (verdict, detail)."""
    r = subprocess.run(
        ["zig", "test",
         # ⚠ own cache dir per variant -- see the module docstring.
         "--cache-dir", str(d / "zc"),
         "--dep", "testkit",
         "-Mroot=" + str(d / "m.zig"),
         "-Mtestkit=" + str(TESTKIT)],
        capture_output=True, text=True, timeout=1800)
    out = r.stdout + r.stderr
    if "no module named" in out or "unable to load" in out:
        first = next((l.strip() for l in out.splitlines() if "error:" in l), "")
        return "BROKEN", "the runner could not build at all: " + first[:100]
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
        return "BROKEN", "the mutant did not compile: " + ce[:90]
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
    pristine = SRC.read_text()
    bad_anchor, mismatched, broken, results = [], [], [], []
    try:
        for label, needle, repl, expect in table:
            d = WORK / label.split()[0].replace("/", "_")
            if d.exists():
                shutil.rmtree(d)
            d.mkdir(parents=True)
            if needle is None:
                text = pristine          # the negative control edits nothing
            else:
                n = pristine.count(needle)
                if n != 1:
                    kind = "PATCH-MISS" if n == 0 else f"AMBIGUOUS({n})"
                    bad_anchor.append((label, kind))
                    print(f"  {label:<46} {kind}", flush=True)
                    continue
                text = pristine.replace(needle, repl, 1)
            (d / "m.zig").write_text(text)
            # ⚠ diff-verify on disk: a mutation that did not land would
            # otherwise be published as a survivor.
            on_disk = (d / "m.zig").read_text()
            if needle is not None and on_disk == pristine:
                bad_anchor.append((label, "DID-NOT-LAND"))
                print(f"  {label:<46} DID-NOT-LAND", flush=True)
                continue

            verdict, detail = build_and_run(d)
            results.append((label, verdict, expect))
            mark = ""
            if verdict == "BROKEN":
                broken.append(label)
            elif expect and verdict != expect:
                mark = f"  ⛔ expected {expect}"
                mismatched.append((label, verdict, expect))
            print(f"  {label:<46} {verdict}{mark}", flush=True)
            if detail:
                print(f"      {detail}", flush=True)
    finally:
        shutil.rmtree(WORK, ignore_errors=True)

    green = [r for r in results
             if r[1] == "GREEN" and not r[0].startswith(("NC-", "PC-"))]
    print(f"\n{len(results)} rows: "
          f"{sum(1 for r in results if r[1] == 'RED')} RED, "
          f"{sum(1 for r in results if r[1] == 'GREEN')} GREEN, "
          f"{len(broken)} BROKEN, {len(bad_anchor)} anchor problems")
    if green:
        print("\nConstants the suite did NOT notice:")
        for label, _, _ in green:
            print(f"   {label}")

    rc = 0
    if broken:
        print(f"\n⛔ {len(broken)} row(s) could not BUILD -- a defect in this runner, "
              f"not a verdict about the module.", file=sys.stderr)
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
    # ⚠ The two controls point opposite ways; check each for ITS answer.
    nc = [r for r in results if r[0].startswith("NC-")]
    pc = [r for r in results if r[0].startswith("PC-")]
    if not nc or any(v != "GREEN" for _, v, _ in nc):
        print("\n⛔ THE NEGATIVE CONTROL DID NOT COME BACK GREEN (or never ran): the "
              "unmutated suite does not pass, so nothing here measures the module.",
              file=sys.stderr)
        rc = 1
    if not pc or any(v != "RED" for _, v, _ in pc):
        print("\n⛔ THE POSITIVE CONTROL SURVIVED (or never ran). A corrupted IV must "
              "be caught; every row above is meaningless.", file=sys.stderr)
        rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
