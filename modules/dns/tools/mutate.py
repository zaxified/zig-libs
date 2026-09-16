#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fault injection: would `message.zig`'s own tests notice if a guard were removed?

    modules/dns/tools/mutate.py             # the whole table
    modules/dns/tools/mutate.py M1 M3       # only those rows
    modules/dns/tools/mutate.py --controls  # only the two positive controls

RED   = the suite noticed (the guard is pinned by a test)
GREEN = the suite passed with the guard gone (the guard is INVISIBLE to it)

Every guard below stands between an attacker-supplied packet and either a loop,
an allocation, or a fixed-size read. "The suite is green" and "the guard is
untested" look identical from outside, which is what mutation is for.

⚠ Each row copies the LIVE `modules/dns/src/{message,goldens}.zig` into a
per-process scratch tree and mutates the copy. It never carries its own
snapshot: the audit's copies had rotted 181 lines behind the module they
claimed to describe (CONVENTIONS.md §9).

⚠ THE COMMAND LINE IS THE PART THAT ROTS. The shell runner this replaces did
`zig test mut.zig` with no `--dep` at all, which was right when it was written
and is wrong now: `message.zig` gained `@import("testkit")` at file scope, and
it imports `goldens.zig` relatively. Measured 2026-09-16, that runner fails
with `goldens.zig: FileNotFound` before a single mutation is judged -- so every
row would have read RED, the positive control included. Anchors do not catch
this: all 9 still matched their site exactly once. Only running it does.
"""
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
SRC = ROOT / "modules/dns/src"
WORK = ROOT / ".zig-cache/dns-mutate"
MUT = WORK / f"mut-{os.getpid()}"

# (tag, old, new, description, expect)
MUTATIONS = [
    ('M1',
     "                if (jumps > max_pointer_jumps) return error.PointerLoop;\n",
     "",
     'remove the 16-jump compression-pointer budget', 'RED'),
    ('M2',
     "pub const max_name_text_len = 253;",
     "pub const max_name_text_len = 4096;",
     'raise the 253-char name cap to 4096', 'RED'),
    ('M3',
     "                if (target >= pos) return error.BadPointer;",
     "                if (target >= bytes.len) return error.BadPointer;",
     'accept FORWARD compression pointers', 'RED'),
    ('M4',
     "    if (@as(usize, count) * min_record_wire > d.bytes.len - d.pos) return error.Truncated;\n",
     "",
     'drop the record-count pre-check (allocation amplification)', 'RED'),
    ('M5',
     "    if (@as(usize, count) * min_question_wire > d.bytes.len - d.pos) return error.Truncated;\n",
     "",
     'drop the question-count pre-check (allocation amplification)', 'RED'),
    ('M6',
     "            else => return error.BadLabel, // 0b01/0b10: reserved label types",
     "            else => { pos += 1; },",
     'accept reserved label types as labels', 'RED'),
    ('M7',
     "if (tag_len == 0 or tag_len > rdlength - 2) return error.BadRecord;",
     "if (tag_len > rdlength - 2) return error.BadRecord;",
     'CAA empty tag accepted', 'RED'),
    ('M8',
     "    if (d.pos > rdata_end) return error.BadRecord; // rdata fields overran RDLENGTH\n",
     "",
     'drop the rdata-overran-RDLENGTH check', 'RED'),
]

# ⚠ The rows that judge the RUNNER rather than the module. Without them a broken
# command line fails every build identically, and a table of uniform REDs reads
# exactly like a suite that catches everything -- which is precisely how the
# shell runner this replaces was failing.
#
# PC-bad must fail at RUNTIME, not in the compiler: a control that can only fail
# while compiling proves the mutation landed and proves nothing about whether
# the test binary ran and its assertions were evaluated.
CONTROLS = [
    ('PC-ok',
     "pub const max_name_text_len = 253;",
     "pub const max_name_text_len = 253; // PC-ok: a no-op edit, the suite must stay GREEN",
     'no-op edit -- if this is RED the runner is broken, not the module', 'GREEN'),
    ('PC-bad',
     "if (rdlength != 4) return error.BadRecord;",
     "if (rdlength != 5) return error.BadRecord;",
     'an A record with RDLENGTH 5 -- if this is GREEN the suite did not run', 'RED'),
]


def build_and_run():
    """Build the mutated copy and run its tests. Returns (verdict, detail)."""
    r = subprocess.run(
        [str(ROOT / "scripts/capped"), "zig", "test",
         "--cache-dir", str(ROOT / ".zig-cache"),
         "--dep", "testkit",
         "-Mroot=" + str(MUT / "message.zig"),
         "-Mtestkit=" + str(ROOT / "modules/testkit/src/root.zig")],
        capture_output=True, text=True, timeout=600)
    out = r.stdout + r.stderr
    if r.returncode == 0:
        return "GREEN", ""
    first = next((l.strip() for l in out.splitlines() if "error:" in l), "")
    if "FileNotFound" in out or "unable to load" in out or "no module named" in out:
        return "BROKEN", "the runner could not build at all: " + first[:100]
    detail = next((l.strip() for l in out.splitlines()
                   if "passed;" in l and "failed" in l), "")
    return "RED", detail or first[:100]


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    table = list(CONTROLS)
    if "--controls" not in sys.argv:
        table += [m for m in MUTATIONS if not args or m[0] in args]
    known = {m[0] for m in MUTATIONS} | {c[0] for c in CONTROLS}
    unknown = [a for a in args if a not in known]
    if unknown:
        print("unknown row(s): " + ", ".join(unknown), file=sys.stderr)
        return 2

    WORK.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("ZIGLIBS_MEM_MAX", "4G")

    bad_anchor, mismatched, broken, results = [], [], [], []
    for tag, old, new, desc, expect in table:
        if MUT.exists():
            shutil.rmtree(MUT)
        MUT.mkdir(parents=True)
        # ⚠ goldens.zig travels with it: message.zig imports it relatively.
        for f in ("message.zig", "goldens.zig"):
            shutil.copy(SRC / f, MUT / f)
        target = MUT / "message.zig"
        text = target.read_text()
        n = text.count(old)
        if n != 1:
            kind = "PATCH-MISS" if n == 0 else f"AMBIGUOUS({n})"
            bad_anchor.append((tag, kind, desc))
            print(f"  {tag:<7} {kind:<14} {desc}", flush=True)
            continue
        target.write_text(text.replace(old, new))

        verdict, detail = build_and_run()
        results.append((tag, verdict, expect, desc))
        mark = ""
        if verdict == "BROKEN":
            broken.append((tag, desc))
        elif expect and verdict != expect:
            mark = f"  ⛔ expected {expect}"
            mismatched.append((tag, verdict, expect, desc))
        print(f"  {tag:<7} {verdict:<6} {desc}{mark}", flush=True)
        if detail:
            print(f"          {detail}", flush=True)

    if MUT.exists():
        shutil.rmtree(MUT)

    green = [r for r in results if r[1] == "GREEN" and not r[0].startswith("PC-")]
    print(f"\n{len(results)} rows: "
          f"{sum(1 for r in results if r[1] == 'RED')} RED, "
          f"{sum(1 for r in results if r[1] == 'GREEN')} GREEN, "
          f"{len(broken)} BROKEN, {len(bad_anchor)} anchor problems")
    if green:
        print("\nGuards the suite did NOT notice:")
        for tag, _, _, desc in green:
            print(f"   {tag:<7} {desc}")

    rc = 0
    if broken:
        print(f"\n⛔ {len(broken)} row(s) could not BUILD. That is a defect in this "
              f"runner's command line, not a verdict about the module.", file=sys.stderr)
        rc = 1
    if bad_anchor:
        print(f"\n⛔ {len(bad_anchor)} anchor(s) no longer name a unique site. A row "
              f"that was not applied is MISSING, not passing.", file=sys.stderr)
        rc = 1
    if mismatched:
        print(f"\n⛔ {len(mismatched)} row(s) came back against their pinned verdict.",
              file=sys.stderr)
        rc = 1
    ctl = {r[0]: r[1] for r in results if r[0].startswith("PC-")}
    if ctl.get("PC-ok") != "GREEN" or ctl.get("PC-bad") != "RED":
        print(f"\n⛔ THE CONTROLS FAILED (PC-ok={ctl.get('PC-ok')}, "
              f"PC-bad={ctl.get('PC-bad')}). The runner is broken and every row "
              f"above is meaningless.", file=sys.stderr)
        rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
