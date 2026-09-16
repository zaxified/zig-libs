#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fault injection: would this module's suite notice if a guard were removed?

    modules/s7comm/tools/mutate.py            # the whole table
    modules/s7comm/tools/mutate.py W2 D7      # only those rows
    modules/s7comm/tools/mutate.py --controls # only the two positive controls

RED   = the suite noticed (the guard is pinned by a test)
GREEN = the suite passed with the guard gone (the guard is INVISIBLE to it)

Two kinds of row, deliberately. DELETIONS neutralise a guard outright; WEAKENINGS
move a bound by one, compare fewer octets, or widen a range. The second kind is
what found audit F7: four guards where the suite is green against a *weakened*
check, and `tools/verify_survivors.py` then shows the weakened code reading an
octet of memory that is not the caller's.

⚠ Every row copies the LIVE `modules/s7comm/src/*.zig` into a per-process
scratch tree and mutates the copy. Never a snapshot of its own, never the
tracked tree (CONVENTIONS.md §9).

⚠ THE COMMAND LINE ROTS SEPARATELY FROM THE ANCHORS, and only running catches
it. The audit's runner drove a bare `zig test <file>` with no module graph.
Measured 2026-09-17 against the live module: that now fails with
`no module named 'testkit' available within module 'test'` -- 12 of this
module's files import `testkit` at file scope for their fuzz corpora. Its
positive control ran the same way, so it failed loudly rather than lying; but
it measured nothing at all. With `--dep testkit` the same files are exit 0.
A dry run cannot see this: 16 of its 17 anchors still matched their site
exactly once.
"""
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
SRC = ROOT / "modules/s7comm/src"
TESTKIT = ROOT / "modules/testkit/src/root.zig"
WORK = ROOT / ".zig-cache/s7comm-mutate"
MUT = WORK / f"mut-{os.getpid()}"

# (tag, file, old, new, files-to-test, description, expect)
#
# `files-to-test` names the files whose own `zig test` covers the mutated
# guard: this module is a set of siblings, so running the one file that holds
# the guard plus the golden set that exercises it is both faster and sharper
# than a whole-module lane.
#
# `expect` is None until measured. The audit's verdicts are NOT copied forward:
# all 14 findings were fixed in 2026-09-10, and a fix is exactly what turns a
# row from GREEN to RED.
MUTATIONS = [
    # ── deletions: the coarsest probe ───────────────────────────────────────
    ('D1', 'tpkt.zig',
     '    if (bytes.len < total) return error.TruncatedPacket;',
     '    if (false) return error.TruncatedPacket;',
     ['tpkt.zig', 'goldens.zig'],
     'drop the TPKT-length vs octets-present cross-check', 'RED'),
    # ⚠ Re-derived: the audit's `if (false)` left `need` unused, so the mutant
    # failed to COMPILE (`vars.zig:79: error: unused local constant`) and the
    # row scored RED -- a build failure wearing a verdict's clothes. `need !=
    # need` neutralises the guard while still consuming the value.
    ('D2', 'vars.zig',
     '    if (bytes.len - 2 != need) return error.ItemCountMismatch;',
     '    if (need != need) return error.ItemCountMismatch;',
     ['vars.zig', 'server.zig'],
     'remove the item-count bound entirely', 'RED'),
    ('D3', 'address.zig',
     '    if (n.value > 7) return error.BadBitIndex;',
     '    if (false) return error.BadBitIndex;',
     ['address.zig'],
     'accept a bit offset > 7', 'RED'),
    ('D4', 's7plus_value.zig',
     '    if (depth == 0) return error.DepthExceeded;\n\n    if (flags.isArray()) {',
     '    if (false) return error.DepthExceeded;\n\n    if (flags.isArray()) {',
     ['s7plus_value.zig', 's7plus_object.zig'],
     "remove the recursion depth limit from skipBody", 'GREEN'),
    ('D5', 'client.zig',
     '        if (pdu.header.pdu_reference != self.pdu_ref) return error.PduReferenceMismatch;',
     '        if (false) return error.PduReferenceMismatch;',
     ['client.zig'],
     'skip the PDU-reference comparison', 'RED'),
    ('D6', 's7.zig',
     '    if (bytes.len != hl + body) return error.LengthMismatch;',
     '    if (bytes.len < hl + body) return error.LengthMismatch;',
     ['s7.zig', 'goldens.zig'],
     'drop the exact parameter+data length check', 'RED'),
    ('D7', 'server.zig',
     '            if (item.count == 0) {\n                try w.addError(.invalid_address, error_item_length);\n                continue;\n            }',
     '            if (item.count == 1000000) {\n                try w.addError(.invalid_address, error_item_length);\n                continue;\n            }',
     ['server.zig'],
     'drop the zero-element-count refusal (the 2026-08 CRIT fix)', 'RED'),

    # ── weakenings: compare less, compare loosely, move a bound by one ──────
    ('W1', 'client.zig',
     '        if (pdu.header.pdu_reference != self.pdu_ref) return error.PduReferenceMismatch;',
     '        if (pdu.header.pdu_reference >> 8 != self.pdu_ref >> 8) return error.PduReferenceMismatch;',
     ['client.zig'],
     'compare only the HIGH octet of the PDU reference', 'RED'),
    ('W2', 'server.zig',
     '            if (start + want > store.len) {',
     '            if (start + want > store.len + 1) {',
     ['server.zig', 'goldens.zig'],
     'guard the read bound only from above, not at equality', 'RED'),
    ('W3', 'items.zig',
     '        if (self.pos + 4 + n > self.bytes.len) return error.BadDataLength;',
     '        if (self.pos + 4 + n > self.bytes.len + 1) return error.BadDataLength;',
     ['items.zig', 'goldens.zig'],
     'move the data-item bound by one', 'RED'),
    ('W4', 'address.zig',
     '    if (n.value > 7) return error.BadBitIndex;',
     '    if (n.value > 15) return error.BadBitIndex;',
     ['address.zig'],
     'accept bit offsets up to 15 instead of 7', 'RED'),
    ('W5', 'cotp.zig',
     '        else => if (raw_code & 0x0F != 0) return error.UnknownTpduCode,',
     '        else => if (raw_code & 0x0E != 0) return error.UnknownTpduCode,',
     ['cotp.zig'],
     'check only the high nibble of a DT/DR/DC/ER code', 'RED'),
    # ⚠ W6's anchor is NOT the audit's. That one named the TWO-argument
    # `try value.skipValue(cur, depth);`, and the 2026-08 F5/F6 fixes gave the
    # call a third parameter: the shared element budget. So the old text
    # matches ZERO times today -- the row read "needle not found" while looking
    # like a result. Re-derived against the current three-argument call.
    ('W6', 's7plus_object.zig',
     '                try value.skipValue(cur, depth, elem_budget);',
     '                try value.skipValue(cur, value.max_depth, elem_budget);',
     ['s7plus_object.zig'],
     'hand the value walk a FRESH depth budget (the 2026-08 F5 fix)', 'RED'),
    # ⚠ W6b is NEW, and it exists because re-deriving W6 showed a guard the
    # audit could not have had a row for: F6 made one `elem_budget` shared by
    # every attribute value in the whole object graph. Giving each nested walk
    # its own budget is the defect that fix removed -- a handful of octets
    # buying tens of millions of loop iterations.
    ('W6b', 's7plus_object.zig',
     '                try walkObject(cur, depth - 1, elem_budget);',
     '                var fresh: u32 = value.max_walk_budget;\n                try walkObject(cur, depth - 1, &fresh);',
     ['s7plus_object.zig'],
     'give each nested object its OWN element budget (undo the F6 fix)', 'GREEN'),
    ('W7', 'items.zig',
     '        if (ts == .bit and raw <= 8) return 1;\n        return error.LengthTransportMismatch;',
     '        if (raw <= 8) return 1;\n        return error.LengthTransportMismatch;',
     ['items.zig', 'goldens.zig'],
     'accept a bit-counted length that is not a whole octet', 'RED'),
    ('W8', 's7plus_value.zig',
     '        if (count > max_elements) return error.TooLong;',
     '        if (count > max_elements + 1) return error.TooLong;',
     ['s7plus_value.zig'],
     'raise max_elements by one (the array-count ceiling)', 'RED'),
    ('W9', 'tpkt.zig',
     '    if (total < min_length) return error.LengthTooSmall;\n    if (bytes.len < total) return error.TruncatedPacket;',
     '    if (total + 1 < min_length) return error.LengthTooSmall;\n    if (bytes.len < total) return error.TruncatedPacket;',
     ['tpkt.zig'],
     'accept a TPKT length one octet below the legal minimum', 'RED'),
    ('W10', 's7plus.zig',
     '        if (trailer[0] != protocol_id or trailer[1] != @intFromEnum(pt) or',
     '        if (trailer[0] != protocol_id or false or',
     ['s7plus.zig'],
     'accept a trailer whose PDU-type octet differs', 'RED'),
]

# ⚠ The rows that judge the RUNNER rather than the module. Without them a
# broken module graph fails every row identically, and a table of uniform REDs
# reads exactly like a suite that catches everything.
#
# PC-bad must fail at RUNTIME, not in the compiler: a control that can only
# fail while compiling proves the mutation landed and proves nothing about
# whether the test binary ran and its assertions were evaluated.
CONTROLS = [
    ('PC-ok', 'tpkt.zig',
     '    if (bytes.len < total) return error.TruncatedPacket;',
     '    if (bytes.len < total) return error.TruncatedPacket; // PC-ok: no-op',
     ['tpkt.zig', 'goldens.zig'],
     'no-op edit -- if this is RED the runner is broken, not the module', 'GREEN'),
    # ⚠ Re-derived TWICE, and the second time because the control itself came
    # back GREEN and the runner refused the table.
    #   1. The first version named `pub const min_length: usize = 7;` -- written
    #      from how TPKT works rather than from the file. Zero matches.
    #   2. The second RAISED that minimum (`header_len + 1` -> `+ 2`). It
    #      matched, it landed, and nothing failed: the tests at tpkt.zig:191-192
    #      expect `LengthTooSmall` for `00 04` and `00 00`, and a HIGHER minimum
    #      still refuses those. Only a test that decodes a minimal 5-octet
    #      packet would have caught it, and there is none.
    # Shifting `version` instead is unambiguous: `decode` checks
    # `bytes[0] != version`, so every valid packet and every golden fails at
    # RUNTIME.
    ('PC-bad', 'tpkt.zig',
     'pub const version: u8 = 3;',
     'pub const version: u8 = 4;',
     ['tpkt.zig', 'goldens.zig'],
     'shift the TPKT version octet -- if this is GREEN the suite did not run', 'RED'),
]


def run_files(files):
    """Run `zig test` over each named file of the mutated copy."""
    reds = []
    for f in files:
        r = subprocess.run(
            [str(ROOT / "scripts/capped"), "zig", "test",
             "--cache-dir", str(ROOT / ".zig-cache"),
             # ⚠ testkit is NOT optional -- see the module docstring.
             "--dep", "testkit",
             "-Mroot=" + str(MUT / f),
             "-Mtestkit=" + str(TESTKIT)],
            capture_output=True, text=True, timeout=900)
        out = r.stdout + r.stderr
        # ⚠ A mutant that does not COMPILE is not a caught mutation. Scoring it
        # RED says "the suite noticed", which is false -- nothing ran. D2 hit
        # exactly this: neutralising its guard left `need` unused, so the copy
        # failed with `error: unused local constant` and the row read RED.
        # A build failure is a defect in the MUTATION, not a verdict about the
        # module, so it gets its own outcome.
        compile_err = any(
            ": error: " in l and l.split(":")[0].endswith(".zig")
            for l in out.splitlines())
        if "no module named" in out or "unable to load" in out or (
                compile_err and "passed" not in out):
            return None, "BROKEN: " + next(
                (l.strip() for l in out.splitlines() if "error:" in l), "")[:110]
        if r.returncode != 0:
            first = next((l.strip()[:110] for l in out.splitlines()
                          if "FAIL" in l or "error:" in l or "panic" in l), "")
            reds.append(f"{f}{(' -> ' + first) if first else ''}")
    return reds, ""


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
    for tag, fname, old, new, files, desc, expect in table:
        if MUT.exists():
            shutil.rmtree(MUT)
        shutil.copytree(SRC, MUT, ignore=shutil.ignore_patterns(".zig-cache", "__pycache__"))
        target = MUT / fname
        text = target.read_text()
        n = text.count(old)
        if n != 1:
            kind = "PATCH-MISS" if n == 0 else f"AMBIGUOUS({n})"
            bad_anchor.append((tag, kind, desc))
            print(f"  {tag:<6} {kind:<14} {desc}", flush=True)
            continue
        target.write_text(text.replace(old, new, 1))

        reds, broke = run_files(files)
        if reds is None:
            verdict, detail = "BROKEN", broke
            broken.append((tag, desc))
        else:
            verdict = "RED" if reds else "GREEN"
            detail = "; ".join(reds)[:150]
        results.append((tag, verdict, expect, desc))
        mark = ""
        if expect and verdict != expect and verdict != "BROKEN":
            mark = f"  ⛔ expected {expect}"
            mismatched.append((tag, verdict, expect, desc))
        print(f"  {tag:<6} {verdict:<6} {desc}{mark}", flush=True)
        if detail:
            print(f"         {detail}", flush=True)

    if MUT.exists():
        shutil.rmtree(MUT)

    green = [r for r in results if r[1] == "GREEN" and not r[0].startswith("PC-")]
    print(f"\n{len(results)} rows: "
          f"{sum(1 for r in results if r[1] == 'RED')} RED, "
          f"{sum(1 for r in results if r[1] == 'GREEN')} GREEN, "
          f"{len(broken)} BROKEN, {len(bad_anchor)} anchor problems")
    if green:
        print("\nGuards the suite did NOT notice "
              "(feed each to tools/verify_survivors.py):")
        for tag, _, _, desc in green:
            print(f"   {tag:<6} {desc}")

    # ⚠ And it exits on the result. The audit's runner exited non-zero only when
    # its positive control was red; a survivor or a broken row still returned 0.
    rc = 0
    if broken:
        print(f"\n⛔ {len(broken)} row(s) could not BUILD. That is a defect in this "
              f"runner's module graph, not a verdict about the module.", file=sys.stderr)
        rc = 1
    if bad_anchor:
        print(f"\n⛔ {len(bad_anchor)} anchor(s) no longer name a unique site. A row "
              f"that was not applied is MISSING, not passing -- re-derive it.",
              file=sys.stderr)
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
