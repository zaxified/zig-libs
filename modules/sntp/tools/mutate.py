#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fault injection: would this module's suite notice if a guard were removed?

    modules/sntp/tools/mutate.py              # the whole table
    modules/sntp/tools/mutate.py --only M9    # rows whose id contains "M9"
    modules/sntp/tools/mutate.py --controls   # only the controls

RED   = the suite noticed (the guard is pinned by a test)
GREEN = the suite passed with the guard gone (it is INVISIBLE to the tests)

⚠ Every row copies the LIVE `modules/sntp/src/root.zig` into a per-process
scratch tree and mutates the copy. The audit's own copy (`sntp.zig`) is today
964 lines against the live 1305 -- 427 differing lines -- because the whole
F1/F2 refactor landed after it. Anything measured against that copy would be a
statement about code that no longer exists (CONVENTIONS.md §9).

⚠ EVERY VARIANT GETS ITS OWN --cache-dir. A shared one served a STALE binary
elsewhere in this campaign and turned 18 mutations into false PASSes.

⚠ THE COMMAND LINE ROTS SEPARATELY FROM THE ANCHORS. The audit runner drove a
bare `zig test <file>`. Measured 2026-09-17 against the live module: it fails at
`root.zig:1209` with `no module named 'testkit'`; with `--dep testkit` the same
suite is `37 passed, 1 skipped, rc=0`. A dry run cannot see this -- 11 of the
audit's 13 anchors still matched their site exactly once.

⚠ TWO ANCHORS ROTTED, AND NOT BY THE FILE GROWING. `M1` named
`try verifyOriginate(reply, t1);` inside `query`, and `M9` named
`if (!incoming.from.eql(&dest)) continue;`. Audit finding F1 was precisely that
those two guards sat in a shape no test could reach, so the fix MOVED them into
`processReply`/`validateReply` where a unit test drives them directly. The
anchors rotted because the finding was fixed -- and the re-derived rows below
point at the new sites. `M1` also changed ARGUMENT: the echo is now checked
against `origin_nonce` (the CSPRNG wire nonce from F4), not against `t1`.

⚠ BROKEN IS NOT RED. A mutant that fails to compile ran nothing; scoring it as
"the suite noticed" would report a measurement that never happened.

⚠ TWO CONTROLS POINTING OPPOSITE WAYS. `NC-no-edit` must come back GREEN (the
unmutated suite passes). `PC-control` swaps seconds/fraction in
`Timestamp.fromBytes` and must come back RED. The audit runner had only the
second kind, and no exit code at all -- it printed and returned 0 regardless.
"""
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
SRC = ROOT / "modules/sntp/src/root.zig"
TESTKIT = ROOT / "modules/testkit/src/root.zig"
WORK = ROOT / f".zig-cache/sntp-mutate/run-{os.getpid()}"

# (id, description, needle, replacement, expect)
MUT = [
    ('NC-no-edit', 'negative control: no edit at all', None, None, 'GREEN'),

    ('PC-control', 'positive control: swap seconds/fraction in Timestamp.fromBytes',
     ".seconds = std.mem.readInt(u32, bytes[0..4], .big),\n            .fraction = std.mem.readInt(u32, bytes[4..8], .big),",
     ".seconds = std.mem.readInt(u32, bytes[4..8], .big),\n            .fraction = std.mem.readInt(u32, bytes[0..4], .big),", 'RED'),

    # ⚠ RE-DERIVED. Was `try verifyOriginate(reply, t1);` in `query`; F1's fix
    # moved it into `validateReply` and F4 changed the argument to the nonce.
    # ⚠ `_ = origin_nonce;` is not decoration: deleting the only use of a
    # PARAMETER makes the mutant fail to compile, and a mutant that does not
    # build scores BROKEN -- nothing ran. Spending it is the same cure this
    # campaign proved on s7comm's D2, in the form Zig wants for a parameter.
    ('M1-drop-origin-call', 'validateReply: drop the origin-echo check entirely',
     "    try verifyOriginate(reply, origin_nonce);",
     "    _ = origin_nonce; // MUTATION: origin-timestamp check removed", 'RED'),

    ('M2-origin-hi-only', 'Timestamp.eql: compare only the upper 32 bits (seconds)',
     "        return self.seconds == other.seconds and self.fraction == other.fraction;",
     "        return self.seconds == other.seconds; // MUTATION: half-width compare", 'RED'),

    ('M3-origin-lo-only', 'Timestamp.eql: compare only the lower 32 bits (fraction)',
     "        return self.seconds == other.seconds and self.fraction == other.fraction;",
     "        return self.fraction == other.fraction; // MUTATION: half-width compare", 'RED'),

    ('M4-accept-stratum0', 'decodeResponse: accept stratum 0 (Kiss-o-Death) as a time source',
     "    if (p.stratum == 0) {",
     "    if (false) {", 'RED'),

    ('M5-skip-mode', 'decodeResponse: skip the mode-4 check',
     "    if (p.mode != .server) return error.NotServerMode;",
     "    // MUTATION: mode check removed", 'RED'),

    ('M6-stratum-offbyone', 'decodeResponse: move the stratum bound by one (>=16 -> >=17)',
     "    if (p.stratum >= 16) return error.UnsynchronizedStratum;",
     "    if (p.stratum >= 17) return error.UnsynchronizedStratum;", 'RED'),

    ('M7-drop-xmit-zero', 'decodeResponse: drop the all-zero Transmit Timestamp check',
     "    if (p.transmit.isZero()) return error.TransmitTimestampUnset;",
     "    // MUTATION: transmit-zero check removed", 'RED'),

    ('M8-drop-version', 'decodeResponse: drop the VN=0 check',
     "    if (p.version == 0) return error.InvalidVersion;",
     "    // MUTATION: version check removed", 'RED'),

    # ⚠ RE-DERIVED. Was `if (!incoming.from.eql(&dest)) continue;` in `query`'s
    # receive loop; F1's fix moved the peer guard into `processReply`, which
    # returns null to mean "keep waiting".
    ('M9-drop-peer-check', 'processReply: accept a datagram from ANY source address/port',
     "    if (!from.eql(&server)) return null;",
     "    _ = from;\n    _ = server; // MUTATION: source address/port check removed", 'RED'),

    ('M10-len-loose', 'Packet.decode: accept >= 48 bytes instead of exactly 48',
     "        if (bytes.len != packet_len) return error.InvalidLength;",
     "        if (bytes.len < packet_len) return error.InvalidLength;", 'RED'),

    ('M11-kod-only-deny', 'parseKissCode: collapse RATE to .unrecognized',
     '        .{ "RATE", KissCode.rate },',
     '        .{ "RATE", KissCode.unrecognized },', 'RED'),

    ('M12-offset-floor', 'computeOffsetNanos: @divTrunc -> @divFloor (rounding direction)',
     "    return @divTrunc(a + b, 2);",
     "    return @divFloor(a + b, 2);", 'RED'),

    # ⚠ NEW rows the audit could not have had: F2, F3 and F7 were findings then,
    # so there was no guard to remove. Each now has a named test, and these rows
    # are how "the fix is pinned" stops being an assertion.
    ('M13-drop-trunc-check', 'validateReply: drop the truncated-datagram check (audit F2)',
     "    if (truncated) return error.InvalidLength;",
     "    _ = truncated; // MUTATION: truncation check removed", 'RED'),

    ('M14-drop-recv-zero', 'decodeResponse: drop the all-zero Receive Timestamp check (audit F3)',
     "    if (p.receive.isZero()) return error.ReceiveTimestampUnset;",
     "    // MUTATION: receive-zero check removed", 'RED'),

    ('M15-accept-leap3', 'decodeResponse: accept Leap Indicator 3 again (audit F7)',
     "    if (p.leap == .unsynchronized) return error.UnsynchronizedLeap;",
     "    // MUTATION: unsynchronized-leap check removed", 'RED'),
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
        for mid, desc, needle, repl, expect in table:
            d = WORK / mid
            if d.exists():
                shutil.rmtree(d)
            d.mkdir(parents=True)
            if needle is None:
                text = pristine
            else:
                n = pristine.count(needle)
                if n != 1:
                    kind = "PATCH-MISS" if n == 0 else f"AMBIGUOUS({n})"
                    bad_anchor.append((mid, kind))
                    print(f"  {mid:<22} {kind:<14} {desc}", flush=True)
                    continue
                text = pristine.replace(needle, repl, 1)
            (d / "m.zig").write_text(text)
            # ⚠ diff-verify on disk: a mutation that did not land would
            # otherwise be published as a survivor.
            if needle is not None and (d / "m.zig").read_text() == pristine:
                bad_anchor.append((mid, "DID-NOT-LAND"))
                print(f"  {mid:<22} DID-NOT-LAND   {desc}", flush=True)
                continue

            verdict, detail = build_and_run(d)
            results.append((mid, verdict, expect))
            mark = ""
            if verdict == "BROKEN":
                broken.append(mid)
            elif expect and verdict != expect:
                mark = f"  ⛔ expected {expect}"
                mismatched.append((mid, verdict, expect))
            print(f"  {mid:<22} {verdict:<14} {desc}{mark}", flush=True)
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
        print("\nGuards the suite did NOT notice:")
        for mid, _, _ in green:
            print(f"   {mid}")

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
