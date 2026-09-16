#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fault injection: would this module's suite notice if a guard were removed?

    modules/tc/tools/mutate.py            # the whole table
    modules/tc/tools/mutate.py M13 M18    # only those rows
    modules/tc/tools/mutate.py --controls # only the two positive controls

Tests prove the code passes. Only mutation shows the suite can FAIL -- and this
module's guards are mostly length checks standing between kernel bytes and a
fixed-size read, where "the suite is green" and "the guard is untested" look
identical from outside.

RED   = the suite noticed (the guard is pinned by a test)
GREEN = the suite passed with the guard gone (the guard is INVISIBLE to it)

⚠ Every row copies the LIVE `modules/tc/src/*.zig` into a scratch tree at run
time and mutates the copy. It never carries its own snapshot of the module and
never writes to the tracked tree -- an instrument that keeps its own copy
reports on a module that no longer exists (CONVENTIONS.md §9).

⚠ The dependency set is `--dep netlink --dep testkit`, which is what
`build.zig` declares for this module. Getting that wrong does not fail one row,
it fails EVERY build identically, and a table of uniform REDs reads exactly
like a suite that catches everything. The positive controls below exist to
catch precisely that.
"""
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
SRC = ROOT / "modules/tc/src"
WORK = ROOT / ".zig-cache/tc-mutate"
# ⚠ Per-process scratch. With a single shared `mut/` two runs of this tool at
# once -- the whole table in one terminal, two rows in another -- silently
# overwrite each other's mutant between the copy and the build, and each then
# reports a verdict about the other's edit. Nothing warns; the rows just read
# wrong.
MUT = WORK / f"mut-{os.getpid()}"
BIN = WORK / f"mut-bin-{os.getpid()}"
LOG = WORK / f"mut-{os.getpid()}.log"

# (tag, file, old, new, description, expect)
#
# `expect` is "RED", "GREEN", or None for a row whose verdict has not been
# pinned yet. A pinned row that comes back the other way fails the run.
#
# ⚠ The expectations here are MEASURED on the tree as it stands, not copied
# from the 2026-09-04 audit. That audit found 36 of 53 mutants RED; five fix
# passes have closed F1-F12 and F-VM1 since, and several of those fixes exist
# precisely to turn one of these rows from GREEN to RED. Copying the old
# verdicts forward would have pinned them upside down.
MUTATIONS = [
    # ── caller-input validation guards ──────────────────────────────────────
    ('M1', 'qdisc.zig',
     'if (!(pct >= 0.0 and pct <= 100.0)) return error.InvalidPercent;',
     'if (false) return error.InvalidPercent;',
     'percentToU32 range/NaN guard', 'RED'),
    ('M2', 'qdisc.zig',
     'if (ns > std.math.maxInt(i64)) return error.InvalidDelay;',
     'if (false) return error.InvalidDelay;',
     'checkDelayNs (the 2026-07 F1 fix)', 'RED'),
    ('M2b', 'qdisc.zig',
     'if (ns > std.math.maxInt(i64)) return error.InvalidDelay;',
     'if (ns > std.math.maxInt(u64)) return error.InvalidDelay;',
     'checkDelayNs, widened rather than removed', 'RED'),
    ('M3', 'filter.zig',
     'if (u.keys.len > u32_max_keys) return error.TooManyKeys;',
     'if (false) return error.TooManyKeys;',
     'u32 TooManyKeys', 'RED'),
    ('M4', 'action.zig',
     'if (actions.len > max_actions) return error.TooManyActions;',
     'if (false) return error.TooManyActions;',
     'TooManyActions (TCA_ACT_MAX_PRIO)', 'RED'),
    ('M5', 'action.zig',
     'if (a.cookie().len > max_cookie_len) return error.CookieTooLong;',
     'if (false) return error.CookieTooLong;',
     'CookieTooLong', 'RED'),
    ('M5b', 'action.zig',
     'if (a.cookie().len > max_cookie_len) return error.CookieTooLong;',
     'if (a.cookie().len > 1_000_000) return error.CookieTooLong;',
     'CookieTooLong, widened rather than removed', 'RED'),
    ('M6', 'qdisc.zig',
     'if (t.peakrate != 0 and t.mtu == 0) return error.MissingMtu;',
     'if (false) return error.MissingMtu;',
     'tbf MissingMtu', 'RED'),
    ('M7', 'qdisc.zig',
     'if (t.limit == 0 and t.latency_us == 0) return error.MissingLimit;',
     'if (false) return error.MissingLimit;',
     'tbf MissingLimit', 'RED'),
    ('M8', 'filter.zig',
     'if (portAttrs(proto) == null) return error.PortWithoutProto;',
     'if (false) return error.PortWithoutProto;',
     'flower PortWithoutProto', 'RED'),
    ('M8b', 'filter.zig',
     'if (portAttrs(proto) == null) return error.PortWithoutProto;',
     'if (portAttrs(proto) == null and false) return error.PortWithoutProto;',
     'PortWithoutProto, neutralised rather than removed', 'RED'),
    ('M9', 'handle.zig',
     'if (v > std.math.maxInt(u16)) return error.HandleOverflow;',
     'if (false) return error.HandleOverflow;',
     'Handle.parseHalf overflow', 'RED'),
    ('M10', 'action.zig',
     'if (p.burst == 0) return error.MissingBurst;',
     'if (false) return error.MissingBurst;',
     'police MissingBurst', 'RED'),

    # ── parse side: each gate stands between kernel bytes and a fixed read ──
    ('M11', 'action.zig',
     'if (s.len > kind_max) return error.BadLength;',
     'if (s.len > 1_000_000) return error.BadLength;',
     'copyKind kind_max (OOB memcpy)', 'RED'),
    ('M12', 'action.zig',
     'const n = @min(attr.data.len, max_cookie_len);',
     'const n = attr.data.len;',
     'TCA_ACT_COOKIE truncation (OOB memcpy)', 'RED'),
    ('M13', 'filter.zig',
     'while (off + tc_u32_key_len <= a.data.len and uw.keys_len < uw.keys.len) {',
     'while (off + tc_u32_key_len <= a.data.len) {',
     'parseU32Options keys[] bound (OOB write)', 'GREEN'),
    ('M14', 'filter.zig',
     'if (a.data.len < tc_u32_sel_len) return error.BadLength;',
     'if (a.data.len < 0) return error.BadLength;',
     'parseU32Options SEL length gate', 'RED'),
    ('M15', 'qdisc.zig',
     'if (a.data.len < tc_htb_opt_len) return error.BadLength;',
     'if (a.data.len < 0) return error.BadLength;',
     'parseHtbClassOptions PARMS gate', 'RED'),
    ('M16', 'action.zig',
     'if (attr.data.len < tc_police_len) return error.BadLength;',
     'if (attr.data.len < 0) return error.BadLength;',
     'parsePoliceOptions TBF gate', 'RED'),
    ('M17', 'action.zig',
     'if (attr.data.len < tc_mirred_len) return error.BadLength;',
     'if (attr.data.len < 0) return error.BadLength;',
     'parseMirredOptions PARMS gate', 'RED'),

    # ── wire policy ─────────────────────────────────────────────────────────
    #
    # ⚠ M18 was ONE row until 2026-09-16, and its anchor
    # `const ordinal: u16 = @intCast(i + 1);` matches TWICE in action.zig --
    # once on the actions path and once on the refs path. A `str.replace`
    # patched both at once, so whatever the row reported was a verdict about
    # two guards jointly and about neither on its own. Split, each anchored by
    # the call that follows it (`a.kind()` vs `r.kind`).
    ('M18', 'action.zig',
     'const ordinal: u16 = @intCast(i + 1);\n'
     '        const entry = try codec.nestBegin(gpa, list, ordinal);\n'
     '        try appendKind(gpa, list, a.kind());',
     'const ordinal: u16 = @intCast(i);\n'
     '        const entry = try codec.nestBegin(gpa, list, ordinal);\n'
     '        try appendKind(gpa, list, a.kind());',
     '1-based action ordinals (actions path)', 'RED'),
    ('M18b', 'action.zig',
     'const ordinal: u16 = @intCast(i + 1);\n'
     '        const entry = try codec.nestBegin(gpa, list, ordinal);\n'
     '        try appendKind(gpa, list, r.kind);',
     'const ordinal: u16 = @intCast(i);\n'
     '        const entry = try codec.nestBegin(gpa, list, ordinal);\n'
     '        try appendKind(gpa, list, r.kind);',
     '1-based action ordinals (refs path)', 'RED'),
    ('M19', 'action.zig',
     'const opts = try codec.nestBegin(gpa, list, TCA_ACT.OPTIONS | codec.NLA_F_NESTED);',
     'const opts = try codec.nestBegin(gpa, list, TCA_ACT.OPTIONS);',
     'NLA_F_NESTED on TCA_ACT_OPTIONS', 'RED'),
    ('M20', 'message.zig',
     'if (spec.carriesOptions()) {',
     'if (true) {',
     'mq carries no TCA_OPTIONS', 'RED'),
    ('M22', 'ratespec.zig',
     'if (clock_res == 1_000_000_000) t2us = us2t;',
     'if (false) t2us = us2t;',
     'psched ns-resolution compat hack', 'RED'),
    # ⚠ M23's anchor is NOT the one the audit wrote. That named
    # `while ((mtu >> @intCast(cell_log)) > 255) cell_log += 1;`, and the live
    # loop grew a `cell_log < max_cell_log` clause when F2/F7 were fixed, so
    # the old text matches ZERO times today and the row read "not applied"
    # while looking like a result. Re-derived against the current source.
    ('M23', 'ratespec.zig',
     'while (cell_log < max_cell_log and (mtu >> @intCast(cell_log)) > 255) cell_log += 1;',
     'while (cell_log < max_cell_log and (mtu >> @intCast(cell_log)) > 254) cell_log += 1;',
     'deriveCellLog 255 boundary', 'RED'),
    ('M24', 'root.zig',
     'const max_dump_attempts = 4;',
     'const max_dump_attempts = 1;',
     'max_dump_attempts', 'RED'),
    ('M25', 'root.zig',
     'if (item.ifindex != ifindex) continue;',
     'if (false) continue;',
     'dump client-side ifindex filter', 'RED'),
    ('M26', 'root.zig',
     'if (rec.type != reply_type) continue;',
     'if (false) continue;',
     'dump reply-type filter', 'RED'),
    ('M26b', 'root.zig',
     'if (rec.type != reply_type) continue;',
     'if (rec.type != reply_type and false) continue;',
     'dump reply-type filter, neutralised rather than removed', 'RED'),
    ('M27', 'qdisc.zig',
     'return if (rate >= (1 << 32)) std.math.maxInt(u32) else @intCast(rate);',
     'return if (rate >= (1 << 31)) std.math.maxInt(u32) else @intCast(rate);',
     'htb/tbf ~0U rate clamp', 'RED'),

    # ── the constants the wire format is defined by ─────────────────────────
    ('M28', 'action.zig',
     'pub const max_actions_decoded = 4;',
     'pub const max_actions_decoded = 2;',
     'max_actions_decoded', 'RED'),
    ('M29', 'action.zig',
     'pub const max_cookie_len = 16;',
     'pub const max_cookie_len = 8;',
     'max_cookie_len (TC_COOKIE_MAX_SIZE)', 'RED'),
    ('M30', 'filter.zig',
     'pub const u32_max_keys = 128;',
     'pub const u32_max_keys = 64;',
     'u32_max_keys', 'RED'),
    ('M31', 'action.zig',
     'pub const kind_max',
     'pub const kind_max_UNUSED',
     'kind_max symbol (a compile RED is the expected shape)', 'RED'),
    ('M32', 'ratespec.zig',
     'spec.cell_align = -1;',
     'spec.cell_align = 0;',
     'tc_ratespec.cell_align = -1', 'RED'),
    ('M33', 'ratespec.zig',
     'spec.linklayer = @intFromEnum(linklayer) & LinkLayer.mask;',
     'spec.linklayer = @intFromEnum(linklayer);',
     'linklayer mask', 'GREEN'),
    ('M34', 'qdisc.zig',
     'const burst: u64 = if (c.burst != 0) c.burst else rate64 / hz + c.mtu;',
     'const burst: u64 = if (c.burst != 0) c.burst else rate64 / hz;',
     'htb default burst (+mtu)', 'RED'),
    ('M35', 'filter.zig',
     'pub fn makeInfo',
     'pub fn makeInfo_UNUSED',
     'makeInfo symbol (a compile RED is the expected shape)', 'RED'),
    ('M36', 'ratespec.zig',
     'pub const rate_table_entries = 256;',
     'pub const rate_table_entries = 255;',
     'rate table shape', 'RED'),
]

# ⚠ The two rows that judge the RUNNER rather than the module. Without them a
# broken command line (a missing `--dep`, a wrong path, a mutant that never got
# written) shows up as a table where every row is RED -- which is exactly what
# a suite that catches everything looks like. `whois`'s migrated runner shipped
# with one dep missing and every row read RED, the no-op included.
CONTROLS = [
    ('PC-ok', 'root.zig',
     'const max_dump_attempts = 4;',
     'const max_dump_attempts = 4; // PC-ok: a no-op edit, the suite must stay GREEN',
     'no-op edit -- if this is RED the runner is broken, not the module', 'GREEN'),
    # ⚠ PC-bad must fail at RUNTIME, not in the compiler. The first version of
    # this control shrank `rate_table_entries` to 4 and went RED with
    # "index 255 outside array of length 4" -- a compile error. That proves the
    # mutation landed and the build works, and proves NOTHING about whether the
    # test binary ran and its assertions were evaluated; a control that can only
    # fail at compile time cannot tell "the suite caught it" from "the suite
    # never executed". This edit compiles cleanly and is caught by an assertion:
    # `us2t` 0x40 -> 0x41 breaks `tickInUsec() == 15.625` and every byte-exact
    # golden that carries a rate table.
    ('PC-bad', 'ratespec.zig',
     'pub const golden_psched: Psched = Psched.fromFields(0x3e8, 0x40, 0x000f4240, 0x3b9aca00);',
     'pub const golden_psched: Psched = Psched.fromFields(0x3e8, 0x41, 0x000f4240, 0x3b9aca00);',
     'the golden host calibration, off by one tick -- if this is GREEN the suite did not run', 'RED'),
]


def build_and_run(tag):
    """Build the mutated copy and run it. Returns (verdict, detail)."""
    LOG.write_text("")
    r = subprocess.run(
        [str(ROOT / "scripts/capped"), "zig", "test", "--test-no-exec",
         "-femit-bin=" + str(BIN),
         "--cache-dir", str(ROOT / ".zig-cache"),
         "--dep", "netlink", "--dep", "testkit",
         "-Mroot=" + str(MUT / "root.zig"),
         "-Mnetlink=" + str(ROOT / "modules/netlink/src/root.zig"),
         "-Mtestkit=" + str(ROOT / "modules/testkit/src/root.zig")],
        capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        first = next((l.strip() for l in (r.stdout + r.stderr).splitlines()
                      if "error:" in l), "")
        return "RED", "compile: " + first[:90]
    try:
        p = subprocess.run([str(BIN)], capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return "RED", "the mutant HUNG (300 s) -- a hang is a verdict, not a pass"
    out = p.stdout + p.stderr
    if p.returncode == 0:
        return "GREEN", ""
    detail = ""
    for line in out.splitlines():
        if "passed;" in line and "failed" in line:
            detail = line.strip()
            break
    if not detail:
        detail = next((l.strip()[:90] for l in out.splitlines()
                       if "panic" in l or "error:" in l), "")
    return "RED", detail


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    only_controls = "--controls" in sys.argv

    table = list(CONTROLS)
    if not only_controls:
        table += [m for m in MUTATIONS if not args or m[0] in args]
    if args:
        known = {m[0] for m in MUTATIONS} | {c[0] for c in CONTROLS}
        unknown = [a for a in args if a not in known]
        if unknown:
            print("unknown row(s): " + ", ".join(unknown), file=sys.stderr)
            return 2

    WORK.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("ZIGLIBS_MEM_MAX", "4G")

    bad_anchor, mismatched, results = [], [], []
    for tag, fname, old, new, desc, expect in table:
        if MUT.exists():
            shutil.rmtree(MUT)
        # ⚠ from the LIVE sources, every row, never from a snapshot.
        shutil.copytree(SRC, MUT, ignore=shutil.ignore_patterns(".zig-cache", "__pycache__"))
        target = MUT / fname
        text = target.read_text()
        n = text.count(old)
        if n != 1:
            kind = "PATCH-MISS" if n == 0 else f"AMBIGUOUS({n})"
            bad_anchor.append((tag, kind, desc))
            print(f"  {tag:<7} {kind:<14} {desc}", flush=True)
            continue
        target.write_text(text.replace(old, new))

        verdict, detail = build_and_run(tag)
        results.append((tag, verdict, expect, desc))
        mark = ""
        if expect and verdict != expect:
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
          f"{len(bad_anchor)} anchor problems")
    if green:
        print("\nGuards the suite did NOT notice:")
        for tag, _, _, desc in green:
            print(f"   {tag:<7} {desc}")

    # ⚠ And it exits on the result. A mutation runner that reports and returns
    # zero is a green light nobody earned -- three parked instruments in this
    # collection had exactly that shape.
    rc = 0
    if bad_anchor:
        print(f"\n⛔ {len(bad_anchor)} anchor(s) no longer name a unique site. "
              f"A row that was not applied is MISSING, not passing -- re-derive it "
              f"against the current source.", file=sys.stderr)
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
