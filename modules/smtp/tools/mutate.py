#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fault injection: would this module's suite notice if a guard were removed?

    modules/smtp/tools/mutate.py             # the whole table
    modules/smtp/tools/mutate.py M1 M8       # only those rows
    modules/smtp/tools/mutate.py --controls  # only the two positive controls

RED   = the suite noticed (the guard is pinned by a test)
GREEN = the suite passed with the guard gone (the guard is INVISIBLE to it)

⚠ Every row copies the LIVE `modules/smtp/src/*.zig` into a per-process scratch
tree and mutates the copy. Never a snapshot of its own (CONVENTIONS.md §9).

⚠ TWO DEFECTS IN THE SHELL RUNNER THIS REPLACES, both found by reading it
rather than trusting its output:

  * `M11_no_boundary_collision_check` had NO `run_one` in front of it -- the
    edit sat in the file as a bare shell string, was expanded, and was thrown
    away. The row looked present in the source and never ran once. It is
    restored here, and its anchor still matches the live source exactly once.
  * `M15_stuffer_dot_free` replaced a string with ITSELF. The diff-verify
    caught that and printed "MUTATION DID NOT LAND", so it did not lie -- but
    it measured nothing either. It is left out rather than ported as a row that
    can only report its own inertness.

⚠ And the shell runner had no exit code at all: every row echoed, and the
process returned 0 whatever the table said.
"""
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
SRC = ROOT / "modules/smtp/src"
WORK = ROOT / ".zig-cache/smtp-mutate"
MUT = WORK / f"mut-{os.getpid()}"

# (tag, file, old, new, description, expect)
#
# `expect` is None until measured. The audit's verdicts are NOT copied forward:
# all twelve findings have been fixed since (F2/F6/F8 on 2026-09-13), and a fix
# is exactly what turns a row from GREEN to RED.
MUTATIONS = [
    ('M1', 'data.zig',
     'allow_bare_lf: bool = false,',
     'allow_bare_lf: bool = true,',
     'accept bare lf eod', 'RED'),
    ('M2', 'data.zig',
     "if (self.at_line_start and c == '.') {",
     'if (false) {',
     'drop the dot stuffing', 'RED'),
    ('M3', 'mime.zig',
     "fn checkValue(v: []const u8) HeaderError!void {\n    for (v) |c| {\n        if (c == '\\r' or c == '\\n' or c == 0) return error.ControlCharacterInHeader;\n    }\n}",
     'fn checkValue(v: []const u8) HeaderError!void {\n    _ = v;\n}',
     'drop the header crlf check', 'RED'),
    ('M4', 'message.zig',
     'if (depth > opts.max_depth) return error.DepthExceeded;',
     'if (false) return error.DepthExceeded;',
     'drop the mime depth limit', 'RED'),
    ('M5', 'session.zig',
     'if (!self.tls_active and !self.opts.allow_plaintext_auth) {\n                    self.state = .closed;\n                    return error.PlaintextAuthRefused;\n                }',
     '// mutation: plaintext AUTH refusal removed',
     'auth before starttls', 'RED'),
    # ⚠ M6's verdict DEPENDS ON THE OPTIMIZE MODE, and the pin below is the
    # default (Debug) one. Measured 2026-09-17:
    #     Debug                        GREEN
    #     MUT_OPT=ReleaseFast          RED  (135 passed; 1 skipped; 1 failed)
    # The guard is pinned -- by `session.zig`'s F5 dead-stack test, which opens
    # with `if (builtin.mode != .ReleaseFast) return error.SkipZigTest;`. In the
    # mode this runner uses by default that test does not run at all, so the row
    # reads GREEN for a reason that is about the HARNESS, not about the module.
    # Re-run it as `MUT_OPT=ReleaseFast modules/smtp/tools/mutate.py M6`.
    ('M6', 'auth.zig',
     'defer std.crypto.secureZero(u8, raw[0..raw_len]);',
     '// mutation: no secureZero',
     'drop the secure zero (RED under MUT_OPT=ReleaseFast)', 'GREEN'),
    ('M7', 'session.zig',
     'self.caps.deinit();\n        self.caps = .empty(self.gpa);\n        self.esmtp = false;\n        self.state = .ehlo;',
     'self.state = .ehlo;',
     'drop the starttls cap discard', 'RED'),
    ('M8', 'client.zig',
     'if (!self.parser.atBoundary()) return error.PlaintextInjection;',
     '// mutation: guard removed',
     'drop the plaintext injection guard', 'RED'),
    ('M9', 'mime.zig',
     "        if (bytes[i] == '\\n') {\n            var end = i;\n            if (end > start and bytes[end - 1] == '\\r') end -= 1;\n            if (end - start > max) return error.LineTooLong;\n            start = i + 1;\n        }",
     "        if (bytes[i] == '\\n') start = i + 1;",
     'drop the line length check', 'RED'),
    ('M10', 'mime.zig',
     '    command.validateMailbox(a.addr, .{}, true) catch |e| return switch (e) {\n        error.ControlCharacterInArgument => error.ControlCharacterInHeader,\n        else => error.InvalidAddress,\n    };',
     '// mutation: F4 gate removed',
     'drop the mailbox gate in mime', 'RED'),
    ('M12', 'reply.zig',
     '    fn compact(self: *Parser) void {\n        if (self.cursor == 0) return;',
     '    fn compact(self: *Parser) void {\n        if (self.cursor == 0) return;\n        if (self.cursor * 2 < self.pending.items.len) return; // amortise',
     'amortised compact (GREEN in Debug AND ReleaseFast)', 'GREEN'),
    ('M11b', 'message.zig',
     '            var clash = false;\n            for (kids.items) |k| {\n                if (std.mem.indexOf(u8, k.headers, cand) != null or\n                    std.mem.indexOf(u8, k.content, cand) != null)\n                {\n                    clash = true;\n                    break;\n                }\n            }',
     '            const clash = false;',
     'drop the boundary collision check', 'RED'),
    ('M13', 'session.zig',
     'std.crypto.secureZero(u8, self.out.items);',
     '// mutation: no secureZero of the command buffer',
     'drop the session wipeout (GREEN in Debug AND ReleaseFast)', 'GREEN'),
    ('M14', 'command.zig',
     'if (label_len >= 63) return false;',
     'if (label_len > 63) return false;',
     'drop the label63 check', 'RED'),
    # ⚠ M15 is DROPPED, not ported. In the shell runner it read
    # `s.replace(X, X)` -- old and new identical, so it mutated nothing.
    # Its diff-verify reported "MUTATION DID NOT LAND", so it never lied;
    # it simply never measured. Re-derive it deliberately or leave it out.

]

# ⚠ The rows that judge the RUNNER rather than the module. PC-bad must fail at
# RUNTIME, not in the compiler: a control that can only fail while compiling
# proves the mutation landed and proves nothing about whether the test binary
# ran and its assertions were evaluated.
CONTROLS = [
    ('PC-ok', 'data.zig',
     'allow_bare_lf: bool = false,',
     'allow_bare_lf: bool = false, // PC-ok: a no-op edit, the suite must stay GREEN',
     'no-op edit -- if this is RED the runner is broken, not the module', 'GREEN'),
    ('PC-bad', 'data.zig',
     "if (self.at_line_start and c == '.') {",
     'if (false) {',
     'stop dot-stuffing entirely -- if this is GREEN the suite did not run', 'RED'),
]


def build_and_run():
    """Build the mutated copy and run its tests. Returns (verdict, detail)."""
    # ⚠ THE OPTIMIZE MODE IS PART OF THE VERDICT. Three of this module's
    # guards are pinned by tests that SKIP unless the build is ReleaseFast
    # (`session.zig`'s F5 dead-stack test) or unless an env var is set
    # (`reply.zig`'s SMTP_BENCH_F1). Run in Debug and those rows come back
    # GREEN -- not because the suite is blind, but because the test that
    # watches them did not run. `MUT_OPT=ReleaseFast SMTP_BENCH_F1=1` reruns
    # them the way they are meant to be judged.
    opt = os.environ.get("MUT_OPT", "Debug")
    r = subprocess.run(
        [str(ROOT / "scripts/capped"), "zig", "test", "-O", opt,
         "--cache-dir", str(ROOT / ".zig-cache"),
         # ⚠ build.zig declares `.deps = netaddr`, `.test_deps = testkit`.
         "--dep", "netaddr", "--dep", "testkit",
         "-Mroot=" + str(MUT / "root.zig"),
         "-Mnetaddr=" + str(ROOT / "modules/netaddr/src/root.zig"),
         "-Mtestkit=" + str(ROOT / "modules/testkit/src/root.zig")],
        capture_output=True, text=True, timeout=1800)
    out = r.stdout + r.stderr
    if "no module named" in out or "unable to load" in out or "FileNotFound" in out:
        first = next((l.strip() for l in out.splitlines() if "error:" in l), "")
        return "BROKEN", "the runner could not build at all: " + first[:100]
    if r.returncode == 0:
        return "GREEN", ""
    detail = next((l.strip() for l in out.splitlines()
                   if "passed;" in l and "failed" in l), "")
    if detail:
        return "RED", detail
    # ⚠ Distinguish the three ways a row goes RED. Labelling them all
    # "compile:" was wrong and said so in the output: a test binary that
    # ABORTS has compiled and RUN -- it panicked, which is a stronger result
    # than a compile error, not a weaker one.
    if "signal ABRT" in out or "panic:" in out:
        first = next((l.strip() for l in out.splitlines() if "panic:" in l), "")
        return "RED", "PANIC (the mutant aborted at runtime)" + (
            " -- " + first[:80] if first else "")
    # ⚠ A mutant that does not COMPILE is not a caught mutation: nothing ran,
    # so "the suite noticed" is false. The s7comm runner hit exactly this --
    # neutralising a guard left a local unused, the copy failed to build, and
    # the row read RED. A build failure is a defect in the MUTATION, not a
    # verdict about the module, so it gets its own outcome. (Checked after the
    # panic branch above: a panic means it compiled AND ran.)
    compile_err = next(
        (l.strip() for l in out.splitlines()
         if ": error: " in l and l.split(":")[0].endswith(".zig")), "")
    if compile_err:
        return "BROKEN", "the mutant did not compile: " + compile_err[:90]
    first = next((l.strip() for l in out.splitlines() if "error:" in l), "")
    return ("RED", "compile: " + first[:90]) if first else ("RED", "")


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
    for tag, fname, old, new, desc, expect in table:
        if MUT.exists():
            shutil.rmtree(MUT)
        shutil.copytree(SRC, MUT, ignore=shutil.ignore_patterns(".zig-cache", "__pycache__"))
        target = MUT / fname
        text = target.read_text()
        n = text.count(old)
        if n != 1:
            kind = "PATCH-MISS" if n == 0 else f"AMBIGUOUS({n})"
            bad_anchor.append((tag, kind, desc))
            print(f"  {tag:<7} {kind:<14} {desc}", flush=True)
            continue
        target.write_text(text.replace(old, new, 1))

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
        print(f"\n⛔ {len(broken)} row(s) could not BUILD -- a defect in this runner's "
              f"module graph, not a verdict about the module.", file=sys.stderr)
        rc = 1
    if bad_anchor:
        print(f"\n⛔ {len(bad_anchor)} anchor(s) no longer name a unique site. A row that "
              f"was not applied is MISSING, not passing -- re-derive it.", file=sys.stderr)
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
