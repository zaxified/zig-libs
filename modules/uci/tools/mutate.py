#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fault injection: would this module's suite notice if a guard were removed?

    modules/uci/tools/mutate.py               # the whole table
    modules/uci/tools/mutate.py --only quote  # rows whose name contains "quote"
    modules/uci/tools/mutate.py --controls    # only the positive controls

RED   = the suite noticed (the guard is pinned by a test)
GREEN = the suite passed with the guard gone (the guard is INVISIBLE to it)

Mutations come in two strengths, because REMOVING a check is a coarser probe
than WEAKENING it: a removal often breaks something obvious, while a bound
moved by one, or a comparison narrowed to a prefix, is exactly the shape a
suite misses.

⚠ Every row copies the LIVE `modules/uci/src/` into a per-process scratch tree
and mutates the copy. Never a snapshot of its own (CONVENTIONS.md §9).

⚠ EVERY VARIANT GETS ITS OWN --cache-dir. A shared one served a STALE binary in
this campaign and turned 18 mutations into false PASSes. That rule is inherited
from the audit runner and kept deliberately.

⚠ THE COMMAND LINE ROTS SEPARATELY FROM THE ANCHORS, and only running catches
it. The audit runner drove `zig test root.zig` with no module graph. Measured
2026-09-17 against the live module: it fails at `root.zig:1921` with
`no module named 'testkit'`; with `--dep testkit` the same suite is
`53/53, rc=0`. A dry run cannot see this -- 19 of its 33 anchors still matched
their site exactly once.

⚠ AND 13 ANCHORS HAD ROTTED. The U5/U6 tokenizer rewrite (2026-09-11) and the
U8/U9/U10/U17/U19 batch (2026-09-13) grew root.zig from 1452 to 2621 lines, so
the old texts named code that no longer exists -- `LineTooLong` is now checked
as `end - start > max_line_len` inside `checkLineLenAt`, CR is folded in
`bump`/`quoteByte` instead of stripped per line, and so on. Each was re-derived
against the current source and verified to match exactly once; a row that does
not apply is reported as PATCH-MISS, never scored.
"""
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
SRC = ROOT / "modules/uci/src"
TESTKIT = ROOT / "modules/testkit/src/root.zig"
WORK = ROOT / f".zig-cache/uci-mutate/run-{os.getpid()}"

# (name, needle, replacement, expect)
#
# `expect` is None until measured. The audit's verdicts are NOT copied forward:
# all 19 findings have been closed since, and a fix is exactly what turns a row
# from GREEN to RED.
MUT = [
    ('POSCTL_serializer_never_quotes',
     '    if (!needs_double) {',
     '    if (true) {', 'RED'),
    ('POSCTL_list_becomes_single',
     '                .list => {\n                    try ob.values.append(p.arena, value);\n                    p.total_items += 1; // one new value',
     '                .list => {\n                    ob.values.clearRetainingCapacity();\n                    try ob.values.append(p.arena, value);\n                    p.total_items += 1; // one new value', 'RED'),
    ('del_input_too_large',
     '    if (bytes.len > max_input_len) {',
     '    if (false) {', 'RED'),
    ('del_line_too_long',
     '        if (end - start > max_line_len) return error.LineTooLong;',
     '        if (false) return error.LineTooLong;', 'RED'),
    ('del_option_outside_section',
     'if (p.current == null) return error.OptionOutsideSection;',
     'if (false) return error.OptionOutsideSection;', 'RED'),
    ('del_mixed_option_list',
     'if (ob.kind != kind) return error.MixedOptionList;',
     'if (false) return error.MixedOptionList;', 'RED'),
    # ⚠ `else => return,` does NOT compile: endStatement returns ParseError!bool,
    # so a bare return is void. Swallowing the rest of the line and reporting
    # "statement ended" is the real weakening -- and it must consume the input,
    # or the caller re-reads the same byte forever instead of failing a test.
    ('del_too_many_args_config',
     '            else => return error.TooManyArguments,',
     '            else => {\n                p.skipToEndOfLine();\n                return false;\n            },', 'RED'),
    # ⚠ `if (false)` leaves the loop capture `c` unused and the mutant does not
    # build. SPEND the value instead (`c != c` is always false) -- same cure as
    # s7comm's D2, and for the same reason: a row that fails to compile scores
    # RED while nothing ever ran.
    ('del_unserializable_value',
     '        if (isEscapelessControl(c)) return error.UnserializableValue;',
     '        if (c != c) return error.UnserializableValue;', 'RED'),
    ('del_bad_keyword',
     '                if (after_separator) return error.BadKeyword;',
     '                if (false) return error.BadKeyword;', 'RED'),
    ('del_unterminated_single_quote',
     "                        if (p.pos >= p.bytes.len) return error.UnterminatedQuote;\n                        const d = try p.quoteByte();\n                        if (d == '\\'') break;",
     "                        if (p.pos >= p.bytes.len) break;\n                        const d = try p.quoteByte();\n                        if (d == '\\'') break;", 'RED'),
    ('del_unterminated_double_quote',
     '                        if (p.pos >= p.bytes.len) return error.UnterminatedQuote;\n                        const d = try p.quoteByte();\n                        if (d == \'"\') break;',
     '                        if (p.pos >= p.bytes.len) break;\n                        const d = try p.quoteByte();\n                        if (d == \'"\') break;', 'RED'),
    ('weak_input_cap_plus_4k',
     '    if (bytes.len > max_input_len) {',
     '    if (bytes.len > max_input_len + 4096) {', 'RED'),
    ('weak_line_cap_off_by_one',
     '        if (end - start > max_line_len) return error.LineTooLong;',
     '        if (end - start > max_line_len + 1) return error.LineTooLong;', 'RED'),
    ('weak_unserializable_only_nul',
     "    return c < 0x20 and c != '\\t' and c != '\\n' and c != '\\r';",
     '    return c == 0;', 'RED'),
    ('weak_unserializable_allows_newline',
     "    return c < 0x20 and c != '\\t' and c != '\\n' and c != '\\r';",
     "    return c < 0x20 and c != '\\t' and c != '\\n' and c != '\\r' and c != 0x0b;", 'GREEN'),
    ('weak_needs_double_ignores_ctrl',
     "        if (c == '\\'' or isEscapelessControl(c)) {",
     "        if (c == '\\'') {", 'RED'),
    ('weak_baresafe_allows_hash',
     "    return std.ascii.isAlphanumeric(c) or c == '_' or c == '-';",
     "    return std.ascii.isAlphanumeric(c) or c == '_' or c == '-' or c == '#';", 'GREEN'),
    ('weak_baresafe_allows_space',
     "    return std.ascii.isAlphanumeric(c) or c == '_' or c == '-';",
     "    return std.ascii.isAlphanumeric(c) or c == '_' or c == '-' or c == ' ';", 'GREEN'),
    ('weak_baresafe_allows_squote',
     "    return std.ascii.isAlphanumeric(c) or c == '_' or c == '-';",
     "    return std.ascii.isAlphanumeric(c) or c == '_' or c == '-' or c == '\\'';", 'RED'),
    ('weak_empty_name_stays_named',
     '                .anonymous = sec_name == null,',
     '                .anonymous = false,', 'GREEN'),
    ('weak_dup_option_accumulates',
     '                    ob.values.clearRetainingCapacity();',
     '                    if (false) ob.values.clearRetainingCapacity();', 'RED'),
    ('weak_nth_drops_negative_form',
     '        if (idx < 0) idx += count;',
     '        if (false) idx += count;', 'RED'),
    ('weak_nth_upper_bound_only',
     '        if (idx < 0 or idx >= count) return null;',
     '        if (idx >= count) return null;', 'GREEN'),
    # ⚠ Dropping the type test leaves the PARAMETER `section_type` unused, which
    # is a compile error in Zig. `section_type.len != section_type.len` is always
    # false, so `or` falls through to the name test: the type is ignored, which
    # is the mutation, and the parameter is spent, which lets it build.
    ('weak_section_ignores_type',
     'if (std.mem.eql(u8, s.type, section_type) and std.mem.eql(u8, n, name)) return s;',
     'if (section_type.len != section_type.len or std.mem.eql(u8, n, name)) return s;', 'RED'),
    ('weak_option_lookup_prefix_match',
     '            if (std.mem.eql(u8, o.key, key)) return o;',
     '            if (std.mem.startsWith(u8, o.key, key)) return o;', 'RED'),
    # ⚠ weak_addoption_prefix_match DROPPED: U2's fix replaced addOption's linear std.mem.eql scan with a hash index (cur.index.get(key)), so the guard this weakened no longer exists; the fix itself is pinned by `addOption is not quadratic in distinct keys per section`.

    ('weak_crlf_strips_any_last_byte',
     "        if (end > start and p.bytes[end - 1] == '\\r') end -= 1;",
     '        if (end > start) end -= 1;', 'RED'),
    ('weak_iterate_prefix_match',
     '            if (std.mem.eql(u8, s.type, it.section_type)) return s;',
     '            if (std.mem.startsWith(u8, s.type, it.section_type)) return s;', 'RED'),
    ('weak_sectionbyname_prefix_match',
     '            if (std.mem.eql(u8, n, name)) return s;',
     '            if (std.mem.startsWith(u8, n, name)) return s;', 'RED'),
    ('weak_writeword_empty_emitted_bare',
     '    return writeValue(gpa, out, word);\n}',
     '    return out.appendSlice(gpa, word);\n}', 'RED'),
    ('weak_nth_counts_named_only',
     '            if (std.mem.eql(u8, s.type, section_type)) count += 1;',
     '            if (std.mem.eql(u8, s.type, section_type) and s.name != null) count += 1;', 'RED'),
    ('weak_anonymous_flag_always_false',
     '            .anonymous = sec.name == null,',
     '            .anonymous = false,', 'RED'),
    ('weak_get_returns_last_not_first',
     '        return o.values[0];',
     '        return o.values[o.values.len - 1];', 'RED'),
]


def build_and_run(d):
    """Build and run the mutated copy. Returns (verdict, detail)."""
    r = subprocess.run(
        [str(ROOT / "scripts/capped"), "zig", "test", "-O", "ReleaseSafe",
         # ⚠ own cache dir per variant -- see the module docstring.
         "--cache-dir", str(d / "zc"),
         "--dep", "testkit",
         "-Mroot=" + str(d / "root.zig"),
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
    table = [m for m in MUT if m[0].startswith("POSCTL")]
    if "--controls" not in sys.argv:
        table += [m for m in MUT
                  if not m[0].startswith("POSCTL") and (not only or only in m[0])]

    WORK.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("ZIGLIBS_MEM_MAX", "4G")
    bad_anchor, mismatched, broken, results = [], [], [], []
    try:
        for name, needle, repl, expect in table:
            d = WORK / name
            if d.exists():
                shutil.rmtree(d)
            shutil.copytree(SRC, d, ignore=shutil.ignore_patterns(".zig-cache", "__pycache__"))
            target = d / "root.zig"
            text = target.read_text()
            n = text.count(needle)
            if n != 1:
                kind = "PATCH-MISS" if n == 0 else f"AMBIGUOUS({n})"
                bad_anchor.append((name, kind))
                print(f"  {name:<38} {kind}", flush=True)
                continue
            target.write_text(text.replace(needle, repl, 1))

            verdict, detail = build_and_run(d)
            results.append((name, verdict, expect))
            mark = ""
            if verdict == "BROKEN":
                broken.append(name)
            elif expect and verdict != expect:
                mark = f"  ⛔ expected {expect}"
                mismatched.append((name, verdict, expect))
            print(f"  {name:<38} {verdict}{mark}", flush=True)
            if detail:
                print(f"      {detail}", flush=True)
    finally:
        shutil.rmtree(WORK, ignore_errors=True)

    green = [r for r in results if r[1] == "GREEN" and not r[0].startswith("POSCTL")]
    print(f"\n{len(results)} rows: "
          f"{sum(1 for r in results if r[1] == 'RED')} RED, "
          f"{sum(1 for r in results if r[1] == 'GREEN')} GREEN, "
          f"{len(broken)} BROKEN, {len(bad_anchor)} anchor problems")
    if green:
        print("\nGuards the suite did NOT notice:")
        for name, _, _ in green:
            print(f"   {name}")

    rc = 0
    if broken:
        print(f"\n⛔ {len(broken)} row(s) could not BUILD -- a defect in this runner, "
              f"not a verdict about the module.", file=sys.stderr)
        rc = 1
    if bad_anchor:
        print(f"\n⛔ {len(bad_anchor)} anchor(s) no longer name a unique site. A row that "
              f"was not applied is MISSING, not passing -- re-derive it.", file=sys.stderr)
        rc = 1
    if mismatched:
        print(f"\n⛔ {len(mismatched)} row(s) came back against their pinned verdict.",
              file=sys.stderr)
        rc = 1
    ctl = [r for r in results if r[0].startswith("POSCTL")]
    if not ctl or any(v == "GREEN" for _, v, _ in ctl):
        print(f"\n⛔ A POSITIVE CONTROL SURVIVED (or none ran). The runner is broken and "
              f"every row above is meaningless.", file=sys.stderr)
        rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
