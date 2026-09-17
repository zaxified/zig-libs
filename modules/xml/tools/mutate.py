#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fault injection: would this module's suite notice if a guard were removed?

    modules/xml/tools/mutate.py               # the whole table
    modules/xml/tools/mutate.py --only M21    # rows whose id contains "M21"
    modules/xml/tools/mutate.py --controls    # only the controls

RED   = the suite noticed (the guard is pinned by a test)
GREEN = the suite passed with the guard gone (it is INVISIBLE to the tests)

Mutations come in two strengths, because REMOVING a check is a coarser probe
than WEAKENING it: a removal often breaks something obvious, while a bound moved
by one, or a comparison narrowed to a prefix, is exactly the shape a suite
misses. Nine of the audit's eleven survivors were weakenings.

⚠ THIS MODULE IS MULTI-FILE, AND THE SCRATCH COPY MUST BE THE WHOLE TREE.
`root.zig` pulls in `xmlconf_test.zig`, which pulls in `xmlconf_vectors.zig`,
which `@embedFile`s 130 fixtures from `src/testdata/xmlconf/`. Copying only the
three `.zig` files builds nothing: measured 2026-09-17, it dies with
`unable to open 'testdata/xmlconf/sun-valid/valid/dtd00.xml': FileNotFound`.
`@embedFile` binds the copy to DATA, not just to source -- the three
single-file modules migrated before this one never had to care.

⚠ EVERY VARIANT GETS ITS OWN --cache-dir. A shared one served a STALE binary
elsewhere in this campaign and turned 18 mutations into false PASSes.

⚠ THE COMMAND LINE ROTS SEPARATELY FROM THE ANCHORS. The audit runner drove a
bare `zig test root.zig` from `mut/`. Measured today it fails at `root.zig:2594`
with `no module named 'testkit'`; the module graph below is what it needs.
A dry run cannot see this -- 33 of the audit's 34 anchors still matched their
site exactly once.

⚠ ONE ANCHOR ROTTED, AND BECAUSE THE FINDING WAS FIXED. `M21` named the whole
recursive `findByAttrRec`. Audit F5-zbytek replaced that machine recursion with
an explicit heap stack AND changed the public signature (`findByAttr` now takes
an allocator and returns an error union), so the old text matches zero times.
The row below is re-derived against the new body.

⚠ BROKEN IS NOT RED. A mutant that fails to compile ran nothing; scoring it as
"the suite noticed" would report a measurement that never happened. The audit
hit this twice (M14, M25 died on `unused local constant` / `unused function
parameter`) and re-derived them compile-clean as M14b/M25b -- the same cure this
campaign later proved on s7comm's D2. Both forms are kept below: the original is
the honest record of what was tried, the `b` form is what measures.

⚠ TWO CONTROLS POINTING OPPOSITE WAYS. `NC-no-edit` must come back GREEN (the
unmutated suite passes). `PC-idguard` deletes the DuplicateId guard and must
come back RED. The audit runner had only the first kind and no exit code.
"""
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
SRC_DIR = ROOT / "modules/xml/src"
TESTKIT = ROOT / "modules/testkit/src/root.zig"
WORK = ROOT / f".zig-cache/xml-mutate/run-{os.getpid()}"

# ── the re-derived M21 (audit F5-zbytek moved this whole body) ───────────────
_FIND_BY_ATTR_BODY = """        if (self.root.attr(uri, local)) |v| {
            if (std.mem.eql(u8, v, value)) return self.root;
        }
        var stack: std.ArrayList([]const Child) = .empty;
        defer stack.deinit(alloc);
        try stack.append(alloc, self.root.children);
        while (stack.items.len > 0) {
            const top = &stack.items[stack.items.len - 1];
            if (top.len == 0) {
                _ = stack.pop();
                continue;
            }
            const c = top.*[0];
            top.* = top.*[1..];
            switch (c.content) {
                .element => |el| {
                    if (el.attr(uri, local)) |v| {
                        if (std.mem.eql(u8, v, value)) return el;
                    }
                    try stack.append(alloc, el.children);
                },
                else => {},
            }
        }
        return null;"""

_FIND_BY_ATTR_LAST = """        var last: ?*Element = null;
        if (self.root.attr(uri, local)) |v| {
            if (std.mem.eql(u8, v, value)) last = self.root;
        }
        var stack: std.ArrayList([]const Child) = .empty;
        defer stack.deinit(alloc);
        try stack.append(alloc, self.root.children);
        while (stack.items.len > 0) {
            const top = &stack.items[stack.items.len - 1];
            if (top.len == 0) {
                _ = stack.pop();
                continue;
            }
            const c = top.*[0];
            top.* = top.*[1..];
            switch (c.content) {
                .element => |el| {
                    if (el.attr(uri, local)) |v| {
                        if (std.mem.eql(u8, v, value)) last = el;
                    }
                    try stack.append(alloc, el.children);
                },
                else => {},
            }
        }
        return last;"""

# (id, description, needle, replacement, expect)
MUT = [
    ('NC-no-edit', 'negative control: no edit at all', None, None, 'GREEN'),
    ('PC-idguard', 'positive control: delete the DuplicateId guard',
     "if (gop.found_existing) return error.DuplicateId;",
     "if (gop.found_existing) {}", 'RED'),

    ('M02', 'weaken: DuplicateId compares only the first 8 bytes of the value',
     "const gop = try self.ids.getOrPut(self.a, at.value);",
     "const gop = try self.ids.getOrPut(self.a, at.value[0..@min(at.value.len, 8)]);", 'RED'),
    ('M03', 'weaken: register only the FIRST id-typed attribute on an element',
     "            if (!is_id) continue;",
     "            if (!is_id) continue;\n            if (el.attributes.len > 1 and !std.mem.eql(u8, at.local, el.attributes[0].local)) continue;", 'RED'),
    ('M04', 'delete: depth limit',
     "if (self.stack.items.len + 1 > self.opts.max_depth) return error.MaxDepthExceeded;",
     "if (false) return error.MaxDepthExceeded;", 'RED'),
    ('M05', 'delete: max_elements limit',
     "if (self.n_elements > self.opts.max_elements) return error.TooManyElements;",
     "if (false) return error.TooManyElements;", 'RED'),
    ('M06', 'weaken: depth limit off by one',
     "if (self.stack.items.len + 1 > self.opts.max_depth) return error.MaxDepthExceeded;",
     "if (self.stack.items.len + 1 > self.opts.max_depth + 1) return error.MaxDepthExceeded;", 'RED'),
    ('M07', 'weaken: max_attributes off by one',
     "if (raw.items.len >= self.opts.max_attributes) return error.TooManyAttributes;",
     "if (raw.items.len > self.opts.max_attributes) return error.TooManyAttributes;", 'RED'),
    ('M08', 'fail-open: undeclared ELEMENT prefix resolves to no namespace',
     "el.uri = el.resolveNsCounted(name.prefix, &probes) orelse return error.UndeclaredNamespacePrefix;",
     "el.uri = el.resolveNsCounted(name.prefix, &probes) orelse \"\";", 'RED'),
    ('M09', 'fail-open: undeclared ATTRIBUTE prefix resolves to no namespace',
     "at.uri = el.resolveNsCounted(at.prefix, &probes) orelse return error.UndeclaredNamespacePrefix;",
     "at.uri = el.resolveNsCounted(at.prefix, &probes) orelse \"\";", 'RED'),
    # ⚠ audit F3 lived here: this survived, and the CR reached c14n as 0d 0a.
    ('M10', 'delete: CR/LF normalisation in text',
     "            } else if (c == '\\r') {\n                // Line-ending normalization: \\r\\n and \\r \u2192 \\n.\n                try out.append(self.a, '\\n');",
     "            } else if (c == '\\r') {\n                // MUTATED\n                try out.append(self.a, '\\r');", 'GREEN'),
    ('M11', 'fail-open: an unknown entity expands to nothing instead of erroring',
     "        } else {\n            return error.UndefinedEntity;\n        }",
     "        } else {\n            // MUTATED\n        }", 'RED'),
    ('M12', 'weaken: duplicate-attribute check ignores the namespace URI',
     "                    if (std.mem.eql(u8, a1.uri, a2.uri) and std.mem.eql(u8, a1.local, a2.local)) {",
     "                    if (std.mem.eql(u8, a1.local, a2.local) and a1.uri.len == a2.uri.len and false) {", 'RED'),
    ('M13', 'weaken: isXmlChar admits surrogates',
     "    return cp == 0x9 or cp == 0xA or cp == 0xD or\n        (cp >= 0x20 and cp <= 0xD7FF) or",
     "    return cp == 0x9 or cp == 0xA or cp == 0xD or\n        (cp >= 0x20 and cp <= 0xDFFF) or", 'GREEN'),
    # ⚠ M14 is the audit's COMPILE-BROKEN form, kept as the honest record;
    # M14b is the compile-clean re-derivation that actually measures.
    ('M14', 'delete: required whitespace between attributes (audit form: leaves a local unused)',
     "            if (self.i == before_ws) return error.UnexpectedChar;",
     "            if (false) return error.UnexpectedChar;", 'BROKEN'),
    ('M14b', 'delete: required whitespace between attributes (compile-clean)',
     "            if (self.i == before_ws) return error.UnexpectedChar;",
     "            _ = before_ws;", 'RED'),
    ('M15', 'delete: literal ]]> rejected in character data (XML sec2.4)',
     "            } else if (c == ']' and self.starts(\"]]>\")) {",
     "            } else if (false) {", 'RED'),
    ('M16', 'delete: up-front UTF-8 validation',
     "    if (!std.unicode.utf8ValidateSlice(source)) return error.InvalidCharacter;",
     "    if (false) return error.InvalidCharacter;", 'GREEN'),
    ('M17', 'delete: DOCTYPE rejected by default',
     "        if (self.opts.doctype == .reject) return error.DoctypeForbidden;",
     "        if (false) return error.DoctypeForbidden;", 'RED'),
    ('M18', 'weaken: xml/xmlns reserved-URI binding check removed',
     "                    if (std.mem.eql(u8, ra.value, xml_ns)) return error.NamespaceError; // xml URI reserved",
     "                    if (false) return error.NamespaceError; // MUTATED", 'RED'),
    ('M19', 'weaken: name length cap doubled',
     "        if (name.len > self.opts.max_name_len) return error.NameTooLong;",
     "        if (name.len > self.opts.max_name_len * 2) return error.NameTooLong;", 'RED'),
    ('M20', 'weaken: char-ref upper bound raised past U+10FFFF (hex path)',
     "                    if (cp > 0x10FFFF) return error.InvalidCharRef;\n                }\n            } else {",
     "                    if (cp > 0x1FFFFF) return error.InvalidCharRef;\n                }\n            } else {", 'GREEN'),
    # ⚠ RE-DERIVED against the post-F5-zbytek heap-stack body.
    ('M21', 'weaken: findByAttr returns the LAST match, not the first (document order unpinned)',
     _FIND_BY_ATTR_BODY, _FIND_BY_ATTR_LAST, 'GREEN'),
    ('M22', 'delete: attribute-value whitespace normalisation (tab/LF kept verbatim)',
     "            } else if (c == '\\t' or c == '\\n') {\n                // Attribute-value normalization: literal whitespace \u2192 space.\n                try out.append(self.a, ' ');",
     "            } else if (c == '\\t' or c == '\\n') {\n                // MUTATED\n                try out.append(self.a, c);", 'RED'),
    ('M23', 'delete: colon forbidden in a PI target',
     "        if (std.mem.indexOfScalar(u8, target, ':') != null) return error.NamespaceError;",
     "        if (false) return error.NamespaceError;", 'RED'),
    ('M24', 'weaken: reserved PI target compared case-SENSITIVELY',
     "        if (asciiEqualIgnoreCase(target, \"xml\")) return error.MalformedPI; // reserved",
     "        if (std.mem.eql(u8, target, \"xml\")) return error.MalformedPI; // reserved", 'RED'),
    ('M25', 'weaken: Element.attr ignores the namespace (audit form: leaves a parameter unused)',
     "            if (std.mem.eql(u8, a.uri, uri) and std.mem.eql(u8, a.local, local)) return a.value;",
     "            if (std.mem.eql(u8, a.local, local)) return a.value;", 'BROKEN'),
    ('M25b', 'weaken: Element.attr ignores the namespace URI (compile-clean)',
     "        for (self.attributes) |a| {\n            if (std.mem.eql(u8, a.uri, uri) and std.mem.eql(u8, a.local, local)) return a.value;",
     "        _ = uri;\n        for (self.attributes) |a| {\n            if (std.mem.eql(u8, a.local, local)) return a.value;", 'RED'),
    ('M26', 'delete: xmlns:p="" (prefix undeclaration) rejection',
     "                if (ra.value.len == 0) return error.NamespaceError; // cannot undeclare a prefix in 1.0",
     "                if (false) return error.NamespaceError;", 'RED'),
    ('M27', 'weaken: MismatchedTag compares only the LOCAL name, not the prefix',
     "        if (!std.mem.eql(u8, top.el.prefix, name.prefix) or !std.mem.eql(u8, top.el.local, name.local)) {",
     "        if (!std.mem.eql(u8, top.el.local, name.local)) {", 'RED'),
    ('M28', 'delete: duplicate xmlns declaration on ONE element allowed',
     "        self.countCompare();\n        if (use_hash) return (try seen.getOrPut(self.a, pfx)).found_existing;",
     "        self.countCompare();\n        if (use_hash) { _ = try seen.getOrPut(self.a, pfx); return false; }", 'RED'),
    ('M29', 'weaken: xml:id no longer treated as an ID',
     "            if (std.mem.eql(u8, at.uri, xml_ns) and std.mem.eql(u8, at.local, \"id\")) {\n                is_id = true;",
     "            if (false) {\n                is_id = true;", 'RED'),
    ('M30', 'weaken: Element.attr returns the LAST matching attribute',
     "        for (self.attributes) |a| {\n            if (std.mem.eql(u8, a.uri, uri) and std.mem.eql(u8, a.local, local)) return a.value;\n        }\n        return null;",
     "        var last: ?[]const u8 = null;\n        for (self.attributes) |a| {\n            if (std.mem.eql(u8, a.uri, uri) and std.mem.eql(u8, a.local, local)) last = a.value;\n        }\n        return last;", 'GREEN'),
    ('M31', 'weaken: element span ends one byte early',
     "            el.span.end = self.i;\n            try self.attachFinished(el, root);",
     "            el.span.end = self.i - 1;\n            try self.attachFinished(el, root);", 'RED'),
    ('M32', 'delete: MultipleRootElements guard',
     "            if (root.* != null) return error.MultipleRootElements;",
     "            if (false) return error.MultipleRootElements;", 'RED'),
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
            # ⚠ the WHOLE src/ tree, testdata included -- see the docstring.
            shutil.copytree(SRC_DIR, d / "src",
                            ignore=shutil.ignore_patterns(".zig-cache", "__pycache__"))
            target = d / "src" / "root.zig"
            if needle is not None:
                n = pristine.count(needle)
                if n != 1:
                    kind = "PATCH-MISS" if n == 0 else f"AMBIGUOUS({n})"
                    bad_anchor.append((mid, kind))
                    print(f"  {mid:<8} {kind:<14} {desc}", flush=True)
                    continue
                target.write_text(pristine.replace(needle, repl, 1))
                if target.read_text() == pristine:
                    bad_anchor.append((mid, "DID-NOT-LAND"))
                    print(f"  {mid:<8} DID-NOT-LAND   {desc}", flush=True)
                    continue

            verdict, detail = build_and_run(d)
            results.append((mid, verdict, expect))
            mark = ""
            if verdict == "BROKEN" and expect != "BROKEN":
                broken.append(mid)
            elif expect and verdict != expect:
                mark = f"  ⛔ expected {expect}"
                mismatched.append((mid, verdict, expect))
            print(f"  {mid:<8} {verdict:<14} {desc}{mark}", flush=True)
            if detail:
                print(f"      {detail}", flush=True)
    finally:
        shutil.rmtree(WORK, ignore_errors=True)

    green = [r for r in results
             if r[1] == "GREEN" and not r[0].startswith(("NC-", "PC-"))]
    # ⚠ Count BROKEN from the rows themselves, not from the `broken` list --
    # that list holds only UNPINNED ones. A summary that says "0 BROKEN" above
    # two rows displaying BROKEN is a summary disagreeing with its own output.
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

    rc = 0
    if broken:
        print(f"\n⛔ {len(broken)} UNPINNED row(s) could not BUILD -- a defect in this "
              f"runner, not a verdict about the module.", file=sys.stderr)
        rc = 1
    # ⚠ `M14`/`M25` are pinned BROKEN ON PURPOSE: they are the audit's own
    # compile-broken forms, kept as the record of what was tried, with `M14b`/
    # `M25b` doing the measuring. A pinned BROKEN that starts COMPILING is just
    # as much a change worth failing on as a flipped RED/GREEN -- the mismatch
    # check above covers that direction.
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
