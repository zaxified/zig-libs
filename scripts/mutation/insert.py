#!/usr/bin/env python3
"""insert.py — apply a mutant list to a COPY of a module as runtime-switched
schemata (CONVENTIONS.md §9, "the mutation kit").

    insert.py <mutants.tsv> <ENV_NAME>

Each non-comment line of <mutants.tsv> is

    <id> TAB <file> TAB <line> TAB <old> TAB <new>

`<file>` is relative to the current directory (run it inside the detached copy,
never in the tree you commit from). On line `<line>` of `<file>` the text `<old>`
must occur EXACTLY ONCE; it is replaced by `<new>`, which must contain
`mut(<id>)` and keeps the original as its other arm, e.g.

    7  modules/zstd/src/frame.zig  212  if (sfd  if (!mut(7) and sfd

Several mutants may sit on one line: they are applied left to right in file
order of their anchors, each anchor checked against the line as it is after the
ones before it.

Several mutants may share ONE anchor (same file, line and `<old>`, e.g. `<` to
`<=` and to `>`): the first is applied to the line, each later one replaces the
original arm of the one before it, in list order --

    5  f.zig  40  a < b  (if (mut(5)) a <= b else a < b)
    6  f.zig  40  a < b  (if (mut(6)) a > b else a < b)
    -> (if (mut(5)) a <= b else (if (mut(6)) a > b else a < b))

so every earlier `<new>` must contain `<old>` exactly once (its original arm);
a prefix-style one (`if (x` -> `if (!mut(1) and x`) cannot take a second mutant
and is refused with that reason. Every mutated file gets, once, a switch read
from <ENV_NAME>:

    fn mut(n: u32) bool   -- true when <ENV_NAME>=n (0 or unset = the original)

placed after the file's `const std = @import("std");`, or at the end of the file
when there is none (a file opening with a `//!` block must keep it first).

It refuses, before writing anything: an anchor that occurs 0 or 2+ times on its
line, a `<new>` without `mut(<id>)`, a duplicate id, id 0 (reserved for the
original). After writing it counts the distinct `mut(N)` calls per file and
fails unless they equal the list -- a failed insert must never leave an
unmutated copy whose every mutant "survives" (met twice, 2026-10-05).
"""
import re
import sys
from collections import defaultdict
from pathlib import Path

SWITCH = '''
// ── mutant schemata (scripts/mutation/insert.py) ──
var mut_id: ?u32 = null;
fn mut(n: u32) bool {{
    if (@inComptime()) return n == 0;
    if (mut_id == null) {{
        const v = std.testing.environ.getPosix("{env}") orelse "0";
        mut_id = std.fmt.parseInt(u32, v, 10) catch 0;
    }}
    return mut_id.? == n;
}}
'''


def fail(msg: str) -> None:
    print(f"insert.py: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: insert.py <mutants.tsv> <ENV_NAME>")
    spec, env = Path(sys.argv[1]), sys.argv[2]
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", env):
        fail(f"ENV_NAME '{env}' must be UPPER_SNAKE")

    by_file: dict[str, list[tuple[int, int, str, str]]] = defaultdict(list)
    seen: set[int] = set()
    for n, raw in enumerate(spec.read_text().splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        cols = raw.split("\t")
        if len(cols) != 5:
            fail(f"{spec}:{n}: expected 5 tab-separated columns, got {len(cols)}")
        mid, path, line, old, new = int(cols[0]), cols[1], int(cols[2]), cols[3], cols[4]
        if mid == 0:
            fail(f"{spec}:{n}: id 0 is the original")
        if mid in seen:
            fail(f"{spec}:{n}: duplicate id {mid}")
        seen.add(mid)
        if f"mut({mid})" not in new:
            fail(f"{spec}:{n}: replacement lacks mut({mid})")
        by_file[path].append((line, mid, old, new))

    out: dict[str, str] = {}
    for path, muts in by_file.items():
        lines = Path(path).read_text().split("\n")
        # Mutants sharing an anchor become one nested replacement (list order).
        groups: dict[tuple[int, str], list[tuple[int, str]]] = {}
        for line, mid, old, new in muts:
            groups.setdefault((line, old), []).append((mid, new))
        for (line, old), stack in sorted(groups.items(), key=lambda g: (g[0][0], lines[g[0][0] - 1].find(g[0][1]) if 0 < g[0][0] <= len(lines) else 0)):
            mid = stack[0][0]
            if not 0 < line <= len(lines):
                fail(f"{path}:{line} (mutant {mid}): no such line")
            text = lines[line - 1]
            count = text.count(old)
            if count != 1:
                fail(f"{path}:{line} (mutant {mid}): anchor occurs {count} times on the line: {old!r}\n  line: {text}")
            composed = stack[0][1]
            for (prev, _), (nxt, new) in zip(stack, stack[1:]):
                inner = composed.count(old)
                if inner != 1:
                    fail(f"{path}:{line} (mutant {nxt}): shares its anchor with mutant {prev}, whose "
                         f"replacement holds the anchor {inner} times (needs exactly 1, its original arm, "
                         f"to nest into): {old!r}\n  so far: {composed}")
                composed = composed.replace(old, new, 1)
            lines[line - 1] = text.replace(old, composed, 1)
        src = "\n".join(lines)
        anchor = 'const std = @import("std");\n'
        switch = SWITCH.format(env=env)
        src = src.replace(anchor, anchor + switch, 1) if anchor in src else src + switch
        out[path] = src

    for path, src in out.items():
        Path(path).write_text(src)
    for path, muts in by_file.items():
        found = set(int(x) for x in re.findall(r"\bmut\((\d+)\)", Path(path).read_text()))
        want = {m[1] for m in muts}
        if found != want:
            fail(f"{path}: {len(found)} distinct mut(N) after inserting, {len(want)} listed "
                 f"(missing {sorted(want - found)[:8]}, extra {sorted(found - want)[:8]})")
    print(f"insert.py: {len(seen)} mutant(s) in {len(by_file)} file(s), switch {env}")


if __name__ == "__main__":
    main()
