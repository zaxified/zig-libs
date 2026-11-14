#!/usr/bin/env python3
"""check-tool-imports — every module a build.zig-wired tools program imports
must be one build.zig hands it.

WHY THIS EXISTS
---------------
`build.zig` gives each kind of program under `modules/<m>/tools/` a fixed set
of modules to import (see the `moduleHasInterop` / `moduleHasLive` /
`moduleHasBench` / `moduleHasSizeprobe` blocks). A program that imports a
module outside its set compiles nowhere locally: those programs are built only
by the full-CI `interop` lane (`check-interop`), so the error -- `no module
named 'x' available within module 'interop'` -- surfaced after the push, four
times in ten days (CI audit D4, 2026-11-14). The fix is one word in the
module's build.zig row (`interop_deps`, `bench_deps`, ...); this check asks for
it before the push.

WHAT IT CHECKS
--------------
For `tools/interop.zig`, `tools/live.zig`, `tools/bench.zig` and
`tools/sizeprobe.zig` of every module, and every `.zig` file they reach by a
relative `@import` inside `tools/`: each `@import("<name>")` that is not a file,
`std`, `builtin` or `root` must be in the program kind's set:

  interop    the module, deps, test_deps, interop_deps
  live       the module, deps, test_deps
  bench      the module, deps, bench_deps, fastmem, testkit, benchkit
  sizeprobe  the module

Keep the sets in step with build.zig; a set drifting the other way (build.zig
hands more) only makes this check stricter than the build.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROW_RE = re.compile(r'^\s*\.\{\s*\.name\s*=\s*"([\w-]+)"(.*)$')
IMPORT_RE = re.compile(r'@import\("([^"]+)"\)')
BUILTIN = {"std", "builtin", "root"}


def field(rest: str, name: str) -> list[str]:
    m = re.search(r'\.' + name + r'\s*=\s*&\.\{([^}]*)\}', rest)
    return re.findall(r'"([\w-]+)"', m.group(1)) if m else []


def rows() -> dict[str, dict[str, list[str]]]:
    out: dict[str, dict[str, list[str]]] = {}
    for line in (ROOT / "build.zig").read_text().splitlines():
        m = ROW_RE.match(line)
        if not m:
            continue
        name, rest = m.group(1), m.group(2)
        if not (ROOT / "modules" / name / "src" / "root.zig").is_file():
            continue
        out[name] = {k: field(rest, k) for k in ("deps", "test_deps", "interop_deps", "bench_deps")}
    return out


def imports(entry: Path, tools: Path) -> dict[str, Path]:
    """Module names imported by `entry` and the tools/ files it reaches."""
    seen: set[Path] = set()
    found: dict[str, Path] = {}
    todo = [entry]
    while todo:
        f = todo.pop()
        if f in seen or not f.is_file():
            continue
        seen.add(f)
        for name in IMPORT_RE.findall(f.read_text(errors="replace")):
            if name.endswith(".zig") or name.endswith(".zon"):
                nxt = (f.parent / name).resolve()
                if nxt.suffix == ".zig" and tools in nxt.parents:
                    todo.append(nxt)
                continue
            if name not in BUILTIN:
                found.setdefault(name, f)
    return found


def main() -> int:
    table = rows()
    if len(table) < 100:
        print(f"check-tool-imports: read only {len(table)} module rows from build.zig -- parser out of date")
        return 1
    bad = []
    checked = 0
    for m, r in sorted(table.items()):
        tools = (ROOT / "modules" / m / "tools").resolve()
        kinds = {
            "interop": {m, *r["deps"], *r["test_deps"], *r["interop_deps"]},
            "live": {m, *r["deps"], *r["test_deps"]},
            "bench": {m, *r["deps"], *r["bench_deps"], "fastmem", "testkit", "benchkit"},
            "sizeprobe": {m},
        }
        for kind, allowed in kinds.items():
            entry = tools / f"{kind}.zig"
            if not entry.is_file():
                continue
            checked += 1
            for name, where in sorted(imports(entry, tools).items()):
                if name not in allowed:
                    rel = where.relative_to(ROOT)
                    field_name = {"interop": "interop_deps", "bench": "bench_deps"}.get(kind, "deps or test_deps")
                    bad.append(f"{rel}: imports '{name}', which build.zig does not hand a {kind} program of '{m}' "
                               f"(add it to {m}'s `{field_name}` in build.zig)")
    if bad:
        print("check-tool-imports: a tools program imports a module it will not get:", file=sys.stderr)
        for b in bad:
            print("  " + b, file=sys.stderr)
        return 1
    print(f"check-tool-imports: {checked} tools program(s), every import wired")
    return 0


if __name__ == "__main__":
    sys.exit(main())
