#!/usr/bin/env python3
"""check-tool-module-lists — a tool recipe's hand-written module list must name
every dependency of the modules it builds.

WHY THIS EXISTS
---------------
Some oracles and generators under `modules/<m>/tools/` do not go through
`build.zig`: they call `zig build-exe` / `zig test` themselves with a module
list written out by hand (`--dep jsontext -Mmcp=modules/mcp/src/root.zig
-Mjsontext=modules/jsontext/src/root.zig`). When a module gains a dependency in
`build.zig` (`.deps`), every such list that builds it goes stale, and nothing
local notices: the recipes are compiled only by the full-CI `interop` lane, or
by hand. Full CI 42535103239 (2026-11-08) went red that way after the
duplicate-code pass gave `mcp` a `jsontext` dependency (`no module named
'jsontext' available within module 'mcp'`); the fix commit found the same stale
list in three more tool recipes (framing, kv, sealedbox).

WHAT IT CHECKS
--------------
For every text file under `modules/*/tools/`: each `-M<name>=modules/<m>/src/root.zig`
names a module `<m>`; every direct `.deps` entry `<d>` of `<m>` in `build.zig`
must also appear in the same file as `-M<d>=modules/<d>/src/root.zig`. Checking
the direct dependencies of every module present covers the whole closure.

⛔ WHAT IT CANNOT SEE
--------------------
A list assembled at run time (a loop over names, a variable holding the path),
build-option modules (`zl_options`), and the `--dep` flags themselves (which
module may import which) — `zig` reports those as soon as the recipe compiles.
The union is per file, so a file with two recipes is checked as one.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROW_RE = re.compile(r'^\s*\.\{\s*\.name\s*=\s*"([\w-]+)"(.*)$')
DEPS_RE = re.compile(r'\.deps\s*=\s*&\.\{([^}]*)\}')
M_RE = re.compile(r'-M(\w+)=modules/([\w-]+)/src/root\.zig')
TEXT_SUFFIXES = {".zig", ".py", ".sh", ".md", ".js", ".ts", ".mjs", ".txt", ""}


def module_deps() -> dict[str, list[str]]:
    deps: dict[str, list[str]] = {}
    for line in (ROOT / "build.zig").read_text().splitlines():
        m = ROW_RE.match(line)
        if not m:
            continue
        name = m.group(1)
        if not (ROOT / "modules" / name / "src" / "root.zig").is_file():
            continue
        d = DEPS_RE.search(m.group(2))
        deps[name] = re.findall(r'"([\w-]+)"', d.group(1)) if d else []
    return deps


def main() -> int:
    deps = module_deps()
    if len(deps) < 100:
        print(f"check-tool-module-lists: read only {len(deps)} module rows from build.zig -- parser out of date")
        return 1
    bad = 0
    files = 0
    for f in sorted((ROOT / "modules").glob("*/tools/**/*")):
        if not f.is_file() or f.suffix not in TEXT_SUFFIXES or "__pycache__" in f.parts:
            continue
        try:
            text = f.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        present = {m for _, m in M_RE.findall(text)}
        if not present:
            continue
        files += 1
        for m in sorted(present):
            missing = [d for d in deps.get(m, []) if d not in present]
            if missing:
                bad += 1
                print(f"{f.relative_to(ROOT)}: builds `{m}` without its dependencies {', '.join(missing)} "
                      f"(build.zig .deps of {m}); add -M<d>=modules/<d>/src/root.zig and the --dep")
    if bad:
        print(f"check-tool-module-lists: {bad} stale module list(s) in tool recipes")
        return 1
    print(f"check-tool-module-lists: OK ({files} tool files with hand-written module lists)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
