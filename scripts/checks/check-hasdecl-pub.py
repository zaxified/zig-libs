#!/usr/bin/env python3
"""check-hasdecl-pub — a `@hasDecl` probe must not look for a private declaration.

WHY THIS EXISTS
---------------
Since Zig 0.17 `@hasDecl(T, "n")` sees only `pub` declarations. A probe that
selects an optional capability — "use the fast path if the sink has `tailPtr`"
— therefore goes quietly false when the capability is declared without `pub`,
and nothing fails: the slow path is correct, the tests stay green, only the
speed is gone. That is how `brotli`'s fast literal loop (`Sink.tailPtr`) and
`lzma`'s `FastSrc.peek` path were dead from the 0.17 migration until § FC of
the maturity log (2026-10-27). The first sweep after that found a third one in
`metrics/tools/bench.zig`: `const net_prefix` without `pub`, so every workload
row was treated as a network one.

WHAT IT CHECKS
--------------
For every `@hasDecl(X, "n")` in a module whose result is SILENT — no
`@compileError` within the next few lines — any container-level declaration of
`n` without `pub` in the same module's `.zig` files. Container-level means not a
local inside a function body: brace depth is tracked per frame, and a `struct`/
`union`/`enum`/`opaque` literal opens a container even inside a function. A
probe that ends in `@compileError` is loud already (a missing `pub` is a build
failure there), so it is not checked.

⛔ WHAT IT CANNOT SEE
--------------------
A consumer's type. `validate_rules`, `noise_stack_bytes`, `cbor_options` and
the other hooks are declared OUTSIDE this repository by the code that uses
them; a consumer who forgets `pub` gets the silent fallback and no library-side
check can tell (`@typeInfo(T).decls` is pub-only too). The module docs have to
say `pub`. It also matches by name within a module only, so a probe whose
candidate types come from another module is not covered.
"""
import re
import sys
from pathlib import Path

LOUD_WITHIN = 6  # lines after the probe in which a `@compileError` makes it loud
PROBE_RE = re.compile(r'@hasDecl\([^,]+,\s*"(\w+)"\)')
DECL_RE = re.compile(r'^\s*(pub\s+)?(?:export\s+|extern\s+)?(?:inline\s+)?(const|var|fn)\s+(\w+)\b')
CONTAINER_RE = re.compile(r'\b(struct|union|enum|opaque)\b[^{]*\{')
STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')


def code(line):
    """The line without string/char literals and `//` comments."""
    if line.lstrip().startswith("\\\\"):
        return ""
    line = STRING_RE.sub('""', line)
    i = line.find("//")
    return line if i < 0 else line[:i]


def private_decls(path):
    """Yield (lineno, name) for each container-level declaration without `pub`."""
    stack = []  # one entry per open brace: "container" or "body"
    for n, raw in enumerate(path.read_text(errors="replace").split("\n"), 1):
        line = code(raw)
        m = DECL_RE.match(line)
        if m and not m.group(1) and not (stack and stack[-1] == "body"):
            yield n, m.group(3)
        # Classify each `{` on the line: a container literal, or a body
        # (function, test, block, initializer — anything a local can live in).
        containers = len(CONTAINER_RE.findall(line))
        for ch in line:
            if ch == "{":
                if containers:
                    stack.append("container")
                    containers -= 1
                else:
                    stack.append("body")
            elif ch == "}" and stack:
                stack.pop()


def main() -> int:
    hits = []
    probes = 0
    for mod in sorted(p for p in Path("modules").iterdir() if p.is_dir()):
        files = sorted(mod.rglob("*.zig"))
        silent = {}  # name -> first probe site
        for f in files:
            text = f.read_text(errors="replace")
            if "@hasDecl" not in text:
                continue
            lines = text.split("\n")
            for i, raw in enumerate(lines):
                if raw.lstrip().startswith("//"):
                    continue
                for m in PROBE_RE.finditer(raw):
                    probes += 1
                    after = "\n".join(lines[i:i + 1 + LOUD_WITHIN])
                    if "@compileError" in after:
                        continue
                    silent.setdefault(m.group(1), f"{f}:{i + 1}")
        if not silent:
            continue
        for f in files:
            for ln, name in private_decls(f):
                if name in silent:
                    hits.append((str(f), ln, name, silent[name]))

    if hits:
        for f, ln, name, site in sorted(hits):
            print(f"{f}:{ln}: `{name}` is declared without `pub`, and {site} probes it with @hasDecl")
        print()
        print("Since Zig 0.17 `@hasDecl` sees only `pub` declarations, so that probe is")
        print("false for this type and the code silently takes its fallback. Make the")
        print("declaration `pub`, or rename it if it is not the capability being probed.")
        return 1

    print(f"check-hasdecl-pub: {probes} @hasDecl probes, no silent one names a private declaration in its module")
    return 0


if __name__ == "__main__":
    sys.exit(main())
