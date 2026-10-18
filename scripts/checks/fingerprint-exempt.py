#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The top-level declarations of build.zig that `module-fingerprints` leaves out
of the MACHINERY hash, computed from the reference graph -- and the check that
build.zig's `fingerprint_exempt` list is exactly that set.

Why (2026-10-10): the machinery hash was all of build.zig minus `module_list`,
so editing any repo check's implementation (the catalog gate, the changelog
check, ...) re-keyed every module and turned the push lane into a cold run of
the whole collection (81/81, 75/75, 88/88 modules per shard; 50+ minutes).
A check's make function cannot change what a module compiles to or what its
tests do, so it does not belong in the key.

The rule, fail-closed:
  * check roots = every build.zig declaration the gate tool reads
    (`defs.X` in `scripts/gates/*.zig`, Zig 0.17: the checks left build.zig
    when custom steps were removed), plus -- for a build.zig that still has
    them -- every identifier named as `.makeFn = X` (or `X.make`) and every
    struct with a `make` method that `build()` allocates;
  * machinery roots = every other identifier `build()` references, plus
    `Module` and `module_list`;
  * exempt = declarations reachable from a check root and NOT reachable from a
    machinery root. Anything reachable from both, or from neither, stays in
    the hash -- a wrong guess can only re-key too much, never too little.

  scripts/checks/fingerprint-exempt.py           # --check: list == computed
  scripts/checks/fingerprint-exempt.py --write   # rewrite the list in build.zig
"""

import glob
import re
import sys

PATH = "build.zig"
DECL = re.compile(r"^(?:pub )?(?:inline )?(?:fn|const|var) ([A-Za-z_][A-Za-z0-9_]*)", re.M)
IDENT = re.compile(r"@?\b[A-Za-z_][A-Za-z0-9_]*\b")
LIST_RE = re.compile(r"(const fingerprint_exempt = \[_\]\[\]const u8\{\n)((?:    \"[^\"\n]*\",\n)*)(\};)")


def strip_comments_and_strings(src):
    src = re.sub(r'"(?:\\.|[^"\\\n])*"', '""', src)
    src = re.sub(r"\\\\[^\n]*", "", src)
    return re.sub(r"//[^\n]*", "", src)


def decls(src):
    marks = [(m.start(), m.group(1)) for m in DECL.finditer(src)]
    out = {}
    for i, (start, name) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(src)
        out[name] = src[start:end]
    return out


def refs(body, names):
    return {t for t in IDENT.findall(body) if t in names}


def compute(src):
    clean = strip_comments_and_strings(src)
    d = decls(clean)
    names = set(d)
    graph = {n: refs(body, names) - {n} for n, body in d.items()}

    build_body = d["build"]
    check_roots = set(re.findall(r"\.makeFn\s*=\s*([A-Za-z_][A-Za-z0-9_]*)", clean))
    # A struct whose `make` is a step function: its own type name in build()
    # is how the step is allocated, not module wiring.
    step_structs = {n for n in names if re.search(r"\bfn make\(", d[n]) and d[n].lstrip().startswith(("const", "pub const"))}
    check_roots |= step_structs
    check_roots &= names
    # A make function named in build() is wiring of a CHECK, not of a module;
    # a declaration the gate tool reads but build() also uses is both, and
    # stays in the hash (it is in `machinery` below).
    machinery_roots = (refs(build_body, names) - check_roots - {"build"}) | {"Module", "module_list"}
    for gate_src in sorted(glob.glob("scripts/gates/*.zig")):
        check_roots |= set(re.findall(r"\bdefs\.([A-Za-z_][A-Za-z0-9_]*)", strip_comments_and_strings(open(gate_src).read())))
    check_roots &= names

    def closure(roots):
        seen, stack = set(), list(roots)
        while stack:
            n = stack.pop()
            if n in seen:
                continue
            seen.add(n)
            stack.extend(graph.get(n, ()))
        return seen

    machinery = closure(machinery_roots)
    checks = closure(check_roots)
    return sorted((checks - machinery) | {"fingerprint_exempt"})


def main():
    src = open(PATH).read()
    want = compute(src)
    m = LIST_RE.search(src)
    if not m:
        sys.exit("fingerprint-exempt: no `const fingerprint_exempt = [_][]const u8{` list in build.zig")
    have = re.findall(r'"([^"]+)"', m.group(2))
    if "--write" in sys.argv:
        body = "".join(f'    "{n}",\n' for n in want)
        open(PATH, "w").write(src[: m.start(2)] + body + src[m.end(2) :])
        print(f"fingerprint-exempt: wrote {len(want)} names")
        return
    if have != want:
        extra = sorted(set(have) - set(want))
        missing = sorted(set(want) - set(have))
        if extra:
            print("fingerprint-exempt: listed but reachable from module wiring (would hide a re-key):", ", ".join(extra))
        if missing:
            print("fingerprint-exempt: exempt by the graph but not listed (only re-keys too much):", ", ".join(missing))
        print("fix: scripts/checks/fingerprint-exempt.py --write")
        sys.exit(1)
    print(f"fingerprint-exempt: OK ({len(want)} declarations out of the machinery hash)")


main()
