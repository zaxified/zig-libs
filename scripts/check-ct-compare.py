#!/usr/bin/env python3
"""Pin every constant-time comparison the repository currently makes.

## Why this gate exists

`ctap2pin`'s audit (A1 H3) replaced `std.crypto.timing_safe.eql` with
`std.mem.eql` in BOTH PIN protocols and the change survived everything:

  * the module's test suite, 37/37 green -- and no value test can ever see it,
    because the two functions return the same answer for every input
    (`feedback_property_no_value_test_can_see`);
  * `scripts/ctgrind.sh ctap2pin`, measured 2026-09-09: the pinned counts do
    not move by a single context, because on this compiler `std.mem.eql` over
    a fixed-size MAC compiles branch-free too.

That second half matters and is easy to misread. The mutation is not currently
a timing leak -- it is SAFE BY ACCIDENT, exactly like `std.mem.allEqual`
compiling to one `vptest` in `sphinx`. Nothing pins the vectorisation, and a
different LLVM, `ReleaseSafe`, or another target silently turns it back into a
byte loop with an early return. What is missing is not a measurement; it is
something that holds the INTENT in place.

So this gate does the only thing that can be done here: it counts, per file,
how many constant-time comparisons the repository makes today, and goes red if
that number changes. It is a pin, in the same spirit as
`ctgrind-expected.tsv`: it does not prove the code is right, it proves nobody
quietly stopped doing the thing they decided to do.

## What it does NOT do

⛔ It does not check that the RIGHT values are compared, nor that a module
which should make a constant-time comparison makes one. A module that has never
had a `timing_safe` call has no row here and this gate says nothing about it.
Read a green run as "no site regressed", never as "all comparisons are safe".

## Aliases

⚠ A literal grep for `timing_safe.eql` measures a smaller world than it looks
like: `iec62351/src/goose.zig` writes `const ts = std.crypto.timing_safe;` and
`opaque/src/root.zig` writes `const timing_safe = std.crypto.timing_safe;`, so
two of the repository's users would have been invisible to it. This resolves
`const` aliases to a fixpoint before counting -- the same defect
`feedback_my_own_lint_measured_a_smaller_world` records, where an anchor on the
literal `std.testing.fuzz` missed 271 calls made through an alias.
"""

import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PIN = os.path.join(REPO, "scripts", "ct-compare-expected.tsv")

# `timing_safe` exposes three comparisons; all of them are the posture this
# gate is about, and a swap between them is as much a regression as a swap to
# `std.mem`.
CT_FNS = ("eql", "lt", "gt")
# The value-equal, timing-unequal replacements a mutation reaches for.
PLAIN_FNS = ("eql", "eqlBytes")


def strip_comments(src: str) -> str:
    """Drop `//` comments without touching `//` inside a string literal.

    Zig has no block comments, so this is a per-line scan. Character literals
    cannot contain `//` in any form that matters here.
    """
    out = []
    for line in src.split("\n"):
        in_str = False
        esc = False
        cut = len(line)
        i = 0
        while i < len(line):
            c = line[i]
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = not in_str
            elif c == "/" and not in_str and line[i : i + 2] == "//":
                cut = i
                break
            i += 1
        out.append(line[:cut])
    return "\n".join(out)


def resolve_aliases(src: str, root: str) -> set:
    """Every expression in `src` that names `root` (e.g. `std.crypto.timing_safe`).

    Follows `const A = <expr>;` to a fixpoint, so `const c = std.crypto;` plus
    `const ts = c.timing_safe;` both resolve.
    """
    names = {root}
    # `std.crypto.timing_safe` -> also reachable as `<alias of std.crypto>.timing_safe`
    parts = root.split(".")
    consts = dict(re.findall(r"\bconst\s+(\w+)\s*=\s*([\w.]+)\s*;", src))
    for _ in range(4):  # fixpoint; depth beyond this does not occur in practice
        grew = False
        for name, value in consts.items():
            if value in names and name not in names:
                names.add(name)
                grew = True
            # `const c = std.crypto;` makes `c.timing_safe` a name for the root
            for i in range(1, len(parts)):
                prefix, suffix = ".".join(parts[:i]), ".".join(parts[i:])
                if value == prefix or value in names:
                    cand = f"{name}.{suffix}"
                    if value == prefix and cand not in names:
                        names.add(cand)
                        grew = True
        if not grew:
            break
    return names


def count_calls(src: str, roots: set, fns) -> int:
    total = 0
    for root in roots:
        for fn in fns:
            pattern = r"(?<![\w.])" + re.escape(root) + r"\." + fn + r"\s*\("
            total += len(re.findall(pattern, src))
    return total


def measure(path: str):
    with open(path, encoding="utf-8") as fh:
        src = strip_comments(fh.read())
    ct_roots = resolve_aliases(src, "std.crypto.timing_safe")
    plain_roots = resolve_aliases(src, "std.mem")
    return count_calls(src, ct_roots, CT_FNS), count_calls(src, plain_roots, PLAIN_FNS)


def scan_all():
    """Every module source file that makes at least one constant-time comparison."""
    found = {}
    modules_dir = os.path.join(REPO, "modules")
    for module in sorted(os.listdir(modules_dir)):
        src_dir = os.path.join(modules_dir, module, "src")
        if not os.path.isdir(src_dir):
            continue
        for name in sorted(os.listdir(src_dir)):
            if not name.endswith(".zig") or name == "ctgrind_harness.zig":
                continue
            rel = f"modules/{module}/src/{name}"
            ct, plain = measure(os.path.join(src_dir, name))
            if ct:
                found[rel] = (ct, plain)
    return found


def read_pin():
    rows = {}
    if not os.path.exists(PIN):
        return rows
    with open(PIN, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            path, ct, plain = line.split("\t")
            rows[path] = (int(ct), int(plain))
    return rows


HEADER = """\
# Constant-time comparison sites, pinned. See scripts/check-ct-compare.py for
# why this file exists -- in short: swapping `std.crypto.timing_safe.eql` for
# `std.mem.eql` is invisible to every value test AND to ctgrind (measured on
# ctap2pin, 2026-09-09: not one context moves), so the only thing that can hold
# the decision in place is a count that goes red when it changes.
#
# path<TAB>constant-time compares<TAB>plain std.mem compares in the same file
#
# ⚠ The second column is context, not a verdict: plenty of files legitimately
# compare public bytes with `std.mem.eql`. It is pinned so that a swap shows up
# as BOTH a drop on the left and a rise on the right, which is what a mutation
# looks like and what a refactor usually does not.
"""


def write_pin(rows):
    with open(PIN, "w", encoding="utf-8") as fh:
        fh.write(HEADER)
        for path in sorted(rows):
            ct, plain = rows[path]
            fh.write(f"{path}\t{ct}\t{plain}\n")


def main() -> int:
    update = "--update" in sys.argv
    found = scan_all()

    if update:
        write_pin(found)
        print(f"check-ct-compare: pinned {len(found)} file(s) in scripts/ct-compare-expected.tsv")
        return 0

    pinned = read_pin()
    if not pinned:
        print(
            "check-ct-compare: scripts/ct-compare-expected.tsv is empty or missing — "
            "run scripts/check-ct-compare.py --update",
            file=sys.stderr,
        )
        return 2

    # ⛔ A gate that scans nothing also exits zero. If the scan finds no
    # constant-time comparison anywhere, the pin cannot have been satisfied
    # honestly and the scanner itself is what broke.
    if not found:
        print(
            "check-ct-compare: the scan found NO constant-time comparison in any module. "
            "That is not a code change, that is this script failing to see the tree.",
            file=sys.stderr,
        )
        return 2

    fail = 0
    for path in sorted(pinned):
        want_ct, want_plain = pinned[path]
        if not os.path.exists(os.path.join(REPO, path)):
            print(f"FAIL {path}: pinned file no longer exists — re-pin deliberately.", file=sys.stderr)
            fail = 1
            continue
        got_ct, got_plain = found.get(path, measure(os.path.join(REPO, path)))
        if got_ct != want_ct or got_plain != want_plain:
            print(
                f"FAIL {path}: constant-time compares {got_ct} (pinned {want_ct}), "
                f"plain std.mem compares {got_plain} (pinned {want_plain}).",
                file=sys.stderr,
            )
            if got_ct < want_ct:
                print(
                    "     A DROP on the left is the mutation this gate exists for: a "
                    "constant-time comparison became a value-equal one. No test and no "
                    "ctgrind row can see that — check the diff before re-pinning.",
                    file=sys.stderr,
                )
            fail = 1

    for path in sorted(found):
        if path not in pinned:
            print(
                f"FAIL {path}: makes a constant-time comparison but is not pinned — "
                f"add it with scripts/check-ct-compare.py --update.",
                file=sys.stderr,
            )
            fail = 1

    if fail:
        return 1
    print(f"check-ct-compare: {len(pinned)} file(s) hold their constant-time comparisons")
    return 0


if __name__ == "__main__":
    sys.exit(main())
