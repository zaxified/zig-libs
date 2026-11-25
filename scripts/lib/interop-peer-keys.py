#!/usr/bin/env python3
"""Per-module digest of the interop peers in scripts/lib/ci-environment.sh.

    interop-peer-keys.py <ci-environment.sh> <module>...

prints one `<module> TAB <12 hex>` line per module. The digest covers the
lines of the script that can change what module's interop take runs against:

  * every line inside an `if needs ...; then` block that names the module
    (nested blocks: the module must be named by every enclosing one), and
  * every line outside any `needs` block (the shared preamble, the userns
    setup, apt-get update, the Go module caches...),

minus lines that only a role other than `interop` runs (`if want tests;`,
`if want ctgrind;`), comment-only lines and blank lines. So a pin bump in the
mqttz block re-takes mqtt only, a comment edit re-takes nothing, and an edit to
a shared line re-takes everything -- which it may well affect.

The block structure is read from COLUMN-0 `if ... then` / `fi` lines only, the
script's own layout (nested shell inside a block is indented or one-line). If
that structure does not close cleanly, every module gets the digest of the
whole file: the old key, never a weaker one.
"""
import hashlib
import re
import sys

NEEDS = re.compile(r"^if needs ((?:[A-Za-z0-9_-]+ ?)+); then$")
WANT = re.compile(r"^if (want .+); then$")
OPENS = re.compile(r"^if .*\bthen$")
CLOSES = re.compile(r"^(fi|.*; fi)$")


def roles_of(cond: str):
    """`want tests || want interop` -> {"tests", "interop"}; None if not a pure want test."""
    roles = set()
    for part in cond.split("||"):
        m = re.fullmatch(r"\s*want ([a-z]+)\s*", part)
        if not m:
            return None
        roles.add(m.group(1))
    return roles


def parse(text: str):
    """Returns [(line, needs_sets, interop_ok)] or None when the structure does not close."""
    stack = []  # entries: ("needs", set) | ("want", bool) | ("other", None)
    out = []
    # Continuation lines are one logical line; a heredoc body is content only.
    logical, pending = [], ""
    for raw in text.splitlines():
        if raw.endswith("\\"):
            pending += raw[:-1] + " "
            continue
        logical.append(pending + raw)
        pending = ""
    if pending:
        logical.append(pending)
    heredoc = None
    for raw in logical:
        line = raw.rstrip()
        if heredoc is not None:
            if line == heredoc:
                heredoc = None
            out.append((line, [e[1] for e in stack if e[0] == "needs"], all(e[1] for e in stack if e[0] == "want")))
            continue
        hd = re.search(r"<<-?'?([A-Za-z_]+)'?", line)
        if hd and not line.lstrip().startswith("#"):
            heredoc = hd.group(1)
        if line.startswith("if ") and not line.endswith("fi"):
            if not OPENS.match(line):
                return None  # `then` on its own line: not this script's layout
            m = NEEDS.match(line)
            w = WANT.match(line)
            if m:
                entry = ("needs", set(m.group(1).split()))
            elif w and roles_of(w.group(1)) is not None:
                entry = ("want", "interop" in roles_of(w.group(1)) or "all" in roles_of(w.group(1)))
            else:
                entry = ("other", None)
            out.append((line, [e[1] for e in stack if e[0] == "needs"], all(e[1] for e in stack if e[0] == "want")))
            stack.append(entry)
            continue
        if CLOSES.match(line) and not line.startswith(("#", " ", "\t")):
            if not stack:
                return None
            out.append((line, [e[1] for e in stack if e[0] == "needs"], all(e[1] for e in stack if e[0] == "want")))
            stack.pop()
            continue
        out.append((line, [e[1] for e in stack if e[0] == "needs"], all(e[1] for e in stack if e[0] == "want")))
    if stack:
        return None
    return out


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    path, modules = sys.argv[1], sys.argv[2:]
    with open(path, encoding="utf-8") as f:
        text = f.read()
    lines = parse(text)
    whole = hashlib.sha256(text.encode()).hexdigest()[:12]
    for mod in modules:
        if lines is None:
            print(f"{mod}\t{whole}")
            continue
        h = hashlib.sha256()
        for line, needs_sets, interop_ok in lines:
            s = line.strip()
            if not s or s.startswith("#") or not interop_ok:
                continue
            if all(mod in ns for ns in needs_sets):
                h.update(s.encode() + b"\n")
        print(f"{mod}\t{h.hexdigest()[:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
