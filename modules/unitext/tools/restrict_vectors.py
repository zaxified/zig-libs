# SPDX-License-Identifier: MIT
"""Restrict `src/testdata/rust_vectors.txt` (frozen by `tools/rust_case.rs` with an older
Unicode than the module's tables) to the code points whose case data did not change.

    python3 -I tools/restrict_vectors.py --oracle-ucd tools/ucd_gen/data/17.0.0 \\
        --ucd tools/ucd_gen/data/18.0.0 src/testdata/rust_vectors.txt

Rust 1.93's `char::UNICODE_VERSION` is 17.0.0; the tables are 18.0.0. A code point whose
lowercase or uppercase mapping (UnicodeData simple mapping or unconditional SpecialCasing
entry) differs between the two versions gets an `X;cp;;` line instead of its `C` line, and
the replay skips it (it is not checked for identity either); a string (`S` line) that
contains a code point whose mappings or Cased / Case_Ignorable properties changed is
dropped. Everything else is Rust's answer, unchanged. Rewrites the file in place;
running it again with the same directories changes nothing.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "ucd_gen"))
import gen  # noqa: E402

MARK = "# restricted by tools/restrict_vectors.py"


def case_rec(u, c):
    s = u.simple.get(c)
    sp = u.special.get(c)
    return (s[0] if s else None, s[1] if s else None, sp[0] if sp else None, sp[2] if sp else None)


def ctx_rec(u, c):
    p = u.cp_props
    return case_rec(u, c) + (c in p["Cased"], c in p["Case_Ignorable"])


def main():
    args = sys.argv[1:]
    opts = {}
    while len(args) > 1:
        a = args.pop(0)
        opts[a] = args.pop(0)
    if len(args) != 1 or "--oracle-ucd" not in opts or "--ucd" not in opts:
        gen.die("usage: restrict_vectors.py --oracle-ucd DIR --ucd DIR FILE")
    path = args[0]
    old, new = gen.Ucd(opts["--oracle-ucd"]), gen.Ucd(opts["--ucd"])
    cps = [c for c in range(gen.MAX_CP + 1) if not 0xD800 <= c <= 0xDFFF]
    skip = {c for c in cps if case_rec(old, c) != case_rec(new, c)}
    ctx = {c for c in cps if ctx_rec(old, c) != ctx_rec(new, c)}
    head, rows, strs = [], [], []
    for line in open(path, encoding="utf-8").read().splitlines():
        if line.startswith(MARK):
            continue
        if line.startswith("#"):
            head.append(line)
            continue
        f = line.split(";")
        if f[0] in ("C", "X"):
            c = int(f[1], 16)
            if c not in skip:
                rows.append((c, line))
        elif f[0] == "S":
            if not any(int(x, 16) in ctx for x in f[1].split()):
                strs.append(line)
        else:
            gen.die("unexpected line: " + line)
    rows += [(c, f"X;{c:X};;") for c in skip]
    rows.sort()
    n_strs_before = len(open(path, encoding="utf-8").read().split("\nS;")) - 1
    head.append(f"{MARK} (UCD {old.version} -> {new.version}): {len(skip)} code points whose lower/upper "
                f"mapping changed are `X` lines (skipped); strings with a code point whose mappings or "
                f"Cased / Case_Ignorable changed ({len(ctx)} code points) are dropped.")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(head + [r for _, r in rows] + strs) + "\n")
    sys.stderr.write(f"restrict_vectors: {len(skip)} X lines, {len(strs)} of {n_strs_before} strings kept\n")


if __name__ == "__main__":
    main()
