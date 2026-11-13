# SPDX-License-Identifier: MIT
"""Freeze CPython's answers as the test vectors of `unitext` (`src/testdata/cpython_vectors.txt`).

    python3 -I tools/py_oracle.py --ucd16 tools/ucd_gen/data/16.0.0 --ucd tools/ucd_gen/data/17.0.0 \
        --ucd tools/ucd_gen/data/18.0.0 -out src/testdata/cpython_vectors.txt

CPython 3.14's `unicodedata` is Unicode 16.0.0, the module's tables are 18.0.0, so
only code points whose UCD data are IDENTICAL in 16.0.0 and in every `--ucd` directory
(each version up to the tables') are compared: for each code point, every record the
answers depend on (UnicodeData row, SpecialCasing, CaseFolding, the Uppercase /
Lowercase / Cased / Case_Ignorable properties, Numeric_Type, the quick-check values and
the records of every code point in its decompositions and case mappings) must be equal
in all the directories. The count of the exclusion is written into the file header.

Needs only the Python 3 standard library and `tools/ucd_gen/gen.py` (imported, for
its UCD parser). CPython supplies, per code point (surrogates excluded): general
category, combining class, the eleven `str.is*` answers, `is_normalized` for the four
forms, and lower / upper / title / casefold / NFC / NFD / NFKC / NFKD of the one-character
string; the three `simple` columns are NOT CPython's (it has no simple-mapping API): they
are read by this script's own parser from UnicodeData.txt / CaseFolding.txt of 16.0.0.
Then a seeded set of multi-character strings (Final_Sigma contexts, marks in every
order, Hangul jamo, ligatures) with the same answers plus capitalize / swapcase.
"""

import importlib.util
import os
import random
import sys
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("gen", os.path.join(HERE, "ucd_gen", "gen.py"))
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)

MAX_CP = 0x10FFFF
PREDS = ["isalpha", "isdecimal", "isdigit", "isnumeric", "isalnum", "isspace", "isupper", "islower", "istitle", "isprintable", "isascii"]


def hexs(s):
    return " ".join("%X" % ord(c) for c in s)


def rec(u, c):
    p = u.cp_props
    return (
        u.gc[c], u.ccc[c], u.bidi[c], u.decomp_raw.get(c), u.simple.get(c), u.special.get(c),
        u.fold_simple.get(c), u.fold_full.get(c), u.numtype.get(c, 0),
        c in p["Uppercase"], c in p["Lowercase"], c in p["Cased"], c in p["Case_Ignorable"],
        c in u.fce, u.qc["NFC_QC"].get(c, 0), u.qc["NFKC_QC"].get(c, 0), c in u.qc["NFD_QC"], c in u.qc["NFKD_QC"],
    )


def closure(u, c):
    out = {c}
    out.update(u.full(c, True))
    out.update(u.full(c, False))
    s = u.simple.get(c)
    if s:
        out.update(x for x in s if x is not None)
    sp = u.special.get(c)
    if sp:
        for t in sp:
            out.update(t)
    if c in u.fold_simple:
        out.add(u.fold_simple[c])
    if c in u.fold_full:
        out.update(u.fold_full[c])
    return out


def main():
    args = sys.argv[1:]
    opts = {}
    newer = []
    while args:
        a = args.pop(0)
        if a == "--ucd":
            newer.append(gen.Ucd(args.pop(0)))
        else:
            opts[a] = args.pop(0)
    if not newer:
        gen.die("usage: py_oracle.py --ucd16 DIR --ucd DIR [--ucd DIR ...] -out FILE")
    u16 = gen.Ucd(opts["--ucd16"])
    assert unicodedata.unidata_version == u16.version, (unicodedata.unidata_version, u16.version)
    cache = {}

    def same(c):
        r = cache.get(c)
        if r is None:
            r16 = rec(u16, c)
            r = cache[c] = all(rec(u, c) == r16 for u in newer)
        return r

    ok = [False] * (MAX_CP + 1)
    skipped = 0
    for c in range(MAX_CP + 1):
        if 0xD800 <= c <= 0xDFFF:
            continue
        if 0xAC00 <= c <= 0xD7A3 and (c - 0xAC00) % 11 != 0 and c != 0xD7A3:
            continue  # Hangul is algorithmic: every 11th syllable (all L, V and T combinations recur) and the last
        if all(same(x) for x in closure(u16, c)) and all(same(x) for u in newer for x in closure(u, c)):
            ok[c] = True
        else:
            skipped += 1
    lines = []
    prev = None  # (start, end, key) for range merging
    rows = []
    for c in range(MAX_CP + 1):
        if not ok[c]:
            continue
        ch = chr(c)
        flags = "".join("1" if getattr(ch, p)() else "0" for p in PREDS)
        isn = "".join("1" if unicodedata.is_normalized(f, ch) else "0" for f in ("NFC", "NFD", "NFKC", "NFKD"))
        maps = []
        for v in (ch.lower(), ch.upper(), ch.title(), ch.casefold(), unicodedata.normalize("NFC", ch), unicodedata.normalize("NFD", ch),
                  unicodedata.normalize("NFKC", ch), unicodedata.normalize("NFKD", ch)):
            maps.append("" if v == ch else hexs(v))
        s = u16.simple.get(c)
        simp = []
        for kind in (1, 0, 2):  # lower, upper, title
            t = s[kind] if s else None
            simp.append("" if t is None or t == c else "%X" % t)
        f = u16.fold_simple.get(c)
        simp.append("" if f is None or f == c else "%X" % f)
        key = (gen.GCS[u16.gc[c]], unicodedata.combining(ch), flags, isn)
        assert unicodedata.category(ch) == key[0], (hex(c), unicodedata.category(ch), key[0])
        mapped = any(maps) or any(simp)
        rows.append((c, key, maps, simp, mapped))
    out = []
    i = 0
    while i < len(rows):
        c, key, maps, simp, mapped = rows[i]
        j = i
        if not mapped:
            while j + 1 < len(rows) and rows[j + 1][0] == rows[j][0] + 1 and rows[j + 1][1] == key and not rows[j + 1][4]:
                j += 1
        end = rows[j][0]
        rng = "%X" % c if end == c else "%X-%X" % (c, end)
        out.append(";".join([rng, key[0], str(key[1]), key[2], key[3]] + maps + simp))
        i = j + 1
    # strings
    rnd = random.Random(20261109)
    cased = [r[0] for r in rows if r[4] and 0 < len(r[2][0]) + len(r[2][1]) + len(r[2][2])]
    marks = [r[0] for r in rows if r[1][1] != 0]
    anyc = [r[0] for r in rows if r[1][0] != "Cn"]
    special = [0x3A3, 0x3C3, 0x3C2, 0xDF, 0x130, 0x131, 0x1C4, 0x1C5, 0x1C6, 0x149, 0x390, 0x1E9E, 0xFB00, 0xFB03, 0x2B0, 0xAD, 0x27, 0x2E, 0x3A, 0x2019, 0x345,
               0x1F80, 0x1FB3, 0x300, 0x301, 0x323, 0x307, 0x1100, 0x1161, 0x11A8, 0xAC00, 0xAC01, 0x41, 0x61, 0x20, 0x31, 0x3A9, 0x3C9, 0xB7, 0x2D, 0x4E09, 0xA0, 0x212B, 0x2126]
    special = [c for c in special if ok[c]]
    ascii_ = [ord(x) for x in "abcXYZ019 .,'-_"]
    strs = set()
    while len(strs) < 2000:
        n = rnd.randint(1, 10)
        cs = []
        for _ in range(n):
            r = rnd.random()
            pool = special if r < 0.40 else cased if r < 0.65 else marks if r < 0.80 else ascii_ if r < 0.90 else anyc
            cs.append(rnd.choice(pool))
        strs.add("".join(map(chr, cs)))
    sl = []
    for s in sorted(strs):
        flags = "".join("1" if getattr(s, p)() else "0" for p in PREDS)
        isn = "".join("1" if unicodedata.is_normalized(f, s) else "0" for f in ("NFC", "NFD", "NFKC", "NFKD"))
        vals = [s.lower(), s.upper(), s.title(), s.capitalize(), s.swapcase(), s.casefold(),
                unicodedata.normalize("NFC", s), unicodedata.normalize("NFD", s), unicodedata.normalize("NFKC", s), unicodedata.normalize("NFKD", s)]
        sl.append(";".join(["S", hexs(s), flags, isn] + [hexs(v) for v in vals]))
    py = sys.version.split()[0]
    header = [
        f"# unitext: CPython {py} answers (unicodedata {unicodedata.unidata_version}), frozen by tools/py_oracle.py.",
        f"# Code points whose UCD data differ between {u16.version} and any of " + ", ".join(u.version for u in newer) + f" (incl. their decomposition / mapping targets) are left out: {skipped}.",
        "# Range line: cp[-cp];gc;ccc;flags(" + ",".join(PREDS) + ");isnormalized(nfc,nfd,nfkc,nfkd);lower;upper;title;casefold;nfc;nfd;nfkc;nfkd;simple lower;upper;title;fold",
        "# A mapping field is empty when the answer is the code point itself; mappings are hex code points. Simple columns: read from the UCD text by this script, not CPython.",
        "# String line: S;cps;flags;isnormalized;lower;upper;title;capitalize;swapcase;casefold;nfc;nfd;nfkc;nfkd",
    ]
    with open(opts["-out"], "w", encoding="utf-8") as fh:
        fh.write("\n".join(header + out + sl) + "\n")
    sys.stderr.write(f"wrote {opts['-out']}: {len(out)} range lines, {len(sl)} strings, {skipped} code points skipped as changed since {u16.version}\n")


if __name__ == "__main__":
    main()
