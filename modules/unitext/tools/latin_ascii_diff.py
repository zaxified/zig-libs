# SPDX-License-Identifier: MIT
"""Differential oracle for `unaccent`'s derived lists: ICU's `Latin-ASCII` transliterator.

    tools/ucd_gen/fetch.sh 17.0.0      # ICU 78 is Unicode 17.0.0
    python3 -I tools/latin_ascii_diff.py --ucd tools/ucd_gen/data/17.0.0 [--oracle-ucd DIR] [--uconv /usr/bin/uconv] [-v]

Feeds every code point of Script=Latin and of the Latin blocks (Latin-1 Supplement,
Latin Extended-A..G, IPA Extensions, Latin Extended Additional, Alphabetic Presentation
Forms), one per line, through `uconv -x Latin-ASCII` and through `unaccent`'s model (NFD,
drop General_Category Mn, map `unaccent_letters`, expand `unaccent_expansions`, NFC; the
lists come from `ucd_gen/gen.py`'s `unaccent_lists`, the same function that writes
`src/tables.zig`, whose `-check` mode ties the two together). Every difference is put in
exactly one class:

  adopt-missing   a letter (General_Category L*) without a compatibility decomposition that
                  Latin-ASCII folds to ASCII letters and `unaccent` does not: a gap. Exit 1.
  arbitrary       the same, but named in ARBITRARY below with the reason it is left.
  compat          a letter with a compatibility decomposition (superscripts, small forms,
                  fullwidth, the ligature presentation forms with <compat>): `unaccent` applies no
                  compatibility mappings by design.
  nonletter       not a letter (punctuation, symbols, digits, marks of category Mc/Me):
                  out of `unaccent`'s scope by design.
  icu-not-ascii   a letter Latin-ASCII maps to something that is not only ASCII letters and
                  not itself; `unaccent` keeps its own answer.
  ours-only       a Latin letter `unaccent` folds and Latin-ASCII leaves unchanged (letters
                  added after Latin-ASCII's rules were written, or one case of a pair Latin-ASCII
                  folds only in the other case): the name rule applies uniformly.
  not-latin       a code point of another script inside a Latin block (the Hebrew presentation
                  forms in Alphabetic Presentation Forms): Latin-ASCII does not touch other
                  scripts, `unaccent` drops their nonspacing marks by design.
  not-in-oracle   a code point not assigned in the oracle's Unicode version (`--oracle-ucd`,
                  default `--ucd`): not compared.

With a newer UCD than the oracle's, pass the oracle's directory as `--oracle-ucd` so that
code points new in the newer version are reported, not compared. The context-sensitive
rules of Latin-ASCII (a capital ligature before a lowercase letter) do not fire: each code
point is alone on its line.
"""

import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "ucd_gen"))
import gen  # noqa: E402

LATIN_BLOCKS = (
    "Latin-1 Supplement", "Latin Extended-A", "Latin Extended-B", "IPA Extensions",
    "Latin Extended Additional", "Latin Extended-C", "Latin Extended-D", "Latin Extended-E",
    "Latin Extended-F", "Latin Extended-G", "Alphabetic Presentation Forms",
)

# Letters Latin-ASCII folds to ASCII letters that `unaccent` deliberately leaves, with the
# reason (also in SPEC.md "What is deliberately not done"). Keyed by UCD name.
ARBITRARY = {
    "LATIN SMALL LETTER HENG WITH HOOK":
        "IPA sj-sound; Latin-ASCII folds it to h but leaves LATIN SMALL LETTER HENG (U+A727) alone",
    "LATIN SMALL LETTER DUM": "medieval abbreviation for a syllable (-dum); one letter loses it",
    "LATIN SMALL LETTER LUM": "medieval abbreviation for a syllable (-lum); one letter loses it",
    "LATIN SMALL LETTER MUM": "medieval abbreviation for a syllable (-mum); one letter loses it",
    "LATIN SMALL LETTER NUM": "medieval abbreviation for a syllable (-num); one letter loses it",
    "LATIN SMALL LETTER RUM": "medieval abbreviation for a syllable (-rum); one letter loses it",
    "LATIN LETTER SMALL CAPITAL RUM": "medieval abbreviation for a syllable (-rum); one letter loses it",
    "LATIN SMALL LETTER TUM": "medieval abbreviation for a syllable (-tum); one letter loses it",
}


def ranges_file(path):
    for f in gen.data_lines(path):
        r = f[0]
        lo, hi = (gen.hexcp(x) for x in r.split("..")) if ".." in r else (gen.hexcp(r),) * 2
        yield lo, hi, f[1]


def latin_cps(d):
    """(every code point to compare, the Script=Latin ones)"""
    cps = set()
    for lo, hi, v in ranges_file(os.path.join(d, "Scripts.txt")):
        if v == "Latin":
            cps.update(range(lo, hi + 1))
    script = set(cps)
    found = set()
    for lo, hi, v in ranges_file(os.path.join(d, "Blocks.txt")):
        if v in LATIN_BLOCKS:
            cps.update(range(lo, hi + 1))
            found.add(v)
    missing = set(LATIN_BLOCKS) - found
    if missing:
        gen.die("blocks not in Blocks.txt: " + ", ".join(sorted(missing)))
    return cps, script


def assigned(d):
    out = set()
    first = None
    for f in gen.data_lines(os.path.join(d, "UnicodeData.txt")):
        cp = gen.hexcp(f[0])
        if f[1].endswith(", First>"):
            first = cp
            continue
        out.update(range(first if f[1].endswith(", Last>") else cp, cp + 1))
    return out


class Model:
    """`unaccent` on one code point, from the UCD and the generator's lists."""

    def __init__(self, u):
        self.u = u
        letters, lig = gen.unaccent_lists(u)
        self.map = {c: a for c, a in letters}
        self.map.update({c: s for c, s in lig})
        self.pairs = {m: c for c, m in u.canon.items() if len(m) == 2 and c not in u.fce}

    def nfd(self, cps):
        out = []
        for c in cps:
            out.extend(self.u.full(c, False))
        # canonical ordering (stable sort of each run of non-starters)
        i = 0
        while i < len(out):
            if self.u.ccc[out[i]] == 0:
                i += 1
                continue
            j = i
            while j < len(out) and self.u.ccc[out[j]] != 0:
                j += 1
            out[i:j] = sorted(out[i:j], key=lambda c: self.u.ccc[c])
            i = j
        return out

    def nfc(self, cps):
        cps = self.nfd(cps)
        if not cps:
            return cps
        out = [cps[0]]
        starter = 0 if self.u.ccc[cps[0]] == 0 else None
        last_cc = -1
        for c in cps[1:]:
            cc = self.u.ccc[c]
            if starter is not None and (last_cc < cc or (last_cc == -1 and cc == 0)):
                comp = self.pairs.get((out[starter], c))
                if comp is not None:
                    out[starter] = comp
                    continue
            if cc == 0:
                starter = len(out)
                last_cc = -1
            else:
                last_cc = cc
            out.append(c)
        return out

    def unaccent(self, cp):
        mid = []
        for c in self.nfd([cp]):
            if c < 0x80:
                mid.append(c)
            elif gen.GCS[self.u.gc[c]] == "Mn":
                continue
            elif c in self.map:
                mid.extend(ord(x) for x in self.map[c])
            else:
                mid.append(c)
        return "".join(chr(c) for c in self.nfc(mid))


def icu(uconv, cps):
    text = "\n".join(chr(c) for c in cps) + "\n"
    r = subprocess.run([uconv, "-f", "utf-8", "-t", "utf-8", "-x", "Latin-ASCII"], input=text.encode(),
                       capture_output=True)
    if r.returncode != 0:
        gen.die("uconv failed: " + r.stderr.decode())
    out = r.stdout.decode().split("\n")
    if len(out) != len(cps) + 1 or out[-1] != "":
        gen.die(f"uconv returned {len(out) - 1} lines for {len(cps)} code points")
    return out[:-1]


def main():
    args = sys.argv[1:]
    opts = {"--uconv": "/usr/bin/uconv"}
    verbose = False
    while args:
        a = args.pop(0)
        if a == "-v":
            verbose = True
            continue
        if not args:
            gen.die(f"{a} needs a value")
        opts[a] = args.pop(0)
    d = opts.get("--ucd") or gen.die("usage: latin_ascii_diff.py --ucd <UCD dir> [--oracle-ucd DIR] [--uconv PATH] [-v]")
    u = gen.Ucd(d)
    model = Model(u)
    in_oracle = assigned(opts.get("--oracle-ucd", d))
    all_cps, script = latin_cps(d)
    cps = sorted(c for c in all_cps if c in u.name and c != 0x0A)
    theirs = icu(opts["--uconv"], cps)
    ascii_letters = re.compile(r"^[A-Za-z]+$")
    classes = {k: [] for k in ("same", "adopt-missing", "arbitrary", "compat", "nonletter", "icu-not-ascii",
                               "ours-only", "not-latin", "not-in-oracle")}
    named_seen = set()
    for c, t in zip(cps, theirs):
        if c not in in_oracle:
            classes["not-in-oracle"].append((c, None, None))
            continue
        ours = model.unaccent(c)
        if ours == t:
            classes["same"].append((c, ours, t))
            continue
        nm = u.name[c]
        g = gen.GCS[u.gc[c]]
        if not g.startswith("L"):
            k = "nonletter"
        elif c not in script:
            k = "not-latin"
        elif t == chr(c):
            k = "ours-only"
        elif c in u.compat or any(x in u.compat for x in u.full(c, False)):
            k = "compat"
        elif not ascii_letters.match(t):
            k = "icu-not-ascii"
        elif ours == chr(c) or not ascii_letters.match(ours):
            if nm in ARBITRARY:
                k = "arbitrary"
                named_seen.add(nm)
            else:
                k = "adopt-missing"
        else:
            k = "adopt-missing"
        classes[k].append((c, ours, t))
    print(f"latin_ascii_diff: UCD {u.version}, {len(cps)} code points (Script=Latin + the Latin blocks)")
    for k, v in classes.items():
        print(f"  {k:14} {len(v)}")
    for k in ("adopt-missing", "arbitrary", "icu-not-ascii", "ours-only") + (("compat", "nonletter", "not-latin", "not-in-oracle") if verbose else ()):
        for c, ours, t in classes[k]:
            extra = f"  ({ARBITRARY[u.name[c]]})" if k == "arbitrary" else ""
            print(f"{k}\tU+{c:04X}\t{chr(c)}\tours={ours!r}\tlatin-ascii={t!r}\t{u.name[c]}{extra}")
    stale = set(ARBITRARY) - named_seen
    for nm in sorted(stale):
        print(f"stale\tARBITRARY entry no longer differs: {nm}")
    sys.exit(1 if classes["adopt-missing"] or stale else 0)


if __name__ == "__main__":
    main()
