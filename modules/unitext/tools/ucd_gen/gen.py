# SPDX-License-Identifier: MIT
"""Generate `src/tables.zig` (the Unicode Character Database tables `unitext`
reads) and `src/testdata/normalization_test.txt` (a frozen copy of
NormalizationTest.txt) and `src/testdata/alphabetic_ranges.txt` (the Alphabetic
ranges of DerivedCoreProperties.txt) from UCD files.

    tools/ucd_gen/fetch.sh 17.0.0                 # the files below into tools/ucd_gen/data/17.0.0/ (gitignored)
    python3 -I tools/ucd_gen/gen.py --ucd tools/ucd_gen/data/17.0.0 -out src
    python3 -I tools/ucd_gen/gen.py --ucd tools/ucd_gen/data/17.0.0 -check src
    python3 -I tools/ucd_gen/gen.py --ucd tools/ucd_gen/data/16.0.0 -out <scratch dir>   # CPython 3.14's version

Reads (all under the UCD directory): UnicodeData.txt, SpecialCasing.txt,
CaseFolding.txt, DerivedNormalizationProps.txt, DerivedCoreProperties.txt,
extracted/DerivedNumericType.txt, NormalizationTest.txt. Needs `zig` on PATH
only for `zig fmt --stdin`. Python 3 standard library only. The data are
Unicode's (Unicode License v3, see the module's NOTICE); the encoding, the
derived `unaccent` table and this code are ours.

What is derived here and how (the module's SPEC.md says the same):

  * General_Category, Bidi_Class (only WS/B/S matter: `isSpace`), the
    Uppercase / Lowercase / Cased / Case_Ignorable / Alphabetic properties and
    Numeric_Type -> one 16-bit record per code point (`gcflags`; bit 12 is the Alphabetic derived property).
  * Canonical_Combining_Class, NFC_QC / NFKC_QC (Yes, Maybe, No), NFD_QC,
    NFKD_QC -> one 16-bit record per code point (`norm`).
  * Full recursive canonical and compatibility decompositions (Hangul
    syllables are algorithmic and are not in the table) -> `decomp`.
  * Primary composites: canonical decompositions of length 2 that are not in
    Full_Composition_Exclusion -> `compose_pairs`, sorted by (first, second).
  * Simple lower / upper / title mappings (UnicodeData fields 13, 12, 14; an
    empty title field means "same as upper"), simple case folding (CaseFolding
    status C and S) as deltas; the unconditional entries of SpecialCasing.txt
    and the status F entries of CaseFolding.txt as `special_*` lists (a
    SpecialCasing entry is kept only if it differs from the simple mapping).
  * `unaccent_*`: letters without a canonical decomposition whose name is
    "LATIN (SMALL|CAPITAL) LETTER <base> [WITH ...]" (or a small capital), the
    base one letter A-Z or a named base (see NAMED_LETTERS / NAMED_EXPANSIONS /
    NAMED_DIGRAPHS below; checked against ICU Latin-ASCII by tools/latin_ascii_diff.py).
"""

import os
import re
import subprocess
import sys

MAX_CP = 0x10FFFF
GCS = ["Lu", "Ll", "Lt", "Lm", "Lo", "Mn", "Mc", "Me", "Nd", "Nl", "No", "Pc", "Pd", "Ps", "Pe", "Pi", "Pf",
       "Po", "Sm", "Sc", "Sk", "So", "Zs", "Zl", "Zp", "Cc", "Cf", "Cs", "Co", "Cn"]
GC_INDEX = {g: i for i, g in enumerate(GCS)}

# gcflags layout (u16): bits 0-4 general category, then flags.
F_UPPER, F_LOWER, F_CASED, F_IGNORABLE, F_SPACE = 1 << 5, 1 << 6, 1 << 7, 1 << 8, 1 << 9
NUM_SHIFT = 10  # bits 10-11: 0 none, 1 Numeric, 2 Digit, 3 Decimal
F_ALPHABETIC = 1 << 12  # the Alphabetic derived property (DerivedCoreProperties.txt)

# norm layout (u16): bits 0-7 ccc; 8-9 NFC_QC; 10-11 NFKC_QC (0 Yes, 1 Maybe, 2 No); 12 NFD_QC=No; 13 NFKD_QC=No.

# `unaccent` reads a Latin letter's UCD name as `LATIN (SMALL|CAPITAL) (LETTER|LIGATURE) <base>
# [WITH <modifiers>]`, or `LATIN LETTER SMALL CAPITAL <base> ...` / `LATIN SMALL CAPITAL LETTER
# <base> ...` (a small capital folds to the capital letter). A base of one letter A-Z folds to that
# letter; the bases below are the other letter names that stand for one ASCII letter. The modifiers
# (hook, stroke, bar, tail, ...) are dropped, as NFD + dropping marks drops an accent. Only letters
# without a canonical decomposition are listed (the rest reach their base through NFD); the case of
# the result follows SMALL / CAPITAL.
NAMED_LETTERS = {
    "DOTLESS I": "i", "DOTLESS J": "j", "ETH": "d", "LONG S": "s",
    # letters of their own alphabet's order whose ASCII stand-in is fixed by the orthography or by
    # transliteration practice: Sami / African eng (n), Greenlandic kra (q since the 1973 reform),
    # the African open e, iota, u bar and D, the script g (a glyph variant of g)
    "ENG": "n", "KRA": "q", "OPEN E": "e", "IOTA": "i", "U BAR": "u", "AFRICAN D": "d", "SCRIPT G": "g",
    # the medieval / Celtic glyph variants of one letter
    "BROKEN L": "l", "INSULAR D": "d", "INSULAR F": "f", "INSULAR T": "t", "MIDDLE-WELSH V": "v",
    "BARRED B": "b",
}
# Ligatures, digraph letters and letters that stand for several ASCII letters (the
# `expand_ligatures` option), by the same name shape.
NAMED_EXPANSIONS = {
    "AE": "ae", "OE": "oe", "IJ": "ij", "SHARP S": "ss", "THORN": "th", "TH": "th",
    "FF": "ff", "FI": "fi", "FL": "fl", "FFI": "ffi", "FFL": "ffl", "ST": "st", "LONG S T": "st",
    # the medievalist and Americanist ligature letters
    "AA": "aa", "AO": "ao", "AU": "au", "AV": "av", "AY": "ay", "OO": "oo", "VY": "vy", "UE": "ue",
    "HV": "hv", "OI": "oi", "MIDDLE-WELSH LL": "ll",
    # the IPA digraph letters
    "DB DIGRAPH": "db", "QP DIGRAPH": "qp", "DZ DIGRAPH": "dz", "TS DIGRAPH": "ts",
    "LS DIGRAPH": "ls", "LZ DIGRAPH": "lz",
}
# The Latin digraph letters DZ, LJ, NJ in their three case shapes (U+01C4-01CC, U+01F1-01F3),
# expanded like ICU's Latin-ASCII. Matched against the UCD name exactly (they have only a
# compatibility decomposition; the "X WITH ..." letter rule must not see the titlecase ones).
NAMED_DIGRAPHS = {
    "LATIN CAPITAL LETTER DZ WITH CARON": "DZ",
    "LATIN CAPITAL LETTER D WITH SMALL LETTER Z WITH CARON": "Dz",
    "LATIN SMALL LETTER DZ WITH CARON": "dz",
    "LATIN CAPITAL LETTER LJ": "LJ",
    "LATIN CAPITAL LETTER L WITH SMALL LETTER J": "Lj",
    "LATIN SMALL LETTER LJ": "lj",
    "LATIN CAPITAL LETTER NJ": "NJ",
    "LATIN CAPITAL LETTER N WITH SMALL LETTER J": "Nj",
    "LATIN SMALL LETTER NJ": "nj",
    "LATIN CAPITAL LETTER DZ": "DZ",
    "LATIN CAPITAL LETTER D WITH SMALL LETTER Z": "Dz",
    "LATIN SMALL LETTER DZ": "dz",
}


def die(m):
    sys.stderr.write(f"ucd_gen: {m}\n")
    sys.exit(2)


def hexcp(s):
    return int(s, 16)


def data_lines(path):
    """(fields, comment) of each non-blank line, '#' comments removed."""
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        body = line.split("#", 1)[0].strip()
        if body:
            yield [f.strip() for f in body.split(";")]


def prop_ranges(path):
    """{property: [(lo, hi, value-or-None)]} of a `cp[..cp] ; Prop [; Value]` file."""
    out = {}
    for f in data_lines(path):
        r = f[0]
        lo, hi = (hexcp(x) for x in r.split("..")) if ".." in r else (hexcp(r),) * 2
        out.setdefault(f[1], []).append((lo, hi, f[2] if len(f) > 2 else None))
    return out


class Ucd:
    def __init__(self, d):
        self.dir = d
        self.version = None
        m = re.search(r"(\d+\.\d+\.\d+)", open(os.path.join(d, "DerivedNormalizationProps.txt"), encoding="utf-8").readline())
        if not m:
            die("cannot read the version from DerivedNormalizationProps.txt")
        self.version = m.group(1)
        self.load_unicode_data()
        self.load_props()
        self.load_casing()
        self.load_decomp()

    def load_unicode_data(self):
        n = MAX_CP + 1
        self.gc = [GC_INDEX["Cn"]] * n
        self.ccc = [0] * n
        self.bidi = [""] * n
        self.name = {}
        self.decomp_raw = {}
        self.simple = {}  # cp -> (upper, lower, title) code points or None
        first = None
        for f in data_lines(os.path.join(self.dir, "UnicodeData.txt")):
            cp = hexcp(f[0])
            name = f[1]
            if name.endswith(", First>"):
                first = cp
                continue
            lo = cp
            if name.endswith(", Last>"):
                lo = first
            for c in range(lo, cp + 1):
                self.gc[c] = GC_INDEX[f[2]]
                self.ccc[c] = int(f[3])
                self.bidi[c] = f[4]
            if lo == cp:
                self.name[cp] = name
                if f[5]:
                    self.decomp_raw[cp] = f[5]
                up = hexcp(f[12]) if f[12] else None
                lw = hexcp(f[13]) if f[13] else None
                ti = hexcp(f[14]) if f[14] else None
                if ti is None:
                    ti = up
                if up is not None or lw is not None or ti is not None:
                    self.simple[cp] = (up, lw, ti)

    def load_props(self):
        core = prop_ranges(os.path.join(self.dir, "DerivedCoreProperties.txt"))
        self.cp_props = {}
        for p in ("Uppercase", "Lowercase", "Cased", "Case_Ignorable", "Alphabetic"):
            s = set()
            for lo, hi, _ in core[p]:
                s.update(range(lo, hi + 1))
            self.cp_props[p] = s
        self.numtype = {}
        for typ, rs in prop_ranges(os.path.join(self.dir, "extracted", "DerivedNumericType.txt")).items():
            if typ not in ("Numeric", "Digit", "Decimal"):
                die("unexpected Numeric_Type " + typ)
            for lo, hi, _ in rs:
                for c in range(lo, hi + 1):
                    self.numtype[c] = {"Numeric": 1, "Digit": 2, "Decimal": 3}[typ]
        norm = prop_ranges(os.path.join(self.dir, "DerivedNormalizationProps.txt"))
        self.fce = set()
        for lo, hi, _ in norm["Full_Composition_Exclusion"]:
            self.fce.update(range(lo, hi + 1))
        self.qc = {"NFC_QC": {}, "NFKC_QC": {}, "NFD_QC": set(), "NFKD_QC": set()}
        for k in ("NFC_QC", "NFKC_QC"):
            for lo, hi, v in norm[k]:
                for c in range(lo, hi + 1):
                    self.qc[k][c] = {"M": 1, "N": 2}[v]
        for k in ("NFD_QC", "NFKD_QC"):
            for lo, hi, v in norm[k]:
                assert v == "N"
                self.qc[k].update(range(lo, hi + 1))

    def load_casing(self):
        # SpecialCasing: unconditional entries only (no 5th field).
        self.special = {}  # cp -> (lower, title, upper) tuples of code points
        for f in data_lines(os.path.join(self.dir, "SpecialCasing.txt")):
            if len(f) > 4 and f[4]:
                continue  # conditional (Final_Sigma, language): not an unconditional mapping
            cp = hexcp(f[0])
            self.special[cp] = tuple(tuple(hexcp(x) for x in f[i].split()) for i in (1, 2, 3))
        self.fold_simple = {}
        self.fold_full = {}
        for f in data_lines(os.path.join(self.dir, "CaseFolding.txt")):
            cp = hexcp(f[0])
            tgt = tuple(hexcp(x) for x in f[2].split())
            if f[1] in ("C", "S"):
                assert len(tgt) == 1
                self.fold_simple[cp] = tgt[0]
            elif f[1] == "F":
                self.fold_full[cp] = tgt

    def load_decomp(self):
        self.canon = {}
        self.compat = {}
        for cp, raw in self.decomp_raw.items():
            parts = raw.split()
            if parts[0].startswith("<"):
                self.compat[cp] = tuple(hexcp(x) for x in parts[1:])
            else:
                self.canon[cp] = tuple(hexcp(x) for x in parts)

    def full(self, cp, compat):
        m = self.canon.get(cp) or (self.compat.get(cp) if compat else None)
        if m is None:
            return (cp,)
        out = ()
        for c in m:
            out += self.full(c, compat)
        return out


# ── table packing ───────────────────────────────────────────────────────────


def width(maxv):
    return "u8" if maxv < 256 else "u16" if maxv < 65536 else "u32"


def nbytes(t):
    return {"u8": 1, "u16": 2, "u32": 4}[t]


def dedupe(vals, sh):
    n = 1 << sh
    blocks = {}
    s1 = []
    s2 = []
    for b in range(0, len(vals), n):
        blk = tuple(vals[b:b + n])
        i = blocks.get(blk)
        if i is None:
            i = len(blocks)
            blocks[blk] = i
            s2.extend(blk)
        s1.append(i)
    return s1, s2


def indexed(raw):
    """raw values (hashable) -> (index per cp, unique values with raw[0] at index 0)."""
    uniq = [raw[0]]
    pos = {raw[0]: 0}
    idx = []
    for v in raw:
        i = pos.get(v)
        if i is None:
            i = len(uniq)
            pos[v] = i
            uniq.append(v)
        idx.append(i)
    return idx, uniq


def arr(name, typ, vals, per=16, fmt=str):
    rows = []
    for i in range(0, len(vals), per):
        rows.append("    " + ", ".join(fmt(v) for v in vals[i:i + per]) + ",")
    return f"pub const {name} = [_]{typ}{{\n" + "\n".join(rows) + "\n};\n"


def emit_table(name, raw, ztype, fmt, doc):
    """Three-stage table over all code points: `vals[leaf[(t2[(t1[cp >> (a+b)] << b) | ((cp >> a) & mb)] << a) | (cp & ma)]]`."""
    idx, vals = indexed(raw)
    best = None
    for a in range(3, 9):
        for b in range(1, 7):
            l1, leaf = dedupe(idx, a)
            t1, t2 = dedupe(l1, b)
            size = (len(t1) * nbytes(width(max(t1))) + len(t2) * nbytes(width(max(t2))) + len(leaf) * nbytes(width(max(leaf))))
            if best is None or size < best[0]:
                best = (size, a, b, t1, t2, leaf)
    size, a, b, t1, t2, leaf = best
    tw = [width(max(x)) for x in (t1, t2, leaf)]
    body = f"/// {doc}\npub const {name} = struct {{\n    pub const Value = {ztype};\n    pub const shift_a = {a};\n    pub const shift_b = {b};\n"
    for line in (arr("t1", tw[0], t1) + arr("t2", tw[1], t2) + arr("leaf", tw[2], leaf) + arr("vals", ztype, vals, 8, fmt)).splitlines():
        body += "    " + line + "\n"
    body += "};\n"
    vsize = len(vals) * (4 if ztype in ("i32", "u32") else 2 if ztype == "u16" else 8)
    sys.stderr.write(f"  table {name}: a={a} b={b} t1 {len(t1)}x{tw[0]}, t2 {len(t2)}x{tw[1]}, leaf {len(leaf)}x{tw[2]}, {len(vals)} values = {size + vsize} bytes\n")
    return body


# ── generation ──────────────────────────────────────────────────────────────



def unaccent_lists(u):
    """(letters, expansions) of `unaccent`: `[(cp, ascii)]` each, sorted by cp, derived from the UCD names."""
    letters = []
    lig = []
    rx = re.compile(r"^LATIN (SMALL|CAPITAL) (?:LETTER|LIGATURE) (.+)$")
    rx_smallcap = re.compile(r"^LATIN (?:LETTER SMALL CAPITAL|SMALL CAPITAL LETTER) (.+)$")
    for c in sorted(u.name):
        nm = u.name[c]
        if c < 0x80 or c in u.canon:
            continue  # ASCII, or reaches its base letter through NFD
        if nm in NAMED_DIGRAPHS:
            lig.append((c, NAMED_DIGRAPHS[nm]))
            continue
        m = rx_smallcap.match(nm)
        if m:
            capital, rest = True, m.group(1)
        else:
            m = rx.match(nm)
            if not m:
                continue
            capital, rest = m.group(1) == "CAPITAL", m.group(2)
        base, _, mods = rest.partition(" WITH ")
        # "... WITH SMALL LETTER Z WITH CARON" is a titlecase digraph (Dž Lj Nj Dz), not one
        # letter with a diacritic: folding it to its first letter would drop letters (UR-1).
        if "LETTER" in mods.split():
            continue
        if re.fullmatch(r"[A-Z]", base):
            letters.append((c, base if capital else base.lower()))
        elif base in NAMED_LETTERS:
            s = NAMED_LETTERS[base]
            letters.append((c, s.upper() if capital else s))
        elif base in NAMED_EXPANSIONS:
            s = NAMED_EXPANSIONS[base]
            lig.append((c, s.upper() if capital else s))
    assert sum(1 for c in u.name if u.name[c] in NAMED_DIGRAPHS) == len(NAMED_DIGRAPHS), "a digraph name is missing from the UCD"
    return letters, lig


def build(u):
    n = MAX_CP + 1
    out = []
    out.append(f'pub const unicode_version = "{u.version}";\n')
    out.append("pub const unicode_version_major: u32 = %d;\n" % int(u.version.split(".")[0]))
    out.append("pub const gc_count = %d;\n" % len(GCS))

    # gcflags
    gcf = [0] * n
    sets = u.cp_props
    for c in range(n):
        v = u.gc[c]
        if c in sets["Uppercase"]:
            v |= F_UPPER
        if c in sets["Lowercase"]:
            v |= F_LOWER
        if c in sets["Cased"]:
            v |= F_CASED
        if c in sets["Case_Ignorable"]:
            v |= F_IGNORABLE
        if c in sets["Alphabetic"]:
            v |= F_ALPHABETIC
        g = GCS[u.gc[c]]
        if g == "Zs" or u.bidi[c] in ("WS", "B", "S"):
            v |= F_SPACE
        v |= u.numtype.get(c, 0) << NUM_SHIFT
        gcf[c] = v
    out.append(emit_table("gcflags", gcf, "u16", str, "General_Category (bits 0-4), flags (bit 12: Alphabetic) and Numeric_Type per code point."))

    # norm
    nrm = [0] * n
    for c in range(n):
        v = u.ccc[c]
        v |= u.qc["NFC_QC"].get(c, 0) << 8
        v |= u.qc["NFKC_QC"].get(c, 0) << 10
        if c in u.qc["NFD_QC"]:
            v |= 1 << 12
        if c in u.qc["NFKD_QC"]:
            v |= 1 << 13
        nrm[c] = v
    out.append(emit_table("norm", nrm, "u16", str, "Canonical_Combining_Class (bits 0-7), NFC_QC, NFKC_QC, NFD_QC=No, NFKD_QC=No."))

    # decomposition (Hangul syllables are algorithmic)
    pool = []
    pool_pos = {}

    def pooled(t):
        if t in pool_pos:
            return pool_pos[t]
        # reuse an existing occurrence as a substring
        for i in range(len(pool) - len(t) + 1):
            if tuple(pool[i:i + len(t)]) == t:
                pool_pos[t] = i
                return i
        pool_pos[t] = len(pool)
        pool.extend(t)
        return pool_pos[t]

    dec = [(0, 0, 0, 0)] * n
    for c in sorted(set(u.canon) | set(u.compat)):
        d = u.full(c, False) if c in u.canon else None
        k = u.full(c, True)
        assert k != (c,)
        assert len(k) <= 18 and (d is None or len(d) < 256), hex(c)
        dec[c] = (pooled(d) if d else 0, len(d) if d else 0, pooled(k), len(k))
    assert len(pool) < 65536
    out.append("/// `{ nfd_off, nfd_len, nfkd_off, nfkd_len }` into `decomp_pool`; nfd_len 0 = no canonical decomposition, all zero = none. Lengths are in code points.\n")
    out.append("pub const DecompRec = struct { nfd_off: u16, nfd_len: u8, nfkd_off: u16, nfkd_len: u8 };\n")
    out.append(emit_table("decomp", dec, "DecompRec", lambda r: f".{{ .nfd_off = {r[0]}, .nfd_len = {r[1]}, .nfkd_off = {r[2]}, .nfkd_len = {r[3]} }}", "Full canonical (NFD) and compatibility (NFKD) decomposition of a code point; Hangul syllables are not in it."))
    out.append("pub const decomp_pool = [_]u32{\n" + "".join("    " + ", ".join(f"0x{v:X}" for v in pool[i:i + 12]) + ",\n" for i in range(0, len(pool), 12)) + "};\n")
    sys.stderr.write(f"  decomp pool {len(pool)} code points\n")

    # composition pairs
    pairs = []
    for c, m in u.canon.items():
        if len(m) == 2 and c not in u.fce:
            pairs.append((m[0], m[1], c))
    pairs.sort()
    out.append("/// Primary composites `{ first, second, composite }`, sorted by (first, second).\n")
    out.append("pub const ComposePair = struct { a: u32, b: u32, c: u32 };\n")
    out.append("pub const compose_pairs = [_]ComposePair{\n" + "".join(f"    .{{ .a = 0x{a:X}, .b = 0x{b:X}, .c = 0x{c:X} }},\n" for a, b, c in pairs) + "};\n")
    sys.stderr.write(f"  compose_pairs: {len(pairs)}\n")

    # case deltas
    def special_diff(kind):
        # kind: 0 lower, 1 title, 2 upper ; returns {cp: tuple} where SpecialCasing differs from the simple mapping
        res = {}
        for c, trio in u.special.items():
            sp = trio[kind]
            simple = u.simple.get(c)
            sm = None
            if simple is not None:
                sm = simple[{0: 1, 1: 2, 2: 0}[kind]]
            want = (sm,) if sm is not None else (c,)
            if sp != want:
                res[c] = sp
        return res

    def delta_table(name, simple_of, special, doc):
        raw = [0] * n
        for c in range(n):
            t = simple_of(c)
            if t is not None and t != c:
                raw[c] = (t - c) * 2
        for c in special:
            raw[c] += 1
        out.append(emit_table(name, raw, "i32", str, doc))
        lst = sorted(special.items())
        out.append(f"/// Full (SpecialCasing / CaseFolding F) mappings for `{name}`, sorted by code point: `{{ cp, len, a, b, c }}`.\n")
        out.append(f"pub const special_{name} = [_]Special{{\n" + "".join(
            f"    .{{ .cp = 0x{c:X}, .len = {len(t)}, .m = .{{ " + ", ".join(f"0x{x:X}" for x in t + (0,) * (3 - len(t))) + " } },\n"
            for c, t in lst) + "};\n")

    out.append("pub const Special = struct { cp: u32, len: u8, m: [3]u32 };\n")
    lower_sp, title_sp, upper_sp = special_diff(0), special_diff(1), special_diff(2)
    delta_table("lower", lambda c: u.simple[c][1] if c in u.simple else None, lower_sp, "Simple lowercase mapping (UnicodeData field 13) as `delta * 2 + special`; bit 0 set = `special_lower` has the full mapping.")
    delta_table("upper", lambda c: u.simple[c][0] if c in u.simple else None, upper_sp, "Simple uppercase mapping (field 12) as `delta * 2 + special`; bit 0 set = `special_upper` has the full mapping.")
    delta_table("title", lambda c: u.simple[c][2] if c in u.simple else None, title_sp, "Simple titlecase mapping (field 14, else upper) as `delta * 2 + special`; bit 0 set = `special_title` has the full mapping.")
    fold_sp = {c: t for c, t in u.fold_full.items() if t != (u.fold_simple.get(c, c),)}
    delta_table("fold", lambda c: u.fold_simple.get(c), fold_sp, "Simple case folding (CaseFolding C+S) as `delta * 2 + special`; bit 0 set = `special_fold` has the full folding (status F).")

    # unaccent
    letters, lig = unaccent_lists(u)
    out.append("/// Letters with no decomposition that `unaccent` folds to one ASCII letter, `{ cp, ascii }`, sorted by cp.\n")
    out.append("pub const UnaccentLetter = struct { cp: u32, ascii: u8 };\n")
    out.append("pub const unaccent_letters = [_]UnaccentLetter{\n" + "".join(f"    .{{ .cp = 0x{c:X}, .ascii = '{a}' }},\n" for c, a in letters) + "};\n")
    out.append("/// Ligatures and letters `unaccent` expands under `expand_ligatures`, `{ cp, len, ascii }`, sorted by cp.\n")
    out.append("pub const UnaccentExpansion = struct { cp: u32, len: u8, ascii: [4]u8 };\n")
    out.append("pub const unaccent_expansions = [_]UnaccentExpansion{\n" + "".join(
        f"    .{{ .cp = 0x{c:X}, .len = {len(s)}, .ascii = .{{ " + ", ".join(f"'{x}'" for x in s) + ", 0" * (4 - len(s)) + " } },\n"
        for c, s in lig) + "};\n")
    sys.stderr.write(f"  unaccent: {len(letters)} letters, {len(lig)} expansions\n")
    return "".join(out), letters, lig


def header(u):
    return (
        "// SPDX-License-Identifier: MIT\n"
        f"// GENERATED by modules/unitext/tools/ucd_gen/gen.py (Unicode {u.version}) -- do not hand-edit.\n"
        "//! The Unicode Character Database tables `unitext` reads: general category and flags,\n"
        "//! combining class and quick-check values, decompositions and composition pairs, case\n"
        "//! mappings and the `unaccent` letter lists, as three-stage lookup tables\n"
        "//! (see `emit_table` in the generator for the index arithmetic). A transformed form of Unicode's data:\n"
        "//! see the module's NOTICE for the Unicode License v3.\n\n"
    )


def zig_fmt(text):
    r = subprocess.run(["zig", "fmt", "--stdin"], input=text.encode(), capture_output=True)
    if r.returncode != 0:
        die("zig fmt failed: " + r.stderr.decode())
    return r.stdout.decode()


def norm_test(u):
    """Frozen copy of NormalizationTest.txt: `c1;c2;c3;c4;c5` per line, `@PartN` headers kept."""
    lines = []
    for line in open(os.path.join(u.dir, "NormalizationTest.txt"), encoding="utf-8"):
        line = line.rstrip("\n")
        if line.startswith("@Part"):
            lines.append(line.split()[0])
            continue
        body = line.split("#", 1)[0].strip()
        if not body:
            continue
        f = body.rstrip(";").split(";")
        assert len(f) == 5
        lines.append(";".join(f))
    head = (
        f"# unitext: NormalizationTest.txt of Unicode {u.version} (Unicode License v3; see ../../NOTICE).\n"
        "# Comments and descriptions removed by tools/ucd_gen/gen.py; fields c1;c2;c3;c4;c5, code points in hex, space separated.\n"
    )
    return head + "\n".join(lines) + "\n"


def alphabetic_test(u):
    """Frozen Alphabetic ranges from DerivedCoreProperties.txt (an independent check of the packed flag)."""
    lines = []
    for lo, hi, _ in sorted(prop_ranges(os.path.join(u.dir, "DerivedCoreProperties.txt"))["Alphabetic"]):
        lines.append(f"{lo:X}" if lo == hi else f"{lo:X}..{hi:X}")
    head = (
        f"# unitext: the Alphabetic ranges of DerivedCoreProperties.txt of Unicode {u.version} (Unicode License v3; see ../../NOTICE).\n"
        "# Comments and the property name removed by tools/ucd_gen/gen.py; one `lo` or `lo..hi` per line, hex.\n"
    )
    return head + "\n".join(lines) + "\n"


def main():
    args = sys.argv[1:]
    opts = {}
    while args:
        a = args.pop(0)
        if not args:
            die(f"{a} needs a value")
        opts[a] = args.pop(0)
    ucd = opts.get("--ucd") or die("usage: gen.py --ucd <UCD dir> (-out <dir> | -check <dir>)")
    u = Ucd(ucd)
    body, _, _ = build(u)
    tables = zig_fmt(header(u) + body)
    files = {"tables.zig": tables, os.path.join("testdata", "normalization_test.txt"): norm_test(u),
             os.path.join("testdata", "alphabetic_ranges.txt"): alphabetic_test(u)}
    if "-out" in opts:
        for f, t in files.items():
            path = os.path.join(opts["-out"], f)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(t)
            sys.stderr.write(f"wrote {path} ({len(t)} bytes)\n")
    elif "-check" in opts:
        bad = False
        for f, t in files.items():
            old = open(os.path.join(opts["-check"], f), encoding="utf-8").read()
            if old != t:
                sys.stderr.write(f"{f}: DRIFT -- committed file differs from a fresh build\n")
                bad = True
            else:
                sys.stderr.write(f"{f}: committed file matches a fresh build\n")
        sys.exit(1 if bad else 0)
    else:
        die("one of -out, -check is required")


if __name__ == "__main__":
    main()
