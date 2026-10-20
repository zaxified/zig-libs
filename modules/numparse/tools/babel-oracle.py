#!/usr/bin/env python3
"""Differential oracle for `numparse.parse`: Babel (BSD-3-Clause) as a black box.

Two jobs, both through Babel's public API only:

1. `--check-table`: (a) compare the 25 original rows (TABLE below) with what
   Babel's CLDR data says; (b) regenerate `src/cldr_locales.zig` in memory and
   require it to equal the file on disk (stale table = failure). Exit 1 on any
   mismatch.
1b. `--gen-table`: write `src/cldr_locales.zig`, every locale identifier Babel
   knows (name, latn group/decimal, grouping, the locale's default numbering
   system with its group/decimal), plus the digit-zero code point of each
   numbering system that appears. Digit zeros come from Python's
   `unicodedata` (Babel exposes no digit data): the code point named
   "<SCRIPT> DIGIT ZERO", checked to start ten consecutive decimal digits 0..9.
2. default: write `src/testdata/babel_golden.txt` — one line per case,
   `locale<TAB>input<TAB>expected`, where `expected` is what
   `babel.numbers.parse_decimal(input, locale, strict=True)` returns as a
   plain decimal string, or `-` when it refuses. Inputs are Babel's own
   formatting of random values (must parse) plus systematic corruptions of
   them (wrong group widths, swapped or mixed separators, a leading-zero
   group, a dangling separator), so both acceptance and refusal are covered.

Babel's strict mode has a few behaviours `numparse` deliberately does not copy
(listed in SPEC.md "Verification"); those input shapes are simply not
generated here: a leading '+' or U+2212, a trailing decimal separator, an
exponent, an empty integer part before the decimal separator, and leading
zeros on an UNGROUPED integer (Babel's strict re-format check refuses
`0123`; numparse reads it as 123, like Decimal.parse).

    modules/numparse/tools/babel-oracle.py --check-table
    modules/numparse/tools/babel-oracle.py --gen-table
    modules/numparse/tools/babel-oracle.py > modules/numparse/src/testdata/babel_golden.txt
"""
import os
import random
import sys
import unicodedata
from decimal import Decimal

import babel
from babel import Locale, localedata
from babel.numbers import (NumberFormatError, format_decimal, get_decimal_symbol,
                           get_group_symbol, parse_decimal, parse_grouping)

# Mirror of the table in src/root.zig `locale` (name, group, decimal, grouping).
TABLE = [
    ("en", ",", ".", "western"), ("en_US", ",", ".", "western"),
    ("en_GB", ",", ".", "western"), ("en_IN", ",", ".", "indian"),
    ("hi", ",", ".", "indian"), ("ja", ",", ".", "western"),
    ("zh", ",", ".", "western"), ("de", ".", ",", "western"),
    ("de_AT", ".", ",", "western"), ("de_CH", "’", ".", "western"),
    ("it", ".", ",", "western"), ("es", ".", ",", "western"),
    ("pt_BR", ".", ",", "western"), ("nl", ".", ",", "western"),
    ("da", ".", ",", "western"), ("fr", " ", ",", "western"),
    ("cs", " ", ",", "western"), ("sk", " ", ",", "western"),
    ("pl", " ", ",", "western"), ("ru", " ", ",", "western"),
    ("uk", " ", ",", "western"), ("sv", " ", ",", "western"),
    ("fi", " ", ",", "western"), ("hu", " ", ",", "western"),
    ("nb", " ", ",", "western"),
]


GROUPING_BY_SIZES = {(3, 3): "western", (3, 2): "indian", (2, 2): "two", (1000, 1000): "none"}

# CLDR 46 is what Babel 2.17 ships; Babel has no API for the version
# (`babel.core.get_cldr_version` does not exist in 2.17), so it is named here
# and the header says so.
CLDR_VERSION_FALLBACK = "46 (Babel 2.17 data; Babel exposes no CLDR version API)"

# "<script> DIGIT ZERO" names, Unicode character names.
ZERO_NAMES = {
    "latn": "DIGIT ZERO",
    "arab": "ARABIC-INDIC DIGIT ZERO",
    "arabext": "EXTENDED ARABIC-INDIC DIGIT ZERO",
    "deva": "DEVANAGARI DIGIT ZERO",
    "adlm": "ADLAM DIGIT ZERO",
    "beng": "BENGALI DIGIT ZERO",
    "cakm": "CHAKMA DIGIT ZERO",
    "hmnp": "NYIAKENG PUACHUE HMONG DIGIT ZERO",
    "olck": "OL CHIKI DIGIT ZERO",
    "tibt": "TIBETAN DIGIT ZERO",
    "nkoo": "NKO DIGIT ZERO",
    "mymr": "MYANMAR DIGIT ZERO",
    "mtei": "MEETEI MAYEK DIGIT ZERO",
}


def grouping_kind(loc):
    pattern = loc.decimal_formats[None].pattern.split(";")[0]
    integer = pattern.split(".")[0]
    return GROUPING_BY_SIZES[parse_grouping(integer)]


def zero_of(ns):
    z = ord(unicodedata.lookup(ZERO_NAMES[ns]))
    for k in range(10):
        assert unicodedata.decimal(chr(z + k)) == k, (ns, k)
    return z


def locale_rows():
    rows = []
    for ident in sorted(localedata.locale_identifiers(), key=str.lower):
        loc = Locale.parse(ident)
        lat = loc.number_symbols["latn"]
        ns = loc.default_numbering_system
        # Babel's own accessors, as parse_decimal(numbering_system='default')
        # uses them: the CLDR `alias` entries (ne, as, ccp, ...) resolve to latn.
        rows.append((ident, lat["group"], lat["decimal"], grouping_kind(loc), ns,
                     get_group_symbol(loc, numbering_system="default"),
                     get_decimal_symbol(loc, numbering_system="default")))
    return rows


def zig_str(s):
    out = []
    for ch in s:
        o = ord(ch)
        if 0x20 <= o < 0x7F and ch not in '"\\':
            out.append(ch)
        else:
            out.append("\\u{%X}" % o)
    return '"' + "".join(out) + '"'


def gen_table_text():
    rows = locale_rows()
    systems = sorted({r[4] for r in rows} | {"latn"})
    try:
        cldr = babel.core.get_cldr_version()
    except AttributeError:
        cldr = CLDR_VERSION_FALLBACK
    o = []
    o.append("// SPDX-License-Identifier: MIT AND Unicode-3.0")
    o.append("// GENERATED by tools/babel-oracle.py --gen-table; do not edit.")
    o.append("// Source: Babel %s, CLDR %s." % (babel.__version__, cldr))
    o.append("// Digit zeros: Python unicodedata %s (\"<SCRIPT> DIGIT ZERO\"), checked as ten"
             % unicodedata.unidata_version)
    o.append("// consecutive decimal digits. Data derived from Unicode CLDR (Unicode-3.0")
    o.append("// licence) via Babel (BSD-3-Clause); see ../NOTICE.")
    o.append("")
    o.append("pub const Grouping = enum {")
    o.append("    /// Groups of three: `1,234,567` (most of CLDR).")
    o.append("    western,")
    o.append("    /// Indian lakh/crore: the last group three, the others two, `12,34,567`.")
    o.append("    indian,")
    o.append("    /// Groups of two (CLDR pattern `#,#0.###`, e.g. `tok`): `1,23,45`.")
    o.append("    two,")
    o.append("    /// The locale does not group (CLDR pattern `0.######`, `en_US_POSIX`):")
    o.append("    /// any group separator in the input is refused.")
    o.append("    none,")
    o.append("};")
    o.append("")
    o.append("pub const System = struct { name: []const u8, zero: u21 };")
    o.append("")
    o.append("/// Numbering systems that occur as a locale default (plus latn), by name.")
    o.append("pub const systems = [_]System{")
    for n in systems:
        o.append("    .{ .name = %s, .zero = 0x%X }," % (zig_str(n), zero_of(n)))
    o.append("};")
    o.append("")
    o.append("pub const Row = struct {")
    o.append("    name: []const u8,")
    o.append("    group: []const u8,")
    o.append("    decimal: []const u8,")
    o.append("    grouping: Grouping,")
    o.append("    /// Index into `systems`: the locale's default numbering system.")
    o.append("    native: u8,")
    o.append("    native_group: []const u8,")
    o.append("    native_decimal: []const u8,")
    o.append("};")
    o.append("")
    o.append("/// Sorted by `name` lowercased (byte order).")
    o.append("pub const rows = [_]Row{")
    for (n, g, d, k, ns, ng, nd) in rows:
        o.append("    .{ .name = %s, .group = %s, .decimal = %s, .grouping = .%s, .native = %d, "
                 ".native_group = %s, .native_decimal = %s },"
                 % (zig_str(n), zig_str(g), zig_str(d), k, systems.index(ns), zig_str(ng), zig_str(nd)))
    o.append("};")
    o.append("")
    return "\n".join(o)


TABLE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "cldr_locales.zig")


def check_table():
    bad = 0
    for name, group, dec, grouping in TABLE:
        loc = Locale.parse(name)
        sym = loc.number_symbols["latn"]
        got = (sym["group"], sym["decimal"], grouping_kind(loc))
        if got != (group, dec, grouping):
            print(f"MISMATCH {name}: table {(group, dec, grouping)!r} CLDR {got!r}")
            bad += 1
    print(f"table: {len(TABLE)} locales, {bad} mismatches")
    try:
        on_disk = open(TABLE_PATH, encoding="utf-8").read()
    except OSError:
        on_disk = None
    fresh = gen_table_text()
    if on_disk != fresh:
        print("MISMATCH src/cldr_locales.zig is missing or differs from a fresh --gen-table")
        bad += 1
    else:
        print(f"generated table: {len(locale_rows())} locales, up to date")
    return bad == 0


def plain(d):
    s = format(d, "f")
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    if s in ("-0", ""):
        s = "0"
    return s


def oracle(text, name, native=False):
    try:
        return plain(parse_decimal(text, locale=name, strict=True,
                                   numbering_system="default" if native else "latn"))
    except (NumberFormatError, ValueError):
        return "-"


def corruptions(text, group, dec):
    out = []
    if group in text:
        i = text.index(group)
        out.append(text[:i] + text[i + len(group):])          # drop one separator
        out.append(text[: i + len(group) + 1] + group + text[i + len(group) + 1:])  # split a group
        out.append(text.replace(group, dec, 1))                 # swap the first separator
        out.append("0" + text)                                  # leading-zero first group
        out.append(text + group)                                # dangling separator
        if group != " ":
            out.append(text.replace(group, " ", 1))             # mixed spelling
    if dec in text:
        i = text.index(dec)
        out.append(text[:i] + group + text[i + len(dec):])      # decimal → group
        out.append(text + dec + "5")                            # second decimal separator
    return out


def emit(name, text, seen, tag=None, native=False):
    key = (name, text, native)
    if not text or key in seen:
        return
    seen.add(key)
    if native:
        v = oracle(text, name, native=True)
        print(f"{name}:native\t{text}\t{v}")
    else:
        print(f"{name}\t{text}\t{oracle(text, name)}")


def random_value(rng):
    mag = rng.choice([1, 2, 3, 4, 5, 6, 7, 9, 12])
    v = Decimal(rng.randrange(10 ** (mag - 1), 10 ** mag))
    if rng.random() < 0.6:
        v = v / (Decimal(10) ** rng.randrange(1, 4))
    if rng.random() < 0.3:
        v = -v
    return v


def extended_sample(rows):
    """Locales for the extended golden: every non-western grouping, one
    locale per distinct (group, decimal) pair, 20 random ones, and the first
    three locales of every non-latn default numbering system."""
    pick = {}
    for r in rows:
        if r[3] != "western":
            pick[r[0]] = r
    pairs = {}
    for r in rows:
        pairs.setdefault((r[1], r[2]), r)
    for r in pairs.values():
        pick[r[0]] = r
    rng = random.Random(20261020)
    for r in rng.sample(rows, 20):
        pick[r[0]] = r
    per_ns = {}
    for r in rows:
        if r[4] != "latn" and per_ns.setdefault(r[4], []).__len__() < 3:
            per_ns[r[4]].append(r)
            pick[r[0]] = r
    return sorted(pick.values(), key=lambda r: r[0].lower())


def main():
    rng = random.Random(20261004)
    print("# numparse golden: babel.numbers.parse_decimal(strict=True), Babel "
          + babel.__version__ + "; generated by tools/babel-oracle.py")
    seen = set()
    for name, group, dec, _ in TABLE:
        for _ in range(40):
            v = random_value(rng)
            text = format_decimal(v, locale=name, decimal_quantization=False)
            for t in [text] + corruptions(text, group, dec):
                if not t or (name, t) in seen:
                    continue
                seen.add((name, t))
                print(f"{name}\t{t}\t{oracle(t, name)}")

    # Extended: sampled CLDR locales. Lines `name:native` use the locale's own
    # numbering system (parse_decimal(numbering_system='default')): ungrouped
    # numbers only, since Babel's strict mode refuses grouped native-digit
    # numbers (its check formats with latn digits); those are hand-tested.
    print("# extended: sampled CLDR locales (latn, then `name:native`)")
    rng = random.Random(20261020)
    seen = set()
    old = {r[0] for r in TABLE}
    for (name, group, dec, kind, ns, ngroup, ndec) in extended_sample(locale_rows()):
        if name in old:
            continue
        for _ in range(8):
            v = random_value(rng)
            text = format_decimal(v, locale=name, decimal_quantization=False)
            for t in [text] + corruptions(text, group, dec):
                emit(name, t, seen)
            # group separators where the locale has none (en_US_POSIX) or
            # in shapes the other kinds refuse
            for t in (f"1{group}234", f"12{group}34", f"1{group}23{group}45", f"1{group}234{dec}5"):
                emit(name, t, seen)
        if ns != "latn":
            for _ in range(6):
                v = random_value(rng)
                text = format_decimal(v, locale=name, decimal_quantization=False,
                                      group_separator=False, numbering_system="default")
                # Babel formats symbols natively but always emits ASCII digits,
                # so transliterate them here (Python's Decimal reads any Nd).
                z = zero_of(ns)
                text = text.translate({48 + k: chr(z + k) for k in range(10)})
                for t in (text, text + ndec + text.lstrip("-")[:1], text + "x"):
                    emit(name, t, seen, native=True)


if __name__ == "__main__":
    if "--check-table" in sys.argv:
        sys.exit(0 if check_table() else 1)
    if "--gen-table" in sys.argv:
        text = gen_table_text()
        with open(TABLE_PATH, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"wrote {TABLE_PATH}", file=sys.stderr)
        sys.exit(0)
    main()
