#!/usr/bin/env python3
"""Generate src/cjk_tables.zig from the vendored WHATWG CJK index files.

Usage:  python3 -I tools/gen_cjk_tables.py [--check]

Reads ONLY src/testdata/index-{jis0208,jis0212,iso-2022-jp-katakana,euc-kr,
gb18030,gb18030-ranges,big5}.txt (vendored byte-for-byte, see ../NOTICE); no
network. Deterministic. --check regenerates in memory and fails if
src/cjk_tables.zig differs.

Layout (see the header the generator writes for the byte counts):

  decode  `<name>_dec`   pointer -> low 16 bits of the code point, 0xFFFF = no
                         entry (U+FFFF is in no index). Index base: entry i is
                         pointer `<name>_base + i`. Big5 alone has code points
                         above U+FFFF (all in plane 2, U+20000..U+2FFFF); their
                         plane bit is `big5_sip[i / 8] >> (i % 8) & 1`.
  encode  `<name>_enc`   the POINTERS to use, one per encodable code point,
                         sorted by the code point they decode to (a binary
                         search compares through `_dec`): 2 bytes per code
                         point, no second copy of the code points.
                         The Standard's per-encoding pointer rules are applied
                         here ("first pointer"; Big5: pointers < 5024 excluded
                         and the LAST pointer for six code points) so the
                         runtime does no filtering.
  jis0208_sjis_fix       Shift_JIS excludes pointers 8272..8835 ("index
                         Shift_JIS pointer"); for the code points whose first
                         pointer lies there, the first pointer outside it.
"""
import hashlib
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "src")
TESTDATA = os.path.join(SRC, "testdata")
OUT = os.path.join(SRC, "cjk_tables.zig")

NONE = 0xFFFF
FILES = [
    "jis0208", "jis0212", "iso-2022-jp-katakana", "euc-kr",
    "gb18030", "gb18030-ranges", "big5",
]


def read(path):
    with open(path, "rb") as f:
        return f.read()


def parse(name):
    """-> (dict pointer -> code point, identifier, date)."""
    text = read(os.path.join(TESTDATA, "index-%s.txt" % name)).decode("utf-8")
    d = {}
    ident = date = None
    for line in text.split("\n"):
        if not line:
            continue
        if line.startswith("#"):
            m = re.match(r"# Identifier: ([0-9a-f]{64})$", line)
            if m:
                ident = m.group(1)
            m = re.match(r"# Date: (\d{4}-\d\d-\d\d)$", line)
            if m:
                date = m.group(1)
            continue
        parts = line.split("\t")
        p = int(parts[0])
        assert p not in d, (name, p)
        assert parts[1].startswith("0x")
        d[p] = int(parts[1], 16)
    assert ident and date, name
    return d, ident, date


def first_pointers(idx, skip=lambda p: False):
    first = {}
    for p in sorted(idx):
        if skip(p):
            continue
        first.setdefault(idx[p], p)
    return first


class Out:
    def __init__(self):
        self.lines = []
        self.sizes = []  # (symbol, bytes)

    def emit(self, text):
        self.lines.append(text)

    def array(self, sym, typ, values, doc, per_line=12, fmt="0x%04X"):
        self.sizes.append((sym, len(values) * {"u16": 2, "u8": 1, "u32": 4}[typ]))
        self.emit("/// %s" % doc)
        self.emit("pub const %s = [_]%s{" % (sym, typ))
        for i in range(0, len(values), per_line):
            self.emit("    " + ", ".join(fmt % v for v in values[i:i + per_line]) + ",")
        self.emit("};")
        self.emit("")


def dense(idx, base):
    n = max(idx) + 1 - base
    arr = [NONE] * n
    for p, cp in idx.items():
        assert cp != NONE
        assert cp <= 0xFFFF, "non-BMP needs the plane bitset"
        arr[p - base] = cp
    return arr


def main():
    idx = {}
    meta = {}
    for n in FILES:
        idx[n], ident, date = parse(n)
        meta[n] = (ident, date)

    out = Out()

    # ---- jis0208 / jis0212 / katakana --------------------------------
    j8 = idx["jis0208"]
    j12 = idx["jis0212"]
    kata = idx["iso-2022-jp-katakana"]
    assert sorted(kata) == list(range(63))
    out.array("jis0208_dec", "u16", dense(j8, 0), "index jis0208, pointer 0..%d." % max(j8))
    out.array("jis0212_dec", "u16", dense(j12, min(j12)), "index jis0212, pointer %d..%d (`jis0212_base`)." % (min(j12), max(j12)))
    out.array("katakana_dec", "u16", dense(kata, 0), "index ISO-2022-JP katakana: halfwidth U+FF61 + i -> its code point.", per_line=12)

    first8 = first_pointers(j8)
    out.array("jis0208_enc", "u16", [first8[cp] for cp in sorted(first8)],
              "index jis0208 pointer for each code point (the FIRST pointer), sorted by code point.")
    sj_first = first_pointers(j8, skip=lambda p: 8272 <= p <= 8835)
    fix = [cp for cp in sorted(first8) if 8272 <= first8[cp] <= 8835 and cp in sj_first]
    # every code point whose first pointer is excluded has another one outside the range
    # (the generator proves it, the runtime relies on it)
    lost = [cp for cp in first8 if 8272 <= first8[cp] <= 8835 and cp not in sj_first]
    assert not lost, lost
    out.array("jis0208_sjis_fix", "u16", [sj_first[cp] for cp in fix],
              "Shift_JIS pointer for the code points whose first pointer is in 8272..8835, sorted by code point.")
    # the code points that sort into jis0208_enc must be found in the fix table by value
    # EUC-JP/ISO-2022-JP use first8 as is (pointer < 8836, per the Standard).
    assert all(p < 8836 for p in first8.values())

    # ---- EUC-KR ------------------------------------------------------
    ek = idx["euc-kr"]
    out.array("euckr_dec", "u16", dense(ek, 0), "index EUC-KR, pointer 0..%d." % max(ek))
    firstk = first_pointers(ek)
    out.array("euckr_enc", "u16", [firstk[cp] for cp in sorted(firstk)], "index EUC-KR pointer per code point (first), sorted by code point.")

    # ---- gb18030 ------------------------------------------------------
    gb = idx["gb18030"]
    out.array("gb_dec", "u16", dense(gb, 0), "index gb18030, pointer 0..%d." % max(gb))
    firstg = first_pointers(gb)
    out.array("gb_enc", "u16", [firstg[cp] for cp in sorted(firstg)], "index gb18030 pointer per code point (first), sorted by code point.")
    rg = idx["gb18030-ranges"]
    rp = sorted(rg)
    rc = [rg[p] for p in rp]
    # the Standard's "last code point <= codePoint" search needs both columns increasing
    assert all(a < b for a, b in zip(rc, rc[1:])) and all(a < b for a, b in zip(rp, rp[1:]))
    out.array("gb_ranges_ptr", "u32", rp, "index gb18030 ranges, first column (pointer), ascending.", per_line=10, fmt="0x%06X")
    out.array("gb_ranges_cp", "u32", rc, "index gb18030 ranges, second column (code point), ascending.", per_line=10, fmt="0x%06X")

    # ---- Big5 ---------------------------------------------------------
    b5 = idx["big5"]
    base = min(b5)
    n = max(b5) + 1 - base
    low = [NONE] * n
    sip = [0] * ((n + 7) // 8)
    for p, cp in b5.items():
        if cp > 0xFFFF:
            assert cp >> 16 == 2 and (cp & 0xFFFF) != NONE
            sip[(p - base) // 8] |= 1 << ((p - base) % 8)
        assert cp != NONE
        low[p - base] = cp & 0xFFFF
    out.array("big5_dec", "u16", low, "index Big5, pointer %d..%d (`big5_base`); low 16 bits of the code point." % (base, max(b5)))
    out.array("big5_sip", "u8", sip, "Big5 plane bit per `big5_dec` entry: set = code point is U+2xxxx.", per_line=24, fmt="0x%02X")
    # "index Big5 pointer": exclude pointers < (0xA1 - 0x81) * 157, first pointer,
    # except the LAST pointer for six code points.
    lim = (0xA1 - 0x81) * 157
    assert lim == 5024
    cand = {p: cp for p, cp in b5.items() if p >= lim}
    fb = first_pointers(cand)
    lastp = {}
    for p in sorted(cand):
        lastp[cand[p]] = p
    for cp in (0x2550, 0x255E, 0x2561, 0x256A, 0x5341, 0x5345):
        assert cp in fb
        fb[cp] = lastp[cp]
    out.array("big5_enc", "u16", [fb[cp] for cp in sorted(fb)], "index Big5 pointer per code point (Standard's rules), sorted by code point.")

    # ---- assemble ------------------------------------------------------
    total = sum(s for _, s in out.sizes)
    h = hashlib.sha256()
    for n_ in FILES:
        h.update(n_.encode() + b"\0" + meta[n_][0].encode() + b"\0")
    hdr = []
    hdr.append("// SPDX-License-Identifier: MIT")
    hdr.append("//! GENERATED by tools/gen_cjk_tables.py from the vendored WHATWG Encoding Standard")
    hdr.append("//! index files (src/testdata/index-*.txt). Do not edit; `--check` verifies.")
    hdr.append("//! A MODIFIED rendering of CC-BY 4.0 data (see ../NOTICE): reformatted into")
    hdr.append("//! arrays, 0xFFFF marks \"no pointer\", encode tables added, the Standard's")
    hdr.append("//! pointer-selection rules pre-applied.")
    hdr.append("//!")
    hdr.append("//! Sources (index Identifier, Date):")
    for n_ in FILES:
        hdr.append("//!   index-%s.txt  %s  %s" % (n_, meta[n_][0][:16], meta[n_][1]))
    hdr.append("//!")
    hdr.append("//! Bytes per table (decode + encode share nothing; total %d bytes = %.1f KiB):" % (total, total / 1024))
    for sym, sz in out.sizes:
        hdr.append("//!   %-18s %6d" % (sym, sz))
    hdr.append("//! Per encoding (decode + encode tables it owns; jis0208 is shared by Shift_JIS,")
    hdr.append("//! EUC-JP and ISO-2022-JP, jis0212 by EUC-JP decode only):")
    sz = dict(out.sizes)

    def tot(*names):
        return sum(sz[x] for x in names)
    hdr.append("//!   shift_jis    %6d  (jis0208_dec, jis0208_enc, jis0208_sjis_fix)" % tot("jis0208_dec", "jis0208_enc", "jis0208_sjis_fix"))
    hdr.append("//!   euc_jp       %6d  (jis0208_dec, jis0208_enc, jis0212_dec; shared with shift_jis)" % tot("jis0208_dec", "jis0208_enc", "jis0212_dec"))
    hdr.append("//!   iso_2022_jp  %6d  (jis0208_dec, jis0208_enc, katakana_dec; shared)" % tot("jis0208_dec", "jis0208_enc", "katakana_dec"))
    hdr.append("//!   euc_kr       %6d  (euckr_dec, euckr_enc)" % tot("euckr_dec", "euckr_enc"))
    hdr.append("//!   gb18030/gbk  %6d  (gb_dec, gb_enc, gb_ranges_ptr, gb_ranges_cp)" % tot("gb_dec", "gb_enc", "gb_ranges_ptr", "gb_ranges_cp"))
    hdr.append("//!   big5         %6d  (big5_dec, big5_sip, big5_enc)" % tot("big5_dec", "big5_sip", "big5_enc"))
    hdr.append("")
    hdr.append("pub const jis0212_base: u32 = %d;" % min(j12))
    hdr.append("pub const big5_base: u32 = %d;" % base)
    hdr.append("")
    text = "\n".join(hdr + out.lines)
    if not text.endswith("\n"):
        text += "\n"
    data = text.encode("utf-8")

    if "--check" in sys.argv:
        cur = read(OUT) if os.path.exists(OUT) else b""
        if cur != data:
            sys.stderr.write("cjk_tables.zig is out of date: run python3 -I tools/gen_cjk_tables.py\n")
            return 1
        print("cjk_tables.zig: up to date (%d bytes)" % len(data))
        return 0
    with open(OUT, "wb") as f:
        f.write(data)
    print("wrote %s (%d bytes of source, %d bytes of tables)" % (OUT, len(data), total))
    return 0


if __name__ == "__main__":
    sys.exit(main())
