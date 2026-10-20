#!/usr/bin/env python3
"""Generate src/sb_tables.zig from the vendored WHATWG Encoding Standard files.

Usage:  python3 -I tools/gen_tables.py [--check]

Reads ONLY src/testdata/encodings.json, src/testdata/index-*.txt (WHATWG) and
src/testdata/CP{437,850,852}.TXT (Unicode.org MICSFT/PC mappings), all vendored
byte-for-byte, see ../NOTICE; no network. Deterministic: the same inputs give
the same bytes. --check regenerates in memory and fails if src/sb_tables.zig
differs.

Output: per single-byte page a 128-entry decode table (byte 0x80..0xFF, 0xFFFF
= no pointer -> U+FFFD), a sorted encode table (the inverse), the canonical
name; plus the complete label table of encodings.json and the labels of the
non-WHATWG DOS pages (DOS_PAGES below).
"""
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "src")
TESTDATA = os.path.join(SRC, "testdata")
OUT = os.path.join(SRC, "sb_tables.zig")

SB_HEADING = "Legacy single-byte encodings"
SENTINEL = 0xFFFF

# WHATWG names that are not single-byte pages and what they map to.
SPECIAL = {
    "UTF-8": "utf8",
    "UTF-16LE": "utf16le",
    "UTF-16BE": "utf16be",
    "replacement": "replacement",
}
# `x-user-defined` has no index file: byte 0x80+i is U+F780+i (WHATWG, "x-user-defined
# decoder"). It becomes a page like the single-byte ones (appended after iso_8859_1).
X_USER_DEFINED = "x-user-defined"

# NON-WHATWG pages: IBM PC / MS-DOS code pages from Unicode.org's MICSFT/PC
# mappings. (page name = IANA name, tag, vendored file, labels). The labels are
# the IANA aliases of each charset (https://www.iana.org/assignments/character-sets),
# NOT from the WHATWG table: WHATWG has no such encodings, so `lookupLabel`
# answering them is this module's extension. None may collide with a WHATWG label.
DOS_PAGES = [
    ("IBM437", "cp437", "CP437.TXT", ["cp437", "ibm437", "437", "cspc8codepage437"]),
    ("IBM850", "cp850", "CP850.TXT", ["cp850", "ibm850", "850", "cspc850multilingual"]),
    ("IBM852", "cp852", "CP852.TXT", ["cp852", "ibm852", "852", "cspcp852"]),
]
# Page whose index file is shared (no index-ISO-8859-8-I.txt exists).
SHARED_INDEX = {"ISO-8859-8-I": "ISO-8859-8"}

# Departure from WHATWG, kept from root.zig `Encoding.parse`: WHATWG maps these
# labels to windows-1252 (what the web actually contains); this module keeps a
# distinct, true ISO/IEC 8859-1 page and these labels select it. Every other
# windows-1252 label (ascii, us-ascii, ansi_x3.4-1968, cp1252, x-cp1252,
# windows-1252) stays on windows-1252.
ISO_8859_1_OVERRIDES = [
    ("iso-8859-1", "WHATWG: windows-1252; this module: true ISO/IEC 8859-1"),
    ("iso8859-1", "WHATWG: windows-1252; this module: true ISO/IEC 8859-1"),
    ("iso88591", "WHATWG: windows-1252; this module: true ISO/IEC 8859-1"),
    ("iso_8859-1", "WHATWG: windows-1252; this module: true ISO/IEC 8859-1"),
    ("iso_8859-1:1987", "IANA name of ISO_8859-1; follows the iso-8859-1 family"),
    ("iso-ir-100", "IANA alias of ISO_8859-1:1987; follows the family"),
    ("latin1", "WHATWG: windows-1252; this module: true ISO/IEC 8859-1"),
    ("l1", "IANA alias of ISO_8859-1:1987; follows the family"),
    ("csisolatin1", "IANA alias of ISO_8859-1:1987; follows the family"),
    ("cp819", "IANA alias of ISO_8859-1:1987; follows the family"),
    ("ibm819", "IANA alias of ISO_8859-1:1987; follows the family"),
]


def read(path):
    with open(path, "rb") as f:
        return f.read()


def tag(name):
    return name.lower().replace("-", "_")


def parse_index(name):
    """Return (decode[128] with SENTINEL holes, identifier, date)."""
    fname = "index-%s.txt" % SHARED_INDEX.get(name, name).lower()
    text = read(os.path.join(TESTDATA, fname)).decode("utf-8")
    dec = [None] * 128
    ident = date = None
    for line in text.split("\n"):
        s = line.strip()
        if not s:
            continue
        if s.startswith("#"):
            m = re.match(r"# Identifier: ([0-9a-f]{64})$", s)
            if m:
                ident = m.group(1)
            m = re.match(r"# Date: (\S+)$", s)
            if m:
                date = m.group(1)
            continue
        f = line.split("\t")
        ptr, cp = int(f[0].strip()), int(f[1].strip(), 16)
        assert 0 <= ptr < 128 and dec[ptr] is None, (fname, ptr)
        assert cp < SENTINEL, (fname, cp)  # 0xFFFF is the hole sentinel
        dec[ptr] = cp
    # Upstream's Identifier = sha256(json.dumps(codepoints)). Reproducible for
    # gap-free indexes; for indexes with holes the serialisation upstream
    # hashes is not known to us (null / compact / filtered variants all miss),
    # so only gap-free files are checked here.
    if None not in dec:
        h = hashlib.sha256(json.dumps(dec).encode("ascii")).hexdigest()
        assert h == ident, "%s: Identifier mismatch (%s != %s)" % (fname, h, ident)
    return [SENTINEL if c is None else c for c in dec], ident, date


def parse_micsft(fname):
    """Decode table (128 entries) of a Unicode.org MICSFT/PC mapping file.
    Every byte must be defined once and 0x00-0x7F must be the identity (the
    `Encoding` invariant is ASCII compatibility)."""
    # The files end with a DOS ^Z; only lines starting `0x` are data.
    text = read(os.path.join(TESTDATA, fname)).decode("ascii")
    m = {}
    for line in text.split("\n"):
        line = line.rstrip("\r")
        if not line.startswith("0x"):
            continue
        f = line.split("\t")
        b, cp = int(f[0], 16), int(f[1], 16)
        assert 0 <= b < 256 and b not in m and cp < SENTINEL, (fname, b)
        m[b] = cp
    assert sorted(m) == list(range(256)), fname
    assert all(m[b] == b for b in range(128)), fname + ": low half is not ASCII"
    return [m[b] for b in range(128, 256)]


def build():
    raw = read(os.path.join(TESTDATA, "encodings.json"))
    groups = json.loads(raw.decode("utf-8"))

    pages = []  # (name, tag, decode)
    label_target = {}  # label -> (kind, payload)
    dates = set()
    late_pages = []  # appended after iso_8859_1
    for g in groups:
        single = g["heading"] == SB_HEADING
        for e in g["encodings"]:
            name = e["name"]
            if single:
                dec, _, date = parse_index(name)
                dates.add(date)
                pages.append((name, tag(name), dec))
                target = ("page", tag(name))
            elif name == X_USER_DEFINED:
                late_pages.append((name, tag(name), [0xF780 + i for i in range(128)]))
                target = ("page", tag(name))
            elif name in SPECIAL:
                target = (SPECIAL[name], None)
            elif "multi-byte" in g["heading"]:
                target = ("unsupported", name)
            else:
                raise SystemExit("unclassified encoding %r" % name)
            for lab in e["labels"]:
                assert lab == lab.lower() and lab not in label_target, lab
                label_target[lab] = target
    assert len(dates) == 1, dates
    date = dates.pop()

    for lab, why in ISO_8859_1_OVERRIDES:
        assert label_target[lab] == ("page", "windows_1252"), lab
    override = dict(ISO_8859_1_OVERRIDES)

    # iso_8859_1: the true Latin-1 identity high half (not a WHATWG encoding).
    pages.append(("iso-8859-1", "iso_8859_1", list(range(0x80, 0x100))))
    pages.extend(late_pages)
    n_whatwg_labels = len(label_target)
    for name, t, fname, labs in DOS_PAGES:
        pages.append((name, t, parse_micsft(fname)))
        for lab in labs:
            assert lab == lab.lower() and lab not in label_target, lab
            label_target[lab] = ("page", t)
    dos_labels = {lab for _, _, _, labs in DOS_PAGES for lab in labs}

    o = []
    w = o.append
    w("// SPDX-License-Identifier: MIT\n")
    w("//! GENERATED by tools/gen_tables.py from the vendored WHATWG files — do not edit.\n")
    w("//!\n")
    w("//! Source: WHATWG Encoding Standard (https://encoding.spec.whatwg.org/), the vendored\n")
    w("//! src/testdata/index-*.txt (each header: Date: %s) and src/testdata/encodings.json\n" % date)
    w("//! (sha256 %s); the DOS pages cp437/cp850/cp852 come from Unicode.org's\n" % hashlib.sha256(raw).hexdigest())
    w("//! MICSFT/PC mapping files src/testdata/CP{437,850,852}.TXT, and x_user_defined\n")
    w("//! (U+F780 + byte - 0x80) from the Standard's own definition.\n")
    w("//! Derived data, see ../NOTICE (CC-BY 4.0; this file is a MODIFIED, reformatted\n")
    w("//! rendering of the vendored tables). Regenerate: `python3 -I tools/gen_tables.py`;\n")
    w("//! `--check` verifies this file is current.\n")
    w("//!\n")
    w("//! Decode tables: index 0 = byte 0x80; 0xFFFF = the index has no pointer for the\n")
    w("//! byte (decodes to U+FFFD). Encode tables: the inverse, sorted by `cp`, high\n")
    w("//! entries only (ASCII is identity). WHATWG's encoder uses the FIRST index pointer\n")
    w("//! for a code point; no vendored index maps two bytes to one code point, so each\n")
    w("//! inverse is unambiguous.\n\n")
    w('const std = @import("std");\n\n')
    w("/// Sentinel in a decode table: byte has no pointer in the index.\n")
    w("pub const undefined_cp: u16 = 0xFFFF;\n\n")
    w("pub const Page = enum {\n")
    for _, t, _ in pages:
        w("    %s,\n" % t)
    w("};\n\n")
    w("pub const EncodeEntry = struct { cp: u16, byte: u8 };\n\n")
    w("pub const PageInfo = struct {\n")
    w("    page: Page,\n")
    w("    /// WHATWG name, exact case (`iso_8859_1`: this module's own name).\n")
    w("    canonical_name: []const u8,\n")
    w("    decode: *const [128]u16,\n")
    w("    encode: []const EncodeEntry,\n")
    w("};\n\n")

    def emit_decode(t, dec):
        w("pub const %s_decode: [128]u16 = .{\n" % t)
        for i in range(0, 128, 8):
            w("    " + " ".join("0x%04X," % c for c in dec[i:i + 8]) + "\n")
        w("};\n\n")

    def inverse(dec):
        inv = {}
        for i, c in enumerate(dec):
            if c != SENTINEL and c not in inv:  # first pointer wins
                inv[c] = 0x80 + i
        return sorted(inv.items())

    done = {}
    for name, t, dec in pages:
        w("pub const %s_canonical_name = \"%s\";\n" % (t, name))
        if name in SHARED_INDEX:
            base = tag(SHARED_INDEX[name])
            assert done[base] == dec
            w("pub const %s_decode = %s_decode;\n" % (t, base))
            w("pub const %s_encode = %s_encode;\n\n" % (t, base))
            continue
        done[t] = dec
        emit_decode(t, dec)
        inv = inverse(dec)
        w("pub const %s_encode = [%d]EncodeEntry{\n" % (t, len(inv)))
        for cp, b in inv:
            w("    .{ .cp = 0x%04X, .byte = 0x%02X },\n" % (cp, b))
        w("};\n\n")

    w("/// One entry per `Page`, in declaration order: `page_info[@backingInt(p)]`.\n")
    w("pub const page_info = [_]PageInfo{\n")
    for name, t, _ in pages:
        w("    .{ .page = .%s, .canonical_name = %s_canonical_name, .decode = &%s_decode, .encode = &%s_encode },\n" % (t, t, t, t))
    w("};\n\n")
    w("pub fn info(p: Page) *const PageInfo {\n")
    w("    return &page_info[@backingInt(p)];\n")
    w("}\n\n")

    w("/// What a label resolves to (WHATWG \"get an encoding\", before the departure noted\n")
    w("/// at `labels`). `unsupported` carries the WHATWG name of an encoding that is known\n")
    w("/// but not implemented.\n")
    w("pub const Target = union(enum) {\n")
    w("    page: Page,\n    utf8,\n    utf16le,\n    utf16be,\n    replacement,\n")
    w("    unsupported: []const u8,\n")
    w("};\n\n")
    w("pub const Label = struct { label: []const u8, target: Target };\n\n")
    w("/// Every label of encodings.json (%d) plus the %d IANA labels of the non-WHATWG DOS\n" % (n_whatwg_labels, len(dos_labels)))
    w("/// pages (marked below), sorted bytewise by `label` (all lowercase;\n")
    w("/// the caller trims ASCII whitespace and lowercases, then binary-searches).\n")
    w("/// DEPARTURE from WHATWG: the %d labels of the iso-8859-1 family map to\n" % len(ISO_8859_1_OVERRIDES))
    w("/// `.page = .iso_8859_1` instead of windows-1252, each marked below.\n")
    w("pub const labels = [_]Label{\n")
    for lab in sorted(label_target):
        kind, payload = label_target[lab]
        if lab in dos_labels:
            w("    // not WHATWG: IANA alias of a DOS code page\n")
            tgt = ".{ .page = .%s }" % payload
        elif lab in override:
            w("    // departure: %s\n" % override[lab])
            tgt = ".{ .page = .iso_8859_1 }"
        elif kind == "page":
            tgt = ".{ .page = .%s }" % payload
        elif kind == "unsupported":
            tgt = '.{ .unsupported = "%s" }' % payload
        else:
            tgt = ".%s" % kind
        w('    .{ .label = "%s", .target = %s },\n' % (lab, tgt))
    w("};\n\n")
    w("/// Look up an already trimmed, lowercased label.\n")
    w("pub fn lookupLabel(label: []const u8) ?Target {\n")
    w("    const Ctx = struct {\n")
    w("        fn order(key: []const u8, item: Label) std.math.Order {\n")
    w("            return std.mem.order(u8, key, item.label);\n")
    w("        }\n")
    w("    };\n")
    w("    const i = std.sort.binarySearch(Label, &labels, label, Ctx.order) orelse return null;\n")
    w("    return labels[i].target;\n")
    w("}\n")
    return "".join(o)


def main():
    text = build().encode("utf-8")
    if "--check" in sys.argv[1:]:
        cur = read(OUT) if os.path.exists(OUT) else b""
        if cur != text:
            sys.exit("sb_tables.zig is not up to date: run tools/gen_tables.py")
        print("sb_tables.zig is up to date")
    else:
        with open(OUT, "wb") as f:
            f.write(text)


if __name__ == "__main__":
    main()
