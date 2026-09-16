#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Campaign 2: hand-built pathologies. Compares the DECISION (accept/reject) and
the value, not just the value.

WHY THIS EXISTS. A random generator produces messages a correct encoder would
emit. It will never produce a non-minimal varint, a field number of 0, wire type
7, a length claiming 4 GiB, or an overlong UTF-8 NUL — and those are exactly the
inputs where two implementations part company, because each is a place where the
spec says "must reject" and an implementation may quietly not. Every case below
was written by hand for that reason, and the label says which rule it probes.

⚠ EVERY CASE HERE IS A CHOICE SOMEBODY MADE, so a divergence exits non-zero. If
one turns out to be a deliberate difference of policy rather than a defect, add
it to `EXPECTED` below **by label, with the reason** — never by loosening the
comparison. A named exemption stays visible; a weakened check does not.

WHAT IT NEEDS. `pip install protobuf` and the `probe` binary (README.md).

    python3 camp2.py

WHAT IT PRODUCES. One line per case, `!!` marking a divergence, with both sides'
answers; then the totals. Exit 1 if any unexpected divergence was seen, or if
the corpus somehow compared nothing.
"""
import sys
import gen
from gen import varint, tag

# label -> why this divergence is expected and not a defect. Empty by design.
EXPECTED = {}

C = []          # (label, op, schema, hex)


def add(label, schema, raw, op="d"):
    C.append((label, op, schema, raw.hex() if isinstance(raw, (bytes, bytearray)) else raw))


# ── varint pathologies ──────────────────────────────────────────────────────
add("varint/non-minimal 2B", "Wide", tag(1, 0) + b"\x81\x00")
add("varint/non-minimal 5B", "Wide", tag(1, 0) + b"\x81\x80\x80\x80\x00")
add("varint/non-minimal 10B", "Wide", tag(1, 0) + b"\x81\x80\x80\x80\x80\x80\x80\x80\x80\x00")
add("varint/10B all-ones (=u64max)", "Wide", tag(1, 0) + b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01")
add("varint/10th byte = 0x02 (bit64)", "Wide", tag(1, 0) + b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x02")
add("varint/10th byte = 0x7f", "Wide", tag(1, 0) + b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f")
add("varint/11 bytes", "Wide", tag(1, 0) + b"\xff" * 10 + b"\x01")
add("varint/unterminated at EOF", "Wide", tag(1, 0) + b"\x80\x80")
add("varint/lone continuation", "Wide", tag(1, 0) + b"\x80")
add("varint/tag non-minimal", "Wide", b"\x88\x80\x80\x80\x00" + b"\x01")

# ── tag pathologies ─────────────────────────────────────────────────────────
add("tag/field 0 wt0", "Wide", b"\x00\x00")
add("tag/field 0 wt2", "Wide", b"\x02\x00")
add("tag/field 2^29-1", "Wide", tag(2**29 - 1, 0) + b"\x01")
add("tag/field 2^29", "Wide", tag(2**29, 0) + b"\x01")
add("tag/field 2^32", "Wide", tag(2**32, 0) + b"\x01")
add("tag/field 19000 reserved", "Wide", tag(19000, 0) + b"\x01")
add("tag/wt3 sgroup", "Wide", tag(1, 3) + b"")
add("tag/wt3+wt4 balanced group", "Wide", tag(20, 3) + tag(1, 0) + b"\x01" + tag(20, 4))
add("tag/wt4 egroup alone", "Wide", tag(1, 4))
add("tag/wt6", "Wide", tag(1, 6) + b"\x01")
add("tag/wt7", "Wide", tag(1, 7) + b"\x01")

# ── length pathologies ──────────────────────────────────────────────────────
add("len/string len past end", "Wide", tag(15, 2) + varint(4) + b"abc")
add("len/string len exact", "Wide", tag(15, 2) + varint(3) + b"abc")
add("len/4GiB claim", "Wide", tag(15, 2) + varint(0xFFFFFFFF))
add("len/2^63 claim", "Wide", tag(15, 2) + varint(1 << 63))
add("len/u64max claim", "Wide", tag(15, 2) + varint(2**64 - 1))
add("len/zero-length submessage", "Wide", tag(17, 2) + varint(0))
add("len/submessage len past end", "Wide", tag(17, 2) + varint(9) + b"\x08\x01")

# ── repeated / packed ───────────────────────────────────────────────────────
add("packed/packed on packed field", "Repeated", tag(1, 2) + varint(3) + b"\x01\x02\x03")
add("packed/unpacked on packed field", "Repeated", tag(1, 0) + b"\x01" + tag(1, 0) + b"\x02")
add("packed/packed on UNpacked field", "Repeated", tag(2, 2) + varint(3) + b"\x01\x02\x03")
add("packed/unpacked on unpacked field", "Repeated", tag(2, 0) + b"\x01" + tag(2, 0) + b"\x02")
add("packed/mixed both forms field1", "Repeated",
    tag(1, 2) + varint(2) + b"\x01\x02" + tag(1, 0) + b"\x03")
add("packed/empty packed payload", "Repeated", tag(1, 2) + varint(0))
add("packed/truncated last element", "Repeated", tag(1, 2) + varint(2) + b"\x01\x80")
add("packed/fixed32 len not multiple of 4", "Repeated", tag(4, 2) + varint(6) + b"\x01\x02\x03\x04\x05\x06")
add("packed/fixed32 len ok", "Repeated", tag(4, 2) + varint(8) + b"\x01\x02\x03\x04\x05\x06\x07\x08")
add("packed/bool with 0x02", "Repeated", tag(5, 2) + varint(3) + b"\x00\x01\x02")
add("packed/bool multi-byte varint", "Repeated", tag(5, 2) + varint(3) + b"\x80\x80\x01")
add("packed/on a string field (len type)", "Repeated", tag(7, 2) + varint(3) + b"abc")
add("packed/on a message field", "Repeated", tag(8, 2) + varint(2) + b"\x08\x01")
add("packed/enum out of range", "Repeated", tag(6, 2) + varint(5) + b"\xff\xff\xff\xff\x0f")
add("packed/enum negative int32", "Repeated", tag(6, 0) + b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01")

# ── scalar semantics / truncation ───────────────────────────────────────────
add("int32/-1 as 10-byte varint", "Wide", tag(1, 0) + b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01")
add("int32/-1 as 5-byte varint (i64 truncation)", "Wide", tag(1, 0) + b"\xff\xff\xff\xff\x0f")
add("int32/value with high 32 bits set", "Wide", tag(1, 0) + varint((1 << 40) | 7))
add("uint32/value > 2^32", "Wide", tag(3, 0) + varint((1 << 33) + 5))
add("sint32/zigzag of u64max", "Wide", tag(5, 0) + b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01")
add("sint64/zigzag u64max = INT64_MIN", "Wide", tag(6, 0) + b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01")
add("sint64/zigzag 1 = -1", "Wide", tag(6, 0) + b"\x01")
add("bool/0x02", "Wide", tag(7, 0) + b"\x02")
add("bool/big varint", "Wide", tag(7, 0) + b"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01")
add("enum/negative", "Wide", tag(8, 0) + b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01")
add("enum/2^31", "Wide", tag(8, 0) + varint(1 << 31))
add("double/-0.0", "Wide", tag(11, 1) + b"\x00\x00\x00\x00\x00\x00\x00\x80")
add("double/NaN", "Wide", tag(11, 1) + b"\x00\x00\x00\x00\x00\x00\xf8\x7f")
add("double/signaling NaN", "Wide", tag(11, 1) + b"\x01\x00\x00\x00\x00\x00\xf0\x7f")
add("double/+Inf", "Wide", tag(11, 1) + b"\x00\x00\x00\x00\x00\x00\xf0\x7f")
add("double/-Inf", "Wide", tag(11, 1) + b"\x00\x00\x00\x00\x00\x00\xf0\xff")
add("float/-0.0", "Wide", tag(14, 5) + b"\x00\x00\x00\x80")
add("float/NaN", "Wide", tag(14, 5) + b"\x00\x00\xc0\x7f")
add("fixed64/truncated", "Wide", tag(9, 1) + b"\x01\x02\x03")
add("fixed32/truncated", "Wide", tag(12, 5) + b"\x01\x02")

# ── duplicates / last-wins / merge ──────────────────────────────────────────
add("dup/scalar twice", "Wide", tag(1, 0) + b"\x01" + tag(1, 0) + b"\x02")
add("dup/string twice", "Wide", tag(15, 2) + varint(1) + b"a" + tag(15, 2) + varint(1) + b"b")
add("dup/optional scalar twice", "Presence", tag(2, 0) + b"\x01" + tag(2, 0) + b"\x02")
add("merge/submessage twice", "Wide",
    tag(17, 2) + varint(2) + b"\x08\x01" + tag(17, 2) + varint(3) + b"\x12\x01x")
add("merge/second copy empty", "Wide",
    tag(17, 2) + varint(2) + b"\x08\x01" + tag(17, 2) + varint(0))
add("merge/three copies", "Wide",
    tag(17, 2) + varint(2) + b"\x08\x01" + tag(17, 2) + varint(3) + b"\x12\x01x" +
    tag(17, 2) + varint(2) + b"\x08\x09")
add("merge/nested chain", "Chain",
    b"\x08\x01" + tag(2, 2) + varint(6) + b"\x08\x02\x12\x02\x08\x63" +
    tag(2, 2) + varint(2) + b"\x08\x07")
add("merge/repeated message NOT merged", "Repeated",
    tag(8, 2) + varint(2) + b"\x08\x01" + tag(8, 2) + varint(3) + b"\x12\x01x")

# ── unknown fields ──────────────────────────────────────────────────────────
add("unknown/varint field 99", "Wide", tag(99, 0) + varint(7))
add("unknown/len field 99", "Wide", tag(99, 2) + varint(3) + b"abc")
add("unknown/wire-type mismatch on known field", "Wide", tag(1, 2) + varint(1) + b"\x05")
add("unknown/wire-type mismatch i64 on int32", "Wide", tag(1, 1) + b"\x00" * 8)
add("unknown/mismatch then correct", "Wide", tag(1, 1) + b"\x00" * 8 + tag(1, 0) + b"\x2a")
add("unknown/len mismatch on submessage field", "Wide", tag(17, 0) + varint(5))
add("unknown/two unknowns preserved order", "Wide",
    tag(50, 0) + varint(1) + tag(40, 0) + varint(2))

# ── UTF-8 ───────────────────────────────────────────────────────────────────
add("utf8/invalid start byte", "Wide", tag(15, 2) + varint(1) + b"\xff")
add("utf8/overlong NUL", "Wide", tag(15, 2) + varint(2) + b"\xc0\x80")
add("utf8/surrogate half", "Wide", tag(15, 2) + varint(3) + b"\xed\xa0\x80")
add("utf8/truncated seq", "Wide", tag(15, 2) + varint(1) + b"\xc3")
add("utf8/embedded NUL is fine", "Wide", tag(15, 2) + varint(3) + b"a\x00b")
add("utf8/4-byte emoji", "Wide", tag(15, 2) + varint(4) + b"\xf0\x9f\x8e\x89")
add("utf8/5-byte sequence", "Wide", tag(15, 2) + varint(5) + b"\xf8\x88\x80\x80\x80")
add("utf8/U+10FFFF", "Wide", tag(15, 2) + varint(4) + b"\xf4\x8f\xbf\xbf")
add("utf8/U+110000 out of range", "Wide", tag(15, 2) + varint(4) + b"\xf4\x90\x80\x80")
add("utf8/bad in repeated string", "Repeated", tag(7, 2) + varint(1) + b"\xff")
add("utf8/bad inside submessage note", "Wide",
    tag(17, 2) + varint(3) + tag(2, 2) + varint(1) + b"\xff")
add("utf8/bad in UNKNOWN field (no schema)", "Wide", tag(60, 2) + varint(1) + b"\xff")
add("bytes/0xff fine", "Wide", tag(16, 2) + varint(1) + b"\xff")


# ── nesting ─────────────────────────────────────────────────────────────────
def chain(n, inner=b"\x08\x01"):
    buf = inner
    for _ in range(n):
        buf = tag(2, 2) + varint(len(buf)) + buf
    return buf


for n in (1, 32, 62, 63, 64, 65, 100, 200):
    add("nest/depth %d" % n, "Chain", chain(n))

# ── trailing / empty ────────────────────────────────────────────────────────
add("misc/empty message", "Wide", b"")
add("misc/trailing garbage byte", "Wide", tag(1, 0) + b"\x01" + b"\xff")
add("misc/only a tag, no value", "Wide", tag(1, 0))

if __name__ == "__main__":
    rows = gen.run(C)
    diffs = 0
    unexpected = []
    for (lbl, op, sch, hx, z, p) in rows:
        same = z == p
        mark = "  " if same else ("EX" if lbl in EXPECTED else "!!")
        if not same:
            diffs += 1
            if lbl not in EXPECTED:
                unexpected.append(lbl)
        print("%s %-44s %-9s %s\n      zig: %s\n      py : %s" % (mark, lbl, sch, hx[:70], z[:300], p[:300]))
    print("\n%d cases, %d divergences (%d unexpected)" % (len(rows), diffs, len(unexpected)))
    if not rows:
        print("⛔ the corpus compared nothing at all")
        sys.exit(1)
    if unexpected:
        print("⛔ unexpected: " + ", ".join(unexpected[:12]))
    sys.exit(1 if unexpected else 0)
