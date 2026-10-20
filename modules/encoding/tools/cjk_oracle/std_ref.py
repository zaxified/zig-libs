#!/usr/bin/env python3
"""Literal transliteration of the WHATWG Encoding Standard's CJK decoders and
encoders (sections 10-13, with the I/O queue and its "restore"), used to
classify where golang.org/x/text (the Go oracle, main.go) differs from the
Standard, and to freeze the verdict into src/cjk_oracle_vectors.zig.

    go run . -out DUMP                     # Go's answers
    python3 -I std_ref.py DUMP > ../../src/cjk_oracle_vectors.zig

Written from the Standard's text only; it shares no code with src/cjk.zig
(only the vendored index files). Slow and obvious on purpose.
"""
import hashlib
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TESTDATA = os.path.join(HERE, "..", "..", "src", "testdata")

EOQ = None
FINISHED = "finished"
CONTINUE = "continue"
ERROR = "error"


def load_index(name):
    d = {}
    with open(os.path.join(TESTDATA, "index-%s.txt" % name), encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            p = line.split("\t")
            d[int(p[0])] = int(p[1], 16)
    return d


def first_pointer(index):
    m = {}
    for p in sorted(index):
        m.setdefault(index[p], p)
    return m


JIS0208 = load_index("jis0208")
JIS0212 = load_index("jis0212")
KATA = load_index("iso-2022-jp-katakana")
EUCKR = load_index("euc-kr")
GB = load_index("gb18030")
GBR = load_index("gb18030-ranges")
BIG5 = load_index("big5")

JIS0208_PTR = first_pointer(JIS0208)
SJIS_PTR = first_pointer({p: c for p, c in JIS0208.items() if not 8272 <= p <= 8835})
EUCKR_PTR = first_pointer(EUCKR)
GB_PTR = first_pointer(GB)
_b5 = {p: c for p, c in BIG5.items() if p >= (0xA1 - 0x81) * 157}
BIG5_PTR = first_pointer(_b5)
for _cp in (0x2550, 0x255E, 0x2561, 0x256A, 0x5341, 0x5345):
    BIG5_PTR[_cp] = max(p for p, c in _b5.items() if c == _cp)

GBR_PTRS = sorted(GBR)


def gb_ranges_cp(pointer):
    if 39419 < pointer < 189000 or pointer > 1237575:
        return None
    if pointer == 7457:
        return 0xE7C7
    off = max(p for p in GBR_PTRS if p <= pointer)
    return GBR[off] + pointer - off


GBR_CPS = sorted((c, p) for p, c in GBR.items())


def gb_ranges_pointer(cp):
    if cp == 0xE7C7:
        return 7457
    off_cp, off_p = max((c, p) for c, p in GBR_CPS if c <= cp)
    return off_p + cp - off_cp


def in_range(x, lo, hi):
    return x is not None and lo <= x <= hi


# ── decoders: handler(q, byte) -> CONTINUE | FINISHED | ERROR | [code points]
class GB18030Decoder:
    def __init__(self):
        self.first = self.second = self.third = 0

    def handler(self, q, byte):
        if byte is EOQ and self.first == self.second == self.third == 0:
            return FINISHED
        if byte is EOQ:
            self.first = self.second = self.third = 0
            return ERROR
        if self.third != 0:
            if not 0x30 <= byte <= 0x39:
                q[0:0] = [self.second, self.third, byte]
                self.first = self.second = self.third = 0
                return ERROR
            cp = gb_ranges_cp((self.first - 0x81) * (10 * 126 * 10) + (self.second - 0x30) * (10 * 126)
                              + (self.third - 0x81) * 10 + byte - 0x30)
            self.first = self.second = self.third = 0
            if cp is None:
                return ERROR
            return [cp]
        if self.second != 0:
            if 0x81 <= byte <= 0xFE:
                self.third = byte
                return CONTINUE
            q[0:0] = [self.second, byte]
            self.first = self.second = 0
            return ERROR
        if self.first != 0:
            if 0x30 <= byte <= 0x39:
                self.second = byte
                return CONTINUE
            leading = self.first
            self.first = 0
            pointer = None
            offset = 0x40 if byte < 0x7F else 0x41
            if 0x40 <= byte <= 0x7E or 0x80 <= byte <= 0xFE:
                pointer = (leading - 0x81) * 190 + (byte - offset)
            cp = None if pointer is None else GB.get(pointer)
            if cp is not None:
                return [cp]
            if byte < 0x80:
                q.insert(0, byte)
            return ERROR
        if byte < 0x80:
            return [byte]
        if byte == 0x80:
            return [0x20AC]
        if 0x81 <= byte <= 0xFE:
            self.first = byte
            return CONTINUE
        return ERROR


BIG5_SPECIAL = {1133: [0x00CA, 0x0304], 1135: [0x00CA, 0x030C], 1164: [0x00EA, 0x0304], 1166: [0x00EA, 0x030C]}


class Big5Decoder:
    def __init__(self):
        self.leading = 0

    def handler(self, q, byte):
        if byte is EOQ and self.leading != 0:
            self.leading = 0
            return ERROR
        if byte is EOQ:
            return FINISHED
        if self.leading != 0:
            leading = self.leading
            self.leading = 0
            pointer = None
            offset = 0x40 if byte < 0x7F else 0x62
            if 0x40 <= byte <= 0x7E or 0xA1 <= byte <= 0xFE:
                pointer = (leading - 0x81) * 157 + (byte - offset)
            if pointer in BIG5_SPECIAL:
                return list(BIG5_SPECIAL[pointer])
            cp = None if pointer is None else BIG5.get(pointer)
            if cp is not None:
                return [cp]
            if byte < 0x80:
                q.insert(0, byte)
            return ERROR
        if byte < 0x80:
            return [byte]
        if 0x81 <= byte <= 0xFE:
            self.leading = byte
            return CONTINUE
        return ERROR


class EucJpDecoder:
    def __init__(self):
        self.jis0212 = False
        self.leading = 0

    def handler(self, q, byte):
        if byte is EOQ and self.leading != 0:
            self.leading = 0
            return ERROR
        if byte is EOQ:
            return FINISHED
        if self.leading == 0x8E and 0xA1 <= byte <= 0xDF:
            self.leading = 0
            return [0xFF61 - 0xA1 + byte]
        if self.leading == 0x8F and 0xA1 <= byte <= 0xFE:
            self.jis0212 = True
            self.leading = byte
            return CONTINUE
        if self.leading != 0:
            leading = self.leading
            self.leading = 0
            cp = None
            if 0xA1 <= leading <= 0xFE and 0xA1 <= byte <= 0xFE:
                ptr = (leading - 0xA1) * 94 + byte - 0xA1
                cp = (JIS0212 if self.jis0212 else JIS0208).get(ptr)
            self.jis0212 = False
            if cp is not None:
                return [cp]
            if byte < 0x80:
                q.insert(0, byte)
            return ERROR
        if byte < 0x80:
            return [byte]
        if byte in (0x8E, 0x8F) or 0xA1 <= byte <= 0xFE:
            self.leading = byte
            return CONTINUE
        return ERROR


class Iso2022JpDecoder:
    def __init__(self):
        self.state = "ascii"
        self.output_state = "ascii"
        self.leading = 0
        self.output = False

    def handler(self, q, byte):
        s = self.state
        if s in ("ascii", "roman", "katakana", "leading"):
            if byte == 0x1B:
                self.state = "escape_start"
                return CONTINUE
            if byte is EOQ:
                return FINISHED
            if s == "ascii":
                if byte <= 0x7F and byte not in (0x0E, 0x0F):
                    self.output = False
                    return [byte]
            elif s == "roman":
                if byte == 0x5C:
                    self.output = False
                    return [0xA5]
                if byte == 0x7E:
                    self.output = False
                    return [0x203E]
                if byte <= 0x7F and byte not in (0x0E, 0x0F):
                    self.output = False
                    return [byte]
            elif s == "katakana":
                if 0x21 <= byte <= 0x5F:
                    self.output = False
                    return [0xFF61 - 0x21 + byte]
            else:
                if 0x21 <= byte <= 0x7E:
                    self.output = False
                    self.leading = byte
                    self.state = "trailing"
                    return CONTINUE
            self.output = False
            return ERROR
        if s == "trailing":
            if byte == 0x1B:
                self.state = "escape_start"
                return ERROR
            if byte is not EOQ and 0x21 <= byte <= 0x7E:
                self.state = "leading"
                cp = JIS0208.get((self.leading - 0x21) * 94 + byte - 0x21)
                if cp is None:
                    return ERROR
                return [cp]
            self.state = "leading"
            return ERROR
        if s == "escape_start":
            if byte in (0x24, 0x28):
                self.leading = byte
                self.state = "escape"
                return CONTINUE
            if byte is not EOQ:
                q.insert(0, byte)
            self.output = False
            self.state = self.output_state
            return ERROR
        assert s == "escape"
        leading = self.leading
        self.leading = 0
        state = None
        if leading == 0x28 and byte == 0x42:
            state = "ascii"
        if leading == 0x28 and byte == 0x4A:
            state = "roman"
        if leading == 0x28 and byte == 0x49:
            state = "katakana"
        if leading == 0x24 and byte in (0x40, 0x42):
            state = "leading"
        if state is not None:
            self.state = self.output_state = state
            output = self.output
            self.output = True
            return CONTINUE if not output else ERROR
        if byte is EOQ:
            q.insert(0, leading)
        else:
            q[0:0] = [leading, byte]
        self.output = False
        self.state = self.output_state
        return ERROR


class ShiftJisDecoder:
    def __init__(self):
        self.leading = 0

    def handler(self, q, byte):
        if byte is EOQ and self.leading != 0:
            self.leading = 0
            return ERROR
        if byte is EOQ:
            return FINISHED
        if self.leading != 0:
            leading = self.leading
            self.leading = 0
            pointer = None
            offset = 0x40 if byte < 0x7F else 0x41
            leading_offset = 0x81 if leading < 0xA0 else 0xC1
            if 0x40 <= byte <= 0x7E or 0x80 <= byte <= 0xFC:
                pointer = (leading - leading_offset) * 188 + byte - offset
            if in_range(pointer, 8836, 10715):
                return [0xE000 - 8836 + pointer]
            cp = None if pointer is None else JIS0208.get(pointer)
            if cp is not None:
                return [cp]
            if byte < 0x80:
                q.insert(0, byte)
            return ERROR
        if byte < 0x80 or byte == 0x80:
            return [byte]
        if 0xA1 <= byte <= 0xDF:
            return [0xFF61 - 0xA1 + byte]
        if 0x81 <= byte <= 0x9F or 0xE0 <= byte <= 0xFC:
            self.leading = byte
            return CONTINUE
        return ERROR


class EucKrDecoder:
    def __init__(self):
        self.leading = 0

    def handler(self, q, byte):
        if byte is EOQ and self.leading != 0:
            self.leading = 0
            return ERROR
        if byte is EOQ:
            return FINISHED
        if self.leading != 0:
            leading = self.leading
            self.leading = 0
            pointer = None
            if 0x41 <= byte <= 0xFE:
                pointer = (leading - 0x81) * 190 + (byte - 0x41)
            cp = None if pointer is None else EUCKR.get(pointer)
            if cp is not None:
                return [cp]
            if byte < 0x80:
                q.insert(0, byte)
            return ERROR
        if byte < 0x80:
            return [byte]
        if 0x81 <= byte <= 0xFE:
            self.leading = byte
            return CONTINUE
        return ERROR


DECODERS = {
    "shift_jis": ShiftJisDecoder, "euc_jp": EucJpDecoder, "iso_2022_jp": Iso2022JpDecoder,
    "euc_kr": EucKrDecoder, "gb18030": GB18030Decoder, "gbk": GB18030Decoder, "big5": Big5Decoder,
}


def cp_utf8(cp):
    return chr(cp).encode("utf-8", "surrogatepass")


def decode(enc, data):
    q = list(data) + [EOQ]
    h = DECODERS[enc]()
    out = bytearray()
    while True:
        item = q[0] if q[0] is EOQ else q.pop(0)
        r = h.handler(q, item)
        if r == FINISHED:
            return bytes(out)
        if r == ERROR:
            out += "�".encode()
        elif r != CONTINUE:
            for cp in r:
                assert not 0xD800 <= cp <= 0xDFFF
                out += cp_utf8(cp)


# ── encoders: handler(q, cp) -> FINISHED | CONTINUE | bytes | ("error", cp)
GB_SIDE = {
    0xE78D: (0xA6, 0xD9), 0xE78E: (0xA6, 0xDA), 0xE78F: (0xA6, 0xDB), 0xE790: (0xA6, 0xDC),
    0xE791: (0xA6, 0xDD), 0xE792: (0xA6, 0xDE), 0xE793: (0xA6, 0xDF), 0xE794: (0xA6, 0xEC),
    0xE795: (0xA6, 0xED), 0xE796: (0xA6, 0xF3), 0xE81E: (0xFE, 0x59), 0xE826: (0xFE, 0x61),
    0xE82B: (0xFE, 0x66), 0xE82C: (0xFE, 0x67), 0xE832: (0xFE, 0x6D), 0xE843: (0xFE, 0x7E),
    0xE854: (0xFE, 0x90), 0xE864: (0xFE, 0xA0),
}


class Gb18030Encoder:
    def __init__(self, is_gbk):
        self.is_gbk = is_gbk

    def handler(self, q, cp):
        if cp is EOQ:
            return FINISHED
        if cp < 0x80:
            return bytes([cp])
        if cp == 0xE5E5:
            return ("error", cp)
        if self.is_gbk and cp == 0x20AC:
            return bytes([0x80])
        if cp in GB_SIDE:
            return bytes(GB_SIDE[cp])
        pointer = GB_PTR.get(cp)
        if pointer is not None:
            leading = pointer // 190 + 0x81
            trailing = pointer % 190
            offset = 0x40 if trailing < 0x3F else 0x41
            return bytes([leading, trailing + offset])
        if self.is_gbk:
            return ("error", cp)
        pointer = gb_ranges_pointer(cp)
        b1 = pointer // (10 * 126 * 10)
        pointer %= 10 * 126 * 10
        b2 = pointer // (10 * 126)
        pointer %= 10 * 126
        b3 = pointer // 10
        b4 = pointer % 10
        return bytes([b1 + 0x81, b2 + 0x30, b3 + 0x81, b4 + 0x30])


class Big5Encoder:
    def handler(self, q, cp):
        if cp is EOQ:
            return FINISHED
        if cp < 0x80:
            return bytes([cp])
        pointer = BIG5_PTR.get(cp)
        if pointer is None:
            return ("error", cp)
        leading = pointer // 157 + 0x81
        trailing = pointer % 157
        offset = 0x40 if trailing < 0x3F else 0x62
        return bytes([leading, trailing + offset])


class EucJpEncoder:
    def handler(self, q, cp):
        if cp is EOQ:
            return FINISHED
        if cp < 0x80:
            return bytes([cp])
        if cp == 0xA5:
            return bytes([0x5C])
        if cp == 0x203E:
            return bytes([0x7E])
        if 0xFF61 <= cp <= 0xFF9F:
            return bytes([0x8E, cp - 0xFF61 + 0xA1])
        if cp == 0x2212:
            cp = 0xFF0D
        pointer = JIS0208_PTR.get(cp)
        if pointer is None:
            return ("error", cp)
        return bytes([pointer // 94 + 0xA1, pointer % 94 + 0xA1])


class Iso2022JpEncoder:
    def __init__(self):
        self.state = "ascii"

    def handler(self, q, cp):
        if cp is EOQ and self.state != "ascii":
            self.state = "ascii"
            return bytes([0x1B, 0x28, 0x42])
        if cp is EOQ:
            return FINISHED
        if self.state in ("ascii", "roman") and cp in (0x0E, 0x0F, 0x1B):
            return ("error", 0xFFFD)
        if self.state == "ascii" and cp < 0x80:
            return bytes([cp])
        if self.state == "roman" and ((cp < 0x80 and cp not in (0x5C, 0x7E)) or cp in (0xA5, 0x203E)):
            if cp < 0x80:
                return bytes([cp])
            if cp == 0xA5:
                return bytes([0x5C])
            return bytes([0x7E])
        if cp < 0x80 and self.state != "ascii":
            q.insert(0, cp)
            self.state = "ascii"
            return bytes([0x1B, 0x28, 0x42])
        if cp in (0xA5, 0x203E) and self.state != "roman":
            q.insert(0, cp)
            self.state = "roman"
            return bytes([0x1B, 0x28, 0x4A])
        if cp == 0x2212:
            cp = 0xFF0D
        if 0xFF61 <= cp <= 0xFF9F:
            cp = KATA[cp - 0xFF61]
        pointer = JIS0208_PTR.get(cp)
        if pointer is None:
            if self.state == "jis0208":
                q.insert(0, cp)
                self.state = "ascii"
                return bytes([0x1B, 0x28, 0x42])
            return ("error", cp)
        if self.state != "jis0208":
            q.insert(0, cp)
            self.state = "jis0208"
            return bytes([0x1B, 0x24, 0x42])
        return bytes([pointer // 94 + 0x21, pointer % 94 + 0x21])


class ShiftJisEncoder:
    def handler(self, q, cp):
        if cp is EOQ:
            return FINISHED
        if cp < 0x80 or cp == 0x80:
            return bytes([cp])
        if cp == 0xA5:
            return bytes([0x5C])
        if cp == 0x203E:
            return bytes([0x7E])
        if 0xFF61 <= cp <= 0xFF9F:
            return bytes([cp - 0xFF61 + 0xA1])
        if cp == 0x2212:
            cp = 0xFF0D
        pointer = SJIS_PTR.get(cp)
        if pointer is None:
            return ("error", cp)
        leading = pointer // 188
        leading_offset = 0x81 if leading < 0x1F else 0xC1
        trailing = pointer % 188
        offset = 0x40 if trailing < 0x3F else 0x41
        return bytes([leading + leading_offset, trailing + offset])


class EucKrEncoder:
    def handler(self, q, cp):
        if cp is EOQ:
            return FINISHED
        if cp < 0x80:
            return bytes([cp])
        pointer = EUCKR_PTR.get(cp)
        if pointer is None:
            return ("error", cp)
        return bytes([pointer // 190 + 0x81, pointer % 190 + 0x41])


def make_encoder(enc):
    return {
        "shift_jis": ShiftJisEncoder, "euc_jp": EucJpEncoder, "iso_2022_jp": Iso2022JpEncoder,
        "euc_kr": EucKrEncoder, "gb18030": lambda: Gb18030Encoder(False), "gbk": lambda: Gb18030Encoder(True),
        "big5": Big5Encoder,
    }[enc]()


def encode(enc, cps, mode):
    """mode "fatal": None on error; "html": numeric character references."""
    q = list(cps) + [EOQ]
    h = make_encoder(enc)
    out = bytearray()
    while True:
        item = q[0] if q[0] is EOQ else q.pop(0)
        r = h.handler(q, item)
        if r == FINISHED:
            return bytes(out)
        if isinstance(r, tuple):
            if mode == "fatal":
                return None
            out += b"&#%d;" % r[1]
        else:
            out += r


# ── domains (rebuilt, not read) ────────────────────────────────────────────
def e1_cps():
    cps = [c for c in range(0x30000) if not 0xD800 <= c <= 0xDFFF]
    cps += list(range(0x30000, 0x110000, 7))
    cps.append(0x10FFFF)
    return cps


def domain(name, enc, inputs):
    if name == "d1":
        return [bytes([i]) for i in range(256)]
    if name == "d2":
        return [bytes([i >> 8, i & 255]) for i in range(65536)]
    if name == "d3":
        return [bytes([0x8F, i >> 8, i & 255]) for i in range(65536)]
    if name == "d4":
        return [bytes([a, b, c, d]) for a in range(0x81, 0xFF) for b in range(0x30, 0x3A)
                for c in range(0x81, 0xFF) for d in range(0x30, 0x3A)]
    if name in ("d5", "d6", "e2"):
        return inputs[name]
    raise KeyError(name)


def read_answers(path):
    data = open(path, "rb").read()
    out = []
    i = 0
    while i < len(data):
        (n,) = struct.unpack_from("<I", data, i)
        i += 4
        if n == 0xFFFFFFFF:
            out.append(None)
        else:
            out.append(data[i:i + n])
            i += n
    return out


def stream_digest(answers):
    h = hashlib.sha256()
    for a in answers:
        if a is None:
            h.update(struct.pack("<I", 0xFFFFFFFF))
        else:
            h.update(struct.pack("<I", len(a)))
            h.update(a)
    return h.hexdigest()


F = "\ufffd"


def shape(out):
    """U+FFFD -> F, ASCII -> a, private use -> P, anything else -> c."""
    t = out.decode()
    return "".join("F" if c == F else "a" if ord(c) < 0x80 else "P" if 0xE000 <= ord(c) <= 0xF8FF else "c" for c in t)


# Rule text per class (the Standard's rule that decides it). Counts are measured.
RULES = {
    "sjis-eudc": "Shift_JIS decoder: pointers 8836..10715 (lead 0xF0-0xF9) are EUDC, code point 0xE000 - 8836 + pointer (Go: U+FFFD).",
    "ascii-trail-restore": "Decoders of Shift_JIS/Big5/gb18030: an ASCII byte that fails as a trail byte is `restore`d to the stream (it is decoded on its own after the U+FFFD); Go swallows it.",
    "nonascii-trail-consumed": "Decoders of EUC-JP/gb18030: a non-ASCII byte that fails as a trail byte is consumed with the lead byte: ONE U+FFFD (Go emits two).",
    "gb-user-defined": "gb18030 index: 0xA140-0xA7A0, 0xAAA1-0xAFFE, 0xF8A1-0xFEFE map to Private Use code points (Go: U+FFFD).",
    "gb-2022-two-byte": "gb18030 index (GB18030-2022): 0xA6D9..0xA6F3, 0xA8BC, 0xFE50..0xFEA0 map to U+FE10.., U+1E3F, U+9FB4.. as two bytes (Go: U+FFFD).",
    "gb-truncated-four-byte": "gb18030 decoder: a four-byte form cut short (lead, digit, ...) at the end of the input is ONE error (end-of-queue with first/second/third set); Go emits U+FFFD then the digit.",
    "gb-four-byte-gap": "gb18030 ranges: a four-byte pointer in 39420..188999 (or > 1237575) has no code point: ONE error consuming all four bytes (Go re-reads the digits).",
    "gb-e7c7": "gb18030 ranges: pointer 7457 is U+E7C7 (the 2005 change handled inline); Go: U+1E3F.",
    "iso-so-si": "ISO-2022-JP decoder: 0x0E and 0x0F are errors in the ASCII, Roman, katakana and lead-byte states (Go passes them through).",
    "iso-escape-recovery": "ISO-2022-JP decoder: an escape that is not one of the five known ones is an error and its bytes are restored; a repeated or interrupted escape is an error (Go differs in how many bytes the error swallows).",
    "e-sjis-special": "Shift_JIS encoder: U+0080 -> 0x80, U+00A5 -> 0x5C, U+203E -> 0x7E, U+2212 -> U+FF0D (Go: unmappable).",
    "e-sjis-nec-ibm": "index Shift_JIS pointer: pointers 8272..8835 (NEC-selected IBM extensions, rows 0xED/0xEE) are excluded, so the IBM extension rows 0xFA-0xFC are used (Go: 0xED/0xEE).",
    "e-eucjp-special": "EUC-JP encoder: U+00A5 -> 0x5C, U+203E -> 0x7E, U+2212 -> U+FF0D (Go: unmappable).",
    "e-eucjp-no-jis0212": "EUC-JP encoder uses index jis0208 only: a character only in jis0212 is unmappable (Go writes 0x8F + two bytes).",
    "e-iso-special": "ISO-2022-JP encoder: U+00A5/U+203E switch to the Roman state (ESC ( J), U+2212 -> U+FF0D (Go: unmappable).",
    "e-iso-controls": "ISO-2022-JP encoder: U+000E, U+000F, U+001B are an error (with U+FFFD) in the ASCII and Roman states (Go passes them).",
    "e-iso-katakana": "ISO-2022-JP encoder: U+FF61..U+FF9F are mapped through index ISO-2022-JP katakana to full-width and written in the jis0208 state (Go: ESC ( I half-width).",
    "e-gb-e5e5": "gb18030 encoder: U+E5E5 is an error (0xA3 0xA0 decodes to U+3000, so it cannot round-trip); Go writes a four-byte form.",
    "e-gb-two-byte": "gb18030 encoder: the side table (Private Use code points of GB18030-2022) and index gb18030 give these two bytes; Go writes four bytes (gb18030) or nothing (GBK).",
    "e-big5-hkscs": "index Big5 pointer: pointers below (0xA1 - 0x81) * 157 (the HKSCS extension) are excluded from the encoder (Go encodes them).",
    "e-big5-duplicate": "index Big5 pointer: for a duplicated code point the FIRST pointer is used (Go: the last), except U+2550, U+255E, U+2561, U+256A, U+5341, U+5345 (last).",
    "random-composite": "A random input; every divergence contains at least one construct of the classes above, not attributed individually.",
}


def classify(enc, dom, idx, inp, go, std, cps):
    if dom in ("d5", "d6", "e2"):
        return "random-composite"
    if dom == "e1":
        c = cps[idx]
        if enc == "shift_jis":
            return "e-sjis-special" if c in (0x80, 0xA5, 0x203E, 0x2212) else "e-sjis-nec-ibm"
        if enc == "euc_jp":
            return "e-eucjp-special" if c in (0xA5, 0x203E, 0x2212) else "e-eucjp-no-jis0212"
        if enc == "iso_2022_jp":
            if c in (0x0E, 0x0F, 0x1B):
                return "e-iso-controls"
            return "e-iso-katakana" if 0xFF61 <= c <= 0xFF9F else "e-iso-special"
        if enc in ("gb18030", "gbk"):
            return "e-gb-e5e5" if c == 0xE5E5 else "e-gb-two-byte"
        if enc == "big5":
            return "e-big5-hkscs" if go is not None and std is None else "e-big5-duplicate"
        raise AssertionError((enc, c))
    g, s = shape(go), shape(std)
    if enc == "shift_jis":
        if (g, s) == ("F", "P"):
            return "sjis-eudc"
        if (g, s) == ("F", "Fa"):
            return "ascii-trail-restore"
    if enc == "big5" and (g, s) in (("F", "Fa"), ("Fa", "Faa"), ("FF", "FaF")):
        return "ascii-trail-restore"
    if enc == "euc_jp" and g.count("F") > s.count("F") and g.replace("F", "") == s.replace("F", "") or (enc == "euc_jp" and (g, s) == ("Fc", "FF")):
        return "nonascii-trail-consumed"
    if enc in ("gb18030", "gbk"):
        if dom == "d2":
            return {("F", "P"): "gb-user-defined", ("Fa", "F"): "gb-truncated-four-byte",
                    ("FF", "F"): "nonascii-trail-consumed", ("F", "c"): "gb-2022-two-byte"}[(g, s)]
        if dom == "d3":
            return {("FaF", "F"): "gb-truncated-four-byte", ("FFa", "Fa"): "nonascii-trail-consumed",
                    ("FFF", "FF"): "nonascii-trail-consumed", ("FFc", "Fc"): "nonascii-trail-consumed"}[(g, s)]
        if dom == "d4":
            return {("FaFa", "F"): "gb-four-byte-gap", ("c", "P"): "gb-e7c7"}[(g, s)]
    if enc == "iso_2022_jp":
        return "iso-so-si" if any(b in (0x0E, 0x0F) for b in inp) else "iso-escape-recovery"
    raise AssertionError((enc, dom, inp.hex(), g, s))


def runs_of(idxs):
    runs = []
    for i in idxs:
        if runs and runs[-1][0] + runs[-1][1] == i:
            runs[-1][1] += 1
        else:
            runs.append([i, 1])
    return runs


def main():
    dump = sys.argv[1]
    inputs = {"d5": [], "d6": [], "e2": []}
    for line in open(os.path.join(dump, "inputs.txt")):
        n, hx = line.rstrip("\n").split(" ")
        inputs[n].append(bytes.fromhex(hx))
    encs = ["shift_jis", "euc_jp", "iso_2022_jp", "euc_kr", "gb18030", "gbk", "big5"]
    cps = e1_cps()
    results = []
    classes = []
    for enc in encs:
        for dom in ["d1", "d2", "d3", "d4", "d5", "d6", "e1", "e2"]:
            path = os.path.join(dump, "answers-%s-%s.bin" % (enc, dom))
            if not os.path.exists(path):
                continue
            go = read_answers(path)
            if dom == "e1":
                ins = cps
                std = [encode(enc, [c], "fatal") for c in cps]
            elif dom == "e2":
                ins = inputs["e2"]
                std = [encode(enc, [ord(ch) for ch in x.decode("utf-8")], "html") for x in ins]
            else:
                ins = domain(dom, enc, inputs)
                std = [decode(enc, x) for x in ins]
            assert len(go) == len(std), (enc, dom, len(go), len(std))
            div = [i for i in range(len(go)) if go[i] != std[i]]
            counts = {}
            for i in div:
                k = classify(enc, dom, i, ins[i], go[i], std[i], cps)
                counts[k] = counts.get(k, 0) + 1
            divset = set(div)
            results.append({
                "enc": enc, "dom": dom, "n": len(go),
                "std": stream_digest(std),
                "go_agree": stream_digest([g for i, g in enumerate(go) if i not in divset]),
                "std_div": stream_digest([std[i] for i in div]),
                "runs": runs_of(div), "ndiv": len(div),
            })
            for k, v in sorted(counts.items()):
                classes.append((enc, dom, k, v))
            sys.stderr.write("%s %s: %d cases, %d diverge %s\n" % (enc, dom, len(go), len(div), counts))
    emit(results, classes, inputs)


def zstr(b):
    return '"' + "".join("\\x%02x" % c for c in b) + '"'


def emit(results, classes, inputs):
    o = []
    w = o.append
    w("// SPDX-License-Identifier: MIT")
    w("//! GENERATED by tools/cjk_oracle/std_ref.py from the answers of golang.org/x/text")
    w("//! v0.42.0 (tools/cjk_oracle/main.go, BSD-3-Clause; only its observable answers are")
    w("//! recorded). Do not edit. Replayed by cjk_test.zig.")
    w("//!")
    w("//! Per (encoding, domain): `std_sha256` = SHA-256 of the answers of a literal")
    w("//! transliteration of the Standard (std_ref.py); `runs` = the cases (start, length")
    w("//! pairs) where Go's answer differs from it; `go_agree_sha256` = Go's answers on all")
    w("//! OTHER cases; `std_div_sha256` = the Standard's answers on the diverging cases.")
    w("//! cjk_test.zig proves ours == Standard everywhere and ours == Go off the runs.")
    w("//! Answer stream: per case u32le length (0xFFFFFFFF = error/unmappable) + bytes.")
    w("")
    w("pub const Result = struct {")
    w("    enc: []const u8,")
    w("    domain: []const u8,")
    w("    cases: u32,")
    w("    diverging: u32,")
    w("    std_sha256: []const u8,")
    w("    go_agree_sha256: []const u8,")
    w("    std_div_sha256: []const u8,")
    w("    runs: []const u32,")
    w("};")
    w("pub const Class = struct { enc: []const u8, domain: []const u8, name: []const u8, count: u32 };")
    w("pub const Rule = struct { name: []const u8, text: []const u8 };")
    w("")
    for name in ("d5", "d6", "e2"):
        w("pub const %s_inputs = [_][]const u8{" % name)
        for x in inputs[name]:
            w("    %s," % zstr(x))
        w("};")
        w("")
    w("pub const rules = [_]Rule{")
    for k, v in RULES.items():
        w("    .{ .name = %s, .text = %s }," % (json_str(k), json_str(v)))
    w("};")
    w("")
    w("pub const classes = [_]Class{")
    for enc, dom, k, v in classes:
        w("    .{ .enc = \"%s\", .domain = \"%s\", .name = \"%s\", .count = %d }," % (enc, dom, k, v))
    w("};")
    w("")
    w("pub const results = [_]Result{")
    for r in results:
        head = "    .{ .enc = \"%s\", .domain = \"%s\", .cases = %d, .diverging = %d, .std_sha256 = \"%s\", .go_agree_sha256 = \"%s\", .std_div_sha256 = \"%s\", .runs = &.{" % (
            r["enc"], r["dom"], r["n"], r["ndiv"], r["std"], r["go_agree"], r["std_div"])
        flat = [x for run in r["runs"] for x in run]
        if not flat:
            w(head + "} },")
            continue
        w(head)
        for j in range(0, len(flat), 16):
            w("        " + ", ".join("0x%06X" % x for x in flat[j:j + 16]) + ",")
        w("    } },")
    w("};")
    sys.stdout.write("\n".join(o) + "\n")


def json_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


if __name__ == "__main__":
    main()
