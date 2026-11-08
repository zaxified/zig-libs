#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Writes modules/jsontext/src/testdata/vectors.txt (CPython column set).

Run from the repository root:  python3 -I modules/jsontext/tools/gen_vectors.py
then (optional, needs Go 1.26, standard library only):
    cd modules/jsontext/tools/go_vectors && GOTOOLCHAIN=local GOPROXY=off go run .
which writes src/testdata/vectors_go.txt from this file's inputs.

Every line:  <input hex> TAB <valid 0/1> TAB <d> <a> <ah> <e> <ea> <eh> <eah>
(all TAB separated, each expected output as hex of the UTF-8 bytes, '-' = not
applicable). Column meaning (option set -> who produced it):

  d    default options (.replace)           CPython json.dumps(ensure_ascii=False)
                                            of bytes.decode('utf-8','replace')   [py]
  a    ascii_only                           CPython json.dumps(ensure_ascii=True)
                                            of the same text; '-' when the input
                                            holds DEL (CPython escapes it, we do not) [py]
  ah   ascii_only + html_safe               CPython 'a' output, then < > & escaped
                                            as \\u003c \\u003e \\u0026         [own]
  e    invalid_utf8 = .escape_bytes         CPython maximal-subpart boundaries
                                            (error handler) + \\u00XX per byte  [own]
  ea / eh / eah   escape_bytes combined with ascii_only / html_safe / both   [own]

The html_safe column ('h') comes from Go (vectors_go.txt). The reject policy
needs no column: the valid flag says whether `error.InvalidUtf8` is expected.

CPython claim checked here (assert below): bytes.decode('utf-8','replace')
substitutes one U+FFFD per MAXIMAL SUBPART, i.e. the same as ours, including
3-byte and 4-byte truncations (E2 82 -> one, F0 9F 98 -> one).
"""
import codecs
import json
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "src", "testdata", "vectors.txt")

SENT = "\U0010fffe"  # replaced bytes (escape_bytes); never in an input
DELS = "\U0010fffd"  # a DEL, protected from CPython's ensure_ascii escape
S_ASC = "\\udbff\\udffe"
D_ASC = "\\udbff\\udffd"


def inputs():
    out = []
    add = out.append
    for b in range(256):
        add(bytes([b]))
    add(b"")
    add(b"plain ascii text")
    add(b'q"b\\s/ and \\u0041 literal')
    add(b"<script>a & b</script>")
    add(bytes(range(0x20)))
    add(bytes(range(0x20, 0x80)))
    add(b"a\x7fb")
    add(b"\x00")
    add(b"x" * 100 + b"\n" + b"y" * 100)
    add(b"\n" + b"x" * 40)
    add(b"x" * 40 + b"\n")
    add(b"x" * 33 + b'"' + b"x" * 33 + b"\\" + b"x" * 33)
    cps = [0x80, 0x85, 0xA0, 0xE9, 0x7FF, 0x800, 0x2027, 0x2028, 0x2029, 0x202A,
           0x20AC, 0xD7FF, 0xE000, 0xFEFF, 0xFFFD, 0xFFFF, 0x10000, 0x1F600, 0x10FFFF]
    for cp in cps:
        e = chr(cp).encode()
        add(e)
        add(b"a" + e + b"b")
        add(b"<" + e + b"&")
        add(e + e)
    # ill-formed: leads x second bytes, leads x second x third, 4-byte lattice
    leads2 = [0x80, 0xBF, 0xC0, 0xC1, 0xC2, 0xDF, 0xE0, 0xE1, 0xEC, 0xED, 0xEE, 0xEF,
              0xF0, 0xF1, 0xF3, 0xF4, 0xF5, 0xF8, 0xFE, 0xFF]
    b1s = [0x41, 0x80, 0x8F, 0x90, 0x9F, 0xA0, 0xBF, 0xC2]
    for l in leads2:
        for b1 in b1s:
            add(bytes([l, b1]))
    for l in [0xE0, 0xE1, 0xEC, 0xED, 0xEE, 0xEF]:
        for b1 in [0x7F, 0x80, 0x8F, 0x9F, 0xA0, 0xBF, 0xC0]:
            add(bytes([l, b1]))
            for b2 in [0x41, 0x80, 0xBF, 0xC0]:
                add(bytes([l, b1, b2]))
    for l in [0xF0, 0xF1, 0xF3, 0xF4, 0xF5]:
        for b1 in [0x80, 0x8F, 0x90, 0xBF, 0xC0]:
            add(bytes([l, b1]))
            for b2 in [0x41, 0x80, 0xBF]:
                add(bytes([l, b1, b2]))
                for b3 in [0x41, 0x80, 0xBF]:
                    add(bytes([l, b1, b2, b3]))
    for s in [b"\xed\xa0\xbd\xed\xb8\x80", b"\xe2\x82\xac\xff\xe2\x82\xac", b"a\xe2\x82b",
              b"\xf0\x9f\x98\x80\xf0\x9f\x98", b"\xc0\xaf", b"\xff\xfe\xfd", b"\x80\xbf\x80"]:
        add(s)
    base = list(out)
    rng = random.Random(8)
    # wrapped in context (run flush before/after an interrupt)
    for s in base[256:]:
        if rng.random() < 0.15:
            add(b"a" + s + b"<b")
    # random mixed strings
    pool = (list(range(0x20)) + list(range(0x20, 0x80)) * 2 + [0x22, 0x5C, 0x3C, 0x26, 0x7F]
            + list(range(0x80, 0x100)) * 2)
    for _ in range(150):
        n = rng.randrange(1, 25)
        add(bytes(rng.choice(pool) for _ in range(n)))
    seen, uniq = set(), []
    for s in out:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


def hexs(s):
    return s.encode("utf-8").hex()


def html(t):
    return (t.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def decode_escape(b):
    """(text with SENT markers, [replaced byte groups]) using CPython's maximal subparts."""
    groups = []

    def handler(exc):
        groups.append(bytes(exc.object[exc.start:exc.end]))
        return (SENT, exc.end)

    codecs.register_error("jsontext_esc", handler)
    return b.decode("utf-8", "jsontext_esc"), groups


def fill(text, groups, ascii_):
    sent = S_ASC if ascii_ else SENT
    parts = text.split(sent)
    assert len(parts) == len(groups) + 1, (text, groups)
    res = parts[0]
    for g, p in zip(groups, parts[1:]):
        res += "".join("\\u%04x" % x for x in g) + p
    return res


def own_column(b, ascii_, html_):
    text, groups = decode_escape(b)
    text = text.replace("\x7f", DELS)
    j = json.dumps(text, ensure_ascii=ascii_)
    if html_:
        j = html(j[1:-1])
        j = '"' + j + '"'
    j = j.replace(D_ASC if ascii_ else DELS, "\x7f")
    j = fill(j, groups, ascii_)
    return j


def rows():
    # the CPython claim in the header
    for b, n in [(b"\xe2\x82", 1), (b"\xf0\x9f\x98", 1), (b"\xf0\x9f", 1), (b"\xe2\x82A", 2),
                 (b"\xf1\x80\x80A", 2), (b"\xed\xa0\x80", 3), (b"\xf0\x80\x80\xaf", 4), (b"\xf5\x80", 2)]:
        assert len(b.decode("utf-8", "replace")) == n, b
    for b in inputs():
        assert SENT.encode() not in b and DELS.encode() not in b
        try:
            b.decode("utf-8")
            valid = 1
        except UnicodeDecodeError:
            valid = 0
        t = b.decode("utf-8", "replace")
        d = json.dumps(t, ensure_ascii=False)
        a = json.dumps(t, ensure_ascii=True)
        if b"\x7f" in b:
            a = None
        # ah: CPython ascii output with < > & escaped (own composition); DEL kept raw
        t2 = t.replace("\x7f", DELS)
        a2 = json.dumps(t2, ensure_ascii=True).replace(D_ASC, "\x7f")
        ah = '"' + a2[1:-1].replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026") + '"'
        cols = [d, a, ah, own_column(b, False, False), own_column(b, True, False),
                own_column(b, False, True), own_column(b, True, True)]
        yield b, valid, cols


def main():
    n = 0
    with open(OUT, "w", newline="\n") as f:
        f.write("# input-hex valid d a ah e ea eh eah -- see tools/gen_vectors.py; generated, do not edit\n")
        for b, valid, cols in rows():
            f.write("\t".join([b.hex() or "-", str(valid)] + [hexs(c) if c is not None else "-" for c in cols]) + "\n")
            n += 1
    print("wrote", n, "rows to", os.path.normpath(OUT))


main()
