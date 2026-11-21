#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Write `src/testdata/cpython_props_vectors.txt`: what CPython's `unicodedata` says about
decimal / digit / numeric / bidirectional / mirrored / east_asian_width / decomposition for a
sample of code points, replayed by `src/vectors_test.zig`.

    tools/ucd_gen/fetch.sh 16.0.0 && tools/ucd_gen/fetch.sh 18.0.0
    python3 -I tools/props_vectors.py > src/testdata/cpython_props_vectors.txt

CPython 3.14's `unicodedata` is Unicode 16.0.0 and the tables are 18.0.0, so only code points
whose UnicodeData fields 4-9, Numeric_Value and East_Asian_Width are identical in both UCD
versions are written (the same rule as `py_oracle.py`). The sample: every code point with a numeric
value or a mirrored mapping, every third one with a decomposition, every 23rd of the rest.
Line: `cp;decimal;digit;numeric;bidi;mirrored;eaw;decomposition`, empty = none (CPython raises
ValueError / returns '').
"""
import os, sys, unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
D = os.path.join(HERE, "ucd_gen", "data")
if unicodedata.unidata_version != "16.0.0":
    sys.exit("needs a CPython with Unicode 16.0.0 (3.14); this one has " + unicodedata.unidata_version)

def load(ver):
    ud = {}
    first = None
    for line in open(os.path.join(D, ver, "UnicodeData.txt"), encoding="utf-8"):
        f = line.rstrip("\n").split(";")
        cp = int(f[0], 16)
        if f[1].endswith(", First>"):
            first = cp
            continue
        lo = first if f[1].endswith(", Last>") else cp
        for c in range(lo, cp + 1):
            ud[c] = tuple(f[4:10])
    eaw = {}
    for line in open(os.path.join(D, ver, "EastAsianWidth.txt"), encoding="utf-8"):
        line = line.split("#")[0].strip()
        if not line:
            continue
        r, w = [x.strip() for x in line.split(";")]
        lo, hi = (int(x, 16) for x in r.split("..")) if ".." in r else (int(r, 16),) * 2
        for c in range(lo, hi + 1):
            eaw[c] = w
    num = {}
    for line in open(os.path.join(D, ver, "extracted", "DerivedNumericValues.txt"), encoding="utf-8"):
        line = line.split("#")[0].strip()
        if not line:
            continue
        f = [x.strip() for x in line.split(";")]
        lo, hi = (int(x, 16) for x in f[0].split("..")) if ".." in f[0] else (int(f[0], 16),) * 2
        for c in range(lo, hi + 1):
            num[c] = f[3]
    return ud, eaw, num

u16, e16, n16 = load("16.0.0")
u18, e18, n18 = load("18.0.0")
out = []
for cp in sorted(set(u16) & set(u18)):
    if cp in range(0xD800, 0xE000):
        continue
    if u16[cp] != u18[cp] or e16.get(cp, "N") != e18.get(cp, "N") or n16.get(cp) != n18.get(cp):
        continue
    ch = chr(cp)
    def opt(fn):
        try:
            return fn(ch)
        except ValueError:
            return None
    dec, dig, nu = opt(unicodedata.decimal), opt(unicodedata.digit), opt(unicodedata.numeric)
    dc = unicodedata.decomposition(ch)
    mir = unicodedata.mirrored(ch)
    keep = nu is not None or mir or (dc and cp % 3 == 0) or cp % 23 == 0
    if not keep:
        continue
    out.append("%X;%s;%s;%s;%s;%d;%s;%s" % (cp, "" if dec is None else dec, "" if dig is None else dig,
                                          "" if nu is None else repr(nu), unicodedata.bidirectional(ch), int(mir),
                                          unicodedata.east_asian_width(ch), dc))
sys.stdout.write("\n".join(out) + "\n")
