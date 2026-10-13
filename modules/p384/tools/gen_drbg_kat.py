#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Known answers for the two DRBG uses no external vector covers, computed with
Python's own hmac/hashlib and integer affine arithmetic (independent of the
module's code). Pinned in src/kat_test.zig, test "DRBG known answers".

  python3 -I modules/p384/tools/gen_drbg_kat.py

  * KeyPair.generateDeterministic(seed = 0x07 * 48): RFC 6979 HMAC-DRBG
    (SHA-384) with x = 0x01 * 48, h = 0 * 48 and the seed as §3.6 additional
    data; the first candidate in [1, n-1] is d.
  * sign("abc", noise = 0x55 * 48) with that key: RFC 6979 §3.2 + §3.6 (the
    noise appended to both K updates), r and s.
"""
import hashlib
import hmac

P = 2**384 - 2**128 - 2**96 + 2**32 - 1
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
A = P - 3
GX = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
GY = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F


def add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    (x1, y1), (x2, y2) = p, q
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def mul(k, pt):
    r = None
    while k:
        if k & 1:
            r = add(r, pt)
        pt = add(pt, pt)
        k >>= 1
    return r


def h(key, data):
    return hmac.new(key, data, hashlib.sha384).digest()


def drbg(x, h1, extra):
    k, v = b"\x00" * 48, b"\x01" * 48
    for tag in (b"\x00", b"\x01"):
        k = h(k, v + tag + x + h1 + extra)
        v = h(k, v)
    while True:
        v = h(k, v)
        c = int.from_bytes(v, "big")
        if 1 <= c < N:
            return c
        k = h(k, v + b"\x00")
        v = h(k, v)


def b48(i):
    return i.to_bytes(48, "big")


d = drbg(b"\x01" * 48, b"\x00" * 48, b"\x07" * 48)
q = mul(d, (GX, GY))
e = int.from_bytes(hashlib.sha384(b"abc").digest(), "big") % N
k = drbg(b48(d), b48(e), b"\x55" * 48)
r = mul(k, (GX, GY))[0] % N
s = pow(k, -1, N) * (e + r * d) % N
print("d  =", b48(d).hex())
print("qx =", b48(q[0]).hex())
print("qy =", b48(q[1]).hex())
print("r  =", b48(r).hex())
print("s  =", b48(s).hex())
