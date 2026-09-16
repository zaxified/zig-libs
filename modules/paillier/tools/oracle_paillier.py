#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""External differential oracle for the Zig `paillier` module.

    .zig-cache/paillier-oracle/probe_vectors 512 200 | \
        modules/paillier/tools/oracle_paillier.py

Independent from the module: everything below is recomputed from the Paillier
1999 formulas with Python's built-in `pow(x, y, m)`. No `phe` import, no shared
code -- the only inputs are n, g, lambda, mu and the hex vectors on stdin.

    encrypt(m, r) = g^m * r^n            (mod n^2)
    decrypt(c)    = L(c^lambda mod n^2) * mu   (mod n),   L(x) = (x-1)/n
    add(c1, c2)   = c1 * c2              (mod n^2)
    addPlaintext  = c  * g^m             (mod n^2)
    mulPlaintext  = c^k                  (mod n^2)

SPEC.md grades this module "class B - oracle EXTERNAL". In the tree that rests
on four `phe`-cross-checked toy vectors against one small key; this recomputes
every operation at real key sizes across as many trials as you ask for, which
is what the grade actually claims. Needs a Python -- a foreign toolchain
`zig build test-paillier` must never require (CONVENTIONS.md §9).

Exits 1 on a mismatch, 2 when the input itself is unusable.
"""
import sys

n = g = lam = mu = None
nsq = None
counts = {}
fails = []
saw_end = False


def H(s):
    return int(s, 16)


def L(x):
    assert (x - 1) % n == 0, "L not exact"
    return (x - 1) // n


def decrypt(c):
    return (L(pow(c, lam, nsq)) * mu) % n


for line in sys.stdin:
    f = line.split()
    if not f:
        continue
    tag = f[0]
    if tag == "END":
        saw_end = True
        continue
    if tag == "N":
        n = H(f[1]); nsq = n * n
    elif tag == "G":
        g = H(f[1])
    elif tag == "LAMBDA":
        lam = H(f[1])
    elif tag == "MU":
        mu = H(f[1])
    elif tag == "V":
        m, r, c, dec = map(H, f[1:5])
        counts["V"] = counts.get("V", 0) + 1
        ref_c = (pow(g, m, nsq) * pow(r, n, nsq)) % nsq
        if ref_c != c:
            fails.append(("V-ciphertext", counts["V"], hex(c), hex(ref_c)))
        ref_m = decrypt(c)
        if ref_m != dec:
            fails.append(("V-plaintext", counts["V"], hex(dec), hex(ref_m)))
        if dec != m % n:
            fails.append(("V-roundtrip", counts["V"], hex(dec), hex(m % n)))
    elif tag == "A":
        c1, c2, cadd, dec = map(H, f[1:5])
        counts["A"] = counts.get("A", 0) + 1
        ref = (c1 * c2) % nsq
        if ref != cadd:
            fails.append(("A-ciphertext", counts["A"], hex(cadd), hex(ref)))
        if decrypt(cadd) != dec or dec != (decrypt(c1) + decrypt(c2)) % n:
            fails.append(("A-plaintext", counts["A"], hex(dec), hex(decrypt(cadd))))
    elif tag == "P":
        c1, m2, cadd, dec = map(H, f[1:5])
        counts["P"] = counts.get("P", 0) + 1
        ref = (c1 * pow(g, m2, nsq)) % nsq
        if ref != cadd:
            fails.append(("P-ciphertext", counts["P"], hex(cadd), hex(ref)))
        if dec != (decrypt(c1) + m2) % n:
            fails.append(("P-plaintext", counts["P"], hex(dec), hex((decrypt(c1) + m2) % n)))
    elif tag == "M":
        c1, k, cmul, dec = map(H, f[1:5])
        counts["M"] = counts.get("M", 0) + 1
        ref = pow(c1, k, nsq)
        if ref != cmul:
            fails.append(("M-ciphertext", counts["M"], hex(cmul), hex(ref)))
        if dec != (decrypt(c1) * k) % n:
            fails.append(("M-plaintext", counts["M"], hex(dec), hex((decrypt(c1) * k) % n)))

# ⚠ THE PROBE MUST HAVE FINISHED. `probe_vectors` prints `END` as its last
# line; without this check a probe that died halfway -- OOM-killed, timed out,
# a broken pipe -- yields a short stream that this script compares happily and
# calls clean. It could fail on CONTENT but not on TRUNCATION, which is the
# same gap the dns differential had.
if not saw_end:
    print("\n\u26d4 the probe's END marker is missing: its output is TRUNCATED, so "
          "the rows above are a sample of unknown size, not a result.", file=sys.stderr)
    sys.exit(2)
if n is None or g is None or lam is None or mu is None:
    print("\n\u26d4 no key material on stdin (N/G/LAMBDA/MU) -- nothing could be "
          "recomputed.", file=sys.stderr)
    sys.exit(2)
if not counts:
    print("\n\u26d4 not one vector was checked -- the probe produced a header and "
          "nothing else.", file=sys.stderr)
    sys.exit(2)

print(f"n bits            : {n.bit_length()}")
print(f"g == n+1          : {g == n + 1}")
print(f"lambda == lcm(p-1,q-1) shape: mu == lambda^-1 mod n : {(lam * mu) % n == 1 % n}")
print("checked:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
print(f"MISMATCHES: {len(fails)}")
for row in fails[:20]:
    print("   ", row)
sys.exit(1 if fails else 0)
