#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate src/precompile_vectors.zig: EIP-196/197 KATs over our own inputs.

    python3 modules/bn254/tools/gen_precompile_vectors.py > modules/bn254/src/precompile_vectors.zig

The expected values come from a second, independent implementation: the
affine BN254 arithmetic below, written from the curve equations alone
(no third-party code, no imports beyond the standard library). Nothing here
shares code with the Zig field tower.

ecPairing needs no pairing in Python: every TRUE vector is built so that
bilinearity makes the product 1 (pairs (a_i*G1, b_i*G2) closed by
(-(sum a_i*b_i)*G1, G2)), and every FALSE vector perturbs one scalar so the
product is a non-trivial power of e(G1, G2), which is not 1 because the
pairing is non-degenerate.

Inputs are drawn from a fixed-seed PRNG, so a rerun reproduces the file
byte for byte.
"""

import random

P = 21888242871839275222246405745257275088696311157297823662689037894645226208583
R = 21888242871839275222246405745257275088548364400416034343698204186575808495617

# ── G1: y^2 = x^3 + 3 over Fp; None is the point at infinity ──────────────


def g1_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    (x1, y1), (x2, y2) = a, b
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = 3 * x1 * x1 * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def g1_mul(pt, k):
    acc = None
    while k:
        if k & 1:
            acc = g1_add(acc, pt)
        pt = g1_add(pt, pt)
        k >>= 1
    return acc


def g1_neg(pt):
    return None if pt is None else (pt[0], (-pt[1]) % P)


def g1_on_curve(pt):
    return pt is None or (pt[1] * pt[1] - pt[0] ** 3 - 3) % P == 0


G1 = (1, 2)

# ── Fp2 = Fp[u]/(u^2 + 1), element (c0, c1) = c0 + c1*u ─────────────────


def f2_add(a, b):
    return ((a[0] + b[0]) % P, (a[1] + b[1]) % P)


def f2_sub(a, b):
    return ((a[0] - b[0]) % P, (a[1] - b[1]) % P)


def f2_mul(a, b):
    return ((a[0] * b[0] - a[1] * b[1]) % P, (a[0] * b[1] + a[1] * b[0]) % P)


def f2_inv(a):
    t = pow(a[0] * a[0] + a[1] * a[1], -1, P)
    return (a[0] * t % P, -a[1] * t % P)


def f2_scale(a, k):
    return (a[0] * k % P, a[1] * k % P)


# ── G2: the D-type twist y^2 = x^3 + 3/(9 + u) over Fp2 ──────────────────

B2 = f2_mul((3, 0), f2_inv((9, 1)))


def g2_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    (x1, y1), (x2, y2) = a, b
    if x1 == x2:
        if f2_add(y1, y2) == (0, 0):
            return None
        lam = f2_mul(f2_scale(f2_mul(x1, x1), 3), f2_inv(f2_scale(y1, 2)))
    else:
        lam = f2_mul(f2_sub(y2, y1), f2_inv(f2_sub(x2, x1)))
    x3 = f2_sub(f2_sub(f2_mul(lam, lam), x1), x2)
    return (x3, f2_sub(f2_mul(lam, f2_sub(x1, x3)), y1))


def g2_mul(pt, k):
    acc = None
    while k:
        if k & 1:
            acc = g2_add(acc, pt)
        pt = g2_add(pt, pt)
        k >>= 1
    return acc


def g2_on_curve(pt):
    if pt is None:
        return True
    x, y = pt
    return f2_sub(f2_mul(y, y), f2_add(f2_mul(f2_mul(x, x), x), B2)) == (0, 0)


# EIP-197's generator of the order-r subgroup of the twist.
G2 = (
    (
        10857046999023057135944570762232829481370756359578518086990519993285655852781,
        11559732032986387107991004021392285783925812861821192530917403151452391805634,
    ),
    (
        8495653923123431417604973247489272438418190587263600148770280649306958101930,
        4082367875863433681332203403145435568316851327593401208105741076214120093531,
    ),
)

# ── EIP-196/197 encodings ────────────────────────────────────────────────


def w(n):
    return n.to_bytes(32, "big").hex()


def enc_g1(pt):
    return w(0) + w(0) if pt is None else w(pt[0]) + w(pt[1])


def enc_g2(pt):
    # Imaginary part first (EIP-197), the point at infinity as all zeros.
    if pt is None:
        return w(0) * 4
    (x0, x1), (y0, y1) = pt
    return w(x1) + w(x0) + w(y1) + w(y0)


# ── self-checks before anything is emitted ──────────────────────────────

assert g1_on_curve(G1) and g1_mul(G1, R) is None
assert g2_on_curve(G2) and g2_mul(G2, R) is None

rng = random.Random(0x62E254)


def scalar():
    return rng.randrange(1, R)


def g1_rand():
    return g1_mul(G1, scalar())


# ── ecAdd (0x06) ─────────────────────────────────────────────────────────

pa, pb = g1_rand(), g1_rand()
add = [
    ("a_plus_b", enc_g1(pa) + enc_g1(pb), g1_add(pa, pb)),
    ("doubling", enc_g1(pa) + enc_g1(pa), g1_add(pa, pa)),
    ("p_plus_neg_p", enc_g1(pa) + enc_g1(g1_neg(pa)), None),
    ("infinity_plus_p", enc_g1(None) + enc_g1(pb), pb),
    ("infinity_plus_infinity", enc_g1(None) * 2, None),
    ("generator_plus_generator", enc_g1(G1) * 2, g1_add(G1, G1)),
    # Short calldata is right-padded with zeros (EIP-196).
    ("empty", "", None),
    ("short_64_one_point", enc_g1(pb), pb),
    ("short_96_zero_tail", enc_g1(pb) + w(0), pb),
    # Long calldata is truncated to the first 128 octets.
    ("long_trailing_bytes", enc_g1(pa) + enc_g1(pb) + "ab" * 64, g1_add(pa, pb)),
]

# ── ecMul (0x07) ─────────────────────────────────────────────────────────

pm = g1_rand()
s = scalar()
s_hi = rng.randrange(1, 1 << 128)
mul = [
    ("p_times_s", enc_g1(pm) + w(s), g1_mul(pm, s)),
    ("scalar_zero", enc_g1(pm) + w(0), None),
    ("scalar_one", enc_g1(pm) + w(1), pm),
    ("scalar_r", enc_g1(pm) + w(R), None),
    ("scalar_r_minus_one", enc_g1(pm) + w(R - 1), g1_neg(pm)),
    ("scalar_r_plus_one", enc_g1(pm) + w(R + 1), pm),
    ("scalar_all_ones", enc_g1(pm) + "ff" * 32, g1_mul(pm, (1 << 256) - 1)),
    ("infinity_times_s", enc_g1(None) + w(s), None),
    ("generator_times_two", enc_g1(G1) + w(2), g1_add(G1, G1)),
    ("empty", "", None),
    ("short_64_no_scalar", enc_g1(pm), None),
    # 16 scalar octets, right-padded: the scalar is s_hi * 2^128.
    ("short_80_half_scalar", enc_g1(pm) + s_hi.to_bytes(16, "big").hex(), g1_mul(pm, s_hi << 128)),
    ("long_trailing_bytes", enc_g1(pm) + w(s) + "cd" * 32, g1_mul(pm, s)),
]

# ── ecPairing (0x08) ─────────────────────────────────────────────────────


def balanced(n):
    """n-1 random pairs (a_i*G1, b_i*G2) closed by (-(sum a_i*b_i)*G1, G2)."""
    pairs, acc = [], 0
    for _ in range(n - 1):
        a, b = scalar(), scalar()
        pairs.append((g1_mul(G1, a), g2_mul(G2, b)))
        acc = (acc + a * b) % R
    pairs.append((g1_mul(G1, (-acc) % R), G2))
    return pairs


def unbalance(pairs):
    """Replace the closing G1 point by its double: the product becomes
    e(G1, G2)^(-sum a_i*b_i), which is not 1 unless that sum is 0 mod r."""
    *head, (last_p, last_q) = pairs
    return head + [(g1_add(last_p, last_p), last_q)]


def enc_pairs(pairs):
    return "".join(enc_g1(p) + enc_g2(q) for p, q in pairs)


two = balanced(2)
ten = balanced(10)
pairing = [
    ("two_pairs_balanced", enc_pairs(two), True),
    ("one_pair_generators", enc_pairs([(G1, G2)]), False),
    ("empty", "", True),
    ("two_pairs_unbalanced", enc_pairs(unbalance(two)), False),
    ("ten_pairs_balanced", enc_pairs(ten), True),
    ("ten_pairs_unbalanced", enc_pairs(unbalance(ten)), False),
    ("infinity_g1", enc_pairs([(None, g2_mul(G2, scalar()))]), True),
    ("infinity_g2", enc_pairs([(g1_rand(), None)]), True),
    ("balanced_plus_infinity_pair", enc_pairs(two + [(None, G2)]), True),
]

for _, inp, _ in pairing:
    assert len(inp) % (192 * 2) == 0

# ── emit ─────────────────────────────────────────────────────────────────

out = [
    "// SPDX-License-Identifier: MIT",
    "// GENERATED by modules/bn254/tools/gen_precompile_vectors.py -- do not edit.",
    "//! EIP-196/197 precompile known answers over this repository's own inputs.",
    "//! Expected values come from the generator's independent affine BN254",
    "//! arithmetic; ecPairing truth values hold by construction (bilinearity).",
    "",
    "pub const AddVector = struct { name: []const u8, input: []const u8, expected: []const u8 };",
    "pub const MulVector = struct { name: []const u8, input: []const u8, expected: []const u8 };",
    "pub const PairingVector = struct { name: []const u8, input: []const u8, expected_true: bool };",
    "",
    "pub const add_vectors = [_]AddVector{",
]
for name, inp, res in add:
    assert g1_on_curve(res)
    out.append(f'    .{{ .name = "{name}", .input = "{inp}", .expected = "{enc_g1(res)}" }},')
out += ["};", "", "pub const mul_vectors = [_]MulVector{"]
for name, inp, res in mul:
    assert g1_on_curve(res)
    out.append(f'    .{{ .name = "{name}", .input = "{inp}", .expected = "{enc_g1(res)}" }},')
out += ["};", "", "pub const pairing_vectors = [_]PairingVector{"]
for name, inp, ok in pairing:
    out.append(f'    .{{ .name = "{name}", .input = "{inp}", .expected_true = {"true" if ok else "false"} }},')
out.append("};")
print("\n".join(out))
