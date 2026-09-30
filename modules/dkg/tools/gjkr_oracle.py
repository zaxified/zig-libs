#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent recomputation of GJKR DKG + resharing public outputs.

Written from the GJKR paper (Gennaro, Jarecki, Krawczyk, Rabin, "Secure
Distributed Key Generation for Discrete-Log Based Cryptosystems", J. Cryptology
2007, Fig. 2) and the redistribution construction of Desmedt-Jajodia (1997) /
Wong-Wang-Wing (2002) -- with plain Python integers over secp256k1 and NOTHING
from any DKG/TSS library. The module's own Zig code and this script share no
source, only the two definitions this repository fixes by convention:

  * the second Pedersen generator `h` (SPEC: SHA-256 try-and-increment over
    "zig-libs/dkg/pedersen-h/secp256k1/v1" || counter_u32_be, even-y point);
  * participant ids are the Shamir evaluation points 1..n.

The ORACLE CLASS IS "REDERIVED", not "foreign": a second implementation of the
same equations by the same author team. It catches arithmetic and encoding
slips in `commit.zig`, `core.zig`, `participant.zig` and `reshare.zig`; it cannot
catch a misreading of the paper that both share.

Usage:
    python3 tools/gjkr_oracle.py --write   # regenerate src/transcript_vectors.zig
    python3 tools/gjkr_oracle.py --check   # recompute everything from the REVEALED
                                           # values in the committed file and compare

The transcript reveals every secret polynomial coefficient (test data only);
`--check` re-derives commitments, shares, Q, X_j, the resharing outputs, and
asserts they equal what the file records (which is what the Zig test replays).
"""
import hashlib
import json
import os
import re
import sys

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)
H_DOMAIN = b"zig-libs/dkg/pedersen-h/secp256k1/v1"

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "..", "src", "transcript_vectors.zig")


# ---- secp256k1 in affine coordinates (None = point at infinity) -------------

def inv(x, m):
    return pow(x, -1, m)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0]:
        if (a[1] + b[1]) % P == 0:
            return None
        lam = 3 * a[0] * a[0] * inv(2 * a[1], P) % P
    else:
        lam = (b[1] - a[1]) * inv(b[0] - a[0], P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def mul(k, pt):
    k %= N
    acc = None
    while k:
        if k & 1:
            acc = add(acc, pt)
        pt = add(pt, pt)
        k >>= 1
    return acc


def enc_pt(pt):
    assert pt is not None
    return ("02" if pt[1] % 2 == 0 else "03") + "%064x" % pt[0]


def dec_pt(h):
    b = bytes.fromhex(h)
    assert len(b) == 33 and b[0] in (2, 3)
    x = int.from_bytes(b[1:], "big")
    y = pow((x ** 3 + 7) % P, (P + 1) // 4, P)
    assert y * y % P == (x ** 3 + 7) % P
    if y % 2 != b[0] - 2:
        y = P - y
    return (x, y)


def enc_sc(s):
    return "%064x" % (s % N)


def pedersen_h():
    counter = 0
    while True:
        d = hashlib.sha256(H_DOMAIN + counter.to_bytes(4, "big")).digest()
        x = int.from_bytes(d, "big")
        counter += 1
        if x >= P:
            continue
        rhs = (x ** 3 + 7) % P
        y = pow(rhs, (P + 1) // 4, P)
        if y * y % P != rhs:
            continue
        if y % 2:
            y = P - y  # 0x02 prefix = even y
        return (x, y)


H = pedersen_h()


# ---- polynomial helpers -----------------------------------------------------

def poly(coeffs, x):
    return sum(c * pow(x, k, N) for k, c in enumerate(coeffs)) % N


def lagrange0(ids, i):
    num, den = 1, 1
    for j in ids:
        if j != i:
            num = num * j % N
            den = den * (j - i) % N
    return num * inv(den, N) % N


def det_scalar(label):
    return int.from_bytes(hashlib.sha256(label.encode()).digest(), "big") % N


# ---- the protocol, transcribed from GJKR Fig. 2 -----------------------------

def dkg_outputs(n, t, a, b):
    """a[i], b[i]: coefficient lists of dealer i+1 (length t). Everyone qualifies."""
    ped = [[add(mul(a[i][k], G), mul(b[i][k], H)) for k in range(t)] for i in range(n)]
    fel = [[mul(a[i][k], G) for k in range(t)] for i in range(n)]
    shares = [[(poly(a[i], j), poly(b[i], j)) for j in range(1, n + 1)] for i in range(n)]
    # Pedersen check (Fig. 2 step 2) and Feldman check (step 4): g^s h^s' = prod C_k^(j^k)
    for i in range(n):
        for j in range(1, n + 1):
            s, sp = shares[i][j - 1]
            lhs = add(mul(s, G), mul(sp, H))
            rhs = None
            for k in range(t):
                rhs = add(rhs, mul(pow(j, k, N), ped[i][k]))
            assert lhs == rhs, "pedersen"
            rhs = None
            for k in range(t):
                rhs = add(rhs, mul(pow(j, k, N), fel[i][k]))
            assert mul(s, G) == rhs, "feldman"
    Q = None
    for i in range(n):
        Q = add(Q, fel[i][0])
    x = [sum(shares[i][j][0] for i in range(n)) % N for j in range(n)]
    X = [mul(x[j], G) for j in range(n)]
    secret = sum(a[i][0] for i in range(n)) % N
    assert mul(secret, G) == Q
    for subset in ([1, 2, 3][:t], list(range(n, n - t, -1))):
        assert sum(x[i - 1] * lagrange0(subset, i) for i in subset) % N == secret
    return ped, fel, shares, Q, x, X, secret


def reshare_outputs(old_x, old_X, Q, S, new_n, new_t, c):
    """Dealers S (old ids) share old_x[i-1] with degree new_t-1 polynomials
    g_i(z) = x_i + c[i][0] z + ...; new party j takes sum_i lambda_i g_i(j)."""
    g = {i: [old_x[i - 1]] + c[i] for i in S}
    B = {i: [mul(v, G) for v in g[i]] for i in S}
    for i in S:
        assert B[i][0] == old_X[i - 1], "B_i0 must equal the old verifying share"
    sh = {i: [poly(g[i], j) for j in range(1, new_n + 1)] for i in S}
    lam = {i: lagrange0(S, i) for i in S}
    newx = [sum(lam[i] * sh[i][j] for i in S) % N for j in range(new_n)]
    newX = [mul(v, G) for v in newx]
    Fp = []
    for k in range(new_t):
        acc = None
        for i in S:
            acc = add(acc, mul(lam[i], B[i][k]))
        Fp.append(acc)
    assert Fp[0] == Q, "group key must be unchanged"
    for j in range(1, new_n + 1):
        rhs = None
        for k in range(new_t):
            rhs = add(rhs, mul(pow(j, k, N), Fp[k]))
        assert rhs == newX[j - 1]
    ids = list(range(1, new_t + 1))
    assert sum(newx[i - 1] * lagrange0(ids, i) for i in ids) % N == sum(old_x[i - 1] * lagrange0(S, i) for i in S) % N
    return g, B, sh, lam, newx, newX, Fp


# ---- transcript -------------------------------------------------------------

DKG_N, DKG_T = 4, 3
RS_DEALERS, RS_N, RS_T = [1, 2, 4], 3, 2


def build():
    a = [[det_scalar("gjkr-fixture/a/%d/%d" % (i + 1, k)) for k in range(DKG_T)] for i in range(DKG_N)]
    b = [[det_scalar("gjkr-fixture/b/%d/%d" % (i + 1, k)) for k in range(DKG_T)] for i in range(DKG_N)]
    c = {i: [det_scalar("gjkr-fixture/reshare/%d/%d" % (i, k)) for k in range(1, RS_T)] for i in RS_DEALERS}
    return a, b, c


def render(a, b, c):
    ped, fel, shares, Q, x, X, _ = dkg_outputs(DKG_N, DKG_T, a, b)
    g, B, sh, lam, newx, newX, Fp = reshare_outputs(x, X, Q, RS_DEALERS, RS_N, RS_T, c)
    doc = {
        "n": DKG_N,
        "t": DKG_T,
        "h": enc_pt(H),
        "dealers": [
            {
                "id": i + 1,
                "a": [enc_sc(v) for v in a[i]],
                "b": [enc_sc(v) for v in b[i]],
                "pedersen": [enc_pt(p) for p in ped[i]],
                "feldman": [enc_pt(p) for p in fel[i]],
                "shares": [[enc_sc(s), enc_sc(sp)] for (s, sp) in shares[i]],
            }
            for i in range(DKG_N)
        ],
        "group_public_key": enc_pt(Q),
        "outputs": [{"id": j + 1, "x": enc_sc(x[j]), "X": enc_pt(X[j])} for j in range(DKG_N)],
        "reshare": {
            "dealers": RS_DEALERS,
            "new_n": RS_N,
            "new_t": RS_T,
            "dealer_polys": [
                {
                    "id": i,
                    "c": [enc_sc(v) for v in c[i]],
                    "commitments": [enc_pt(p) for p in B[i]],
                    "shares": [enc_sc(v) for v in sh[i]],
                    "lambda": enc_sc(lam[i]),
                }
                for i in RS_DEALERS
            ],
            "new_commitments": [enc_pt(p) for p in Fp],
            "outputs": [{"id": j + 1, "x": enc_sc(newx[j]), "X": enc_pt(newX[j])} for j in range(RS_N)],
        },
    }
    return doc


def write_zig(doc):
    text = json.dumps(doc, indent=1)
    lines = "\n".join("    \\\\" + ln for ln in text.split("\n"))
    out = (
        "// SPDX-License-Identifier: MIT\n"
        "//! GENERATED by tools/gjkr_oracle.py --write -- do not edit by hand.\n"
        "//!\n"
        "//! A recorded GJKR transcript (4 parties, t = 3) and a resharing of its key to\n"
        "//! 3 parties, t = 2, with EVERY secret coefficient revealed (test data only) and\n"
        "//! every public output recomputed by the independent Python oracle. The Zig\n"
        "//! test replays the participants with these coefficients and asserts equality.\n"
        "\n"
        "pub const json =\n" + lines + "\n;\n"
    )
    with open(VECTORS, "w") as f:
        f.write(out)


def read_zig():
    with open(VECTORS) as f:
        src = f.read()
    body = "\n".join(m.group(1) for m in re.finditer(r"^    \\\\(.*)$", src, re.M))
    return json.loads(body)


def check():
    doc = read_zig()
    n, t = doc["n"], doc["t"]
    assert enc_pt(H) == doc["h"]
    a = [[int(v, 16) for v in d["a"]] for d in doc["dealers"]]
    b = [[int(v, 16) for v in d["b"]] for d in doc["dealers"]]
    c = {p["id"]: [int(v, 16) for v in p["c"]] for p in doc["reshare"]["dealer_polys"]}
    rs = doc["reshare"]
    assert (rs["dealers"], rs["new_n"], rs["new_t"]) == (RS_DEALERS, RS_N, RS_T) and (n, t) == (DKG_N, DKG_T)
    fresh = render(a, b, c)
    if fresh != doc:
        for key in fresh:
            if fresh[key] != doc.get(key):
                print("MISMATCH in", key)
        return 1
    # Everything below is from the revealed values only: no generator state.
    print("ok: %d-of-%d transcript and %d-of-%d resharing recomputed identically" % (t, n, rs["new_t"], rs["new_n"]))
    return 0


def main(argv):
    if "--write" in argv:
        a, b, c = build()
        write_zig(render(a, b, c))
        print("wrote", os.path.normpath(VECTORS))
        return 0
    if "--check" in argv:
        return check()
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
