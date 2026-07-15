# bn254 — SPEC

BN254 (alt-bn128): see [README.md](README.md) for purpose and API.

## Purpose

Parts 1-3 of a multi-part arc (`README.md`): the base field `Fp`, the
extension tower `Fp2`/`Fp6`/`Fp12`, the scalar field `Fr` (Parts 1-2),
and the pairing groups `G1`/`G2` (Part 3, `g1.zig`/`g2.zig`) —
everything a future pairing/precompile/Groth16 layer needs as its
foundation. NO pairing in this module yet (Part 4+).

## Model-after + seed

- **Source of truth for the field/curve parameters**: EIP-196
  (`https://eips.ethereum.org/EIPS/eip-196`) and EIP-197
  (`https://eips.ethereum.org/EIPS/eip-197`) — the Ethereum alt_bn128
  precompile specification — cross-checked against `py_ecc`'s
  published `bn128_field_elements.field_modulus` /
  `bn128_curve.curve_order` / `bn128_curve.G1` / `bn128_curve.G2`
  constants (these are PUBLISHED NUMBERS, not copyrightable expression
  — see the "NOTICE" section below for why no NOTICE entry is needed).
- **`Fp`/`Fr` ride on `std.crypto.ff.Modulus`/`Fe`** (`fp.zig`/
  `scalar.zig`), exactly as `bls12_381` does — this module supplies the
  BN254-specific modulus values and field-arithmetic entry points on
  top; it does NOT reimplement big-integer or Montgomery arithmetic
  itself. Both `Fp` and `Fr` use a 256-bit (32-byte) container — a
  BN254-specific quirk vs. `bls12_381` (whose `Fp`/`Fr` use DIFFERENT
  widths, 384 vs. 256 bits) because BN254's `p` and `r` are both
  exactly 254 bits.
- **The extension-tower ARITHMETIC (mul/square/inv formulas) is
  ADAPTED, not reinvented, from the sibling `bls12_381` module.** The
  Devegili–Ó hÉigeartaigh–Scott–Dahab tower-multiplication formulas
  (`Fp6`/`Fp12` mul/square/inv) and the Adj & Rodriguez-Henriquez
  ePrint 2012/685 Algorithm 9 complex-method square root (`Fp2.sqrt`)
  are GENERIC in the field's non-residue — every formula is expressed
  only through `mulByNonresidue`/`add`/`sub`/`mul` calls, never a
  literal non-residue constant baked into the algebra — so they carry
  over from `bls12_381` UNCHANGED; only the non-residue VALUES
  (`fp2.zig`'s `u²=-1` — same as `bls12_381`; `fp6.zig`'s `ξ=9+u` —
  DIFFERENT from `bls12_381`'s `ξ=u+1`) and the modulus `p` itself
  differ. `bls12_381`'s own SPEC.md records that these formula shapes
  were themselves validated against independently-computed vectors,
  not transcribed from `zkcrypto`/`blst` source — that provenance
  carries forward here.
- **Granger–Scott cyclotomic squaring** (`fp12.zig`'s
  `cyclotomicSquare`, "Faster Squaring in the Cyclotomic Subgroup of
  Sixth Degree Extensions", PKC 2010) is likewise generic in the
  tower's non-residues and copied unchanged from `bls12_381`.
- **Part 3's `G1`/`G2` Jacobian point arithmetic (`add`/`double`,
  add-2007-bl/dbl-2009-l, Bernstein–Lange EFD `shortw/jacobian-0`) is
  ADAPTED unchanged from `bls12_381/src/g1.zig`/`g2.zig`** — both
  formulas are GENERIC in the curve's `b` constant (only the `a = 0`
  short-Weierstrass coefficient matters, which BN254's `G1`/twist `E'`
  share with BLS12-381's), so only the curve constants (`b = 3` for
  `G1`; `b' = 3*(9+u)^-1` for `G2`'s twist) and generator coordinates
  differ. `G1`'s wire codec is a NEW, simpler design vs.
  `bls12_381/src/g1.zig`'s (EIP-196/197 has no compressed format or
  flag bits, unlike the ZCash/IETF format `bls12_381` uses) — see
  `g1.zig`/`g2.zig`'s module doc comments for the exact reasoning.

## Design & invariants

- **`p ≡ 3 (mod 4)`, `p ≡ 1 (mod 3)`, `p ≡ 1 (mod 6)`** — all three
  confirmed directly from `p_bytes` and independently in Python (see
  "Verification performed" below). These are exactly the congruences
  every formula in this tower depends on (`Fp.sqrt`'s simple case,
  `Fp2.sqrt`'s complex method, `Fp6`/`Fp12`'s exact-division Frobenius
  exponents) — same congruence class as `bls12_381`'s `p`, which is why
  the formula shapes transfer without modification.
- **Frobenius coefficients: derived in code, never transcribed** — same
  discipline as `bls12_381`. `Fp6`'s `γ_1 = ξ^((p-1)/3)` (`γ_2 =
  γ_1²`) and `Fp12`'s `γ = ξ^((p-1)/6)` are computed via `Fp2.pow` with
  exponents derived at COMPTIME from the verified `p_bytes`
  (`fp.pExponentBytes`, which hard-fails the build if a division is
  inexact). Pinned two ways: definitionally (`frobenius(a) == a^p`
  computed with plain mul/square) and byte-exactly against
  independently-recomputed values (see KAT tests in `fp6.zig`/
  `fp12.zig`).
- **`Fp2` non-residue convention: `u² = -1`.** SAME as `bls12_381` —
  confirmed independently: `py_ecc.bn128`'s `FQ2` uses
  `modulus_coeffs = (1, 0)`, i.e. `i² + 1 = 0`.
- **`Fp6` non-residue convention: `ξ = 9 + u`.** DIFFERENT from
  `bls12_381`'s `ξ = u+1` — this is the standard BN254 tower
  construction (confirmed via the `G2`-twist on-curve check below: the
  twist coefficient `b₂ = 3/ξ` only lands on the known-published `G2`
  generator with `ξ = 9+u`).
- **No `isLexicographicallyLargest` (deliberate omission vs.
  `bls12_381`).** `bls12_381` needs this "sign of y" helper because its
  point-serialization convention (ZCash/IETF) COMPRESSES points (x-only
  + a 1-bit sign flag). Ethereum's EIP-196/197 `G1`/`G2` precompile
  encoding is UNCOMPRESSED — raw `(x, y)` (and `(x_im, x_re, y_im,
  y_re)` for `G2`) coordinate pairs, no compression, no sign bit. This
  module therefore has no correctness need for that helper in its
  planned arc; adding it back is a one-line change if a future
  compressed-encoding consumer ever appears, but it would currently be
  dead, untested code.
- **Montgomery-storage / canonical-storage convention: identical to
  `bls12_381`** (`Fp`/`Fr` store canonically at rest; see `fp.zig`'s
  module doc comment).
- **`G1`'s cofactor is 1 — a load-bearing fact, not a simplification.**
  BN254's defining polynomial family gives `#E(Fp) = p + 1 - t = r`
  EXACTLY (`t = 6x^2+1`, confirmed `p + 1 - t == r` symbolically — see
  "Verification performed" below), i.e. `r` (prime) IS the full order
  of `E(Fp)`, not merely a large prime factor. Since a group of prime
  order has no nontrivial proper subgroups, `E(Fp)` and `G1` are THE
  SAME SET — `isOnCurve() == subgroupCheck()` for every point,
  unconditionally. This is a REAL difference from `bls12_381`'s `G1`
  (cofactor `h1 = 0x396c8c...`, nontrivial), not a shortcut this module
  took: `g1.zig`'s `subgroupCheck` returning `isOnCurve()` is the
  mathematically exact answer, verified independently two ways (the
  polynomial identity, and `[r]G1 == O` computed via full scalar-mul in
  both this module's tests and the Python cross-check below).
- **`G2`'s cofactor is NONTRIVIAL** (`#E'(Fp2) = r * h2`, `h2 > 1`) —
  `subgroupCheck` for `G2` is a REAL `[r]P == O` scalar multiplication
  (`g2.zig`), not a shortcut. This module does NOT compute or expose
  `h2`/cofactor-clearing: BN254 has no standardized hash-to-`G2` used by
  EIP-197 precompile semantics or Groth16 verification (both only ever
  consume caller-supplied `G2` points, never hash an arbitrary message
  onto the twist), so cofactor clearing has no consumer in this arc —
  see `g2.zig`'s module doc comment. `subgroupCheck` alone (no
  clearing) is sufficient and IS exercised: a constructed on-twist,
  non-subgroup point (`x = u`) is verified to FAIL it (see `g2.zig`'s
  tests and "Verification performed" below).
- **`b' = 3/ξ = 3*(9+u)^-1` is DERIVED at runtime via real `Fp2`
  arithmetic (`g2.zig`'s `twistB()`), never hand-transcribed as a
  numeric literal.** Pinned byte-exact against an independent Python
  computation (below).
- **EIP-197's `G2` wire encoding is imaginary-component-FIRST**: an
  `Fp2` element `a + b*i` serializes as `(b, a)`. Combined with `Fp2`'s
  `c1` being the `u`-coefficient (`fp2.zig`'s convention), the 128-byte
  `G2` encoding is `x.c1 || x.c0 || y.c1 || y.c0` — see `g2.zig`'s codec
  section doc comment. Pinned against a KAT vector where `c0 != c1` on
  every coordinate (the generator itself qualifies), so a swapped
  ordering could not silently pass.

## Tier assessment — Fable NOT required for Parts 1-3

This is a **careful, verified ADAPTATION**, not novel cryptographic
design. Every algorithm (Montgomery field arithmetic via
`std.crypto.ff`, Karatsuba/Devegili tower multiplication, the
Adj–Rodriguez-Henriquez complex-method square root, Granger–Scott
cyclotomic squaring, programmatic Frobenius-coefficient derivation) is
the SAME formula shape already proven correct and battle-tested in the
sibling `bls12_381` module — the only things that changed are the
modulus `p`/`r` and the `Fp6` non-residue `ξ`, both independently
verified against multiple public sources (below) and pinned by
byte-exact KAT. Nothing here required inventing a new algorithm,
resolving an ambiguous spec, or making an irreducible cryptographic
design judgment call. **No stub was left; no test was weakened to
pass; every identity (Fermat, Frobenius=pow(p), cyclotomic-square=
square-on-subgroup, ring axioms) held on the first implementation
attempt** — there was no "genuinely subtle" failure to isolate.

**Part 3 (`G1`/`G2`) is the same story, one level up.** The Jacobian
`add`/`double` formulas are UNCHANGED from `bls12_381` (generic in `b`);
`scalarMul`'s constant-time double-and-add-always construction is
UNCHANGED. The two genuinely BN254-specific pieces — `G1`'s cofactor
being exactly 1 (not merely "small"), and deriving `b' = 3/(9+u)` in
`Fp2` rather than transcribing it — are ARITHMETIC FACTS with a
mechanical derivation and an independent Python cross-check each, not
open design questions: there was no ambiguity about which of two
candidate formulas to use, no judgment call about a threat model, no
place a wrong choice could have been made and only discovered by an
adversarial audit. Every group-law identity (associativity,
distributivity of `scalarMul`, `[r]G1 == O`, `[r]G2 == O`, the
non-subgroup `G2` point failing `subgroupCheck`, every `[k]G`
byte-exact KAT) passed on the first implementation attempt — again, no
"genuinely subtle" failure surfaced. The Fable-hard work in this arc,
if any, remains deferred to a LATER part: the optimal-ate Miller loop /
final-exponentiation hard part (Part 4) is where BN254 diverges
non-trivially from BLS12-381 (different embedding structure, different
`6x+2` NAF loop, D-type vs. twist details worth a dedicated audit) —
that is where a harder-tier pass would be worth spending, not here.

## Verification performed

Every embedded constant was independently re-derived/cross-checked
with Python (`python3`, standard library only — no third-party crypto
package), OUTSIDE this module, before being pinned as a test vector or
comptime literal. Reproducible steps:

**1. Primality + BN polynomial-family re-derivation** (confirms `p_bytes`/`r_bytes`):

```python
p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
x = 4965661367192848881  # the BN seed
assert p == 36*x**4 + 36*x**3 + 24*x**2 + 6*x + 1
assert r == 36*x**4 + 36*x**3 + 18*x**2 + 6*x + 1
# both independently confirmed prime by a 40-round Miller-Rabin test
```

**2. `p`'s congruences** (confirms the algorithm-shape preconditions):
`p % 4 == 3`, `(p-1) % 3 == 0`, `(p-1) % 6 == 0` — all directly
computed.

**3. `G1`/`G2`-on-curve cross-check** (confirms `p` AND the `Fp6`
non-residue `ξ = 9+u` together, without this module implementing any
group arithmetic itself — see `fp.zig`'s own KAT test for the `G1`
half):

```python
# G1 = (1, 2) on y^2 = x^3 + 3 (EIP-196 / py_ecc bn128_curve.py)
assert (2*2) % p == (1**3 + 3) % p

# G2 on the sextic twist y^2 = x^3 + b2, b2 = 3/(9+u), using
# Fp2 = Fp[u]/(u^2+1), element (c0,c1) = c0 + c1*u:
def fp2_mul(a,b):
    a0,a1=a; b0,b1=b
    return ((a0*b0 - a1*b1) % p, (a0*b1 + a1*b0) % p)
def fp2_inv(a):
    a0,a1 = a
    n = pow((a0*a0 + a1*a1) % p, p-2, p)
    return ((a0*n) % p, ((-a1)*n) % p)
xi = (9, 1)
b2 = fp2_mul((3,0), fp2_inv(xi))
G2x = (10857046999023057135944570762232829481370756359578518086990519993285655852781,
       11559732032986387107991004021392285783925812861821192530917403151452391805634)
G2y = (8495653923123431417604973247489272438418190587263600148770280649306958101930,
       4082367875863433681332203403145435568316851327593401208105741076214120093531)
def fp2_add(a,b): return ((a[0]+b[0])%p,(a[1]+b[1])%p)
x3 = fp2_mul(fp2_mul(G2x,G2x), G2x)
assert fp2_mul(G2y,G2y) == fp2_add(x3, b2)  # True
```

(`G2x`/`G2y` are `py_ecc.bn128.bn128_curve.G2`'s published coordinates,
`FQ2([c0, c1])` meaning `c0 + c1*i`.)

**4. Full independent field-tower KAT generator.** A from-scratch
Python re-implementation of `Fp2`/`Fp6`/`Fp12` arithmetic (Montgomery
storage NOT used — plain `pow`/`%` big-integer arithmetic, deliberately
a DIFFERENT implementation strategy than this module's
`std.crypto.ff`-backed Zig code, so the two cannot share a bug) was
used to generate every KAT hex string pinned in `fp2.zig`/`fp6.zig`/
`fp12.zig`'s `test "KAT: ..."` blocks: `Fp2` multiplication and
inversion, `Fp6`/`Fp12` Frobenius coefficients (`γ_1`, `γ`), `Fp6`
multiplication and inversion, `Fp12` multiplication, and `Fr`'s 64-byte
`reduceWide` reduction. The generator (kept for reproducibility, not
shipped/imported by the module):

```python
p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
def fp_inv(a): return pow(a, p-2, p)

def fp2_add(a,b): return ((a[0]+b[0])%p, (a[1]+b[1])%p)
def fp2_sub(a,b): return ((a[0]-b[0])%p, (a[1]-b[1])%p)
def fp2_mul(a,b):
    a0,a1=a; b0,b1=b
    return ((a0*b0 - a1*b1)%p, (a0*b1+a1*b0)%p)
def fp2_sq(a): return fp2_mul(a,a)
def fp2_inv(a):
    a0,a1=a
    ninv = fp_inv((a0*a0+a1*a1)%p)
    return ((a0*ninv)%p, ((-a1)*ninv)%p)
FP2_ONE=(1,0); FP2_ZERO=(0,0)
XI = (9,1)  # Fp6 non-residue = 9+u

def fp6_mulByNonresidue(a):
    c0,c1,c2 = a
    return (fp2_mul(c2, XI), c0, c1)
def fp6_mul(a,b):
    a0,a1,a2=a; b0,b1,b2=b
    v0=fp2_mul(a0,b0); v1=fp2_mul(a1,b1); v2=fp2_mul(a2,b2)
    t0 = fp2_sub(fp2_sub(fp2_mul(fp2_add(a1,a2),fp2_add(b1,b2)),v1),v2)
    c0 = fp2_add(fp2_mul(t0, XI), v0)
    c1 = fp2_add(fp2_sub(fp2_sub(fp2_mul(fp2_add(a0,a1),fp2_add(b0,b1)),v0),v1), fp2_mul(v2,XI))
    c2 = fp2_sub(fp2_add(fp2_sub(fp2_mul(fp2_add(a0,a2),fp2_add(b0,b2)),v0),v1),v2)
    return (c0,c1,c2)
FP6_ONE=(FP2_ONE,FP2_ZERO,FP2_ZERO)
def fp6_inv(a):
    a0,a1,a2=a
    c0 = fp2_sub(fp2_sq(a0), fp2_mul(fp2_mul(a1,a2),XI))
    c1 = fp2_sub(fp2_mul(fp2_sq(a2),XI), fp2_mul(a0,a1))
    c2 = fp2_sub(fp2_sq(a1), fp2_mul(a0,a2))
    t = fp2_add(fp2_mul(fp2_add(fp2_mul(a1,c2),fp2_mul(a2,c1)),XI), fp2_mul(a0,c0))
    tinv = fp2_inv(t)
    return (fp2_mul(c0,tinv), fp2_mul(c1,tinv), fp2_mul(c2,tinv))

def fp6_add(a,b): return tuple(fp2_add(x,y) for x,y in zip(a,b))
def fp6_sub(a,b): return tuple(fp2_sub(x,y) for x,y in zip(a,b))
def fp12_mul(a,b):
    a0,a1=a; b0,b1=b
    v0=fp6_mul(a0,b0); v1=fp6_mul(a1,b1)
    c0 = fp6_add(v0, fp6_mulByNonresidue(v1))
    c1 = fp6_sub(fp6_sub(fp6_mul(fp6_add(a0,a1),fp6_add(b0,b1)),v0),v1)
    return (c0,c1)

def fp2_pow(a, e):
    acc = FP2_ONE
    base = a
    while e > 0:
        if e & 1: acc = fp2_mul(acc, base)
        base = fp2_sq(base)
        e >>= 1
    return acc

gamma_1 = fp2_pow(XI, (p-1)//3)   # Fp6 Frobenius coefficient
gamma   = fp2_pow(XI, (p-1)//6)   # Fp12 Frobenius coefficient
```

(Every KAT test in this module cites which of these computations it
pins.) Hex encoding: each `Fp` value is
`format(x % p, '064x')` (32 bytes, big-endian); `Fp2`/`Fp6`/`Fp12`
concatenate their components HIGH-to-LOW (`c1||c0`, `c2||c1||c0`,
`c1||c0`) matching this module's own `toBytes` convention.

**5. `Fr.reduceWide` 64-byte KAT**: `int.from_bytes(b'\xff'*64, 'big')
% r`, computed directly in Python.

**6. Part 3 (`G1`/`G2`) — independent from-scratch Python EC
implementation.** Plain textbook AFFINE-coordinate short-Weierstrass
formulas over Python big integers (a DIFFERENT algorithm family than
this module's Jacobian/`std.crypto.ff` Zig code) were used to:

```python
p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
def fp_inv(a): return pow(a, p-2, p)
def fp2_mul(a,b):
    a0,a1=a; b0,b1=b
    return ((a0*b0 - a1*b1) % p, (a0*b1 + a1*b0) % p)
def fp2_sq(a): return fp2_mul(a,a)
def fp2_inv(a):
    a0,a1 = a
    n = fp_inv((a0*a0 + a1*a1) % p)
    return ((a0*n) % p, ((-a1)*n) % p)
def fp2_add(a,b): return ((a[0]+b[0])%p, (a[1]+b[1])%p)
def fp2_sub(a,b): return ((a[0]-b[0])%p, (a[1]-b[1])%p)

xi = (9, 1)
b2 = fp2_mul((3,0), fp2_inv(xi))  # G2's twist constant b'

G1 = (1, 2)
def g1_add(P, Q):  # standard affine EC addition/doubling over Fp
    if P is None: return Q
    if Q is None: return P
    x1,y1 = P; x2,y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0: return None
    if P == Q:
        if y1 == 0: return None
        m = (3*x1*x1) * fp_inv(2*y1) % p
    else:
        m = (y2-y1) * fp_inv((x2-x1) % p) % p
    x3 = (m*m - x1 - x2) % p
    y3 = (m*(x1-x3) - y1) % p
    return (x3, y3)
def g1_mul(P, k):
    R, Q = None, P
    while k > 0:
        if k & 1: R = g1_add(R, Q)
        Q = g1_add(Q, Q); k >>= 1
    return R

def g2_add(P, Q):  # same shape, over Fp2
    if P is None: return Q
    if Q is None: return P
    x1,y1 = P; x2,y2 = Q
    if x1 == x2 and fp2_add(y1,y2) == (0,0): return None
    if P == Q:
        if y1 == (0,0): return None
        m = fp2_mul(fp2_mul((3,0), fp2_sq(x1)), fp2_inv(fp2_mul((2,0), y1)))
    else:
        m = fp2_mul(fp2_sub(y2,y1), fp2_inv(fp2_sub(x2,x1)))
    x3 = fp2_sub(fp2_sub(fp2_sq(m), x1), x2)
    y3 = fp2_sub(fp2_mul(m, fp2_sub(x1,x3)), y1)
    return (x3, y3)
def g2_mul(P, k):
    R, Q = None, P
    while k > 0:
        if k & 1: R = g2_add(R, Q)
        Q = g2_add(Q, Q); k >>= 1
    return R
```

used to:
- confirm `p + 1 - t == r` (`t = 6x^2+1`) — the polynomial identity
  behind `G1`'s cofactor-1 claim;
- confirm `r * G1 == O` and `r * G2 == O` (via `g1_mul`/`g2_mul`) —
  independent of this module's own `[r]P == O` tests;
- generate the `[k]G1`/`[k]G2` byte-exact KAT vectors pinned in
  `g1.zig`/`g2.zig` for `k ∈ {2, 3, 5, 0x0123...cdef}`;
- search small `x = (0, c1)` values on the `G2` twist (via `fp2_sqrt`,
  the same complex-method construction as `fp2.zig`'s `Fp2.sqrt`) for
  one where `g2_mul(P, r) is not None` — `x = u` (`c1 = 1`) was the
  first hit, confirmed on-twist AND outside the subgroup, and is the
  vector `g2.zig`'s negative `subgroupCheck` test uses;
- confirm `twistB()`'s value (`b2` above) byte-for-byte against
  `g2.zig`'s comptime/runtime-computed result, and the EIP-197
  imaginary-first 128-byte encoding of the `G2` generator and `[2]G2`
  byte-for-byte against `g2.zig`'s `toBytes` output.

## NOTICE — why no entry

Per `CONVENTIONS.md` §5's NOTICE policy: EIP-196/197 is a public
specification (merger doctrine — not copyrightable), and the field/
curve constants themselves are mathematical facts, not third-party
expression. `py_ecc`'s published constant VALUES were cross-checked
(not its source code ported or studied for algorithm/API shape — this
module's algorithms come from `bls12_381`, an internal sibling module,
not from `py_ecc`). This mirrors `bls12_381`'s own NOTICE-free
precedent (its "Model-after" cites `draft-irtf-cfrg-pairing-friendly-
curves`, a spec, and has no NOTICE entry either). No entry needed.

## Backlog

- Part 3 (`G1`/`G2` group arithmetic — Jacobian/affine points,
  constant-time scalar multiplication, on-curve + subgroup checks):
  **done** (`g1.zig`/`g2.zig`).
- Part 4: the optimal-ate pairing (`6x+2` NAF Miller loop, final
  exponentiation) — the first place this arc may warrant a harder
  verification tier (see "Tier assessment" above).
- Part 5: EIP-196/197 precompile-exact semantics (point-at-infinity
  encoding, gas-irrelevant validation rules, the exact error/success
  behavior the EVM expects).
- Part 6: Groth16 verifier over the pairing.
- Persistent Montgomery storage / precomputed Frobenius-coefficient
  tables (performance-only; same deferred-optimization shape as
  `bls12_381`'s SPEC.md Backlog) — not needed until a later part's hot
  path (Miller loop) makes it worth the complexity.
- `G2`'s fast endomorphism-based subgroup check (untwist-Frobenius-twist
  — same technique `bls12_381/src/g2.zig`'s Backlog defers) — the
  simple `[r]P == O` form implemented here is correct and is what a
  scaffolding-stage Part 3 needs; a faster check is a follow-up
  optimization, not a correctness gap.
- `G2` cofactor value/`clearCofactor` — deliberately out of scope for
  this arc (see "Design & invariants" above); revisit only if a future
  part adds hash-to-`G2`.
