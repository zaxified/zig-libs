# bn254

BN254 (alt-bn128): the pairing-friendly elliptic curve behind
Ethereum's EIP-196/197 precompiles (`ecAdd`/`ecMul`/`ecPairing`,
addresses `0x06`/`0x07`/`0x08`) and Groth16 zk-SNARK verification —
this module is **Parts 1-3** of a planned multi-part arc: the base
field `Fp`, the extension tower `Fp2`/`Fp6`/`Fp12`, the scalar field
`Fr`, and the pairing groups `G1`/`G2`.

**Status: Parts 1-3 complete.** Full field-tower arithmetic
(`add`/`sub`/`neg`/`mul`/`square`/`inv`/`pow`/`sqrt`/Frobenius at every
tower level) plus `G1`/`G2` Jacobian group arithmetic (`add`/`double`/
`negate`/constant-time `scalarMul`), on-curve and subgroup-membership
checks, and EIP-196/197 (de)serialization. Every field/curve constant
independently verified (see `SPEC.md`), byte-exact KAT coverage against
independently-computed reference vectors, 103/103 tests pass in Debug
AND ReleaseFast. NO pairing, NO precompile wiring yet — those are later
parts.

This module was built by careful, verified ADAPTATION of the sibling
[`bls12_381`](../bls12_381) module: same `std.crypto.ff`-backed
`Fp`/`Fr` construction, same tower-arithmetic formula shapes, and the
same Jacobian point-arithmetic formulas (all generic in the field's
non-residue / the curve's `b` constant, so they carry over unchanged),
with BN254's own modulus/non-residue/generator constants substituted in
and independently re-verified from scratch — see `SPEC.md`.

## The multi-part arc

| Part | Scope | Status |
|---|---|---|
| 1-2 | Field tower (`Fp`/`Fp2`/`Fp6`/`Fp12`) + scalar field `Fr` | **done** |
| 3 | Groups `G1`/`G2` | **done** |
| 4 | The pairing itself: Miller loop + final exponentiation | planned |
| 5 | EIP-196/197 precompile semantics (`ecAdd`/`ecMul`/`ecPairing`) | planned |
| 6 | Groth16 zk-SNARK verifier | planned |

## Import

```zig
const bn254 = @import("bn254");
```

## API sketch

```zig
// Base field, scalar field:
const a = try bn254.Fp.fromBytes(bytes_32); // EVM/EIP-196 big-endian 32-byte encoding
const s = try bn254.Fr.fromBytes(bytes_32);

// Extension tower:
const x: bn254.Fp2 = .{ .c0 = a, .c1 = bn254.Fp.zero };
const y: bn254.Fp6 = .{ .c0 = x, .c1 = bn254.Fp2.zero, .c2 = bn254.Fp2.zero };
const z: bn254.Fp12 = .{ .c0 = y, .c1 = bn254.Fp6.zero };

// Arithmetic (every layer has the same shape):
const sum = a.add(a);       // add/sub/neg/mul/square/inv/pow
const sq = a.sqrt();        // Fp/Fp2 only — the complex method for p ≡ 3 (mod 4)
const fr = x.frobenius();   // Fp2/Fp6/Fp12 — programmatically-derived coefficients, no transcribed table

// G1 (cofactor 1 — every on-curve point is automatically a subgroup
// member, see g1.zig's module doc comment):
const p1 = bn254.G1.Jacobian.fromAffine(bn254.G1.Affine.generator);
const p1_2 = p1.scalarMul(s);                 // constant-time double-and-add
try std.testing.expect(p1_2.subgroupCheck()); // == isOnCurve() for G1
const p1_bytes = bn254.G1.toBytes(p1_2.toAffine()); // EIP-196, 64 bytes

// G2 (cofactor > 1 — subgroupCheck is a REAL [r]P == O check):
const p2 = bn254.G2.Jacobian.fromAffine(bn254.G2.Affine.generator);
const p2_2 = p2.scalarMul(s);
try std.testing.expect(p2_2.subgroupCheck()); // mandatory before trusting an external G2 point
const p2_bytes = bn254.G2.toBytes(p2_2.toAffine()); // EIP-197, 128 bytes, imaginary-first Fp2 ordering
```

Deliberately absent vs. `bls12_381`: `isLexicographicallyLargest` (a
compressed-point "sign of y" helper) — Ethereum's EIP-196/197 encodes
`G1`/`G2` points UNCOMPRESSED, so no consumer for that helper exists in
this arc; see `SPEC.md`. Also absent: `G1`/`G2` cofactor-clearing —
`G1`'s cofactor is 1 (nothing to clear) and `G2`'s cofactor-clearing has
no consumer in this arc (BN254 has no standardized hash-to-`G2` needed
for EIP-197/Groth16 verification); see `g1.zig`/`g2.zig`'s module doc
comments.

## File layout

| File | Contents |
|---|---|
| `fp.zig` | Base field `Fp` (mod `p`), built on `std.crypto.ff.Modulus(256)` |
| `fp2.zig` | `Fp2 = Fp[u]/(u²+1)` |
| `fp6.zig` | `Fp6 = Fp2[v]/(v³−ξ)`, `ξ = 9+u` (differs from `bls12_381`'s `u+1`) |
| `fp12.zig` | `Fp12 = Fp6[w]/(w²−v)` — the future pairing's target field |
| `scalar.zig` | Scalar field `Fr` (mod `r`, the group order), built on `std.crypto.ff.Modulus(256)` |
| `g1.zig` | `G1`: `E(Fp): y²=x³+3`, cofactor 1, Jacobian arithmetic, EIP-196 64-byte codec |
| `g2.zig` | `G2`: the sextic twist `E'(Fp2): y²=x³+b'`, `b'=3/(9+u)`, cofactor > 1 (subgroup check mandatory), Jacobian arithmetic, EIP-197 128-byte codec |
| `root.zig` | Module entry: `meta`, re-exports, dark-tests aggregator |

## Verify

```
zig build test-bn254                        # Debug — 103/103 pass
zig build test-bn254 -Doptimize=ReleaseFast # ReleaseFast — 103/103 pass
zig fmt --check modules/bn254/
```

Design record + cited sources: see [SPEC.md](SPEC.md). No `NOTICE`
entry — BN254's parameters come from a public spec (EIP-196/197) and
mathematical constants, not third-party source (see `SPEC.md`'s
"Model-after + seed").
