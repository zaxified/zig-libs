# bls12_381

BLS12-381: the pairing-friendly elliptic curve behind BLS signatures,
KZG polynomial commitments, and threshold-BLS schemes — the base field
`Fp`, the extension tower `Fp2`/`Fp6`/`Fp12`, the scalar field `Fr`, and
the two pairing groups `G1`/`G2`.

**Status: Part 1 complete.** Full field-tower and group arithmetic,
every curve/field constant independently verified (see `NOTICE` —
including a G2-cofactor scaffold bug found and fixed during the
crypto-core pass), constant-time scalar multiplication and branchless
point addition, and 94 tests green in Debug AND ReleaseFast — see
`SPEC.md` for the design record. The pairing itself is Part 2.

## The multi-part arc

This module is planned across several parts; only Part 1 exists so far.

| Part | Scope | Status |
|---|---|---|
| 1 | Field tower (`Fp`/`Fp2`/`Fp6`/`Fp12`) + groups (`G1`/`G2`) | **done (this)** |
| 2 | The pairing itself: Miller loop + final exponentiation | not started |
| 3 | Hash-to-curve (RFC 9380, for hashing messages onto `G1`/`G2`) | not started |
| 4 | BLS signatures (RFC 9380's BLS ciphersuites / the IETF BLS draft) | not started |
| 5 | KZG polynomial commitments | not started |
| 6 | Threshold BLS (Shamir/FROST-style share aggregation) | not started |

## Import

```zig
const bls12_381 = @import("bls12_381");
```

## API sketch

```zig
// Base field, scalar field:
const a = try bls12_381.Fp.fromBytes(bytes_48);
const s = try bls12_381.Fr.fromBytes(bytes_32);

// Extension tower:
const x: bls12_381.Fp2 = .{ .c0 = a, .c1 = bls12_381.Fp.zero };
const y: bls12_381.Fp6 = .{ .c0 = x, .c1 = bls12_381.Fp2.zero, .c2 = bls12_381.Fp2.zero };
const z: bls12_381.Fp12 = .{ .c0 = y, .c1 = bls12_381.Fp6.zero };

// Groups:
const g1_gen = bls12_381.G1.Affine.generator;
const g2_gen = bls12_381.G2.Affine.generator;

const p = bls12_381.G1.Jacobian.fromAffine(g1_gen);
const compressed = bls12_381.G1.toBytesCompressed(g1_gen); // 48 bytes
const parsed = try bls12_381.G1.fromBytesCompressed(compressed); // 48 bytes -> Affine

// Arithmetic:
const sum = a.add(a);                    // field ops: add/sub/neg/mul/square/inv/pow/sqrt
const doubled = p.double();              // point ops: add/double/negate/scalarMul/toAffine
const pk = p.scalarMul(s);               // constant-time (secret-scalar-safe)
const ok = pk.subgroupCheck();           // REQUIRED for untrusted points (see SPEC.md)
```

Deserialization (`fromBytesCompressed`/`fromBytesUncompressed`) checks
the curve equation but deliberately NOT subgroup membership — callers
crossing a trust boundary MUST also call `subgroupCheck` (the classic
BLS pitfall; see `SPEC.md`'s threat model).

## File layout

| File | Contents |
|---|---|
| `fp.zig` | Base field `Fp` (mod `p`), built on `std.crypto.ff.Modulus(384)` |
| `fp2.zig` | `Fp2 = Fp[u]/(u²+1)` |
| `fp6.zig` | `Fp6 = Fp2[v]/(v³−(u+1))` |
| `fp12.zig` | `Fp12 = Fp6[w]/(w²−v)` — the pairing's target field |
| `scalar.zig` | Scalar field `Fr` (mod `r`, the group order), built on `std.crypto.ff.Modulus(256)` |
| `g1.zig` | `G1`: the order-`r` subgroup of `E(Fp): y²=x³+4` |
| `g2.zig` | `G2`: the order-`r` subgroup of the sextic twist `E'(Fp2): y²=x³+4(1+u)` |
| `root.zig` | Module entry: `meta`, re-exports, dark-tests aggregator |

## Verify

```
zig build test-bls12_381                        # Debug — 94/94 pass
zig build test-bls12_381 -Doptimize=ReleaseFast # ReleaseFast — 94/94 pass
zig fmt --check modules/bls12_381/
```

Provenance: see [NOTICE](NOTICE). Design record: see [SPEC.md](SPEC.md).
