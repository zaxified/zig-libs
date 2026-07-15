# bn254

BN254 (alt-bn128): the pairing-friendly elliptic curve behind
Ethereum's EIP-196/197 precompiles (`ecAdd`/`ecMul`/`ecPairing`,
addresses `0x06`/`0x07`/`0x08`) and Groth16 zk-SNARK verification —
this module is **Parts 1-2** of a planned multi-part arc: the base
field `Fp`, the extension tower `Fp2`/`Fp6`/`Fp12`, and the scalar
field `Fr`.

**Status: Parts 1-2 complete.** Full field-tower arithmetic
(`add`/`sub`/`neg`/`mul`/`square`/`inv`/`pow`/`sqrt`/Frobenius at every
tower level), every field/curve constant independently verified (see
`SPEC.md`), byte-exact KAT coverage against independently-computed
reference vectors, 65/65 tests pass in Debug AND ReleaseFast. NO group
arithmetic (`G1`/`G2`), NO pairing, NO precompile wiring yet — those
are later parts.

This module was built by careful, verified ADAPTATION of the sibling
[`bls12_381`](../bls12_381) module: same `std.crypto.ff`-backed
`Fp`/`Fr` construction, same tower-arithmetic formula shapes (they are
generic in the field's non-residue, so they carry over unchanged), with
BN254's own modulus/non-residue/generator constants substituted in and
independently re-verified from scratch — see `SPEC.md`.

## The multi-part arc

| Part | Scope | Status |
|---|---|---|
| 1-2 | Field tower (`Fp`/`Fp2`/`Fp6`/`Fp12`) + scalar field `Fr` | **done** |
| 3 | Groups `G1`/`G2` | planned |
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
```

Deliberately absent vs. `bls12_381`: `isLexicographicallyLargest` (a
compressed-point "sign of y" helper) — Ethereum's EIP-196/197 encodes
`G1`/`G2` points UNCOMPRESSED, so no consumer for that helper exists in
this arc; see `SPEC.md`.

## File layout

| File | Contents |
|---|---|
| `fp.zig` | Base field `Fp` (mod `p`), built on `std.crypto.ff.Modulus(256)` |
| `fp2.zig` | `Fp2 = Fp[u]/(u²+1)` |
| `fp6.zig` | `Fp6 = Fp2[v]/(v³−ξ)`, `ξ = 9+u` (differs from `bls12_381`'s `u+1`) |
| `fp12.zig` | `Fp12 = Fp6[w]/(w²−v)` — the future pairing's target field |
| `scalar.zig` | Scalar field `Fr` (mod `r`, the group order), built on `std.crypto.ff.Modulus(256)` |
| `root.zig` | Module entry: `meta`, re-exports, dark-tests aggregator |

## Verify

```
zig build test-bn254                        # Debug — 65/65 pass
zig build test-bn254 -Doptimize=ReleaseFast # ReleaseFast — 65/65 pass
zig fmt --check modules/bn254/
```

Design record + cited sources: see [SPEC.md](SPEC.md). No `NOTICE`
entry — BN254's parameters come from a public spec (EIP-196/197) and
mathematical constants, not third-party source (see `SPEC.md`'s
"Model-after + seed").
