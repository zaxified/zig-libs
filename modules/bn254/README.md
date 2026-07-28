# bn254

BN254 (alt-bn128): the pairing-friendly elliptic curve behind
Ethereum's EIP-196/197 precompiles (`ecAdd`/`ecMul`/`ecPairing`,
addresses `0x06`/`0x07`/`0x08`) and Groth16 zk-SNARK verification —
this module is the **complete 6-part arc**: the base
field `Fp`, the extension tower `Fp2`/`Fp6`/`Fp12`, the scalar field
`Fr`, the pairing groups `G1`/`G2`, the optimal-ate pairing itself, the
EVM precompile entry points themselves, and a Groth16 zk-SNARK verifier.

**Status: all 6 parts complete.** Full field-tower arithmetic (`add`/
`sub`/`neg`/`mul`/`square`/`inv`/`pow`/`sqrt`/Frobenius at every tower
level) plus `G1`/`G2` Jacobian group arithmetic (`add`/`double`/
`negate`/constant-time `scalarMul`), on-curve and subgroup-membership
checks, and EIP-196/197 (de)serialization (Parts 1-3), the optimal-ate
pairing itself (Part 4): `Gt`/`PairingPair`, the `6x+2` loop parameter,
the `millerLoop` core (its `6x+2` walk with the BN-specific Frobenius
tail) and `finalExponentiation` core (curve-generic easy part + the
BN-specific exact-`d` hard-part addition chain), and `pairing`/
`multiMillerLoop`/`pairingCheck` — all real and tested, byte-exact
against `ethereum/py_ecc`; the EVM precompile entry points
themselves (Part 5): `ecAdd`/`ecMul`/`ecPairing` (`0x06`/`0x07`/`0x08`)
— pure ABI composition over Parts 1-4, byte-exact against the OFFICIAL
`ethereum/go-ethereum` `core/vm/testdata/precompiles/*.json`
conformance vectors; and now a Groth16 zk-SNARK proof VERIFIER (Part 6,
`groth16.zig`): `VerifyingKey`/`Proof`/`verify` — pure composition over
Parts 1-4 (a `G1` multi-scalar accumulation plus one `pairingCheck`),
verified against a REAL, independently-sourced snarkjs-produced
Groth16/BN254 proof (darkforest-v0.3's "move" circuit) — the real proof
verifies TRUE, six independent tamper cases each verify FALSE. Every
field/curve constant independently verified (see `SPEC.md`), byte-exact
KAT coverage against independently-computed AND (Parts 5-6)
independently-SOURCED reference vectors, all passing in Debug AND
ReleaseFast.

This module was built by careful, verified ADAPTATION of the sibling
[`bls12_381`](../bls12_381) module: same `std.crypto.ff`-backed
`Fp`/`Fr` construction, same tower-arithmetic formula shapes, the same
Jacobian point-arithmetic formulas (all generic in the field's
non-residue / the curve's `b` constant, so they carry over unchanged),
and the same pairing STRUCTURE (`bls12_381/src/pairing.zig`),
with BN254's own modulus/non-residue/generator constants — and, for
Part 4, its own `6x+2` loop parameter and BN-specific final-exponentiation
hard part — substituted in and independently re-verified from scratch —
see `SPEC.md`. Parts 5-6 (`precompiles.zig`, `groth16.zig`) are pure
composition on top — no new field/curve/pairing algorithm, see
`SPEC.md`'s "Part 5"/"Part 6" sections for the tier accounting.

## The multi-part arc

| Part | Scope | Status |
|---|---|---|
| 1-2 | Field tower (`Fp`/`Fp2`/`Fp6`/`Fp12`) + scalar field `Fr` | **done** |
| 3 | Groups `G1`/`G2` | **done** |
| 4 | The pairing itself: Miller loop + final exponentiation | **done** |
| 5 | EIP-196/197 precompile semantics (`ecAdd`/`ecMul`/`ecPairing`) | **done** |
| 6 | Groth16 zk-SNARK verifier | **done** |

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

// Pairing (Part 4 — the optimal-ate pairing e: G1 x G2 -> Gt):
const e = bn254.pairing.pairing(bn254.G1.Affine.generator, bn254.G2.Affine.generator);
try std.testing.expect(!e.eql(bn254.Fp12.one)); // non-degenerate

// EVM precompiles (Part 5 — EIP-196/197 calldata in, calldata out):
const sum_bytes = try bn254.ecAdd(add_calldata);              // 0x06, 64 bytes out
const prod_bytes = try bn254.ecMul(mul_calldata);              // 0x07, 64 bytes out
const ok = try bn254.ecPairing(allocator, pairing_calldata);   // 0x08, 32-byte ABI bool

// Groth16 verifier (Part 6 — e.g. from a snarkjs verification_key.json/
// proof.json; public inputs are Fr, so an out-of-field value is rejected
// at Fr.fromBytes, before it could ever reach verify):
const vk: bn254.Groth16VerifyingKey = .{
    .alpha_g1 = alpha, .beta_g2 = beta, .gamma_g2 = gamma, .delta_g2 = delta, .ic = &ic,
};
const proof: bn254.Groth16Proof = .{ .a = a, .b = b, .c = c };
const valid = try bn254.groth16Verify(vk, proof, public_inputs); // bool
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
| `gate.zig` | Part 4 test gate — `pairing_core_implemented` (now `true`, the cores landed); documents the scaffold-era split between core-independent and core-driven tests |
| `pairing.zig` | Part 4: `Gt`/`PairingPair`, the pairing (`pairing`/`multiMillerLoop`/`pairingCheck`), and the `millerLoop` (`6x+2` walk + BN Frobenius tail) / `finalExponentiation` (easy + BN hard-part) cores |
| `precompiles.zig` | Part 5: EVM precompile entry points `ecAdd`/`ecMul`/`ecPairing` (EIP-196/197 calldata padding/truncation, point decode, group op, re-encode) — pure composition over Parts 1-4 |
| `groth16.zig` | Part 6: Groth16 zk-SNARK verifier — `VerifyingKey`/`Proof`/`verify` (`G1` multi-scalar accumulation + one `pairingCheck`) — pure composition over Parts 1-4 |
| `root.zig` | Module entry: `meta`, re-exports, dark-tests aggregator |

## Verify

```
zig build test-bn254                        # Debug
zig build test-bn254 -Doptimize=ReleaseFast # ReleaseFast
zig fmt --check modules/bn254/
```

Design record + cited sources: see [SPEC.md](SPEC.md). Parts 1-3 needed
no `NOTICE` entry (public spec + mathematical constants only). Part 4
added one — [NOTICE](NOTICE) — covering `ethereum/py_ecc`'s use as a
numeric KAT oracle and the basis-conversion methodology (see `SPEC.md`'s
"Part 4 — KAT generation"). Part 5 extends the same `NOTICE` with a
5th entry for `ethereum/go-ethereum`'s precompile test-vector JSON
files: EIP-196/197 conformance DATA (public-standard input/output
vectors, not copyrightable expression under merger doctrine — the same
category Parts 1-4's `py_ecc`-sourced constants already fall into),
listed out of caution since the vectors are literal fetched file
contents rather than independently-recomputed values; no go-ethereum
SOURCE was read or ported. Part 6 extends `NOTICE` with a 6th entry for
`darkforest-eth/darkforest-v0.3`'s "move"-circuit Groth16 proof (the
positive KAT vector) — same "public numeric conformance data" category,
plus `py_ecc` again (2nd use) as an independent cross-check of the
verification equation's sign convention; see `SPEC.md`'s "Part 6 — KAT
provenance".
