# bls12_381

BLS12-381: the pairing-friendly elliptic curve behind BLS signatures,
KZG polynomial commitments, and threshold-BLS schemes — the base field
`Fp`, the extension tower `Fp2`/`Fp6`/`Fp12`, the scalar field `Fr`, the
two pairing groups `G1`/`G2`, and the pairing `e: G1 x G2 -> Gt`.

**Status: Parts 1, 2 AND 3 complete.** Part 1's full field-tower and
group arithmetic, every curve/field constant independently verified
(see `NOTICE` — including a G2-cofactor scaffold bug found and fixed
during the crypto-core pass), constant-time scalar multiplication and
branchless point addition. Part 2 (`pairing.zig`) is the real pairing:
the optimal ate Miller loop (D-type-twist line evaluation, batched
allocation-free multi-pairing) and the full final exponentiation (easy
part + the Hayashida-Hayasaka-Teruya exact hard-part chain), verified
by a full bilinearity property suite PLUS a byte-exact `e(G1,G2)` KAT
against the IETF pairing-friendly-curves draft's official test vector
(with a py_ecc cross-check). Part 3 (`hash_to_curve.zig`) is RFC 9380
hash-to-curve for `G1`/`G2` (suites
`BLS12381G{1,2}_XMD:SHA-256_SSWU_RO_`/`_NU_`): the full
`expand_message_xmd` → `hash_to_field` → Simplified-SWU-plus-isogeny →
`h_eff` clear-cofactor chain, byte-exact against RFC 9380's own
vectors at every published stage (Appendix K.1; J.9.1/J.10.1 `u`,
`Q0`/`Q1`, final `P` — all 5 messages each), with the isogeny
coefficient tables sourced programmatically from the RFC's raw text
and verified by an independent implementation (see `NOTICE`).
128/128 tests green in Debug AND ReleaseFast — see `SPEC.md` for the
design record.

## The multi-part arc

This module is planned across several parts.

| Part | Scope | Status |
|---|---|---|
| 1 | Field tower (`Fp`/`Fp2`/`Fp6`/`Fp12`) + groups (`G1`/`G2`) | **done** |
| 2 | The pairing itself: Miller loop + final exponentiation | **done** |
| 3 | Hash-to-curve (RFC 9380, for hashing messages onto `G1`/`G2`) | **done** |
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

// The pairing (Part 2 — subgroup inputs required, see SPEC.md):
const gt = bls12_381.pairing.pairing(g1_gen, g2_gen); // e(G1, G2) ∈ Gt (== Fp12)
const ok2 = bls12_381.pairing.pairingCheck(&.{
    .{ .p = g1_gen, .q = g2_gen },
    // ... more (P, Q) pairs — one shared Miller loop + one final
    // exponentiation over the whole product, the shape BLS aggregate
    // verification / KZG batch openings need.
});

// Hash-to-curve (Part 3 — RFC 9380; output is always on-curve AND in
// the r-subgroup, no extra subgroupCheck needed):
const dst = "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_"; // caller-chosen, per RFC 9380 §3.1
const h1 = bls12_381.hash_to_curve.hashToCurveG1("message", dst); // G1.Affine
const h2 = bls12_381.hash_to_curve.hashToCurveG2("message", dst); // G2.Affine (a G2 suite DST in practice)
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
| `pairing.zig` | Part 2: `e: G1 x G2 -> Gt`, the optimal ate Miller loop + final exponentiation |
| `hash_to_curve.zig` | Part 3: RFC 9380 hash-to-curve — `expandMessageXmd`, `hashToFieldFp`/`hashToFieldFp2`, Simplified SWU + 11-/3-isogeny maps, `hashToCurveG1`/`G2` + `encodeToCurveG1`/`G2` |
| `root.zig` | Module entry: `meta`, re-exports, dark-tests aggregator |

## Verify

```
zig build test-bls12_381                        # Debug — 128/128 pass
zig build test-bls12_381 -Doptimize=ReleaseFast # ReleaseFast — same
zig fmt --check modules/bls12_381/
```

Provenance: see [NOTICE](NOTICE). Design record: see [SPEC.md](SPEC.md).
