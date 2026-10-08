# bls12_381

BLS12-381: the pairing-friendly elliptic curve behind BLS signatures,
KZG polynomial commitments, and threshold-BLS schemes — the base field
`Fp`, the extension tower `Fp2`/`Fp6`/`Fp12`, the scalar field `Fr`, the
two pairing groups `G1`/`G2`, and the pairing `e: G1 x G2 -> Gt`.

**Status: Parts 1-5 complete.** Part 1's full
field-tower and group arithmetic, every curve/field constant
independently verified (see `NOTICE` — including a G2-cofactor
scaffold bug found and fixed during the crypto-core pass),
constant-time scalar multiplication and branchless point addition.
Part 2 (`pairing.zig`) is the real pairing: the optimal ate Miller loop
(D-type-twist line evaluation, batched allocation-free multi-pairing)
and the full final exponentiation (easy part + the
Hayashida-Hayasaka-Teruya exact hard-part chain), verified by a full
bilinearity property suite PLUS a byte-exact `e(G1,G2)` KAT against the
IETF pairing-friendly-curves draft's official test vector (with a
py_ecc cross-check). Part 3 (`hash_to_curve.zig`) is RFC 9380
hash-to-curve for `G1`/`G2` (suites
`BLS12381G{1,2}_XMD:SHA-256_SSWU_RO_`/`_NU_`): the full
`expand_message_xmd` → `hash_to_field` → Simplified-SWU-plus-isogeny →
`h_eff` clear-cofactor chain, byte-exact against RFC 9380's own
vectors at every published stage (Appendix K.1; J.9.1/J.10.1 `u`,
`Q0`/`Q1`, final `P` — all 5 messages each), with the isogeny
coefficient tables sourced programmatically from the RFC's raw text
and verified by an independent implementation (see `NOTICE`). Part 4
(`bls_sig.zig`, `scheme.zig`) is BLS signatures per
draft-irtf-cfrg-bls-signature-05, **all six ciphersuites**:
`bls_sig.Bls(variant, scheme)` for min-pk / min-sig times Basic /
MessageAugmentation / ProofOfPossession (`bls_sig.MinPkPop`, `MinSigBasic`,
… — the file-level `bls_sig.sign`/`verify`/… are `MinPkPop`, Ethereum's
suite) — `keyGen`/`skToPk`/`keyValidate`, `sign`/`verify`,
signature/pubkey aggregation with `aggregateVerify` (and, for POP,
`fastAggregateVerify` and `popProve`/`popVerify`), and `verifyBatch`
(random-linear-combination batch verification of independent
signatures). Byte-exact against `ethereum/bls12-381-tests` v0.1.2 and,
for all six suites and `keyGen`, against supranational/blst run as a
black box; live drand beacons verify under both Basic layouts. The
mandatory subgroup/`KeyValidate` checks are fail-closed at every verify
entry point. `eip2333.zig` derives Ethereum validator keys
(`deriveMasterSk`/`deriveChildSk`/`derivePath`, EIP-2334 paths), checked
against the EIP's vectors and blst; `msm.zig` is Pippenger
multi-scalar multiplication for `G1` and `G2` (public data only). Part 5 (`kzg.zig`) is EIP-4844
(deneb) KZG polynomial commitments: the trusted-setup loader (parses
and validates the embedded official Ethereum KZG ceremony
`trusted_setup.txt`, on-curve + subgroup-checking all 8257 points —
once per process, memoized), blob<->polynomial (de)serialization with
canonical-field-element enforcement, `blobToKzgCommitment`,
`computeKzgProof`/`verifyKzgProof`, `computeBlobKzgProof`/
`verifyBlobKzgProof`/`verifyBlobKzgProofBatch`, plus reusable `Fr`
FFT/inverse-FFT and Pippenger `G1` multi-scalar-multiplication
primitives — byte-exact against `ethereum/c-kzg-4844`'s official KAT
vectors across every public function (see `kzg.zig`'s module doc
comment and `SPEC.md`). Parts 1-6: all pass, no panics, in
Debug AND ReleaseFast (see `SPEC.md` for the design record).

**Part 6 (`threshold.zig`) is COMPLETE.** Trusted-dealer threshold BLS
— Shamir secret sharing + Feldman verifiable secret sharing (VSS) +
Lagrange-interpolation-in-the-exponent combining — built entirely on
Part 4's min-pk ciphersuite (a partial signature IS a `bls_sig.sign`
call under a Shamir share; a combined signature IS an ordinary
`bls_sig.Signature`, byte-for-byte equal to `bls_sig.sign(&sk, msg)` and
verified with the ordinary `bls_sig.verify` — which transitively pins
the threshold path to Part 4's `ethereum/bls12-381-tests` vectors). See
`threshold.zig`'s own module doc comment and `SPEC.md`'s "Part 6
design" (including the const-time breakdown for the secret paths).

## The multi-part arc

This module is planned across several parts.

| Part | Scope | Status |
|---|---|---|
| 1 | Field tower (`Fp`/`Fp2`/`Fp6`/`Fp12`) + groups (`G1`/`G2`) | **done** |
| 2 | The pairing itself: Miller loop + final exponentiation | **done** |
| 3 | Hash-to-curve (RFC 9380, for hashing messages onto `G1`/`G2`) | **done** |
| 4 | BLS signatures (draft-irtf-cfrg-bls-signature-05, min-pk/ProofOfPossession) | **done** |
| 5 | KZG polynomial commitments (EIP-4844 / deneb) | **done** |
| 6 | Threshold BLS (trusted-dealer Shamir + Feldman VSS + Lagrange combine) | **done** |

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
const ok = pk.subgroupCheck();           // decoders do this; REQUIRED for points built otherwise

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

// BLS signatures (Part 4 — min-pk/ProofOfPossession ciphersuite):
const bls = bls12_381.bls_sig;
var sk: bls.SecretKey = undefined;           // a secret: written in place, passed by pointer
try bls.keyGen(&sk, "at least 32 bytes of IKM go here......", "");
defer sk.deinit();
const pk = bls.skToPk(&sk);
const ok = bls.keyValidate(pk);               // REQUIRED on any external pk
const sig = bls.sign(&sk, "message");         // constant-time in sk
const valid = bls.verify(pk, "message", sig); // fail-closed subgroup/KeyValidate checks
const agg = try bls.aggregate(&.{ sig, sig2 });
const ok3 = try bls.aggregateVerify(&.{ pk, pk2 }, &.{ "message", "msg2" }, agg);
const proof = bls.popProve(&sk);              // proof of possession (registration time)
const ok4 = bls.popVerify(pk, proof);

// KZG polynomial commitments (Part 5 — EIP-4844/deneb):
const kzg = bls12_381.kzg;
var setup = try kzg.loadTrustedSetup(allocator); // embedded ceremony; validated once per process, memoized
defer setup.deinit(allocator);
const commitment = try kzg.blobToKzgCommitment(allocator, &blob, &setup);
const result = try kzg.computeKzgProof(allocator, &blob, z_bytes, &setup); // .proof + .y
const ok5 = try kzg.verifyKzgProof(commitment, z_bytes, result.y, result.proof, &setup);
const blob_proof = try kzg.computeBlobKzgProof(allocator, &blob, commitment, &setup);
const ok6 = try kzg.verifyBlobKzgProof(allocator, &blob, commitment, blob_proof, &setup);
const ok7 = try kzg.verifyBlobKzgProofBatch(allocator, &blobs, &commitments, &proofs, &setup);

// Threshold BLS (Part 6 — trusted-dealer, min-pk):
const threshold = bls12_381.threshold;
const split = try threshold.splitSecretKey(allocator, sk, 3, 5, coeffs); // t=3-of-5, coeffs.len == t-1
defer allocator.free(split.shares);
defer allocator.free(split.vvec.commitments);
const partial1 = threshold.partialSign(split.shares[0], "message"); // thin over bls_sig.sign
const ok8 = threshold.verifyPartialSignature(threshold.derivePublicKeyShare(split.vvec, 1), "message", partial1);
const combined = try threshold.combineSignatures(&.{ partial1, partial2, partial3 }, 3); // == bls.sign(sk, "message")
const ok9 = bls.verify(threshold.groupPublicKey(split.vvec), "message", combined); // ordinary bls_sig.verify
```

Deserialization (`fromBytesCompressed`/`fromBytesUncompressed`) checks
the curve equation AND subgroup membership (`error.NotInSubgroup`) — the
classic BLS pitfall closed at the boundary (see `SPEC.md`'s threat
model). `fromBytes*Unchecked` skip the subgroup check, for bytes the
caller already trusts only. A point built some other way still needs
`subgroupCheck` before it meets a pairing.

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
| `bls_sig.zig` | Part 4: BLS signatures — `keyGen`/`skToPk`/`keyValidate`, `sign`/`verify`, `aggregate`/`aggregatePublicKeys`, `coreAggregateVerify`/`aggregateVerify`/`fastAggregateVerify`, `popProve`/`popVerify` |
| `kzg.zig` | Part 5: EIP-4844 KZG — `loadTrustedSetup` (memoized), `blobToKzgCommitment`/`computeKzgProof`/`verifyKzgProof`/`computeBlobKzgProof`/`verifyBlobKzgProof`/`verifyBlobKzgProofBatch`, plus `fft`/`ifft` and `g1Msm` primitives |
| `src/data/trusted_setup.txt` | The embedded official Ethereum KZG ceremony trusted setup (`@embedFile`d by `kzg.zig`) |
| `src/data/kzg_test_vectors/` | Two embedded `c-kzg-4844` KAT blobs (constant-2 + random #4; see `NOTICE`) |
| `threshold.zig` | Part 6: trusted-dealer threshold BLS — `splitSecretKey`/`groupPublicKey`/`derivePublicKeyShare` (Shamir+Feldman VSS), `partialSign`/`verifyPartialSignature` (thin over `bls_sig`), `combineSignatures` (Lagrange-in-the-exponent) |
| `root.zig` | Module entry: `meta`, re-exports, dark-tests aggregator |

## Verify

```
zig build test-bls12_381                        # Debug (slow: the KZG KATs dominate, several minutes)
zig build test-bls12_381 -Doptimize=ReleaseFast # ReleaseFast (~1 min)
zig fmt --check modules/bls12_381/
```

Provenance: see [NOTICE](NOTICE). Design record: see [SPEC.md](SPEC.md).
