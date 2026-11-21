# bls12_381

BLS12-381: the pairing-friendly elliptic curve behind BLS signatures,
KZG polynomial commitments, and threshold-BLS schemes — the base field
`Fp`, the extension tower `Fp2`/`Fp6`/`Fp12`, the scalar field `Fr`, the
two pairing groups `G1`/`G2`, and the pairing `e: G1 x G2 -> Gt`.

The module is built in six parts, all in this package:

1. **Field tower and groups** (`fp.zig`, `fp2.zig`, `fp6.zig`, `fp12.zig`, `scalar.zig`, `g1.zig`,
   `g2.zig`): every field and group operation, constant-time scalar multiplication and branchless
   complete point addition; every curve and field constant independently verified (see `NOTICE`).
2. **The pairing** (`pairing.zig`): the optimal ate Miller loop (Jacobian D-type-twist line
   evaluation, batched allocation-free multi-pairing) and the full final exponentiation (easy part
   plus the Hayashida-Hayasaka-Teruya exact hard-part chain), byte-exact against the IETF
   pairing-friendly-curves draft's `e(G1,G2)` vector with a py_ecc cross-check.
3. **Hash-to-curve** (`hash_to_curve.zig`): RFC 9380 for `G1`/`G2` (suites
   `BLS12381G{1,2}_XMD:SHA-256_SSWU_RO_`/`_NU_`, plus the `G1` SHAKE-256 suite): the full
   `expand_message_xmd` -> `hash_to_field` -> Simplified-SWU-plus-isogeny -> `h_eff` clear-cofactor
   chain, byte-exact against RFC 9380's own vectors at every published stage; the isogeny tables
   were parsed from the RFC text and checked by an independent implementation (see `NOTICE`).
4. **BLS signatures** (`bls_sig.zig`, `scheme.zig`): draft-irtf-cfrg-bls-signature-05, **all six
   ciphersuites** — `bls_sig.Bls(variant, scheme)` for min-pk / min-sig times Basic /
   MessageAugmentation / ProofOfPossession (`bls_sig.MinPkPop`, `MinSigBasic`, ...; the file-level
   `bls_sig.sign`/`verify`/... are `MinPkPop`, Ethereum's suite): `keyGen`/`keyGenV4`/`skToPk`/
   `keyValidate`, `sign`/`verify`, aggregation with `aggregateVerify` (and, for POP,
   `fastAggregateVerify` and `popProve`/`popVerify`), and `verifyBatch` (random-linear-combination
   batch verification of independent signatures). Byte-exact against `ethereum/bls12-381-tests`
   v0.1.2 and, for all six suites and both key generations, against supranational/blst run as a
   black box; live drand beacons verify under both Basic layouts. The mandatory subgroup and
   `KeyValidate` checks are fail-closed at every verify entry point. `eip2333.zig` derives Ethereum
   validator keys (`deriveMasterSk`/`deriveChildSk`/`derivePath`, EIP-2334 paths), checked against
   the EIP's vectors and blst; `msm.zig` is Pippenger multi-scalar multiplication for `G1` and `G2`
   (public data only).
5. **KZG** (`kzg.zig`): EIP-4844 (deneb) polynomial commitments. The trusted-setup loader parses
   and validates the embedded official Ethereum KZG ceremony `trusted_setup.txt` (on-curve and
   subgroup check of all 8257 points, once per process, memoized); blob <-> polynomial
   (de)serialization with canonical-field-element enforcement; `blobToKzgCommitment`,
   `computeKzgProof`/`verifyKzgProof`, `computeBlobKzgProof`/`verifyBlobKzgProof`/
   `verifyBlobKzgProofBatch`; reusable `Fr` FFT/inverse-FFT and `G1` multi-scalar multiplication.
   Byte-exact against `ethereum/c-kzg-4844`'s KAT vectors for every public function.
6. **Threshold BLS** (`threshold.zig`): trusted-dealer Shamir secret sharing + Feldman verifiable
   secret sharing + Lagrange-interpolation-in-the-exponent combining, generic over the suite
   (`Threshold(variant, scheme)`; min-pk and min-sig, Basic and POP; the file-level names are the
   min-pk POP instance `MinPk`). A partial signature IS a `sign` call under a Shamir share; a combined
   signature IS an ordinary signature, byte-for-byte equal to `sign(&sk, msg)` and verified with the
   ordinary `verify`, which pins the threshold path to the signature vectors.

See `SPEC.md` for the design record (including the constant-time breakdown for the secret paths).

**Deps:** `entropy` (batch-verify randomness, key material), `montint` (constant-time `Fr` arithmetic); no third-party code.

## Not provided

EIP-7594 (PeerDAS) cell proofs, distributed key generation (threshold is trusted-dealer only),
threshold shares under the MessageAugmentation suites, and constant-time pairing, hash-to-curve or
KZG (they take public data only). See `SPEC.md` *What is deliberately not done* and *Backlog /
deferred*.


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
p.scalarMulInto(&out, &s);               // same, scalar by pointer, burned frame (secret scalar)
const ok = pk.subgroupCheck();           // decoders do this; REQUIRED for points built otherwise

// The pairing (Part 2 — subgroup inputs required, see SPEC.md):
const gt = bls12_381.pairing.pairing(g1_gen, g2_gen); // e(G1, G2) ∈ Gt (== Fp12)
const gt_r = gt.pow(&r);                 // Gt^r, constant-time in the secret exponent r
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

// Threshold BLS (Part 6 — trusted-dealer; file-level names = min-pk POP):
const threshold = bls12_381.threshold;
const split = try threshold.splitSecretKey(allocator, &sk, 3, 5, coeffs); // t=3-of-5, coeffs.len == t-1
defer allocator.free(split.shares);
defer allocator.free(split.vvec.commitments);
const partial1 = threshold.partialSign(&split.shares[0], "message"); // thin over bls_sig.sign
const ok8 = threshold.verifyPartialSignature(threshold.derivePublicKeyShare(split.vvec, 1), "message", partial1);
const combined = try threshold.combineSignatures(&.{ partial1, partial2, partial3 }, 3); // == bls.sign(sk, "message")
const ok9 = bls.verify(threshold.groupPublicKey(split.vvec), "message", combined); // ordinary bls_sig.verify
// min-sig (keys/commitments in G2, signatures in G1): the same API on threshold.MinSig;
// threshold.Threshold(.min_sig, .basic) is drand quicknet's suite.
const ms_split = try threshold.MinSig.splitSecretKey(allocator, &sk, 3, 5, coeffs);
const ms_partial = threshold.MinSig.partialSign(&ms_split.shares[0], "message"); // == bls.MinSigPop.sign under the share
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
| `fp.zig` | Base field `Fp` (mod `p`): own constant-time Montgomery backend (six `u64` limbs; `std.crypto.ff` only as a comptime constant and test oracle) |
| `fp2.zig` | `Fp2 = Fp[u]/(u²+1)` |
| `fp6.zig` | `Fp6 = Fp2[v]/(v³−(u+1))` |
| `fp12.zig` | `Fp12 = Fp6[w]/(w²−v)` — the pairing's target field |
| `scalar.zig` | Scalar field `Fr` (mod `r`, the group order), `montint.Field(r)` |
| `g1.zig` | `G1`: the order-`r` subgroup of `E(Fp): y²=x³+4` |
| `g2.zig` | `G2`: the order-`r` subgroup of the sextic twist `E'(Fp2): y²=x³+4(1+u)` |
| `pairing.zig` | Part 2: `e: G1 x G2 -> Gt`, the optimal ate Miller loop + final exponentiation |
| `hash_to_curve.zig` | Part 3: RFC 9380 hash-to-curve — `expandMessageXmd`, `hashToFieldFp`/`hashToFieldFp2`, Simplified SWU + 11-/3-isogeny maps, `hashToCurveG1`/`G2` + `encodeToCurveG1`/`G2` |
| `bls_sig.zig` | Part 4: BLS signatures — `keyGen`/`skToPk`/`keyValidate`, `sign`/`verify`, `aggregate`/`aggregatePublicKeys`, `coreAggregateVerify`/`aggregateVerify`/`fastAggregateVerify`, `popProve`/`popVerify` |
| `scheme.zig` | Part 4: the generic `Bls(variant, scheme)` ciphersuite behind `bls_sig` (min-pk / min-sig x Basic / MessageAugmentation / ProofOfPossession) |
| `eip2333.zig` | EIP-2333/2334 Ethereum validator key derivation (`deriveMasterSk`/`deriveChildSk`/`derivePath`) |
| `msm.zig` | Pippenger multi-scalar multiplication for `G1`/`G2` (public data only) |
| `kzg.zig` | Part 5: EIP-4844 KZG — `loadTrustedSetup` (memoized), `blobToKzgCommitment`/`computeKzgProof`/`verifyKzgProof`/`computeBlobKzgProof`/`verifyBlobKzgProof`/`verifyBlobKzgProofBatch`, plus `fft`/`ifft` and `g1Msm` primitives |
| `src/data/trusted_setup.txt` | The embedded official Ethereum KZG ceremony trusted setup (`@embedFile`d by `kzg.zig`) |
| `src/data/kzg_test_vectors/` | Two embedded `c-kzg-4844` KAT blobs (constant-2 + random #4; see `NOTICE`) |
| `threshold.zig` | Part 6: trusted-dealer threshold BLS, `Threshold(variant, scheme)` (min-pk/min-sig × Basic/POP; file-level names = `MinPk`) — `splitSecretKey`/`groupPublicKey`/`derivePublicKeyShare` (Shamir+Feldman VSS), `partialSign`/`verifyPartialSignature` (thin over `bls_sig`), `combineSignatures` (Lagrange-in-the-exponent) |
| `root.zig` | Module entry: `meta`, re-exports, dark-tests aggregator |
| `burn.zig` | Dead-stack burn for every entry point that holds a secret (probe: `stackprobe_test.zig`) |
| `blst_vectors.zig`, `blst_interop_test.zig` | supranational/blst black-box vectors (produced by `tools/blst-vectors`) and the test that checks all six suites against them |
| `fuzz_test.zig`, `stackprobe_test.zig`, `ctgrind_harness.zig` | Fuzz driver (`BLS12_381_FUZZ`), dead-stack probe, ctgrind harness |

## Verify

```
scripts/modtest bls12_381                        # the module's tests
zig build test-bls12_381                        # Debug (slow: the KZG KATs dominate, several minutes)
zig build test-bls12_381 -Doptimize=ReleaseFast # ReleaseFast (~1 min)
zig fmt --check modules/bls12_381/
```

Provenance: see [NOTICE](NOTICE). Design record: see [SPEC.md](SPEC.md).
