# frost

FROST (Flexible Round-Optimized Schnorr Threshold signatures), RFC 9591,
**secp256k1/SHA-256 ciphersuite (§6.5) only**: a t-of-n threshold Schnorr
signing protocol — any `MIN_PARTICIPANTS`-sized subset of
`MAX_PARTICIPANTS` signers can jointly produce a single two-round
aggregate signature `(R, z)` verifiable under one group public key, with
no interaction needed from signers outside that subset.

Wire codecs, RFC §4.3 list operations, the five ciphersuite hash functions
(`h1`..`h5`) and all the threshold-specific cores below are byte-exact against
RFC 9591 Appendix E.5's published intermediate values (`kat_test.zig`). See
`SPEC.md` for the design, the BIP340-compatibility finding (short version:
**NOT compatible** — different element encoding, different signature length,
different challenge hash), and the full threat model.

| File | Contents |
|---|---|
| `root.zig` | Every public type (`Identifier`, `Element`/`GroupPublicKey`/`VerifyingShare`/`NonceCommitment`, `SigningShare`, `SignatureShare`, `SigningNonces`, `SigningCommitments`, `Signature`), the REAL hash layer (`h1`..`h5`, `computeChallenge`, `nonceGenerate`, `generateNonces`), REAL §4.3 list operations (`encodeGroupCommitmentList`, `participantsFromCommitmentList`, `bindingFactorForParticipant`, `sortCommitmentsByIdentifier`), and all ten threshold-specific crypto cores |
| `kat_vectors.zig` | RFC 9591 Appendix E.5's official secp256k1/SHA-256 test vector, embedded |
| `kat_test.zig` | KAT assertions against every embedded value + an end-to-end (2,3) round-trip test |

Provenance: clean-room from RFC 9591 (FROST) and RFC 9380 (hash-to-curve), both
public IRTF/IETF specifications with no reference implementation consulted; the
secp256k1 group comes from the sibling [`k256`](../k256) module. Detail in this
module's own [`NOTICE`](NOTICE); it carries no condition beyond zig-libs' MIT
license.

## Import

```zig
const frost = @import("frost");
```

## API surface

**Ciphersuite constants:**

```zig
frost.context_string  // "FROST-secp256k1-SHA256-v1"
frost.Ne               // 33 (Element wire size)
frost.Ns               // 32 (Scalar wire size)
frost.group_order      // the secp256k1 curve order
```

**Wire types** (each with `fromBytes`/`toBytes`, and `encoded_length`):

```zig
frost.Identifier        // 32-byte NonZeroScalar (participant i)
frost.Element            // 33-byte SEC1-compressed point
frost.GroupPublicKey      // = Element
frost.VerifyingShare       // = Element
frost.NonceCommitment       // = Element
frost.SigningShare           // 32-byte Scalar (a participant's key share sk_i)
frost.SignatureShare          // 32-byte Scalar (a round-2 output z_i)
frost.SigningCommitments       // { identifier, hiding: NonceCommitment, binding: NonceCommitment }
frost.Signature                 // { r: Element, z: [32]u8 } — 65 bytes total
```

**Non-wire types** (never serialized — see `SPEC.md`):

```zig
frost.Scalar             // re-exported std.crypto.ecc.Secp256k1.scalar.Scalar
frost.SigningNonces        // { hiding: Scalar, binding: Scalar } — SECRET
frost.NonceCommitmentPair    // { hiding: NonceCommitment, binding: NonceCommitment }
frost.ParticipantShare         // { identifier, signing_share } — a trusted-dealer share
```

**Hash layer (REAL)**:

```zig
frost.h1(msg: []const u8) Scalar   // hash_to_field, DST=...+"rho"
frost.h2(msg: []const u8) Scalar   // hash_to_field, DST=...+"chal" (the challenge hash)
frost.h3(msg: []const u8) Scalar   // hash_to_field, DST=...+"nonce"
frost.h4(msg: []const u8) [32]u8   // tagged SHA-256, "msg"
frost.h5(msg: []const u8) [32]u8   // tagged SHA-256, "com"
frost.computeChallenge(group_commitment: Element, group_public_key: GroupPublicKey, msg: []const u8) Scalar
frost.nonceGenerate(random_bytes: [32]u8, secret: Scalar) Scalar
frost.generateNonces(out: *SigningNonces, signing_share: *const SigningShare, hiding_random: [32]u8, binding_random: [32]u8) void
```

**List operations (REAL)**:

```zig
frost.encodeGroupCommitmentList(allocator, commitment_list: []const SigningCommitments) ![]u8
frost.participantsFromCommitmentList(allocator, commitment_list: []const SigningCommitments) ![]Identifier
frost.bindingFactorForParticipant(binding_factor_list: []const BindingFactor, identifier: Identifier) !Scalar
frost.sortCommitmentsByIdentifier(commitment_list: []SigningCommitments) void
```

**Crypto cores (all implemented)**:

```zig
frost.deriveInterpolatingValue(participant_list: []const Identifier, x_i: Identifier) !Scalar
frost.computeBindingFactors(allocator, group_public_key, commitment_list, msg) ![]BindingFactor
frost.computeGroupCommitment(commitment_list, binding_factor_list) !Element
frost.round1Commit(nonces: *const SigningNonces) !NonceCommitmentPair
frost.round2Sign(allocator, identifier, signing_share: *const SigningShare, group_public_key, nonces: *const SigningNonces, msg, commitment_list) !SignatureShare
frost.aggregate(allocator, commitment_list, msg, group_public_key, sig_shares) !Signature
frost.aggregateVerified(allocator, commitment_list, msg, group_public_key, sig_shares, verifying_shares, culprit: ?*Identifier) !Signature
frost.verifySignatureShare(allocator, identifier, verifying_share, comm_i, sig_share_i, commitment_list, group_public_key, msg) !bool
frost.verify(msg, sig: Signature, group_public_key: GroupPublicKey) bool
frost.trustedDealerKeygen(allocator, secret_key: Scalar, coefficients: []const Scalar, max_participants: u16, min_participants: u16) !TrustedDealerKeygenResult
frost.secretShareCombine(shares: []const ParticipantShare) !Scalar
frost.vssVerify(share: *const ParticipantShare, vss_commitment: []const Element) !bool   // RFC 9591 C.2

// Distributed key generation (frost-core's dkg: part1 / part2 / part3):
frost.dkg.part1(allocator, out: *dkg.Round1SecretPackage, identifier, max_signers, min_signers, coefficients: []const Scalar, nonce: *const Scalar) !dkg.Round1Package
frost.dkg.part2(allocator, out: *dkg.Round2SecretPackage, secret: *const dkg.Round1SecretPackage, round1_packages: []const dkg.Round1Received, culprit: ?*Identifier) ![]dkg.Round2Package
frost.dkg.part3(allocator, out: *dkg.KeyPackage, secret: *const dkg.Round2SecretPackage, round1_packages, round2_packages: []const dkg.Round2Received, culprit: ?*Identifier) !dkg.PublicKeyPackage
frost.dkg.verifyProofOfKnowledge(sender: Identifier, package: dkg.Round1Package) bool
```

## Usage

```zig
// Trusted-dealer keygen (2-of-3):
const keygen = try frost.trustedDealerKeygen(allocator, secret, &coefficients, 3, 2);

// Round 1 (each of 2 chosen signers):
var nonces: frost.SigningNonces = undefined;
frost.generateNonces(&nonces, &share.signing_share, hiding_random, binding_random);
const comm = try frost.round1Commit(&nonces);
// ... exchange SigningCommitments{identifier, comm.hiding, comm.binding} via the Coordinator ...

// Round 2 (each signer, given the full sorted commitment_list):
const sig_share = try frost.round2Sign(allocator, identifier, &share.signing_share, keygen.group_public_key, &nonces, msg, commitment_list);

// Aggregation (the Coordinator):
const sig = try frost.aggregate(allocator, commitment_list, msg, keygen.group_public_key, sig_shares);
std.debug.assert(frost.verify(msg, sig, keygen.group_public_key));
```

## Verify

```
zig build test-frost
```

RFC 9591 Appendix E.5 known-answer tests for every core, frost-core's published
DKG vector, an end-to-end (2,3) round trip, deterministic fuzz harnesses (`FROST_FUZZ`) and a dead-stack probe
for the secrets; `SPEC.md` *Verification* lists the classes.

## Not provided

Other ciphersuites (ristretto255, Ed25519, Ed448, P-256), a BIP-340/Taproot-compatible
variant, share refresh, repair and re-randomized signatures: see `SPEC.md` *Compared with*
and *Roadmap*.
