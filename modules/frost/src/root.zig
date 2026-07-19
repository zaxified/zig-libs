// SPDX-License-Identifier: MIT
//! frost — FROST (Flexible Round-Optimized Schnorr Threshold signatures),
//! per RFC 9591, **secp256k1/SHA-256 ciphersuite (RFC 9591 §6.5) only**: a
//! t-of-n threshold Schnorr signing protocol whose two rounds
//! (`round1Commit` / `round2Sign`) plus `aggregate` produce a single
//! two-element `(R, z)` Schnorr signature verifiable under one group
//! public key, with no interaction required from a full n-of-n set —
//! only any `MIN_PARTICIPANTS`-sized subset. Builds on the sibling
//! `bip340` module... in name only for now: **this ciphersuite's
//! aggregate signature is NOT a BIP340 signature** — see the "BIP340
//! compatibility" finding below. `bip340` is listed as a dependency by
//! the orchestrator for a future cross-module comparison/test, not
//! because `verify` here calls into it.
//!
//! **Status: complete** — all ten threshold cores implemented and
//! KAT-validated (32/32 tests, Debug + ReleaseFast). Wire codecs
//! (`Identifier`, `Element`,
//! `SigningShare`, `SignatureShare`, `Signature`, `SigningCommitments`),
//! RFC §4.3 "List Operations" (`encodeGroupCommitmentList`,
//! `participantsFromCommitmentList`, `bindingFactorForParticipant`,
//! `sortCommitmentsByIdentifier`), and the five ciphersuite hash
//! functions `h1`..`h5` (§6.5) plus `computeChallenge` (§4.6, pure H2
//! glue) and `nonceGenerate`/`generateNonces` (§4.1, pure H3 glue) are
//! REAL and cross-validated byte-exact against RFC 9591 Appendix E.5
//! intermediate values (`kat_test.zig`'s `"h1/h3/h4/h5 match ..."`
//! tests) — see each function's doc comment for exactly which
//! `expand_message_xmd`/`hash_to_field` (RFC 9380 §5.3/§5.4.1)
//! construction it is. The ten threshold-specific CORES —
//! `computeBindingFactors`, `computeGroupCommitment`,
//! `deriveInterpolatingValue`, `round1Commit`, `round2Sign`, `aggregate`,
//! `verifySignatureShare`, `verify`, `trustedDealerKeygen`, and
//! `secretShareCombine` — are implemented per each doc comment's exact
//! RFC 9591 construction (section + pseudocode line): Lagrange
//! interpolation (`derive_interpolating_value` via the scalar field's
//! constant-time modular inverse), the per-participant binding factors,
//! the group commitment, the §5.2 signature-share equation, aggregation,
//! and Appendix B's `prime_order_verify` (FROST-secp256k1's own Schnorr
//! verify — 33-byte compressed R, `"chal"`-DST `expand_message_xmd`
//! challenge — NOT BIP340, never calls `bip340.verify`).
//! `kat_vectors.zig` carries the RFC 9591 Appendix E.5 official
//! secp256k1/SHA-256 test vector (config, group secret + public key,
//! all 3 trusted-dealer shares, the one Shamir coefficient, both
//! signers' round-1 nonces/commitments/binding-factor inputs/binding
//! factors, both signers' round-2 signature shares, and the final
//! aggregate signature) byte-exact, transcribed from the RFC text — see
//! `NOTICE`. `kat_test.zig` asserts (once the cores are filled in): (1)
//! `trustedDealerKeygen` reproduces the vector's 3 shares + group public
//! key from the vector's secret + coefficient, and `secretShareCombine`
//! reconstructs the group secret from any 2-of-3 subset; (2) each
//! signer's binding factor matches byte-exact; (3) `round1Commit`
//! reproduces both signers' published nonce commitments byte-exact; (4)
//! `aggregate` reproduces the exact published final signature byte-exact (cores implemented)
//! (this transitively pins down `round2Sign`'s signature-share equation
//! AND `computeGroupCommitment`, since RFC 9591's own Appendix E.5 does
//! NOT publish a standalone `group_commitment`/`challenge` scalar for
//! this ciphersuite — see the "what the vectors do NOT cover" note
//! below); (5) `verify` accepts the aggregate and rejects a tampered
//! one; (6) `verifySignatureShare` accepts each of the two published
//! shares and rejects a corrupted one; (7) an end-to-end (2,3)
//! `trustedDealerKeygen` → `generateNonces` → `round1Commit` →
//! `round2Sign` → `aggregate` → `verify` round trip with FRESH random
//! key material (not a published vector).
//!
//! **What the vectors do NOT cover** (read RFC 9591 Appendix E.5's raw
//! text before assuming otherwise): unlike some KAT suites, this
//! ciphersuite's published vector does NOT include a standalone
//! `group_commitment` or `challenge` field — only `binding_factor_input`/
//! `binding_factor` (round 1) and `sig_share` (round 2) are given
//! per-signer, plus the final `sig`. `computeGroupCommitment`'s and
//! `computeChallenge`'s correctness is therefore checked *indirectly*:
//! `aggregate`'s output `R` component IS `computeGroupCommitment`'s
//! return value (RFC 9591 §5.3's `aggregate` returns `(group_commitment,
//! z)` verbatim), and `round2Sign`'s signature-share equation (§5.2)
//! only reproduces the published `sig_share` byte-exact if `challenge`
//! (hence `computeChallenge`, hence `h2`) was computed correctly — so a
//! byte-exact match on `aggregate`'s full 65-byte output is already a
//! complete, if indirect, check of both.
//!
//! ## BIP340 compatibility — explicit finding: **NO, byte-incompatible**
//!
//! RFC 9591 §6.5's secp256k1/SHA-256 ciphersuite is **NOT** BIP340's
//! x-only/even-y convention, and the aggregate `(R, z)` signature this
//! module produces is **NOT** a 64-byte BIP340 signature `bip340.verify`
//! would accept. Concretely (RFC 9591 §3.1 `SerializeElement` + §6.5 +
//! Appendix A/B, confirmed against the Appendix E.5 vector: the
//! `group_public_key`/commitment values are 33 bytes starting `02`/`03`,
//! and the final `sig` is 65 bytes, not 64):
//!
//!   - **Element encoding**: every group element (group public key,
//!     verifying shares, nonce commitments, the signature's `R`) is the
//!     FULL 33-byte SEC1-COMPRESSED point (`Secp256k1.toCompressedSec1`/
//!     `fromSec1` — parity byte `02`/`03` + 32-byte x-coordinate).
//!     BIP340 instead drops the parity byte entirely and canonicalizes
//!     every point to its even-y representative (`bip340.XOnlyPublicKey`,
//!     32 bytes) — a lossy, different encoding of the same curve.
//!   - **Signature shape**: RFC 9591's `(R, z)` is `SerializeElement(R)
//!     || SerializeScalar(z)` = 33 + 32 = **65 bytes** (Appendix A). A
//!     BIP340 signature is `bytes(r) || bytes(s)` = 32 + 32 = **64
//!     bytes**, where `r` is `R`'s x-only x-coordinate.
//!   - **Challenge preimage AND tag**: RFC 9591's `compute_challenge`
//!     (§4.6) hashes `SerializeElement(R) || SerializeElement(PK) ||
//!     msg` (33 + 33 + variable bytes) through `H2` = `hash_to_field`
//!     with `expand_message_xmd`/SHA-256 and DST
//!     `"FROST-secp256k1-SHA256-v1chal"` (RFC 9380 §5.3, NOT a
//!     BIP340-style tagged hash). BIP340's challenge instead hashes
//!     `bytes(r) || bytes(P) || msg` (32 + 32 + variable) through
//!     `SHA256(SHA256("BIP0340/challenge") || SHA256("BIP0340/challenge")
//!     || ·)` — a completely different domain separator, a completely
//!     different hash CONSTRUCTION (tagged double-SHA256 vs.
//!     `expand_message_xmd` hash-to-field), and a different preimage
//!     length (33-byte elements, not 32-byte x-only values).
//!   - **Net effect**: even for `NUM_PARTICIPANTS = 1` (a degenerate
//!     "threshold" of one signer holding the whole secret — RFC 9591's
//!     own Appendix B `prime_order_sign`/`prime_order_verify`, which
//!     THIS module's `verify` implements), the resulting signature is
//!     bit-for-bit different from what `bip340.sign` would produce over
//!     the same key and message, and `bip340.verify` would reject it (or
//!     more likely fail to even parse it — wrong length). The two
//!     schemes happen to share the same curve and the same *style*
//!     (Schnorr `s = k + e·d`) but are NOT interoperable at the wire or
//!     verification-equation level. This module's `verify` implements
//!     RFC 9591 Appendix B's `prime_order_verify` directly — it does NOT
//!     call `bip340.verify`, and no combination of encode/decode glue
//!     makes the two compatible (the challenge hash itself differs, not
//!     just the serialization).
//!
//! `std.crypto.ecc.Secp256k1` (field/scalar arithmetic, `basePoint`,
//! `mul`/`mulDoubleBasePublic`, `fromSec1`/`toCompressedSec1`,
//! `scalar.reduce48` for `hash_to_field`'s wide reduction) supplies the
//! curve group; `std.crypto.hash.sha2.Sha256` supplies the hash. Zig std
//! GAP: yes — std has neither RFC 9380 `expand_message_xmd`/
//! `hash_to_field` NOR any FROST/threshold-Schnorr layer; both are this
//! module's own (clean-room from RFC 9591 + RFC 9380's public text — see
//! `NOTICE`).
//!
//! Only the secp256k1/SHA-256 ciphersuite (RFC 9591 §6.5) is scaffolded.
//! RFC 9591 Appendix E also publishes vectors for Ed25519, Ed448,
//! ristretto255, and P-256 (§6.1-§6.4) — none of those are in scope
//! here; a ristretto255 pass would need its own module (different group,
//! different `H1`..`H5`, different `SerializeElement`/`SerializeScalar`
//! sizes) and is explicitly out of scope for this pass.

const std = @import("std");
const bip340 = @import("bip340");

/// Re-exported for callers (and `kat_test.zig`) that need to construct a
/// raw curve point directly (e.g. deriving a `VerifyingShare` from a
/// `SigningShare` via `Secp256k1.basePoint.mul`).
pub const Secp256k1 = @import("k256").Secp256k1;
const scalar_mod = Secp256k1.scalar;

/// Re-exported: the std scalar-field type this module's `SigningNonces`,
/// `trustedDealerKeygen`'s `secret_key`/`coefficients`, and
/// `secretShareCombine`'s return value all use directly (see the module
/// doc comment: ephemeral/dealer-only secret values use the raw std
/// `Scalar` type rather than a bespoke wire-codec wrapper, since they are
/// never serialized onto the wire).
pub const Scalar = scalar_mod.Scalar;

pub const meta = .{
    .platform = .any,
    .role = .util, // pure computation — no I/O, no wire framing of its own
    .concurrency = .reentrant, // no globals; all types are plain values
    .model_after = "RFC 9591 (\"The Flexible Round-Optimized Schnorr Threshold (FROST) Protocol for Two-Round Schnorr Signatures\"), §6.5 secp256k1/SHA-256 ciphersuite; RFC 9380 (hash-to-curve) §5.3/§5.4.1 expand_message_xmd/hash_to_field for H1-H3; the k256 module supplies the curve group (byte-exact to std.crypto.ecc.Secp256k1)",
    .deps = .{ "bip340", "k256" }, // bip340 orchestrator-registered (NOT used by verify); k256 curve group
};

// ── ciphersuite constants (RFC 9591 §6.5) ───────────────────────────────

/// RFC 9591 §6.5's `contextString`: `"FROST-secp256k1-SHA256-v1"`. Every
/// hash function below (`h1`..`h5`) prefixes its own label onto this
/// exact string to form its domain-separation tag/DST.
pub const context_string = "FROST-secp256k1-SHA256-v1";

/// The secp256k1 group order `p` (RFC 9591 §6.5's `Order()`), i.e.
/// `Secp256k1.scalar.field_order` — restated here only for doc-comment
/// cross-reference; use `scalar_mod.field_order` in code.
pub const group_order = scalar_mod.field_order;

/// `Ne` (RFC 9591 §6.5): the fixed encoded length of a group `Element`
/// (33-byte SEC1-compressed point).
pub const Ne: usize = 33;

/// `Ns` (RFC 9591 §6.5): the fixed encoded length of a `Scalar`
/// (32-byte big-endian field element).
pub const Ns: usize = 32;

// ── H1..H5 (RFC 9591 §6.5) — REAL, cross-validated against Appendix E.5 ──
//
// H1, H2, H3 are `hash_to_field(m, count=1)` (RFC 9380 §5.3) built from
// `expand_message_xmd` with SHA-256 (RFC 9380 §5.4.1), L=48,
// DST = contextString || label. H4, H5 are plain tagged SHA-256 (no
// expand_message_xmd): `SHA256(contextString || label || m)`.
//
// `expandMessageXmd48` below is deliberately specialized to
// `len_in_bytes = 48` (this ciphersuite's ONLY value: `hash_to_field`'s
// `L = ceil((ceil(log2(p)) + k) / 8)` with `p` = the secp256k1 order
// (256-bit) and `k` = 128 (the target security level) works out to 48
// for every one of H1/H2/H3 — RFC 9380 §5.1/§8.9's "L" table lists 48 for
// secp256k1), NOT a general-purpose arbitrary-length implementation —
// there is no other length this ciphersuite ever needs. `ell = 2` (two
// SHA-256 blocks, `ceil(48/32)`) is likewise hardcoded.

/// RFC 9380 §5.4.1 `expand_message_xmd` specialized to SHA-256
/// (`b_in_bytes = 32`, `s_in_bytes = 64`) and `len_in_bytes = 48`
/// (`ell = 2`). `dst` MUST be ≤ 255 bytes (RFC 9380's own DST-length
/// ceiling; this ciphersuite's DSTs — `contextString` plus a 3-5 byte
/// label — are always ≤ 32, far under the limit, so this is a defensive
/// assert, not a real constraint in practice).
///
/// `msg_parts` is hashed as the CONCATENATION of every part, streamed
/// through incremental `Sha256.update` calls — this avoids ever
/// materializing the concatenated message in a buffer (no allocator, no
/// fixed-size ceiling on the combined length), which is what lets
/// `computeChallenge` below feed `comm_enc || pk_enc || msg` straight
/// through without copying.
///
/// Byte-exact against RFC 9591 Appendix E.5's `P1 binding_factor_input`
/// → `P1 binding_factor` pair when composed with `h1` below (this
/// function IS `h1`/`h2`/`h3`'s shared inner step) — see
/// `kat_test.zig`.
fn expandMessageXmd48(msg_parts: []const []const u8, dst: []const u8) [48]u8 {
    std.debug.assert(dst.len <= 255);
    var dst_prime_buf: [256]u8 = undefined;
    @memcpy(dst_prime_buf[0..dst.len], dst);
    dst_prime_buf[dst.len] = @intCast(dst.len);
    const dst_prime = dst_prime_buf[0 .. dst.len + 1];

    const z_pad = [_]u8{0} ** 64; // s_in_bytes for SHA-256
    const l_i_b_str = [_]u8{ 0x00, 0x30 }; // I2OSP(48, 2)

    var hasher0 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher0.update(&z_pad);
    for (msg_parts) |part| hasher0.update(part);
    hasher0.update(&l_i_b_str);
    hasher0.update(&[_]u8{0x00}); // I2OSP(0, 1)
    hasher0.update(dst_prime);
    var b0: [32]u8 = undefined;
    hasher0.final(&b0);

    var hasher1 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher1.update(&b0);
    hasher1.update(&[_]u8{0x01}); // I2OSP(1, 1)
    hasher1.update(dst_prime);
    var b1: [32]u8 = undefined;
    hasher1.final(&b1);

    var xored: [32]u8 = undefined;
    for (&xored, b0, b1) |*o, x, y| o.* = x ^ y;

    var hasher2 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher2.update(&xored);
    hasher2.update(&[_]u8{0x02}); // I2OSP(2, 1)
    hasher2.update(dst_prime);
    var b2: [32]u8 = undefined;
    hasher2.final(&b2);

    var out: [48]u8 = undefined;
    out[0..32].* = b1;
    out[32..48].* = b2[0..16].*;
    return out;
}

/// `hash_to_field(msg, count=1)` (RFC 9380 §5.3) for the secp256k1
/// scalar field, given an already-assembled DST: expand to 48 bytes via
/// `expandMessageXmd48`, then `OS2IP(..) mod p` via
/// `Secp256k1.scalar.Scalar.fromBytes48` (std's wide-reduction helper —
/// exactly RFC 9380's `p`-order reduction of a 384-bit integer).
fn hashToScalar(dst: []const u8, msg_parts: []const []const u8) Scalar {
    return Scalar.fromBytes48(expandMessageXmd48(msg_parts, dst), .big);
}

/// `H1(m)` (RFC 9591 §6.5): `hash_to_field(m, 1)` with
/// `DST = contextString || "rho"`. Used only inside `computeBindingFactors`
/// (§4.4) to derive each participant's binding factor `rho_i`.
pub fn h1(msg: []const u8) Scalar {
    return hashToScalar(context_string ++ "rho", &.{msg});
}

/// `H2(m)` (RFC 9591 §6.5): `hash_to_field(m, 1)` with
/// `DST = contextString || "chal"`. This is the per-message Schnorr
/// CHALLENGE hash — see `computeChallenge` below, and the module doc
/// comment's BIP340-compatibility finding (this DST/construction is NOT
/// BIP340's tagged-hash challenge).
pub fn h2(msg: []const u8) Scalar {
    return hashToScalar(context_string ++ "chal", &.{msg});
}

/// `H3(m)` (RFC 9591 §6.5): `hash_to_field(m, 1)` with
/// `DST = contextString || "nonce"`. Used only inside `nonce_generate`
/// (§4.1) — see `nonceGenerate` below.
pub fn h3(msg: []const u8) Scalar {
    return hashToScalar(context_string ++ "nonce", &.{msg});
}

/// `H4(m)` (RFC 9591 §6.5): `H(contextString || "msg" || m)` — plain
/// SHA-256, NOT `hash_to_field` (no `expand_message_xmd`). Used only
/// inside `computeBindingFactors` to hash the message once per signing
/// session (`msg_hash`, §4.4).
pub fn h4(msg: []const u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(context_string ++ "msg");
    hasher.update(msg);
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

/// `H5(m)` (RFC 9591 §6.5): `H(contextString || "com" || m)` — plain
/// SHA-256. Used only inside `computeBindingFactors`, applied to
/// `encodeGroupCommitmentList`'s output (`encoded_commitment_hash`,
/// §4.4).
pub fn h5(msg: []const u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(context_string ++ "com");
    hasher.update(msg);
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

// ── nonce_generate (RFC 9591 §4.1) — REAL, pure H3 glue ─────────────────

/// RFC 9591 §4.1 `nonce_generate(secret)`: `H3(random_bytes ||
/// G.SerializeScalar(secret))`. REAL (not a stub) — this is pure hashing
/// with no secret-dependent branching or "irreducible" cryptographic
/// judgment, just `h3` applied to a fixed preimage. Byte-exact against
/// RFC 9591 Appendix E.5 (`P1 hiding_nonce_randomness` + `P1
/// participant_share` → `P1 hiding_nonce`) — see `kat_test.zig`.
///
/// Deliberately takes `random_bytes` as a CALLER-SUPPLIED parameter, not
/// generated internally via an RNG: this is the "hedged" nonce
/// construction the RFC recommends (mix fresh randomness with the secret
/// key, §4.1's opening paragraph), and taking the randomness as an
/// explicit input — rather than reading `std.Io`/a global RNG — is what
/// makes this function deterministically replayable against a KAT
/// vector. A real deployment's caller is responsible for sourcing
/// `random_bytes` from a secure RNG (see `generateNonces` below, which
/// is the usual two-call entry point built on top of this).
pub fn nonceGenerate(random_bytes: [32]u8, secret: Scalar) Scalar {
    var preimage: [64]u8 = undefined;
    preimage[0..32].* = random_bytes;
    preimage[32..64].* = secret.toBytes(.big);
    return h3(&preimage);
}

/// RFC 9591 §5.1 `commit`'s nonce half only (the commitment half is
/// `round1Commit` below, which is STUBBED — group-element scalar
/// multiplication is listed as a CORE per the task brief even though its
/// math is simple, so the specialist owns the full `commit` shape,
/// including error handling): calls `nonceGenerate` twice with two
/// INDEPENDENT random seeds, once for the hiding nonce and once for the
/// binding nonce (RFC 9591 §5.1: "this function invokes nonce_generate
/// twice, once for each type of nonce produced"). REAL, since it is
/// nothing more than two `nonceGenerate` calls.
///
/// `hiding_random`/`binding_random` MUST each be fresh, independent,
/// secret 32-byte random values (RFC 9591 §5.1: "the nonces ... MUST be
/// generated from a source of secure randomness") — passing the same
/// bytes for both, or a predictable value, breaks the scheme exactly as
/// badly as ECDSA/Schnorr nonce reuse does elsewhere.
pub fn generateNonces(signing_share: SigningShare, hiding_random: [32]u8, binding_random: [32]u8) SigningNonces {
    const secret = signing_share.scalar();
    return .{
        .hiding = nonceGenerate(hiding_random, secret),
        .binding = nonceGenerate(binding_random, secret),
    };
}

// ── Identifier (RFC 9591 §3.1 NonZeroScalar, as used for participant i) ──

pub const IdentifierError = error{InvalidIdentifier};

/// A FROST participant identifier: a `NonZeroScalar` (RFC 9591 §3.1),
/// `G.SerializeScalar`-encoded (32-byte big-endian). The RFC allows any
/// nonzero scalar as an identifier; `fromU16` covers the common
/// "sequential small integer" convention Appendix E.5's vector and
/// `trustedDealerKeygen` use (participant `i`'s identifier is literally
/// the integer `i`, `i` in `[1, MAX_PARTICIPANTS]`).
pub const Identifier = struct {
    bytes: [Ns]u8,

    pub const encoded_length = Ns;

    /// The common case: identifier = participant index, `i` in
    /// `[1, 65535]`. Rejects `i == 0` (RFC 9591 §3.1's `NonZeroScalar`).
    pub fn fromU16(i: u16) IdentifierError!Identifier {
        if (i == 0) return error.InvalidIdentifier;
        var bytes = [_]u8{0} ** Ns;
        std.mem.writeInt(u16, bytes[Ns - 2 .. Ns], i, .big);
        return .{ .bytes = bytes };
    }

    /// General case: any nonzero-scalar 32-byte big-endian encoding
    /// (`G.DeserializeScalar` + the `NonZeroScalar` check).
    pub fn fromBytes(bytes: [Ns]u8) IdentifierError!Identifier {
        const s = Scalar.fromBytes(bytes, .big) catch return error.InvalidIdentifier;
        if (s.isZero()) return error.InvalidIdentifier;
        return .{ .bytes = bytes };
    }

    pub fn toBytes(id: Identifier) [Ns]u8 {
        return id.bytes;
    }

    /// Already validated non-zero-canonical by both constructors, so
    /// this unwrap cannot fail.
    pub fn scalar(id: Identifier) Scalar {
        return Scalar.fromBytes(id.bytes, .big) catch unreachable;
    }

    /// Byte-order comparator for `sortCommitmentsByIdentifier` — a
    /// fixed-width big-endian byte compare is exactly a numeric compare
    /// of the underlying scalar (RFC 9591 §3.1: "the least nonnegative
    /// representation mod p is used" when sorting Scalars).
    fn lessThan(_: void, a: Identifier, b: Identifier) bool {
        return std.mem.order(u8, &a.bytes, &b.bytes) == .lt;
    }
};

// ── Element (RFC 9591 §6.5 SerializeElement/DeserializeElement) ─────────

pub const ElementError = error{InvalidElement};

/// A FROST group element: 33-byte SEC1-compressed secp256k1 point (RFC
/// 9591 §6.5, `Ne = 33`). This single wire type stands in for the RFC's
/// `GroupPublicKey`, `VerifyingShare`, and `NonceCommitment` — all
/// encoded identically at this ciphersuite (aliased below for
/// call-site clarity). NEVER the identity element
/// (`SerializeElement`'s own requirement, RFC 9591 §3.1); both
/// constructors reject it.
pub const Element = struct {
    bytes: [Ne]u8,

    pub const encoded_length = Ne;

    /// `DeserializeElement` (RFC 9591 §6.5): SEC1-compressed point
    /// parse + full public-key validation (on-curve, canonical
    /// coordinates, not the point at infinity) via
    /// `Secp256k1.fromSec1` + `rejectIdentity`.
    pub fn fromBytes(bytes: [Ne]u8) ElementError!Element {
        const p = Secp256k1.fromSec1(&bytes) catch return error.InvalidElement;
        p.rejectIdentity() catch return error.InvalidElement;
        return .{ .bytes = bytes };
    }

    /// `SerializeElement` applied to an in-hand curve point — rejects
    /// the identity element per the RFC's own requirement on
    /// `SerializeElement`.
    pub fn fromPoint(p: Secp256k1) ElementError!Element {
        p.rejectIdentity() catch return error.InvalidElement;
        return .{ .bytes = p.toCompressedSec1() };
    }

    /// The real secp256k1 point. Re-validates (cheap; the heavy lifting
    /// is `fromSec1`'s own on-curve check) so this is safe on
    /// hand-constructed values, matching `bip340.XOnlyPublicKey.lift`'s
    /// precedent.
    pub fn point(e: Element) ElementError!Secp256k1 {
        const p = Secp256k1.fromSec1(&e.bytes) catch return error.InvalidElement;
        p.rejectIdentity() catch return error.InvalidElement;
        return p;
    }

    pub fn toBytes(e: Element) [Ne]u8 {
        return e.bytes;
    }
};

/// The group's public key `PK = G.ScalarBaseMult(s)` (RFC 9591 §5's
/// "group info"). Same wire shape as any other `Element`.
pub const GroupPublicKey = Element;

/// A single participant's public verifying share `PK_i =
/// G.ScalarBaseMult(sk_i)` (RFC 9591 §5's "group info"). Same wire shape
/// as any other `Element`.
pub const VerifyingShare = Element;

/// One of a participant's two public nonce commitments
/// (`hiding_nonce_commitment` or `binding_nonce_commitment`, RFC 9591
/// §5.1). Same wire shape as any other `Element`.
pub const NonceCommitment = Element;

// ── SigningShare / SignatureShare (RFC 9591 Scalar-valued wire types) ───

/// Factory for a 32-byte-big-endian-`Scalar`-backed wire type: parses
/// via `DeserializeScalar`'s canonical range check
/// (`Scalar.fromBytes`), nothing more. Used for `SigningShare` (a
/// participant's Shamir share `sk_i`) and `SignatureShare` (a round-2
/// output `z_i`) — same encoding, kept as nominally DISTINCT Zig types
/// (each `comptime tag` produces its own type identity) so the two
/// cannot be accidentally swapped at a call site despite the identical
/// wire shape.
fn ScalarWire(comptime tag: []const u8) type {
    _ = tag;
    return struct {
        bytes: [Ns]u8,

        pub const encoded_length = Ns;

        pub fn fromBytes(bytes: [Ns]u8) ScalarWireError!@This() {
            _ = Scalar.fromBytes(bytes, .big) catch return error.InvalidScalar;
            return .{ .bytes = bytes };
        }

        pub fn fromScalar(s: Scalar) @This() {
            return .{ .bytes = s.toBytes(.big) };
        }

        /// Already validated canonical by `fromBytes`/`fromScalar`, so
        /// this unwrap cannot fail.
        pub fn scalar(self: @This()) Scalar {
            return Scalar.fromBytes(self.bytes, .big) catch unreachable;
        }

        pub fn toBytes(self: @This()) [Ns]u8 {
            return self.bytes;
        }
    };
}

pub const ScalarWireError = error{InvalidScalar};

/// A participant's Shamir signing-key share `sk_i` (RFC 9591 §5: "a
/// Scalar value representing the i-th Shamir secret share of the group
/// signing key s").
pub const SigningShare = ScalarWire("SigningShare");

/// A round-2 signature share `z_i` (RFC 9591 §5.2 `sign`'s output).
pub const SignatureShare = ScalarWire("SignatureShare");

// ── SigningNonces / SigningCommitments (RFC 9591 §5.1) ───────────────────

/// A participant's SECRET round-1 nonce pair `(hiding_nonce,
/// binding_nonce)` (RFC 9591 §5.1). Deliberately NOT a wire type — RFC
/// 9591 §5.1: "The nonce value is secret and MUST NOT be shared" — so,
/// unlike `SigningCommitments` below, this holds raw `Scalar`s with no
/// `fromBytes`/`toBytes` codec (nothing should ever serialize a
/// `SigningNonces` onto a wire).
pub const SigningNonces = struct {
    hiding: Scalar,
    binding: Scalar,
};

/// The PUBLIC half of round 1: one participant's pair of nonce
/// commitments, still unattached to an `Identifier` (mirrors RFC 9591
/// §5.1 `commit`'s own output shape — `commit` returns `(nonces, comms)`
/// with no identifier; the caller already knows which participant it
/// asked). `round1Commit` returns this; the caller attaches its own
/// `Identifier` to build a `SigningCommitments` entry for the
/// `commitment_list` other participants/the Coordinator will see.
pub const NonceCommitmentPair = struct {
    hiding: NonceCommitment,
    binding: NonceCommitment,
};

/// One entry of RFC 9591's `commitment_list = [(i,
/// hiding_nonce_commitment_i, binding_nonce_commitment_i), ...]` (used
/// throughout §4.3-§5.3): a participant identifier plus its PUBLIC pair
/// of round-1 nonce commitments. A full `commitment_list` (`[]const
/// SigningCommitments`) MUST be sorted in ascending order by identifier
/// before being passed to `computeBindingFactors`/
/// `computeGroupCommitment`/`round2Sign`/etc — see
/// `sortCommitmentsByIdentifier`.
pub const SigningCommitments = struct {
    identifier: Identifier,
    hiding: NonceCommitment,
    binding: NonceCommitment,
};

/// Sorts `commitment_list` in place into RFC 9591's required ascending-
/// by-identifier order (§4.3: "This list MUST be sorted in ascending
/// order by identifier" — stated as a precondition on every function
/// that takes a `commitment_list`, not performed automatically by any of
/// them). REAL — a plain comparison sort, no cryptographic content.
pub fn sortCommitmentsByIdentifier(commitment_list: []SigningCommitments) void {
    std.sort.block(SigningCommitments, commitment_list, {}, struct {
        fn lessThan(_: void, a: SigningCommitments, b: SigningCommitments) bool {
            return Identifier.lessThan({}, a.identifier, b.identifier);
        }
    }.lessThan);
}

// ── Signature (RFC 9591 Appendix A canonical encoding) ───────────────────

pub const SignatureError = error{InvalidSignature};

/// A FROST aggregate signature `(R, z)` (RFC 9591 §5.3 `aggregate`'s
/// output; Appendix A's canonical encoding: `SerializeElement(R) ||
/// SerializeScalar(z)`, 33 + 32 = **65 bytes total** — NOT a 64-byte
/// BIP340 signature; see the module doc comment's BIP340-compatibility
/// finding).
pub const Signature = struct {
    r: Element,
    z: [Ns]u8,

    pub const encoded_length = Ne + Ns;

    pub fn fromBytes(bytes: [Ne + Ns]u8) SignatureError!Signature {
        const r = Element.fromBytes(bytes[0..Ne].*) catch return error.InvalidSignature;
        const z = bytes[Ne .. Ne + Ns].*;
        _ = Scalar.fromBytes(z, .big) catch return error.InvalidSignature;
        return .{ .r = r, .z = z };
    }

    pub fn toBytes(sig: Signature) [Ne + Ns]u8 {
        var out: [Ne + Ns]u8 = undefined;
        out[0..Ne].* = sig.r.toBytes();
        out[Ne .. Ne + Ns].* = sig.z;
        return out;
    }

    /// Already validated canonical by `fromBytes`, so this unwrap
    /// cannot fail on a value obtained that way (may still be `.z` set
    /// directly via `.{ .r = ..., .z = ... }` by trusted internal code,
    /// e.g. `aggregate`'s own construction — that path is responsible
    /// for only ever storing a canonical `z`).
    pub fn zScalar(sig: Signature) Scalar {
        return Scalar.fromBytes(sig.z, .big) catch unreachable;
    }
};

// ── §4.3 List Operations — REAL, pure plumbing (no crypto judgment) ─────

/// RFC 9591 §4.3 `encode_group_commitment_list`: concatenates, for each
/// entry in `commitment_list` (in the order given — callers MUST have
/// already sorted via `sortCommitmentsByIdentifier`), `SerializeScalar
/// (identifier) || SerializeElement(hiding) || SerializeElement
/// (binding)` — `Ns + Ne + Ne = 98` bytes per entry. Allocates the exact
/// `commitment_list.len * 98`-byte result via `allocator` (caller
/// frees). REAL: pure byte concatenation, the plumbing `H5` is applied
/// to inside `computeBindingFactors` — no cryptographic judgment here.
pub fn encodeGroupCommitmentList(allocator: std.mem.Allocator, commitment_list: []const SigningCommitments) std.mem.Allocator.Error![]u8 {
    const entry_len = Ns + Ne + Ne;
    const out = try allocator.alloc(u8, commitment_list.len * entry_len);
    var offset: usize = 0;
    for (commitment_list) |entry| {
        out[offset..][0..Ns].* = entry.identifier.toBytes();
        offset += Ns;
        out[offset..][0..Ne].* = entry.hiding.toBytes();
        offset += Ne;
        out[offset..][0..Ne].* = entry.binding.toBytes();
        offset += Ne;
    }
    return out;
}

/// RFC 9591 §4.3 `participants_from_commitment_list`: the list of
/// identifiers, in `commitment_list`'s given order. REAL — pure
/// extraction, no crypto.
pub fn participantsFromCommitmentList(allocator: std.mem.Allocator, commitment_list: []const SigningCommitments) std.mem.Allocator.Error![]Identifier {
    const out = try allocator.alloc(Identifier, commitment_list.len);
    for (commitment_list, out) |entry, *slot| slot.* = entry.identifier;
    return out;
}

/// One entry of RFC 9591's `binding_factor_list = [(i, binding_factor),
/// ...]` (§4.4's output shape).
pub const BindingFactor = struct {
    identifier: Identifier,
    factor: Scalar,
};

pub const BindingFactorLookupError = error{InvalidParticipant};

/// RFC 9591 §4.3 `binding_factor_for_participant`: linear lookup by
/// identifier. REAL — pure lookup, no crypto.
pub fn bindingFactorForParticipant(binding_factor_list: []const BindingFactor, identifier: Identifier) BindingFactorLookupError!Scalar {
    for (binding_factor_list) |entry| {
        if (std.mem.eql(u8, &entry.identifier.bytes, &identifier.bytes)) return entry.factor;
    }
    return error.InvalidParticipant;
}

// ── §4.6 Signature Challenge Computation — REAL, pure H2 glue ───────────

/// RFC 9591 §4.6 `compute_challenge`: `H2(SerializeElement(group_commitment)
/// || SerializeElement(group_public_key) || msg)`. REAL — pure
/// concatenation feeding the already-REAL `h2`; no secret material, no
/// scalar-field judgment beyond the hash-to-field `h2` already performs.
/// NOT independently checked against a published RFC 9591 Appendix E.5
/// scalar (the vector does not publish one for this ciphersuite — see
/// the module doc comment) but IS checked indirectly: `round2Sign`'s
/// signature-share equation only reproduces the vector's published
/// `sig_share` byte-exact if this function's output is correct.
///
/// Feeds `comm_enc || pk_enc || msg` to `hash_to_field` as three
/// SEPARATE streamed parts (`hashToScalar`'s `msg_parts`) rather than
/// concatenating into one buffer first — zero-allocation, no ceiling on
/// `msg`'s length, no hidden global allocator (CONVENTIONS.md §1 item 2).
pub fn computeChallenge(group_commitment: Element, group_public_key: GroupPublicKey, msg: []const u8) Scalar {
    const comm_enc = group_commitment.toBytes();
    const pk_enc = group_public_key.toBytes();
    return hashToScalar(context_string ++ "chal", &.{ &comm_enc, &pk_enc, msg });
}

// ── crypto cores (implemented — see each doc comment for the RFC 9591 ref) ──

pub const DeriveInterpolatingValueError = error{
    /// `x_i` does not appear in `participant_list` (RFC 9591 §4.2's
    /// `"invalid parameters"`, case 1).
    NotInList,
    /// Some x-coordinate appears more than once in `participant_list`
    /// (RFC 9591 §4.2's `"invalid parameters"`, case 2).
    DuplicateParticipant,
};

/// RFC 9591 §4.2 `derive_interpolating_value` — the Lagrange coefficient
/// `lambda_i` at `x = 0` for participant `x_i` over the participant set
/// `participant_list`:
///
/// ```text
/// numerator = 1; denominator = 1
/// for x_j in participant_list, x_j != x_i:
///   numerator *= x_j
///   denominator *= (x_j - x_i)
/// return numerator / denominator   // Scalar field division = numerator * denominator.invert()
/// ```
///
/// THE threshold-specific core of the whole scheme: everything else in
/// FROST is "ordinary" (multi-party) Schnorr; this is what turns a
/// signer's raw Shamir SHARE `sk_i` into its correct WEIGHTED
/// contribution `lambda_i * sk_i` toward the group secret `s = f(0)` —
/// see `round2Sign`'s signature-share equation and `secretShareCombine`,
/// both of which call this. Pure scalar-field arithmetic
/// (`Secp256k1.scalar`'s `mul`/`sub`/`invert`) over PUBLIC identifiers —
/// no constant-time requirement against `participant_list`/`x_i`
/// themselves (RFC 9591 §7.1 lists this as a documented side-channel
/// consideration ONLY insofar as an implementation must still be careful
/// that `lambda_i * sk_i` — the SECRET-touching multiplication done by
/// the CALLER, not here — doesn't leak `sk_i`; this function's own
/// inputs/outputs are all public and its `invert()` calls
/// (`Secp256k1.scalar.Scalar.invert`) are already constant-time per
/// std's own implementation).
pub fn deriveInterpolatingValue(participant_list: []const Identifier, x_i: Identifier) DeriveInterpolatingValueError!Scalar {
    // RFC 9591 §4.2's two "invalid parameters" cases, surfaced as
    // distinct errors: x_i must appear in the list, and no x-coordinate
    // may appear twice. All identifiers are PUBLIC — the O(n^2) byte
    // compare and the early returns below are not secret-dependent.
    var found = false;
    for (participant_list, 0..) |x_j, j| {
        for (participant_list[j + 1 ..]) |x_k| {
            if (std.mem.eql(u8, &x_j.bytes, &x_k.bytes)) return error.DuplicateParticipant;
        }
        if (std.mem.eql(u8, &x_j.bytes, &x_i.bytes)) found = true;
    }
    if (!found) return error.NotInList;

    // numerator = prod x_j; denominator = prod (x_j - x_i), over j != i.
    // (Equivalently prod (0 - x_j)/(x_i - x_j): both signs flip, so the
    // quotient is identical — this is the RFC's own pseudocode form.)
    const xi = x_i.scalar();
    var numerator = Scalar.one;
    var denominator = Scalar.one;
    for (participant_list) |x_j| {
        if (std.mem.eql(u8, &x_j.bytes, &x_i.bytes)) continue;
        const xj = x_j.scalar();
        numerator = numerator.mul(xj);
        denominator = denominator.mul(xj.sub(xi));
    }
    // denominator is a product of nonzero factors (no duplicates, so
    // every x_j - x_i is nonzero), hence invertible.
    return numerator.mul(denominator.invert());
}

pub const ComputeBindingFactorsError = error{
    /// `encodeGroupCommitmentList`'s allocation failed.
    OutOfMemory,
};

/// RFC 9591 §4.4 `compute_binding_factors`:
///
/// ```text
/// group_public_key_enc = SerializeElement(group_public_key)   // Element.toBytes, Ne=33 bytes
/// msg_hash              = H4(msg)                              // h4(msg), 32 bytes
/// encoded_commitment_hash = H5(encode_group_commitment_list(commitment_list))  // h5(encodeGroupCommitmentList(...)), 32 bytes
/// rho_input_prefix = group_public_key_enc || msg_hash || encoded_commitment_hash   // 33+32+32 = 97 bytes
/// for (identifier, _, _) in commitment_list:
///   rho_input = rho_input_prefix || SerializeScalar(identifier)   // + 32 bytes = 129 bytes total
///   binding_factor = H1(rho_input)                                // h1(rho_input)
/// ```
///
/// Returns one `BindingFactor{identifier, factor}` per `commitment_list`
/// entry, in the same order, allocated via `allocator` (caller frees the
/// returned slice with the same allocator). Every sub-step (`h1`, `h4`,
/// `h5`, `encodeGroupCommitmentList`) is already REAL — this stub is
/// purely the composition/loop, but is listed as a CORE (not inlined
/// into `round2Sign`/`verifySignatureShare`/`aggregate` directly) because
/// it is the anti-forgery construction that ties each signer's binding
/// nonce to the ENTIRE commitment set (RFC 9591's own module doc-comment
/// framing: "the binding factor computation ... ties each participant's
/// binding nonce to the whole commitment set" — this is what makes a
/// FROST signature share non-malleable/non-reusable across different
/// commitment sets for the same message).
///
/// Byte-exact target: RFC 9591 Appendix E.5's `P1`/`P3`
/// `binding_factor_input` → `binding_factor` pairs (`kat_test.zig`).
pub fn computeBindingFactors(
    allocator: std.mem.Allocator,
    group_public_key: GroupPublicKey,
    commitment_list: []const SigningCommitments,
    msg: []const u8,
) ComputeBindingFactorsError![]BindingFactor {
    const encoded = try encodeGroupCommitmentList(allocator, commitment_list);
    defer allocator.free(encoded);

    // rho_input = SerializeElement(PK) || H4(msg) || H5(encoded list)
    //             || SerializeScalar(identifier)  — 33+32+32+32 = 129 bytes;
    // the first 97 bytes (the prefix) are shared across all participants.
    var rho_input: [Ne + 32 + 32 + Ns]u8 = undefined;
    rho_input[0..Ne].* = group_public_key.toBytes();
    rho_input[Ne..][0..32].* = h4(msg);
    rho_input[Ne + 32 ..][0..32].* = h5(encoded);

    const out = try allocator.alloc(BindingFactor, commitment_list.len);
    for (commitment_list, out) |entry, *slot| {
        rho_input[Ne + 64 ..][0..Ns].* = entry.identifier.toBytes();
        slot.* = .{ .identifier = entry.identifier, .factor = h1(&rho_input) };
    }
    return out;
}

pub const ComputeGroupCommitmentError = error{
    /// The summed group commitment landed on the identity element
    /// (`Element.fromPoint`'s own rejection) — RFC 9591 does not
    /// enumerate this as a named failure mode but it cannot be encoded
    /// as a valid `SerializeElement` output, so it MUST be surfaced as
    /// an error rather than silently producing an invalid `Signature.r`.
    InvalidElement,
};

/// RFC 9591 §4.5 `compute_group_commitment`:
///
/// ```text
/// group_commitment = Identity
/// for (identifier, hiding_nonce_commitment, binding_nonce_commitment) in commitment_list:
///   binding_factor = binding_factor_for_participant(binding_factor_list, identifier)   // REAL lookup
///   binding_nonce  = ScalarMult(binding_nonce_commitment, binding_factor)               // Secp256k1.mul
///   group_commitment = group_commitment + hiding_nonce_commitment + binding_nonce       // Secp256k1.add
/// return group_commitment
/// ```
///
/// This IS `aggregate`'s output `R` (RFC 9591 §5.3: `aggregate` calls
/// this directly and returns `(group_commitment, z)` verbatim) — so its
/// correctness is checked exactly when `aggregate`'s 65-byte output
/// matches RFC 9591 Appendix E.5's published `sig`'s first 33 bytes (see
/// the module doc comment's "what the vectors do NOT cover" note: this
/// ciphersuite's vector does not publish a standalone
/// `group_commitment` field).
pub fn computeGroupCommitment(commitment_list: []const SigningCommitments, binding_factor_list: []const BindingFactor) ComputeGroupCommitmentError!Element {
    var group_commitment = Secp256k1.identityElement;
    for (commitment_list) |entry| {
        // A missing binding factor (mismatched lists) makes the sum
        // impossible to evaluate — surfaced as InvalidElement, the only
        // failure this function's contract carries (a well-formed caller
        // always derives binding_factor_list from this same
        // commitment_list, so the lookup cannot fail there).
        const binding_factor = bindingFactorForParticipant(binding_factor_list, entry.identifier) catch
            return error.InvalidElement;
        const hiding = entry.hiding.point() catch return error.InvalidElement;
        const binding = entry.binding.point() catch return error.InvalidElement;
        // ScalarMult(binding_nonce_commitment, binding_factor): the
        // factor is public, but std's constant-time mul is used anyway;
        // it errors only on a zero factor / identity result (negligible
        // for an honestly-derived H1 output).
        const binding_scaled = binding.mul(binding_factor.toBytes(.big), .big) catch
            return error.InvalidElement;
        group_commitment = group_commitment.add(hiding).add(binding_scaled);
    }
    return Element.fromPoint(group_commitment) catch return error.InvalidElement;
}

pub const Round1CommitError = error{
    /// `Secp256k1.basePoint.mul` returned the identity element for one
    /// of the two nonces (only possible if the nonce Scalar is exactly
    /// zero — negligible probability for an honestly-generated
    /// `SigningNonces`, but `nonceGenerate`'s output is not itself
    /// guaranteed nonzero, so this MUST be checked, mirroring
    /// `bip340.sign`'s own defensive `k0 == 0`/identity checks).
    InvalidNonce,
};

/// RFC 9591 §5.1 `commit`'s public-commitment half:
///
/// ```text
/// hiding_nonce_commitment  = ScalarBaseMult(nonces.hiding)    // Secp256k1.basePoint.mul
/// binding_nonce_commitment = ScalarBaseMult(nonces.binding)   // Secp256k1.basePoint.mul
/// ```
///
/// Deterministic — takes the SECRET nonces directly (already produced by
/// `generateNonces`, which IS real, or supplied verbatim by a KAT vector
/// for reproducibility: RFC 9591 Appendix E.5 gives `P1 hiding_nonce`/
/// `P1 binding_nonce` directly) rather than generating them internally,
/// so this function alone has no RNG dependency and is fully replayable
/// against a fixed nonce pair. Byte-exact target: RFC 9591 Appendix
/// E.5's `P1`/`P3` `hiding_nonce_commitment`/`binding_nonce_commitment`
/// (`kat_test.zig`).
pub fn round1Commit(nonces: SigningNonces) Round1CommitError!NonceCommitmentPair {
    // ScalarBaseMult on each SECRET nonce — Secp256k1.mul is
    // constant-time; it errors exactly when the nonce is zero (identity
    // result), the defensive case Round1CommitError documents.
    const hiding_point = Secp256k1.combMulBase(nonces.hiding.toBytes(.big), .big) catch
        return error.InvalidNonce;
    const binding_point = Secp256k1.combMulBase(nonces.binding.toBytes(.big), .big) catch
        return error.InvalidNonce;
    return .{
        .hiding = Element.fromPoint(hiding_point) catch return error.InvalidNonce,
        .binding = Element.fromPoint(binding_point) catch return error.InvalidNonce,
    };
}

pub const Round2SignError = error{
    OutOfMemory,
    /// A sub-step (`computeBindingFactors`, `computeGroupCommitment`,
    /// `deriveInterpolatingValue`) failed.
    InvalidCommitmentList,
};

/// RFC 9591 §5.2 `sign` — a single participant's round-2 signature
/// share:
///
/// ```text
/// binding_factor_list = compute_binding_factors(group_public_key, commitment_list, msg)
/// binding_factor      = binding_factor_for_participant(binding_factor_list, identifier)
/// group_commitment     = compute_group_commitment(commitment_list, binding_factor_list)
/// participant_list     = participants_from_commitment_list(commitment_list)
/// lambda_i              = derive_interpolating_value(participant_list, identifier)
/// challenge             = compute_challenge(group_commitment, group_public_key, msg)
/// sig_share = nonces.hiding + (nonces.binding * binding_factor) + (lambda_i * signing_share * challenge)
/// ```
///
/// Every sub-step above already has a fixed FINAL signature in this
/// module (`computeBindingFactors`, `bindingFactorForParticipant`
/// (REAL), `computeGroupCommitment`, `participantsFromCommitmentList`
/// (REAL), `deriveInterpolatingValue`, `computeChallenge` (REAL)) — this
/// stub is the composition PLUS the signature-share equation itself
/// (the final line: `hiding + binding*rho + lambda*sk*e`, all
/// `Secp256k1.scalar` field ops on SECRET values — `nonces.hiding`,
/// `nonces.binding`, `signing_share` are all secret, so this
/// multiplication/addition chain is exactly the kind of secret-touching
/// arithmetic `Secp256k1.scalar`'s constant-time ops exist for).
///
/// `identifier` MUST be present in `commitment_list` (RFC 9591 §5.2:
/// "each participant MUST ensure that its identifier and commitments ...
/// appear in commitment_list" — this function does not itself validate
/// that its `nonces`/`signing_share` correspond to THIS `identifier`;
/// that binding is the caller's responsibility, same as the RFC's own
/// division of labor between "the signer validates its input" (§5.2's
/// prose, before calling `sign`) and `sign` itself).
///
/// Byte-exact target: RFC 9591 Appendix E.5's `P1`/`P3` `sig_share`
/// (`kat_test.zig`) — this is the strongest available check on
/// `computeChallenge`/`h2` for this ciphersuite (see the module doc
/// comment's "what the vectors do NOT cover" note).
pub fn round2Sign(
    allocator: std.mem.Allocator,
    identifier: Identifier,
    signing_share: SigningShare,
    group_public_key: GroupPublicKey,
    nonces: SigningNonces,
    msg: []const u8,
    commitment_list: []const SigningCommitments,
) Round2SignError!SignatureShare {
    const binding_factor_list = try computeBindingFactors(allocator, group_public_key, commitment_list, msg);
    defer allocator.free(binding_factor_list);
    const binding_factor = bindingFactorForParticipant(binding_factor_list, identifier) catch
        return error.InvalidCommitmentList;
    const group_commitment = computeGroupCommitment(commitment_list, binding_factor_list) catch
        return error.InvalidCommitmentList;

    const participant_list = try participantsFromCommitmentList(allocator, commitment_list);
    defer allocator.free(participant_list);
    const lambda_i = deriveInterpolatingValue(participant_list, identifier) catch
        return error.InvalidCommitmentList;

    const challenge = computeChallenge(group_commitment, group_public_key, msg);

    // sig_share = hiding_nonce + binding_nonce*binding_factor
    //           + lambda_i*sk_i*challenge — every operand touching a
    // SECRET (both nonces, sk_i) goes through Secp256k1.scalar's
    // constant-time field ops; no secret-dependent branching.
    const sig_share = nonces.hiding
        .add(nonces.binding.mul(binding_factor))
        .add(lambda_i.mul(signing_share.scalar()).mul(challenge));
    return SignatureShare.fromScalar(sig_share);
}

pub const AggregateError = error{
    OutOfMemory,
    InvalidCommitmentList,
};

/// RFC 9591 §5.3 `aggregate` — the Coordinator's final step:
///
/// ```text
/// binding_factor_list = compute_binding_factors(group_public_key, commitment_list, msg)
/// group_commitment     = compute_group_commitment(commitment_list, binding_factor_list)
/// z = sum(sig_shares)                       // Secp256k1.scalar addition, NOT secret-sensitive at this point (public shares)
/// return (group_commitment, z)
/// ```
///
/// `sig_shares` and `commitment_list` MUST correspond index-for-index to
/// the SAME `NUM_PARTICIPANTS` signers, in ANY order relative to each
/// other (this function only sums `sig_shares`; it does not need to
/// match a share to its signer — that matching only matters for
/// `verifySignatureShare`, called separately per RFC 9591 §5.3's own
/// "MAY verify each signature share individually" escape hatch).
///
/// Byte-exact target: RFC 9591 Appendix E.5's final `sig` (65 bytes: the
/// `R` component pins down `computeGroupCommitment`; the `z` component,
/// being the plain sum of the vector's own published `sig_share`
/// values, is checked once `round2Sign`'s equation is correct upstream)
/// — see `kat_test.zig`.
pub fn aggregate(
    allocator: std.mem.Allocator,
    commitment_list: []const SigningCommitments,
    msg: []const u8,
    group_public_key: GroupPublicKey,
    sig_shares: []const SignatureShare,
) AggregateError!Signature {
    const binding_factor_list = try computeBindingFactors(allocator, group_public_key, commitment_list, msg);
    defer allocator.free(binding_factor_list);
    const group_commitment = computeGroupCommitment(commitment_list, binding_factor_list) catch
        return error.InvalidCommitmentList;

    var z = Scalar.zero;
    for (sig_shares) |share| z = z.add(share.scalar());

    // Scalar.toBytes is always canonical, satisfying Signature's
    // trusted-internal-construction contract on .z (see zScalar's doc).
    return .{ .r = group_commitment, .z = z.toBytes(.big) };
}

pub const VerifySignatureShareError = error{
    OutOfMemory,
    InvalidCommitmentList,
};

/// RFC 9591 §5.3 `verify_signature_share` — lets the Coordinator (or
/// anyone holding "group info") check ONE participant's share BEFORE
/// aggregating, to identify a misbehaving signer (RFC 9591 §5.4
/// "Identifiable Abort"):
///
/// ```text
/// binding_factor_list = compute_binding_factors(group_public_key, commitment_list, msg)
/// binding_factor      = binding_factor_for_participant(binding_factor_list, identifier)
/// group_commitment     = compute_group_commitment(commitment_list, binding_factor_list)
/// comm_share = comm_i.hiding + ScalarMult(comm_i.binding, binding_factor)
/// challenge   = compute_challenge(group_commitment, group_public_key, msg)
/// participant_list = participants_from_commitment_list(commitment_list)
/// lambda_i           = derive_interpolating_value(participant_list, identifier)
/// l = ScalarBaseMult(sig_share_i)
/// r = comm_share + ScalarMult(PK_i, challenge * lambda_i)
/// return l == r
/// ```
///
/// Returns `false` on every failure path (malformed input, mismatched
/// equation) — like `bip340.verify`, NEVER panics/errors for "signature
/// doesn't verify"; the `!Error` union here is reserved for allocator
/// failure and a `commitment_list`/`identifier` inconsistency that makes
/// the equation impossible to even evaluate (e.g. `identifier` absent
/// from `commitment_list`), which are implementation-environment
/// failures distinct from "the share is invalid."
///
/// Byte-exact target: accepts RFC 9591 Appendix E.5's `P1`/`P3`
/// `sig_share` against their own `hiding_nonce_commitment`/
/// `binding_nonce_commitment`/`participant_share`-derived
/// `VerifyingShare`, and rejects a deliberately corrupted share
/// (`kat_test.zig`).
pub fn verifySignatureShare(
    allocator: std.mem.Allocator,
    identifier: Identifier,
    verifying_share: VerifyingShare,
    comm_i: NonceCommitmentPair,
    sig_share_i: SignatureShare,
    commitment_list: []const SigningCommitments,
    group_public_key: GroupPublicKey,
    msg: []const u8,
) VerifySignatureShareError!bool {
    const binding_factor_list = try computeBindingFactors(allocator, group_public_key, commitment_list, msg);
    defer allocator.free(binding_factor_list);
    // `identifier` absent from commitment_list is the documented
    // implementation-environment failure (the equation cannot even be
    // evaluated) — an error, not `false`.
    const binding_factor = bindingFactorForParticipant(binding_factor_list, identifier) catch
        return error.InvalidCommitmentList;
    // A malformed commitment element / degenerate sum is "the share
    // doesn't verify" territory: false, never a panic.
    const group_commitment = computeGroupCommitment(commitment_list, binding_factor_list) catch
        return false;

    const participant_list = try participantsFromCommitmentList(allocator, commitment_list);
    defer allocator.free(participant_list);
    const lambda_i = deriveInterpolatingValue(participant_list, identifier) catch
        return error.InvalidCommitmentList;

    const challenge = computeChallenge(group_commitment, group_public_key, msg);

    // comm_share = comm_i.hiding + ScalarMult(comm_i.binding, binding_factor)
    const hiding = comm_i.hiding.point() catch return false;
    const binding = comm_i.binding.point() catch return false;
    const binding_scaled = binding.mul(binding_factor.toBytes(.big), .big) catch return false;
    const comm_share = hiding.add(binding_scaled);

    // l = ScalarBaseMult(sig_share_i); r = comm_share + PK_i*(challenge*lambda_i)
    const l = Secp256k1.combMulBase(sig_share_i.toBytes(), .big) catch return false;
    const pk_i = verifying_share.point() catch return false;
    const pk_scaled = pk_i.mul(challenge.mul(lambda_i).toBytes(.big), .big) catch return false;
    const r = comm_share.add(pk_scaled);
    return l.equivalent(r);
}

/// RFC 9591 Appendix B `prime_order_verify` (via §6.5's "Signature
/// verification is as specified in Appendix B"), i.e. the ciphersuite's
/// single-Schnorr verify — what an ordinary (non-threshold) verifier
/// runs against the AGGREGATE `(R, z)` signature:
///
/// ```text
/// comm_enc = SerializeElement(sig.r)
/// pk_enc   = SerializeElement(group_public_key)
/// c = H2(comm_enc || pk_enc || msg)     // == computeChallenge(sig.r, group_public_key, msg)
/// l = ScalarBaseMult(sig.z)
/// r = sig.r + ScalarMult(group_public_key, c)
/// return l == r
/// ```
///
/// **NOT** `bip340.verify` — see the module doc comment's explicit
/// BIP340-compatibility finding (different element encoding, different
/// challenge preimage/tag, different signature length). Returns `false`
/// on every failure path (malformed `sig`/`group_public_key`, equation
/// mismatch), matching `bip340.verify`'s own never-panic/never-error
/// convention.
///
/// Byte-exact target: accepts RFC 9591 Appendix E.5's published `sig`
/// under its published `group_public_key`/`message`, and REJECTS a
/// deliberately tampered copy (flipped byte in `z`, or in `r`)
/// (`kat_test.zig`).
pub fn verify(msg: []const u8, sig: Signature, group_public_key: GroupPublicKey) bool {
    // Every failure path returns false — never panics/errors. The
    // explicit canonical check on sig.z guards a hand-constructed
    // `Signature` (struct-literal, not via fromBytes): std's point mul
    // computes with the raw 256-bit integer, so letting a non-canonical
    // z through would verify its reduced twin (a malleability hole).
    _ = Scalar.fromBytes(sig.z, .big) catch return false;
    const pk = group_public_key.point() catch return false;
    const r_point = sig.r.point() catch return false;

    const challenge = computeChallenge(sig.r, group_public_key, msg);

    // l = ScalarBaseMult(z); r = R + ScalarMult(PK, c)
    const l = Secp256k1.combMulBase(sig.z, .big) catch return false;
    const pk_scaled = pk.mul(challenge.toBytes(.big), .big) catch return false;
    const r = r_point.add(pk_scaled);
    return l.equivalent(r);
}

// ── Appendix C: Trusted Dealer Key Generation ────────────────────────────

/// One Shamir share as handed to a participant by the trusted dealer
/// (RFC 9591 Appendix C's `participant_private_keys` entry shape, and
/// the input shape `secret_share_combine` takes).
pub const ParticipantShare = struct {
    identifier: Identifier,
    signing_share: SigningShare,
};

pub const TrustedDealerKeygenResult = struct {
    /// One entry per participant `i` in `[1, max_participants]`, owned
    /// (caller frees with the same allocator passed to
    /// `trustedDealerKeygen`).
    shares: []ParticipantShare,
    /// `vss_commitment[0]` (RFC 9591 Appendix C: "trusted_dealer_keygen
    /// ... return participant_private_keys, vss_commitment[0],
    /// vss_commitment" — the group public key IS the constant-term VSS
    /// commitment).
    group_public_key: GroupPublicKey,
    /// Feldman VSS commitment to every coefficient of the sharing
    /// polynomial (RFC 9591 Appendix C.2 `vss_commit`), length
    /// `min_participants`, owned (caller frees). `vss_commitment[0] ==
    /// group_public_key`.
    vss_commitment: []Element,
};

pub const TrustedDealerKeygenError = error{
    OutOfMemory,
    /// `min_participants` is 0, or `coefficients.len !=
    /// min_participants - 1`, or `max_participants < min_participants`.
    InvalidParameters,
};

/// RFC 9591 Appendix C `trusted_dealer_keygen` (composed with
/// `secret_share_shard`, Appendix C.1, and `vss_commit`, Appendix C.2):
///
/// ```text
/// coefficients_full = [secret_key] + coefficients        // degree (min_participants - 1) polynomial f
/// for i in 1..=max_participants:
///   shares[i] = (i, polynomial_evaluate(Scalar(i), coefficients_full))   // Horner's method
/// vss_commitment[j] = ScalarBaseMult(coefficients_full[j])  for j in 0..min_participants
/// return shares, vss_commitment[0], vss_commitment
/// ```
///
/// Takes `coefficients` (length `min_participants - 1`, the
/// RANDOM/non-constant coefficients `a_1..a_{t-1}`) as a CALLER-SUPPLIED
/// parameter rather than sampling them internally via an RNG — the same
/// "deterministic entry point" shape as `round1Commit`'s caller-supplied
/// nonces, and for the identical reason: RFC 9591 Appendix E.5 publishes
/// `share_polynomial_coefficients[1]` directly (the ONE coefficient for
/// this vector's degree-1, `min_participants = 2` polynomial), so
/// feeding it straight in makes `trustedDealerKeygen` itself fully
/// replayable against the KAT. A real deployment's caller samples
/// `coefficients` via `Secp256k1.scalar.random`/`std.Io`.
///
/// Byte-exact target: RFC 9591 Appendix E.5's `group_secret_key` +
/// `share_polynomial_coefficients[1]` in → all 3 `Pn participant_share`
/// values AND `group_public_key` out (`kat_test.zig`).
pub fn trustedDealerKeygen(
    allocator: std.mem.Allocator,
    secret_key: Scalar,
    coefficients: []const Scalar,
    max_participants: u16,
    min_participants: u16,
) TrustedDealerKeygenError!TrustedDealerKeygenResult {
    if (min_participants == 0) return error.InvalidParameters;
    if (max_participants < min_participants) return error.InvalidParameters;
    if (coefficients.len != @as(usize, min_participants) - 1) return error.InvalidParameters;

    // Appendix C.1 secret_share_shard: evaluate the degree-(t-1)
    // polynomial f (coefficients_full = [secret_key] ++ coefficients)
    // at x = 1..max_participants via Horner's method. Coefficients and
    // the secret are SECRET — the loop bounds and indices are public
    // (participant count), and every field op is constant-time.
    const shares = try allocator.alloc(ParticipantShare, max_participants);
    errdefer allocator.free(shares);
    var i: u16 = 1;
    while (i <= max_participants) : (i += 1) {
        const id = Identifier.fromU16(i) catch unreachable; // i >= 1
        const x = id.scalar();
        var acc = Scalar.zero;
        var j: usize = coefficients.len;
        while (j > 0) : (j -= 1) acc = acc.mul(x).add(coefficients[j - 1]);
        const y = acc.mul(x).add(secret_key); // constant term last
        shares[i - 1] = .{ .identifier = id, .signing_share = SigningShare.fromScalar(y) };
    }

    // Appendix C.2 vss_commit: one base-point commitment per
    // coefficient of coefficients_full; vss_commitment[0] IS the group
    // public key. A zero secret/coefficient (identity commitment) is a
    // degenerate, invalid sharing polynomial → InvalidParameters.
    const vss_commitment = try allocator.alloc(Element, min_participants);
    errdefer allocator.free(vss_commitment);
    for (vss_commitment, 0..) |*slot, k| {
        const coeff = if (k == 0) secret_key else coefficients[k - 1];
        const point = Secp256k1.combMulBase(coeff.toBytes(.big), .big) catch
            return error.InvalidParameters;
        slot.* = Element.fromPoint(point) catch return error.InvalidParameters;
    }

    return .{
        .shares = shares,
        .group_public_key = vss_commitment[0],
        .vss_commitment = vss_commitment,
    };
}

pub const SecretShareCombineError = error{
    /// Fewer than 2 shares given, or duplicate/invalid identifiers among
    /// them (RFC 9591 Appendix C.1's `"invalid parameters"` on
    /// `secret_share_combine`, surfaced through `deriveInterpolatingValue`'s
    /// own duplicate/not-in-list checks).
    InvalidParameters,
};

/// RFC 9591 Appendix C.1 `secret_share_combine` (built on Appendix
/// C.1.1's `polynomial_interpolate_constant`):
///
/// ```text
/// x_coords = [i for (i, _) in shares]
/// f_zero = 0
/// for (i, y_i) in shares:
///   f_zero += y_i * derive_interpolating_value(x_coords, i)
/// return f_zero
/// ```
///
/// Reconstructs the group secret `s = f(0)` from ANY subset of at least
/// `MIN_PARTICIPANTS` shares (this function does not itself know
/// `MIN_PARTICIPANTS` — a caller passing too few shares gets a
/// mathematically WRONG `s` back, not an error, exactly per the RFC's
/// own text: "MUST be at minimum MIN_PARTICIPANTS secret shares" is a
/// caller-side precondition, not something `secret_share_combine` can
/// check from `shares` alone). Every `derive_interpolating_value` call
/// is `deriveInterpolatingValue` (stubbed above); this function is
/// itself listed as a separate CORE (not left for a caller to inline)
/// because it is the "shares reconstruct the group secret" property
/// `kat_test.zig` checks by name.
///
/// Byte-exact target: reconstructs RFC 9591 Appendix E.5's
/// `group_secret_key` from the vector's own `P1 participant_share` +
/// `P3 participant_share` (matching the vector's own `participant_list:
/// 1,3`), and from other 2-of-3 subsets of the same official shares
/// (`kat_test.zig`).
pub fn secretShareCombine(shares: []const ParticipantShare) SecretShareCombineError!Scalar {
    // Appendix C.1's own "invalid parameters" cases: fewer than 2
    // shares, or duplicate identifiers (deriveInterpolatingValue's
    // DuplicateParticipant, folded into InvalidParameters here).
    if (shares.len < 2) return error.InvalidParameters;
    for (shares, 0..) |a, i| {
        for (shares[i + 1 ..]) |b| {
            if (std.mem.eql(u8, &a.identifier.bytes, &b.identifier.bytes)) return error.InvalidParameters;
        }
    }

    // C.1.1 polynomial_interpolate_constant: f(0) = sum over shares of
    // y_i * lambda_i, lambda_i = derive_interpolating_value(x_coords, x_i).
    // This signature carries no allocator, so the x_coords slice
    // deriveInterpolatingValue would take cannot be materialized for an
    // arbitrary share count — the IDENTICAL §4.2 numerator/denominator
    // loop runs inline over the shares' own identifiers instead (same
    // math, same duplicate/membership guarantees via the check above;
    // x_i trivially "in the list" since it iterates the list itself).
    // The share values y_i are SECRET: they only ever flow through
    // constant-time Scalar.mul/.add; every branch below depends solely
    // on PUBLIC identifiers.
    var f_zero = Scalar.zero;
    for (shares) |share_i| {
        const xi = share_i.identifier.scalar();
        var numerator = Scalar.one;
        var denominator = Scalar.one;
        for (shares) |share_j| {
            if (std.mem.eql(u8, &share_j.identifier.bytes, &share_i.identifier.bytes)) continue;
            const xj = share_j.identifier.scalar();
            numerator = numerator.mul(xj);
            denominator = denominator.mul(xj.sub(xi));
        }
        const lambda_i = numerator.mul(denominator.invert());
        f_zero = f_zero.add(share_i.signing_share.scalar().mul(lambda_i));
    }
    return f_zero;
}

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ─────────────────────
test {
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
}

test "meta.model_after names RFC 9591 and the secp256k1 ciphersuite" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "RFC 9591") != null);
    try std.testing.expectEqualStrings("bip340", meta.deps[0]);
}

test "context_string matches RFC 9591 §6.5 exactly" {
    try std.testing.expectEqualStrings("FROST-secp256k1-SHA256-v1", context_string);
}

test "encoded_length constants match RFC 9591 §6.5's Ne=33/Ns=32" {
    try std.testing.expectEqual(@as(usize, 33), Element.encoded_length);
    try std.testing.expectEqual(@as(usize, 32), Identifier.encoded_length);
    try std.testing.expectEqual(@as(usize, 32), SigningShare.encoded_length);
    try std.testing.expectEqual(@as(usize, 32), SignatureShare.encoded_length);
    try std.testing.expectEqual(@as(usize, 65), Signature.encoded_length);
}

test "Identifier.fromU16 rejects zero" {
    try std.testing.expectError(error.InvalidIdentifier, Identifier.fromU16(0));
    _ = try Identifier.fromU16(1);
}

test "Element.fromBytes rejects the identity element" {
    // The identity element has no valid SEC1-compressed encoding under
    // fromSec1 (there is no (x, y) satisfying the curve equation that
    // fromSec1 would map to Secp256k1.identityElement), so this is
    // exercised indirectly: any structurally-invalid all-zero input is
    // rejected too.
    try std.testing.expectError(error.InvalidElement, Element.fromBytes([_]u8{0} ** 33));
}

test "sortCommitmentsByIdentifier sorts ascending by identifier" {
    var list = [_]SigningCommitments{
        .{ .identifier = try Identifier.fromU16(3), .hiding = undefined, .binding = undefined },
        .{ .identifier = try Identifier.fromU16(1), .hiding = undefined, .binding = undefined },
        .{ .identifier = try Identifier.fromU16(2), .hiding = undefined, .binding = undefined },
    };
    sortCommitmentsByIdentifier(&list);
    try std.testing.expectEqual(@as(u8, 1), list[0].identifier.bytes[31]);
    try std.testing.expectEqual(@as(u8, 2), list[1].identifier.bytes[31]);
    try std.testing.expectEqual(@as(u8, 3), list[2].identifier.bytes[31]);
}
