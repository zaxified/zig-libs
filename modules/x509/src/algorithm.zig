// SPDX-License-Identifier: MIT
//! This module's own algorithm-identifier lookup.
//!
//! Every AlgorithmIdentifier OID `chain.zig` needed used to be resolved by
//! `std.crypto.Certificate.parseAlgorithmCategory`. That table is closed:
//! an OID it does not carry is `error.CertificateHasUnrecognizedObjectId`,
//! and `AlgorithmCategory` is an exhaustive enum, so there is no seam to
//! extend it from outside std. ML-DSA (RFC 9881, published 2025-10) is not
//! in it — so recognising a post-quantum certificate *at all* required this
//! module to own the lookup rather than borrow it.
//!
//! Only the lookup moved. The DER walk is still `Certificate`'s
//! (`parseElement`, `parseTime`, `parseBitString`, `parseNamedCurve`) and
//! the signature mathematics is still `std.crypto`'s — this file adds no
//! parser and no cryptography. What changed is that adding an algorithm no
//! longer waits on std adding it first.
//!
//! Std's table is consulted first and its answers are passed through
//! unchanged, so every certificate that verified before this file existed
//! resolves to exactly the same category by exactly the same bytes.

const std = @import("std");
const Certificate = std.crypto.Certificate;

/// FIPS 204 parameter set, as named by an X.509 AlgorithmIdentifier.
///
/// ML-DSA uses the SAME OID for the SubjectPublicKeyInfo algorithm and for
/// the `signatureAlgorithm` (RFC 9881 §3, §5.1) — unlike RSA and ECDSA,
/// where the key OID and the signature OID are different and the digest is
/// named by the latter. There is no digest to choose here: ML-DSA signs the
/// message itself, so the parameter set is the whole algorithm identity.
///
/// The AlgorithmIdentifier for these MUST have absent `parameters`
/// (RFC 9881 §3) — there is nothing to encode — which is why nothing in
/// this file takes a params element the way the EC branch does.
pub const MlDsa = enum {
    ml_dsa_44,
    ml_dsa_65,
    ml_dsa_87,

    /// `2.16.840.1.101.3.4.3.17` / `.18` / `.19` — NIST CSOR
    /// `sigAlgs` arc, assigned in RFC 9881 §5.1. First byte `0x60` is the
    /// packed `2.16` of every OID under `joint-iso-itu-t(2) country(16)`.
    pub const map = std.StaticStringMap(MlDsa).initComptime(.{
        .{ &.{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11 }, .ml_dsa_44 },
        .{ &.{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12 }, .ml_dsa_65 },
        .{ &.{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13 }, .ml_dsa_87 },
    });

    /// The `std.crypto.sign.mldsa` instantiation for this parameter set.
    /// A runtime `MlDsa` reaches its comptime type through `inline else` at
    /// the call site; this exists so the mapping is written down once.
    pub fn Impl(comptime self: MlDsa) type {
        return switch (self) {
            .ml_dsa_44 => std.crypto.sign.mldsa.MLDSA44,
            .ml_dsa_65 => std.crypto.sign.mldsa.MLDSA65,
            .ml_dsa_87 => std.crypto.sign.mldsa.MLDSA87,
        };
    }
};

/// What an AlgorithmIdentifier OID names, across both tables.
pub const Category = union(enum) {
    /// Resolved by std's own table, and reported with std's own spelling —
    /// the paths that hand a link to `Certificate.Parsed.verify` need the
    /// value to be bit-for-bit what std would have produced itself.
    std_category: Certificate.AlgorithmCategory,
    ml_dsa: MlDsa,
};

/// Resolve raw OID content bytes (no tag, no length), or `null` when
/// neither table names them. Callers turn `null` into
/// `error.CertificateHasUnrecognizedObjectId` — the same error std raised
/// for the same input before this file existed.
pub fn fromOid(oid: []const u8) ?Category {
    if (Certificate.AlgorithmCategory.map.get(oid)) |c| return .{ .std_category = c };
    if (MlDsa.map.get(oid)) |p| return .{ .ml_dsa = p };
    return null;
}

/// What kind of key a SubjectPublicKeyInfo holds — this module's
/// `Certificate.Parsed.PubKeyAlgo`, with the one variant std has no name
/// for. The four shared variants keep std's exact names so the two types
/// read as the same list.
pub const PubKeyAlgo = union(enum) {
    rsaEncryption,
    rsassa_pss,
    X9_62_id_ecPublicKey: Certificate.NamedCurve,
    curveEd25519,
    ml_dsa: MlDsa,

    /// The std spelling of the same value, for the links this module still
    /// delegates to `Certificate.Parsed.verify`. `null` for an algorithm
    /// std cannot name — a caller reaching that has already taken, or must
    /// take, its own path.
    pub fn toStd(self: PubKeyAlgo) ?Certificate.Parsed.PubKeyAlgo {
        return switch (self) {
            .rsaEncryption => .rsaEncryption,
            .rsassa_pss => .rsassa_pss,
            .X9_62_id_ecPublicKey => |curve| .{ .X9_62_id_ecPublicKey = curve },
            .curveEd25519 => .curveEd25519,
            .ml_dsa => null,
        };
    }
};

const testing = std.testing;

test "fromOid: std's table answers first, and with std's own spelling" {
    // rsaEncryption, ecPublicKey, Ed25519 — the bytes are std's own map keys,
    // written out here so a change to either table shows up as a test failure
    // rather than as a certificate that silently stops verifying.
    const rsa_oid = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
    const ec_oid = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
    const ed_oid = [_]u8{ 0x2B, 0x65, 0x70 };

    try testing.expectEqual(Certificate.AlgorithmCategory.rsaEncryption, fromOid(&rsa_oid).?.std_category);
    try testing.expectEqual(Certificate.AlgorithmCategory.X9_62_id_ecPublicKey, fromOid(&ec_oid).?.std_category);
    try testing.expectEqual(Certificate.AlgorithmCategory.curveEd25519, fromOid(&ed_oid).?.std_category);
}

test "fromOid: the three ML-DSA parameter sets std has no name for" {
    const oid44 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11 };
    const oid65 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12 };
    const oid87 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13 };

    try testing.expectEqual(MlDsa.ml_dsa_44, fromOid(&oid44).?.ml_dsa);
    try testing.expectEqual(MlDsa.ml_dsa_65, fromOid(&oid65).?.ml_dsa);
    try testing.expectEqual(MlDsa.ml_dsa_87, fromOid(&oid87).?.ml_dsa);

    // The point of the whole file: std cannot answer these.
    try testing.expectEqual(@as(?Certificate.AlgorithmCategory, null), Certificate.AlgorithmCategory.map.get(&oid65));
}

test "fromOid: an unassigned neighbour in the same arc is not recognised" {
    // .16 and .20 bracket the ML-DSA assignments (.20 is SLH-DSA, which this
    // module does not implement). A map that matched on a prefix, or that
    // ignored the last byte, would answer here.
    const below = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x10 };
    const above = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x14 };
    const truncated = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03 };

    try testing.expect(fromOid(&below) == null);
    try testing.expect(fromOid(&above) == null);
    try testing.expect(fromOid(&truncated) == null);
}

test "Impl: each parameter set reaches the FIPS 204 sizes for that level" {
    // Table 2 of FIPS 204. Wrong wiring in `Impl` compiles fine and then
    // rejects every real certificate, so the sizes are asserted directly.
    try testing.expectEqual(@as(usize, 1312), MlDsa.Impl(.ml_dsa_44).PublicKey.encoded_length);
    try testing.expectEqual(@as(usize, 2420), MlDsa.Impl(.ml_dsa_44).Signature.encoded_length);
    try testing.expectEqual(@as(usize, 1952), MlDsa.Impl(.ml_dsa_65).PublicKey.encoded_length);
    try testing.expectEqual(@as(usize, 3309), MlDsa.Impl(.ml_dsa_65).Signature.encoded_length);
    try testing.expectEqual(@as(usize, 2592), MlDsa.Impl(.ml_dsa_87).PublicKey.encoded_length);
    try testing.expectEqual(@as(usize, 4627), MlDsa.Impl(.ml_dsa_87).Signature.encoded_length);
}

test "toStd: the four shared variants round-trip, ML-DSA reports absence" {
    try testing.expectEqual(Certificate.AlgorithmCategory.rsaEncryption, PubKeyAlgo.toStd(.rsaEncryption).?);
    try testing.expectEqual(Certificate.AlgorithmCategory.rsassa_pss, PubKeyAlgo.toStd(.rsassa_pss).?);
    try testing.expectEqual(Certificate.AlgorithmCategory.curveEd25519, PubKeyAlgo.toStd(.curveEd25519).?);
    try testing.expectEqual(
        Certificate.NamedCurve.secp384r1,
        PubKeyAlgo.toStd(.{ .X9_62_id_ecPublicKey = .secp384r1 }).?.X9_62_id_ecPublicKey,
    );
    try testing.expect(PubKeyAlgo.toStd(.{ .ml_dsa = .ml_dsa_65 }) == null);
}
