// SPDX-License-Identifier: MIT
//! keys — BBS `KeyGen`/`SkToPk` (draft-irtf-cfrg-bbs-signatures-12
//! §3.4.1/§3.4.2) and the `SecretKey`/`PublicKey` wire types. REAL — both
//! functions are ordinary deterministic derivation (a `hash_to_scalar`
//! call and a fixed-base scalar multiplication), with no ZK judgment;
//! unlike `bbs.zig`'s four Fable cores, nothing here is gated.
//!
//! `SecretKey` wraps `ciphersuite.Fr` directly (a scalar `0 < sk < r`);
//! `PublicKey` wraps a `G2` point (`W = sk * BP2` — draft §3.3.1: "public
//! keys are in G2 and signatures in G1", the opposite convention from
//! `bls12_381.bls_sig`'s min-pk scheme, which puts public keys in `G1`).

const std = @import("std");
const cs = @import("ciphersuite.zig");
const burn = @import("burn.zig");

pub const Fr = cs.Fr;
pub const G2 = cs.G2;
/// The error set of `Fr.fromBytes` (a non-canonical encoding).
const FrError = @typeInfo(@typeInfo(@TypeOf(Fr.fromBytes)).@"fn".return_type.?).error_union.error_set;

pub const KeyGenError = error{
    /// draft §3.4.1 step 1: `key_material` MUST be at least 32 bytes.
    KeyMaterialTooShort,
    /// draft §3.4.1 step 2: `key_info` MUST be at most 65535 bytes.
    KeyInfoTooLong,
    /// `key_material.len + 2 + key_info.len` exceeds this file's fixed
    /// stack scratch buffer (`max_derive_input_len`) — a scaffold-stage
    /// ergonomic limit (no allocator param), not a draft requirement;
    /// every published test vector and any realistic real-world
    /// `key_material`/`key_info` pair is far under this. Raise
    /// `max_derive_input_len` (or add an allocator-taking overload) if a
    /// genuine caller needs more.
    DeriveInputTooLong,
    /// draft §3.4.1 step 5 ("if SK is INVALID, return INVALID"): the
    /// derived scalar happened to reduce to zero — astronomically
    /// unlikely (probability ~2^-255) for any real input; surfaced as an
    /// error rather than silently retried (unlike
    /// `bls12_381.bls_sig.keyGen`'s HKDF-based construction, which loops
    /// on a *counter* input already built into the draft's own
    /// `bls-signature` KeyGen — this BBS draft's KeyGen has no such
    /// retry mechanism to fall back on).
    InvalidSecretKey,
};

/// Generous fixed bound on `key_material.len + 2 + key_info.len` for
/// `keyGen`'s stack scratch buffer — see `KeyGenError.DeriveInputTooLong`.
const max_derive_input_len = 4096;

/// A BBS secret key: an `Fr` scalar `0 < sk < r` (`keyGen`'s
/// postcondition). Wraps `ciphersuite.Fr` directly — the draft does not
/// mandate a secret-key wire format; the plain 32-byte big-endian scalar
/// encoding is the common convention (same choice `bls12_381.bls_sig`'s
/// `SecretKey` makes).
pub const SecretKey = struct {
    scalar: Fr,

    pub const encoded_bytes = Fr.encoded_bytes; // 32

    /// REAL — delegates to `Fr.toBytes`. The encoding is a secret, so it is
    /// written to `out`, never returned through the stack.
    pub fn toBytes(self: *const SecretKey, out: *[encoded_bytes]u8) void {
        burn.run(burn.key_burn, void, toBytesBody, .{ self, out });
    }

    fn toBytesBody(self: *const SecretKey, out: *[encoded_bytes]u8) void {
        out.* = self.scalar.toBytes();
    }

    /// REAL — delegates to `Fr.fromBytes` (rejects `>= r`). Does NOT
    /// reject a decoded zero (a degenerate key, not a malformed
    /// encoding) — `keyGen` itself never returns one. The key is written to
    /// `out` (zeroed on error); `bytes` comes in by pointer. The body runs one
    /// frame down and the stack it dirtied is zeroed after it (`burn.zig`).
    pub fn fromBytes(out: *SecretKey, bytes: *const [encoded_bytes]u8) FrError!void {
        std.crypto.secureZero(u8, std.mem.asBytes(out));
        return burn.run(burn.key_burn, FrError!void, fromBytesBody, .{ out, bytes });
    }

    fn fromBytesBody(out: *SecretKey, bytes: *const [encoded_bytes]u8) FrError!void {
        out.scalar = try Fr.fromBytes(bytes.*);
    }

    /// Securely wipe the key material. `SecretKey` is a single fixed-size
    /// `Fr` scalar (no heap), so zeroing the struct's bytes erases it.
    /// Call when the key is no longer needed; the struct is left zeroed
    /// and must not be reused. Idempotent — safe to call more than once.
    pub fn deinit(self: *SecretKey) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

/// A BBS public key: a `G2` point (draft §3.3.1's "public keys in G2"
/// convention — the opposite of `bls12_381.bls_sig`'s min-pk scheme).
pub const PublicKey = struct {
    point: G2.Affine,

    pub const encoded_bytes = G2.compressed_bytes; // 96

    /// REAL — delegates to `G2.toBytesCompressed`.
    pub fn toBytes(self: PublicKey) [encoded_bytes]u8 {
        return G2.toBytesCompressed(self.point);
    }

    /// REAL — the draft's `KeyValidate` (§3.4.2): `G2.fromBytesCompressed`
    /// rejects any point outside the prime-order subgroup, then the identity
    /// is rejected here, so the pairing/challenge checks in `verify`/
    /// `proofVerify` only ever operate on the domain their soundness proof
    /// assumes (a cofactor-tainted key can otherwise sit outside that model).
    pub fn fromBytes(bytes: [encoded_bytes]u8) !PublicKey {
        const point = G2.fromBytesCompressed(bytes) catch |err|
            return if (err == error.NotInSubgroup) error.InvalidPublicKey else err;
        if (point.infinity) return error.InvalidPublicKey;
        return .{ .point = point };
    }
};

/// `KeyGen(key_material, key_info, key_dst)` (draft §3.4.1). `key_dst`
/// defaults to `ciphersuite.keygen_dst` when `null` (the draft's own
/// default-parameter convention).
///
/// Construction (draft §3.4.1, verbatim):
/// ```
/// 1. if length(key_material) < 32, return INVALID
/// 2. if length(key_info) > 65535, return INVALID
/// 3. derive_input = key_material || I2OSP(length(key_info), 2) || key_info
/// 4. SK = hash_to_scalar(derive_input, key_dst)
/// 5. if SK is INVALID (i.e. SK == 0), return INVALID
/// 6. return SK
/// ```
/// REAL — `ciphersuite.hashToScalar` is already real; this is pure
/// concatenation plus that call, no ZK judgment. Byte-exact against
/// draft-12 §8.4.1's key pair (see `kat_test.zig`).
///
/// The key is written to `out` (zeroed on error), never returned through the
/// stack; the body runs one frame down and the stack it dirtied — the
/// `key_material` copy in the derive buffer, `expand_message`'s blocks, the
/// reduced scalar — is zeroed after it (`burn.zig`).
pub fn keyGen(out: *SecretKey, key_material: []const u8, key_info: []const u8, key_dst: ?[]const u8) KeyGenError!void {
    return keyGenWith(cs.Sha256, out, key_material, key_info, key_dst);
}

/// `keyGen` under either ciphersuite (`cs.Sha256` / `cs.Shake256`): the
/// suite fixes the default `key_dst` and the `hash_to_scalar` expander.
pub fn keyGenWith(comptime Suite: type, out: *SecretKey, key_material: []const u8, key_info: []const u8, key_dst: ?[]const u8) KeyGenError!void {
    std.crypto.secureZero(u8, std.mem.asBytes(out));
    if (key_material.len < 32) return error.KeyMaterialTooShort;
    if (key_info.len > 65535) return error.KeyInfoTooLong;
    if (key_material.len + 2 + key_info.len > max_derive_input_len) return error.DeriveInputTooLong;
    const Body = struct {
        fn run(o: *SecretKey, km: []const u8, ki: []const u8, kd: ?[]const u8) KeyGenError!void {
            return keyGenBody(Suite, o, km, ki, kd);
        }
    };
    return burn.run(burn.keygen_burn, KeyGenError!void, Body.run, .{ out, key_material, key_info, key_dst });
}

fn keyGenBody(comptime Suite: type, out: *SecretKey, key_material: []const u8, key_info: []const u8, key_dst: ?[]const u8) KeyGenError!void {
    var buf: [max_derive_input_len]u8 = undefined;
    @memcpy(buf[0..key_material.len], key_material);
    std.mem.writeInt(u16, buf[key_material.len..][0..2], @intCast(key_info.len), .big);
    @memcpy(buf[key_material.len + 2 ..][0..key_info.len], key_info);
    const derive_input = buf[0 .. key_material.len + 2 + key_info.len];

    const dst = key_dst orelse Suite.keygen_dst;
    const sk = Suite.hashToScalar(derive_input, dst);
    if (sk.isZero()) return error.InvalidSecretKey;
    out.scalar = sk;
}

/// `SkToPk(SK)` (draft §3.4.2): `W = SK * BP2`. REAL — `G2.Jacobian`'s
/// scalar multiplication is already real (`bls12_381` Part 1). `sk` comes in
/// by pointer; the multiply runs one frame down and the stack it dirtied is
/// zeroed after it (`burn.zig`).
pub fn skToPk(sk: *const SecretKey) PublicKey {
    return burn.run(burn.key_burn, PublicKey, skToPkBody, .{sk});
}

fn skToPkBody(sk: *const SecretKey) PublicKey {
    const w = G2.Jacobian.fromAffine(cs.BP2).scalarMul(sk.scalar);
    return .{ .point = w.toAffine() };
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

// Test helpers over the pointer/out-param API: tests compare values, library
// code never returns a secret through the stack.
fn testKeyGen(key_material: []const u8, key_info: []const u8) KeyGenError!SecretKey {
    var sk: SecretKey = undefined;
    try keyGen(&sk, key_material, key_info, null);
    return sk;
}
fn testSecretKey(bytes: [SecretKey.encoded_bytes]u8) !SecretKey {
    var sk: SecretKey = undefined;
    try SecretKey.fromBytes(&sk, &bytes);
    return sk;
}
fn testSkBytes(sk: *const SecretKey) [SecretKey.encoded_bytes]u8 {
    var out: [SecretKey.encoded_bytes]u8 = undefined;
    sk.toBytes(&out);
    return out;
}

test "keyGen rejects key_material shorter than 32 bytes" {
    try testing.expectError(error.KeyMaterialTooShort, testKeyGen("short", ""));
}

test "keyGen rejects key_info longer than 65535 bytes" {
    const key_material = "0" ** 32;
    const big_info: [65536]u8 = @splat('a');
    try testing.expectError(error.KeyInfoTooLong, testKeyGen(key_material, &big_info));
}

test "keyGen length edges: 31 bytes refused, 32 accepted; 65535-byte key_info is not KeyInfoTooLong" {
    // Mutation run 2026-10-05: `< 31` and `>= 65535` both survived.
    try testing.expectError(error.KeyMaterialTooShort, testKeyGen("0" ** 31, ""));
    _ = try testKeyGen("0" ** 32, "");
    const info: [65535]u8 = @splat('a');
    try testing.expectError(error.DeriveInputTooLong, testKeyGen("0" ** 32, &info));
}

test "PublicKey.fromBytes refuses an on-twist point outside G2" {
    // x = u (c1 = 1, c0 = 0, wire order c1 || c0) is on the twist and not
    // in G2 (`bls12_381`'s g2 tests pin both facts).
    var bytes = [_]u8{0} ** PublicKey.encoded_bytes;
    bytes[0] = 0x80;
    bytes[47] = 1;
    _ = try G2.fromBytesCompressedUnchecked(bytes);
    try testing.expectError(error.InvalidPublicKey, PublicKey.fromBytes(bytes));
}

test "skToPk is a fixed-base scalar multiplication of BP2" {
    var sk_bytes = [_]u8{0} ** 32;
    sk_bytes[31] = 7;
    const sk = try testSecretKey(sk_bytes);
    const pk = skToPk(&sk);
    const expected = G2.Jacobian.fromAffine(cs.BP2).scalarMul(sk.scalar).toAffine();
    try testing.expectEqualSlices(u8, &G2.toBytesCompressed(expected), &pk.toBytes());
}

test "SecretKey / PublicKey byte round-trips" {
    var sk_bytes = [_]u8{0} ** 32;
    sk_bytes[31] = 42;
    const sk = try testSecretKey(sk_bytes);
    try testing.expectEqualSlices(u8, &sk_bytes, &testSkBytes(&sk));

    const pk = skToPk(&sk);
    const pk_bytes = pk.toBytes();
    const pk2 = try PublicKey.fromBytes(pk_bytes);
    try testing.expectEqualSlices(u8, &pk_bytes, &pk2.toBytes());
}

test "SecretKey.deinit zeroes the scalar" {
    var sk_bytes = [_]u8{0} ** 32;
    sk_bytes[31] = 99;
    var sk = try testSecretKey(sk_bytes);
    sk.deinit();
    try testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &testSkBytes(&sk));
}
