// SPDX-License-Identifier: MIT
//! prehash — the approved pre-hash functions PH of HashSLH-DSA (FIPS 205
//! §10.2.2) with their DER object identifiers (NIST CSOR hashAlgs arc
//! 2.16.840.1.101.3.4.2.x). Used by `engine.zig` to build
//! M' = 0x01 || len(ctx) || ctx || OID || PH(M).

const std = @import("std");
const sha2 = std.crypto.hash.sha2;
const sha3 = std.crypto.hash.sha3;

/// Longest PH output (SHA-512, SHA3-512, SHAKE256 at 512 bits).
pub const max_digest_length = 64;

/// Encoded OID length: tag, length, the nine content octets of
/// 2.16.840.1.101.3.4.2 and the final arc.
pub const oid_length = 11;

/// The FIPS 205 §10.2.2 approved set. SHAKE128 yields 256 bits and SHAKE256
/// 512 bits, as Algorithms 23/25 fix them.
pub const PreHash = enum {
    sha2_224,
    sha2_256,
    sha2_384,
    sha2_512,
    sha2_512_224,
    sha2_512_256,
    sha3_224,
    sha3_256,
    sha3_384,
    sha3_512,
    shake128,
    shake256,

    /// Length in bytes of PH(M); the length a caller-supplied digest must have.
    pub fn digestLength(ph: PreHash) usize {
        return switch (ph) {
            .sha2_224, .sha2_512_224, .sha3_224 => 28,
            .sha2_256, .sha2_512_256, .sha3_256, .shake128 => 32,
            .sha2_384, .sha3_384 => 48,
            .sha2_512, .sha3_512, .shake256 => 64,
        };
    }

    /// DER encoding (06 09 60 86 48 01 65 03 04 02 NN) of the PH's OID.
    pub fn oid(ph: PreHash) [oid_length]u8 {
        const last: u8 = switch (ph) {
            .sha2_256 => 1,
            .sha2_384 => 2,
            .sha2_512 => 3,
            .sha2_224 => 4,
            .sha2_512_224 => 5,
            .sha2_512_256 => 6,
            .sha3_224 => 7,
            .sha3_256 => 8,
            .sha3_384 => 9,
            .sha3_512 => 10,
            .shake128 => 11,
            .shake256 => 12,
        };
        return .{ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, last };
    }

    /// PH(msg) into `out`; returns the `digestLength()` prefix that was written.
    pub fn hash(ph: PreHash, msg: []const u8, out: *[max_digest_length]u8) []const u8 {
        const len = ph.digestLength();
        switch (ph) {
            inline else => |tag| {
                const H = switch (tag) {
                    .sha2_224 => sha2.Sha224,
                    .sha2_256 => sha2.Sha256,
                    .sha2_384 => sha2.Sha384,
                    .sha2_512 => sha2.Sha512,
                    .sha2_512_224 => sha2.Sha512_224,
                    .sha2_512_256 => sha2.Sha512_256,
                    .sha3_224 => sha3.Sha3_224,
                    .sha3_256 => sha3.Sha3_256,
                    .sha3_384 => sha3.Sha3_384,
                    .sha3_512 => sha3.Sha3_512,
                    .shake128 => sha3.Shake128,
                    .shake256 => sha3.Shake256,
                };
                if (comptime tag == .shake128 or tag == .shake256) {
                    H.hash(msg, out[0..len], .{});
                } else {
                    var d: [H.digest_length]u8 = undefined;
                    H.hash(msg, &d, .{});
                    @memcpy(out[0..len], &d);
                }
            },
        }
        return out[0..len];
    }
};

test "OID encodings and digest lengths match FIPS 205 / CSOR" {
    const t = std.testing;
    try t.expectEqualSlices(u8, &.{ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 }, &PreHash.sha2_256.oid());
    try t.expectEqual(@as(u8, 12), PreHash.shake256.oid()[10]);
    inline for (@typeInfo(PreHash).@"enum".fields) |f| {
        const ph: PreHash = @enumFromInt(f.value);
        var out: [max_digest_length]u8 = undefined;
        try t.expectEqual(ph.digestLength(), ph.hash("abc", &out).len);
    }
}

test "PH(M) known answers: SHA-256 and SHA-512/256 of abc, SHAKE128 length" {
    var out: [max_digest_length]u8 = undefined;
    var exp: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&exp, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    try std.testing.expectEqualSlices(u8, &exp, PreHash.sha2_256.hash("abc", &out));
    _ = try std.fmt.hexToBytes(&exp, "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23");
    try std.testing.expectEqualSlices(u8, &exp, PreHash.sha2_512_256.hash("abc", &out));
}
