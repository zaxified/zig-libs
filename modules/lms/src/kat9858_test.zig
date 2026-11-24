// SPDX-License-Identifier: MIT
//! RFC 9858 Appendix A known-answer tests: SHA-256/192 (Test Case 1, H5/W8),
//! SHAKE256/192 (2, H5/W8), SHAKE256/256 (3, H5/W8) and SHA-256/192 W4
//! (4, H20/W4). Every case gives the SEED and I (RFC 8554 Appendix A), so for
//! the H5 cases the public key is regenerated and the LMS signature reproduced
//! byte for byte with the RFC's randomizer `C`. Test Case 4's H20 tree (2^20
//! leaves) is not regenerated: its signature verifies, and its LM-OTS part is
//! reproduced from SEED, I and `C`.
//!
//! A 24-byte SEED is passed as the first 24 bytes of the module's 32-byte
//! seed (`params.n`); the rest is never read.

const std = @import("std");
const lms = @import("root.zig");
const core = @import("core.zig");
const kat = @import("kat_vectors.zig");
const v = @import("kat_vectors_9858.zig");

const Case = struct {
    seed: []const u8,
    id: [16]u8,
    pub_bytes: []const u8,
    msg: []const u8,
    sig: []const u8,
    lms: lms.ParamSet,
    ots: lms.OtsParamSet,
};

fn case(comptime k: u8, comptime set: lms.ParamSet, comptime ots: lms.OtsParamSet) Case {
    const p = std.fmt.comptimePrint("tc{d}_", .{k});
    return .{
        .seed = &kat.bytes(@field(v, p ++ "seed")),
        .id = kat.bytes(@field(v, p ++ "id")),
        .pub_bytes = &kat.bytes(@field(v, p ++ "pub")),
        .msg = &kat.bytes(@field(v, p ++ "msg")),
        .sig = &kat.bytes(@field(v, p ++ "sig")),
        .lms = set,
        .ots = ots,
    };
}

const tc1 = case(1, .sha256_m24_h5, .sha256_n24_w8);
const tc2 = case(2, .shake_m24_h5, .shake_n24_w8);
const tc3 = case(3, .shake_m32_h5, .shake_n32_w8);
const tc4 = case(4, .sha256_m24_h20, .sha256_n24_w4);

fn seed32(c: Case) [32]u8 {
    var s: [32]u8 = @splat(0);
    @memcpy(s[0..c.seed.len], c.seed);
    return s;
}

/// The parts every case shares: the layout, the parsed key, verification and
/// refusal of a flipped byte, and the LM-OTS signature regenerated from SEED,
/// I and the RFC's `C`.
fn checkCommon(c: Case) !void {
    const nb: usize = c.ots.nLen();
    try std.testing.expectEqual(c.seed.len, nb);
    try std.testing.expectEqual(4 + lms.LmsPublicKey.encodedLenFor(c.lms), c.pub_bytes.len);
    try std.testing.expectEqual(4 + lms.lmsSignatureLength(c.lms, c.ots), c.sig.len);
    const pk = try lms.HssPublicKey.parse(c.pub_bytes);
    try std.testing.expectEqual(@as(u8, 1), pk.levels);
    try std.testing.expectEqual(c.lms, pk.top.lms);
    try std.testing.expectEqual(c.ots, pk.top.ots);
    try std.testing.expectEqualSlices(u8, &c.id, &pk.top.id);
    var enc: [lms.HssPublicKey.max_encoded_len]u8 = undefined;
    try std.testing.expectEqualSlices(u8, c.pub_bytes, pk.encode(&enc));
    try std.testing.expect(lms.hssVerify(c.pub_bytes, c.msg, c.sig));
    try std.testing.expect(lms.lmsVerify(c.pub_bytes[4..], c.msg, c.sig[4..]));

    var bad: [2048]u8 = undefined;
    @memcpy(bad[0..c.sig.len], c.sig);
    bad[c.sig.len / 2] ^= 1;
    try std.testing.expect(!lms.hssVerify(c.pub_bytes, c.msg, bad[0..c.sig.len]));
    try std.testing.expect(!lms.hssVerify(c.pub_bytes, c.msg[0 .. c.msg.len - 1], c.sig));

    // LM-OTS part: u32 Nspk || u32 q || [ots signature] || ...
    const q = std.mem.readInt(u32, c.sig[4..8], .big);
    const ots_sig = c.sig[8..][0..c.ots.sigLen()];
    var rnd: [32]u8 = @splat(0);
    @memcpy(rnd[0..nb], ots_sig[4..][0..nb]);
    const seed = seed32(c);
    var got: [2048]u8 = undefined;
    core.otsSign(c.ots, &c.id, q, &seed, &rnd, c.msg, got[0..ots_sig.len]);
    try std.testing.expectEqualSlices(u8, ots_sig, got[0..ots_sig.len]);
}

/// The H5 cases: the whole key from SEED and I, and the LMS signature.
fn checkRegenerated(c: Case) !void {
    try checkCommon(c);
    const gpa = std.testing.allocator;
    const seed = seed32(c);
    var tree: lms.Tree = undefined;
    try lms.Tree.init(&tree, gpa, c.lms, c.ots, c.id, &seed);
    defer tree.deinit();
    var enc: [lms.LmsPublicKey.max_encoded_len]u8 = undefined;
    try std.testing.expectEqualSlices(u8, c.pub_bytes[4..], tree.publicKey().encode(&enc));

    const nb: usize = c.ots.nLen();
    const q = std.mem.readInt(u32, c.sig[4..8], .big);
    var rnd: [32]u8 = @splat(0);
    @memcpy(rnd[0..nb], c.sig[12..][0..nb]);
    var out: [2048]u8 = undefined;
    const got = try tree.signWithRandomizer(q, c.msg, &rnd, &out);
    try std.testing.expectEqualSlices(u8, c.sig[4..], got);
}

test "RFC 9858 A.1: SHA-256/192 H5/W8, key regenerated and signature reproduced" {
    // The hex is "SHA256-192"; the RFC's ASCII column beside it prints "SHA-256/192".
    try std.testing.expectEqualStrings("Test message for SHA256-192\n", tc1.msg);
    try checkRegenerated(tc1);
}

test "RFC 9858 A.2: SHAKE256/192 H5/W8, key regenerated and signature reproduced" {
    try checkRegenerated(tc2);
}

test "RFC 9858 A.3: SHAKE256/256 H5/W8, key regenerated and signature reproduced" {
    try checkRegenerated(tc3);
}

test "RFC 9858 A.4: SHA-256/192 H20/W4 verifies, LM-OTS part reproduced" {
    try checkCommon(tc4);
}

test "RFC 9858 §2.1: SHA-256/192 is SHA-256 truncated to 24 bytes" {
    var h = core.Hasher.init(.{ .hash = .sha256, .len = 24 });
    h.update("abc");
    const got = h.final();
    try std.testing.expectEqualSlices(u8, &kat.bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9c"), got[0..24]);
    try std.testing.expect(std.mem.allEqual(u8, got[24..], 0));
}

test "RFC 9858 sets sign and verify through HSS, two levels of different hashes" {
    const gpa = std.testing.allocator;
    const levels = [_]lms.Level{
        .{ .lms = .shake_m24_h5, .ots = .shake_n24_w4 },
        .{ .lms = .sha256_m24_h5, .ots = .sha256_n24_w8 },
    };
    var sk: lms.SecretKey = undefined;
    try lms.SecretKey.init(&sk, gpa, &levels, &seed32(tc1), tc1.id, null);
    defer sk.deinit();
    var pk_buf: [lms.HssPublicKey.max_encoded_len]u8 = undefined;
    const pk = sk.publicKey().encode(&pk_buf);
    try std.testing.expectEqual(@as(usize, 52), pk.len);
    var sig_buf: [4096]u8 = undefined;
    for (0..3) |i| {
        var m: [8]u8 = undefined;
        std.mem.writeInt(u64, &m, i, .little);
        const sig = try sk.sign(&m, &sig_buf);
        try std.testing.expectEqual(lms.hssSignatureLength(&levels), sig.len);
        try std.testing.expect(lms.hssVerify(pk, &m, sig));
        m[0] ^= 1;
        try std.testing.expect(!lms.hssVerify(pk, &m, sig));
    }
    // A level that pairs an LMS and an LM-OTS set of different hashes is refused.
    var bad: lms.SecretKey = undefined;
    try std.testing.expectError(error.InvalidLevels, lms.SecretKey.init(&bad, gpa, &.{.{ .lms = .shake_m24_h5, .ots = .sha256_n24_w4 }}, &seed32(tc1), tc1.id, null));
}
