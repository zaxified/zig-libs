// SPDX-License-Identifier: MIT
//! RFC 8554 Appendix F known-answer tests.
//!
//! Test Case 1 is verification only (the RFC gives no private key for it).
//! Test Case 2 also gives the SEED and I of both trees (Appendix A
//! procedure), so the public keys and every deterministic part of the
//! signatures are regenerated. The randomizer `C` of an LM-OTS signature is
//! random in the RFC's run; feeding the RFC's own `C` back in reproduces both
//! LMS signatures byte for byte.

const std = @import("std");
const lms = @import("root.zig");
const core = @import("core.zig");
const kat = @import("kat_vectors.zig");

const tc1_pub = kat.bytes(kat.tc1_pub);
const tc1_msg = kat.bytes(kat.tc1_msg);
const tc1_sig = kat.bytes(kat.tc1_sig);
const tc2_pub = kat.bytes(kat.tc2_pub);
const tc2_msg = kat.bytes(kat.tc2_msg);
const tc2_sig = kat.bytes(kat.tc2_sig);

test "vectors: sizes match the RFC's field layout" {
    try std.testing.expectEqual(@as(usize, 60), tc1_pub.len);
    try std.testing.expectEqual(@as(usize, 60), tc2_pub.len);
    // u32 Nspk || LMS sig (H5/W8) || LMS pub || LMS sig (H5/W8)
    try std.testing.expectEqual(4 + 1292 + 56 + 1292, tc1_sig.len);
    // u32 Nspk || LMS sig (H10/W4) || LMS pub || LMS sig (H5/W8)
    try std.testing.expectEqual(4 + 2508 + 56 + 1292, tc2_sig.len);
    try std.testing.expectEqual(@as(usize, 1292), lms.lmsSignatureLength(.sha256_m32_h5, .sha256_n32_w8));
    try std.testing.expectEqual(@as(usize, 2508), lms.lmsSignatureLength(.sha256_m32_h10, .sha256_n32_w4));
    try std.testing.expectEqual(@as(usize, 2644), lms.hssSignatureLength(&.{
        .{ .lms = .sha256_m32_h5, .ots = .sha256_n32_w8 },
        .{ .lms = .sha256_m32_h5, .ots = .sha256_n32_w8 },
    }));
}

test "Test Case 1: the HSS signature verifies" {
    try std.testing.expect(lms.hssVerify(&tc1_pub, &tc1_msg, &tc1_sig));
    const pk = try lms.HssPublicKey.parse(&tc1_pub);
    try std.testing.expectEqual(@as(u8, 2), pk.levels);
    try std.testing.expectEqual(lms.ParamSet.sha256_m32_h5, pk.top.lms);
    try std.testing.expectEqual(lms.OtsParamSet.sha256_n32_w8, pk.top.ots);
    try std.testing.expectEqualSlices(u8, &tc1_pub, &pk.toBytes());
    try std.testing.expect(pk.verify(&tc1_msg, &tc1_sig));
    // The LMS layer alone: the final signature under the level-1 key.
    const l1 = tc1_sig[4 + 1292 ..][0..56];
    const final = tc1_sig[4 + 1292 + 56 ..];
    try std.testing.expect(lms.lmsVerify(l1, &tc1_msg, final));
    // ... and the level-1 key is signed by the first signature.
    try std.testing.expect(lms.lmsVerify(tc1_pub[4..], l1, tc1_sig[4..][0..1292]));
}

test "Test Case 2: the HSS signature verifies" {
    try std.testing.expect(lms.hssVerify(&tc2_pub, &tc2_msg, &tc2_sig));
    const pk = try lms.HssPublicKey.parse(&tc2_pub);
    try std.testing.expectEqual(lms.ParamSet.sha256_m32_h10, pk.top.lms);
    try std.testing.expectEqual(lms.OtsParamSet.sha256_n32_w4, pk.top.ots);
    const l1 = tc2_sig[4 + 2508 ..][0..56];
    try std.testing.expect(lms.lmsVerify(tc2_pub[4..], l1, tc2_sig[4..][0..2508]));
    try std.testing.expect(lms.lmsVerify(l1, &tc2_msg, tc2_sig[4 + 2508 + 56 ..]));
}

test "Test Case 2: both public keys regenerate from the RFC's SEED and I (Appendix A)" {
    const gpa = std.testing.allocator;
    const seed0 = kat.bytes(kat.tc2_seed0);
    const id0 = kat.bytes(kat.tc2_id0);
    const seed1 = kat.bytes(kat.tc2_seed1);
    const id1 = kat.bytes(kat.tc2_id1);

    // Top tree, via the HSS key (builds H10/W4: 1024 leaves).
    const levels = [_]lms.Level{
        .{ .lms = .sha256_m32_h10, .ots = .sha256_n32_w4 },
        .{ .lms = .sha256_m32_h5, .ots = .sha256_n32_w8 },
    };
    var sk = try lms.SecretKey.init(gpa, &levels, seed0, id0, null);
    defer sk.deinit();
    try std.testing.expectEqualSlices(u8, &tc2_pub, &sk.publicKey().toBytes());

    // Second-level tree (H5/W8): its public key is the one inside the signature.
    var t1 = try lms.Tree.init(gpa, .sha256_m32_h5, .sha256_n32_w8, id1, seed1);
    defer t1.deinit();
    const l1 = tc2_sig[4 + 2508 ..][0..56];
    try std.testing.expectEqualSlices(u8, l1, &t1.publicKey().toBytes());

    // sig[0]: leaf 3 of the top tree signs the level-1 public key. Same q,
    // message and RFC randomizer C => identical bytes, auth path included.
    const t0 = &sk.trees[0].?;
    const sig0 = tc2_sig[4..][0..2508];
    const c0: [32]u8 = sig0[8..40].*;
    var out0: [2508]u8 = undefined;
    t0.signWithRandomizer(3, l1, &c0, &out0);
    try std.testing.expectEqualSlices(u8, sig0, &out0);

    // final_signature: leaf 4 of the level-1 tree signs the message.
    const fin = tc2_sig[4 + 2508 + 56 ..];
    const c1: [32]u8 = fin[8..40].*;
    var out1: [1292]u8 = undefined;
    t1.signWithRandomizer(4, &tc2_msg, &c1, &out1);
    try std.testing.expectEqualSlices(u8, fin, &out1);
}

fn flipBit(buf: []u8, bit: usize) void {
    buf[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
}

test "Test Case 1: every bit of the public key and of the message is rejected" {
    var pk = tc1_pub;
    for (0..pk.len * 8) |bit| {
        flipBit(&pk, bit);
        try std.testing.expect(!lms.hssVerify(&pk, &tc1_msg, &tc1_sig));
        flipBit(&pk, bit);
    }
    var msg = tc1_msg;
    for (0..msg.len * 8) |bit| {
        flipBit(&msg, bit);
        try std.testing.expect(!lms.hssVerify(&tc1_pub, &msg, &tc1_sig));
        flipBit(&msg, bit);
    }
    try std.testing.expect(lms.hssVerify(&tc1_pub, &tc1_msg, &tc1_sig));
}

test "Test Case 1: bit flips in the signature are rejected" {
    // All eight bits of the first 64 bytes (Nspk, q, typecodes, C, y[0]) and of
    // the last 64 (the final path), and one rotating bit of every other byte:
    // 21 152 flips at every bit would cost ~130M hashes for no new branch.
    var sig = tc1_sig;
    for (0..sig.len) |i| {
        const all = i < 64 or i >= sig.len - 64;
        const first: usize = if (all) 0 else i % 8;
        const last: usize = if (all) 8 else i % 8 + 1;
        for (first..last) |b| {
            flipBit(&sig, i * 8 + b);
            try std.testing.expect(!lms.hssVerify(&tc1_pub, &tc1_msg, &sig));
            flipBit(&sig, i * 8 + b);
        }
    }
    try std.testing.expect(lms.hssVerify(&tc1_pub, &tc1_msg, &sig));
}

test "Test Case 2: tampering and length changes are rejected" {
    var sig = tc2_sig;
    for ([_]usize{ 0, 3, 4, 7, 8, 30, 100, 2000, 2508 + 4 + 5, 2508 + 4 + 40, tc2_sig.len - 1 }) |i| {
        sig[i] ^= 0x10;
        try std.testing.expect(!lms.hssVerify(&tc2_pub, &tc2_msg, &sig));
        sig[i] ^= 0x10;
    }
    var msg = tc2_msg;
    msg[msg.len - 1] ^= 1;
    try std.testing.expect(!lms.hssVerify(&tc2_pub, &msg, &tc2_sig));
    try std.testing.expect(!lms.hssVerify(&tc2_pub, &tc2_msg, tc2_sig[0 .. tc2_sig.len - 1]));
    try std.testing.expect(!lms.hssVerify(&tc2_pub, &tc2_msg, tc2_sig[0..4]));
    // Test Case 1's signature under Test Case 2's key and vice versa.
    try std.testing.expect(!lms.hssVerify(&tc2_pub, &tc1_msg, &tc1_sig));
    try std.testing.expect(!lms.hssVerify(&tc1_pub, &tc2_msg, &tc2_sig));
}
