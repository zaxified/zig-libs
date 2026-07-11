// SPDX-License-Identifier: MIT
//! kat_test — SLH-DSA-SHA2-128f against the official NIST ACVP FIPS 205
//! known-answer vectors (see kat_vectors.zig for provenance), plus
//! keygen->sign->verify round-trips and tamper-rejection checks.

const std = @import("std");
const params = @import("params.zig");
const engine = @import("engine.zig");
const v = @import("kat_vectors.zig");

const Scheme = engine.SlhDsa(params.sha2_128f);
const sig_len = Scheme.signature_length;

fn hex(comptime len: usize, hex_str: []const u8) [len]u8 {
    var out: [len]u8 = undefined;
    const decoded = std.fmt.hexToBytes(&out, hex_str) catch unreachable;
    std.debug.assert(decoded.len == len);
    return out;
}

fn hexAlloc(gpa: std.mem.Allocator, hex_str: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, hex_str.len / 2);
    _ = std.fmt.hexToBytes(out, hex_str) catch unreachable;
    return out;
}

test "NIST ACVP keyGen tcId 21: seeds produce the exact pk and sk" {
    const kp = Scheme.keyGenFromSeed(
        hex(16, v.keygen_sk_seed),
        hex(16, v.keygen_sk_prf),
        hex(16, v.keygen_pk_seed),
    );
    try std.testing.expectEqualSlices(u8, &hex(32, v.keygen_pk), &kp.pk.toBytes());
    try std.testing.expectEqualSlices(u8, &hex(64, v.keygen_sk), &kp.sk.toBytes());
}

test "NIST ACVP sigGen tcId 115: deterministic internal signature is byte-exact" {
    const sk = Scheme.SecretKey.fromBytes(hex(64, v.det_sk));
    const msg = hex(1, v.det_msg);
    const expected = hex(sig_len, v.det_sig);

    var sig: [sig_len]u8 = undefined;
    Scheme.signInternal(&sig, &msg, sk, null);
    try std.testing.expectEqualSlices(u8, &expected, &sig);

    // The vector's pk must match the sk-embedded one and accept the sig.
    const pk = Scheme.PublicKey.fromBytes(hex(32, v.det_pk));
    try std.testing.expectEqualSlices(u8, &pk.toBytes(), &sk.pk.toBytes());
    try std.testing.expect(Scheme.verifyInternal(&sig, &msg, pk));
}

test "NIST ACVP sigGen tcId 2: deterministic pure signature with context is byte-exact" {
    const sk = Scheme.SecretKey.fromBytes(hex(64, v.pure_sk));
    const pk = Scheme.PublicKey.fromBytes(hex(32, v.pure_pk));
    const msg = hex(1, v.pure_msg);
    const ctx = hex(110, v.pure_ctx);
    const expected = hex(sig_len, v.pure_sig);

    var sig: [sig_len]u8 = undefined;
    try Scheme.sign(&sig, &msg, sk, &ctx, null);
    try std.testing.expectEqualSlices(u8, &expected, &sig);
    try std.testing.expect(Scheme.verify(&sig, &msg, pk, &ctx));

    // Same bytes must NOT verify under a different or missing context.
    try std.testing.expect(!Scheme.verify(&sig, &msg, pk, ""));
    var ctx2 = ctx;
    ctx2[0] ^= 1;
    try std.testing.expect(!Scheme.verify(&sig, &msg, pk, &ctx2));
}

test "NIST ACVP sigGen tcId 433: hedged internal signature is byte-exact" {
    const sk = Scheme.SecretKey.fromBytes(hex(64, v.rand_sk));
    const pk = Scheme.PublicKey.fromBytes(hex(32, v.rand_pk));
    const msg = hex(1, v.rand_msg);
    const addrnd = hex(16, v.rand_addrnd);
    const expected = hex(sig_len, v.rand_sig);

    var sig: [sig_len]u8 = undefined;
    Scheme.signInternal(&sig, &msg, sk, addrnd);
    try std.testing.expectEqualSlices(u8, &expected, &sig);
    try std.testing.expect(Scheme.verifyInternal(&sig, &msg, pk));
}

test "keygen -> sign -> verify round-trip; tampering rejects, never panics" {
    const gpa = std.testing.allocator;
    var seed: [48]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @truncate(i * 37 + 5);
    const kp = Scheme.keyGen(seed);

    const msg = "zig-libs slhdsa round-trip message";
    const ctx = "ctx";
    const sig = try gpa.alloc(u8, sig_len);
    defer gpa.free(sig);
    try Scheme.sign(sig[0..sig_len], msg, kp.sk, ctx, null);
    try std.testing.expect(Scheme.verify(sig, msg, kp.pk, ctx));

    // Flip one byte in each structural region of the signature:
    // R, FORS, and the hypertree tail. All must reject.
    for ([_]usize{ 0, 20, sig_len - 1 }) |pos| {
        sig[pos] ^= 0x01;
        try std.testing.expect(!Scheme.verify(sig, msg, kp.pk, ctx));
        sig[pos] ^= 0x01;
    }
    // Tampered message / wrong context / wrong key must reject.
    try std.testing.expect(!Scheme.verify(sig, "zig-libs slhdsa round-trip messagf", kp.pk, ctx));
    try std.testing.expect(!Scheme.verify(sig, msg, kp.pk, "ctx2"));
    var seed2 = seed;
    seed2[0] +%= 1;
    const kp2 = Scheme.keyGen(seed2);
    try std.testing.expect(!Scheme.verify(sig, msg, kp2.pk, ctx));

    // Malformed signature lengths: false, never a panic.
    try std.testing.expect(!Scheme.verify(sig[0 .. sig_len - 1], msg, kp.pk, ctx));
    try std.testing.expect(!Scheme.verify("", msg, kp.pk, ctx));
    const long = try gpa.alloc(u8, sig_len + 1);
    defer gpa.free(long);
    @memcpy(long[0..sig_len], sig);
    long[sig_len] = 0;
    try std.testing.expect(!Scheme.verify(long, msg, kp.pk, ctx));

    // Oversized context: sign errors, verify returns false.
    const big_ctx = try gpa.alloc(u8, 256);
    defer gpa.free(big_ctx);
    @memset(big_ctx, 0xAB);
    try std.testing.expectError(error.ContextTooLong, Scheme.sign(sig[0..sig_len], msg, kp.sk, big_ctx, null));
    try std.testing.expect(!Scheme.verify(sig, msg, kp.pk, big_ctx));
}

test "hedged and deterministic signatures differ but both verify" {
    var seed: [48]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @truncate(i +% 200);
    const kp = Scheme.keyGen(seed);
    const msg = "same message";

    var det_sig: [sig_len]u8 = undefined;
    var hedged_sig: [sig_len]u8 = undefined;
    try Scheme.sign(&det_sig, msg, kp.sk, "", null);
    try Scheme.sign(&hedged_sig, msg, kp.sk, "", @splat(0x5C));
    try std.testing.expect(!std.mem.eql(u8, &det_sig, &hedged_sig));
    try std.testing.expect(Scheme.verify(&det_sig, msg, kp.pk, ""));
    try std.testing.expect(Scheme.verify(&hedged_sig, msg, kp.pk, ""));
}

test "kat vector hex decodes to the FIPS 205 lengths" {
    const gpa = std.testing.allocator;
    inline for (.{ v.det_sig, v.pure_sig, v.rand_sig }) |sig_hex| {
        const sig = try hexAlloc(gpa, sig_hex);
        defer gpa.free(sig);
        try std.testing.expectEqual(@as(usize, 17088), sig.len);
    }
    try std.testing.expectEqual(@as(usize, 64), v.keygen_sk.len / 2);
    try std.testing.expectEqual(@as(usize, 32), v.keygen_pk.len / 2);
}
