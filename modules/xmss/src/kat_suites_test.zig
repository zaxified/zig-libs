// SPDX-License-Identifier: MIT
//! Per-suite known-answer tests against the RustCrypto `xmss` crate
//! (`kat_suites_vectors.zig`): for every RFC 8391 OPTIONAL and SP 800-208 set at
//! h = 10, (1) its two signatures verify under its public key here and a
//! flipped byte does not, (2) `keyGen` from the same seed gives the same wire
//! public key, and (3) `sign` reproduces both signatures byte for byte.
//! SHA-256 is included as the control (its root is also the C reference's).
//! (2) and (3) build a 2^10-leaf tree per suite: skipped in Debug.

const std = @import("std");
const builtin = @import("builtin");
const xmss = @import("root.zig");
const v = @import("kat_suites_vectors.zig");

fn hexLen(comptime s: []const u8) usize {
    @setEvalBranchQuota(10_000_000);
    var k: usize = 0;
    for (s) |c| {
        if (c != '\n') k += 1;
    }
    return k / 2;
}

fn unhex(comptime s: []const u8) [hexLen(s)]u8 {
    @setEvalBranchQuota(10_000_000);
    var out: [hexLen(s)]u8 = undefined;
    var k: usize = 0;
    var hi: ?u8 = null;
    for (s) |c| {
        if (c == '\n') continue;
        const d = std.fmt.charToDigit(c, 16) catch unreachable;
        if (hi) |x| {
            out[k] = x << 4 | d;
            k += 1;
            hi = null;
        } else hi = d;
    }
    return out;
}

const msgs = [_][]const u8{ "XMSS suite KAT message 0", "XMSS suite KAT message 1" };

fn check(comptime X: type, comptime tag: []const u8) !void {
    const pk_bytes = unhex(@field(v, tag ++ "_pk"));
    const sigs = [_][]const u8{ &unhex(@field(v, tag ++ "_sig0")), &unhex(@field(v, tag ++ "_sig1")) };
    try std.testing.expectEqual(X.public_key_length, pk_bytes.len);
    const pk = try X.PublicKey.fromBytes(&pk_bytes);
    for (sigs, msgs) |sig, m| {
        try std.testing.expectEqual(X.signature_length, sig.len);
        try std.testing.expect(X.verify(pk, m, sig));
        var bad: [X.signature_length]u8 = sig[0..X.signature_length].*;
        bad[X.signature_length / 2] ^= 1;
        try std.testing.expect(!X.verify(pk, m, &bad));
        try std.testing.expect(!X.verify(pk, "another message", sig));
    }

    if (builtin.mode == .debug) return; // the 2^10-leaf keygen below
    const n = X.S.n;
    var seed: [3 * n]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast(i);
    var kp: X.KeyPair = undefined;
    X.keyGen(&kp, seed[0..n], seed[n .. 2 * n], seed[2 * n ..]);
    defer kp.sk.zeroize();
    try std.testing.expectEqualSlices(u8, &pk_bytes, &kp.pk.toBytes());
    var out: [X.signature_length]u8 = undefined;
    for (sigs, msgs) |sig, m| {
        try X.sign(&kp.sk, &out, m);
        try std.testing.expectEqualSlices(u8, sig, &out);
    }
}

test "suite KAT: XMSS-SHA2_10_256 (control: same root as the C reference)" {
    try check(xmss.XmssSha2_10_256, "sha2_10_256");
}
test "suite KAT: XMSS-SHA2_10_512" {
    try check(xmss.XmssSha2_10_512, "sha2_10_512");
}
test "suite KAT: XMSS-SHAKE_10_256 (SHAKE128)" {
    try check(xmss.XmssShake_10_256, "shake_10_256");
}
test "suite KAT: XMSS-SHAKE_10_512 (SHAKE256)" {
    try check(xmss.XmssShake_10_512, "shake_10_512");
}
test "suite KAT: XMSS-SHA2_10_192 (SP 800-208)" {
    try check(xmss.XmssSha2_10_192, "sha2_10_192");
}
test "suite KAT: XMSS-SHAKE256_10_256 (SP 800-208)" {
    try check(xmss.XmssShake256_10_256, "shake256_10_256");
}
test "suite KAT: XMSS-SHAKE256_10_192 (SP 800-208)" {
    try check(xmss.XmssShake256_10_192, "shake256_10_192");
}
