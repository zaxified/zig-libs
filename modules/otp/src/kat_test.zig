// SPDX-License-Identifier: MIT
//! Known-answer tests: every RFC 4226 Appendix D count (0..9, including
//! the intermediate HMAC-SHA-1 digests and pre-modulo truncated integers)
//! and every RFC 6238 Appendix B row for all three hash functions, plus
//! the zero-padded formatting and the ±skew verify window.

const std = @import("std");
const otp = @import("root.zig");
const kat = @import("kat_vectors.zig");

test "RFC 4226 Appendix D: intermediate HMAC-SHA-1 digests" {
    const HmacSha1 = std.crypto.auth.hmac.HmacSha1;
    for (kat.rfc4226_vectors) |v| {
        var msg: [8]u8 = undefined;
        std.mem.writeInt(u64, &msg, v.count, .big);
        var mac: [HmacSha1.mac_length]u8 = undefined;
        HmacSha1.create(&mac, &msg, kat.rfc4226_secret);
        const hex = std.fmt.bytesToHex(mac, .lower);
        try std.testing.expectEqualStrings(v.hmac_hex, &hex);
    }
}

test "RFC 4226 Appendix D: dynamic truncation (pre-modulo integers)" {
    for (kat.rfc4226_vectors) |v| {
        try std.testing.expectEqual(
            v.truncated,
            otp.dynamicTruncate(.sha1, kat.rfc4226_secret, v.count),
        );
    }
    // The worked §5.4 example: count 0 truncates to 1284755224 → 755224.
    try std.testing.expectEqual(
        @as(u32, 1284755224),
        otp.dynamicTruncate(.sha1, kat.rfc4226_secret, 0),
    );
}

test "RFC 4226 Appendix D: 6-digit HOTP codes, counts 0..9" {
    for (kat.rfc4226_vectors) |v| {
        try std.testing.expectEqual(v.hotp6, otp.hotp(.sha1, kat.rfc4226_secret, v.count, 6));
    }
    try std.testing.expectEqual(@as(u32, 755224), otp.hotp(.sha1, kat.rfc4226_secret, 0, 6));
}

test "RFC 4226 Appendix D: formatted codes" {
    var buf: [8]u8 = undefined;
    for (kat.rfc4226_vectors) |v| {
        var want_buf: [8]u8 = undefined;
        const want = try std.fmt.bufPrint(&want_buf, "{d:0>6}", .{v.hotp6});
        try std.testing.expectEqualStrings(
            want,
            try otp.hotpFmt(.sha1, kat.rfc4226_secret, v.count, 6, &buf),
        );
    }
}

test "RFC 6238 Appendix B: time-step counters" {
    for (kat.rfc6238_vectors) |v| {
        try std.testing.expectEqual(v.t, otp.timeStep(v.unix_time, 30, 0));
    }
}

test "RFC 6238 Appendix B: all rows, SHA-1 + SHA-256 + SHA-512" {
    for (kat.rfc6238_vectors) |v| {
        try std.testing.expectEqual(v.sha1, otp.totp(.sha1, kat.rfc6238_secret_sha1, v.unix_time, 30, 0, 8));
        try std.testing.expectEqual(v.sha256, otp.totp(.sha256, kat.rfc6238_secret_sha256, v.unix_time, 30, 0, 8));
        try std.testing.expectEqual(v.sha512, otp.totp(.sha512, kat.rfc6238_secret_sha512, v.unix_time, 30, 0, 8));
    }
}

test "RFC 6238 Appendix B: leading-zero code formats as 07081804" {
    var buf: [8]u8 = undefined;
    try std.testing.expectEqualStrings(
        "07081804",
        try otp.totpFmt(.sha1, kat.rfc6238_secret_sha1, 1111111109, 30, 0, 8, &buf),
    );
}

test "totpVerify: exact step, skew 0" {
    for (kat.rfc6238_vectors) |v| {
        try std.testing.expect(otp.totpVerify(.sha1, kat.rfc6238_secret_sha1, v.unix_time, 30, 0, 8, v.sha1, 0));
        try std.testing.expect(otp.totpVerify(.sha256, kat.rfc6238_secret_sha256, v.unix_time, 30, 0, 8, v.sha256, 0));
        try std.testing.expect(otp.totpVerify(.sha512, kat.rfc6238_secret_sha512, v.unix_time, 30, 0, 8, v.sha512, 0));
    }
}

test "totpVerify: plus/minus one step window" {
    // T=59 is step 1; its code is the Appendix B row 0 code. At a clock
    // one step later (t=61..89 → step 2) it must be rejected with skew 0
    // but accepted with skew 1; two steps later only with skew 2.
    const code_step1: u32 = 94287082; // SHA-1 @ 59
    const key = kat.rfc6238_secret_sha1;
    try std.testing.expect(!otp.totpVerify(.sha1, key, 61, 30, 0, 8, code_step1, 0));
    try std.testing.expect(otp.totpVerify(.sha1, key, 61, 30, 0, 8, code_step1, 1));
    try std.testing.expect(!otp.totpVerify(.sha1, key, 91, 30, 0, 8, code_step1, 1));
    try std.testing.expect(otp.totpVerify(.sha1, key, 91, 30, 0, 8, code_step1, 2));
    // Forward direction: the step-2 code submitted while the clock is
    // still in step 1.
    const code_step2 = otp.totp(.sha1, key, 61, 30, 0, 8);
    try std.testing.expect(!otp.totpVerify(.sha1, key, 59, 30, 0, 8, code_step2, 0));
    try std.testing.expect(otp.totpVerify(.sha1, key, 59, 30, 0, 8, code_step2, 1));
}

test "totpVerify: wrong code rejected across the whole window" {
    const key = kat.rfc6238_secret_sha1;
    // 94287081 differs from every code in steps 0..3 (checked against the
    // generated values), so it must fail even with a wide window.
    const wrong: u32 = 94287081;
    var step: u64 = 0;
    while (step <= 3) : (step += 1) {
        try std.testing.expect(otp.hotp(.sha1, key, step, 8) != wrong);
    }
    try std.testing.expect(!otp.totpVerify(.sha1, key, 59, 30, 0, 8, wrong, 2));
}

test "totpVerify: window clamped at t0 (no underflow)" {
    const key = kat.rfc6238_secret_sha1;
    // unix_time 10 → step 0; skew 2 would reach steps -2..-1, which must
    // be skipped, while steps 0..2 are still checked.
    const code_step0 = otp.hotp(.sha1, key, 0, 8);
    const code_step2 = otp.hotp(.sha1, key, 2, 8);
    try std.testing.expect(otp.totpVerify(.sha1, key, 10, 30, 0, 8, code_step0, 2));
    try std.testing.expect(otp.totpVerify(.sha1, key, 10, 30, 0, 8, code_step2, 2));
}

test "non-default t0 shifts the step origin" {
    const key = kat.rfc6238_secret_sha1;
    // With t0 = 59 - 30 = 29, unix_time 59 lands in step 1 again.
    try std.testing.expectEqual(@as(u64, 1), otp.timeStep(59, 30, 29));
    try std.testing.expectEqual(
        otp.totp(.sha1, key, 59, 30, 0, 8),
        otp.totp(.sha1, key, 89, 30, 30, 8),
    );
}
