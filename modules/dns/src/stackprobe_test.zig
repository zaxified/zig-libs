// SPDX-License-Identifier: MIT

//! Dead-stack probe for `tsig.sign` / `tsig.verify` (`testkit.stackprobe`):
//! residue below each burn, and the secret plus the two HMAC key blocks it
//! becomes (secret ^ ipad, secret ^ opad) as needles in any frame. ReleaseFast
//! only (`skipUnlessOptimized`, a runtime skip, so the body is type-checked
//! in every mode).

const std = @import("std");
const tsig = @import("tsig.zig");
const message = @import("message.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 32 * 1024 });

var secret: [64]u8 = undefined;
var ipad: [128]u8 = undefined;
var opad: [128]u8 = undefined;
var buf: [512]u8 = undefined;
var mac: tsig.Mac = undefined;

test "STACKPROBE: no TSIG secret residue after sign / verify" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha512.hash("dns tsig probe secret", &secret, .{});
    // HMAC-SHA512's block is 128 bytes: the secret, zero-padded, xored.
    for (&ipad, &opad, 0..) |*i, *o, n| {
        const k: u8 = if (n < secret.len) secret[n] else 0;
        i.* = k ^ 0x36;
        o.* = k ^ 0x5c;
    }
    const secrets = [_][]const u8{ &secret, &ipad, &opad };
    const key: tsig.Key = .{ .name = "probe.key", .algorithm = .hmac_sha512, .secret = &secret };

    const q = try message.encodeQuery(&buf, "example.org", .soa, .{ .edns_udp_size = null });
    _ = try P.run("sign", tsig.sign, .{ @as([]u8, &buf), q.len, &key, tsig.SignOptions{ .time = 1_760_000_000 }, &mac }, &secrets, .{});
    const signed_len = q.len + tsig.recordLen(&key);
    _ = try P.run("verify", tsig.verify, .{ @as([]const u8, buf[0..signed_len]), &key, tsig.VerifyOptions{ .now = 1_760_000_000 }, &mac }, &secrets, .{});
}
