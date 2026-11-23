// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the authentication entry
//! points: `addPlaceholder` (a cleartext password goes through its TLV value
//! buffer), `sign` and `verify` (std's HMAC frames hold the key XOR ipad/opad).
//! ReleaseFast only (`skipUnlessOptimized`).

const std = @import("std");
const auth = @import("auth.zig");
const pdu = @import("pdu.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 32 * 1024 });

// 40 distinct bytes: an RFC 5310 key between L and B for SHA-256.
const key_bytes: [40]u8 = blk: {
    var k: [40]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @intCast(0x21 + i * 3);
    break :blk k;
};
const password = "a cleartext IS-IS area password!";

var pdu_buf: [1492]u8 = undefined;
var key_ipad: [40]u8 = undefined;
var key_opad: [40]u8 = undefined;

fn placeholderCleartext() !void {
    var b = try pdu.PsnpBuilder.init(&pdu_buf, .{ .source_id = @splat(0x11) });
    try auth.addPlaceholder(&b.tlvs, .{ .algorithm = .cleartext, .secret = password });
}

test "STACKPROBE: addPlaceholder, sign and verify leave no key or password on the dead stack" {
    try sp.skipUnlessOptimized();
    for (&key_ipad, &key_opad, key_bytes) |*i, *o, k| {
        i.* = k ^ 0x36;
        o.* = k ^ 0x5c;
    }
    const key: auth.Key = .{ .algorithm = .hmac_sha256, .id = 3, .secret = &key_bytes };
    const needles = &[_][]const u8{ &key_bytes, &key_ipad, &key_opad };

    var b = try pdu.PsnpBuilder.init(&pdu_buf, .{ .source_id = @splat(0x11) });
    try auth.addPlaceholder(&b.tlvs, key);
    const n = b.finish().len;
    _ = try P.run("sign", auth.sign, .{ pdu_buf[0..n], key }, needles, .{});
    _ = try P.run("verify", auth.verify, .{ pdu_buf[0..n], &[_]auth.Key{key} }, needles, .{});
    _ = try P.run("addPlaceholder cleartext", placeholderCleartext, .{}, &.{password}, .{});
}
