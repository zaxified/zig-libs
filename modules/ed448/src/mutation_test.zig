// SPDX-License-Identifier: MIT
//! Tests that pin behaviour a delta mutation run (2026-11-25) found unobserved:
//! the worst-case path through the scalar fold chain, the DST length boundary
//! of `expand_message_xof`, and the Elligator 2 exceptional input `u = ±1`.

const std = @import("std");
const scalar = @import("scalar.zig");
const field = @import("field.zig");
const h2c = @import("h2c.zig");

const Fe = field.Fe;
const Shake256 = std.crypto.hash.sha3.Shake256;

test "mutation 2026-11-25: reduceWide worst case, f2 up to 2^464, pins the < 5L bound that makes folds 3 and 4 redundant" {
    const l: u1024 = std.mem.readInt(u456, &scalar.l_bytes, .little);
    const two448: u1024 = @as(u1024, 1) << 448;
    const delta4: u1024 = two448 % l; // 2^448 mod L, the constant every fold multiplies by
    const top: u1024 = @as(u1024, 1) << 912;
    // `fold(v) = (v mod 2^448) + (v >> 448) * delta4` is what one fold step computes.
    // Work backwards from a value T after fold 2 that is >= 2^448 (so fold 3 has a
    // high part) and whose low 448 bits are near 2^448 (so fold 3's own result
    // overflows 2^448 again and fold 4 is needed): f1 with fold(f1) = T, then a
    // digest x with fold(x) = f1.
    var checked: usize = 0;
    for ([_]u1024{ 1, 2, 3, 1 << 16 }) |hi3| {
        for ([_]u1024{ 0, 1, 2, 1000 }) |j| {
            const t: u1024 = hi3 * two448 + (two448 - 1 - j);
            const hi2 = (t - two448 + delta4) / delta4;
            const lo2 = t - hi2 * delta4;
            try std.testing.expect(lo2 < two448);
            const f1 = hi2 * two448 + lo2;
            const hi1 = f1 / delta4;
            const lo1 = f1 % delta4;
            const x = hi1 * two448 + lo1;
            try std.testing.expect(x < top);
            var digest: [114]u8 = undefined;
            std.mem.writeInt(u912, &digest, @intCast(x), .little);
            var want: [scalar.encoded_bytes]u8 = @splat(0);
            std.mem.writeInt(u456, &want, @intCast(x % l), .little);
            try std.testing.expectEqualSlices(u8, &want, &scalar.reduceWide(digest));
            checked += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 16), checked);
}

test "mutation 2026-11-25: expandMessageXof uses a 255-byte DST as is and reduces a 256-byte one" {
    var dst_buf: [256]u8 = undefined;
    for (&dst_buf, 0..) |*b, i| b.* = @intCast('a' + i % 26);
    for ([_]usize{ 255, 256 }) |n| {
        const dst = dst_buf[0..n];
        var h = Shake256.init(.{});
        h.update("msg");
        h.update(&[_]u8{ 0, 40 });
        if (n > 255) {
            var reduced: [56]u8 = undefined;
            var r = Shake256.init(.{});
            r.update("H2C-OVERSIZE-DST-");
            r.update(dst);
            r.squeeze(&reduced);
            h.update(&reduced);
            h.update(&[_]u8{56});
        } else {
            h.update(dst);
            h.update(&[_]u8{255});
        }
        var want: [40]u8 = undefined;
        h.squeeze(&want);
        const got = h2c.expandMessageXof(40, &.{"msg"}, dst);
        try std.testing.expectEqualSlices(u8, &want, &got);
    }
}

test "mutation 2026-11-25: Elligator 2 maps the exceptional inputs u = 1 and u = -1 as u = 0" {
    // RFC 9380 G.2.3: u^2 == 1 (Z*u^2 == -1) is forced to the same x1 = -J, xd = 1
    // case as u = 0; without that select xd = 0 and the map lands on another point.
    const q0 = h2c.mapToCurve(Fe.zero);
    try std.testing.expect(h2c.mapToCurve(Fe.one).equivalent(q0));
    try std.testing.expect(h2c.mapToCurve(Fe.one.neg()).equivalent(q0));
}
