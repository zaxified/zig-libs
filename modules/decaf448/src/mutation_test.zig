// SPDX-License-Identifier: MIT
//! Tests the whole-module mutation run of 2026-11-25 asked for: the reduction
//! of a field element at or above p in the one-way map, the 255/256-byte DST
//! boundary of `expandMessageXof`, and a large sample of scalar inversions
//! against a big-integer oracle.

const std = @import("std");
const element = @import("element.zig");
const hash = @import("hash.zig");
const scalar = @import("scalar.zig");
const ed448 = @import("ed448");
const testing = std.testing;
const Shake256 = std.crypto.hash.sha3.Shake256;

test "mutation 2026-11-25: oneWayMap reduces a 56-byte input at or above p exactly (borrow chain of the subtraction)" {
    // x = p + 255 has bytes 0xfe, 0x00 x 27, 0xff ...: reducing it (255) borrows from byte 0.
    // x = 2^448 - 1 reduces to 2^224; x = p to 0.
    const p = ed448.field.p_bytes;
    var x255 = p;
    var carry: u16 = 255;
    for (&x255) |*b| {
        const s = @as(u16, b.*) + carry;
        b.* = @truncate(s);
        carry = s >> 8;
        if (carry == 0) break;
    }
    const ones: [56]u8 = @splat(0xff);
    var r255: [56]u8 = @splat(0);
    r255[0] = 255;
    var r224: [56]u8 = @splat(0);
    r224[28] = 1;
    const zero56: [56]u8 = @splat(0);
    const tail: [56]u8 = @splat(0x5a);
    const cases = [_][2][56]u8{ .{ x255, r255 }, .{ ones, r224 }, .{ p, zero56 } };
    for (cases) |c| {
        const got = element.oneWayMap(c[0] ++ tail);
        const want = element.oneWayMap(c[1] ++ tail);
        try testing.expect(got.equals(want));
        try testing.expectEqualSlices(u8, &want.encode(), &got.encode());
    }
}

test "mutation 2026-11-25: expandMessageXof takes a 255-byte DST as is and reduces a 256-byte one" {
    const msg = "boundary message";
    var dst: [256]u8 = undefined;
    for (&dst, 0..) |*b, i| b.* = @truncate(i *% 7 +% 1);
    var out: [48]u8 = undefined;
    // 255 bytes: SHAKE256(msg || len_be || dst || 255).
    try hash.expandMessageXof(&out, msg, dst[0..255]);
    var want: [48]u8 = undefined;
    var h = Shake256.init(.{});
    h.update(msg);
    h.update(&[2]u8{ 0, 48 });
    h.update(dst[0..255]);
    h.update(&[1]u8{255});
    h.squeeze(&want);
    try testing.expectEqualSlices(u8, &want, &out);
    // 256 bytes: the reduced DST (56 bytes) is used.
    try hash.expandMessageXof(&out, msg, dst[0..256]);
    const reduced = hash.reduceOversizeDst(dst[0..256]);
    var want2: [48]u8 = undefined;
    var h2 = Shake256.init(.{});
    h2.update(msg);
    h2.update(&[2]u8{ 0, 48 });
    h2.update(&reduced);
    h2.update(&[1]u8{reduced.len});
    h2.squeeze(&want2);
    try testing.expectEqualSlices(u8, &want2, &out);
}

test "mutation 2026-11-25: scalar.invert is the inverse for 30000 random 448-bit inputs (big-integer oracle)" {
    const l: u1024 = std.mem.readInt(u456, &ed448.scalar.l_bytes, .little);
    var prng = std.Random.DefaultPrng.init(0x5afe_6cd5);
    const rand = prng.random();
    for (0..30000) |_| {
        var a: scalar.CompressedScalar = undefined;
        rand.bytes(&a);
        const x: u1024 = std.mem.readInt(u448, &a, .little);
        const inv = scalar.invert(a);
        const iv: u1024 = std.mem.readInt(u448, &inv, .little);
        if (x % l == 0) {
            try testing.expectEqual(@as(u1024, 0), iv);
        } else {
            try testing.expect(iv < l);
            try testing.expectEqual(@as(u1024, 1), (x % l) * iv % l);
        }
    }
}
