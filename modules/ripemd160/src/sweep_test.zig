// SPDX-License-Identifier: MIT

//! No-panic sweep tests (wave GT, gt-a).

const std = @import("std");
const testing = std.testing;
const Ripemd160 = @import("root.zig").Ripemd160;

test "final twice / update after final never leaves buf_len at 64 (sweep RM-1)" {
    // 63 buffered bytes: the 0x80 terminator fills the block (buf_len -> 64)
    // and `final` takes the "pad, compress, fresh zero block" path.
    var msg: [63]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = @intCast(i);
    var d = Ripemd160.init(.{});
    d.update(&msg);
    var out: [20]u8 = undefined;
    var first: [20]u8 = undefined;
    d.final(&first);
    // Misuse sequences: the digest is unspecified, but nothing may trap or
    // write out of bounds, for any number of repeats.
    for (0..200) |_| d.final(&out);
    d.update("x");
    d.final(&out);
    // And the sequence starting at every residue.
    for (0..130) |len| {
        var e = Ripemd160.init(.{});
        e.update(msg[0..@min(len, 63)]);
        e.update(msg[0..@min(len -| 63, 63)]);
        for (0..70) |_| e.final(&out);
        e.update(&msg);
        e.final(&out);
    }
    // The first digest is still the correct one.
    var ref: [20]u8 = undefined;
    Ripemd160.hash(&msg, &ref, .{});
    try testing.expectEqualSlices(u8, &ref, &first);
}
