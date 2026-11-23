// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for `Blinding.fromSeedInto`: the
//! seed, the derived `b` and `f` must not survive below the call. The rest of
//! the module is in `stackprobe_test.zig`. ReleaseFast only
//! (`skipUnlessOptimized`).

const std = @import("std");
const group = @import("group.zig");
const n = @import("scalar.zig").field_order;
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 32 * 1024 });

var seed: [32]u8 = undefined;
var ref: group.Blinding = undefined;
var out: group.Blinding = undefined;

test "STACKPROBE: Blinding.fromSeedInto leaves no seed, b or f on the dead stack" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("k256 probe2 blinding seed", &seed, .{});
    group.Blinding.fromSeedInto(&ref, &seed);
    var b_be: [32]u8 = undefined;
    std.mem.writeInt(u256, &b_be, n - ref.neg_b, .big);
    var b_le = b_be;
    std.mem.reverse(u8, &b_le);
    const f_be = ref.f.toBytes(.big);
    const f_le = ref.f.toBytes(.little);
    _ = try P.run("Blinding.fromSeedInto", group.Blinding.fromSeedInto, .{ &out, &seed }, &.{ &seed, &b_be, &b_le, &f_be, &f_le }, .{});
    try std.testing.expect(std.mem.eql(u8, std.mem.asBytes(&ref), std.mem.asBytes(&out)));
}
