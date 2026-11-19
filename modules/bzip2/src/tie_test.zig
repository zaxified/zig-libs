// SPDX-License-Identifier: MIT

//! Equal rotations: the order the fallback sort leaves them in decides the
//! origin pointer, so the bytes of a periodic block pin every tie decision of
//! the sort (insertion range, quicksort range, the blocks the main sort gives
//! up on). 240 inputs of repeated units against libbzip2 1.0.8's digests.

const std = @import("std");
const testing = std.testing;
const bz = @import("root.zig");
const corpus = @import("shapes.zig");
const td = @import("testdata/tie_data.zig");

test "ties: periodic and mixed-period blocks compress to libbzip2 1.0.8's bytes" {
    const gpa = testing.allocator;
    try testing.expectEqual(@as(usize, corpus.tie_inputs), td.ties.len);
    for (td.ties, 0..) |t, i| {
        const plain = try corpus.tieInput(gpa, @intCast(i));
        defer gpa.free(plain);
        const z = try bz.compress(gpa, plain, .{ .level = 9 });
        defer gpa.free(z);
        var h: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(z, &h, .{});
        const got = std.mem.readInt(u64, h[0..8], .big);
        if (z.len != t.len or got != t.digest) {
            std.debug.print("tie input {d}: {d} bytes, digest {x}; want {d}, {x}\n", .{ i, z.len, got, t.len, t.digest });
            return error.TestUnexpectedResult;
        }
    }
}
