// SPDX-License-Identifier: MIT

//! Replays what `tools/interop.zig --capture` froze from liblzma 5.8.1: our
//! compressed bytes must hash to the digest of liblzma's for every
//! (shape, option string, format) recorded, byte for byte and in length, and
//! the reference streams stored for the small shapes must decode to their
//! input.

const std = @import("std");
const testing = std.testing;
const lzma = @import("root.zig");
const corpus = @import("shapes.zig");
const spec = @import("spec.zig");
const td = @import("testdata/goldens.zig");

test "golden: compressed bytes equal liblzma 5.8.1's (SHA-256, length) for every recorded case" {
    const gpa = testing.allocator;
    try testing.expect(td.goldens.len > 100);
    var last: ?[]const u8 = null;
    var plain: []u8 = &.{};
    defer gpa.free(plain);
    for (td.goldens) |g| {
        if (last == null or !std.mem.eql(u8, last.?, g.shape)) {
            gpa.free(plain);
            plain = &.{};
            plain = try corpus.generate(gpa, corpus.find(g.shape).?);
            last = g.shape;
        }
        const o = try spec.parse(g.spec);
        const got = try lzma.compress(gpa, plain, spec.formatOf(g.format), .{ .lzma = o, .check = spec.checkOf(g.check) });
        defer gpa.free(got);
        var h: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(got, &h, .{});
        const hex = std.fmt.bytesToHex(h, .lower);
        testing.expectEqual(g.len, got.len) catch |e| {
            std.debug.print("{s} {s} {s}\n", .{ g.shape, g.spec, g.format });
            return e;
        };
        testing.expectEqualStrings(g.sha256, &hex) catch |e| {
            std.debug.print("{s} {s} {s}\n", .{ g.shape, g.spec, g.format });
            return e;
        };
    }
}

test "golden: liblzma's own streams decode to their input, and re-encode to themselves" {
    const gpa = testing.allocator;
    var n: usize = 0;
    for (td.goldens) |g| {
        const ref = g.stream orelse continue;
        const plain = try corpus.generate(gpa, corpus.find(g.shape).?);
        defer gpa.free(plain);
        const back = try lzma.decompress(gpa, ref, .xz, .{});
        defer gpa.free(back);
        try testing.expectEqualSlices(u8, plain, back);
        const again = try lzma.compress(gpa, plain, .xz, .{ .lzma = try spec.parse(g.spec), .check = spec.checkOf(g.check) });
        defer gpa.free(again);
        try testing.expectEqualSlices(u8, ref, again);
        n += 1;
    }
    try testing.expect(n >= 20);
}
