// SPDX-License-Identifier: MIT

//! Frames written by the reference lz4 CLI (v1.10.0; recipe
//! `tools/capture-goldens.sh`): default, linked 64 KB blocks with content size
//! and block checksums, HC level 12, `--fast=9`, legacy, stored blocks. Each
//! must decode to an input with the recorded SHA-256, and re-encode through
//! this module's compressor to a frame that decodes to the same bytes.

const std = @import("std");
const testing = std.testing;
const lz4 = @import("root.zig");
const goldens = @import("testdata/goldens.zig").goldens;

test "goldens: lz4 CLI frames decode to the recorded inputs" {
    const gpa = testing.allocator;
    for (goldens) |g| {
        const plain = lz4.decompress(gpa, g.frame, .{}) catch |e| {
            std.debug.print("golden {s} ({s}): {t}\n", .{ g.name, g.flags, e });
            return e;
        };
        defer gpa.free(plain);
        try testing.expectEqual(g.len, plain.len);
        var h: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(plain, &h, .{});
        const hex = std.fmt.bytesToHex(h, .lower);
        try testing.expectEqualStrings(g.sha256, &hex);

        const z = try lz4.compress(gpa, plain, .{ .content_checksum = true });
        defer gpa.free(z);
        const back = try lz4.decompress(gpa, z, .{});
        defer gpa.free(back);
        try testing.expectEqualSlices(u8, plain, back);
    }
}

test "goldens: every damaged byte of a checksummed frame is caught" {
    // hello-default carries a content checksum: a single bit flip is refused
    // or, where it lands on bits the format ignores (the match-length nibble
    // of the literal-only last token), decodes to the same bytes.
    const gpa = testing.allocator;
    const g = goldens[1];
    try testing.expectEqualStrings("hello-default", g.name);
    var buf: [64]u8 = undefined;
    var accepted: usize = 0;
    for (0..g.frame.len) |i| {
        for (0..8) |bit| {
            @memcpy(buf[0..g.frame.len], g.frame);
            buf[i] ^= @as(u8, 1) << @intCast(bit);
            if (lz4.decompress(gpa, buf[0..g.frame.len], .{})) |out| {
                defer gpa.free(out);
                if (!std.mem.eql(u8, out, "hello hello hello hello world\n")) {
                    std.debug.print("byte {d} bit {d} accepted as other bytes\n", .{ i, bit });
                    return error.TestUnexpectedResult;
                }
                accepted += 1;
            } else |_| {}
        }
    }
    // The four low bits of the last token (byte 20).
    try testing.expectEqual(@as(usize, 4), accepted);
}
