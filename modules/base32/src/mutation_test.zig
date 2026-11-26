// SPDX-License-Identifier: MIT
//! Whole-module mutation tests (2026-11-25): the corners the RFC vectors and the fuzz
//! drivers do not pin down.

const std = @import("std");
const testing = std.testing;
const b32 = @import("root.zig");

test "mutation 2026-11-25: encodeAlloc sizes the allocation by the options (unpadded result freed whole)" {
    const out = try b32.encodeAlloc(testing.allocator, "foob", .{ .pad = false });
    defer testing.allocator.free(out); // the allocator checks the length it is given back
    try testing.expectEqualStrings("MZXW6YQ", out);
}

test "mutation 2026-11-25: Encoder.write takes a dest of exactly writeLenUpperBound and emits a group the moment it is complete" {
    var e: b32.Encoder = .init(.{});
    var buf: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try e.write(&buf, "foo"));
    // 3 pending + 2 new = exactly one group: it is written now, into a dest of exactly its size.
    try testing.expectEqual(@as(usize, 8), e.writeLenUpperBound(2));
    try testing.expectEqual(@as(usize, 8), try e.write(&buf, "ba"));
    try testing.expectEqualStrings("MZXW6YTB", &buf);
    try testing.expectEqual(@as(usize, 0), e.npending);
    // The same for a first write of exactly one group.
    var e2: b32.Encoder = .init(.{});
    try testing.expectEqual(@as(usize, 8), try e2.write(&buf, "fooba"));
}

test "mutation 2026-11-25: Encoder.finish wipes the buffered plaintext" {
    var e: b32.Encoder = .init(.{});
    var buf: [16]u8 = undefined;
    _ = try e.write(&buf, "ab");
    try testing.expect(std.mem.eql(u8, e.pending[0..2], "ab"));
    _ = try e.finish(&buf);
    for (e.pending) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "mutation 2026-11-25: a Decoder fault from write is sticky for finish too" {
    var d: b32.Decoder = .init(.{});
    var out: [16]u8 = undefined;
    try testing.expectError(error.InvalidCharacter, d.write(&out, "MZ!W"));
    try testing.expectError(error.InvalidCharacter, d.finish());
    // And a data-after-padding fault stays that fault for finish.
    var p: b32.Decoder = .init(.{});
    _ = try p.write(&out, "MZXW6===");
    try testing.expectError(error.InvalidPadding, p.write(&out, "M"));
    try testing.expectError(error.InvalidPadding, p.finish());
}
