// SPDX-License-Identifier: MIT
//! Bitcoin Core's own `FindAndDelete` unit test, transcribed byte-for-byte.
//!
//! Source: `src/test/script_tests.cpp`, `BOOST_AUTO_TEST_CASE(script_FindAndDelete)`
//! (fetched 2026-08 from `bitcoin/bitcoin` `master`). Every case below is one
//! `BOOST_CHECK_EQUAL(FindAndDelete(s, d), n)` + `BOOST_CHECK(s == expect)`
//! pair, with Core's `CScript() << OP_n` / `ToScript("…"_hex)` spellings
//! resolved to the exact bytes they produce (`OP_0 = 0x00`, `OP_1..OP_4 =
//! 0x51..0x54`, `CScript() << "ff03"_hex = 02 ff 03`) and Core's own comments
//! kept verbatim.
//!
//! This is the external oracle for the primitive itself: the greedy-but-
//! single-pass behaviour, the "matches entire opcodes" boundary rule, the
//! re-anchoring that turns `0302ff03 0302ff03` minus `03` into two DIFFERENT
//! pushes, and the invalid-trailing-push case are all consensus behaviour that
//! no round-trip of our own could establish.

const std = @import("std");
const testing = std.testing;
const interpreter = @import("interpreter.zig");

const Case = struct {
    script: []const u8,
    pattern: []const u8,
    expect: []const u8,
    found: usize,
    comment: []const u8 = "",
};

const cases = [_]Case{
    .{ .script = &.{ 0x51, 0x52 }, .pattern = &.{}, .expect = &.{ 0x51, 0x52 }, .found = 0, .comment = "delete nothing should be a no-op" },
    .{ .script = &.{ 0x51, 0x52, 0x53 }, .pattern = &.{0x52}, .expect = &.{ 0x51, 0x53 }, .found = 1 },
    .{ .script = &.{ 0x53, 0x51, 0x53, 0x53, 0x54, 0x53 }, .pattern = &.{0x53}, .expect = &.{ 0x51, 0x54 }, .found = 4 },
    .{ .script = &.{ 0x03, 0x02, 0xff, 0x03 }, .pattern = &.{ 0x03, 0x02, 0xff, 0x03 }, .expect = &.{}, .found = 1, .comment = "PUSH 0x02ff03 onto stack" },
    .{
        .script = &.{ 0x03, 0x02, 0xff, 0x03, 0x03, 0x02, 0xff, 0x03 },
        .pattern = &.{ 0x03, 0x02, 0xff, 0x03 },
        .expect = &.{},
        .found = 2,
        .comment = "PUSH 0x02ff03 PUSH 0x02ff03",
    },
    .{
        .script = &.{ 0x03, 0x02, 0xff, 0x03, 0x03, 0x02, 0xff, 0x03 },
        .pattern = &.{0x02},
        .expect = &.{ 0x03, 0x02, 0xff, 0x03, 0x03, 0x02, 0xff, 0x03 },
        .found = 0,
        .comment = "FindAndDelete matches entire opcodes",
    },
    .{
        .script = &.{ 0x03, 0x02, 0xff, 0x03, 0x03, 0x02, 0xff, 0x03 },
        .pattern = &.{0xff},
        .expect = &.{ 0x03, 0x02, 0xff, 0x03, 0x03, 0x02, 0xff, 0x03 },
        .found = 0,
    },
    .{
        .script = &.{ 0x03, 0x02, 0xff, 0x03, 0x03, 0x02, 0xff, 0x03 },
        .pattern = &.{0x03},
        .expect = &.{ 0x02, 0xff, 0x03, 0x02, 0xff, 0x03 },
        .found = 2,
        .comment = "odd edge case: strip of the push-three-bytes prefix, leaving 02ff03 which is push-two-bytes",
    },
    .{
        .script = &.{ 0x02, 0xfe, 0xed, 0x51, 0x69 },
        .pattern = &.{ 0xfe, 0xed, 0x51 },
        .expect = &.{ 0x02, 0xfe, 0xed, 0x51, 0x69 },
        .found = 0,
        .comment = "byte sequence that spans multiple opcodes: doesn't match 'inside' opcodes",
    },
    .{
        .script = &.{ 0x02, 0xfe, 0xed, 0x51, 0x69 },
        .pattern = &.{ 0x02, 0xfe, 0xed, 0x51 },
        .expect = &.{0x69},
        .found = 1,
    },
    .{
        .script = &.{ 0x51, 0x69, 0x02, 0xfe, 0xed, 0x51, 0x69 },
        .pattern = &.{ 0xfe, 0xed, 0x51 },
        .expect = &.{ 0x51, 0x69, 0x02, 0xfe, 0xed, 0x51, 0x69 },
        .found = 0,
    },
    .{
        .script = &.{ 0x51, 0x69, 0x02, 0xfe, 0xed, 0x51, 0x69 },
        .pattern = &.{ 0x02, 0xfe, 0xed, 0x51 },
        .expect = &.{ 0x51, 0x69, 0x69 },
        .found = 1,
    },
    .{
        .script = &.{ 0x00, 0x00, 0x51, 0x51 },
        .pattern = &.{ 0x00, 0x51 },
        .expect = &.{ 0x00, 0x51 },
        .found = 1,
        .comment = "FindAndDelete is single-pass",
    },
    .{
        .script = &.{ 0x00, 0x00, 0x51, 0x00, 0x51, 0x51 },
        .pattern = &.{ 0x00, 0x51 },
        .expect = &.{ 0x00, 0x51 },
        .found = 2,
        .comment = "FindAndDelete is single-pass",
    },
    .{
        .script = &.{ 0x00, 0x03, 0xfe, 0xed },
        .pattern = &.{ 0x03, 0xfe, 0xed },
        .expect = &.{0x00},
        .found = 1,
        .comment = "another weird edge case: end with invalid push (not enough data) ... can remove the invalid push",
    },
    .{
        .script = &.{ 0x00, 0x03, 0xfe, 0xed },
        .pattern = &.{0x00},
        .expect = &.{ 0x03, 0xfe, 0xed },
        .found = 1,
    },
};

test "Bitcoin Core script_FindAndDelete: every case matches byte-for-byte" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Guards against the corpus silently shrinking to nothing (a skip is a
    // pass, an empty loop is a pass).
    try testing.expectEqual(@as(usize, 16), cases.len);

    for (cases, 0..) |c, i| {
        const r = try interpreter.findAndDelete(a, c.script, c.pattern);
        testing.expectEqual(c.found, r.found) catch |err| {
            std.debug.print("\nFindAndDelete case {d} ({s}): expected found={d}, got {d}\n", .{ i, c.comment, c.found, r.found });
            return err;
        };
        testing.expectEqualSlices(u8, c.expect, r.script) catch |err| {
            std.debug.print("\nFindAndDelete case {d} ({s}) produced the wrong script\n", .{ i, c.comment });
            return err;
        };
    }
}
