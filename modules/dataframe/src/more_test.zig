// SPDX-License-Identifier: MIT
//! The limits of `more.zig`'s verbs on hand-built frames. Until step R (2026-11-08) this
//! file also ran each verb against `tabular`'s row verb of the same name; that module is
//! retired, and the verbs' anchors are the pandas/polars vectors, the `*Cells` reference
//! paths and the fuzz driver.

const std = @import("std");
const testing = std.testing;
const more = @import("more.zig");
const fm = @import("frame.zig");

test "more verbs: a frame past u32 rows is refused, and concat's cell cap" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]@import("value.zig").Column{.{ .name = "k", .type = .int }};
    const huge: fm.Frame = .{ .columns = &cols, .data = &.{}, .len = 1 << 40 };
    try testing.expectError(error.TooLarge, more.page(a, huge, .{}));
    try testing.expectError(error.TooLarge, more.tail(a, huge, 1));
    try testing.expectError(error.TooLarge, more.sample(a, huge, .{ .n = 1, .seed = 1 }));
    try testing.expectError(error.TooLarge, more.partitionBy(a, huge, &.{}));
    try testing.expectError(error.TooLarge, more.joinAsof(a, huge, huge, .{ .on = "k" }));
    const big: fm.Frame = .{ .columns = &cols, .data = &.{}, .len = 1 << 24 };
    try testing.expectError(error.TooLarge, more.concatByName(a, &.{ big, big }));
}
