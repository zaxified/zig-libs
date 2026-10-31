// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GZ). seqmap had no findings: every entry point is
//! total over a `u16` id, because the table has exactly 65536 slots. These tests
//! pin that totality (they would catch a future capacity change or a wider id).

const std = @import("std");
const testing = std.testing;
const seqmap = @import("root.zig");

test "fetch, fetchPtr and release are total over every u16 id on an empty table (sweep clean)" {
    var m = try seqmap.SeqMap.init(testing.allocator);
    defer m.deinit(testing.allocator);
    var i: u32 = 0;
    while (i <= std.math.maxInt(u16)) : (i += 1) {
        const id: u16 = @intCast(i);
        try testing.expect(m.fetch(id) == null);
        try testing.expect(m.fetchPtr(id) == null);
        m.release(id); // never added: silent no-op
    }
}

test "entries carry any sent_ns, target and probe value untouched (sweep clean)" {
    var m = try seqmap.SeqMap.init(testing.allocator);
    defer m.deinit(testing.allocator);
    const lo = try m.add(std.math.maxInt(u32), std.math.maxInt(u16), std.math.minInt(i64));
    const hi = try m.add(0, 0, std.math.maxInt(i64));
    try testing.expectEqual(std.math.minInt(i64), m.fetch(lo).?.sent_ns);
    try testing.expectEqual(std.math.maxInt(i64), m.fetch(hi).?.sent_ns);
    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), m.fetch(lo).?.target);
    try testing.expectEqual(@as(u16, std.math.maxInt(u16)), m.fetch(lo).?.probe);
}

test "add on a full table fails without touching the table or the cursor, then recovers (sweep clean)" {
    var m = try seqmap.SeqMap.init(testing.allocator);
    defer m.deinit(testing.allocator);
    var i: usize = 0;
    while (i < seqmap.capacity) : (i += 1) _ = try m.add(@intCast(i), 0, @intCast(i));
    try testing.expectEqual(@as(u16, 0), m.cursor);
    var k: usize = 0;
    while (k < 1000) : (k += 1) try testing.expectError(error.Exhausted, m.add(7, 7, 7));
    try testing.expectEqual(@as(u16, 0), m.cursor);
    // The entry the failed adds were aimed at is intact.
    try testing.expectEqual(@as(u32, 0), m.fetch(0).?.target);
    m.clear();
    try testing.expect(m.fetch(0) == null);
    try testing.expectEqual(@as(u16, 0), try m.add(1, 1, 1));
}

test "the cursor wraps cleanly over several full cycles of add/release (sweep clean)" {
    var m = try seqmap.SeqMap.init(testing.allocator);
    defer m.deinit(testing.allocator);
    var i: usize = 0;
    while (i < 3 * seqmap.capacity + 17) : (i += 1) {
        const id = try m.add(1, 0, 0);
        try testing.expectEqual(@as(u16, @truncate(i)), id);
        m.release(id);
    }
    try testing.expectEqual(@as(u16, 17), m.cursor);
}
