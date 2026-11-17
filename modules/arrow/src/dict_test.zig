// SPDX-License-Identifier: MIT

//! Dictionaries on read: replacement in a stream (each record batch indexes the
//! dictionary current when it was read; a categorical's categories are the union of
//! the dictionaries its rows use, as pyarrow's `to_pandas` unifies a chunked
//! dictionary column), refused in a file (the columnar spec forbids it), deltas,
//! dictionaries nested in another dictionary's values, and the budgets repeated
//! replacements are charged against.

const std = @import("std");
const df = @import("dataframe");
const fb = @import("fb.zig");
const schema = @import("schema.zig");
const ipc = @import("ipc.zig");
const stream = @import("stream.zig");
const st = @import("stream_test.zig");

const testing = std.testing;
const Allocator = std.mem.Allocator;
const bytesOf = st.bytesOf;

const one: ipc.FieldNode = .{ .length = 1, .null_count = 0 };
const two: ipc.FieldNode = .{ .length = 2, .null_count = 0 };
const three: ipc.FieldNode = .{ .length = 3, .null_count = 0 };

/// A Utf8 dictionary batch for id `id` (comptime: the slices it holds are static).
fn textDict(comptime id: i64, comptime delta: bool, comptime node: ipc.FieldNode, comptime offsets: []const u8, comptime data: []const u8) st.HandBatch {
    return .{ .length = node.length, .dict_id = id, .delta = delta, .nodes = &.{node}, .bufs = &.{ "", offsets, data } };
}

/// The texts of a frame column, null as null.
fn expectTexts(f: df.Frame, ci: usize, want: []const ?[]const u8) !void {
    try testing.expectEqual(want.len, f.len);
    for (want, 0..) |w, i| {
        const v = f.columnAt(ci).get(i);
        if (w) |s| {
            if (v != .text) {
                std.debug.print("row {d}: {any}, want \"{s}\"\n", .{ i, v, s });
                return error.TestExpectedEqual;
            }
            try testing.expectEqualStrings(s, v.text);
        } else try testing.expect(v == .null);
    }
}

fn expectCategories(c: df.CatColumn, want: []const []const u8) !void {
    try testing.expectEqual(want.len + 1, c.dict.offsets.len);
    for (want, 0..) |w, i| try testing.expectEqualStrings(w, c.dict.at(i).?);
}

/// The messages of a stream laid out as an IPC file: the leading mark, the stream, and a
/// footer naming each dictionary and record batch message in stream order.
fn fileOf(gpa: Allocator, s: []const u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var pos: usize = 0;
    const first = try ipc.readMessage(s, &pos);
    const sch = try schema.decodeSchema(a, first.msg.header.?);
    var dicts: std.ArrayList(u8) = .empty;
    var batches: std.ArrayList(u8) = .empty;
    while (true) {
        const start = pos;
        const m = ipc.readMessage(s, &pos) catch |e| switch (e) {
            error.EndOfStream => break,
            else => return e,
        };
        var block: [24]u8 = @splat(0);
        std.mem.writeInt(i64, block[0..8], @intCast(8 + start), .little);
        std.mem.writeInt(i32, block[8..12], @intCast(pos - m.enc.body.len - start), .little);
        std.mem.writeInt(i64, block[16..24], @intCast(m.enc.body.len), .little);
        try (if (m.msg.header_type == .dictionary_batch) &dicts else &batches).appendSlice(a, &block);
    }
    var b = fb.Builder.init(gpa);
    defer b.deinit();
    const sref = try schema.encodeSchema(&b, sch);
    const dv = try b.createStructVector(dicts.items, 24, 8);
    const bv = try b.createStructVector(batches.items, 24, 8);
    b.startTable();
    try b.addScalarForce(0, schema.MetadataVersion, .v5);
    try b.addOffset(1, sref);
    try b.addOffset(2, dv);
    try b.addOffset(3, bv);
    const footer = try b.finish(try b.endTable());
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, "ARROW1\x00\x00");
    try out.appendSlice(gpa, s);
    try out.appendSlice(gpa, footer);
    try out.appendSlice(gpa, &std.mem.toBytes(std.mem.nativeToLittle(i32, @intCast(footer.len))));
    try out.appendSlice(gpa, "ARROW1");
    return out.toOwnedSlice(gpa);
}

test "replacement: each batch reads the dictionary current when it was read; the categories are their union, sorted" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const fields = [_]schema.Field{.{ .name = "c", .type = .utf8, .dictionary = .{ .id = 0 } }};
    // ["b", "a"]; rows 0 1. Replaced by ["c", "a"]; rows 0 1 null. Delta ["d"]; row 2.
    const bytes = try st.hand(gpa, &fields, &.{
        textDict(0, false, two, bytesOf(i32, &.{ 0, 1, 2 }), "ba"),
        .{ .length = 2, .nodes = &.{two}, .bufs = &.{ "", bytesOf(i32, &.{ 0, 1 }) } },
        textDict(0, false, two, bytesOf(i32, &.{ 0, 1, 2 }), "ca"),
        .{ .length = 3, .nodes = &.{.{ .length = 3, .null_count = 1 }}, .bufs = &.{ &.{0x03}, bytesOf(i32, &.{ 0, 1, 9 }) } },
        textDict(0, true, one, bytesOf(i32, &.{ 0, 1 }), "d"),
        .{ .length = 1, .nodes = &.{one}, .bufs = &.{ "", bytesOf(i32, &.{2}) } },
    });
    defer gpa.free(bytes);
    const f = try stream.readStream(a, bytes, .{});
    try expectTexts(f, 0, &.{ "b", "a", "c", "a", null, "d" });
    try testing.expectEqual(df.ColumnType.categorical, f.columns[0].type);
    const c = f.columnAt(0).categorical;
    try expectCategories(c, &.{ "a", "b", "c", "d" });
    try testing.expect(!c.ordered);

    // The file format forbids it: the same messages in a file are Malformed. With the
    // replacement dropped (one dictionary and its delta) the file reads.
    const fl = try fileOf(gpa, bytes);
    defer gpa.free(fl);
    try testing.expectError(error.Malformed, stream.readFile(a, fl, .{}));
    try testing.expectError(error.Malformed, stream.openFile(a, fl, .{}));
    const ok = try st.hand(gpa, &fields, &.{
        textDict(0, false, two, bytesOf(i32, &.{ 0, 1, 2 }), "ba"),
        textDict(0, true, one, bytesOf(i32, &.{ 0, 1 }), "d"),
        .{ .length = 2, .nodes = &.{two}, .bufs = &.{ "", bytesOf(i32, &.{ 2, 0 }) } },
    });
    defer gpa.free(ok);
    const okf = try fileOf(gpa, ok);
    defer gpa.free(okf);
    try expectTexts(try stream.readFile(a, okf, .{}), 0, &.{ "d", "b" });
    try expectTexts(try stream.readStream(a, ok, .{}), 0, &.{ "d", "b" });
}

test "replacement: an ordered dictionary keeps the order of first appearance; a generation no batch reads adds no category" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    {
        const fields = [_]schema.Field{.{ .name = "o", .type = .utf8, .dictionary = .{ .id = 0, .ordered = true } }};
        const bytes = try st.hand(gpa, &fields, &.{
            textDict(0, false, two, bytesOf(i32, &.{ 0, 2, 4 }), "lohi"),
            .{ .length = 2, .nodes = &.{two}, .bufs = &.{ "", bytesOf(i32, &.{ 1, 0 }) } },
            textDict(0, false, three, bytesOf(i32, &.{ 0, 3, 5, 8 }), "midlotop"),
            .{ .length = 2, .nodes = &.{two}, .bufs = &.{ "", bytesOf(i32, &.{ 0, 2 }) } },
        });
        defer gpa.free(bytes);
        const f = try stream.readStream(a, bytes, .{});
        try expectTexts(f, 0, &.{ "hi", "lo", "mid", "top" });
        const c = f.columnAt(0).categorical;
        try testing.expect(c.ordered);
        try expectCategories(c, &.{ "lo", "hi", "mid", "top" });
    }
    {
        // ["x"] replaced by ["y"] before any batch: only "y" is a category.
        const fields = [_]schema.Field{.{ .name = "c", .type = .utf8, .dictionary = .{ .id = 0 } }};
        const bytes = try st.hand(gpa, &fields, &.{
            textDict(0, false, one, bytesOf(i32, &.{ 0, 1 }), "x"),
            textDict(0, false, one, bytesOf(i32, &.{ 0, 1 }), "y"),
            .{ .length = 1, .nodes = &.{one}, .bufs = &.{ "", bytesOf(i32, &.{0}) } },
        });
        defer gpa.free(bytes);
        const f = try stream.readStream(a, bytes, .{});
        try expectTexts(f, 0, &.{"y"});
        try expectCategories(f.columnAt(0).categorical, &.{"y"});
        // No batch at all: the first dictionary's categories (a zero-row frame).
        const none = try st.hand(gpa, &fields, &.{
            textDict(0, false, one, bytesOf(i32, &.{ 0, 1 }), "x"),
            textDict(0, false, one, bytesOf(i32, &.{ 0, 1 }), "y"),
        });
        defer gpa.free(none);
        const g = try stream.readStream(a, none, .{});
        try testing.expectEqual(@as(usize, 0), g.len);
    }
}

test "replacement: a non-text dictionary, an index past the CURRENT dictionary, a delta with nothing to extend, a batch before any dictionary" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    {
        // Int64 values [10, 20] then [30]: a plain int column.
        const fields = [_]schema.Field{.{ .name = "i", .type = .{ .int = .{ .bits = 64, .signed = true } }, .dictionary = .{ .id = 1, .index = .{ .bits = 8, .signed = true } } }};
        const bytes = try st.hand(gpa, &fields, &.{
            .{ .length = 2, .dict_id = 1, .nodes = &.{two}, .bufs = &.{ "", bytesOf(i64, &.{ 10, 20 }) } },
            .{ .length = 1, .nodes = &.{one}, .bufs = &.{ "", &.{1} } },
            .{ .length = 1, .dict_id = 1, .nodes = &.{one}, .bufs = &.{ "", bytesOf(i64, &.{30}) } },
            .{ .length = 2, .nodes = &.{two}, .bufs = &.{ "", &.{ 0, 0 } } },
        });
        defer gpa.free(bytes);
        const f = try stream.readStream(a, bytes, .{});
        try testing.expectEqual(df.ColumnType.int, f.columns[0].type);
        try testing.expectEqual(@as(usize, 3), f.len);
        for ([_]i64{ 20, 30, 30 }, 0..) |w, i| try testing.expectEqual(w, f.columnAt(0).get(i).int);
    }
    const fields = [_]schema.Field{.{ .name = "c", .type = .utf8, .dictionary = .{ .id = 0 } }};
    const abc = textDict(0, false, three, bytesOf(i32, &.{ 0, 1, 2, 3 }), "abc");
    const z = textDict(0, false, one, bytesOf(i32, &.{ 0, 1 }), "z");
    const row2: st.HandBatch = .{ .length = 1, .nodes = &.{one}, .bufs = &.{ "", bytesOf(i32, &.{2}) } };
    {
        // Index 2 reads "c" before the replacement; after it the dictionary has one entry.
        const good = try st.hand(gpa, &fields, &.{ abc, row2, z });
        defer gpa.free(good);
        try expectTexts(try stream.readStream(a, good, .{}), 0, &.{"c"});
        const bad = try st.hand(gpa, &fields, &.{ abc, z, row2 });
        defer gpa.free(bad);
        try testing.expectError(error.Malformed, stream.readStream(a, bad, .{}));
    }
    {
        // A delta as the first dictionary batch.
        const bytes = try st.hand(gpa, &fields, &.{textDict(0, true, one, bytesOf(i32, &.{ 0, 1 }), "a")});
        defer gpa.free(bytes);
        try testing.expectError(error.Malformed, stream.readStream(a, bytes, .{}));
    }
    {
        // An all-null batch before the dictionary (the columnar spec's edge case), then a
        // batch after it, then a replacement read by the last batch.
        const bytes = try st.hand(gpa, &fields, &.{
            .{ .length = 1, .nodes = &.{.{ .length = 1, .null_count = 1 }}, .bufs = &.{ &.{0}, bytesOf(i32, &.{0}) } },
            abc,
            row2,
            z,
            .{ .length = 1, .nodes = &.{one}, .bufs = &.{ "", bytesOf(i32, &.{0}) } },
        });
        defer gpa.free(bytes);
        const f = try stream.readStream(a, bytes, .{});
        try expectTexts(f, 0, &.{ null, "c", "z" });
        try expectCategories(f.columnAt(0).categorical, &.{ "a", "b", "c", "z" });
    }
}

test "replacement: projection reads a replaced dictionary only for the columns that use it" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const fields = [_]schema.Field{
        .{ .name = "c", .type = .utf8, .dictionary = .{ .id = 0 } },
        .{ .name = "x", .type = .{ .int = .{ .bits = 32, .signed = true } } },
    };
    const bytes = try st.hand(gpa, &fields, &.{
        textDict(0, false, one, bytesOf(i32, &.{ 0, 1 }), "p"),
        .{ .length = 1, .nodes = &.{ one, one }, .bufs = &.{ "", bytesOf(i32, &.{0}), "", bytesOf(i32, &.{7}) } },
        textDict(0, false, one, bytesOf(i32, &.{ 0, 1 }), "q"),
        .{ .length = 1, .nodes = &.{ one, one }, .bufs = &.{ "", bytesOf(i32, &.{0}), "", bytesOf(i32, &.{8}) } },
    });
    defer gpa.free(bytes);
    const full = try stream.readStream(a, bytes, .{});
    try expectTexts(full, 0, &.{ "p", "q" });
    const xs = [_]stream.ColumnRef{.{ .name = "x" }};
    const px = try stream.readStream(a, bytes, .{ .columns = &xs });
    try testing.expectEqual(@as(usize, 1), px.columns.len);
    try testing.expectEqual(@as(i64, 8), px.columnAt(0).get(1).int);
    const cs = [_]stream.ColumnRef{.{ .name = "c" }};
    try expectTexts(try stream.readStream(a, bytes, .{ .columns = &cs }), 0, &.{ "p", "q" });
}

test "nested dictionaries: inside another dictionary's values, replaced together; a cycle and a mismatched shared child are Malformed" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const item = [_]schema.Field{.{ .name = "item", .type = .utf8, .dictionary = .{ .id = 0 } }};
    const fields = [_]schema.Field{.{ .name = "l", .type = .list, .children = &item, .dictionary = .{ .id = 1, .index = .{ .bits = 8, .signed = true } } }};
    // Dictionary 0 ["a", "b"], dictionary 1 [[0, 1]] (= [["a", "b"]]); row 0. Then 0 is
    // replaced by ["c", "d"] and 1 by [[1]] (= [["d"]]); row 0.
    const list1: st.HandBatch = .{ .length = 1, .dict_id = 1, .nodes = &.{ one, two }, .bufs = &.{ "", bytesOf(i32, &.{ 0, 2 }), "", bytesOf(i32, &.{ 0, 1 }) } };
    const list2: st.HandBatch = .{ .length = 1, .dict_id = 1, .nodes = &.{ one, one }, .bufs = &.{ "", bytesOf(i32, &.{ 0, 1 }), "", bytesOf(i32, &.{1}) } };
    const row0: st.HandBatch = .{ .length = 1, .nodes = &.{one}, .bufs = &.{ "", &.{0} } };
    const bytes = try st.hand(gpa, &fields, &.{
        textDict(0, false, two, bytesOf(i32, &.{ 0, 1, 2 }), "ab"),
        list1,
        row0,
        textDict(0, false, two, bytesOf(i32, &.{ 0, 1, 2 }), "cd"),
        list2,
        row0,
    });
    defer gpa.free(bytes);
    const f = try stream.readStream(a, bytes, .{});
    try testing.expectEqual(df.ColumnType.list, f.columns[0].type);
    try testing.expectEqual(df.ColumnType.categorical, f.columns[0].inner[0].type);
    const r0 = f.columnAt(0).get(0).list;
    try testing.expectEqual(@as(usize, 2), r0.len());
    try testing.expectEqualStrings("a", r0.get(0).text);
    try testing.expectEqualStrings("b", r0.get(1).text);
    const r1 = f.columnAt(0).get(1).list;
    try testing.expectEqual(@as(usize, 1), r1.len());
    try testing.expectEqualStrings("d", r1.get(0).text);
    // Projected away, both dictionaries are skipped; projected in, both are read.
    const ls = [_]stream.ColumnRef{.{ .index = 0 }};
    try st.expectSameFrame(f, try stream.readStream(a, bytes, .{ .columns = &ls }));

    // Dictionary 1 whose values hold dictionary 1.
    const self_item = [_]schema.Field{.{ .name = "item", .type = .utf8, .dictionary = .{ .id = 1 } }};
    const cyc = [_]schema.Field{.{ .name = "l", .type = .list, .children = &self_item, .dictionary = .{ .id = 1 } }};
    const cb = try st.hand(gpa, &cyc, &.{});
    defer gpa.free(cb);
    try testing.expectError(error.Malformed, stream.readStream(a, cb, .{}));
    // Two fields sharing dictionary 1 whose values' own dictionary differs in index width.
    const item16 = [_]schema.Field{.{ .name = "item", .type = .utf8, .dictionary = .{ .id = 0, .index = .{ .bits = 16, .signed = true } } }};
    const shared = [_]schema.Field{
        fields[0],
        .{ .name = "m", .type = .list, .children = &item16, .dictionary = .{ .id = 1, .index = .{ .bits = 8, .signed = true } } },
    };
    const sb = try st.hand(gpa, &shared, &.{});
    defer gpa.free(sb);
    try testing.expectError(error.Malformed, stream.readStream(a, sb, .{}));
}
