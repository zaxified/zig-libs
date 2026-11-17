// SPDX-License-Identifier: MIT

//! Round trips of whole frames through the Arrow IPC stream, hand-assembled
//! streams for the layouts the writer never produces (other units, scales,
//! index types, offsets that do not start at 0), and hostile streams.

const std = @import("std");
const df = @import("dataframe");
const fb = @import("fb.zig");
const schema = @import("schema.zig");
const ipc = @import("ipc.zig");
const stream = @import("stream.zig");

const testing = std.testing;
const Allocator = std.mem.Allocator;
const Column = df.Column;
const ColumnData = df.ColumnData;

pub fn validBits(a: Allocator, n: usize, nulls: []const usize) ![]u64 {
    const w = try a.alloc(u64, (n + 63) / 64);
    @memset(w, ~@as(u64, 0));
    for (nulls) |i| w[i / 64] &= ~(@as(u64, 1) << @as(u6, @truncate(i)));
    return w;
}

pub fn textCol(a: Allocator, cells: []const ?[]const u8) !df.TextColumn {
    const offs = try a.alloc(usize, cells.len + 1);
    var bytes: std.ArrayList(u8) = .empty;
    var nulls: std.ArrayList(usize) = .empty;
    offs[0] = 0;
    for (cells, 0..) |c, i| {
        if (c) |t| try bytes.appendSlice(a, t) else try nulls.append(a, i);
        offs[i + 1] = bytes.items.len;
    }
    return .{ .offsets = offs, .bytes = bytes.items, .valid = if (nulls.items.len > 0) try validBits(a, cells.len, nulls.items) else null };
}

pub fn expectSameType(want: Column, got: Column) !void {
    try testing.expectEqual(want.type, got.type);
    try testing.expectEqual(want.array_width, got.array_width);
    if (want.time_zone) |z| try testing.expectEqualStrings(z, got.time_zone.?) else try testing.expect(got.time_zone == null);
    if (want.inner.len > 0) {
        try testing.expectEqual(want.inner.len, got.inner.len);
        for (want.inner, got.inner) |x, y| try expectSameType(x, y);
    }
}

/// Same columns (name, declared type) and the same cells, compared as values.
pub fn expectSameFrame(want: df.Frame, got: df.Frame) !void {
    try testing.expectEqual(want.len, got.len);
    try testing.expectEqual(want.columns.len, got.columns.len);
    for (want.columns, got.columns, 0..) |wc, gc, ci| {
        try testing.expectEqualStrings(wc.name, gc.name);
        try expectSameType(wc, gc);
        for (0..want.len) |r| {
            const x = want.columnAt(ci).get(r);
            const y = got.columnAt(ci).get(r);
            if (std.meta.activeTag(x) != std.meta.activeTag(y) or (x != .null and !x.eql(y))) {
                std.debug.print("column {s} row {d}: want {any} got {any}\n", .{ wc.name, r, x, y });
                return error.TestExpectedEqual;
            }
        }
    }
}

const scale: i128 = df.decimal_scale;

/// Five rows of every column type the mapping covers, with nulls.
pub fn sampleFrame(a: Allocator) !df.Frame {
    const n = 5;
    const ints: ColumnData = .{ .int = .{ .values = &.{ 1, -2, 0, 4, std.math.maxInt(i64) }, .valid = try validBits(a, n, &.{2}) } };
    const items = try a.create(ColumnData);
    items.* = .{ .int = .{ .values = &.{ 10, 11, 12, 13, 14, 15 }, .valid = try validBits(a, 6, &.{3}) } };
    const arr_items = try a.create(ColumnData);
    arr_items.* = .{ .float = .{ .values = &.{ 0.5, 1.5, 2.5, 3.5, 4.5, 5.5, 6.5, 7.5 } } };
    const cat_items = try a.create(ColumnData);
    cat_items.* = .{ .categorical = .{ .codes = .{ .values = &.{ 1, 0, 1 } }, .dict = try textCol(a, &.{ "p", "q" }) } };
    const sc = try a.create(df.StructColumn);
    sc.* = .{
        .names = &.{ "a", "b" },
        .children = try a.dupe(ColumnData, &.{
            .{ .int = .{ .values = &.{ 1, 2, 3, 4, 5 }, .valid = try validBits(a, n, &.{4}) } },
            .{ .text = try textCol(a, &.{ "x", null, "", "yy", "z" }) },
        }),
        .len = n,
        .valid = try validBits(a, n, &.{1}),
    };
    const int_inner = [_]Column{.{ .name = "item", .type = .int }};
    const float_inner = [_]Column{.{ .name = "item", .type = .float }};
    const cat_inner = [_]Column{.{ .name = "item", .type = .categorical }};
    const st_inner = [_]Column{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .text } };
    const columns = [_]Column{
        .{ .name = "i64", .type = .int },
        .{ .name = "f64", .type = .float },
        .{ .name = "b", .type = .bool },
        .{ .name = "dec", .type = .decimal },
        .{ .name = "s", .type = .text },
        .{ .name = "bin", .type = .binary },
        .{ .name = "d", .type = .date },
        .{ .name = "ts", .type = .timestamp, .time_zone = "Europe/Prague" },
        .{ .name = "ts_naive", .type = .timestamp },
        .{ .name = "dur", .type = .duration },
        .{ .name = "tm", .type = .time },
        .{ .name = "cat", .type = .categorical },
        .{ .name = "ord", .type = .categorical },
        .{ .name = "i8", .type = .int8 },
        .{ .name = "i16", .type = .int16 },
        .{ .name = "i32", .type = .int32 },
        .{ .name = "u8", .type = .uint8 },
        .{ .name = "u16", .type = .uint16 },
        .{ .name = "u32", .type = .uint32 },
        .{ .name = "u64", .type = .uint64 },
        .{ .name = "f32", .type = .float32 },
        .{ .name = "l", .type = .list, .inner = &int_inner },
        .{ .name = "arr", .type = .array, .array_width = 2, .inner = &float_inner },
        .{ .name = "st", .type = .@"struct", .inner = &st_inner },
        .{ .name = "lcat", .type = .list, .inner = &cat_inner },
        .{ .name = "nul", .type = .text },
    };
    const data = [_]ColumnData{
        ints,
        .{ .float = .{ .values = &.{ 1.5, 0, -2.25, 1e300, 0 }, .valid = try validBits(a, n, &.{ 1, 4 }) } },
        .{ .bool = .{ .values = &.{ true, false, false, true, true }, .valid = try validBits(a, n, &.{2}) } },
        .{ .decimal = .{ .values = &.{ 12_345 * scale / 100, -1, 0, std.math.maxInt(i64) * scale, 7 }, .valid = try validBits(a, n, &.{2}) } },
        .{ .text = try textCol(a, &.{ "a", "", "h\xc3\xa9llo", null, "z" }) },
        .{ .text = try textCol(a, &.{ "\x00\xff", null, "", "bytes", "\x80" }) },
        .{ .text = try textCol(a, &.{ "2024-02-29", "1970-01-01", null, "0001-01-01", "9999-12-31" }) },
        .{ .int = .{ .values = &.{ 0, 1_700_000_000_000_000, -1, 0, 86_400_000_000 }, .valid = try validBits(a, n, &.{3}) } },
        .{ .int = .{ .values = &.{ 5, 6, 7, 8, 9 } } },
        .{ .int = .{ .values = &.{ -1_000_000, 0, 3_600_000_000, 0, 1 }, .valid = try validBits(a, n, &.{3}) } },
        .{ .int = .{ .values = &.{ 0, 86_399_999_999, 12 * 3_600_000_000, 0, 1 }, .valid = try validBits(a, n, &.{3}) } },
        .{ .categorical = .{ .codes = .{ .values = &.{ 2, 0, 1, 0, 2 }, .valid = try validBits(a, n, &.{3}) }, .dict = try textCol(a, &.{ "a", "b", "c" }) } },
        .{ .categorical = .{ .codes = .{ .values = &.{ 0, 2, 1, 1, 0 } }, .dict = try textCol(a, &.{ "lo", "mid", "hi", "unused" }), .ordered = true } },
        .{ .int8 = .{ .values = &.{ -128, 127, 0, 1, -1 }, .valid = try validBits(a, n, &.{2}) } },
        .{ .int16 = .{ .values = &.{ -32768, 32767, 0, 1, -1 } } },
        .{ .int32 = .{ .values = &.{ std.math.minInt(i32), std.math.maxInt(i32), 0, 1, -1 } } },
        .{ .uint8 = .{ .values = &.{ 0, 255, 1, 2, 3 }, .valid = try validBits(a, n, &.{0}) } },
        .{ .uint16 = .{ .values = &.{ 0, 65535, 1, 2, 3 } } },
        .{ .uint32 = .{ .values = &.{ 0, std.math.maxInt(u32), 1, 2, 3 } } },
        .{ .uint64 = .{ .values = &.{ 0, std.math.maxInt(u64), 1 << 63, 2, 3 }, .valid = try validBits(a, n, &.{4}) } },
        .{ .float32 = .{ .values = &.{ 0.25, -1.5, 3.0e38, 0, 1 } } },
        .{ .list = .{ .offsets = &.{ 0, 2, 2, 2, 5, 6 }, .items = items, .valid = try validBits(a, n, &.{1}) } },
        .{ .list = .{ .offsets = &.{ 0, 2, 4, 4, 6, 8 }, .items = arr_items, .valid = try validBits(a, n, &.{2}) } },
        .{ .@"struct" = sc },
        .{ .list = .{ .offsets = &.{ 0, 1, 1, 3, 3, 3 }, .items = cat_items, .valid = try validBits(a, n, &.{4}) } },
        .nulls,
    };
    return .{ .columns = try a.dupe(Column, &columns), .data = try a.dupe(ColumnData, &data), .len = n };
}

fn roundTrip(arena: Allocator, f: df.Frame, opts: stream.WriteOptions) !df.Frame {
    const bytes = try stream.writeStream(testing.allocator, f, opts);
    defer testing.allocator.free(bytes);
    try testing.expectEqual(@as(usize, 0), bytes.len % 8);
    return stream.readStream(arena, bytes, .{});
}

test "round trip: every mapped column type with nulls, in one batch and in many" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const f = try sampleFrame(a);
    for ([_]usize{ 0, 1, 2, 3, 4, 5, 100 }) |per| {
        const got = try roundTrip(a, f, .{ .rows_per_batch = per });
        try expectSameFrame(f, got);
    }
    // The storage `dataframe` itself would make: a categorical keeps its dictionary, an
    // ordered one its order (unused categories included), a uint64 its own array.
    const got = try roundTrip(a, f, .{});
    const ord = got.columnAt(f.columnIndex("ord").?).categorical;
    try testing.expect(ord.ordered);
    try testing.expectEqual(@as(usize, 5), ord.dict.offsets.len);
    try testing.expectEqualStrings("unused", ord.dict.at(3).?);
    try testing.expect(got.columnAt(f.columnIndex("u64").?) == .uint64);
    try testing.expect(got.columnAt(f.columnIndex("nul").?) == .nulls);
}

test "round trip: Large offsets when the column reaches large_from" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const f = try sampleFrame(a);
    const bytes = try stream.writeStream(testing.allocator, f, .{ .large_from = 0, .rows_per_batch = 2 });
    defer testing.allocator.free(bytes);
    try expectSameFrame(f, try stream.readStream(a, bytes, .{}));
    var pos: usize = 0;
    const m = try ipc.readMessage(bytes, &pos);
    const s = try schema.decodeSchema(a, m.msg.header.?);
    try testing.expect(s.fields[f.columnIndex("s").?].type == .large_utf8);
    try testing.expect(s.fields[f.columnIndex("bin").?].type == .large_binary);
    try testing.expect(s.fields[f.columnIndex("cat").?].type == .large_utf8);
}

test "round trip: an empty frame keeps its columns" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const inner = [_]Column{.{ .name = "item", .type = .int16 }};
    const f: df.Frame = .{
        .columns = &.{
            .{ .name = "x", .type = .int },
            .{ .name = "s", .type = .text },
            .{ .name = "c", .type = .categorical },
            .{ .name = "l", .type = .list, .inner = &inner },
            .{ .name = "ts", .type = .timestamp, .time_zone = "UTC" },
        },
        .data = &.{},
        .len = 0,
    };
    const got = try roundTrip(a, f, .{});
    try expectSameFrame(f, got);
    // No columns at all.
    const none_frame: df.Frame = .{ .columns = &.{}, .data = &.{}, .len = 0 };
    try expectSameFrame(none_frame, try roundTrip(a, none_frame, .{}));
}

test "dictionaries come back as dataframe keeps them: unordered sorted and deduplicated, ordered deduplicated" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const f: df.Frame = .{
        .columns = &.{ .{ .name = "u", .type = .categorical }, .{ .name = "o", .type = .categorical }, .{ .name = "t", .type = .categorical } },
        .data = &.{
            .{ .categorical = .{ .codes = .{ .values = &.{ 0, 1, 2 } }, .dict = try textCol(a, &.{ "b", "a", "b" }) } },
            .{ .categorical = .{ .codes = .{ .values = &.{ 0, 1, 2 } }, .dict = try textCol(a, &.{ "z", "a", "z" }), .ordered = true } },
            // A categorical declaration over plain text storage.
            .{ .text = try textCol(a, &.{ "m", null, "k" }) },
        },
        .len = 3,
    };
    const got = try roundTrip(a, f, .{});
    try expectSameFrame(f, got);
    const u = got.data[0].categorical;
    try testing.expectEqual(@as(usize, 3), u.dict.offsets.len);
    try testing.expectEqualStrings("a", u.dict.at(0).?);
    try testing.expectEqualSlices(u32, &.{ 1, 0, 1 }, u.codes.values);
    const o = got.data[1].categorical;
    try testing.expectEqualStrings("z", o.dict.at(0).?);
    try testing.expectEqualSlices(u32, &.{ 0, 1, 0 }, o.codes.values);
    const t = got.data[2].categorical;
    try testing.expectEqualStrings("k", t.dict.at(0).?);
    try testing.expectEqualStrings("m", t.dict.at(1).?);
}

test "the declared type picks the Arrow type; cells it cannot hold are Unsupported" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // A float column stored as ints is written as Float64.
    const f: df.Frame = .{ .columns = &.{.{ .name = "x", .type = .float }}, .data = &.{.{ .int = .{ .values = &.{ 1, 2 } } }}, .len = 2 };
    const got = try roundTrip(a, f, .{});
    try testing.expect(got.data[0] == .float);
    try testing.expectEqual(@as(f64, 2), got.data[0].float.values[1]);

    const boxed = [_]df.Value{ .{ .int = 1 }, .{ .text = "x" } };
    const items = try a.create(ColumnData);
    items.* = .{ .int = .{ .values = &.{ 1, 2, 3 } } };
    const bad = [_]df.Frame{
        .{ .columns = &.{.{ .name = "b", .type = .text }}, .data = &.{.{ .boxed = &boxed }}, .len = 2 },
        .{ .columns = &.{.{ .name = "i", .type = .int }}, .data = &.{.{ .text = try textCol(a, &.{"1"}) }}, .len = 1 },
        .{ .columns = &.{.{ .name = "d", .type = .date }}, .data = &.{.{ .text = try textCol(a, &.{"2023-02-29"}) }}, .len = 1 },
        .{ .columns = &.{.{ .name = "t", .type = .time }}, .data = &.{.{ .int = .{ .values = &.{-1} } }}, .len = 1 },
        .{ .columns = &.{.{ .name = "u", .type = .uint8 }}, .data = &.{.{ .int = .{ .values = &.{256} } }}, .len = 1 },
        .{ .columns = &.{.{ .name = "a", .type = .array, .array_width = 2 }}, .data = &.{.{ .list = .{ .offsets = &.{ 0, 3 }, .items = items } }}, .len = 1 },
        .{ .columns = &.{.{ .name = "l", .type = .list }}, .data = &.{.{ .int = .{ .values = &.{1} } }}, .len = 1 },
    };
    for (bad) |b| try testing.expectError(error.Unsupported, stream.writeStream(testing.allocator, b, .{}));
}

// ── hand-assembled streams ──────────────────────────────────────────────────

pub const HandBatch = struct {
    length: i64,
    nodes: []const ipc.FieldNode,
    bufs: []const []const u8,
    dict_id: ?i64 = null,
    delta: bool = false,
    /// Marks the body compressed (the buffers are given already prefixed and compressed).
    codec: ?ipc.Codec = null,
    /// `variadicBufferCounts` (one per view-typed field).
    variadic: []const i64 = &.{},
};

pub fn hand(gpa: Allocator, fields: []const schema.Field, batches: []const HandBatch) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var b = fb.Builder.init(gpa);
    defer b.deinit();
    try ipc.writeMessage(gpa, &out, try schema.encodeSchemaMessage(&b, .{ .fields = fields }), &.{});
    for (batches) |hb| {
        var body: ipc.BodyBuilder = .{};
        defer body.deinit(gpa);
        for (hb.bufs) |x| if (x.len == 0) try body.addEmpty(gpa) else try body.add(gpa, x);
        var mb = fb.Builder.init(gpa);
        defer mb.deinit();
        const rb: ipc.RecordBatch = .{ .length = hb.length, .nodes = hb.nodes, .buffers = body.locs.items, .compression = hb.codec, .variadic_counts = hb.variadic };
        const blen: i64 = @intCast(body.bytes.items.len);
        const meta = if (hb.dict_id) |id|
            try ipc.encodeDictionaryBatchMessage(&mb, .{ .id = id, .data = rb, .is_delta = hb.delta }, blen)
        else
            try ipc.encodeRecordBatchMessage(&mb, rb, blen);
        try ipc.writeMessage(gpa, &out, meta, body.bytes.items);
    }
    try ipc.writeEos(gpa, &out);
    return out.toOwnedSlice(gpa);
}

pub fn bytesOf(comptime T: type, comptime xs: []const T) []const u8 {
    return std.mem.sliceAsBytes(xs);
}

test "reader: units, scales, half floats, index types, fixed-size binary, non-text dictionaries, deltas, offsets not from 0" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const i32_item = [_]schema.Field{.{ .name = "item", .type = .{ .int = .{ .bits = 32, .signed = true } } }};
    const fields = [_]schema.Field{
        .{ .name = "ns", .type = .{ .timestamp = .{ .unit = .nanosecond } } },
        .{ .name = "d64", .type = .{ .date = .millisecond } },
        .{ .name = "t32", .type = .{ .time = .{ .unit = .millisecond, .bits = 32 } } },
        .{ .name = "dec2", .type = .{ .decimal = .{ .precision = 10, .scale = 2 } } },
        .{ .name = "h", .type = .{ .float = .half } },
        .{ .name = "u8i", .type = .utf8, .dictionary = .{ .id = 0, .index = .{ .bits = 8, .signed = false } } },
        .{ .name = "fsb", .type = .{ .fixed_size_binary = 2 } },
        .{ .name = "dint", .type = .{ .int = .{ .bits = 64, .signed = true } }, .dictionary = .{ .id = 1 } },
        .{ .name = "lst", .type = .list, .children = &i32_item },
        .{ .name = "sec", .type = .{ .duration = .second } },
    };
    const two: ipc.FieldNode = .{ .length = 2, .null_count = 0 };
    const row0_null = &[_]u8{0b10};
    const bytes = try hand(gpa, &fields, &.{
        // Dictionary 0 in two parts: "x", "y" then a delta "w".
        .{ .length = 2, .dict_id = 0, .nodes = &.{two}, .bufs = &.{ "", bytesOf(i32, &.{ 0, 1, 2 }), "xy" } },
        .{ .length = 1, .dict_id = 0, .delta = true, .nodes = &.{.{ .length = 1, .null_count = 0 }}, .bufs = &.{ "", bytesOf(i32, &.{ 0, 1 }), "w" } },
        .{ .length = 2, .dict_id = 1, .nodes = &.{two}, .bufs = &.{ "", bytesOf(i64, &.{ 10, 20 }) } },
        .{
            .length = 2,
            .nodes = &.{ two, two, two, two, two, two, two, two, .{ .length = 2, .null_count = 1 }, .{ .length = 6, .null_count = 0 }, two },
            .bufs = &.{
                "",        bytesOf(i64, &.{ 1_999_000, -1_000 }),
                "",        bytesOf(i64, &.{ 86_400_000 * 3, -86_400_000 }),
                "",        bytesOf(i32, &.{ 1_500, 0 }),
                "",        bytesOf(i128, &.{ 12_345, -1 }),
                "",        bytesOf(f16, &.{ 1.5, -0.25 }),
                "",        bytesOf(u8, &.{ 2, 0 }),
                "",        "abcd",
                "",        bytesOf(i32, &.{ 1, 1 }),
                row0_null, bytesOf(i32, &.{ 1, 3, 5 }),
                "",        bytesOf(i32, &.{ 0, 1, 2, 3, 4, 5 }),
                "",        bytesOf(i64, &.{ 2, -3 }),
            },
        },
    });
    defer gpa.free(bytes);
    const f = try stream.readStream(a, bytes, .{});
    try testing.expectEqual(@as(usize, 2), f.len);
    const cell = struct {
        fn at(fr: df.Frame, name: []const u8, r: usize) df.Value {
            return fr.cell(r, name).?;
        }
    }.at;
    try testing.expectEqual(@as(i64, 1_999), cell(f, "ns", 0).int);
    try testing.expectEqual(@as(i64, -1), cell(f, "ns", 1).int);
    try testing.expectEqualStrings("1970-01-04", cell(f, "d64", 0).text);
    try testing.expectEqualStrings("1969-12-31", cell(f, "d64", 1).text);
    try testing.expectEqual(df.ColumnType.time, f.columnType("t32").?);
    try testing.expectEqual(@as(i64, 1_500_000), cell(f, "t32", 0).int);
    try testing.expectEqual(@as(i128, 12_345 * 10_000_000_000), cell(f, "dec2", 0).decimal);
    try testing.expectEqual(@as(i128, -10_000_000_000), cell(f, "dec2", 1).decimal);
    try testing.expectEqual(df.ColumnType.float32, f.columnType("h").?);
    try testing.expectEqual(@as(f64, -0.25), cell(f, "h", 1).float);
    try testing.expectEqual(df.ColumnType.categorical, f.columnType("u8i").?);
    try testing.expectEqualStrings("w", cell(f, "u8i", 0).text);
    try testing.expectEqualStrings("x", cell(f, "u8i", 1).text);
    try testing.expectEqual(df.ColumnType.binary, f.columnType("fsb").?);
    try testing.expectEqualStrings("cd", cell(f, "fsb", 1).text);
    try testing.expectEqual(df.ColumnType.int, f.columnType("dint").?);
    try testing.expectEqual(@as(i64, 20), cell(f, "dint", 0).int);
    try testing.expect(cell(f, "lst", 0) == .null);
    const l1 = cell(f, "lst", 1).list;
    try testing.expectEqual(@as(usize, 2), l1.len());
    try testing.expectEqual(@as(i64, 3), l1.get(0).int);
    try testing.expectEqual(@as(i64, 4), l1.get(1).int);
    try testing.expectEqual(@as(i64, -3_000_000), cell(f, "sec", 1).int);
}

fn oneInt32(gpa: Allocator, node: ipc.FieldNode, length: i64, values: []const u8, validity: []const u8) ![]u8 {
    const fields = [_]schema.Field{.{ .name = "x", .type = .{ .int = .{ .bits = 32, .signed = true } } }};
    return hand(gpa, &fields, &.{.{ .length = length, .nodes = &.{node}, .bufs = &.{ validity, values } }});
}

test "reader: targeted corruptions are errors" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const Case = struct { want: anyerror, bytes: []u8 };
    var cases: std.ArrayList(Case) = .empty;
    defer {
        for (cases.items) |c| gpa.free(c.bytes);
        cases.deinit(gpa);
    }
    // Values buffer shorter than the node claims.
    try cases.append(gpa, .{ .want = error.Malformed, .bytes = try oneInt32(gpa, .{ .length = 3, .null_count = 0 }, 3, bytesOf(i32, &.{ 1, 2 }), "") });
    // Null count with no bitmap.
    try cases.append(gpa, .{ .want = error.Malformed, .bytes = try oneInt32(gpa, .{ .length = 2, .null_count = 1 }, 2, bytesOf(i32, &.{ 1, 2 }), "") });
    // Column length differs from the batch.
    try cases.append(gpa, .{ .want = error.Malformed, .bytes = try oneInt32(gpa, .{ .length = 1, .null_count = 0 }, 2, bytesOf(i32, &.{ 1, 2 }), "") });
    // Lengths past max_rows.
    try cases.append(gpa, .{ .want = error.LimitExceeded, .bytes = try oneInt32(gpa, .{ .length = 1 << 40, .null_count = 0 }, 1 << 40, bytesOf(i32, &.{1}), "") });
    {
        // Text offsets running backwards.
        const fields = [_]schema.Field{.{ .name = "s", .type = .utf8 }};
        try cases.append(gpa, .{ .want = error.Malformed, .bytes = try hand(gpa, &fields, &.{.{ .length = 2, .nodes = &.{.{ .length = 2, .null_count = 0 }}, .bufs = &.{ "", bytesOf(i32, &.{ 0, 2, 1 }), "ab" } }}) });
        // Offsets past the data.
        try cases.append(gpa, .{ .want = error.Malformed, .bytes = try hand(gpa, &fields, &.{.{ .length = 1, .nodes = &.{.{ .length = 1, .null_count = 0 }}, .bufs = &.{ "", bytesOf(i32, &.{ 0, 9 }), "ab" } }}) });
    }
    {
        // A dictionary index past the dictionary; an index to a dictionary never sent.
        const fields = [_]schema.Field{.{ .name = "c", .type = .utf8, .dictionary = .{ .id = 3 } }};
        const dict: HandBatch = .{ .length = 1, .dict_id = 3, .nodes = &.{.{ .length = 1, .null_count = 0 }}, .bufs = &.{ "", bytesOf(i32, &.{ 0, 1 }), "a" } };
        const batch: HandBatch = .{ .length = 1, .nodes = &.{.{ .length = 1, .null_count = 0 }}, .bufs = &.{ "", bytesOf(i32, &.{1}) } };
        try cases.append(gpa, .{ .want = error.Malformed, .bytes = try hand(gpa, &fields, &.{ dict, batch }) });
        try cases.append(gpa, .{ .want = error.Malformed, .bytes = try hand(gpa, &fields, &.{batch}) });
        // A dictionary batch for an id the schema does not have.
        var other = dict;
        other.dict_id = 4;
        try cases.append(gpa, .{ .want = error.Malformed, .bytes = try hand(gpa, &fields, &.{other}) });
        // A replacement (non-delta) dictionary.
        try cases.append(gpa, .{ .want = error.Unsupported, .bytes = try hand(gpa, &fields, &.{ dict, dict }) });
    }
    {
        // List offsets past the child.
        const item = [_]schema.Field{.{ .name = "item", .type = .{ .int = .{ .bits = 32, .signed = true } } }};
        const fields = [_]schema.Field{.{ .name = "l", .type = .list, .children = &item }};
        try cases.append(gpa, .{ .want = error.Malformed, .bytes = try hand(gpa, &fields, &.{.{
            .length = 1,
            .nodes = &.{ .{ .length = 1, .null_count = 0 }, .{ .length = 1, .null_count = 0 } },
            .bufs = &.{ "", bytesOf(i32, &.{ 0, 2 }), "", bytesOf(i32, &.{1}) },
        }}) });
        // Too few nodes for the schema.
        try cases.append(gpa, .{ .want = error.Malformed, .bytes = try hand(gpa, &fields, &.{.{ .length = 1, .nodes = &.{.{ .length = 1, .null_count = 0 }}, .bufs = &.{ "", bytesOf(i32, &.{ 0, 0 }) } }}) });
    }
    {
        // A timestamp zone dataframe does not know; a 256-bit decimal of 77 digits.
        const fields = [_]schema.Field{.{ .name = "t", .type = .{ .timestamp = .{ .unit = .second, .tz = "Mars/Olympus" } } }};
        try cases.append(gpa, .{ .want = error.Unsupported, .bytes = try hand(gpa, &fields, &.{}) });
        const f2 = [_]schema.Field{.{ .name = "d", .type = .{ .decimal = .{ .precision = 77, .scale = 0, .bits = 256 } } }};
        try cases.append(gpa, .{ .want = error.Malformed, .bytes = try hand(gpa, &f2, &.{}) });
    }
    for (cases.items, 0..) |c, i| {
        const got = stream.readStream(a, c.bytes, .{});
        if (got) |_| {
            std.debug.print("case {d}: decoded, want {s}\n", .{ i, @errorName(c.want) });
            return error.TestUnexpectedResult;
        } else |e| if (e != c.want) {
            std.debug.print("case {d}: {s}, want {s}\n", .{ i, @errorName(e), @errorName(c.want) });
            return error.TestUnexpectedError;
        }
    }
    // No schema at all; only the end-of-stream marker.
    try testing.expectError(error.Malformed, stream.readStream(a, "", .{}));
    try testing.expectError(error.Malformed, stream.readStream(a, &.{ 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0 }, .{}));
}

test "reader: every truncation and byte flip of a multi-batch stream is an error or a frame, never a crash" {
    const gpa = testing.allocator;
    var keep = std.heap.ArenaAllocator.init(gpa);
    defer keep.deinit();
    const ka = keep.allocator();
    const full = try sampleFrame(ka);
    // A narrower frame keeps the sweep quick; still nested, dictionary and bitmap columns.
    const pick = [_][]const u8{ "i64", "s", "cat", "ord", "l", "arr", "st", "lcat", "u64" };
    var cols: [pick.len]Column = undefined;
    var data: [pick.len]ColumnData = undefined;
    for (pick, 0..) |p, i| {
        const ci = full.columnIndex(p).?;
        cols[i] = full.columns[ci];
        data[i] = full.data[ci];
    }
    const f: df.Frame = .{ .columns = &cols, .data = &data, .len = full.len };
    const good = try stream.writeStream(gpa, f, .{ .rows_per_batch = 2 });
    defer gpa.free(good);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const opts: stream.ReadOptions = .{ .max_rows = 1 << 12 };
    try expectSameFrame(f, try stream.readStream(arena_state.allocator(), good, opts));
    for (0..good.len) |n| {
        _ = arena_state.reset(.retain_capacity);
        _ = stream.readStream(arena_state.allocator(), good[0..n], opts) catch {};
    }
    const copy = try gpa.alloc(u8, good.len);
    defer gpa.free(copy);
    for (0..good.len) |i| {
        for ([_]u8{ 0x00, 0x01, 0x7f, 0x80, 0xff }) |v| {
            @memcpy(copy, good);
            copy[i] = v;
            _ = arena_state.reset(.retain_capacity);
            _ = stream.readStream(arena_state.allocator(), copy, opts) catch {};
        }
    }
}

// ── the file format ─────────────────────────────────────────────────────────

/// `got` holds rows `off..off + got.len` of `want`.
fn expectRows(want: df.Frame, off: usize, got: df.Frame) !void {
    try testing.expectEqual(want.columns.len, got.columns.len);
    for (want.columns, 0..) |wc, ci| {
        try expectSameType(wc, got.columns[ci]);
        for (0..got.len) |r| {
            const x = want.columnAt(ci).get(off + r);
            const y = got.columnAt(ci).get(r);
            if (std.meta.activeTag(x) != std.meta.activeTag(y) or (x != .null and !x.eql(y))) {
                std.debug.print("column {s} row {d}: want {any} got {any}\n", .{ wc.name, off + r, x, y });
                return error.TestExpectedEqual;
            }
        }
    }
}

test "file: round trip, both ARROW1 marks, random access to each batch" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const f = try sampleFrame(a);
    const bytes = try stream.writeFile(gpa, f, .{ .rows_per_batch = 2 });
    defer gpa.free(bytes);
    try testing.expectEqualStrings("ARROW1", bytes[0..6]);
    try testing.expectEqualStrings("ARROW1", bytes[bytes.len - 6 ..]);
    try expectSameFrame(f, try stream.readFile(a, bytes, .{}));

    var file = try stream.openFile(a, bytes, .{});
    try testing.expectEqual(@as(usize, 3), file.batchCount());
    try testing.expectEqual(@as(usize, 1), try file.batchRows(2));
    try testing.expectError(error.Unsupported, file.batchRows(3));
    // Out of order, each batch alone.
    for ([_]usize{ 2, 0, 1 }) |i| {
        const got = try file.readBatch(i);
        try testing.expectEqual(try file.batchRows(i), got.len);
        try expectRows(f, i * 2, got);
    }
    try testing.expectError(error.Unsupported, file.readBatch(3));
    try expectSameFrame(f, try file.readAll());

    // An empty frame: no record batch, the schema and the (empty) dictionaries only.
    const empty: df.Frame = .{ .columns = f.columns, .data = &.{}, .len = 0 };
    const eb = try stream.writeFile(gpa, empty, .{});
    defer gpa.free(eb);
    var ef = try stream.openFile(a, eb, .{});
    try testing.expectEqual(@as(usize, 0), ef.batchCount());
    try expectSameFrame(empty, try ef.readAll());
}

test "file: bad marks, footer and blocks are errors; every truncation and byte flip is an error or a frame" {
    const gpa = testing.allocator;
    var keep = std.heap.ArenaAllocator.init(gpa);
    defer keep.deinit();
    const full = try sampleFrame(keep.allocator());
    const pick = [_][]const u8{ "i64", "s", "cat", "l", "arr", "st" };
    var cols: [pick.len]Column = undefined;
    var data: [pick.len]ColumnData = undefined;
    for (pick, 0..) |p, i| {
        const ci = full.columnIndex(p).?;
        cols[i] = full.columns[ci];
        data[i] = full.data[ci];
    }
    const f: df.Frame = .{ .columns = &cols, .data = &data, .len = full.len };
    const good = try stream.writeFile(gpa, f, .{ .rows_per_batch = 2 });
    defer gpa.free(good);
    const sbytes = try stream.writeStream(gpa, f, .{});
    defer gpa.free(sbytes);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const opts: stream.ReadOptions = .{ .max_rows = 1 << 12 };
    try expectSameFrame(f, try stream.readFile(a, good, opts));

    // A stream is not a file.
    try testing.expectError(error.Malformed, stream.readFile(a, sbytes, opts));
    const copy = try gpa.alloc(u8, good.len);
    defer gpa.free(copy);
    // The trailing mark; the footer length past the start, zero, negative.
    @memcpy(copy, good);
    copy[copy.len - 1] = '2';
    try testing.expectError(error.Malformed, stream.readFile(a, copy, opts));
    for ([_]i32{ std.math.maxInt(i32), 0, -8, @intCast(good.len - 10) }) |bad| {
        @memcpy(copy, good);
        std.mem.writeInt(i32, copy[copy.len - 10 ..][0..4], bad, .little);
        try testing.expectError(error.Malformed, stream.readFile(a, copy, opts));
    }

    for (0..good.len) |n| {
        _ = arena_state.reset(.retain_capacity);
        _ = stream.readFile(arena_state.allocator(), good[0..n], opts) catch {};
    }
    for (0..good.len) |i| {
        for ([_]u8{ 0x00, 0x01, 0x7f, 0x80, 0xff }) |v| {
            @memcpy(copy, good);
            copy[i] = v;
            _ = arena_state.reset(.retain_capacity);
            var file = stream.openFile(arena_state.allocator(), copy, opts) catch continue;
            for (0..file.batchCount()) |b| _ = file.readBatch(b) catch {};
        }
    }
}

// ── body compression (wave A5) ──────────────────────────────────────────────

const zstd = @import("zstd");

/// Counts the compressed buffers of every batch of `bytes` by their prefix: stored raw
/// (-1) or compressed (a length); fails on a batch that is not marked zstd.
fn countPrefixes(a: Allocator, bytes: []const u8) !struct { raw: usize, packed_: usize } {
    var pos: usize = 0;
    var raw: usize = 0;
    var packed_: usize = 0;
    _ = try ipc.readMessage(bytes, &pos); // the schema
    while (true) {
        const m = ipc.readMessage(bytes, &pos) catch |e| switch (e) {
            error.EndOfStream => break,
            else => return e,
        };
        const rb = if (m.msg.header_type == .dictionary_batch)
            (try ipc.decodeDictionaryBatch(a, m.msg.header.?, m.enc.body.len)).data
        else
            try ipc.decodeRecordBatch(a, m.msg.header.?, m.enc.body.len);
        try testing.expectEqual(ipc.Codec.zstd, rb.compression.?);
        for (rb.buffers) |l| {
            if (l.length == 0) continue;
            const b = m.enc.body[@intCast(l.offset)..][0..@intCast(l.length)];
            if (std.mem.readInt(i64, b[0..8], .little) == -1) raw += 1 else packed_ += 1;
        }
    }
    return .{ .raw = raw, .packed_ = packed_ };
}

test "compression: zstd round trip of every column type, stream and file, one batch and many" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const f = try sampleFrame(a);
    for ([_]usize{ 0, 1, 2, 100 }) |per| {
        const opts: stream.WriteOptions = .{ .rows_per_batch = per, .compression = .zstd };
        const s = try stream.writeStream(gpa, f, opts);
        defer gpa.free(s);
        try expectSameFrame(f, try stream.readStream(a, s, .{}));
        const fl = try stream.writeFile(gpa, f, opts);
        defer gpa.free(fl);
        try expectSameFrame(f, try stream.readFile(a, fl, .{}));
        var file = try stream.openFile(a, fl, .{});
        try expectRows(f, 0, try file.readBatch(0));
    }
    // Five-row buffers do not shrink: stored raw behind -1.
    const small = try stream.writeStream(gpa, f, .{ .compression = .zstd });
    defer gpa.free(small);
    const sc = try countPrefixes(a, small);
    try testing.expect(sc.raw > 0);

    // A long repetitive column does shrink, at any level.
    const n = 4096;
    const vals = try a.alloc(i64, n);
    for (vals, 0..) |*v, i| v.* = @intCast(i % 7);
    const big: df.Frame = .{ .columns = &.{.{ .name = "x", .type = .int }}, .data = &.{.{ .int = .{ .values = vals } }}, .len = n };
    const plain = try stream.writeStream(gpa, big, .{});
    defer gpa.free(plain);
    for ([_]i32{ -5, 0, 1, 19 }) |level| {
        const z = try stream.writeStream(gpa, big, .{ .compression = .zstd, .compression_level = level });
        defer gpa.free(z);
        try testing.expect(z.len * 4 < plain.len);
        try testing.expect((try countPrefixes(a, z)).packed_ == 1);
        try expectSameFrame(big, try stream.readStream(a, z, .{}));
    }
    // A level zstd refuses.
    try testing.expectError(error.Unsupported, stream.writeStream(gpa, big, .{ .compression = .zstd, .compression_level = 23 }));
}

test "compression: declared lengths, broken frames and LZ4 are errors" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const fields = [_]schema.Field{.{ .name = "x", .type = .{ .int = .{ .bits = 32, .signed = true } } }};
    const vals = bytesOf(i32, &.{ 7, -8 });
    var frame_buf: [64]u8 = undefined;
    const fl = try zstd.compress(gpa, &frame_buf, vals, .{});
    const frame = frame_buf[0..fl];
    const pre = struct {
        fn with(al: Allocator, len: i64, payload: []const u8) ![]u8 {
            const out = try al.alloc(u8, 8 + payload.len);
            std.mem.writeInt(i64, out[0..8], len, .little);
            @memcpy(out[8..], payload);
            return out;
        }
    }.with;
    const node: ipc.FieldNode = .{ .length = 2, .null_count = 0 };
    const Case = struct { want: ?anyerror, codec: ipc.Codec = .zstd, buf: []const u8 };
    const cases = [_]Case{
        .{ .want = null, .buf = try pre(a, 8, frame) },
        .{ .want = null, .buf = try pre(a, -1, vals) },
        .{ .want = error.LimitExceeded, .buf = try pre(a, 1 << 40, frame) },
        .{ .want = error.Malformed, .buf = try pre(a, -2, frame) },
        .{ .want = error.Malformed, .buf = "\x08\x00\x00" },
        .{ .want = error.Malformed, .buf = try pre(a, 16, frame) }, // decodes to fewer bytes than declared
        .{ .want = error.Malformed, .buf = try pre(a, 4, frame) }, // more
        .{ .want = error.Malformed, .buf = try pre(a, 8, "not a zstd frame") },
        .{ .want = error.Malformed, .buf = try pre(a, 8, "") },
        .{ .want = error.Unsupported, .codec = .lz4_frame, .buf = try pre(a, -1, vals) },
        .{ .want = error.Unsupported, .codec = @fromBackingInt(@intCast(7)), .buf = try pre(a, -1, vals) },
    };
    for (cases, 0..) |c, i| {
        const bytes = try hand(gpa, &fields, &.{.{ .length = 2, .nodes = &.{node}, .bufs = &.{ "", c.buf }, .codec = c.codec }});
        defer gpa.free(bytes);
        const got = stream.readStream(a, bytes, .{});
        if (c.want) |e| {
            testing.expectError(e, got) catch |x| {
                std.debug.print("case {d}\n", .{i});
                return x;
            };
        } else {
            const f = try got;
            try testing.expectEqual(@as(i64, 7), f.columnAt(0).get(0).int);
            try testing.expectEqual(@as(i64, -8), f.columnAt(0).get(1).int);
        }
    }
    // The body cap counts the whole message.
    const two = try hand(gpa, &fields, &.{.{ .length = 2, .nodes = &.{node}, .bufs = &.{ try pre(a, -1, "\xff"), try pre(a, 8, frame) }, .codec = .zstd }});
    defer gpa.free(two);
    try testing.expectError(error.LimitExceeded, stream.readStream(a, two, .{ .max_body_bytes = 8 }));
    _ = try stream.readStream(a, two, .{ .max_body_bytes = 9 });
}

test "compression: every truncation and byte flip of a compressed stream is an error or a frame" {
    const gpa = testing.allocator;
    var keep = std.heap.ArenaAllocator.init(gpa);
    defer keep.deinit();
    const ka = keep.allocator();
    const full = try sampleFrame(ka);
    const pick = [_][]const u8{ "i64", "s", "cat", "l", "st" };
    var cols: [pick.len]Column = undefined;
    var data: [pick.len]ColumnData = undefined;
    for (pick, 0..) |p, i| {
        const ci = full.columnIndex(p).?;
        cols[i] = full.columns[ci];
        data[i] = full.data[ci];
    }
    // Small buffers: most are stored raw (-1); the fuzz driver damages compressed frames.
    const f0: df.Frame = .{ .columns = &cols, .data = &data, .len = full.len };
    const good = try stream.writeStream(gpa, f0, .{ .rows_per_batch = 3, .compression = .zstd });
    defer gpa.free(good);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const opts: stream.ReadOptions = .{ .max_rows = 1 << 12, .max_body_bytes = 1 << 16 };
    try expectSameFrame(f0, try stream.readStream(arena_state.allocator(), good, opts));
    for (0..good.len) |n| {
        _ = arena_state.reset(.retain_capacity);
        _ = stream.readStream(arena_state.allocator(), good[0..n], opts) catch {};
    }
    const copy = try gpa.alloc(u8, good.len);
    defer gpa.free(copy);
    for (0..good.len) |i| {
        for ([_]u8{ 0x00, 0x7f, 0xff }) |v| {
            @memcpy(copy, good);
            copy[i] = v;
            _ = arena_state.reset(.retain_capacity);
            _ = stream.readStream(arena_state.allocator(), copy, opts) catch {};
        }
    }
}

// ── lossy reads (ReadOptions.lossy) ─────────────────────────────────────────

test "lossy: values dataframe cannot hold fail the read by default and read as null with lossy" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const node: ipc.FieldNode = .{ .length = 2, .null_count = 0 };
    const Case = struct { field: schema.Field, values: []const u8, row1: df.Value };
    const cases = [_]Case{
        // 10^37 at scale 0 needs 49 digits at dataframe's 12.
        .{ .field = .{ .name = "dec", .type = .{ .decimal = .{ .precision = 38, .scale = 0 } } }, .values = bytesOf(i128, &.{ std.math.pow(i128, 10, 37), 5 }), .row1 = .{ .decimal = 5 * df.decimal_scale } },
        // 10^-14 has digits past the 12th.
        .{ .field = .{ .name = "dec14", .type = .{ .decimal = .{ .precision = 20, .scale = 14 } } }, .values = bytesOf(i128, &.{ 1, 300 }), .row1 = .{ .decimal = 3 } },
        // 24:00:00, which Arrow allows.
        .{ .field = .{ .name = "t", .type = .{ .time = .{ .unit = .second, .bits = 32 } } }, .values = bytesOf(i32, &.{ 86_400, 1 }), .row1 = .{ .int = 1_000_000 } },
        .{ .field = .{ .name = "tneg", .type = .{ .time = .{ .unit = .microsecond, .bits = 64 } } }, .values = bytesOf(i64, &.{ -1, 2 }), .row1 = .{ .int = 2 } },
        // Year 12921.
        .{ .field = .{ .name = "d", .type = .{ .date = .day } }, .values = bytesOf(i32, &.{ 4_000_000, 0 }), .row1 = .{ .text = "1970-01-01" } },
        // Seconds whose microseconds overflow i64.
        .{ .field = .{ .name = "ts", .type = .{ .timestamp = .{ .unit = .second } } }, .values = bytesOf(i64, &.{ std.math.maxInt(i64), 2 }), .row1 = .{ .int = 2_000_000 } },
        .{ .field = .{ .name = "dur", .type = .{ .duration = .millisecond } }, .values = bytesOf(i64, &.{ std.math.minInt(i64), 3 }), .row1 = .{ .int = 3_000 } },
    };
    for (cases) |c| {
        const bytes = try hand(gpa, &.{c.field}, &.{.{ .length = 2, .nodes = &.{node}, .bufs = &.{ "", c.values } }});
        defer gpa.free(bytes);
        try testing.expectError(error.Unsupported, stream.readStream(a, bytes, .{}));
        const f = try stream.readStream(a, bytes, .{ .lossy = true });
        try testing.expect(f.columnAt(0).get(0) == .null);
        const got = f.columnAt(0).get(1);
        if (!got.eql(c.row1)) {
            std.debug.print("{s}: want {any} got {any}\n", .{ c.field.name, c.row1, got });
            return error.TestExpectedEqual;
        }
    }
    // A zone `tz` does not know: the column reads naive, every instant kept.
    const zf = [_]schema.Field{.{ .name = "z", .type = .{ .timestamp = .{ .unit = .microsecond, .tz = "Nowhere/Atlantis" } } }};
    const zb = try hand(gpa, &zf, &.{.{ .length = 2, .nodes = &.{node}, .bufs = &.{ "", bytesOf(i64, &.{ 5, 6 }) } }});
    defer gpa.free(zb);
    try testing.expectError(error.Unsupported, stream.readStream(a, zb, .{}));
    const zr = try stream.readStream(a, zb, .{ .lossy = true });
    try testing.expectEqual(df.ColumnType.timestamp, zr.columns[0].type);
    try testing.expect(zr.columns[0].time_zone == null);
    try testing.expectEqual(@as(i64, 5), zr.columnAt(0).get(0).int);
    try testing.expectEqual(@as(i64, 6), zr.columnAt(0).get(1).int);
    // `lossy` does not excuse a malformed stream.
    const short = try oneInt32(gpa, .{ .length = 3, .null_count = 0 }, 3, bytesOf(i32, &.{ 1, 2 }), "");
    defer gpa.free(short);
    try testing.expectError(error.Malformed, stream.readStream(a, short, .{ .lossy = true }));
}

// ── review fixes (2026-11-17) ───────────────────────────────────────────────

test "utf8: the writer refuses text that is not UTF-8; the reader checks Utf8 unless told not to" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const bad = try textCol(a, &.{ "ok", "\xff\xfe", null });
    const frames = [_]df.Frame{
        .{ .columns = &.{.{ .name = "s", .type = .text }}, .data = &.{.{ .text = bad }}, .len = 3 },
        // A categorical's dictionary; text storage under a categorical declaration.
        .{ .columns = &.{.{ .name = "c", .type = .categorical }}, .data = &.{.{ .categorical = .{ .codes = .{ .values = &.{ 0, 1, 0 } }, .dict = try textCol(a, &.{ "a", "\xc3" }) } }}, .len = 3 },
        .{ .columns = &.{.{ .name = "c", .type = .categorical }}, .data = &.{.{ .text = bad }}, .len = 3 },
    };
    for (frames) |f| {
        try testing.expectError(error.InvalidUtf8, stream.writeStream(gpa, f, .{}));
        try testing.expectError(error.InvalidUtf8, stream.writeFile(gpa, f, .{ .compression = .zstd }));
    }
    // The same bytes declared binary are written as Binary.
    const bin: df.Frame = .{ .columns = &.{.{ .name = "b", .type = .binary }}, .data = &.{.{ .text = bad }}, .len = 3 };
    try expectSameFrame(bin, try roundTrip(a, bin, .{}));

    // Reader: a Utf8 value and a Utf8 dictionary entry that are not UTF-8.
    const node: ipc.FieldNode = .{ .length = 2, .null_count = 0 };
    const sf = [_]schema.Field{.{ .name = "s", .type = .large_utf8 }};
    const sb = try hand(gpa, &sf, &.{.{ .length = 2, .nodes = &.{node}, .bufs = &.{ "", bytesOf(i64, &.{ 0, 1, 3 }), "a\xe2\x82" } }});
    defer gpa.free(sb);
    try testing.expectError(error.InvalidUtf8, stream.readStream(a, sb, .{}));
    try testing.expectError(error.InvalidUtf8, stream.readStream(a, sb, .{ .lossy = true }));
    const raw = try stream.readStream(a, sb, .{ .validate_utf8 = false });
    try testing.expectEqualStrings("\xe2\x82", raw.columnAt(0).get(1).text);
    const df_ = [_]schema.Field{.{ .name = "c", .type = .utf8, .dictionary = .{ .id = 0 } }};
    const db = try hand(gpa, &df_, &.{
        .{ .length = 2, .dict_id = 0, .nodes = &.{node}, .bufs = &.{ "", bytesOf(i32, &.{ 0, 1, 2 }), "x\x80" } },
        .{ .length = 2, .nodes = &.{node}, .bufs = &.{ "", bytesOf(i32, &.{ 0, 0 }) } },
    });
    defer gpa.free(db);
    try testing.expectError(error.InvalidUtf8, stream.readStream(a, db, .{}));
    _ = try stream.readStream(a, db, .{ .validate_utf8 = false });
    // Binary is never checked.
    const bf = [_]schema.Field{.{ .name = "b", .type = .binary }};
    const bb = try hand(gpa, &bf, &.{.{ .length = 2, .nodes = &.{node}, .bufs = &.{ "", bytesOf(i32, &.{ 0, 1, 3 }), "a\xe2\x82" } }});
    defer gpa.free(bb);
    _ = try stream.readStream(a, bb, .{});
}

test "inexact time conversions: refused without lossy, times truncated toward zero, dates floored to their day with it" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const node: ipc.FieldNode = .{ .length = 3, .null_count = 0 };
    const Case = struct { field: schema.Field, values: []const u8, want: [3]df.Value };
    const cases = [_]Case{
        // -1 ns truncates to 0 us (a floor would give -1); -1999 ns to -1 us.
        .{ .field = .{ .name = "ts", .type = .{ .timestamp = .{ .unit = .nanosecond } } }, .values = bytesOf(i64, &.{ -1, -1_999, 1_700_000_000_123_456_789 }), .want = .{ .{ .int = 0 }, .{ .int = -1 }, .{ .int = 1_700_000_000_123_456 } } },
        .{ .field = .{ .name = "dur", .type = .{ .duration = .nanosecond } }, .values = bytesOf(i64, &.{ -1, -1_999, 2_500 }), .want = .{ .{ .int = 0 }, .{ .int = -1 }, .{ .int = 2 } } },
        .{ .field = .{ .name = "t", .type = .{ .time = .{ .unit = .nanosecond, .bits = 64 } } }, .values = bytesOf(i64, &.{ 1, 1_999, 3_000 }), .want = .{ .{ .int = 0 }, .{ .int = 1 }, .{ .int = 3 } } },
        // Date64 off a day boundary is floored to the day that contains the instant.
        .{ .field = .{ .name = "d", .type = .{ .date = .millisecond } }, .values = bytesOf(i64, &.{ -1, 86_400_000 + 1, -86_400_000 - 1 }), .want = .{ .{ .text = "1969-12-31" }, .{ .text = "1970-01-02" }, .{ .text = "1969-12-30" } } },
    };
    for (cases) |c| {
        const bytes = try hand(gpa, &.{c.field}, &.{.{ .length = 3, .nodes = &.{node}, .bufs = &.{ "", c.values } }});
        defer gpa.free(bytes);
        try testing.expectError(error.Unsupported, stream.readStream(a, bytes, .{}));
        const f = try stream.readStream(a, bytes, .{ .lossy = true });
        for (c.want, 0..) |w, i| {
            const got = f.columnAt(0).get(i);
            if (!got.eql(w)) {
                std.debug.print("{s} row {d}: want {any} got {any}\n", .{ c.field.name, i, w, got });
                return error.TestExpectedEqual;
            }
        }
    }
    // Exact values read without lossy, negative ones included.
    const exact = try hand(gpa, &.{.{ .name = "ts", .type = .{ .timestamp = .{ .unit = .nanosecond } } }}, &.{.{ .length = 3, .nodes = &.{node}, .bufs = &.{ "", bytesOf(i64, &.{ -1_000, 0, 5_000 }) } }});
    defer gpa.free(exact);
    const f = try stream.readStream(a, exact, .{});
    try testing.expectEqual(@as(i64, -1), f.columnAt(0).get(0).int);
}

test "metadata version: V4 and V5 read, older or unknown versions are Unsupported" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const fields = [_]schema.Field{.{ .name = "x", .type = .{ .int = .{ .bits = 32, .signed = true } } }};
    for ([_]struct { v: schema.MetadataVersion, ok: bool }{
        .{ .v = .v5, .ok = true },
        .{ .v = .v4, .ok = true },
        .{ .v = .v3, .ok = false },
        .{ .v = .v1, .ok = false },
        .{ .v = @fromBackingInt(@intCast(5)), .ok = false },
    }) |c| {
        var b = fb.Builder.init(gpa);
        defer b.deinit();
        const sref = try schema.encodeSchema(&b, .{ .fields = &fields });
        b.startTable();
        try b.addScalarForce(0, schema.MetadataVersion, c.v);
        try b.addScalarForce(1, schema.HeaderType, .schema);
        try b.addOffset(2, sref);
        const meta = try b.finish(try b.endTable());
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        try ipc.writeMessage(gpa, &out, meta, &.{});
        try ipc.writeEos(gpa, &out);
        if (c.ok) _ = try stream.readStream(a, out.items, .{}) else try testing.expectError(error.Unsupported, stream.readStream(a, out.items, .{}));
    }
}

test "decimal precision: written as the widest value's digits; values wider than declared are refused" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const precisionOf = struct {
        fn f(al: Allocator, values: []const i128) !i32 {
            const fr: df.Frame = .{ .columns = &.{.{ .name = "d", .type = .decimal }}, .data = &.{.{ .decimal = .{ .values = values } }}, .len = values.len };
            const bytes = try stream.writeStream(testing.allocator, fr, .{});
            defer testing.allocator.free(bytes);
            try expectSameFrame(fr, try stream.readStream(al, bytes, .{}));
            var pos: usize = 0;
            const m = try ipc.readMessage(bytes, &pos);
            return (try schema.decodeSchema(al, m.msg.header.?)).fields[0].type.decimal.precision;
        }
    }.f;
    try testing.expectEqual(@as(i32, 12), try precisionOf(a, &.{ 5, -7 }));
    try testing.expectEqual(@as(i32, 18), try precisionOf(a, &.{ 123_456 * scale, -1 }));
    try testing.expectEqual(@as(i32, 38), try precisionOf(a, &.{std.math.pow(i128, 10, 38) - 1}));
    // 39 digits fit an i128 but no Decimal128.
    for ([_]i128{ std.math.pow(i128, 10, 38), std.math.maxInt(i128), std.math.minInt(i128) }) |x| {
        const fr: df.Frame = .{ .columns = &.{.{ .name = "d", .type = .decimal }}, .data = &.{.{ .decimal = .{ .values = &.{x} } }}, .len = 1 };
        try testing.expectError(error.Unsupported, stream.writeStream(gpa, fr, .{}));
    }

    const node: ipc.FieldNode = .{ .length = 2, .null_count = 0 };
    // Decimal128(3, 0) holding 1000: more digits than declared.
    const wide = try hand(gpa, &.{.{ .name = "d", .type = .{ .decimal = .{ .precision = 3, .scale = 0 } } }}, &.{.{ .length = 2, .nodes = &.{node}, .bufs = &.{ "", bytesOf(i128, &.{ 1000, -999 }) } }});
    defer gpa.free(wide);
    try testing.expectError(error.Unsupported, stream.readStream(a, wide, .{}));
    const lf = try stream.readStream(a, wide, .{ .lossy = true });
    try testing.expect(lf.columnAt(0).get(0) == .null);
    try testing.expectEqual(-999 * scale, lf.columnAt(0).get(1).decimal);
    // Decimal128(38, 11) holding 1.2e37: 39 digits once at 12 fractional digits.
    const big = try hand(gpa, &.{.{ .name = "d", .type = .{ .decimal = .{ .precision = 38, .scale = 11 } } }}, &.{.{ .length = 2, .nodes = &.{node}, .bufs = &.{ "", bytesOf(i128, &.{ 12 * std.math.pow(i128, 10, 36), 1 }) } }});
    defer gpa.free(big);
    try testing.expectError(error.Unsupported, stream.readStream(a, big, .{}));
    try testing.expect((try stream.readStream(a, big, .{ .lossy = true })).columnAt(0).get(0) == .null);
    // A precision Decimal128 cannot have.
    for ([_]i32{ 0, 39, -1 }) |p| {
        const bp = try hand(gpa, &.{.{ .name = "d", .type = .{ .decimal = .{ .precision = p, .scale = 0 } } }}, &.{});
        defer gpa.free(bp);
        try testing.expectError(error.Malformed, stream.readStream(a, bp, .{}));
    }
}

test "a dictionary shared by two fields: read when the value types agree, refused otherwise" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const node: ipc.FieldNode = .{ .length = 2, .null_count = 0 };
    const dict: HandBatch = .{ .length = 2, .dict_id = 0, .nodes = &.{node}, .bufs = &.{ "", bytesOf(i32, &.{ 0, 1, 2 }), "yx" } };
    const batch: HandBatch = .{ .length = 2, .nodes = &.{ node, node }, .bufs = &.{ "", bytesOf(i32, &.{ 0, 1 }), "", bytesOf(u8, &.{ 1, 1 }) } };
    const shared = [_]schema.Field{
        .{ .name = "p", .type = .utf8, .dictionary = .{ .id = 0 } },
        .{ .name = "q", .type = .utf8, .dictionary = .{ .id = 0, .index = .{ .bits = 8, .signed = false } } },
    };
    const ok = try hand(gpa, &shared, &.{ dict, batch });
    defer gpa.free(ok);
    const f = try stream.readStream(a, ok, .{});
    try testing.expectEqualStrings("p", f.columns[0].name);
    try testing.expectEqualStrings("q", f.columns[1].name);
    try testing.expectEqual(df.ColumnType.categorical, f.columns[1].type);
    try testing.expectEqualStrings("y", f.cell(0, "p").?.text);
    try testing.expectEqualStrings("x", f.cell(1, "p").?.text);
    try testing.expectEqualStrings("x", f.cell(0, "q").?.text);
    // Projected: the dictionary is read when either of its columns is picked.
    for ([_][]const u8{ "p", "q" }) |nm| {
        const one = [_]stream.ColumnRef{.{ .name = nm }};
        const g = try stream.readStream(a, ok, .{ .columns = &one });
        try testing.expectEqual(@as(usize, 1), g.columns.len);
        try testing.expectEqualStrings(f.cell(0, nm).?.text, g.cell(0, nm).?.text);
        try testing.expectEqualStrings(f.cell(1, nm).?.text, g.cell(1, nm).?.text);
    }

    const Case = struct { want: anyerror, second: schema.Field };
    for ([_]Case{
        .{ .want = error.Malformed, .second = .{ .name = "q", .type = .binary, .dictionary = .{ .id = 0, .index = .{ .bits = 8, .signed = false } } } },
        .{ .want = error.Malformed, .second = .{ .name = "q", .type = .large_utf8, .dictionary = .{ .id = 0, .index = .{ .bits = 8, .signed = false } } } },
        .{ .want = error.Unsupported, .second = .{ .name = "q", .type = .utf8, .dictionary = .{ .id = 0, .index = .{ .bits = 8, .signed = false }, .ordered = true } } },
    }) |c| {
        const bytes = try hand(gpa, &.{ shared[0], c.second }, &.{ dict, batch });
        defer gpa.free(bytes);
        try testing.expectError(c.want, stream.readStream(a, bytes, .{}));
    }
}

test "a Utf8View dictionary: categorical, its variadic buffers in the DictionaryBatch; skipped unread when no picked column uses it" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const fields = [_]schema.Field{
        .{ .name = "v", .type = .utf8_view, .dictionary = .{ .id = 0 } },
        .{ .name = "n", .type = .{ .int = .{ .bits = 32, .signed = true } } },
    };
    const long = "a dictionary value past twelve bytes";
    const node: ipc.FieldNode = .{ .length = 2, .null_count = 0 };
    const batch: HandBatch = .{ .length = 2, .nodes = &.{ node, node }, .bufs = &.{ "", bytesOf(i32, &.{ 1, 0 }), "", bytesOf(i32, &.{ 7, 8 }) } };
    for ([_]bool{ true, false }) |good| {
        var views: [32]u8 = undefined;
        views[0..16].* = view("s", 0, 0);
        views[16..32].* = view(long, 0, 3);
        if (!good) views[20] = 'X'; // a prefix that is not the data's
        const dict: HandBatch = .{ .length = 2, .dict_id = 0, .variadic = &.{1}, .nodes = &.{node}, .bufs = &.{ "", &views, "xyz" ++ long } };
        const bytes = try hand(gpa, &fields, &.{ dict, batch });
        defer gpa.free(bytes);
        const by_v = [_]stream.ColumnRef{.{ .name = "v" }};
        if (good) {
            for ([_]?[]const stream.ColumnRef{ null, &by_v }) |cols| {
                const f = try stream.readStream(a, bytes, .{ .columns = cols });
                try testing.expectEqual(df.ColumnType.categorical, f.columns[0].type);
                try testing.expectEqualStrings(long, f.cell(0, "v").?.text);
                try testing.expectEqualStrings("s", f.cell(1, "v").?.text);
            }
        } else {
            try testing.expectError(error.Malformed, stream.readStream(a, bytes, .{}));
            try testing.expectError(error.Malformed, stream.readStream(a, bytes, .{ .columns = &by_v }));
        }
        // Only `n` picked: the dictionary's body is not read, the bad one included.
        const by_n = [_]stream.ColumnRef{.{ .index = 1 }};
        const g = try stream.readStream(a, bytes, .{ .columns = &by_n });
        try testing.expectEqual(@as(usize, 1), g.columns.len);
        try testing.expectEqual(@as(i64, 8), g.cell(1, "n").?.int);
    }
}

test "metadata: schema, field (nested) and footer key/value metadata round trip; extra columns are Unsupported, extra children dropped" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const f = try sampleFrame(a);
    const kv = struct {
        fn one(comptime k: []const u8, comptime v: []const u8) []const stream.KeyValue {
            const x = [_]stream.KeyValue{.{ .key = k, .value = v }};
            return &x;
        }
    }.one;
    var fm: [24]stream.FieldMetadata = @splat(.{});
    fm[0] = .{ .metadata = kv("unit", "m/s") };
    fm[21] = .{ .children = &.{.{ .metadata = kv("odd_values", "{}") }} }; // l: its item
    fm[23] = .{ .metadata = kv("ARROW:extension:name", "point"), .children = &.{ .{}, .{ .metadata = kv("b", "") } } }; // st
    const schema_md = [_]stream.KeyValue{ .{ .key = "pandas", .value = "{\"index_columns\": []}" }, .{ .key = "empty", .value = "" } };
    const wo: stream.WriteOptions = .{ .schema_metadata = &schema_md, .field_metadata = &fm, .footer_metadata = kv("written_by", "zig-libs") };
    for ([_]bool{ false, true }) |file| {
        const bytes = if (file) try stream.writeFile(gpa, f, wo) else try stream.writeStream(gpa, f, wo);
        defer gpa.free(bytes);
        var md: stream.Metadata = .{};
        const back = if (file) try stream.readFile(a, bytes, .{ .metadata = &md }) else try stream.readStream(a, bytes, .{ .metadata = &md });
        try expectSameFrame(f, back);
        try testing.expectEqual(@as(usize, 2), md.schema.len);
        try testing.expectEqualStrings("pandas", md.schema[0].key);
        try testing.expectEqualStrings("{\"index_columns\": []}", md.schema[0].value);
        try testing.expectEqualStrings("", md.schema[1].value);
        try testing.expectEqual(f.columns.len, md.fields.len);
        try testing.expectEqualStrings("i64", md.fields[0].name);
        try testing.expectEqualStrings("m/s", md.fields[0].metadata[0].value);
        try testing.expectEqual(@as(usize, 0), md.fields[1].metadata.len);
        try testing.expectEqualStrings("odd_values", md.fields[21].children[0].metadata[0].key);
        try testing.expectEqual(@as(usize, 0), md.fields[21].metadata.len);
        try testing.expectEqualStrings("point", md.fields[23].metadata[0].value);
        try testing.expectEqual(@as(usize, 0), md.fields[23].children[0].metadata.len);
        try testing.expectEqualStrings("b", md.fields[23].children[1].metadata[0].key);
        if (file) {
            try testing.expectEqual(@as(usize, 1), md.footer.len);
            try testing.expectEqualStrings("zig-libs", md.footer[0].value);
        } else try testing.expectEqual(@as(usize, 0), md.footer.len);
    }
    // Without the options nothing is written; without `metadata` nothing is read.
    const plain = try stream.writeFile(gpa, f, .{});
    defer gpa.free(plain);
    var none: stream.Metadata = .{ .schema = kv("stale", "x") };
    _ = try stream.readFile(a, plain, .{ .metadata = &none });
    try testing.expectEqual(@as(usize, 0), none.schema.len + none.footer.len);
    for (none.fields) |x| try testing.expectEqual(@as(usize, 0), x.metadata.len);

    // More entries than columns: Unsupported.
    const extra = try a.alloc(stream.FieldMetadata, f.columns.len + 1);
    @memset(extra, .{});
    try testing.expectError(error.Unsupported, stream.writeStream(gpa, f, .{ .field_metadata = extra }));
    // More children than a field has (a run-end encoded field's two, written back plain):
    // the children's metadata is dropped, all of it, the field's own kept.
    var kids: [24]stream.FieldMetadata = @splat(.{});
    kids[0] = .{ .metadata = kv("own", "kept"), .children = &.{.{ .metadata = kv("run_ends", "") }} }; // an int column has no children
    kids[21] = .{ .metadata = kv("l", "kept"), .children = &.{ .{ .metadata = kv("run_ends", "") }, .{ .metadata = kv("values", "") } } }; // l has one
    const dropped = try stream.writeStream(gpa, f, .{ .field_metadata = &kids });
    defer gpa.free(dropped);
    var dmd: stream.Metadata = .{};
    try expectSameFrame(f, try stream.readStream(a, dropped, .{ .metadata = &dmd }));
    try testing.expectEqualStrings("kept", dmd.fields[0].metadata[0].value);
    try testing.expectEqual(@as(usize, 0), dmd.fields[0].children.len);
    try testing.expectEqualStrings("kept", dmd.fields[21].metadata[0].value);
    try testing.expectEqual(@as(usize, 1), dmd.fields[21].children.len);
    try testing.expectEqual(@as(usize, 0), dmd.fields[21].children[0].metadata.len);
}

test "projection: columns by name and index, in the order asked; unknown, ambiguous and repeated selections" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const f = try sampleFrame(a);
    const st_ix = for (f.columns, 0..) |c, i| {
        if (std.mem.eql(u8, c.name, "st")) break i;
    } else unreachable;
    const cat_ix = for (f.columns, 0..) |c, i| {
        if (std.mem.eql(u8, c.name, "cat")) break i;
    } else unreachable;
    const refs = [_]stream.ColumnRef{ .{ .name = "st" }, .{ .index = 0 }, .{ .name = "cat" }, .{ .name = "lcat" } };
    const lcat_ix = f.columns.len - 2;
    const want_ix = [_]usize{ st_ix, 0, cat_ix, lcat_ix };
    var cols: [4]Column = undefined;
    var data: [4]ColumnData = undefined;
    for (want_ix, 0..) |i, k| {
        cols[k] = f.columns[i];
        data[k] = f.columnAt(i);
    }
    const want: df.Frame = .{ .columns = &cols, .data = &data, .len = f.len };
    const fm = [_]stream.FieldMetadata{.{ .metadata = &.{.{ .key = "first", .value = "1" }} }};
    for ([_]stream.Compression{ .none, .zstd }) |c| {
        const wo: stream.WriteOptions = .{ .compression = c, .rows_per_batch = 2, .field_metadata = &fm };
        const sb = try stream.writeStream(gpa, f, wo);
        defer gpa.free(sb);
        const fb_ = try stream.writeFile(gpa, f, wo);
        defer gpa.free(fb_);
        var md: stream.Metadata = .{};
        try expectSameFrame(want, try stream.readStream(a, sb, .{ .columns = &refs, .metadata = &md }));
        // Metadata follows the frame's columns: column 0 ("i64") is now the second.
        try testing.expectEqual(@as(usize, 4), md.fields.len);
        try testing.expectEqualStrings("st", md.fields[0].name);
        try testing.expectEqualStrings("first", md.fields[1].metadata[0].key);
        try expectSameFrame(want, try stream.readFile(a, fb_, .{ .columns = &refs }));
        var file = try stream.openFile(a, fb_, .{ .columns = &refs });
        const b1 = try file.readBatch(1);
        try testing.expectEqual(@as(usize, 4), b1.columns.len);
        try expectRows(want, 2, b1);
        // No column at all: the rows, nothing else.
        const none = try stream.readStream(a, sb, .{ .columns = &.{} });
        try testing.expectEqual(f.len, none.len);
        try testing.expectEqual(@as(usize, 0), none.columns.len);
        for ([_][]const stream.ColumnRef{
            &.{.{ .name = "nope" }},
            &.{.{ .index = f.columns.len }},
            &.{ .{ .name = "st" }, .{ .index = st_ix } },
        }) |bad| {
            try testing.expectError(error.UnknownColumn, stream.readStream(a, sb, .{ .columns = bad }));
            try testing.expectError(error.UnknownColumn, stream.readFile(a, fb_, .{ .columns = bad }));
        }
    }
    // A name two fields share picks neither.
    const dup = [_]schema.Field{ .{ .name = "x", .type = .{ .int = .{ .bits = 8, .signed = true } } }, .{ .name = "x", .type = .{ .int = .{ .bits = 8, .signed = true } } } };
    const one: ipc.FieldNode = .{ .length = 1, .null_count = 0 };
    const db = try hand(gpa, &dup, &.{.{ .length = 1, .nodes = &.{ one, one }, .bufs = &.{ "", "\x01", "", "\x02" } }});
    defer gpa.free(db);
    try testing.expectError(error.UnknownColumn, stream.readStream(a, db, .{ .columns = &.{.{ .name = "x" }} }));
    try testing.expectEqual(@as(i64, 2), (try stream.readStream(a, db, .{ .columns = &.{.{ .index = 1 }} })).columnAt(0).get(0).int);
}

test "projection: unprojected columns and dictionaries are neither decompressed nor decoded nor charged" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // "bad" holds bytes that are not UTF-8, "cat"'s dictionary too; "x" is fine.
    const fields = [_]schema.Field{
        .{ .name = "bad", .type = .utf8 },
        .{ .name = "x", .type = .{ .int = .{ .bits = 32, .signed = true } } },
        .{ .name = "cat", .type = .utf8, .dictionary = .{ .id = 0 } },
    };
    const two: ipc.FieldNode = .{ .length = 2, .null_count = 0 };
    const bytes = try hand(gpa, &fields, &.{
        .{ .length = 1, .dict_id = 0, .nodes = &.{.{ .length = 1, .null_count = 0 }}, .bufs = &.{ "", bytesOf(i32, &.{ 0, 1 }), "\xff" } },
        .{ .length = 2, .nodes = &.{ two, two, two }, .bufs = &.{ "", bytesOf(i32, &.{ 0, 1, 2 }), "\xc3\x28", "", bytesOf(i32, &.{ 7, 8 }), "", bytesOf(i32, &.{ 0, 0 }) } },
    });
    defer gpa.free(bytes);
    try testing.expectError(error.InvalidUtf8, stream.readStream(a, bytes, .{}));
    try testing.expectError(error.InvalidUtf8, stream.readStream(a, bytes, .{ .columns = &.{.{ .name = "cat" }} }));
    const f = try stream.readStream(a, bytes, .{ .columns = &.{.{ .name = "x" }} });
    try testing.expectEqual(@as(i64, 8), f.columnAt(0).get(1).int);
    // Only the projected column's slots count: 2 rows of 1 column (+ none of the dictionary's).
    _ = try stream.readStream(a, bytes, .{ .columns = &.{.{ .name = "x" }}, .max_cells = 2 });
    try testing.expectError(error.LimitExceeded, stream.readStream(a, bytes, .{ .max_cells = 6 }));

    // Compressed: the unprojected columns' buffers do not count against max_body_bytes.
    const sf = try sampleFrame(a);
    const z = try stream.writeStream(gpa, sf, .{ .compression = .zstd });
    defer gpa.free(z);
    try testing.expectError(error.LimitExceeded, stream.readStream(a, z, .{ .max_body_bytes = 64 }));
    const p = try stream.readStream(a, z, .{ .max_body_bytes = 64, .columns = &.{.{ .name = "i64" }} });
    try testing.expectEqual(@as(i64, -2), p.columnAt(0).get(1).int);
}

test "decimal widths: Decimal32 / Decimal64 widen exactly, Decimal256 when it fits; precision per width" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const dec = struct {
        fn f(p: i32, sc: i32, bits: i32) schema.Type {
            return .{ .decimal = .{ .precision = p, .scale = sc, .bits = bits } };
        }
    }.f;
    const fields = [_]schema.Field{
        .{ .name = "d32", .type = dec(9, 2, 32) },
        .{ .name = "d64", .type = dec(18, 0, 64) },
        .{ .name = "d256", .type = dec(40, 12, 256) },
    };
    const two: ipc.FieldNode = .{ .length = 2, .null_count = 0 };
    const big: i256 = 99_999_999_999_999_999_999_999_999_999_999_999_999; // 38 digits
    const bytes = try hand(gpa, &fields, &.{.{ .length = 2, .nodes = &.{ two, two, two }, .bufs = &.{
        "", bytesOf(i32, &.{ -123_456_789, 5 }),
        "", bytesOf(i64, &.{ 999_999_999_999_999_999, -1 }),
        "", bytesOf(i256, &.{ big, -7 }),
    } }});
    defer gpa.free(bytes);
    const f = try stream.readStream(a, bytes, .{});
    try testing.expectEqual(df.ColumnType.decimal, f.columns[0].type);
    try testing.expectEqual(@as(i128, -123_456_789 * 10_000_000_000), f.cell(0, "d32").?.decimal);
    try testing.expectEqual(@as(i128, 5 * 10_000_000_000), f.cell(1, "d32").?.decimal);
    try testing.expectEqual(@as(i128, 999_999_999_999_999_999 * scale), f.cell(0, "d64").?.decimal);
    try testing.expectEqual(@as(i128, -scale), f.cell(1, "d64").?.decimal);
    try testing.expectEqual(@as(i128, @intCast(big)), f.cell(0, "d256").?.decimal);
    try testing.expectEqual(@as(i128, -7), f.cell(1, "d256").?.decimal);
    // Written back as Decimal128.
    const back = try stream.writeStream(gpa, f, .{});
    defer gpa.free(back);
    try expectSameFrame(f, try stream.readStream(a, back, .{}));

    // A Decimal256 of 39 digits, one outside i128, one past its declared precision:
    // Unsupported, null under lossy.
    const one: ipc.FieldNode = .{ .length = 1, .null_count = 0 };
    for ([_]struct { schema.Type, i256 }{
        .{ dec(40, 12, 256), big * 10 + 9 },
        .{ dec(76, 0, 256), @as(i256, 1) << 200 },
        .{ dec(76, 0, 256), -(@as(i256, 1) << 200) },
        .{ dec(3, 0, 256), 1000 },
        .{ dec(3, 0, 32), -1000 },
    }) |c| {
        var raw: [32]u8 = undefined;
        const w: usize = @intCast(@divExact(c[0].decimal.bits, 8));
        std.mem.writeInt(i256, &raw, c[1], .little);
        const bad = try hand(gpa, &.{.{ .name = "d", .type = c[0] }}, &.{.{ .length = 1, .nodes = &.{one}, .bufs = &.{ "", raw[0..w] } }});
        defer gpa.free(bad);
        try testing.expectError(error.Unsupported, stream.readStream(a, bad, .{}));
        try testing.expect((try stream.readStream(a, bad, .{ .lossy = true })).cell(0, "d").? == .null);
    }
    // Precisions a width cannot hold are not types.
    for ([_]schema.Type{ dec(10, 0, 32), dec(19, 0, 64), dec(39, 0, 128), dec(77, 0, 256), dec(0, 0, 256) }) |t| {
        const bad = try hand(gpa, &.{.{ .name = "d", .type = t }}, &.{});
        defer gpa.free(bad);
        try testing.expectError(error.Malformed, stream.readStream(a, bad, .{}));
    }
}

test "run-end encoded: read expanded into a plain column, over batches; a sliced array's runs past the length are cut; bad run ends are Malformed" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const i16_ends = schema.Field{ .name = "run_ends", .nullable = false, .type = .{ .int = .{ .bits = 16, .signed = true } } };
    const i32_ends = schema.Field{ .name = "run_ends", .nullable = false, .type = .{ .int = .{ .bits = 32, .signed = true } } };
    const r16_kids = [_]schema.Field{ i16_ends, .{ .name = "values", .type = .{ .int = .{ .bits = 32, .signed = true } } } };
    const rs_kids = [_]schema.Field{ i32_ends, .{ .name = "values", .type = .utf8 } };
    const fields = [_]schema.Field{
        .{ .name = "r16", .type = .run_end_encoded, .children = &r16_kids },
        .{ .name = "rs", .type = .run_end_encoded, .children = &rs_kids },
    };
    const nd = struct {
        fn f(len: i64, nulls: i64) ipc.FieldNode {
            return .{ .length = len, .null_count = nulls };
        }
    }.f;
    const bytes = try hand(gpa, &fields, &.{
        .{ .length = 5, .nodes = &.{ nd(5, 0), nd(2, 0), nd(2, 1), nd(5, 0), nd(2, 0), nd(2, 0) }, .bufs = &.{
            "",    bytesOf(i16, &.{ 2, 5 }), "\x01", bytesOf(i32, &.{ 7, 0 }),
            "",    bytesOf(i32, &.{ 1, 5 }), "",     bytesOf(i32, &.{ 0, 1, 3 }),
            "abc",
        } },
        .{ .length = 3, .nodes = &.{ nd(3, 0), nd(1, 0), nd(1, 0), nd(3, 0), nd(3, 0), nd(3, 1) }, .bufs = &.{
            "",   bytesOf(i16, &.{3}),         "",     bytesOf(i32, &.{9}),
            "",   bytesOf(i32, &.{ 1, 2, 3 }), "\x05", bytesOf(i32, &.{ 0, 1, 1, 2 }),
            "xz",
        } },
    });
    defer gpa.free(bytes);
    const f = try stream.readStream(a, bytes, .{});
    try testing.expectEqual(@as(usize, 8), f.len);
    try testing.expectEqual(df.ColumnType.int32, f.columns[0].type);
    try testing.expectEqual(df.ColumnType.text, f.columns[1].type);
    const want16 = [_]?i64{ 7, 7, null, null, null, 9, 9, 9 };
    const wants = [_]?[]const u8{ "a", "bc", "bc", "bc", "bc", "x", null, "z" };
    for (0..8) |i| {
        const x = f.columnAt(0).get(i);
        if (want16[i]) |w| try testing.expectEqual(w, x.int) else try testing.expect(x == .null);
        const y = f.columnAt(1).get(i);
        if (wants[i]) |w| try testing.expectEqualStrings(w, y.text) else try testing.expect(y == .null);
    }
    // Written back plain.
    const back = try stream.writeStream(gpa, f, .{});
    defer gpa.free(back);
    try expectSameFrame(f, try stream.readStream(a, back, .{}));
    // The expansion is charged: 8 rows of each column, its runs and values, then 8 copies each.
    try testing.expectError(error.LimitExceeded, stream.readStream(a, bytes, .{ .max_cells = 40 }));

    // One column, three rows, two runs: run ends that are not a run-end array.
    const one = [_]schema.Field{fields[0]};
    const Case = struct { ends: []const u8, ree_nulls: i64 = 0, ends_nulls: i64 = 0, ends_valid: []const u8 = "", vals_len: i64 = 2 };
    for ([_]Case{
        .{ .ends = bytesOf(i16, &.{ 2, 2 }) }, // not strictly increasing
        .{ .ends = bytesOf(i16, &.{ 3, 1 }) },
        .{ .ends = bytesOf(i16, &.{ 0, 3 }) }, // not positive
        .{ .ends = bytesOf(i16, &.{ -1, 3 }) },
        .{ .ends = bytesOf(i16, &.{ 1, 2 }) }, // short of the length
        .{ .ends = bytesOf(i16, &.{ 1, 3 }), .ree_nulls = 1 }, // nulls on the parent
        .{ .ends = bytesOf(i16, &.{ 1, 3 }), .ends_nulls = 1, .ends_valid = "\x02" }, // a null run end
        .{ .ends = bytesOf(i16, &.{ 1, 3 }), .vals_len = 1 }, // fewer values than runs
        .{ .ends = bytesOf(i16, &.{1}) }, // a short buffer
    }) |c| {
        const bad = try hand(gpa, &one, &.{.{ .length = 3, .nodes = &.{ nd(3, c.ree_nulls), nd(2, c.ends_nulls), nd(c.vals_len, 0) }, .bufs = &.{ c.ends_valid, c.ends, "", bytesOf(i32, &.{ 1, 2 }) } }});
        defer gpa.free(bad);
        try testing.expectError(error.Malformed, stream.readStream(a, bad, .{}));
    }
    // A sliced array: the last run may end past the length (one run, or several, beyond
    // it); only the batch's rows are expanded, batch by batch.
    {
        const sliced = try hand(gpa, &one, &.{
            .{ .length = 3, .nodes = &.{ nd(3, 0), nd(3, 0), nd(3, 0) }, .bufs = &.{ "", bytesOf(i16, &.{ 1, 4, 9 }), "", bytesOf(i32, &.{ 1, 2, 3 }) } },
            .{ .length = 2, .nodes = &.{ nd(2, 0), nd(2, 0), nd(2, 0) }, .bufs = &.{ "", bytesOf(i16, &.{ 1, 5 }), "", bytesOf(i32, &.{ 4, 5 }) } },
            .{ .length = 1, .nodes = &.{ nd(1, 0), nd(1, 0), nd(1, 0) }, .bufs = &.{ "", bytesOf(i16, &.{1}), "", bytesOf(i32, &.{6}) } },
        });
        defer gpa.free(sliced);
        const g = try stream.readStream(a, sliced, .{});
        try testing.expectEqual(@as(usize, 6), g.len);
        for ([_]i64{ 1, 2, 2, 4, 5, 6 }, 0..) |w, i| try testing.expectEqual(w, g.columnAt(0).get(i).int);
    }
    // Run ends of a type other than signed Int16/32/64, or not two children.
    for ([_][]const schema.Field{
        &.{ .{ .name = "run_ends", .type = .{ .int = .{ .bits = 16, .signed = false } } }, r16_kids[1] },
        &.{ .{ .name = "run_ends", .type = .{ .int = .{ .bits = 8, .signed = true } } }, r16_kids[1] },
        &.{ .{ .name = "run_ends", .type = .{ .float = .double } }, r16_kids[1] },
        &.{ .{ .name = "run_ends", .type = .utf8, .dictionary = .{ .id = 0 } }, r16_kids[1] },
        &.{ .{ .name = "run_ends", .type = i32_ends.type, .dictionary = .{ .id = 0 } }, r16_kids[1] },
        r16_kids[0..1],
    }) |kids| {
        const bad = try hand(gpa, &.{.{ .name = "r", .type = .run_end_encoded, .children = kids }}, &.{});
        defer gpa.free(bad);
        try testing.expectError(error.Malformed, stream.readStream(a, bad, .{}));
    }
}

test "run-end encoded metadata: reported in the column's shape (the values' children), so a write-back keeps it in place" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const kv = struct {
        fn f(comptime k: []const u8) []const schema.KeyValue {
            return &.{.{ .key = k, .value = k ++ "!" }};
        }
    }.f;
    const ends = schema.Field{ .name = "run_ends", .nullable = false, .type = .{ .int = .{ .bits = 16, .signed = true } }, .metadata = kv("ends") };
    // r: run-end encoded struct{a: int32, b: utf8}, metadata on every field.
    const ab = [_]schema.Field{
        .{ .name = "a", .type = .{ .int = .{ .bits = 32, .signed = true } }, .metadata = kv("a") },
        .{ .name = "b", .type = .utf8, .metadata = kv("b") },
    };
    const r_kids = [_]schema.Field{ ends, .{ .name = "values", .type = .@"struct", .children = &ab, .metadata = kv("values") } };
    // rr: run-end encoded run-end encoded struct{c: int32} (folded through both levels).
    const c = [_]schema.Field{.{ .name = "c", .type = .{ .int = .{ .bits = 32, .signed = true } }, .metadata = kv("c") }};
    const inner_kids = [_]schema.Field{ ends, .{ .name = "values", .type = .@"struct", .children = &c, .metadata = kv("inner values") } };
    const rr_kids = [_]schema.Field{ ends, .{ .name = "values", .type = .run_end_encoded, .children = &inner_kids, .metadata = kv("outer values") } };
    const fields = [_]schema.Field{
        .{ .name = "r", .type = .run_end_encoded, .children = &r_kids, .metadata = kv("r") },
        .{ .name = "rr", .type = .run_end_encoded, .children = &rr_kids, .metadata = kv("rr") },
    };
    const nd = struct {
        fn f(len: i64) ipc.FieldNode {
            return .{ .length = len, .null_count = 0 };
        }
    }.f;
    const bytes = try hand(gpa, &fields, &.{.{ .length = 3, .nodes = &.{ nd(3), nd(2), nd(2), nd(2), nd(2), nd(3), nd(1), nd(1), nd(1), nd(1), nd(1) }, .bufs = &.{
        "", bytesOf(i16, &.{ 1, 3 }), "", "",                  bytesOf(i32, &.{ 10, 20 }), "", bytesOf(i32, &.{ 0, 1, 3 }), "pqq",
        "", bytesOf(i16, &.{3}),      "", bytesOf(i16, &.{1}), "",                         "", bytesOf(i32, &.{5}),
    } }});
    defer gpa.free(bytes);
    var md: stream.Metadata = .{};
    const f = try stream.readStream(a, bytes, .{ .metadata = &md });
    try testing.expectEqual(df.ColumnType.@"struct", f.columns[0].type);
    try testing.expectEqual(df.ColumnType.@"struct", f.columns[1].type);
    try testing.expectEqualStrings("qq", f.columnAt(0).get(2).record.get(1).text);
    try testing.expectEqual(@as(i64, 5), f.columnAt(1).get(2).record.get(0).int);
    // The metadata has the frame's shape: the field's own, then the values' children; the
    // `run_ends` / `values` fields' own metadata is dropped (as Arrow C++ reads it).
    const check = struct {
        fn run(m: stream.Metadata) !void {
            try testing.expectEqual(@as(usize, 2), m.fields.len);
            try testing.expectEqualStrings("r!", m.fields[0].metadata[0].value);
            try testing.expectEqual(@as(usize, 2), m.fields[0].children.len);
            try testing.expectEqualStrings("a!", m.fields[0].children[0].metadata[0].value);
            try testing.expectEqualStrings("b!", m.fields[0].children[1].metadata[0].value);
            try testing.expectEqualStrings("rr!", m.fields[1].metadata[0].value);
            try testing.expectEqual(@as(usize, 1), m.fields[1].children.len);
            try testing.expectEqualStrings("c!", m.fields[1].children[0].metadata[0].value);
            try testing.expectEqual(@as(usize, 1), m.fields[1].children[0].metadata.len);
        }
    }.run;
    try check(md);
    try testing.expectEqualStrings("a", md.fields[0].children[0].name);
    // Written back plain with what was read: every pair lands on the same field again.
    const back = try stream.writeStream(gpa, f, .{ .field_metadata = md.fields });
    defer gpa.free(back);
    var bmd: stream.Metadata = .{};
    try expectSameFrame(f, try stream.readStream(a, back, .{ .metadata = &bmd }));
    try check(bmd);
}

test "map: read as list<struct<key, value>> under the file's names; null entries or keys and bad map schemas are Malformed" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const kv_fields = [_]schema.Field{
        .{ .name = "k", .nullable = false, .type = .utf8 },
        .{ .name = "v", .type = .{ .int = .{ .bits = 32, .signed = true } } },
    };
    const entries = schema.Field{ .name = "pairs", .nullable = false, .type = .@"struct", .children = &kv_fields };
    const ent = [1]schema.Field{entries};
    const mapField = struct {
        fn f(e: *const [1]schema.Field, sorted: bool) [1]schema.Field {
            return .{.{ .name = "m", .type = .{ .map = sorted }, .children = e }};
        }
    }.f;
    const nd = struct {
        fn f(len: i64, nulls: i64) ipc.FieldNode {
            return .{ .length = len, .null_count = nulls };
        }
    }.f;
    // Rows: {x: 1, y: null}, null, {z: 3}.
    const Case = struct { e_nulls: i64 = 0, e_valid: []const u8 = "", k_nulls: i64 = 0, k_valid: []const u8 = "", end: i32 = 3 };
    const make = struct {
        fn f(g: Allocator, fs: []const schema.Field, cs: Case) ![]u8 {
            const offs = [_]i32{ 0, 2, 2, cs.end };
            return hand(g, fs, &.{.{ .length = 3, .nodes = &.{ nd(3, 1), nd(3, cs.e_nulls), nd(3, cs.k_nulls), nd(3, 1) }, .bufs = &.{
                "\x05", std.mem.sliceAsBytes(&offs), cs.e_valid, cs.k_valid, bytesOf(i32, &.{ 0, 1, 2, 3 }), "xyz",
                "\x05", bytesOf(i32, &.{ 1, 0, 3 }),
            } }});
        }
    }.f;
    for ([_]bool{ false, true }) |sorted| {
        const fs = mapField(&ent, sorted);
        const bytes = try make(gpa, &fs, .{});
        defer gpa.free(bytes);
        const f = try stream.readStream(a, bytes, .{});
        const col = f.columns[0];
        try testing.expectEqual(df.ColumnType.list, col.type);
        try testing.expectEqualStrings("pairs", col.inner[0].name);
        try testing.expectEqual(df.ColumnType.@"struct", col.inner[0].type);
        try testing.expectEqualStrings("k", col.inner[0].inner[0].name);
        try testing.expectEqualStrings("v", col.inner[0].inner[1].name);
        const r0 = f.columnAt(0).get(0).list;
        try testing.expectEqual(@as(usize, 2), r0.len());
        try testing.expectEqualStrings("y", r0.get(1).record.get(0).text);
        try testing.expect(r0.get(1).record.get(1) == .null);
        try testing.expect(f.columnAt(0).get(1) == .null);
        try testing.expectEqual(@as(i64, 3), f.columnAt(0).get(2).list.get(0).record.get(1).int);
        // Written back as a List of Struct (the map tag is not kept), read back equal.
        const back = try stream.writeStream(gpa, f, .{});
        defer gpa.free(back);
        try expectSameFrame(f, try stream.readStream(a, back, .{}));
        // Map slots are charged like a list's: the column, its entries, keys and values.
        try testing.expectError(error.LimitExceeded, stream.readStream(a, bytes, .{ .max_cells = 11 }));
        _ = try stream.readStream(a, bytes, .{ .max_cells = 12 });
    }
    const fs = mapField(&ent, false);
    for ([_]Case{
        .{ .e_nulls = 1, .e_valid = "\x06" }, // a null entry
        .{ .k_nulls = 1, .k_valid = "\x06" }, // a null key
        .{ .end = 4 }, // offsets past the entries
    }) |cs| {
        const bad = try make(gpa, &fs, cs);
        defer gpa.free(bad);
        try testing.expectError(error.Malformed, stream.readStream(a, bad, .{}));
    }
    // Schemas Arrow C++ and arrow-rs refuse: nullable entries or keys, entries that are not
    // a struct of two fields, not one child, a dictionary-encoded entries field.
    var nullable_entries = entries;
    nullable_entries.nullable = true;
    const nullable_key = [_]schema.Field{ .{ .name = "k", .type = .utf8 }, kv_fields[1] };
    var key_nullable = entries;
    key_nullable.children = &nullable_key;
    var one_field = entries;
    one_field.children = kv_fields[0..1];
    var not_struct = entries;
    not_struct.type = .utf8;
    not_struct.children = &.{};
    var dict_entries = entries;
    dict_entries.dictionary = .{ .id = 0 };
    var int_pair = entries; // two children, but not a struct
    int_pair.type = .{ .int = .{ .bits = 32, .signed = true } };
    const three = [_]schema.Field{ kv_fields[0], kv_fields[1], kv_fields[1] };
    var three_fields = entries;
    three_fields.children = &three;
    for ([_]schema.Field{ nullable_entries, key_nullable, one_field, not_struct, dict_entries, int_pair, three_fields }) |e| {
        const ea = [1]schema.Field{e};
        const bad = try hand(gpa, &mapField(&ea, false), &.{});
        defer gpa.free(bad);
        try testing.expectError(error.Malformed, stream.readStream(a, bad, .{}));
    }
    const two = [_]schema.Field{.{ .name = "m", .type = .{ .map = false }, .children = &.{ entries, entries } }};
    const bad = try hand(gpa, &two, &.{});
    defer gpa.free(bad);
    try testing.expectError(error.Malformed, stream.readStream(a, bad, .{}));
}

/// A 16-byte BinaryView / Utf8View: inline when `data` holds 12 bytes or fewer, else
/// `len` bytes at `offset` of data buffer `index` (`data` is then the referenced bytes).
pub fn view(data: []const u8, index: i32, offset: i32) [16]u8 {
    var v: [16]u8 = @splat(0);
    std.mem.writeInt(i32, v[0..4], @intCast(data.len), .little);
    if (data.len <= 12) {
        @memcpy(v[4..][0..data.len], data);
    } else {
        @memcpy(v[4..8], data[0..4]);
        std.mem.writeInt(i32, v[8..12], index, .little);
        std.mem.writeInt(i32, v[12..16], offset, .little);
    }
    return v;
}

test "view types: Utf8View / BinaryView inline and in variadic buffers, ListView / LargeListView any order" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const item = [_]schema.Field{.{ .name = "item", .type = .{ .int = .{ .bits = 32, .signed = true } } }};
    const fields = [_]schema.Field{
        .{ .name = "sv", .type = .utf8_view },
        .{ .name = "x", .type = .{ .int = .{ .bits = 8, .signed = true } } },
        .{ .name = "bv", .type = .binary_view },
        .{ .name = "lv", .type = .list_view, .children = &item },
        .{ .name = "llv", .type = .large_list_view, .children = &item },
    };
    const long_a = "a string longer than twelve";
    const long_b = "\x00\x01binary past the inline twelve";
    // sv: short, long (buffer 1), null, long again sharing buffer 1's bytes (offset 2).
    const sv = view("short", 0, 0) ++ view(long_a, 1, 0) ++ view("", 0, 0) ++ view(long_a[2..], 1, 2);
    const bv = view("\xff\xfe", 0, 0) ++ view(long_b, 0, 3) ++ view(long_b, 0, 3) ++ view("", 0, 0);
    const nd = struct {
        fn f(len: i64, nulls: i64) ipc.FieldNode {
            return .{ .length = len, .null_count = nulls };
        }
    }.f;
    const bytes = try hand(gpa, &fields, &.{.{
        .length = 4,
        .variadic = &.{ 2, 1 },
        .nodes = &.{ nd(4, 1), nd(4, 0), nd(4, 0), nd(4, 1), nd(5, 0), nd(4, 0), nd(3, 0) },
        .bufs = &.{
            // sv: validity, views, its two data buffers (the first unused).
            "\x0b",                         &sv,                                    "unused",                        long_a,
            // x
            "",                             bytesOf(i8, &.{ 1, 2, 3, 4 }),
            // bv: validity, views, one data buffer (3 bytes before the value).
                     "",                              &bv,
            "pad" ++ long_b,
                // lv: validity (row 1 null), offsets, sizes; child of 5.
                           "\x0d",                                 bytesOf(i32, &.{ 3, 99, 0, 1 }), bytesOf(i32, &.{ 2, 99, 0, 3 }),
            "",                             bytesOf(i32, &.{ 10, 11, 12, 13, 14 }),
            // llv: offsets, sizes (64-bit); child of 3.
            "",                              bytesOf(i64, &.{ 2, 0, 0, 1 }),
            bytesOf(i64, &.{ 1, 3, 0, 2 }), "",                                     bytesOf(i32, &.{ 20, 21, 22 }),
        },
    }});
    defer gpa.free(bytes);
    const f = try stream.readStream(a, bytes, .{});
    try testing.expectEqual(df.ColumnType.text, f.columns[0].type);
    try testing.expectEqual(df.ColumnType.binary, f.columns[2].type);
    try testing.expectEqual(df.ColumnType.list, f.columns[3].type);
    try testing.expectEqualStrings("short", f.cell(0, "sv").?.text);
    try testing.expectEqualStrings(long_a, f.cell(1, "sv").?.text);
    try testing.expect(f.cell(2, "sv").? == .null);
    try testing.expectEqualStrings(long_a[2..], f.cell(3, "sv").?.text);
    try testing.expectEqualStrings("\xff\xfe", f.cell(0, "bv").?.text);
    try testing.expectEqualStrings(long_b, f.cell(2, "bv").?.text);
    try testing.expectEqualStrings("", f.cell(3, "bv").?.text);
    try testing.expectEqual(@as(i64, 3), f.cell(2, "x").?.int);
    const lv = [_][]const i64{ &.{ 13, 14 }, &.{}, &.{}, &.{ 11, 12, 13 } };
    const llv = [_][]const i64{ &.{22}, &.{ 20, 21, 22 }, &.{}, &.{ 21, 22 } };
    for (0..4) |r| {
        const got = f.cell(r, "lv").?;
        if (r == 1) try testing.expect(got == .null) else {
            try testing.expectEqual(lv[r].len, got.list.len());
            for (lv[r], 0..) |w, k| try testing.expectEqual(w, got.list.get(k).int);
        }
        const g2 = f.cell(r, "llv").?.list;
        try testing.expectEqual(llv[r].len, g2.len());
        for (llv[r], 0..) |w, k| try testing.expectEqual(w, g2.get(k).int);
    }
    // Written back as Utf8 / Binary / List; projection and zstd do not change what is read.
    const back = try stream.writeStream(gpa, f, .{ .compression = .zstd });
    defer gpa.free(back);
    try expectSameFrame(f, try stream.readStream(a, back, .{}));
    const p = try stream.readStream(a, bytes, .{ .columns = &.{ .{ .name = "bv" }, .{ .name = "x" } } });
    try testing.expectEqualStrings(long_b, p.cell(1, "bv").?.text);
    try testing.expectEqual(@as(i64, 4), p.cell(3, "x").?.int);
    // The bytes copied out of views are charged: sv alone is its 4 rows and 5 + 27 + 25 bytes.
    _ = try stream.readStream(a, bytes, .{ .columns = &.{.{ .name = "sv" }}, .max_cells = 4 + 57 });
    try testing.expectError(error.LimitExceeded, stream.readStream(a, bytes, .{ .columns = &.{.{ .name = "sv" }}, .max_cells = 4 + 56 }));
}

test "view types: views and list views outside their buffers are Malformed; bad counts; text not UTF-8" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const one: ipc.FieldNode = .{ .length = 1, .null_count = 0 };
    const sv = [_]schema.Field{.{ .name = "s", .type = .utf8_view }};
    const data = "0123456789abcdefghij";
    const ViewCase = struct { want: anyerror, v: [16]u8, counts: []const i64 = &.{1}, bufs: usize = 1 };
    var bad_prefix = view(data, 0, 0);
    bad_prefix[4] = 'X';
    var neg_len = view("", 0, 0);
    std.mem.writeInt(i32, neg_len[0..4], -1, .little);
    for ([_]ViewCase{
        .{ .want = error.Malformed, .v = view(data, 1, 0) }, // no buffer 1
        .{ .want = error.Malformed, .v = view(data, -1, 0) },
        .{ .want = error.Malformed, .v = view(data[1..], 0, 2) }, // runs past the end
        .{ .want = error.Malformed, .v = view(data, 0, -1) },
        .{ .want = error.Malformed, .v = bad_prefix },
        .{ .want = error.Malformed, .v = neg_len },
        .{ .want = error.Malformed, .v = view("x", 0, 0), .counts = &.{} }, // no count for the view field
        .{ .want = error.Malformed, .v = view("x", 0, 0), .counts = &.{ 1, 0 } }, // one too many
        .{ .want = error.Malformed, .v = view("x", 0, 0), .counts = &.{2} }, // more than the buffers
        .{ .want = error.Malformed, .v = view("x", 0, 0), .counts = &.{-1} },
        .{ .want = error.InvalidUtf8, .v = view("\xc3\x28", 0, 0) },
    }) |c| {
        var bufs: [3][]const u8 = .{ "", &c.v, data };
        const b = try hand(gpa, &sv, &.{.{ .length = 1, .variadic = c.counts, .nodes = &.{one}, .bufs = bufs[0 .. 2 + c.bufs] }});
        defer gpa.free(b);
        try testing.expectError(c.want, stream.readStream(a, b, .{}));
    }
    // The same view inline in a short array is fine; invalid UTF-8 passes unchecked when asked.
    {
        const v = view("\xc3\x28", 0, 0);
        const b = try hand(gpa, &sv, &.{.{ .length = 1, .variadic = &.{0}, .nodes = &.{one}, .bufs = &.{ "", &v } }});
        defer gpa.free(b);
        try testing.expectEqualStrings("\xc3\x28", (try stream.readStream(a, b, .{ .validate_utf8 = false })).cell(0, "s").?.text);
    }
    // List views: an offset or size outside the child, negative ones, short buffers.
    const item = [_]schema.Field{.{ .name = "item", .type = .{ .int = .{ .bits = 32, .signed = true } } }};
    const lv = [_]schema.Field{.{ .name = "l", .type = .list_view, .children = &item }};
    const child = bytesOf(i32, &.{ 1, 2, 3 });
    for ([_]struct { []const u8, []const u8 }{
        .{ bytesOf(i32, &.{3}), bytesOf(i32, &.{1}) },
        .{ bytesOf(i32, &.{1}), bytesOf(i32, &.{3}) },
        .{ bytesOf(i32, &.{4}), bytesOf(i32, &.{0}) },
        .{ bytesOf(i32, &.{-1}), bytesOf(i32, &.{1}) },
        .{ bytesOf(i32, &.{0}), bytesOf(i32, &.{-1}) },
        .{ bytesOf(i32, &.{0}), "" },
    }) |c| {
        const b = try hand(gpa, &lv, &.{.{ .length = 1, .nodes = &.{ one, .{ .length = 3, .null_count = 0 } }, .bufs = &.{ "", c[0], c[1], "", child } }});
        defer gpa.free(b);
        try testing.expectError(error.Malformed, stream.readStream(a, b, .{}));
    }
    // A list view with no child or two.
    for ([_][]const schema.Field{ &.{}, &.{ item[0], item[0] } }) |kids| {
        const b = try hand(gpa, &.{.{ .name = "l", .type = .large_list_view, .children = kids }}, &.{});
        defer gpa.free(b);
        try testing.expectError(error.Malformed, stream.readStream(a, b, .{}));
    }
}

test "view types: compressed batches (raw-prefixed buffers), projected past broken view buffers; short buffers; the exact max_cells of a list view" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const raw = struct {
        // A compressed body's buffer stored as is: length -1, then the bytes.
        fn f(g: Allocator, x: []const u8) ![]u8 {
            const out = try g.alloc(u8, 8 + x.len);
            std.mem.writeInt(i64, out[0..8], -1, .little);
            @memcpy(out[8..], x);
            return out;
        }
    }.f;
    const fields = [_]schema.Field{ .{ .name = "sv", .type = .utf8_view }, .{ .name = "x", .type = .{ .int = .{ .bits = 32, .signed = true } } } };
    const long = "a value longer than twelve bytes";
    var views: [32]u8 = undefined;
    views[0..16].* = view("hi", 0, 0);
    views[16..32].* = view(long, 0, 0);
    const node: ipc.FieldNode = .{ .length = 2, .null_count = 0 };
    const rv = try raw(a, &views);
    const rd = try raw(a, long);
    const rx = try raw(a, bytesOf(i32, &.{ 5, 6 }));
    const by_sv = [_]stream.ColumnRef{.{ .name = "sv" }};
    const by_x = [_]stream.ColumnRef{.{ .name = "x" }};
    for ([_]bool{ true, false }) |good| {
        // Broken: the view field's views and data buffers are too short to hold a length.
        const bytes = try hand(gpa, &fields, &.{.{ .length = 2, .codec = .zstd, .variadic = &.{1}, .nodes = &.{ node, node }, .bufs = &.{ "", if (good) rv else "bad", if (good) rd else "bad", "", rx } }});
        defer gpa.free(bytes);
        const p = try stream.readStream(a, bytes, .{ .columns = &by_x });
        try testing.expectEqual(@as(usize, 1), p.columns.len);
        try testing.expectEqual(@as(i64, 6), p.cell(1, "x").?.int);
        if (good) {
            for ([_]?[]const stream.ColumnRef{ null, &by_sv }) |cols| {
                const f = try stream.readStream(a, bytes, .{ .columns = cols });
                try testing.expectEqualStrings("hi", f.cell(0, "sv").?.text);
                try testing.expectEqualStrings(long, f.cell(1, "sv").?.text);
            }
        } else {
            try testing.expectError(error.Malformed, stream.readStream(a, bytes, .{}));
            try testing.expectError(error.Malformed, stream.readStream(a, bytes, .{ .columns = &by_sv }));
        }
    }
    // A views buffer short of one view per row, a list view's offsets short of one per row.
    {
        const sv = [_]schema.Field{fields[0]};
        const bad = try hand(gpa, &sv, &.{.{ .length = 2, .variadic = &.{1}, .nodes = &.{node}, .bufs = &.{ "", views[16..32], long } }});
        defer gpa.free(bad);
        try testing.expectError(error.Malformed, stream.readStream(a, bad, .{}));
    }
    const item = [_]schema.Field{.{ .name = "item", .type = fields[1].type }};
    const lv = [_]schema.Field{.{ .name = "l", .type = .list_view, .children = &item }};
    const child: ipc.FieldNode = .{ .length = 3, .null_count = 0 };
    {
        const bad = try hand(gpa, &lv, &.{.{ .length = 2, .nodes = &.{ node, child }, .bufs = &.{ "", bytesOf(i32, &.{0}), bytesOf(i32, &.{ 3, 2 }), "", bytesOf(i32, &.{ 1, 2, 3 }) } }});
        defer gpa.free(bad);
        try testing.expectError(error.Malformed, stream.readStream(a, bad, .{}));
    }
    // Two rows naming 3 + 2 of 3 child slots: 2 + 3 node slots, then 5 copied.
    const ok = try hand(gpa, &lv, &.{.{ .length = 2, .nodes = &.{ node, child }, .bufs = &.{ "", bytesOf(i32, &.{ 0, 1 }), bytesOf(i32, &.{ 3, 2 }), "", bytesOf(i32, &.{ 1, 2, 3 }) } }});
    defer gpa.free(ok);
    const f = try stream.readStream(a, ok, .{ .max_cells = 10 });
    try testing.expectEqual(@as(i64, 3), f.cell(1, "l").?.list.get(1).int);
    try testing.expectError(error.LimitExceeded, stream.readStream(a, ok, .{ .max_cells = 9 }));
}
