// SPDX-License-Identifier: MIT

//! The guards the mutation audit found no test for: each test below pins a
//! check or an assignment whose mutant every earlier test let through (boundaries of
//! the Large switch and of the date range, null slots, short buffers, negative offsets
//! and indices, shared dictionaries that differ, `max_rows` / `max_cells` sums, the
//! file's leading mark, footer length and block types, the wire form of a categorical
//! stored as text).

const std = @import("std");
const df = @import("dataframe");
const fb = @import("fb.zig");
const schema = @import("schema.zig");
const ipc = @import("ipc.zig");
const stream = @import("stream.zig");
const st = @import("stream_test.zig");

const testing = std.testing;
const Allocator = std.mem.Allocator;
const Column = df.Column;
const ColumnData = df.ColumnData;
const HandBatch = st.HandBatch;
const bytesOf = st.bytesOf;

fn readHand(gpa: Allocator, a: Allocator, fields: []const schema.Field, batches: []const HandBatch, opts: stream.ReadOptions) !df.Frame {
    const bytes = try st.hand(gpa, fields, batches);
    defer gpa.free(bytes);
    return stream.readStream(a, bytes, opts);
}

fn node(len: i64, nulls: i64) ipc.FieldNode {
    return .{ .length = len, .null_count = nulls };
}

const int32: schema.Type = .{ .int = .{ .bits = 32, .signed = true } };
const one_null = &[_]u8{0b01}; // row 0 valid, row 1 null

/// The schema the stream or file `bytes` starts with.
fn firstSchema(a: Allocator, bytes: []const u8) !schema.Schema {
    var pos: usize = if (std.mem.startsWith(u8, bytes, "ARROW1")) 8 else 0;
    const m = try ipc.readMessage(bytes, &pos);
    return schema.decodeSchema(a, m.msg.header.?);
}

test "writer: a text column of exactly large_from bytes is Large, one byte short of it is not" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const f: df.Frame = .{ .columns = &.{.{ .name = "s", .type = .text }}, .data = &.{.{ .text = try st.textCol(a, &.{"abcd"}) }}, .len = 1 };
    for ([_]struct { from: u64, want: std.meta.Tag(schema.Type) }{ .{ .from = 4, .want = .large_utf8 }, .{ .from = 5, .want = .utf8 } }) |c| {
        const bytes = try stream.writeStream(testing.allocator, f, .{ .large_from = c.from });
        defer testing.allocator.free(bytes);
        try testing.expectEqual(c.want, std.meta.activeTag((try firstSchema(a, bytes)).fields[0].type));
        try testing.expectEqualStrings("abcd", (try stream.readStream(a, bytes, .{})).cell(0, "s").?.text);
    }
}

test "writer: declarations the storage cannot meet are Unsupported, even when every cell is null" {
    const all_null: ColumnData = .{ .int = .{ .values = &.{0}, .valid = &.{0} } };
    const bad = [_]df.Frame{
        .{ .columns = &.{.{ .name = "l", .type = .list }}, .data = &.{all_null}, .len = 1 },
        .{ .columns = &.{.{ .name = "r", .type = .@"struct" }}, .data = &.{all_null}, .len = 1 },
        .{ .columns = &.{.{ .name = "a", .type = .array, .array_width = 1 << 31 }}, .data = &.{.nulls}, .len = 0 },
        .{ .columns = &.{.{ .name = "t", .type = .time }}, .data = &.{.{ .int = .{ .values = &.{86_400_000_000} } }}, .len = 1 },
        .{ .columns = &.{.{ .name = "x", .type = .int }}, .data = &.{.{ .boxed = &.{.{ .int = 1 }} }}, .len = 1 },
    };
    for (bad) |b| try testing.expectError(error.Unsupported, stream.writeStream(testing.allocator, b, .{}));
}

test "writer: a struct child takes its declaration by name, not by position" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const sc = try a.create(df.StructColumn);
    sc.* = .{ .names = &.{"a"}, .children = try a.dupe(ColumnData, &.{.{ .int = .{ .values = &.{ 1, 2 } } }}), .len = 2 };
    const inner = [_]Column{.{ .name = "z", .type = .float }};
    const f: df.Frame = .{ .columns = &.{.{ .name = "r", .type = .@"struct", .inner = &inner }}, .data = &.{.{ .@"struct" = sc }}, .len = 2 };
    const bytes = try stream.writeStream(testing.allocator, f, .{});
    defer testing.allocator.free(bytes);
    const got = try stream.readStream(a, bytes, .{});
    try testing.expectEqual(df.ColumnType.int, got.columns[0].inner[0].type);
}

test "writer: a categorical stored as text sends its distinct texts once, lexically ordered" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const f: df.Frame = .{ .columns = &.{.{ .name = "c", .type = .categorical }}, .data = &.{.{ .text = try st.textCol(a, &.{ "b", "a", "b" }) }}, .len = 3 };
    const bytes = try stream.writeStream(testing.allocator, f, .{});
    defer testing.allocator.free(bytes);
    var pos: usize = 0;
    _ = try ipc.readMessage(bytes, &pos);
    const m = try ipc.readMessage(bytes, &pos);
    try testing.expectEqual(schema.HeaderType.dictionary_batch, m.msg.header_type);
    const db = try ipc.decodeDictionaryBatch(a, m.msg.header.?, m.enc.body.len);
    try testing.expectEqual(@as(i64, 2), db.data.length);
    const loc = db.data.buffers[2];
    try testing.expectEqualStrings("ab", m.enc.body[@intCast(loc.offset)..][0..@intCast(loc.length)]);
}

test "writer: a Null array's null count is its length" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const items = try a.create(ColumnData);
    items.* = .nulls; // no declaration for the items: an Arrow Null child
    const f: df.Frame = .{ .columns = &.{.{ .name = "l", .type = .list }}, .data = &.{.{ .list = .{ .offsets = &.{ 0, 2 }, .items = items } }}, .len = 1 };
    const bytes = try stream.writeStream(testing.allocator, f, .{});
    defer testing.allocator.free(bytes);
    try testing.expectEqual(std.meta.Tag(schema.Type).null, std.meta.activeTag((try firstSchema(a, bytes)).fields[0].children[0].type));
    var pos: usize = 0;
    _ = try ipc.readMessage(bytes, &pos);
    const m = try ipc.readMessage(bytes, &pos);
    const rb = try ipc.decodeRecordBatch(a, m.msg.header.?, m.enc.body.len);
    try testing.expectEqual(node(2, 2), rb.nodes[1]);
}

test "reader: null slots read as zero, false and nothing; a null row's dictionary index is not looked at" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const fields = [_]schema.Field{
        .{ .name = "i", .type = int32 },
        .{ .name = "b", .type = .bool },
        .{ .name = "s", .type = .utf8 },
        .{ .name = "c", .type = .utf8, .dictionary = .{ .id = 0 } },
        .{ .name = "d", .type = .{ .int = .{ .bits = 64, .signed = true } }, .dictionary = .{ .id = 1 } },
        .{ .name = "e", .type = .utf8, .dictionary = .{ .id = 2 } },
    };
    const f = try readHand(gpa, a, &fields, &.{
        .{ .length = 2, .dict_id = 0, .nodes = &.{node(2, 0)}, .bufs = &.{ "", bytesOf(i32, &.{ 0, 1, 2 }), "xy" } },
        .{ .length = 2, .dict_id = 1, .nodes = &.{node(2, 0)}, .bufs = &.{ "", bytesOf(i64, &.{ 10, 20 }) } },
        // Dictionary 2 holds "p" and a null entry.
        .{ .length = 2, .dict_id = 2, .nodes = &.{node(2, 1)}, .bufs = &.{ one_null, bytesOf(i32, &.{ 0, 1, 1 }), "p" } },
        .{
            .length = 2,
            .nodes = &.{ node(2, 1), node(2, 1), node(2, 1), node(2, 1), node(2, 1), node(2, 0) },
            .bufs = &.{
                one_null, bytesOf(i32, &.{ 5, 7 }),
                one_null, &[_]u8{0b11},
                one_null, bytesOf(i32, &.{ 0, 1, 2 }), "a\xff", // the null row's slot is not UTF-8
                one_null, bytesOf(i32, &.{ 0, 99 }), // the null row's index is past the dictionary
                one_null, bytesOf(i32, &.{ 1, 0 }),
                "", bytesOf(i32, &.{ 1, 0 }), // row 0 names the null entry
            },
        },
    }, .{});
    try testing.expectEqual(@as(i32, 0), f.columnAt(0).int32.values[1]);
    try testing.expect(!f.columnAt(1).bool.values[1]);
    try testing.expectEqualStrings("a", f.cell(0, "s").?.text);
    try testing.expect(f.cell(1, "s").? == .null);
    try testing.expectEqualStrings("x", f.cell(0, "c").?.text);
    try testing.expect(f.cell(1, "c").? == .null);
    try testing.expectEqual(@as(i64, 20), f.cell(0, "d").?.int);
    try testing.expect(f.cell(1, "d").? == .null);
    const e = f.columnAt(5).categorical;
    try testing.expect(!e.codes.isValid(0));
    try testing.expectEqual(@as(u32, 0), e.codes.values[0]);
    try testing.expectEqualStrings("p", f.cell(1, "e").?.text);
}

test "reader: short buffers, negative offsets and indices, a struct child of another length are Malformed" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const Case = struct { fields: []const schema.Field, batches: []const HandBatch };
    const item = [_]schema.Field{.{ .name = "item", .type = int32 }};
    const kid = [_]schema.Field{.{ .name = "a", .type = int32 }};
    for ([_]Case{
        // Nine booleans in one byte.
        .{ .fields = &.{.{ .name = "b", .type = .bool }}, .batches = &.{.{ .length = 9, .nodes = &.{node(9, 0)}, .bufs = &.{ "", &[_]u8{0xff} } }} },
        // Two 4-byte values in six bytes.
        .{ .fields = &.{.{ .name = "f", .type = .{ .fixed_size_binary = 4 } }}, .batches = &.{.{ .length = 2, .nodes = &.{node(2, 0)}, .bufs = &.{ "", "abcdef" } }} },
        // Two strings, two offsets.
        .{ .fields = &.{.{ .name = "s", .type = .utf8 }}, .batches = &.{.{ .length = 2, .nodes = &.{node(2, 0)}, .bufs = &.{ "", bytesOf(i32, &.{ 0, 1 }), "ab" } }} },
        // A negative offset.
        .{ .fields = &.{.{ .name = "s", .type = .utf8 }}, .batches = &.{.{ .length = 1, .nodes = &.{node(1, 0)}, .bufs = &.{ "", bytesOf(i32, &.{ 0, -1 }), "ab" } }} },
        // A negative dictionary index.
        .{ .fields = &.{.{ .name = "c", .type = .utf8, .dictionary = .{ .id = 0 } }}, .batches = &.{
            .{ .length = 1, .dict_id = 0, .nodes = &.{node(1, 0)}, .bufs = &.{ "", bytesOf(i32, &.{ 0, 1 }), "x" } },
            .{ .length = 1, .nodes = &.{node(1, 0)}, .bufs = &.{ "", bytesOf(i32, &.{-1}) } },
        } },
        // A struct of two rows over a child of one.
        .{ .fields = &.{.{ .name = "r", .type = .@"struct", .children = &kid }}, .batches = &.{.{ .length = 2, .nodes = &.{ node(2, 0), node(1, 0) }, .bufs = &.{ "", "", bytesOf(i32, &.{1}) } }} },
        // A fixed-size list of two rows of 2 over a child of 3.
        .{ .fields = &.{.{ .name = "l", .type = .{ .fixed_size_list = 2 }, .children = &item }}, .batches = &.{.{ .length = 2, .nodes = &.{ node(2, 0), node(3, 0) }, .bufs = &.{ "", "", bytesOf(i32, &.{ 1, 2, 3 }) } }} },
        // A time whose unit and width disagree (microseconds in 32 bits).
        .{ .fields = &.{.{ .name = "t", .type = .{ .time = .{ .unit = .microsecond, .bits = 32 } } }}, .batches = &.{} },
    }, 0..) |c, i| {
        if (readHand(gpa, a, c.fields, c.batches, .{})) |_| {
            std.debug.print("case {d}: decoded\n", .{i});
            return error.TestUnexpectedResult;
        } else |e| if (e != error.Malformed) {
            std.debug.print("case {d}: {s}\n", .{ i, @errorName(e) });
            return error.TestUnexpectedError;
        }
    }
}

test "reader: list children are cut to what the rows use; offsets not from 0 are honoured" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const item = [_]schema.Field{.{ .name = "item", .type = int32 }};
    const fields = [_]schema.Field{
        .{ .name = "from1", .type = .list, .children = &item },
        .{ .name = "short", .type = .list, .children = &item },
        .{ .name = "fsl", .type = .{ .fixed_size_list = 2 }, .children = &item },
    };
    const f = try readHand(gpa, a, &fields, &.{.{
        .length = 1,
        .nodes = &.{ node(1, 0), node(3, 0), node(1, 0), node(3, 0), node(1, 0), node(3, 0) },
        .bufs = &.{
            "", bytesOf(i32, &.{ 1, 3 }), "",                          bytesOf(i32, &.{ 7, 8, 9 }),
            "", bytesOf(i32, &.{ 0, 2 }), "",                          bytesOf(i32, &.{ 7, 8, 9 }),
            "", "",                       bytesOf(i32, &.{ 7, 8, 9 }),
        },
    }}, .{});
    const l0 = f.cell(0, "from1").?.list;
    try testing.expectEqual(@as(usize, 2), l0.len());
    try testing.expectEqual(@as(i64, 8), l0.get(0).int);
    for (0..3) |ci| try testing.expectEqual(@as(?usize, 2), f.columnAt(ci).list.items.storedLen());
}

test "reader: a dictionary shared by fields whose value types differ in unit, width, child names or child dictionaries" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const a32 = [_]schema.Field{.{ .name = "a", .type = int32 }};
    const b32 = [_]schema.Field{.{ .name = "b", .type = int32 }};
    const a32d = [_]schema.Field{.{ .name = "a", .type = int32, .dictionary = .{ .id = 9 } }};
    const d0: schema.Dictionary = .{ .id = 0 };
    const Pair = [2]schema.Field;
    for ([_]Pair{
        .{ .{ .name = "p", .type = .{ .timestamp = .{ .unit = .second } }, .dictionary = d0 }, .{ .name = "q", .type = .{ .int = .{ .bits = 64, .signed = true } }, .dictionary = d0 } },
        .{ .{ .name = "p", .type = .{ .timestamp = .{ .unit = .second } }, .dictionary = d0 }, .{ .name = "q", .type = .{ .timestamp = .{ .unit = .millisecond } }, .dictionary = d0 } },
        .{ .{ .name = "p", .type = int32, .dictionary = d0 }, .{ .name = "q", .type = .{ .int = .{ .bits = 64, .signed = true } }, .dictionary = d0 } },
        .{ .{ .name = "p", .type = .@"struct", .children = &a32, .dictionary = d0 }, .{ .name = "q", .type = .@"struct", .children = &b32, .dictionary = d0 } },
        .{ .{ .name = "p", .type = .@"struct", .children = &a32, .dictionary = d0 }, .{ .name = "q", .type = .@"struct", .children = &a32d, .dictionary = d0 } },
    }) |pair| try testing.expectError(error.Malformed, readHand(gpa, a, &pair, &.{}, .{}));
}

test "reader: dates of the years 0000 and 9999 read, the years either side are not dates" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const fields = [_]schema.Field{.{ .name = "d", .type = .{ .date = .day } }};
    const f = try readHand(gpa, a, &fields, &.{.{ .length = 4, .nodes = &.{node(4, 0)}, .bufs = &.{ "", bytesOf(i32, &.{ -719_529, -719_528, 2_932_896, 2_932_897 }) } }}, .{ .lossy = true });
    try testing.expect(f.cell(0, "d").? == .null);
    try testing.expectEqualStrings("0000-01-01", f.cell(1, "d").?.text);
    try testing.expectEqualStrings("9999-12-31", f.cell(2, "d").?.text);
    try testing.expect(f.cell(3, "d").? == .null);
}

test "reader: a struct whose every row is null reads as a null column" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const kid = [_]schema.Field{.{ .name = "a", .type = int32 }};
    const fields = [_]schema.Field{.{ .name = "r", .type = .@"struct", .children = &kid }};
    const f = try readHand(gpa, a, &fields, &.{.{ .length = 2, .nodes = &.{ node(2, 2), node(2, 0) }, .bufs = &.{ &[_]u8{0}, "", bytesOf(i32, &.{ 1, 2 }) } }}, .{});
    try testing.expect(f.columnAt(0) == .nulls);
}

test "reader: index types are read with their sign (null dictionaries past 2^15 and 2^31 entries)" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    {
        const fields = [_]schema.Field{.{ .name = "n", .type = .null, .dictionary = .{ .id = 0, .index = .{ .bits = 16, .signed = false } } }};
        const f = try readHand(gpa, a, &fields, &.{
            .{ .length = 0x8001, .dict_id = 0, .nodes = &.{node(0x8001, 0x8001)}, .bufs = &.{} },
            .{ .length = 1, .nodes = &.{node(1, 0)}, .bufs = &.{ "", bytesOf(u16, &.{0x8000}) } },
        }, .{});
        try testing.expect(f.cell(0, "n").? == .null);
    }
    {
        const fields = [_]schema.Field{.{ .name = "n", .type = .null, .dictionary = .{ .id = 0, .index = .{ .bits = 32, .signed = false } } }};
        const f = try readHand(gpa, a, &fields, &.{
            .{ .length = 0x8000_0001, .dict_id = 0, .nodes = &.{node(0x8000_0001, 0x8000_0001)}, .bufs = &.{} },
            .{ .length = 1, .nodes = &.{node(1, 0)}, .bufs = &.{ "", bytesOf(u32, &.{0x8000_0000}) } },
        }, .{ .max_rows = 1 << 32, .max_cells = 1 << 34 });
        try testing.expect(f.cell(0, "n").? == .null);
    }
}

test "reader: a decimal scale past 38 digits of rescaling is Unsupported" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const fields = [_]schema.Field{.{ .name = "d", .type = .{ .decimal = .{ .precision = 1, .scale = 60 } } }};
    try testing.expectError(error.Unsupported, readHand(gpa, arena_state.allocator(), &fields, &.{.{ .length = 1, .nodes = &.{node(1, 0)}, .bufs = &.{ "", bytesOf(i128, &.{1}) } }}, .{}));
}

test "reader: compressed buffers declaring a negative length or more than their frame holds are Malformed" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const fields = [_]schema.Field{.{ .name = "x", .type = int32 }};
    // -2: neither a length nor the raw marker (in a batch of no rows, where 0 bytes would do).
    var neg: [12]u8 = undefined;
    std.mem.writeInt(i64, neg[0..8], -2, .little);
    @memcpy(neg[8..], "abcd");
    try testing.expectError(error.Malformed, readHand(gpa, a, &fields, &.{.{ .length = 0, .nodes = &.{node(0, 0)}, .bufs = &.{ "", &neg }, .codec = .zstd }}, .{}));
    // 4 declared; a zstd frame without a content size whose one raw block holds 3.
    const frame = [_]u8{ 0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00, 0x19, 0x00, 0x00, 'a', 'b', 'c' };
    var short: [8 + frame.len]u8 = undefined;
    std.mem.writeInt(i64, short[0..8], 4, .little);
    @memcpy(short[8..], &frame);
    try testing.expectError(error.Malformed, readHand(gpa, a, &fields, &.{.{ .length = 1, .nodes = &.{node(1, 0)}, .bufs = &.{ "", &short }, .codec = .zstd }}, .{}));
}

test "max_rows and max_cells: frames without columns, a file summed at open, list children summed over batches, dictionary copies" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    {
        // Six rows and no columns, in batches of three.
        const f: df.Frame = .{ .columns = &.{}, .data = &.{}, .len = 6 };
        const s = try stream.writeStream(gpa, f, .{ .rows_per_batch = 3 });
        defer gpa.free(s);
        try testing.expectError(error.LimitExceeded, stream.readStream(a, s, .{ .max_rows = 5 }));
        const file = try stream.writeFile(gpa, f, .{ .rows_per_batch = 3 });
        defer gpa.free(file);
        try testing.expectError(error.LimitExceeded, stream.openFile(a, file, .{ .max_rows = 5 }));
    }
    {
        // A list column: one row of six items in a file, two rows of three in a stream.
        const items = try a.create(ColumnData);
        items.* = .{ .int = .{ .values = &.{ 1, 2, 3, 4, 5, 6 } } };
        const inner = [_]Column{.{ .name = "item", .type = .int }};
        const one: df.Frame = .{ .columns = &.{.{ .name = "l", .type = .list, .inner = &inner }}, .data = &.{.{ .list = .{ .offsets = &.{ 0, 6 }, .items = items } }}, .len = 1 };
        const file = try stream.writeFile(gpa, one, .{});
        defer gpa.free(file);
        try testing.expectError(error.LimitExceeded, stream.openFile(a, file, .{ .max_rows = 5 }));
        const two: df.Frame = .{ .columns = one.columns, .data = &.{.{ .list = .{ .offsets = &.{ 0, 3, 6 }, .items = items } }}, .len = 2 };
        const s = try stream.writeStream(gpa, two, .{ .rows_per_batch = 1 });
        defer gpa.free(s);
        try testing.expectError(error.LimitExceeded, stream.readStream(a, s, .{ .max_rows = 5 }));
    }
    {
        // One int dictionary entry copied into 100 rows: 1 + 100 cells read, 100 more copied.
        const fields = [_]schema.Field{.{ .name = "d", .type = .{ .int = .{ .bits = 64, .signed = true } }, .dictionary = .{ .id = 0 } }};
        const zeros: [100]i32 = @splat(0);
        const batches = [_]HandBatch{
            .{ .length = 1, .dict_id = 0, .nodes = &.{node(1, 0)}, .bufs = &.{ "", bytesOf(i64, &.{42}) } },
            .{ .length = 100, .nodes = &.{node(100, 0)}, .bufs = &.{ "", std.mem.sliceAsBytes(&zeros) } },
        };
        _ = try readHand(gpa, a, &fields, &batches, .{ .max_cells = 201 });
        try testing.expectError(error.LimitExceeded, readHand(gpa, a, &fields, &batches, .{ .max_cells = 150 }));
    }
    {
        // 33 batches of one list row spanning a Null child of 2^27: more elements in total
        // than dataframe's u32 list offsets hold, though each batch is within max_rows.
        const nul = [_]schema.Field{.{ .name = "item", .type = .null }};
        const fields = [_]schema.Field{.{ .name = "l", .type = .list, .children = &nul }};
        const b: HandBatch = .{ .length = 1, .nodes = &.{ node(1, 0), node(1 << 27, 1 << 27) }, .bufs = &.{ "", bytesOf(i32, &.{ 0, 1 << 27 }) } };
        const batches: [33]HandBatch = @splat(b);
        try testing.expectError(error.Unsupported, readHand(gpa, a, &fields, &batches, .{ .max_cells = std.math.maxInt(u64) }));
    }
}

test "stream: the first message must be a schema and the only one" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        var b = fb.Builder.init(gpa);
        defer b.deinit();
        try ipc.writeMessage(gpa, &out, try ipc.encodeRecordBatchMessage(&b, .{ .length = 0, .nodes = &.{}, .buffers = &.{} }, 0), &.{});
        try ipc.writeEos(gpa, &out);
        try testing.expectError(error.Malformed, stream.readStream(a, out.items, .{}));
    }
    {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        for (0..2) |_| {
            var b = fb.Builder.init(gpa);
            defer b.deinit();
            try ipc.writeMessage(gpa, &out, try schema.encodeSchemaMessage(&b, .{ .fields = &.{} }), &.{});
        }
        try ipc.writeEos(gpa, &out);
        try testing.expectError(error.Malformed, stream.readStream(a, out.items, .{}));
    }
}

/// `region` (the leading mark and the messages) closed by a footer naming `batches`.
fn withFooter(gpa: Allocator, region: []const u8, batches: []const u8) ![]u8 {
    var b = fb.Builder.init(gpa);
    defer b.deinit();
    const sref = try schema.encodeSchema(&b, .{ .fields = &.{} });
    const bv = try b.createStructVector(batches, 24, 8);
    b.startTable();
    try b.addScalarForce(0, schema.MetadataVersion, .v5);
    try b.addOffset(1, sref);
    try b.addOffset(3, bv);
    const footer = try b.finish(try b.endTable());
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, region);
    try out.appendSlice(gpa, footer);
    try out.appendSlice(gpa, &std.mem.toBytes(std.mem.nativeToLittle(i32, @intCast(footer.len))));
    try out.appendSlice(gpa, "ARROW1");
    return out.toOwnedSlice(gpa);
}

test "file: the leading mark, a footer reaching into it, a block naming a message of another kind" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const f: df.Frame = .{ .columns = &.{}, .data = &.{}, .len = 0 };
    const good = try stream.writeFile(gpa, f, .{});
    defer gpa.free(good);
    _ = try stream.openFile(a, good, .{});
    {
        const bad = try gpa.dupe(u8, good);
        defer gpa.free(bad);
        bad[0] = 'X';
        try testing.expectError(error.Malformed, stream.openFile(a, bad, .{}));
    }
    {
        // A footer starting at byte 7, inside the leading 8 bytes.
        const region = "ARROW1\x00";
        const tmp = try withFooter(gpa, region, &.{});
        defer gpa.free(tmp);
        try testing.expectError(error.Malformed, stream.openFile(a, tmp, .{}));
    }
    {
        // The record batch list names the schema message (a table that would also parse as an
        // empty record batch).
        const flen: usize = @intCast(std.mem.readInt(i32, good[good.len - 10 ..][0..4], .little));
        const region = good[0 .. good.len - 10 - flen];
        var pos: usize = 8;
        _ = try ipc.readMessage(region, &pos);
        var block: [24]u8 = @splat(0);
        std.mem.writeInt(i64, block[0..8], 8, .little);
        std.mem.writeInt(i32, block[8..12], @intCast(pos - 8), .little);
        const tmp = try withFooter(gpa, region, &block);
        defer gpa.free(tmp);
        try testing.expectError(error.Malformed, stream.openFile(a, tmp, .{}));
    }
}
