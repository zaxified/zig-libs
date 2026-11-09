// SPDX-License-Identifier: MIT
//! Replays `oracle2h_vectors.json` (dataframe S2 wave W9): what pandas 3.1 (`read_csv(chunksize=)`)
//! and polars 2.1 (`read_csv` with `infer_schema_length`, `ignore_errors`) answered for chunked CSV
//! reading (`tools/oracle2h.py` asked the engines; no line of dataframe is consulted there). The
//! expected values are the engines' alone, so a failure is a difference from them, except where
//! `known` says why we differ on purpose.
const std = @import("std");
const testing = std.testing;
const vm = @import("value.zig");
const cio = @import("csvio.zig");
const cc = @import("csvchunk.zig");
const Slow = @import("s2w9_test.zig").Slow;
const J = std.json.Value;

const vectors = @embedFile("oracle2h_vectors.json");

/// Deliberate differences from what the engines answered: id and why.
const known = [_]struct { id: []const u8, why: []const u8 }{
    .{ .id = "pd-header-only", .why = "a stream with a header and no rows yields no chunk (polars); pandas yields an empty chunk" },
};

fn isKnown(id: []const u8) bool {
    for (known) |k| if (std.mem.eql(u8, k.id, id)) return true;
    return false;
}

fn kindOf(t: vm.ColumnType) []const u8 {
    return switch (t) {
        .int => "int",
        .float => "float",
        .bool => "bool",
        else => "text",
    };
}

/// An engine cell against ours. An int and a float of one value agree (a column with a hole is
/// float in pandas and int here, `readCsv`'s documented rule).
fn cellMatches(want: J, got: vm.Value) bool {
    return switch (want) {
        .null => got == .null,
        .bool => |b| got == .bool and got.bool == b,
        .integer => |i| (got == .int and got.int == i) or (got == .float and got.float == @as(f64, @floatFromInt(i))),
        .float => |f| (got == .float and got.float == f) or (got == .int and @as(f64, @floatFromInt(got.int)) == f),
        .string => |s| got == .text and std.mem.eql(u8, got.text, s),
        else => false,
    };
}

fn optsFor(case: std.json.ObjectMap) cio.CsvReadOptions {
    var o: cio.CsvReadOptions = .{};
    if (case.get("opts")) |op| {
        if (op.object.get("nrows")) |v| o.n_rows = @as(usize, @intCast(v.integer));
        if (op.object.get("skiprows")) |v| o.skip_rows = @as(usize, @intCast(v.integer));
        if (op.object.get("comment")) |v| o.comment = v.string[0];
        if (op.object.get("on_bad_lines")) |v| {
            if (std.mem.eql(u8, v.string, "skip")) o.on_bad_lines = .skip;
        }
    }
    return o;
}

test "oracle2h: pandas chunks and polars fixed-schema reads" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const root = try std.json.parseFromSliceLeaky(J, a, vectors, .{});
    var replayed: usize = 0;
    var skipped: usize = 0;
    for (root.array.items) |item| {
        const c = item.object;
        const id = c.get("id").?.string;
        if (isKnown(id)) {
            skipped += 1;
            continue;
        }
        const text = c.get("text").?.string;
        var slow: Slow = undefined;
        slow.init(text, 0);
        const is_pandas = std.mem.eql(u8, c.get("engine").?.string, "pandas");
        if (is_pandas) {
            var rd = try cc.CsvChunkReader.init(testing.allocator, &slow.interface, optsFor(c), .{ .schema = .per_chunk });
            defer rd.deinit();
            const n: usize = @intCast(c.get("chunk").?.integer);
            for (c.get("chunks").?.array.items, 0..) |want, ci| {
                var ca = std.heap.ArenaAllocator.init(testing.allocator);
                defer ca.deinit();
                const f = (try rd.next(ca.allocator(), n)) orelse {
                    std.debug.print("{s}: chunk {d} missing\n", .{ id, ci });
                    return error.TestExpectedEqual;
                };
                const cols = want.object.get("cols").?.array.items;
                const kinds = want.object.get("kinds").?.array.items;
                try testing.expectEqual(cols.len, f.columns.len);
                for (cols, kinds, 0..) |col, kind, j| {
                    try testing.expectEqual(col.array.items.len, f.len);
                    var holes = false;
                    for (col.array.items, 0..) |wv, ri| {
                        holes = holes or wv == .null;
                        if (!cellMatches(wv, f.columnAt(j).get(ri))) {
                            std.debug.print("{s}: chunk {d} col {d} row {d}: want {any} got {any}\n", .{ id, ci, j, ri, wv, f.columnAt(j).get(ri) });
                            return error.TestExpectedEqual;
                        }
                    }
                    if (!holes) try testing.expectEqualStrings(kind.string, kindOf(f.columns[j].type));
                }
            }
            var ca = std.heap.ArenaAllocator.init(testing.allocator);
            defer ca.deinit();
            try testing.expect((try rd.next(ca.allocator(), n)) == null);
        } else {
            const infer: usize = @intCast(c.get("infer_rows").?.integer);
            const ignore = c.get("ignore_errors").?.bool;
            var rd = try cc.CsvChunkReader.init(testing.allocator, &slow.interface, .{}, .{ .infer_rows = infer, .ignore_errors = ignore });
            defer rd.deinit();
            var ca = std.heap.ArenaAllocator.init(testing.allocator);
            defer ca.deinit();
            const got = rd.next(ca.allocator(), 100);
            if (c.get("error").?.bool) {
                try testing.expectError(error.BadValue, got);
            } else {
                const f = (try got).?;
                const cols = c.get("cols").?.array.items;
                const kinds = c.get("kinds").?.array.items;
                try testing.expectEqual(cols.len, f.columns.len);
                for (cols, kinds, 0..) |col, kind, j| {
                    try testing.expectEqual(col.array.items.len, f.len);
                    for (col.array.items, 0..) |wv, ri| {
                        if (!cellMatches(wv, f.columnAt(j).get(ri))) {
                            std.debug.print("{s}: col {d} row {d}: want {any} got {any}\n", .{ id, j, ri, wv, f.columnAt(j).get(ri) });
                            return error.TestExpectedEqual;
                        }
                    }
                    try testing.expectEqualStrings(kind.string, kindOf(f.columns[j].type));
                }
            }
        }
        replayed += 1;
    }
    try testing.expect(replayed >= 15);
}
