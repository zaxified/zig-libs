// SPDX-License-Identifier: MIT
//! Tests of dataframe S2 wave W11 (real dtype widths), the core: `Value.uint`, the width
//! arrays and `frame.conform`, the cast modes, and the readers and writers on a width
//! column. What the engines answer is in `s2w11_oracle_test.zig`.
const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const dtype = @import("dtype.zig");
const keys = @import("keys.zig");
const Frame = fm.Frame;
const Column = vm.Column;
const ColumnType = vm.ColumnType;
const Value = vm.Value;

const big: u64 = (1 << 63) + 5; // above every i64

fn built(a: std.mem.Allocator, name: []const u8, ty: ColumnType, cells: []const Value) !Frame {
    const cols = try a.dupe(Column, &.{.{ .name = name, .type = ty }});
    var b = try fm.FrameBuilder.init(a, cols, cells.len);
    for (cells) |c| try b.appendRow(&.{c});
    return b.toOwned();
}

test "W11 Value.uint orders, compares and keys by its exact value" {
    const u: Value = .{ .uint = big };
    const max_i: Value = .{ .int = std.math.maxInt(i64) };
    try testing.expectEqual(std.math.Order.gt, u.order(max_i));
    try testing.expectEqual(std.math.Order.lt, max_i.order(u));
    // 2^63 as a float: exactly between maxInt(i64) and `big`.
    const two63: Value = .{ .float = 9223372036854775808.0 };
    try testing.expectEqual(std.math.Order.lt, two63.order(u));
    try testing.expectEqual(std.math.Order.gt, two63.order(max_i));
    const u_63: Value = .{ .uint = 1 << 63 };
    try testing.expect(two63.eql(u_63));
    try testing.expectEqual(std.math.Order.eq, u_63.order(two63));
    // A decimal equal to it, and a NaN that is greater than every number.
    const d63: Value = .{ .decimal = @as(i128, 1 << 63) * vm.decimal_scale };
    try testing.expect(d63.eql(u_63));
    try testing.expectEqual(std.math.Order.gt, (Value{ .float = std.math.nan(f64) }).order(u));
    // Keys: the three spellings of 2^63 are one key, `big` another.
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var k1: std.ArrayList(u8) = .empty;
    var k2: std.ArrayList(u8) = .empty;
    var k3: std.ArrayList(u8) = .empty;
    var k4: std.ArrayList(u8) = .empty;
    try keys.encode(a, &k1, u_63, .as_null);
    try keys.encode(a, &k2, two63, .as_null);
    try keys.encode(a, &k3, d63, .as_null);
    try keys.encode(a, &k4, u, .as_null);
    try testing.expectEqualSlices(u8, k1.items, k2.items);
    try testing.expectEqualSlices(u8, k1.items, k3.items);
    try testing.expect(!std.mem.eql(u8, k1.items, k4.items));
    // A hand-built `.uint` at or below maxInt(i64) keys as the int.
    var k5: std.ArrayList(u8) = .empty;
    var k6: std.ArrayList(u8) = .empty;
    try keys.encode(a, &k5, .{ .uint = 7 }, .as_null);
    try keys.encode(a, &k6, .{ .int = 7 }, .as_null);
    try testing.expectEqualSlices(u8, k6.items, k5.items);
    try testing.expectEqual(@as(?f64, 9223372036854775813.0), u.asFloat());
    try testing.expectEqual(@as(?i64, null), u.asInt());
}

test "W11 a declared width gets its own array; cells read back widened" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try built(a, "x", .uint64, &.{ .{ .int = 1 }, .null, .{ .uint = big } });
    try testing.expect(fm.widthsConform(f));
    try testing.expect(f.columnAt(0) == .uint64);
    try testing.expectEqual(@as(i64, 1), f.columnAt(0).get(0).int);
    try testing.expect(f.columnAt(0).get(1) == .null);
    try testing.expectEqual(big, f.columnAt(0).get(2).uint);
    const g = try built(a, "x", .float32, &.{ .{ .float = 0.1 }, .{ .int = 3 } });
    try testing.expect(g.columnAt(0) == .float32);
    try testing.expectEqual(@as(f64, @as(f32, 0.1)), g.columnAt(0).get(0).float);
    try testing.expectEqual(@as(f64, 3), g.columnAt(0).get(1).float);
    // An Int64 or Float64 column keeps the cells' storage, as before W11.
    const h = try built(a, "x", .int, &.{ .{ .int = 1 }, .{ .int = 2 } });
    try testing.expect(h.columnAt(0) == .int);
}

test "W11 conform turns what the width does not hold into null, never a panic" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // A hand-built mix: in range, out of range, a fraction, a whole float, text, a NaN, a UInt64.
    const cells = [_]Value{ .{ .int = 127 }, .{ .int = 128 }, .{ .float = 1.5 }, .{ .float = -3 }, .{ .text = "7" }, .{ .float = std.math.nan(f64) }, .{ .uint = big } };
    const col = try fm.columnFromCells(a, &cells);
    const want = [_]?i64{ 127, null, null, -3, null, null, null };
    const n8 = try fm.conform(a, col, .int8, cells.len);
    try testing.expect(n8 == .int8);
    for (want, 0..) |w, i| {
        const v = n8.get(i);
        if (w) |x| try testing.expectEqual(x, v.int) else try testing.expect(v == .null);
    }
    // Every width over every one of these cells.
    inline for (.{ .int8, .int16, .int32, .uint8, .uint16, .uint32, .uint64, .float32 }) |t| {
        const d = try fm.conform(a, col, t, cells.len);
        try testing.expectEqualStrings(@tagName(t), @tagName(std.meta.activeTag(d)));
        for (0..cells.len) |i| _ = d.get(i);
    }
    // A float32 of a value past its range is infinity, as polars' cast.
    const fl = try fm.conform(a, try fm.columnFromCells(a, &.{.{ .float = 1e300 }}), .float32, 1);
    try testing.expect(std.math.isInf(fl.get(0).float));
    // A storage shorter than the frame reads as null past its end.
    const short = try fm.conform(a, col, .int16, cells.len + 3);
    try testing.expect(short.get(cells.len + 2) == .null);
}

test "W11 cast to a width: null, fail and wrap" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try built(a, "x", .int, &.{ .{ .int = 1 }, .{ .int = 300 }, .null, .{ .int = -1 } });
    const n = try df.cast(a, f, .{ .col = "x", .to = .uint8 });
    try testing.expect(n.columnAt(0) == .uint8);
    try testing.expectEqual(@as(i64, 1), n.columnAt(0).get(0).int);
    try testing.expect(n.columnAt(0).get(1) == .null);
    try testing.expect(n.columnAt(0).get(3) == .null);
    try testing.expectError(error.CastFailed, df.cast(a, f, .{ .col = "x", .to = .uint8, .on_error = .fail }));
    const w = try df.cast(a, f, .{ .col = "x", .to = .uint8, .on_error = .wrap });
    try testing.expectEqual(@as(i64, 44), w.columnAt(0).get(1).int);
    try testing.expect(w.columnAt(0).get(2) == .null); // a null stays null
    try testing.expectEqual(@as(i64, 255), w.columnAt(0).get(3).int);
    // Wrap of a float saturates; of text that is no number, null.
    const g = try built(a, "x", .text, &.{ .{ .text = "abc" }, .{ .text = "300" } });
    const gw = try df.cast(a, g, .{ .col = "x", .to = .int8, .on_error = .wrap });
    try testing.expect(gw.columnAt(0).get(0) == .null);
    try testing.expectEqual(@as(i64, 44), (try df.cast(a, f, .{ .col = "x", .to = .int8, .on_error = .wrap })).columnAt(0).get(1).int);
    const h = try built(a, "x", .float, &.{ .{ .float = 1e300 }, .{ .float = -1e300 }, .{ .float = -2.7 } });
    const hw = try df.cast(a, h, .{ .col = "x", .to = .int16, .on_error = .wrap });
    try testing.expectEqual(@as(i64, 32767), hw.columnAt(0).get(0).int);
    try testing.expectEqual(@as(i64, -32768), hw.columnAt(0).get(1).int);
    try testing.expectEqual(@as(i64, -2), hw.columnAt(0).get(2).int);
    // UInt64 above maxInt(i64) to text and back, and to Int64 (null: out of range).
    const u = try built(a, "x", .uint64, &.{.{ .uint = big }});
    const t = try df.cast(a, u, .{ .col = "x", .to = .text });
    try testing.expectEqualStrings("9223372036854775813", t.columnAt(0).get(0).text);
    const back = try df.cast(a, t, .{ .col = "x", .to = .uint64 });
    try testing.expectEqual(big, back.columnAt(0).get(0).uint);
    try testing.expect((try df.cast(a, u, .{ .col = "x", .to = .int })).columnAt(0).get(0) == .null);
    try testing.expectEqual(@as(i64, 5), (try df.cast(a, u, .{ .col = "x", .to = .int, .on_error = .wrap })).columnAt(0).get(0).int - std.math.minInt(i64));
}

test "W11 CSV and JSON round trip of UInt64 above 2^63 and Float32" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const types = [_]df.TypeOverride{ .{ .name = "u", .type = .uint64 }, .{ .name = "f", .type = .float32 }, .{ .name = "s", .type = .int16 } };
    const f = try df.readCsv(a, "u,f,s\n18446744073709551615,0.1,-32768\n1,,7\n", .{ .types = &types });
    try testing.expect(fm.widthsConform(f));
    try testing.expect(f.columnAt(0) == .uint64 and f.columnAt(1) == .float32 and f.columnAt(2) == .int16);
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), f.columnAt(0).get(0).uint);
    var out: std.Io.Writer.Allocating = .init(a);
    try df.writeCsv(a, &out.writer, f, .{});
    try testing.expectEqualStrings("u,f,s\n18446744073709551615,0.1,-32768\n1,,7\n", out.written());
    var js: std.Io.Writer.Allocating = .init(a);
    try df.writeJson(&js.writer, f, .records);
    try testing.expectEqualStrings("[{\"u\":18446744073709551615,\"f\":0.1,\"s\":-32768},{\"u\":1,\"f\":null,\"s\":7}]", js.written());
    const g = try df.readJson(a, js.written(), .{ .types = &types });
    try testing.expect(fm.widthsConform(g));
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), g.columnAt(0).get(0).uint);
    try testing.expectEqual(@as(f64, @as(f32, 0.1)), g.columnAt(1).get(0).float);
    // Out of the width's range is `error.BadValue`, as polars' `read_csv`.
    try testing.expectError(error.BadValue, df.readCsv(a, "s\n32768\n", .{ .types = types[2..] }));
    try testing.expectError(error.BadValue, df.readCsv(a, "u\n-1\n", .{ .types = types[0..1] }));
    try testing.expectError(error.BadValue, df.readCsv(a, "u\n18446744073709551616\n", .{ .types = types[0..1] }));
}

test "W11 sort, distinct and join by a UInt64 key above 2^63" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try built(a, "k", .uint64, &.{ .{ .uint = big }, .{ .int = 3 }, .{ .uint = big }, .{ .uint = big + 1 }, .null });
    const s = try df.sort(a, f, .{ .key = "k" });
    try testing.expect(s.columnAt(0).get(0) == .null);
    try testing.expectEqual(@as(i64, 3), s.columnAt(0).get(1).int);
    try testing.expectEqual(big, s.columnAt(0).get(2).uint);
    try testing.expectEqual(big + 1, s.columnAt(0).get(4).uint);
    try testing.expect(fm.widthsConform(s));
    const d = try df.distinct(a, f, .{ .keys = &.{} });
    try testing.expectEqual(@as(usize, 4), d.len);
    // An Int64 key column of 3 joins the UInt64 3 (exact value, D10).
    const r = try built(a, "k", .int, &.{ .{ .int = 3 }, .{ .int = std.math.maxInt(i64) } });
    const j = try df.join(a, f, r, .{ .on = "k" });
    try testing.expectEqual(@as(usize, 1), j.len);
}

test "W11 supertype and fitting helpers" {
    try testing.expect(dtype.isWidth(.int8) and !dtype.isWidth(.int) and !dtype.isWidth(.float));
    try testing.expect(dtype.isInteger(.uint64) and !dtype.isInteger(.float32));
    try testing.expectEqualStrings("u64", dtype.name(.uint64));
    try testing.expect(dtype.intValue(-1 - @as(i128, std.math.maxInt(u64))) == null);
    try testing.expectEqual(big, dtype.intValue(big).?.uint);
}
