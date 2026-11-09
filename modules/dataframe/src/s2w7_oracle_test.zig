// SPDX-License-Identifier: MIT
//! Replays `oracle2g_vectors.json` (dataframe S2 wave W7): what pandas 3.1 (`datetime64[us,
//! zone]`) and polars 2.1 (`Datetime("us", time_zone=...)`) answered for the wall clock a zoned
//! column shows, `strftime` with `%z`/`%Z`, `replace_time_zone`/`tz_localize`, `truncate`/
//! `floor`, comparing and casting zoned columns, `group_by_dynamic`/`resample`, and the text
//! I/O (`tools/oracle2g.py` asked the engines; no line of this module is consulted there).
//! A case that two engines answer differently is in the file under both answers, and `known`
//! says which one dataframe does not follow.
const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const vm = @import("value.zig");
const st = @import("structure_test.zig");
const Frame = df.Frame;
const Column = df.Column;
const Value = df.Value;
const Expr = df.Expr;
const J = std.json.Value;

const vectors = @embedFile("oracle2g_vectors.json");

/// Deliberate differences from what an engine answered: id substring, engine ("" = either),
/// and why.
const known = [_]struct { id: []const u8, engine: []const u8, why: []const u8 }{
    .{ .id = "csv-write-", .engine = "polars", .why = "polars writes `2024-07-15T12:00:00.000000+0200` (T, six digits, no colon); the pandas form (space, one 0/3/6 digit width per column, `+02:00`) is what the naive timestamp writer already follows" },
    .{ .id = "json-write-", .engine = "pandas", .why = "pandas writes the UTC instant with `Z` and drops the zone; polars' wall clock with its offset is followed (the same instant, and the offset survives a round trip)" },
    .{ .id = "ndjson-write-", .engine = "pandas", .why = "as json-write: pandas writes UTC with `Z`" },
    .{ .id = "csv-read-zoned-one2", .engine = "pandas", .why = "a cell without an offset: pandas reads it as the wall clock in the zone, polars as UTC (followed: a naive column of this module is UTC); `replace_time_zone` after a zone-less read is the pandas reading" },
    .{ .id = "csv-read-zoned-one3", .engine = "pandas", .why = "as csv-read-zoned-one2" },
    .{ .id = "fields-America/New_York-pre1970", .engine = "", .why = "the 1960 summer cell: `tz.zones` has no history before 1970 and gives the state at the epoch (EST), the engines give EDT" },
    .{ .id = "compare-naive-zoned", .engine = "", .why = "naive against zoned: pandas answers False for ==, polars raises SchemaError; instants are compared here (a naive column is UTC)" },
    .{ .id = "json-table-data", .engine = "", .why = "pandas writes UTC with `Z` and three digits; the local form is tested by a round trip" },
    .{ .id = "html", .engine = "", .why = "pandas pads a column's fractions to one width (.000); `toHtml` shows each cell's own, for naive columns too" },
};

fn isKnown(id: []const u8, engine: []const u8) bool {
    for (known) |k| {
        if (std.mem.find(u8, id, k.id) == null) continue;
        if (k.engine.len == 0 or std.mem.eql(u8, k.engine, engine)) return true;
    }
    return false;
}

fn strOf(o: J, k: []const u8) ?[]const u8 {
    const v = o.object.get(k) orelse return null;
    return if (v == .string) v.string else null;
}

fn arrOf(o: J, k: []const u8) []const J {
    return o.object.get(k).?.array.items;
}

fn jcell(j: J) Value {
    return switch (j) {
        .null => .null,
        .bool => |b| .{ .bool = b },
        .integer => |i| .{ .int = i },
        .float => |x| .{ .float = x },
        .string => |s| .{ .text = s },
        else => .null,
    };
}

fn same(want: J, got: Value) bool {
    return switch (want) {
        .null => got == .null,
        .bool => |b| got == .bool and got.bool == b,
        .integer => |i| (got == .int and got.int == i) or (got == .float and got.float == @as(f64, @floatFromInt(i))),
        .string => |s| got == .text and std.mem.eql(u8, got.text, s),
        else => false,
    };
}

var fails: usize = 0;
var ran: usize = 0;

fn fail(id: []const u8, comptime fmt: []const u8, args: anytype) void {
    fails += 1;
    std.debug.print("MISMATCH {s}: " ++ fmt ++ "\n", .{id} ++ args);
}

const X: Expr = .{ .col = "ts" };

/// Column `ts` of the instants `inst` (microseconds or null) carrying `zone`, and `v` = 0, 1, 2...
fn tsFrame(a: std.mem.Allocator, inst: []const J, zone: ?[]const u8) !Frame {
    const cells = try a.alloc(Value, inst.len);
    const vs = try a.alloc(Value, inst.len);
    for (cells, vs, inst, 0..) |*c, *v, j, i| {
        c.* = jcell(j);
        v.* = .{ .int = @intCast(i) };
    }
    const cols = try a.dupe(Column, &.{
        .{ .name = "ts", .type = .timestamp, .time_zone = zone },
        .{ .name = "v", .type = .int },
    });
    const data = try a.alloc(df.ColumnData, 2);
    data[0] = try df.columnFromCells(a, cells);
    data[1] = try df.columnFromCells(a, vs);
    return .{ .columns = cols, .data = data, .len = inst.len };
}

/// A naive timestamp column (`ts`) from ISO wall-clock texts.
fn naiveFrame(a: std.mem.Allocator, texts: []const J) !Frame {
    const cells = try a.alloc(Value, texts.len);
    for (cells, texts) |*c, j| {
        c.* = if (j == .string) .{ .int = vm.parseIsoTimestamp(try std.fmt.allocPrint(a, "{s}Z", .{j.string})) orelse return error.BadVector } else .null;
    }
    const cols = try a.dupe(Column, &.{.{ .name = "ts", .type = .timestamp }});
    const data = try a.alloc(df.ColumnData, 1);
    data[0] = try df.columnFromCells(a, cells);
    return .{ .columns = cols, .data = data, .len = texts.len };
}

fn evalOut(a: std.mem.Allocator, f: Frame, e: Expr) !Frame {
    return df.mutate(a, f, &.{.{ .out = "out", .expr = e }});
}

fn checkCells(id: []const u8, what: []const u8, want: []const J, g: Frame, col: []const u8) void {
    if (g.len != want.len) return fail(id, "{s}: {d} rows, want {d}", .{ what, g.len, want.len });
    for (want, 0..) |w, ri| {
        const got = g.cell(ri, col) orelse .null;
        if (!same(w, got)) return fail(id, "{s} row {d}: got {any}, want {any}", .{ what, ri, got, w });
    }
}

fn runFields(a: std.mem.Allocator, c: J) !void {
    const id = strOf(c, "id").?;
    const f = try tsFrame(a, arrOf(c, "inst"), strOf(c, "zone"));
    var it = c.object.get("expect").?.object.iterator();
    while (it.next()) |kv| {
        const part = std.meta.stringToEnum(df.DtPart, kv.key_ptr.*) orelse return error.BadVector;
        const g = try evalOut(a, f, .{ .dt = .{ .x = &X, .part = part } });
        checkCells(id, kv.key_ptr.*, kv.value_ptr.array.items, g, "out");
    }
}

fn runStrftime(a: std.mem.Allocator, c: J) !void {
    const f = try tsFrame(a, arrOf(c, "inst"), strOf(c, "zone"));
    const g = try evalOut(a, f, .{ .strftime = .{ .x = &X, .format = strOf(c, "fmt").? } });
    checkCells(strOf(c, "id").?, "strftime", c.object.get("expect").?.array.items, g, "out");
}

fn policyOf(name: []const u8) df.TzPolicy {
    return std.meta.stringToEnum(df.TzPolicy, name).?;
}

fn runReplace(a: std.mem.Allocator, c: J) !void {
    const f = try naiveFrame(a, arrOf(c, "wall"));
    const g = try evalOut(a, f, .{ .replace_time_zone = .{ .x = &X, .zone = strOf(c, "zone"), .policy = policyOf(strOf(c, "policy").?) } });
    checkCells(strOf(c, "id").?, "replace_time_zone", c.object.get("expect").?.array.items, g, "out");
    const ci = g.columnIndex("out").?;
    if (g.columns[ci].time_zone == null or !std.mem.eql(u8, g.columns[ci].time_zone.?, strOf(c, "zone").?)) fail(strOf(c, "id").?, "the result does not carry the zone", .{});
}

fn runReplaceZoned(a: std.mem.Allocator, c: J, to_naive: bool) !void {
    const f = try tsFrame(a, arrOf(c, "inst"), strOf(c, "zone_from"));
    const zone: ?[]const u8 = if (to_naive) null else strOf(c, "zone");
    const g = try evalOut(a, f, .{ .replace_time_zone = .{ .x = &X, .zone = zone, .policy = .earlier } });
    checkCells(strOf(c, "id").?, "replace_time_zone of a zoned column", c.object.get("expect").?.array.items, g, "out");
}

fn runConvertNaive(a: std.mem.Allocator, c: J) !void {
    const f = try tsFrame(a, arrOf(c, "inst"), strOf(c, "zone_from"));
    const g = try evalOut(a, f, .{ .convert_time_zone = .{ .x = &X, .zone = null } });
    checkCells(strOf(c, "id").?, "convert_time_zone(null)", c.object.get("expect").?.array.items, g, "out");
    if (g.columns[g.columnIndex("out").?].time_zone != null) fail(strOf(c, "id").?, "the zone stays", .{});
}

fn runConvertOfNaive(a: std.mem.Allocator, c: J) !void {
    const f = try naiveFrame(a, &.{ .{ .string = "2024-01-15T12:00:00" }, .{ .string = "2024-07-15T12:00:00.25" } });
    const g = try evalOut(a, f, .{ .convert_time_zone = .{ .x = &X, .zone = strOf(c, "zone") } });
    checkCells(strOf(c, "id").?, "convert_time_zone of a naive column", c.object.get("expect").?.array.items, g, "out");
}

fn runTruncate(a: std.mem.Allocator, c: J, mode: df.RoundTo) !void {
    const f = try tsFrame(a, arrOf(c, "inst"), strOf(c, "zone"));
    const g = try evalOut(a, f, .{ .truncate = .{ .x = &X, .every = strOf(c, "every").?, .mode = mode } });
    checkCells(strOf(c, "id").?, "truncate", c.object.get("expect").?.array.items, g, "out");
    if (g.columns[g.columnIndex("out").?].time_zone == null) fail(strOf(c, "id").?, "the result lost the zone", .{});
}

fn runCompare(a: std.mem.Allocator, c: J) !void {
    const f1 = try tsFrame(a, arrOf(c, "a"), strOf(c, "zone_a"));
    const f2 = try tsFrame(a, arrOf(c, "b"), strOf(c, "zone_b"));
    const f = try df.hstack(a, f1, &.{blk: {
        var s = f2.series("ts").?;
        s.name = "ts_b";
        break :blk s;
    }});
    const op = std.meta.stringToEnum(enum { eq, lt, gt }, strOf(c, "op").?).?;
    const b: Expr = .{ .col = "ts_b" };
    const a_in = arrOf(c, "a");
    const g = try evalOut(a, f, .{ .binary = .{ .op = switch (op) {
        .eq => .eq,
        .lt => .lt,
        .gt => .gt,
    }, .l = &X, .r = &b } });
    // pandas answers False where a side is NaT (NaT == x, NaT < x); polars and this module answer null
    const want = try a.dupe(J, c.object.get("expect").?.array.items);
    for (want, a_in) |*w, ai| if (ai == .null) {
        w.* = .null;
    };
    checkCells(strOf(c, "id").?, "compare", want, g, "out");
}

fn runCast(a: std.mem.Allocator, c: J, from_zone: bool, to_zone: bool) !void {
    const f = try tsFrame(a, arrOf(c, "inst"), if (from_zone) (strOf(c, "zone_from") orelse "UTC") else null);
    const g = try df.cast(a, f, .{ .col = "ts", .to = .timestamp, .zone = if (to_zone) strOf(c, "zone") else null });
    checkCells(strOf(c, "id").?, "cast", c.object.get("expect").?.array.items, g, "ts");
    const zone = g.columns[0].time_zone;
    if (to_zone != (zone != null)) fail(strOf(c, "id").?, "the zone after the cast is {?s}", .{zone});
}

fn runDynamic(a: std.mem.Allocator, c: J) !void {
    const f = try tsFrame(a, arrOf(c, "inst"), strOf(c, "zone"));
    const g = try df.groupByDynamic(a, f, .{ .index = "ts", .every = strOf(c, "every").?, .aggs = &.{
        .{ .src = "v", .out = "s", .func = .sum },
        .{ .src = "v", .out = "n", .func = .count },
    } });
    const ex = c.object.get("expect").?;
    const id = strOf(c, "id").?;
    checkCells(id, "label", ex.object.get("label").?.array.items, g, "ts");
    checkCells(id, "count", ex.object.get("n").?.array.items, g, "n");
    checkCells(id, "sum", ex.object.get("sum").?.array.items, g, "s");
}

const WriteKind = enum { csv, json, ndjson };

/// The text a writer made of the frame the case describes.
fn writeText(a: std.mem.Allocator, c: J, kind: WriteKind) ![]const u8 {
    const inst = arrOf(c, "inst");
    const f0 = try tsFrame(a, inst, strOf(c, "zone"));
    // `k` = 1..n as in the generator
    const ks = try a.alloc(Value, inst.len);
    for (ks, 0..) |*k, i| k.* = .{ .int = @intCast(i + 1) };
    const kdata = try df.columnFromCells(a, ks);
    const cols = try a.dupe(Column, &.{ f0.columns[0], .{ .name = "k", .type = .int } });
    const data = try a.dupe(df.ColumnData, &.{ f0.data[0], kdata });
    const f: Frame = .{ .columns = cols, .data = data, .len = inst.len };
    var aw: std.Io.Writer.Allocating = .init(a);
    switch (kind) {
        .csv => try df.writeCsv(a, &aw.writer, f, .{}),
        .json => try df.writeJson(&aw.writer, f, .records),
        .ndjson => try df.writeNdjson(&aw.writer, f),
    }
    return aw.written();
}

/// polars writes the milliseconds of a fraction (`.500`); the writer trims zeros as for a naive timestamp (`.5`).
fn trimFraction(a: std.mem.Allocator, s: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) {
        if (std.mem.startsWith(u8, s[i..], ".500+") or std.mem.startsWith(u8, s[i..], ".500-")) {
            try out.appendSlice(a, &.{ '.', '5', s[i + 4] });
            i += 5;
        } else {
            try out.append(a, s[i]);
            i += 1;
        }
    }
    return out.items;
}

fn runWrite(a: std.mem.Allocator, c: J, kind: WriteKind) !void {
    const got = try writeText(a, c, kind);
    const want_raw = c.object.get("expect").?.string;
    const want = if (kind == .csv) want_raw else try trimFraction(a, want_raw);
    if (!std.mem.eql(u8, got, want)) fail(strOf(c, "id").?, "\n got  {s}\n want {s}", .{ got, want });
}

fn runCsvRead(a: std.mem.Allocator, c: J) !void {
    const id = strOf(c, "id").?;
    const zone = strOf(c, "zone").?;
    const g = try df.readCsv(a, strOf(c, "csv").?, .{ .types = &.{.{ .name = "ts", .type = .timestamp, .time_zone = zone }} });
    const ex = c.object.get("expect").?;
    checkCells(id, "epoch_us", ex.object.get("epoch_us").?.array.items, g, "ts");
    if (g.columns[0].type != .timestamp or g.columns[0].time_zone == null or !std.mem.eql(u8, g.columns[0].time_zone.?, zone)) fail(id, "the column is not a timestamp in {s}", .{zone});
}

fn runTableSchema(a: std.mem.Allocator, c: J) !void {
    const id = strOf(c, "id").?;
    const f = try tsFrame(a, arrOf(c, "inst"), strOf(c, "zone"));
    var aw: std.Io.Writer.Allocating = .init(a);
    try df.writeJson(&aw.writer, f, .table);
    const want = try std.fmt.allocPrint(a, "{{\"name\":\"ts\",\"type\":\"datetime\",\"tz\":\"{s}\"}}", .{strOf(c, "zone").?});
    if (std.mem.find(u8, aw.written(), want) == null) fail(id, "no {s} in {s}", .{ want, aw.written() });
}

fn dispatch(a: std.mem.Allocator, c: J) !void {
    const kind = strOf(c, "kind").?;
    const eq = std.mem.eql;
    if (eq(u8, kind, "fields")) return runFields(a, c);
    if (eq(u8, kind, "strftime")) return runStrftime(a, c);
    if (eq(u8, kind, "replace")) return runReplace(a, c);
    if (eq(u8, kind, "replace_zoned")) return runReplaceZoned(a, c, false);
    if (eq(u8, kind, "replace_naive")) return runReplaceZoned(a, c, true);
    if (eq(u8, kind, "convert_naive")) return runConvertNaive(a, c);
    if (eq(u8, kind, "convert_of_naive")) return runConvertOfNaive(a, c);
    if (eq(u8, kind, "truncate")) return runTruncate(a, c, .floor);
    if (eq(u8, kind, "ceil")) return runTruncate(a, c, .ceil);
    if (eq(u8, kind, "compare")) return runCompare(a, c);
    if (eq(u8, kind, "cast_zoned")) return runCast(a, c, !eq(u8, strOf(c, "id").?, "cast-naive-to-zoned"), true);
    if (eq(u8, kind, "cast_naive")) return runCast(a, c, true, false);
    if (eq(u8, kind, "dynamic")) return runDynamic(a, c);
    if (eq(u8, kind, "csv_write")) return runWrite(a, c, .csv);
    if (eq(u8, kind, "json_write")) return runWrite(a, c, .json);
    if (eq(u8, kind, "ndjson_write")) return runWrite(a, c, .ndjson);
    if (eq(u8, kind, "csv_read")) return runCsvRead(a, c);
    if (eq(u8, kind, "table_schema")) return runTableSchema(a, c);
    return error.UnknownKind;
}

test "oracle2g: replay the engines' answers on zoned columns" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const root = try std.json.parseFromSliceLeaky(J, arena.allocator(), vectors, .{});
    fails = 0;
    ran = 0;
    var skipped: usize = 0;
    for (root.array.items) |c| {
        const id = strOf(c, "id").?;
        const engine = strOf(c, "engine") orelse "";
        if (isKnown(id, engine) or c.object.get("error") != null) {
            skipped += 1;
            continue;
        }
        var scratch: std.heap.ArenaAllocator = .init(testing.allocator);
        defer scratch.deinit();
        dispatch(scratch.allocator(), c) catch |e| fail(id, "error {s}", .{@errorName(e)});
        ran += 1;
    }
    // Silent when green: a full lane treats any stderr from a passing test as a failure.
    if (fails != 0) std.debug.print("oracle2g: {d} cases replayed, {d} known differences skipped, {d} mismatches\n", .{ ran, skipped, fails });
    try testing.expect(ran > 100);
    try testing.expectEqual(@as(usize, 0), fails);
}
