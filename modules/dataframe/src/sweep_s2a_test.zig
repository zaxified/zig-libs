// SPDX-License-Identifier: MIT
//! The S2 no-panic sweep, agent A's files (`expr window listfn callback catfn nestverbs corr
//! exprfn colfn strfn names ranges`; 2026-11-10): each finding's trigger, pinned. Names end
//! "(sweep A-<n>)".

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const expr = @import("expr.zig");
const lf = @import("listfn.zig");
const Value = df.Value;
const Column = df.Column;
const Frame = df.Frame;
const Expr = df.Expr;

fn elapsedMs(t0: i96) i96 {
    return @divFloor(std.Io.Timestamp.now(testing.io, .awake).nanoseconds - t0, std.time.ns_per_ms);
}

fn nowNs() i96 {
    return std.Io.Timestamp.now(testing.io, .awake).nanoseconds;
}

// ── A-1: the schema walks of a nested expression called each other twice per level ──────

test "a chain of list.first over list.first costs a step per node, not 2^depth (sweep A-1)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{.{ .name = "L", .type = .list }};
    const f: Frame = .{ .columns = &cols, .data = &.{}, .len = 2 };
    const depth = 200; // under `max_depth`
    const nodes = try a.alloc(Expr, depth + 1);
    nodes[0] = .{ .col = "L" };
    for (nodes[1..], 0..) |*n, i| n.* = .{ .list = .{ .op = .first, .x = &nodes[i] } };
    expr.test_hooks.shape_steps = 0;
    expr.test_hooks.shape_limit = 1 << 16; // a runaway walk gives up here instead of hanging the run
    defer expr.test_hooks.shape_limit = std.math.maxInt(usize);
    const out = try df.mutate(a, f, &.{.{ .out = "o", .expr = nodes[depth] }});
    try testing.expectEqual(@as(usize, 2), out.len);
    try testing.expect(expr.test_hooks.shape_steps < 2000);
}

// ── A-2: list_eval / struct_fields bodies were compiled with a node budget of their own ──

test "a list_eval DAG that shares its operand and body is ExprTooLarge, not 2^depth compiles (sweep A-2)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{.{ .name = "x", .type = .int }};
    const f: Frame = .{ .columns = &cols, .data = &.{}, .len = 1 };
    const depth = 20; // the tree behind it has 2^21 nodes; `max_nodes` is 2^16
    const nodes = try a.alloc(Expr, depth + 1);
    nodes[0] = .{ .lit = .null };
    for (nodes[1..], 0..) |*n, i| n.* = .{ .list_eval = .{ .x = &nodes[i], .body = &nodes[i] } };
    try testing.expectError(error.ExprTooLarge, df.mutate(a, f, &.{.{ .out = "o", .expr = nodes[depth] }}));
    // A plain program with a body still compiles.
    const one = [_]Expr{ .{ .col = "x" }, .{ .lit = .{ .int = 1 } } };
    const body: Expr = .{ .binary = .{ .op = .add, .l = &.{ .element = {} }, .r = &one[1] } };
    const lit_list: Expr = .{ .lit = .null };
    const ok: Expr = .{ .list_eval = .{ .x = &lit_list, .body = &body } };
    _ = try df.mutate(a, f, &.{.{ .out = "o", .expr = ok }});
}

// ── A-3: the correlation matrix is columns squared, whatever the rows ────────────────────

test "corr of a frame of many columns and no rows refuses the matrix before building it (sweep A-3)" {
    const buf = try testing.allocator.alloc(u8, 32 << 20);
    defer testing.allocator.free(buf);
    var fba = std.heap.FixedBufferAllocator.init(buf);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const k = 9000; // 81M cells > 2^26
    const cols = try arena.allocator().alloc(Column, k);
    for (cols) |*c| c.* = .{ .name = "c", .type = .float };
    const f: Frame = .{ .columns = cols, .data = &.{}, .len = 0 };
    try testing.expectError(error.TooLarge, df.corr(fba.allocator(), f, .{}));
    try testing.expectError(error.TooLarge, df.cov(fba.allocator(), f, .{}));
}

// ── A-4: a column named twice in `cols` is built twice ──────────────────────────────────

test "cumSumHorizontal over a column named many times is refused before the builders (sweep A-4)" {
    const buf = try testing.allocator.alloc(u8, 32 << 20);
    defer testing.allocator.free(buf);
    var fba = std.heap.FixedBufferAllocator.init(buf);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();
    const rows = 1000;
    const vals = try aa.alloc(i64, rows);
    @memset(vals, 1);
    const cols = [_]Column{.{ .name = "a", .type = .int }};
    const data = [_]df.ColumnData{.{ .int = .{ .values = vals } }};
    const f: Frame = .{ .columns = &cols, .data = &data, .len = rows };
    const names = try aa.alloc([]const u8, 20_000); // 20M cells out of 1000 in
    @memset(names, "a");
    try testing.expectError(error.TooLarge, df.cumSumHorizontal(fba.allocator(), f, names));
    // The frame's own columns, each once, are as before.
    const out = try df.cumSumHorizontal(aa, f, &.{"a"});
    try testing.expectEqual(@as(usize, rows), out.len);
    try testing.expectEqual(@as(i64, 1), out.cell(0, "a").?.int);
}

// ── A-5: the duplicate check of renamed fields compared every pair ───────────────────────

fn manyFieldRecord(a: std.mem.Allocator, n: usize, first: []const u8, second: []const u8) !Value {
    const names = try a.alloc([]const u8, n);
    for (names, 0..) |*nm, i| nm.* = if (i == 0) first else if (i == 1) second else try std.fmt.allocPrint(a, "f{d}", .{i});
    const children = try a.alloc(df.ColumnData, n);
    @memset(children, .nulls);
    const st = try a.create(df.StructColumn);
    st.* = .{ .names = names, .children = children, .len = 1 };
    return .{ .record = .{ .fields = st, .row = 0 } };
}

test "name.to_lowercase on a record of 60 000 fields is linear, and still finds a duplicate (sweep A-5)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const rec = try manyFieldRecord(a, 60_000, "A", "B");
    const t0 = nowNs();
    const out = try lf.structCell(a, rec, .{ .map_fields = .lower });
    try testing.expect(elapsedMs(t0) < 3000);
    try testing.expect(out == .record);
    try testing.expectEqual(@as(usize, 60_000), out.record.len());
    try testing.expectEqualStrings("a", out.record.name(0));
    // "Ab" and "aB" are one name once lower-cased: the cell is null, as for a short record.
    const dup = try manyFieldRecord(a, 40, "Ab", "aB");
    try testing.expect((try lf.structCell(a, dup, .{ .map_fields = .lower })) == .null);
    const short = try manyFieldRecord(a, 3, "Ab", "aB");
    try testing.expect((try lf.structCell(a, short, .{ .map_fields = .lower })) == .null);
}

// ── A-7: struct_fields looked each field up by scanning the names ────────────────────────

test "struct_fields over a struct column of 50 000 fields compiles in linear time (sweep A-7)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const n = 50_000;
    const names = try a.alloc([]const u8, n);
    for (names, 0..) |*nm, i| nm.* = try std.fmt.allocPrint(a, "f{d}", .{i});
    const children = try a.alloc(df.ColumnData, n);
    @memset(children, .nulls);
    const st = try a.create(df.StructColumn);
    st.* = .{ .names = names, .children = children, .len = 1 };
    // Declared fields in the opposite order: every positional guess misses.
    const inner = try a.alloc(Column, n);
    for (inner, 0..) |*c, i| c.* = .{ .name = names[n - 1 - i], .type = .int };
    const cols = [_]Column{.{ .name = "s", .type = .@"struct", .inner = inner }};
    const data = [_]df.ColumnData{.{ .@"struct" = st }};
    const f: Frame = .{ .columns = &cols, .data = &data, .len = 1 };
    const fields = try a.alloc(df.NamedExpr, n);
    for (fields, names) |*nf, nm| nf.* = .{ .name = nm, .x = .{ .lit = .{ .int = 7 } } };
    const col: Expr = .{ .col = "s" };
    const t0 = nowNs();
    const out = try df.mutate(a, f, &.{.{ .out = "o", .expr = .{ .struct_fields = .{ .x = &col, .fields = fields } } }});
    try testing.expect(elapsedMs(t0) < 3000);
    try testing.expectEqual(@as(usize, 1), out.len);
    const rec = out.cell(0, "o").?;
    try testing.expectEqual(@as(usize, n), rec.record.len());
    try testing.expectEqual(@as(i64, 7), rec.record.get(n - 1).int);
}

// ── A-10: repeat counted a nested value as its slots, not what it holds ──────────────────

test "repeatValue weighs the text inside a list, so 2M copies of a 1 MiB cell are TooLarge (sweep A-10)" {
    const buf = try testing.allocator.alloc(u8, 64 << 20);
    defer testing.allocator.free(buf);
    var fba = std.heap.FixedBufferAllocator.init(buf);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();
    const big = try aa.alloc(u8, 1 << 20);
    @memset(big, 'x');
    const v = try lf.makeList(aa, &.{.{ .text = big }});
    try testing.expectError(error.TooLarge, df.repeatValue(fba.allocator(), "x", v, 1 << 21, null));
    // A modest value is as before.
    const small = try lf.makeList(aa, &.{ .{ .int = 1 }, .{ .int = 2 } });
    const out = try df.repeatValue(aa, "x", small, 3, null);
    try testing.expectEqual(@as(usize, 3), out.len);
    try testing.expectEqual(@as(i64, 2), out.cell(2, "x").?.list.get(1).int);
}
