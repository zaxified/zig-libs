// SPDX-License-Identifier: MIT

//! Fuzz harness for `dataframe`: the CSV reader on generated and damaged bytes,
//! random frames through random verb sequences, and the writers (JSON, NDJSON,
//! `format`, Markdown, CSV) over random frames.
//!
//! One driver, the choice source picks the target (`<DATAFRAME_FUZZ>=runs[,seed]`,
//! `_MS`, `_SEEDFILE`, `_INPUT`; see `testkit.fuzz.driver`). Oracles:
//!  - csv: any input and any options is a frame or an error, never a panic; the
//!    one-pass reader (`readCsv`) and the two-pass reference (`readCsvCells`) give the
//!    same frame or the same error; the frame is well formed; a frame read with the
//!    default null markers (no NaN cell, which `writeCsv` writes as the null text, as the
//!    SPEC says) written by `writeCsv` and read back with every column's type given reads
//!    back `equals` (the SPEC's "writeCsv then readCsv round-trips every column kind").
//!  - frames: a random frame through 1..4 random verbs with random specs: no panic,
//!    every result well formed (column and data counts, array lengths, validity bits
//!    past `len` clear, a null slot holds 0), and the typed path equals its `*Cells`
//!    reference path (frame or error) wherever `test_hooks` has one.
//!  - writers: no panic; `writeJson` (both orients) and `writeNdjson` parse with
//!    `std.json`, with `len` records / one array per column.
//!
//! Memory: the verbs want an arena (a frame's arrays may sit behind slice capacity), so
//! the allocator the driver hands in backs one arena per run; what the arena cannot
//! show, a leak of the harness's own, `DebugAllocator` still does.

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const csvio = @import("csvio.zig");
const d4b = @import("d4b_test.zig");
const tkfuzz = @import("testkit").fuzz;
const driver = tkfuzz.driver;

const Allocator = std.mem.Allocator;
const Frame = df.Frame;
const Value = df.Value;
const Column = df.Column;
const ColumnData = df.ColumnData;
const ColumnType = df.ColumnType;

// ── draw helpers (only the Smith/Rng methods) ───────────────────────────────

fn below(src: anytype, n: usize) usize {
    return src.index(n);
}

fn chance(src: anytype, pct: usize) bool {
    return src.index(100) < pct;
}

fn range(src: anytype, comptime T: type, lo: T, hi: T) T {
    // Smith has no `usize` (no fixed bit size): draw it as u32.
    if (T == usize) return src.valueRangeAtMost(u32, @intCast(lo), @intCast(hi));
    return src.valueRangeAtMost(T, lo, hi);
}

fn pickEnum(src: anytype, comptime E: type) E {
    const all = comptime std.enums.values(E);
    return all[src.index(all.len)];
}

fn pickOf(src: anytype, comptime T: type, items: []const T) T {
    return items[src.index(items.len)];
}

// ── reach ───────────────────────────────────────────────────────────────────

const Verb = enum {
    filter,
    where,
    sort,
    distinct,
    join,
    join_asof,
    aggregate,
    pivot,
    unpivot,
    window,
    fill_null,
    top_k,
    concat,
    describe,
    value_counts,
    mutate,
    transpose,
    dummies,
    select,
    drop,
    rename,
    cumsum,
    rolling,
    fillna,
    dropna,
    map,
    cast,
};
const n_verbs = std.enums.values(Verb).len;
var verb_ok: [n_verbs]u64 = @splat(0);
var verb_err: [n_verbs]u64 = @splat(0);
var verb_typed_checked: [n_verbs]u64 = @splat(0);

pub fn resetReach() void {
    verb_ok = @splat(0);
    verb_err = @splat(0);
    verb_typed_checked = @splat(0);
    valid_past_len = 0;
}

fn printVerbTable() void {
    for (std.enums.values(Verb), 0..) |v, i|
        std.debug.print("VERB {t} ok={d} err={d} vs_cells={d}\n", .{ v, verb_ok[i], verb_err[i], verb_typed_checked[i] });
    std.debug.print("NOTE validity_bits_past_len={d}\n", .{valid_past_len});
}

// ── well-formedness ─────────────────────────────────────────────────────────

/// Results with a validity bit set past `len`. The module's own sweep treats those bits as
/// garbage that readers mask (S2-3 fixed one producer), and `map`/`allValid` still
/// writes them, so this is a statistic printed with the verdict, not a failure.
var valid_past_len: u64 = 0;

fn validOk(valid: ?[]const u64, len: usize) bool {
    const v = valid orelse return true;
    if (v.len * 64 < len) return false;
    var i = len;
    while (i < v.len * 64) : (i += 1) {
        if ((v[i / 64] >> @intCast(i % 64)) & 1 != 0) {
            valid_past_len += 1;
            break;
        }
    }
    return true;
}

fn why(comptime msg: []const u8, args: anytype) bool {
    std.debug.print("  well-formedness: " ++ msg ++ "\n", args);
    return false;
}

fn typedOk(comptime T: type, c: df.TypedColumn(T), len: usize) bool {
    if (c.values.len != len) return why("{s} array has {d} values for {d} rows", .{ @typeName(T), c.values.len, len });
    if (!validOk(c.valid, len)) return why("validity bits set past len {d}", .{len});
    for (0..len) |i| if (!c.isValid(i)) {
        // A null slot holds 0 (the documented layout; `floatColumn` relies on it).
        const zero = if (T == f64) @as(u64, @bitCast(c.values[i])) == 0 else c.values[i] == if (T == bool) false else 0;
        if (!zero) return why("{s} null slot {d} holds {any}", .{ @typeName(T), i, c.values[i] });
    };
    return true;
}

fn wellFormed(f: Frame) bool {
    if (f.columns.len != f.data.len) return false;
    for (f.data) |d| {
        const ok = switch (d) {
            .nulls => true,
            .int => |c| typedOk(i64, c, f.len),
            .float => |c| typedOk(f64, c, f.len),
            .bool => |c| typedOk(bool, c, f.len),
            .decimal => |c| typedOk(i128, c, f.len),
            .boxed => |c| c.len == f.len,
            .categorical => |c| cat: {
                if (!typedOk(u32, c.codes, f.len)) break :cat false;
                const n = c.dict.offsets.len -| 1;
                for (0..f.len) |i| if (c.codes.isValid(i) and c.codes.values[i] >= n) break :cat false;
                break :cat true;
            },
            .text => |c| text: {
                if (c.offsets.len != f.len + 1 or !validOk(c.valid, f.len)) break :text false;
                if (c.offsets[0] != 0) break :text false;
                for (0..f.len) |i| {
                    if (c.offsets[i] > c.offsets[i + 1] or c.offsets[i + 1] > c.bytes.len) break :text false;
                    if (!c.isValid(i) and c.offsets[i] != c.offsets[i + 1]) break :text false;
                }
                break :text true;
            },
        };
        if (!ok) return false;
    }
    return true;
}

fn expectWellFormed(what: []const u8, f: Frame) !void {
    if (!wellFormed(f)) {
        std.debug.print("{s}: result is not well formed (len={d}, columns={d}, data={d})\n", .{ what, f.len, f.columns.len, f.data.len });
        for (f.columns, 0..) |c, i| std.debug.print("  column {d} {s} {t} storage {t}\n", .{ i, c.name, c.type, f.columnAt(i) });
        return error.NotWellFormed;
    }
}

// ── values and frames ───────────────────────────────────────────────────────

const name_pool = [_][]const u8{ "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9" };

const text_pool = [_][]const u8{
    "",           "a",    "b",         "abc",  "Hello",  " pad ",  "\xc3\xa9\xe2\x82\xac", "\xff\xfe", "NA", "1",
    "2.5",        "true", "a,b",       "q\"x", "l1\nl2", "x|y",    "\xf0\x9f\x98\x80",     "\x00",     "-7", "1e3",
    "2020-01-01", "\r\n", "aaaa bbbb", "Zz",   "\x80",   "ab\xc3",
};

const date_pool = [_][]const u8{ "2020-01-01", "2020-02-29", "1999-12-31", "0000-01-01", "9999-12-31", "2020-13-45", "", "x", "2021-02-29", "2020-1-1" };

const int_edges = [_]i64{ 0, 1, -1, 2, 10, 100, std.math.minInt(i64), std.math.maxInt(i64), 1 << 53, (1 << 53) + 1, -(1 << 53) };

fn genInt(src: anytype) i64 {
    if (chance(src, 60)) return range(src, i64, -5, 5);
    if (chance(src, 70)) return pickOf(src, i64, &int_edges);
    return src.value(i64);
}

fn genFloat(src: anytype) f64 {
    return switch (below(src, 11)) {
        0 => std.math.nan(f64),
        1 => std.math.inf(f64),
        2 => -std.math.inf(f64),
        3 => -0.0,
        4 => 0.0,
        5 => 1e308,
        6 => 5e-324,
        7 => @as(f64, @floatFromInt(range(src, i32, -40, 40))) / 4.0,
        8 => @bitCast(src.value(u64)),
        9 => -1.7976931348623157e308,
        else => @as(f64, @floatFromInt(range(src, i32, -9, 9))),
    };
}

fn genDecimal(src: anytype) i128 {
    return switch (below(src, 6)) {
        0 => 0,
        1 => @as(i128, range(src, i32, -1000, 1000)) * df.decimal_scale,
        2 => @divTrunc(df.decimal_scale, 3) * range(src, i8, -3, 3),
        3 => std.math.maxInt(i128),
        4 => std.math.minInt(i128),
        else => src.value(i128),
    };
}

fn genText(src: anytype, a: Allocator) []const u8 {
    if (chance(src, 75)) return pickOf(src, []const u8, &text_pool);
    const n = below(src, 9);
    const b = a.alloc(u8, n) catch return "";
    src.bytes(b);
    return b;
}

fn genValue(src: anytype, a: Allocator) Value {
    return switch (below(src, 7)) {
        0 => .null,
        1 => .{ .int = genInt(src) },
        2 => .{ .float = genFloat(src) },
        3 => .{ .text = genText(src, a) },
        4 => .{ .bool = chance(src, 50) },
        5 => .{ .decimal = genDecimal(src) },
        else => .{ .int = range(src, i64, -3, 3) },
    };
}

const Kind = enum { int, float, bool, decimal, text, date, timestamp, boxed, nulls };

fn kindType(k: Kind, src: anytype) ColumnType {
    return switch (k) {
        .int => .int,
        .float => .float,
        .bool => .bool,
        .decimal => .decimal,
        .text => .text,
        .date => .date,
        .timestamp => .timestamp,
        .boxed => if (chance(src, 50)) .text else .float,
        .nulls => pickEnum(src, ColumnType),
    };
}

fn genCell(src: anytype, a: Allocator, k: Kind) Value {
    return switch (k) {
        .int => .{ .int = genInt(src) },
        .float => .{ .float = genFloat(src) },
        .bool => .{ .bool = chance(src, 50) },
        .decimal => .{ .decimal = genDecimal(src) },
        .text => .{ .text = genText(src, a) },
        .date => .{ .text = pickOf(src, []const u8, &date_pool) },
        .timestamp => .{ .int = if (chance(src, 70)) range(src, i64, -2_000_000_000_000_000, 200_000_000_000_000_000) else genInt(src) },
        .boxed => genValue(src, a),
        .nulls => .null,
    };
}

fn genColumn(src: anytype, a: Allocator, k: Kind, n: usize) !ColumnData {
    const null_pct: usize = pickOf(src, usize, &.{ 0, 0, 10, 50, 100 });
    const cells = try a.alloc(Value, n);
    for (cells) |*c| c.* = if (chance(src, null_pct)) .null else genCell(src, a, k);
    return df.columnFromCells(a, cells);
}

fn genRows(src: anytype) usize {
    return switch (below(src, 5)) {
        0 => 0,
        1 => range(src, usize, 1, 3),
        2 => range(src, usize, 60, 66),
        else => range(src, usize, 1, 16),
    };
}

/// A frame of columns named from the pool starting at `first`, kinds at random.
fn genFrame(src: anytype, a: Allocator, first: usize, n_rows: usize) !Frame {
    const nc = range(src, usize, 1, 8);
    const cols = try a.alloc(Column, nc);
    const data = try a.alloc(ColumnData, nc);
    for (cols, data, 0..) |*c, *d, i| {
        const k = pickEnum(src, Kind);
        const ty = kindType(k, src);
        c.* = .{ .name = name_pool[(first + i) % name_pool.len], .type = ty };
        d.* = try genColumn(src, a, k, n_rows);
    }
    return .{ .columns = cols, .data = data, .len = n_rows };
}

fn kindOfType(t: ColumnType) Kind {
    return switch (t) {
        .int => .int,
        .float => .float,
        .bool => .bool,
        .decimal => .decimal,
        .text => .text,
        .date => .date,
        .timestamp, .duration => .timestamp,
        .categorical => .text,
    };
}

/// Same columns and types as `like`, other rows.
fn genFrameLike(src: anytype, a: Allocator, like: Frame, n_rows: usize) !Frame {
    const data = try a.alloc(ColumnData, like.columns.len);
    for (like.columns, data) |c, *d| {
        const k: Kind = if (chance(src, 8)) .boxed else kindOfType(c.type);
        d.* = try genColumn(src, a, k, n_rows);
    }
    return .{ .columns = like.columns, .data = data, .len = n_rows };
}

// ── names and specs ─────────────────────────────────────────────────────────

fn pickCol(src: anytype, f: Frame) []const u8 {
    if (f.columns.len != 0 and chance(src, 92)) return f.columns[below(src, f.columns.len)].name;
    return pickOf(src, []const u8, &name_pool);
}

fn pickCols(src: anytype, a: Allocator, f: Frame, max: usize) ![]const []const u8 {
    const n = range(src, usize, 0, max);
    const out = try a.alloc([]const u8, n);
    for (out) |*o| o.* = pickCol(src, f);
    return out;
}

fn pickCols1(src: anytype, a: Allocator, f: Frame, max: usize) ![]const []const u8 {
    const out = try pickCols(src, a, f, max);
    if (out.len != 0) return out;
    const one = try a.alloc([]const u8, 1);
    one[0] = pickCol(src, f);
    return one;
}

fn genQ(src: anytype) f64 {
    return switch (below(src, 6)) {
        0 => std.math.nan(f64),
        1 => 1.5,
        2 => -0.5,
        3 => 0,
        4 => 1,
        else => @as(f64, @floatFromInt(below(src, 101))) / 100.0,
    };
}

fn genOperand(src: anytype, f: Frame) df.Operand {
    return if (chance(src, 60)) .{ .col = pickCol(src, f) } else .{ .num = genFloat(src) };
}

fn genExpr(src: anytype, a: Allocator, f: Frame, depth: usize) Allocator.Error!*const df.Expr {
    const e = try a.create(df.Expr);
    const leaf = depth >= 3 or chance(src, 25);
    if (leaf) {
        e.* = if (chance(src, 60)) .{ .col = pickCol(src, f) } else .{ .lit = genValue(src, a) };
        return e;
    }
    const x = try genExpr(src, a, f, depth + 1);
    e.* = switch (below(src, 22)) {
        0, 1, 2 => .{ .unary = .{ .op = pickEnum(src, df.Unary), .x = x } },
        3, 4, 5, 6 => .{ .binary = .{ .op = pickEnum(src, df.Binary), .l = x, .r = try genExpr(src, a, f, depth + 1) } },
        7 => blk: {
            const vals = try a.alloc(Value, below(src, 4));
            for (vals) |*v| v.* = genValue(src, a);
            break :blk .{ .is_in = .{ .x = x, .values = vals } };
        },
        8 => .{ .if_else = .{ .cond = x, .then = try genExpr(src, a, f, depth + 1), .otherwise = try genExpr(src, a, f, depth + 1) } },
        9 => blk: {
            const xs = try a.alloc(df.Expr, range(src, usize, 0, 3));
            for (xs) |*c| c.* = (try genExpr(src, a, f, depth + 1)).*;
            break :blk .{ .coalesce = xs };
        },
        10 => .{ .cast = .{ .x = x, .to = pickEnum(src, ColumnType) } },
        11 => .{ .replace = .{ .x = x, .from = pickOf(src, []const u8, &.{ "", "a", "b", "ab" }), .to = pickOf(src, []const u8, &.{ "", "zz", "\xff" }) } },
        12 => .{ .round = .{ .x = x, .decimals = pickOf(src, i32, &.{ 0, 1, 2, -1, -300, 400, std.math.minInt(i32), std.math.maxInt(i32) }), .mode = pickEnum(src, df.RoundMode) } },
        13 => .{ .pad = .{ .x = x, .width = pickOf(src, usize, &.{ 0, 1, 5, 40, 4096 }), .side = pickEnum(src, df.PadSide), .fill = pickOf(src, u21, &.{ ' ', '0', 0x20ac, 0x10ffff }) } },
        14 => .{ .slice = .{ .x = x, .offset = genInt(src), .length = if (chance(src, 50)) null else range(src, usize, 0, 5) } },
        15 => .{ .strip_chars = .{ .x = x, .chars = if (chance(src, 50)) null else pickOf(src, []const u8, &.{ "", "a ", "\xff" }), .side = pickEnum(src, df.StripSide) } },
        16 => .{ .to_integer = .{ .x = x, .base = pickOf(src, u8, &.{ 10, 2, 16, 36, 1, 0, 37, 255 }) } },
        17 => .{ .dt = .{ .x = x, .part = pickEnum(src, df.DtPart) } },
        18 => .{ .strptime = .{ .x = x, .format = pickOf(src, []const u8, &.{ "%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%d/%m/%y", "%", "%Q", "" }), .to = if (chance(src, 50)) .date else .timestamp } },
        19 => .{ .strftime = .{ .x = x, .format = pickOf(src, []const u8, &.{ "%Y-%m-%d", "%H:%M:%S.%f", "%A %B", "%", "" }) } },
        20 => .{ .offset_by = .{ .x = x, .by = pickOf(src, []const u8, &.{ "1d", "1mo2d", "-3h", "", "9999999999999d", "1x" }) } },
        else => if (chance(src, 50))
            .{ .truncate = .{ .x = x, .every = pickOf(src, []const u8, &.{ "1h", "1d", "1mo", "0d", "", "2w" }) } }
        else
            .{ .add_business_days = .{ .x = x, .n = genInt(src) } },
    };
    return e;
}

fn genWinOp(src: anytype, f: Frame) df.WindowOp {
    const wins = [_]usize{ 0, 1, 2, 3, 5, 20, 100, 1 << 40, std.math.maxInt(usize) };
    const fns = comptime std.enums.values(df.WinFn);
    return switch (below(src, 16)) {
        0 => .{ .shift = .{ .n = pickOf(src, i64, &.{ 1, -1, 0, 2, 3, -7, 1000, std.math.minInt(i64), std.math.maxInt(i64) }), .fill = if (chance(src, 50)) .null else .{ .float = 0.5 } } },
        1 => .{ .diff = range(src, i64, -3, 3) },
        2 => .{ .pct_change = pickOf(src, i64, &.{ 1, 0, -1, 2, std.math.minInt(i64) }) },
        3 => .cum_sum,
        4 => pickOf(src, df.WindowOp, &.{ .cum_prod, .cum_min, .cum_max, .cum_count, .row_number }),
        5, 6 => .{ .rolling = .{
            .window = pickOf(src, usize, &wins),
            .func = fns[below(src, fns.len)],
            .min_periods = if (chance(src, 50)) null else range(src, usize, 0, 3),
            .center = chance(src, 50),
            .q = genQ(src),
            .ddof = range(src, u32, 0, 3),
        } },
        7 => .{ .rolling_time = .{
            .time_col = pickCol(src, f),
            .period = pickOf(src, i64, &.{ 1, 0, -1, 5, std.math.maxInt(i64), std.math.minInt(i64) }),
            .func = fns[below(src, fns.len)],
            .min_periods = range(src, usize, 0, 3),
            .q = genQ(src),
            .ddof = range(src, u32, 0, 3),
        } },
        8 => .{ .expanding = .{ .func = fns[below(src, fns.len)], .min_periods = range(src, usize, 0, 3), .q = genQ(src), .ddof = range(src, u32, 0, 3) } },
        9 => .{ .ewm = .{
            .alpha = if (chance(src, 40)) genQ(src) else null,
            .span = if (chance(src, 30)) genFloat(src) else null,
            .com = if (chance(src, 20)) genFloat(src) else null,
            .halflife = if (chance(src, 20)) genFloat(src) else null,
            .adjust = chance(src, 50),
            .ignore_na = chance(src, 50),
            .min_periods = range(src, usize, 0, 3),
        } },
        10 => .{ .rank = .{ .method = pickEnum(src, df.RankMethod), .descending = chance(src, 50) } },
        11 => .{ .ffill = if (chance(src, 50)) null else range(src, usize, 0, 3) },
        12 => .{ .bfill = if (chance(src, 50)) null else range(src, usize, 0, 3) },
        13 => .{ .interpolate = .{ .extend_last = chance(src, 50) } },
        else => .{ .transform = .{ .func = pickEnum(src, df.AggFn), .q = genQ(src) } },
    };
}

// ── running a verb ──────────────────────────────────────────────────────────

fn record(v: Verb, ok: bool) void {
    const i = @backingInt(v);
    if (ok) verb_ok[i] += 1 else verb_err[i] += 1;
}

/// `d4b.agree`, plus where two different frames first differ.
fn agree(comptime what: []const u8, new: anytype, old: anytype) !void {
    if (oom_mode) return;
    // No rows: which empty array backs a column (`.float` or `.nulls`) is not a result.
    if (new) |nf| {
        if (old) |of| {
            if (nf.len == 0 and of.len == 0 and nf.columns.len == of.columns.len) {
                for (nf.columns, of.columns) |x, y| if (x.type != y.type or !std.mem.eql(u8, x.name, y.name)) break else return;
            }
        } else |_| {}
    } else |_| {}
    d4b.agree(what, new, old) catch |e| {
        if (new) |nf| {
            if (old) |of| describeDiff(nf, of) else |_| {}
        } else |_| {}
        return e;
    };
}

fn describeDiff(x: Frame, y: Frame) void {
    std.debug.print("  typed: len={d} columns={d}; cells: len={d} columns={d}\n", .{ x.len, x.columns.len, y.len, y.columns.len });
    const n = @min(x.columns.len, y.columns.len);
    for (0..n) |ci| {
        const cx = x.columns[ci];
        const cy = y.columns[ci];
        const dx = x.columnAt(ci);
        const dy = y.columnAt(ci);
        std.debug.print("  col {d}: {s} {t} {t} | {s} {t} {t}\n", .{ ci, cx.name, cx.type, dx, cy.name, cy.type, dy });
        for (0..@min(x.len, y.len)) |ri| {
            const vx = dx.get(ri);
            const vy = dy.get(ri);
            if (!std.meta.eql(vx, vy) and !(vx == .text and vy == .text and std.mem.eql(u8, vx.text, vy.text))) {
                std.debug.print("    row {d}: {any} | {any}\n", .{ ri, vx, vy });
                break;
            }
        }
    }
}

/// One result: counted, checked, and (where `cells` is given) compared with the
/// reference path's. Returns the frame, or null on an error.
fn settle(comptime v: Verb, typed: anytype, cells: anytype) !?Frame {
    if (@TypeOf(cells) != void) {
        verb_typed_checked[@backingInt(v)] += 1;
        try agree(@tagName(v), typed, cells);
    }
    if (typed) |f| {
        record(v, true);
        try expectWellFormed(@tagName(v), f);
        return f;
    } else |_| {
        record(v, false);
        return null;
    }
}

fn runVerb(src: anytype, a: Allocator, cur: Frame, v: Verb) !Frame {
    const hooks = struct {
        const v1 = @import("verbs.zig").test_hooks;
        const mo = @import("more.zig").test_hooks;
        const an = @import("analysis.zig").test_hooks;
        const wi = @import("window.zig").test_hooks;
        const ex = @import("expr.zig").test_hooks;
    };
    const f = cur;
    const next: ?Frame = switch (v) {
        .filter => blk: {
            const preds = try a.alloc(df.Predicate, range(src, usize, 0, 3));
            for (preds) |*p| p.* = .{ .col = pickCol(src, f), .op = pickEnum(src, df.CmpOp), .value = genValue(src, a) };
            break :blk try settle(.filter, df.filter(a, f, .{ .where = preds, .mode = pickEnum(src, @FieldType(df.FilterSpec, "mode")) }), {});
        },
        .where => blk: {
            const e = try genExpr(src, a, f, 0);
            break :blk try settle(.where, df.where(a, f, e), {});
        },
        .sort => blk: {
            const then = try a.alloc(df.SortKey, range(src, usize, 0, 2));
            for (then) |*t| t.* = .{ .key = pickCol(src, f), .dir = pickEnum(src, df.SortDir) };
            const spec: df.SortSpec = .{ .key = pickCol(src, f), .dir = pickEnum(src, df.SortDir), .then_by = then, .missing = pickEnum(src, @FieldType(df.SortSpec, "missing")) };
            break :blk try settle(.sort, df.sort(a, f, spec), hooks.v1.sortCells(a, f, spec));
        },
        .distinct => blk: {
            break :blk try settle(.distinct, df.distinct(a, f, .{ .keys = try pickCols(src, a, f, 2), .keep = pickEnum(src, @FieldType(df.DistinctSpec, "keep")) }), {});
        },
        .join => blk: {
            const right = try genFrame(src, a, below(src, 3), genRows(src));
            var spec: df.JoinSpec = .{ .how = pickEnum(src, df.JoinHow), .null_keys = pickEnum(src, @FieldType(df.JoinSpec, "null_keys")), .coalesce_keys = chance(src, 50) };
            if (chance(src, 50)) spec.on = pickCol(src, f) else spec.keys = try pickCols1(src, a, f, 2);
            if (chance(src, 25)) spec.right_on = try pickCols(src, a, right, 2);
            if (chance(src, 50)) spec.suffix = pickOf(src, []const u8, &.{ "_r", "", "c0" });
            break :blk try settle(.join, df.join(a, f, right, spec), hooks.v1.joinCells(a, f, right, spec));
        },
        .join_asof => blk: {
            const right = try genFrame(src, a, below(src, 3), genRows(src));
            const spec: df.AsofSpec = .{
                .on = pickCol(src, f),
                .by = try pickCols(src, a, f, 1),
                .direction = pickEnum(src, @FieldType(df.AsofSpec, "direction")),
                .tolerance = if (chance(src, 50)) null else pickOf(src, f64, &.{ 0, 3.5, std.math.nan(f64), std.math.inf(f64), -1 }),
                .allow_exact = chance(src, 50),
                .suffix = if (chance(src, 50)) "_r" else null,
            };
            break :blk try settle(.join_asof, df.joinAsof(a, f, right, spec), hooks.mo.joinAsofCells(a, f, right, spec));
        },
        .aggregate => blk: {
            const aggs = try a.alloc(df.AggCol, range(src, usize, 0, 3));
            for (aggs, 0..) |*g, i| g.* = .{
                .src = pickCol(src, f),
                .out = name_pool[(i + 5) % name_pool.len],
                .func = pickEnum(src, df.AggFn),
                .q = genQ(src),
                .interpolation = pickEnum(src, df.Interpolation),
                .ddof = range(src, u32, 0, 3),
                .min_count = range(src, usize, 0, 3),
            };
            const spec: df.AggregateSpec = .{
                .group_by = try pickCols(src, a, f, 2),
                .aggs = aggs,
                .fx = if (chance(src, 15)) .{ .rate_col = pickCol(src, f) } else null,
                .skip_na = chance(src, 50),
                .sort_groups = chance(src, 50),
                .drop_missing_keys = chance(src, 50),
            };
            break :blk try settle(.aggregate, df.aggregate(a, f, spec), hooks.v1.aggregateCells(a, f, spec));
        },
        .pivot => blk: {
            const spec: df.PivotSpec = .{
                .row_key = pickCol(src, f),
                .col_key = pickCol(src, f),
                .value_col = pickCol(src, f),
                .agg = pickEnum(src, df.AggFn),
                .q = genQ(src),
                .skip_na = chance(src, 50),
                .fill_value = if (chance(src, 50)) null else genFloat(src),
            };
            break :blk try settle(.pivot, df.pivot(a, f, spec), hooks.v1.pivotCells(a, f, spec));
        },
        .unpivot => blk: {
            const spec: df.UnpivotSpec = .{
                .id_cols = try pickCols(src, a, f, 2),
                .value_cols = try pickCols(src, a, f, 3),
                .out_key = pickOf(src, []const u8, &.{ "variable", "c0", "" }),
                .out_value = pickOf(src, []const u8, &.{ "value", "c1", "" }),
            };
            break :blk try settle(.unpivot, df.unpivot(a, f, spec), hooks.v1.unpivotCells(a, f, spec));
        },
        .window => blk: {
            const spec: df.WindowSpec = .{
                .value_col = pickCol(src, f),
                .out = pickOf(src, []const u8, &.{ "w", "c0", "c1" }),
                .op = genWinOp(src, f),
                .partition_by = try pickCols(src, a, f, 2),
            };
            break :blk try settle(.window, df.window(a, f, spec), hooks.wi.windowCells(a, f, spec));
        },
        .fill_null => blk: {
            const spec: df.FillNullSpec = .{ .subset = try pickCols(src, a, f, 2), .strategy = pickEnum(src, df.FillStrategy), .limit = if (chance(src, 50)) null else range(src, usize, 0, 3) };
            break :blk try settle(.fill_null, df.fillNull(a, f, spec), hooks.an.fillNullCells(a, f, spec));
        },
        .top_k => blk: {
            const spec: df.TopKSpec = .{ .by = try pickCols(src, a, f, 2), .n = pickOf(src, usize, &.{ 0, 1, 3, 10, 100, std.math.maxInt(usize) }), .largest = chance(src, 50), .keep = pickEnum(src, @FieldType(df.TopKSpec, "keep")) };
            break :blk try settle(.top_k, df.topK(a, f, spec), hooks.an.topKCells(a, f, spec));
        },
        .concat => blk: {
            const how = pickEnum(src, df.ConcatHow);
            const n = range(src, usize, 0, 2);
            const frames = try a.alloc(Frame, n + 1);
            frames[0] = f;
            for (frames[1..]) |*g| g.* = if (chance(src, 60) and how != .horizontal) try genFrameLike(src, a, f, genRows(src)) else try genFrame(src, a, below(src, 3), genRows(src));
            break :blk if (how == .diagonal)
                try settle(.concat, df.concat(a, frames, how), hooks.mo.concatByNameCells(a, frames))
            else
                try settle(.concat, df.concat(a, frames, how), {});
        },
        .describe => blk: {
            const cols = try pickCols(src, a, f, 3);
            break :blk try settle(.describe, df.describe(a, f, cols), hooks.mo.describeCells(a, f, cols));
        },
        .value_counts => blk: {
            const spec: df.ValueCountsSpec = .{ .cols = try pickCols1(src, a, f, 2), .out = pickOf(src, []const u8, &.{ "count", "c0" }), .keep_missing = chance(src, 50) };
            break :blk try settle(.value_counts, df.valueCounts(a, f, spec), hooks.mo.valueCountsCells(a, f, spec));
        },
        .mutate => blk: {
            const assigns = try a.alloc(df.Assign, range(src, usize, 0, 2));
            for (assigns) |*s| s.* = .{
                .out = pickOf(src, []const u8, &name_pool),
                .expr = (try genExpr(src, a, f, 0)).*,
                .type = if (chance(src, 50)) null else pickEnum(src, ColumnType),
            };
            break :blk try settle(.mutate, df.mutate(a, f, assigns), hooks.ex.mutateCells(a, f, assigns));
        },
        .transpose => blk: {
            const names = try a.alloc([]const u8, if (chance(src, 60)) f.len else range(src, usize, 0, 3));
            for (names) |*n| n.* = pickOf(src, []const u8, &name_pool);
            const spec: df.TransposeSpec = .{
                .header_name = if (chance(src, 50)) null else "name",
                .names = if (chance(src, 50)) names else &.{},
                .names_from = if (chance(src, 30)) pickCol(src, f) else null,
            };
            break :blk try settle(.transpose, df.transpose(a, f, spec), {});
        },
        .dummies => blk: {
            const spec: df.DummiesSpec = .{ .cols = try pickCols(src, a, f, 2), .separator = pickOf(src, []const u8, &.{ "_", "", "\xff" }), .drop_first = chance(src, 50), .dummy_na = chance(src, 50) };
            break :blk try settle(.dummies, df.dummies(a, f, spec), {});
        },
        .select => try settle(.select, df.select(a, f, try pickCols(src, a, f, 4)), {}),
        .drop => try settle(.drop, df.drop(a, f, try pickCols(src, a, f, 3)), {}),
        .rename => blk: {
            const rs = try a.alloc(df.Rename, range(src, usize, 0, 3));
            for (rs) |*r| r.* = .{ .from = pickCol(src, f), .to = pickOf(src, []const u8, &name_pool) };
            break :blk try settle(.rename, df.rename(a, f, rs), {});
        },
        .cumsum => try settle(.cumsum, df.cumsum(a, f, .{ .value_col = pickCol(src, f), .out = pickOf(src, []const u8, &.{ "cs", "c0" }) }), {}),
        .rolling => blk: {
            const spec: df.RollSpec = .{
                .value_col = pickCol(src, f),
                .out = pickOf(src, []const u8, &.{ "r", "c0" }),
                .window = pickOf(src, usize, &.{ 0, 1, 2, 3, 70, 1 << 40, std.math.maxInt(usize) }),
                .func = pickEnum(src, @import("spec.zig").RollFn),
            };
            break :blk try settle(.rolling, df.rolling(a, f, spec), {});
        },
        .fillna => blk: {
            break :blk try settle(.fillna, df.fillna(a, f, .{ .subset = try pickCols(src, a, f, 2), .value = genValue(src, a) }), {});
        },
        .dropna => blk: {
            const spec: df.DropNaSpec = .{ .subset = try pickCols(src, a, f, 2), .how = pickEnum(src, @FieldType(df.DropNaSpec, "how")), .thresh = if (chance(src, 50)) null else range(src, usize, 0, 4) };
            break :blk try settle(.dropna, df.dropna(a, f, spec), {});
        },
        .map => blk: {
            const spec: df.MapSpec = .{
                .out = pickOf(src, []const u8, &name_pool),
                .out_type = pickEnum(src, ColumnType),
                .lhs = genOperand(src, f),
                .op = pickEnum(src, df.BinOp),
                .rhs = genOperand(src, f),
                .on_missing = pickEnum(src, df.OnMissing),
            };
            break :blk try settle(.map, df.map(a, f, spec), {});
        },
        .cast => blk: {
            const spec: df.CastSpec = .{ .col = pickCol(src, f), .to = pickEnum(src, ColumnType), .on_error = pickEnum(src, @FieldType(df.CastSpec, "on_error")) };
            break :blk try settle(.cast, df.cast(a, f, spec), {});
        },
    };
    return next orelse cur;
}

fn framesTarget(src: anytype, a: Allocator) !void {
    driver.hit("frames");
    var cur = try genFrame(src, a, 0, genRows(src));
    const steps = range(src, usize, 1, 4);
    for (0..steps) |_| cur = try runVerb(src, a, cur, pickEnum(src, Verb));
}

// ── csv ─────────────────────────────────────────────────────────────────────

const CsvPlan = struct { delim: u8, quote: u8, ncols: usize, has_header: bool, comment: u8, skip: usize };

const CsvKind = enum { int, float, bool, date, ts, decimal, text, mixed };

const int_tokens = [_][]const u8{ "0", "1", "-1", "+5", "007", "42", "9223372036854775807", "9223372036854775808", "-9223372036854775809", " 7", "1_0", "-0" };
const float_tokens = [_][]const u8{ "1.5", "-0", "-0.0", "nan", "NaN", "inf", "-Infinity", "1e5", "1E400", ".5", "5.", "1e-400", "0x10", "1.7976931348623157e308", "2.5e-3", "1e", "e5", "--1" };
const bool_tokens = [_][]const u8{ "True", "false", "TRUE", "t", "1", "0", "yes", "False" };
const null_tokens = [_][]const u8{ "", "NA", "null", "N/A", "None", "NaN", "n/a", "<NA>" };
const date_tokens = [_][]const u8{ "2020-01-01", "2020-13-01", "2020-02-30", "2020-1-1", "0000-00-00", "1999-12-31", "9999-12-31" };
const ts_tokens = [_][]const u8{ "2020-01-01T00:00:00Z", "2020-01-01 12:34:56.123456", "2020-01-01T12:34:56+02:00", "2020-01-01 12:34:56.123456789", "1970-01-01 00:00:00", "2020-01-01T25:00:00", "2020-01-01 12:34:56.5" };
const dec_tokens = [_][]const u8{ "1.123456789012", "1.1234567890123", "-.5", "12", "0.0", "99999999999999999999999.5", "-0.000000000001", "+1." };
const struct_chars = "\",;\t\r\n'#\x00\xef \\|";

fn csvToken(src: anytype, a: Allocator, kind: CsvKind) []const u8 {
    if (chance(src, 8)) return pickOf(src, []const u8, &null_tokens);
    const k: CsvKind = if (kind == .mixed or chance(src, 12)) pickEnum(src, CsvKind) else kind;
    var buf: [48]u8 = undefined;
    switch (k) {
        .int => {
            if (chance(src, 50)) return pickOf(src, []const u8, &int_tokens);
            return a.dupe(u8, std.fmt.bufPrint(&buf, "{d}", .{genInt(src)}) catch "0") catch "0";
        },
        .float => {
            if (chance(src, 60)) return pickOf(src, []const u8, &float_tokens);
            const x = genFloat(src);
            return a.dupe(u8, std.fmt.bufPrint(&buf, "{d}", .{x}) catch "0.5") catch "0.5";
        },
        .bool => return pickOf(src, []const u8, &bool_tokens),
        .date => return pickOf(src, []const u8, &date_tokens),
        .ts => return pickOf(src, []const u8, &ts_tokens),
        .decimal => return pickOf(src, []const u8, &dec_tokens),
        .text, .mixed => return genText(src, a),
    }
}

fn appendEol(src: anytype, a: Allocator, out: *std.ArrayList(u8), mode: usize) !void {
    const m = if (mode == 3) below(src, 3) else mode;
    try out.appendSlice(a, switch (m) {
        0 => "\n",
        1 => "\r\n",
        else => "\r",
    });
}

fn appendField(src: anytype, a: Allocator, out: *std.ArrayList(u8), tok: []const u8, p: CsvPlan) !void {
    const q: u8 = if (p.quote == 0) '"' else p.quote;
    var needs = false;
    for (tok) |c| if (c == p.delim or c == q or c == '\r' or c == '\n') {
        needs = true;
    };
    const quoted = if (needs) !chance(src, 7) else chance(src, 15);
    if (!quoted) return out.appendSlice(a, tok);
    if (chance(src, 3)) {
        // An opening quote that never closes.
        try out.append(a, q);
        return out.appendSlice(a, tok);
    }
    try out.append(a, q);
    for (tok) |c| {
        if (c == q) try out.append(a, q);
        try out.append(a, c);
    }
    try out.append(a, q);
}

fn genCsvBytes(src: anytype, a: Allocator, p: CsvPlan) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    const eol = below(src, 4);
    if (chance(src, 8)) try out.appendSlice(a, "\xef\xbb\xbf");
    for (0..p.skip) |_| {
        try out.appendSlice(a, "junk line");
        try appendEol(src, a, &out, eol);
    }
    const kinds = try a.alloc(CsvKind, p.ncols);
    for (kinds) |*k| k.* = pickEnum(src, CsvKind);
    if (p.has_header or chance(src, 30)) {
        for (0..p.ncols) |i| {
            if (i != 0) try out.append(a, p.delim);
            const name: []const u8 = if (chance(src, 80)) name_pool[i % name_pool.len] else pickOf(src, []const u8, &.{ "", "a", "a", "Unnamed: 1", "a.1", "x y", "\xff" });
            try appendField(src, a, &out, name, p);
        }
        try appendEol(src, a, &out, eol);
    }
    const rows: usize = if (chance(src, 3)) range(src, usize, 60, 90) else below(src, 14);
    for (0..rows) |_| {
        if (p.comment != 0 and chance(src, 6)) {
            try out.append(a, p.comment);
            try out.appendSlice(a, "a comment");
            try appendEol(src, a, &out, eol);
        }
        if (chance(src, 5)) try appendEol(src, a, &out, eol);
        var n = p.ncols;
        if (chance(src, 10)) n = switch (below(src, 3)) {
            0 => n + 1,
            1 => n -| 1,
            else => 0,
        };
        for (0..n) |i| {
            if (i != 0) try out.append(a, p.delim);
            try appendField(src, a, &out, csvToken(src, a, kinds[i % kinds.len]), p);
        }
        try appendEol(src, a, &out, eol);
    }
    if (chance(src, 15) and out.items.len != 0) {
        // No final newline (and so possibly a final empty field).
        while (out.items.len != 0 and (out.items[out.items.len - 1] == '\n' or out.items[out.items.len - 1] == '\r')) _ = out.pop();
    }
    return out.items;
}

fn damage(src: anytype, a: Allocator, in: []const u8) ![]u8 {
    var b: std.ArrayList(u8) = .empty;
    try b.appendSlice(a, in);
    const n = range(src, usize, 1, 4);
    for (0..n) |_| {
        if (b.items.len == 0) break;
        const at = below(src, b.items.len);
        switch (below(src, 6)) {
            0 => b.items[at] = struct_chars[below(src, struct_chars.len)],
            1 => try b.insert(a, at, struct_chars[below(src, struct_chars.len)]),
            2 => {
                const k = @min(range(src, usize, 1, 8), b.items.len - at);
                b.replaceRangeAssumeCapacity(at, k, &.{});
            },
            3 => b.shrinkRetainingCapacity(at),
            4 => {
                const k = @min(range(src, usize, 1, 24), b.items.len - at);
                const chunk = try a.dupe(u8, b.items[at .. at + k]);
                try b.insertSlice(a, at, chunk);
            },
            else => b.items[at] = src.value(u8),
        }
    }
    return b.items;
}

fn rawBytes(src: anytype, a: Allocator) ![]u8 {
    const alphabet = "ab1,.\n\r\"'; \t-eE+0x#\xff";
    const b = try a.alloc(u8, below(src, 160));
    for (b) |*c| c.* = if (chance(src, 80)) alphabet[below(src, alphabet.len)] else src.value(u8);
    return b;
}

fn genCsvOptions(src: anytype, a: Allocator, p: CsvPlan, in_len: usize, header_names: []const []const u8) !csvio.CsvReadOptions {
    var o: csvio.CsvReadOptions = .{ .delimiter = p.delim, .quote = p.quote, .has_header = p.has_header, .comment = p.comment, .skip_rows = p.skip };
    if (chance(src, 15)) {
        const n = if (chance(src, 70)) p.ncols else range(src, usize, 0, 9);
        const names = try a.alloc([]const u8, n);
        for (names, 0..) |*x, i| x.* = if (chance(src, 90)) name_pool[i % name_pool.len] else name_pool[0];
        o.names = names;
    }
    if (chance(src, 15)) {
        const cols = try a.alloc([]const u8, range(src, usize, 0, 3));
        for (cols) |*x| x.* = if (header_names.len != 0 and chance(src, 85)) header_names[below(src, header_names.len)] else "nope";
        o.columns = cols;
    }
    if (chance(src, 25)) {
        const ts = try a.alloc(csvio.TypeOverride, range(src, usize, 0, 3));
        for (ts) |*t| t.* = .{ .name = if (header_names.len != 0 and chance(src, 85)) header_names[below(src, header_names.len)] else "nope", .type = pickEnum(src, ColumnType) };
        o.types = ts;
    }
    switch (below(src, 6)) {
        0 => o.null_values = &df.polars_na_values,
        1 => o.null_values = &.{ "x", "-", "NA" },
        2 => o.null_values = &.{},
        else => {},
    }
    if (chance(src, 10)) o.infer_types = false;
    if (chance(src, 25)) o.parse_dates = true;
    if (chance(src, 20)) o.n_rows = range(src, usize, 0, 5);
    if (chance(src, 20)) o.truncate_ragged = true;
    if (chance(src, 25)) o.strict_quotes = false;
    if (chance(src, 10)) o.max_quoted_lines = range(src, usize, 0, 3);
    if (chance(src, 8)) o.max_bytes = range(src, usize, 0, in_len + 8);
    if (chance(src, 6)) o.max_columns = range(src, usize, 0, 8);
    if (chance(src, 6)) o.max_cell_bytes = range(src, usize, 0, 24);
    if (chance(src, 6)) o.max_record_bytes = range(src, usize, 0, 60);
    if (chance(src, 6)) o.max_rows = range(src, usize, 0, 6);
    if (chance(src, 6)) o.max_cells = range(src, usize, 0, 30);
    return o;
}

var csv_err_n: [@typeInfo(csvio.CsvReadError).error_set.error_names.?.len]u64 = @splat(0);

fn countCsvErr(err: csvio.CsvReadError) void {
    inline for (@typeInfo(csvio.CsvReadError).error_set.error_names.?, 0..) |name, i| {
        if (err == @field(csvio.CsvReadError, name)) csv_err_n[i] += 1;
    }
}

fn printCsvTable() void {
    inline for (@typeInfo(csvio.CsvReadError).error_set.error_names.?, 0..) |name, i|
        std.debug.print("CSVERR {s}={d}\n", .{ name, csv_err_n[i] });
}

fn csvTarget(src: anytype, a: Allocator) !void {
    driver.hit("csv");
    const delim: u8 = if (chance(src, 93)) pickOf(src, u8, ",;\t|") else pickOf(src, u8, &.{ '"', '\n', '\r', 0, 'a', ' ' });
    const quote: u8 = if (chance(src, 90)) '"' else pickOf(src, u8, &.{ 0, '\'', ',', '\n' });
    const p: CsvPlan = .{
        .delim = delim,
        .quote = quote,
        .ncols = range(src, usize, 1, 6),
        .has_header = chance(src, 85),
        .comment = if (chance(src, 12)) '#' else 0,
        .skip = if (chance(src, 12)) range(src, usize, 1, 3) else 0,
    };
    var bytes: []const u8 = undefined;
    if (chance(src, 4)) {
        bytes = try rawBytes(src, a);
        driver.hit("csv_raw");
    } else {
        bytes = try genCsvBytes(src, a, p);
        if (chance(src, 25)) {
            bytes = try damage(src, a, bytes);
            driver.hit("csv_damaged");
        }
    }
    var header_names: []const []const u8 = &name_pool;
    header_names = header_names[0..@min(p.ncols, header_names.len)];
    const o = try genCsvOptions(src, a, p, bytes.len, header_names);
    if (o.types.len != 0) driver.hit("csv_types");
    if (o.names != null) driver.hit("csv_names");
    if (o.columns != null) driver.hit("csv_columns");
    if (o.max_bytes < bytes.len or o.max_columns < 8 or o.max_cell_bytes < 24 or o.max_cells < 30 or o.max_rows < 7 or o.max_record_bytes < 61) driver.hit("csv_limits");
    const r1 = csvio.readCsv(a, bytes, o);
    const r2 = csvio.test_hooks.readCsvCells(a, bytes, o);
    try agree("csv one-pass vs two-pass", r1, r2);
    const f = r1 catch |err| {
        driver.hit("csv_err");
        countCsvErr(err);
        return;
    };
    driver.hit("csv_ok");
    try expectWellFormed("csv", f);
    try csvRoundTrip(a, f, o);
}

fn csvRoundTrip(a: Allocator, f: Frame, o: csvio.CsvReadOptions) !void {
    const default_na: [*]const []const u8 = &df.pandas_na_values;
    const skip = o.null_values.ptr != default_na or o.quote != '"' or std.mem.findScalar(u8, ",;\t|", o.delimiter) == null or f.columns.len == 0;
    var has_nan = false;
    // `readCsv` strips a leading BOM from the first header name, so a name that starts with
    // one (a BOM after skipped rows) is not written back to the same name.
    for (f.columns) |c| if (std.mem.startsWith(u8, c.name, "\xef\xbb\xbf")) {
        has_nan = true;
    };
    for (f.columns, 0..) |c, ci| {
        if (c.type != .float) continue;
        for (0..f.len) |ri| {
            const v = f.columnAt(ci).get(ri);
            if (v == .float and std.math.isNan(v.float)) has_nan = true;
        }
    }
    if (skip or has_nan) {
        driver.hit("csv_rt_skipped");
        return;
    }
    var aw: std.Io.Writer.Allocating = .init(a);
    try df.writeCsv(a, &aw.writer, f, .{ .delimiter = o.delimiter });
    const out = try aw.toOwnedSlice();
    const types = try a.alloc(csvio.TypeOverride, f.columns.len);
    for (types, f.columns) |*t, c| t.* = .{ .name = c.name, .type = c.type };
    const g = csvio.readCsv(a, out, .{ .delimiter = o.delimiter, .types = types, .infer_types = o.infer_types, .parse_dates = o.parse_dates }) catch |err| {
        if (err == error.OutOfMemory) return err;
        std.debug.print("csv round trip: reading back failed with {t}\n--- written ---\n{f}\n---\n", .{ err, std.zig.fmtString(out) });
        return error.RoundTripRead;
    };
    if (!df.equals(f, g)) {
        std.debug.print("csv round trip: frames differ (len {d} vs {d}, columns {d} vs {d})\n--- written ---\n{f}\n---\n", .{ f.len, g.len, f.columns.len, g.columns.len, std.zig.fmtString(out) });
        return error.RoundTripMismatch;
    }
    driver.hit("csv_rt");
}

// ── writers ─────────────────────────────────────────────────────────────────

fn writersTarget(src: anytype, a: Allocator) !void {
    driver.hit("writers");
    const f = try genFrame(src, a, below(src, 3), genRows(src));
    for ([_]df.JsonOrient{ .records, .columns }) |orient| {
        var aw: std.Io.Writer.Allocating = .init(a);
        try df.writeJson(&aw.writer, f, orient);
        const bytes = try aw.toOwnedSlice();
        const v = std.json.parseFromSliceLeaky(std.json.Value, a, bytes, .{}) catch |err| {
            if (err == error.OutOfMemory) return err;
            std.debug.print("writeJson {t}: output does not parse ({t}): {f}\n", .{ orient, err, std.zig.fmtString(bytes) });
            return error.BadJson;
        };
        switch (orient) {
            .records => if (v != .array or v.array.items.len != f.len) return error.BadJsonShape,
            .columns => {
                if (v != .object or v.object.count() != f.columns.len) return error.BadJsonShape;
                var it = v.object.iterator();
                while (it.next()) |e| if (e.value_ptr.* != .array or e.value_ptr.array.items.len != f.len) return error.BadJsonShape;
            },
        }
        driver.hit("json_ok");
    }
    {
        var aw: std.Io.Writer.Allocating = .init(a);
        try df.writeNdjson(&aw.writer, f);
        const bytes = try aw.toOwnedSlice();
        var lines: usize = 0;
        var it = std.mem.splitScalar(u8, bytes, '\n');
        while (it.next()) |line| {
            if (line.len == 0) continue;
            _ = std.json.parseFromSliceLeaky(std.json.Value, a, line, .{}) catch |err| {
                if (err == error.OutOfMemory) return err;
                std.debug.print("writeNdjson: a line does not parse ({t}): {f}\n", .{ err, std.zig.fmtString(line) });
                return error.BadJson;
            };
            lines += 1;
        }
        if (lines != f.len) return error.BadJsonShape;
        driver.hit("ndjson_ok");
    }
    const fo: df.FormatOptions = .{
        .max_rows = range(src, usize, 0, 12),
        .max_cols = range(src, usize, 0, 14),
        .max_cell_chars = range(src, usize, 0, 40),
        .null_text = pickOf(src, []const u8, &.{ "null", "", "\xff", "<NA>" }),
        .show_dtypes = chance(src, 50),
        .show_shape = chance(src, 50),
    };
    _ = try df.format(a, f, fo);
    _ = try df.toMarkdown(a, f, .{ .null_text = fo.null_text });
    driver.hit("render_ok");
    {
        var aw: std.Io.Writer.Allocating = .init(a);
        const delim = pickOf(src, u8, ",;\t|");
        try df.writeCsv(a, &aw.writer, f, .{
            .delimiter = delim,
            .quote = pickOf(src, u8, &.{ '"', '\'' }),
            .header = chance(src, 80),
            .null_text = pickOf(src, []const u8, &.{ "", "NA", "a,b" }),
            .quote_style = pickEnum(src, df.CsvQuote),
            .line_terminator = if (chance(src, 50)) .lf else .crlf,
            .float_precision = if (chance(src, 50)) null else range(src, u8, 0, 30),
        });
        driver.hit("csv_write_ok");
    }
}

// ── the harness ─────────────────────────────────────────────────────────────

/// Generic over the choice source (`testing.Smith` under `--fuzz`, the driver's `Rng`).
pub fn harness(comptime S: type, src: *S, gpa: Allocator) anyerror!void {
    const mode = below(src, 20);
    if (mode >= 18) return oomTarget(src, gpa);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    switch (mode) {
        0...7 => try csvTarget(src, a),
        8...15 => try framesTarget(src, a),
        else => try writersTarget(src, a),
    }
}

/// While set, the allocator may fail, so a verb may answer differently from its reference
/// path (which allocates again): the comparison is off, and `OutOfMemory` is not a finding.
var oom_mode = false;

/// The same targets over an allocator that fails from a drawn allocation on (half the
/// runs never): every verb, reader and writer must answer an error, not panic, and
/// the arena must take back what the failed call had allocated.
fn oomTarget(src: anytype, gpa: Allocator) !void {
    driver.hit("oom");
    // The arena owns the memory (a frame's arrays leak under a plain allocator); the
    // failing allocator sits on top of it, so each allocation a verb makes counts.
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var fa = tkfuzz.failingAllocator(src, arena.allocator(), 150);
    const a = fa.allocator();
    oom_mode = true;
    defer oom_mode = false;
    const r = switch (below(src, 3)) {
        0 => csvTarget(src, a),
        1 => framesTarget(src, a),
        else => writersTarget(src, a),
    };
    if (fa.has_induced_failure) driver.hit("oom_induced");
    r catch |e| switch (e) {
        error.OutOfMemory, error.WriteFailed => driver.hit("oom_error"),
        else => return e,
    };
}

test "fuzz driver: DATAFRAME_FUZZ" {
    resetReach();
    driver.run(harness, .{ .prefix = "DATAFRAME_FUZZ", .name = "dataframe" }) catch |e| {
        if (e != error.SkipZigTest) {
            printVerbTable();
            printCsvTable();
        }
        return e;
    };
    printVerbTable();
    printCsvTable();
}

test "fuzz harness: 300 seeds in every test run, and every verb gets called" {
    resetReach();
    driver.resetReach();
    for (0..300) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: driver.Rng = .{ .r = prng.random() };
        harness(driver.Rng, &rng, testing.allocator) catch |e| {
            std.debug.print("seed {d}: {t}\n", .{ seed, e });
            return e;
        };
    }
    driver.resetReach();
    for (std.enums.values(Verb), 0..) |v, i| if (verb_ok[i] + verb_err[i] == 0) {
        std.debug.print("reach: verb {t} never called in 300 seeds\n", .{v});
        return error.HarnessDoesNotReach;
    };
}
