// SPDX-License-Identifier: MIT
//! The no-panic sweep of wave W11 (real dtype widths Int8..UInt64, Float32), 2026-11-10:
//! hostile frames, extreme cells, hostile text and every public verb that touches a width
//! column. Expected everywhere: an error or a defined value, never a panic or a hang, and a
//! result whose width columns hold their own arrays (`frame.widthsConform`). Findings are
//! pinned in tests named "(sweep W11-N)".

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const fm = @import("frame.zig");
const vm = @import("value.zig");
const dtype = @import("dtype.zig");
const Frame = fm.Frame;
const Column = vm.Column;
const ColumnType = vm.ColumnType;
const ColumnData = fm.ColumnData;
const Value = vm.Value;
const Expr = df.Expr;

const widths = [_]ColumnType{ .int8, .int16, .int32, .uint8, .uint16, .uint32, .uint64, .float32 };
const numerics = widths ++ [_]ColumnType{ .int, .float };

const nan = std.math.nan(f64);
const inf = std.math.inf(f64);
const big: u64 = (1 << 63) + 5;

// ── helpers ─────────────────────────────────────────────────────────────────────

/// What a sweep collects: the entry points whose result broke an invariant.
const Viol = struct {
    a: std.mem.Allocator,
    seen: std.ArrayList([]const u8) = .empty,
    hostile: bool = false,

    fn add(v: *Viol, what: []const u8, detail: []const u8) void {
        const msg = std.fmt.allocPrint(v.a, "{s} {s}", .{ what, detail }) catch return;
        for (v.seen.items) |s| if (std.mem.eql(u8, s, msg)) {
            v.a.free(msg);
            return;
        };
        v.seen.append(v.a, msg) catch {};
    }

    fn report(v: *const Viol, ctx: []const u8) !void {
        if (v.seen.items.len == 0) return;
        std.debug.print("sweep W11 [{s}]: {d} violations\n", .{ ctx, v.seen.items.len });
        for (v.seen.items[0..@min(v.seen.items.len, 30)]) |s| std.debug.print("  {s}\n", .{s});
        return error.SweepViolations;
    }
};

/// An error is fine; a Frame whose width columns disagree with their declarations is not. On a
/// hostile input (`v.hostile`) the input columns `x` and `y` are skipped where a verb passes
/// them on as they are: garbage in stays garbage; what a verb computes must still conform.
fn ck(v: *Viol, what: []const u8, detail: []const u8, r: anytype) void {
    const f = r catch return;
    if (!v.hostile) {
        if (!fm.widthsConform(f)) v.add(what, detail);
        return;
    }
    for (f.columns, 0..) |c, ci| {
        if (std.mem.startsWith(u8, c.name, "x") or std.mem.startsWith(u8, c.name, "y") or !dtype.isWidth(c.type)) continue; // x, y, x_r ...
        const d = f.columnAt(ci);
        if (d == .nulls) continue;
        if (!std.mem.eql(u8, @tagName(std.meta.activeTag(d)), @tagName(c.type))) v.add(what, detail);
    }
}

/// `ck` for `cast`, which rewrites `x` itself: the column `x` is held to the rule.
fn ckAll(v: *Viol, what: []const u8, detail: []const u8, r: anytype) void {
    const f = r catch return;
    const ci = f.columnIndex("x") orelse return;
    const c = f.columns[ci];
    const d = f.columnAt(ci);
    if (!dtype.isWidth(c.type) or d == .nulls) return;
    if (!std.mem.eql(u8, @tagName(std.meta.activeTag(d)), @tagName(c.type))) v.add(what, detail);
}

fn bx(a: std.mem.Allocator, e: Expr) !*const Expr {
    const p = try a.create(Expr);
    p.* = e;
    return p;
}

fn colx(a: std.mem.Allocator, name: []const u8) !*const Expr {
    return bx(a, .{ .col = name });
}

fn litx(a: std.mem.Allocator, v: Value) !*const Expr {
    return bx(a, .{ .lit = v });
}

fn iv(x: i64) Value {
    return .{ .int = x };
}

fn fv(x: f64) Value {
    return .{ .float = x };
}

const lits = [_]Value{
    .{ .int = 0 },
    .{ .int = -1 },
    .{ .int = 1 },
    .{ .int = std.math.maxInt(i64) },
    .{ .int = std.math.minInt(i64) },
    .{ .uint = 1 << 63 },
    .{ .uint = std.math.maxInt(u64) },
    .{ .uint = 5 }, // non-canonical: at or below maxInt(i64)
    .{ .float = nan },
    .{ .float = inf },
    .{ .float = -inf },
    .{ .float = 1e300 },
    .{ .float = -0.0 },
    .{ .float = 0.5 },
    .{ .float = 18446744073709551616.0 },
    .{ .decimal = vm.decimal_scale },
    .{ .decimal = std.math.maxInt(i128) },
    .{ .decimal = std.math.minInt(i128) },
    .{ .text = "a" },
    .{ .bool = true },
    .null,
};

const e_i8 = [_]Value{ iv(-128), iv(127), iv(0), iv(-1), iv(1), .null };
const e_i16 = [_]Value{ iv(-32768), iv(32767), iv(0), iv(-1), iv(1), .null };
const e_i32 = [_]Value{ iv(-2147483648), iv(2147483647), iv(0), iv(-1), iv(1), .null };
const e_u8 = [_]Value{ iv(0), iv(255), iv(1), iv(128), .null, iv(254) };
const e_u16 = [_]Value{ iv(0), iv(65535), iv(1), iv(32768), .null, iv(65534) };
const e_u32 = [_]Value{ iv(0), iv(4294967295), iv(1), iv(2147483648), .null, iv(4294967294) };
const e_u64 = [_]Value{ iv(0), .{ .uint = std.math.maxInt(u64) }, iv(1), .{ .uint = 1 << 63 }, .null, iv(std.math.maxInt(i64)) };
const e_f32 = [_]Value{ fv(nan), fv(inf), fv(-inf), fv(-0.0), fv(@as(f32, 1e-45)), fv(@as(f32, 3.4028235e38)), fv(1.5), .null };
const e_i64 = [_]Value{ iv(std.math.minInt(i64)), iv(std.math.maxInt(i64)), iv(0), iv(-1), iv(1), .null };
const e_f64 = [_]Value{ fv(nan), fv(inf), fv(-inf), fv(-0.0), fv(5e-324), fv(1.7976931348623157e308), fv(1.5), .null };
const e_other = [_]Value{ iv(0), .null };

/// The cells that sit at the edges of a type (min, max, zero, one, null, the specials of a float).
fn edgeCells(ty: ColumnType) []const Value {
    return switch (ty) {
        .int8 => &e_i8,
        .int16 => &e_i16,
        .int32 => &e_i32,
        .uint8 => &e_u8,
        .uint16 => &e_u16,
        .uint32 => &e_u32,
        .uint64 => &e_u64,
        .float32 => &e_f32,
        .int => &e_i64,
        .float => &e_f64,
        else => &e_other,
    };
}

fn frameOf(a: std.mem.Allocator, specs: []const struct { []const u8, ColumnType, []const Value }, n: usize) !Frame {
    const cols = try a.alloc(Column, specs.len);
    for (cols, specs) |*c, s| c.* = .{ .name = s[0], .type = s[1] };
    var b = try fm.FrameBuilder.init(a, cols, n);
    const row = try a.alloc(Value, specs.len);
    for (0..n) |ri| {
        for (row, specs) |*o, s| o.* = s[2][ri % s[2].len];
        try b.appendRow(row);
    }
    return b.toOwned();
}

/// A frame `x`, `y` (both `ty`, the edge cells, `y` rotated), `k` (Int64 group key), `n` rows.
fn edgeFrame(a: std.mem.Allocator, ty: ColumnType, n: usize) !Frame {
    const e = edgeCells(ty);
    const rot = try a.alloc(Value, e.len);
    for (rot, 0..) |*o, i| o.* = e[(i + 1) % e.len];
    const ks = [_]Value{ iv(0), iv(1), iv(0) };
    return frameOf(a, &.{ .{ "x", ty, e }, .{ "y", ty, rot }, .{ "k", .int, &ks } }, n);
}

fn hand(a: std.mem.Allocator, ty: ColumnType, data: ColumnData, n: usize) !Frame {
    const ks = try a.alloc(i64, n);
    for (ks, 0..) |*k, i| k.* = @intCast(i % 3);
    const cols = try a.dupe(Column, &.{ .{ .name = "x", .type = ty }, .{ .name = "y", .type = ty }, .{ .name = "k", .type = .int } });
    const d = try a.dupe(ColumnData, &.{ data, data, .{ .int = .{ .values = ks } } });
    return .{ .columns = cols, .data = d, .len = n };
}

fn textColumn(a: std.mem.Allocator, cells: []const []const u8) !ColumnData {
    const offs = try a.alloc(usize, cells.len + 1);
    var bytes: std.ArrayList(u8) = .empty;
    offs[0] = 0;
    for (cells, 0..) |c, i| {
        try bytes.appendSlice(a, c);
        offs[i + 1] = bytes.items.len;
    }
    return .{ .text = .{ .offsets = offs, .bytes = bytes.items } };
}

// ── the battery: every verb that reads or writes a width column ──────────────────

/// `f` has columns `x`, `y` (the same declared type) and `k` (Int64). `full` runs every literal
/// against every binary operator; a hostile frame gets the short list.
fn battery(a: std.mem.Allocator, f: Frame, v: *Viol, full: bool) !void {
    const x = try colx(a, "x");
    const y = try colx(a, "y");
    const k = try colx(a, "k");

    // Expr: every unary and binary operator, alone and against every literal and column.
    for (std.enums.values(df.Unary)) |u| {
        ck(v, "mutate unary", @tagName(u), df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .unary = .{ .op = u, .x = x } } }}));
    }
    const nl: usize = if (full) lits.len else 9;
    for (std.enums.values(df.Binary)) |b| {
        ck(v, "mutate x,y", @tagName(b), df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .binary = .{ .op = b, .l = x, .r = y } } }}));
        ck(v, "mutate x,k", @tagName(b), df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .binary = .{ .op = b, .l = x, .r = k } } }}));
        ck(v, "mutate k,x", @tagName(b), df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .binary = .{ .op = b, .l = k, .r = x } } }}));
        for (lits[0..nl]) |l| {
            const lp = try litx(a, l);
            ck(v, "mutate x,lit", @tagName(b), df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .binary = .{ .op = b, .l = x, .r = lp } } }}));
            ck(v, "mutate lit,x", @tagName(b), df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .binary = .{ .op = b, .l = lp, .r = x } } }}));
        }
    }
    // Declared output widths over expressions of any kind (the Assign.type guard).
    for (widths) |t| {
        const tn = @tagName(t);
        const sum = try bx(a, .{ .binary = .{ .op = .add, .l = x, .r = y } });
        const quot = try bx(a, .{ .binary = .{ .op = .div, .l = x, .r = y } });
        const txt = try bx(a, .{ .unary = .{ .op = .upper, .x = try litx(a, .{ .text = "300" }) } });
        for ([_]*const Expr{ x, sum, quot, txt }) |e| {
            ck(v, "mutate type=", tn, df.mutate(a, f, &.{.{ .out = "r", .expr = e.*, .type = t }}));
        }
        for (lits[0..nl]) |l| ck(v, "mutate type= lit", tn, df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .lit = l }, .type = t }}));
        ck(v, "mutate cast node", tn, df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .cast = .{ .x = x, .to = t } } }}));
        ck(v, "mutate cast node k", tn, df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .cast = .{ .x = k, .to = t } } }}));
    }
    // Rounding, closeness, membership, conditionals, coalesce.
    for ([_]i32{ 0, 1, -1, 400, -400, std.math.maxInt(i32), std.math.minInt(i32) }) |d| {
        ck(v, "mutate round", "", df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .round = .{ .x = x, .decimals = d } } }}));
    }
    ck(v, "mutate round_sig_figs", "", df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .round_sig_figs = .{ .x = x, .digits = 3 } } }}));
    ck(v, "mutate round_sig_figs", "max", df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .round_sig_figs = .{ .x = x, .digits = std.math.maxInt(u32) } } }}));
    ck(v, "mutate is_close", "", df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .is_close = .{ .l = x, .r = y } } }}));
    ck(v, "mutate is_in", "", df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .is_in = .{ .x = x, .values = &lits } } }}));
    const gt = try bx(a, .{ .binary = .{ .op = .gt, .l = x, .r = y } });
    ck(v, "mutate if_else", "", df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .if_else = .{ .cond = gt, .then = x, .otherwise = k } } }}));
    ck(v, "mutate if_else", "lit", df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .if_else = .{ .cond = gt, .then = x, .otherwise = try litx(a, .{ .uint = big }) } } }}));
    ck(v, "mutate coalesce", "", df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .coalesce = &.{ x.*, y.*, k.* } } }}));
    ck(v, "mutate to_integer", "", df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .to_integer = .{ .x = x } } }}));
    ck(v, "mutate pad", "", df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .pad = .{ .x = x, .width = 40 } } }}));
    ck(v, "mutate dt", "", df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .dt = .{ .x = x, .part = .year } } }}));
    ck(v, "mutate strftime", "", df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .strftime = .{ .x = x, .format = "%Y-%m-%d" } } }}));
    ck(v, "where", "", df.where(a, f, gt));
    ck(v, "where", "x", df.where(a, f, x));

    // cast, every target and mode.
    for (std.enums.values(ColumnType)) |to| {
        for (std.enums.values(@TypeOf((df.CastSpec{ .col = "x", .to = .int }).on_error))) |oe| {
            ckAll(v, "cast", @tagName(to), df.cast(a, f, .{ .col = "x", .to = to, .on_error = oe }));
            ck(v, "cast k", @tagName(to), df.cast(a, f, .{ .col = "k", .to = to, .on_error = oe }));
        }
    }

    // Aggregates, reductions, windows.
    for (std.enums.values(df.AggFn)) |fnn| {
        for ([_]bool{ false, true }) |skip| {
            ck(v, "aggregate by k", @tagName(fnn), df.aggregate(a, f, .{ .group_by = &.{"k"}, .aggs = &.{.{ .src = "x", .out = "o", .func = fnn, .q = 0.9 }}, .skip_na = skip }));
            ck(v, "aggregate whole", @tagName(fnn), df.aggregate(a, f, .{ .group_by = &.{}, .aggs = &.{.{ .src = "x", .out = "o", .func = fnn }}, .skip_na = skip }));
            ck(v, "aggregate by x", @tagName(fnn), df.aggregate(a, f, .{ .group_by = &.{"x"}, .aggs = &.{.{ .src = "y", .out = "o", .func = fnn }}, .skip_na = skip, .sort_groups = true }));
        }
        ck(v, "reduce", @tagName(fnn), df.reduce(a, f, &.{.{ .src = "x", .out = "o", .func = fnn }}));
    }
    ck(v, "cumsum", "", df.cumsum(a, f, .{ .value_col = "x", .out = "o" }));
    for (std.enums.values(df.RollFn)) |rf| {
        for ([_]usize{ 1, 2, 5, 100 }) |w| ck(v, "rolling", @tagName(rf), df.rolling(a, f, .{ .value_col = "x", .out = "o", .window = w, .func = rf }));
    }
    const ops = [_]df.WindowOp{
        .{ .shift = .{ .n = 1 } },
        .{ .shift = .{ .n = -2, .fill = .{ .uint = big } } },
        .{ .shift = .{ .n = 1, .fill = .{ .float = 0.5 } } },
        .{ .shift = .{ .n = std.math.minInt(i64), .fill = .{ .int = 300 } } },
        .{ .diff = 1 },
        .{ .diff = -1 },
        .{ .diff = std.math.maxInt(i64) },
        .{ .diff = std.math.minInt(i64) },
        .{ .pct_change = 1 },
        .{ .pct_change = -1 },
        .cum_sum,
        .cum_prod,
        .cum_min,
        .cum_max,
        .cum_count,
        .row_number,
        .{ .rank = .{} },
        .{ .rank = .{ .method = .dense, .pct = true } },
        .{ .ewm = .{ .alpha = 0.5 } },
    };
    for (ops, 0..) |op, oi| {
        const lab = try std.fmt.allocPrint(a, "{d}", .{oi});
        ck(v, "window", lab, df.window(a, f, .{ .value_col = "x", .out = "o", .op = op }));
        ck(v, "window part", lab, df.window(a, f, .{ .value_col = "x", .out = "o", .op = op, .partition_by = &.{"k"}, .order_by = &.{"y"}, .reverse = true }));
    }
    for (std.enums.values(df.WinFn)) |wf| {
        const tag = @tagName(wf);
        ck(v, "window rolling", tag, df.window(a, f, .{ .value_col = "x", .out = "o", .op = .{ .rolling = .{ .window = 3, .func = wf } } }));
        ck(v, "window rolling part", tag, df.window(a, f, .{ .value_col = "x", .out = "o", .op = .{ .rolling = .{ .window = 2, .func = wf, .min_periods = 0 } }, .partition_by = &.{"k"} }));
        ck(v, "window expanding", tag, df.window(a, f, .{ .value_col = "x", .out = "o", .op = .{ .expanding = .{ .func = wf } } }));
        ck(v, "window transform", tag, df.window(a, f, .{ .value_col = "x", .out = "o", .op = .{ .expanding = .{ .func = wf } }, .partition_by = &.{"k"}, .mapping = .join }));
    }

    // Keys: sort, distinct, joins, pivots, shapes.
    ck(v, "sort", "x", df.sort(a, f, .{ .key = "x" }));
    ck(v, "sort", "x desc", df.sort(a, f, .{ .key = "x", .dir = .desc, .then_by = &.{.{ .key = "y" }}, .missing = .first }));
    ck(v, "sort", "k,x", df.sort(a, f, .{ .key = "k", .then_by = &.{.{ .key = "x", .dir = .desc }} }));
    for ([_]@TypeOf((df.DistinctSpec{ .keys = &.{} }).keep){ .first, .last, .none }) |keep| {
        ck(v, "distinct", "x", df.distinct(a, f, .{ .keys = &.{"x"}, .keep = keep }));
        ck(v, "distinct", "all", df.distinct(a, f, .{ .keys = &.{}, .keep = keep }));
    }
    for (std.enums.values(df.JoinHow)) |how| {
        const tag = @tagName(how);
        ck(v, "join x", tag, df.join(a, f, f, .{ .on = "x", .how = how }));
        ck(v, "join x suffix", tag, df.join(a, f, f, .{ .keys = &.{ "x", "k" }, .how = how, .suffix = "_r", .coalesce_keys = true, .null_keys = .no_match }));
        ck(v, "join x=k", tag, df.join(a, f, f, .{ .keys = &.{"x"}, .right_on = &.{"k"}, .how = how, .suffix = "_r" }));
        ck(v, "join k=x", tag, df.join(a, f, f, .{ .keys = &.{"k"}, .right_on = &.{"x"}, .how = how, .suffix = "_r", .indicator = "m" }));
    }
    for (std.enums.values(df.AggFn)) |fnn| {
        ck(v, "pivot", @tagName(fnn), df.pivot(a, f, .{ .row_key = "k", .col_key = "x", .value_col = "y", .agg = fnn }));
        ck(v, "pivot", @tagName(fnn), df.pivot(a, f, .{ .row_key = "x", .col_key = "k", .value_col = "y", .agg = fnn, .margins = true, .fill_value = 0 }));
    }
    ck(v, "unpivot", "", df.unpivot(a, f, .{ .id_cols = &.{"k"}, .value_cols = &.{ "x", "y" } }));
    ck(v, "unpivot", "all", df.unpivot(a, f, .{ .id_cols = &.{} }));
    for (std.enums.values(df.ConcatHow)) |how| {
        ck(v, "concat", @tagName(how), df.concat(a, &.{ f, f }, how));
    }
    ck(v, "transpose", "", df.transpose(a, f, .{}));
    ck(v, "transpose", "hdr", df.transpose(a, f, .{ .header_name = "h" }));
    ck(v, "describe", "", df.describe(a, f, &.{}));
    ck(v, "describeWith", "", df.describeWith(a, f, .{ .all = true }));
    ck(v, "quantiles", "", df.quantiles(a, f, .{ .qs = &.{ 0, 0.5, 1 } }));
    ck(v, "valueCounts", "", df.valueCounts(a, f, .{ .cols = &.{"x"} }));
    ck(v, "valueCounts", "n", df.valueCounts(a, f, .{ .cols = &.{ "x", "y" }, .normalize = true, .keep_missing = true }));
    ck(v, "clip", "", df.clip(a, f, .{ .col = "x", .lower = -1.5, .upper = 1e30 }));
    ck(v, "clip", "huge", df.clip(a, f, .{ .col = "x", .lower = -1e30, .upper = 1e30 }));
    ck(v, "clip", "nan", df.clip(a, f, .{ .col = "x", .lower = nan, .upper = inf }));
    ck(v, "replace", "", df.replace(a, f, .{ .col = "x", .pairs = &.{ .{ .from = iv(1), .to = .{ .uint = big } }, .{ .from = .{ .uint = big }, .to = fv(0.25) }, .{ .from = .null, .to = iv(300) } } }));
    ck(v, "fillna", "", df.fillna(a, f, .{ .subset = &.{"x"}, .value = .{ .uint = big } }));
    ck(v, "fillna", "300", df.fillna(a, f, .{ .subset = &.{"x"}, .value = iv(300) }));
    ck(v, "fillna", "f", df.fillna(a, f, .{ .subset = &.{"x"}, .value = fv(1.5) }));
    ck(v, "dropna", "", df.dropna(a, f, .{ .subset = &.{"x"} }));
    for (std.enums.values(df.FillStrategy)) |s| {
        ck(v, "fillNull", @tagName(s), df.fillNull(a, f, .{ .subset = &.{"x"}, .strategy = s }));
    }
    for (std.enums.values(df.HorizontalFn)) |h| {
        ck(v, "horizontal", @tagName(h), df.horizontal(a, f, .{ .cols = &.{ "x", "y", "k" }, .func = h, .out = "o" }));
    }
    ck(v, "corr", "", df.corr(a, f, .{ .cols = &.{ "x", "y", "k" } }));
    ck(v, "cov", "", df.cov(a, f, .{ .cols = &.{ "x", "y", "k" } }));
    ck(v, "info", "", df.info(a, f));
    ck(v, "take", "", df.take(a, f, &.{ 0, 1, -1, 1000, std.math.minInt(i64) }));
    ck(v, "reverse", "", df.reverse(a, f));
    ck(v, "topN", "", df.topN(a, f, .{ .n = 2 }));
    ck(v, "nlargest", "", df.nlargest(a, f, .{ .col = "x", .n = 3 }));
    ck(v, "topK", "", df.topK(a, f, .{ .by = &.{"x"}, .n = 3 }));
    ck(v, "duplicateMask", "", df.duplicateMask(a, f, .{ .keys = &.{"x"} }));
    ck(v, "hashRows", "", df.hashRows(a, f, 7, "h"));
    ck(v, "dummies", "", df.dummies(a, f, .{ .cols = &.{"x"} }));
    ck(v, "cut", "", df.cut(a, f, .{ .col = "x", .out = "b", .bins = 3 }));
    ck(v, "cut", "edges", df.cut(a, f, .{ .col = "x", .out = "b", .edges = &.{ -1e30, 0, 1e30 } }));
    ck(v, "qcut", "", df.qcut(a, f, .{ .col = "x", .out = "b", .bins = 3 }));
    ck(v, "update", "", df.update(a, f, f));
    ck(v, "combineFirst", "", df.combineFirst(a, f, f));
    ck(v, "mergeOrdered", "", df.mergeOrdered(a, f, f, .{ .on = &.{"k"} }));
    ck(v, "joinAsof", "", df.joinAsof(a, f, f, .{ .on = "x" }));
    ck(v, "repeatRows", "", df.repeatRows(a, f, .{ .times = 2 }));
    ck(v, "fillna ffill", "", df.fillNull(a, f, .{ .strategy = .forward, .limit = 1 }));
    ck(v, "map", "", df.map(a, f, .{ .out = "o", .lhs = .{ .col = "x" }, .op = .add, .rhs = .{ .col = "y" } }));
    ck(v, "map", "num", df.map(a, f, .{ .out = "o", .lhs = .{ .col = "x" }, .op = .div, .rhs = .{ .num = 0 }, .on_missing = .null }));
    ck(v, "filter", "", df.filter(a, f, .{ .where = &.{.{ .col = "x", .op = .gt, .value = .{ .uint = big } }} }));
    ck(v, "filter", "int", df.filter(a, f, .{ .where = &.{.{ .col = "x", .op = .le, .value = iv(0) }}, .mode = .any }));
    ck(v, "filter", "float", df.filter(a, f, .{ .where = &.{.{ .col = "x", .op = .eq, .value = fv(nan) }} }));

    // Series and frame accessors, text renderings, scalar helpers.
    if (f.floatColumn(a, "x")) |c| std.mem.doNotOptimizeAway(c) else |_| {}
    if (f.seriesXY(a, "x", "y")) |c| std.mem.doNotOptimizeAway(c) else |_| {}
    if (f.seriesXY(a, "k", "x")) |c| std.mem.doNotOptimizeAway(c) else |_| {}
    for (0..f.len + 2) |ri| std.mem.doNotOptimizeAway(f.cell(ri, "x"));
    if (f.series("x")) |s| {
        for (0..f.len + 2) |ri| std.mem.doNotOptimizeAway(s.get(ri));
        std.mem.doNotOptimizeAway(s.nullCount());
        std.mem.doNotOptimizeAway(df.autocorr(s, 1));
        std.mem.doNotOptimizeAway(df.entropy(s, 2, true));
        std.mem.doNotOptimizeAway(df.nanExtreme(s, .max));
        for (lits[0..nl]) |l| {
            std.mem.doNotOptimizeAway(df.searchSorted(s, l, .left));
            std.mem.doNotOptimizeAway(df.indexOf(s, l));
        }
    }
    std.mem.doNotOptimizeAway(df.extremeBy(f, "x", "y", .max) catch .null);
    std.mem.doNotOptimizeAway(df.nUnique(a, f, "x", true) catch 0);
    std.mem.doNotOptimizeAway(df.equals(f, f));
    if (df.nullCount(a, f)) |nf| std.mem.doNotOptimizeAway(nf.len) else |_| {}
    std.mem.doNotOptimizeAway(df.estimatedSize(f));
    if (df.format(a, f, .{})) |s| std.mem.doNotOptimizeAway(s.len) else |_| {}
    if (df.format(a, f, .{ .max_rows = 2, .max_cols = 1 })) |s| std.mem.doNotOptimizeAway(s.len) else |_| {}
    if (df.toMarkdown(a, f, .{})) |s| std.mem.doNotOptimizeAway(s.len) else |_| {}
    if (df.toHtml(a, f, .{})) |s| std.mem.doNotOptimizeAway(s.len) else |_| {}
    if (df.glimpse(a, f, .{})) |s| std.mem.doNotOptimizeAway(s.len) else |_| {}
    ck(v, "factorize", "", blk: {
        const r = df.factorize(a, f, .{ .cols = &.{"x"} }) catch |e| break :blk e;
        break :blk r.frame;
    });
    if (df.argSort(a, f, .{ .key = "x" })) |s| std.mem.doNotOptimizeAway(s.len) else |_| {}
    if (df.toFloatMatrix(a, f, &.{ "x", "y" })) |m| std.mem.doNotOptimizeAway(m) else |_| {}
    try writers(a, f);
}

/// Every writer over `f`; a writer must never panic whatever the storage.
fn writers(a: std.mem.Allocator, f: Frame) !void {
    {
        var aw: std.Io.Writer.Allocating = .init(a);
        df.writeCsv(a, &aw.writer, f, .{}) catch {};
    }
    {
        var aw: std.Io.Writer.Allocating = .init(a);
        df.writeCsv(a, &aw.writer, f, .{ .null_text = "NA", .quote_style = .always, .decimal = ',' }) catch {};
    }
    for (std.enums.values(df.JsonOrient)) |o| {
        var aw: std.Io.Writer.Allocating = .init(a);
        df.writeJsonOpts(a, &aw.writer, f, o, .{}) catch {};
        var bw: std.Io.Writer.Allocating = .init(a);
        df.writeJson(&bw.writer, f, o) catch {};
    }
    {
        var aw: std.Io.Writer.Allocating = .init(a);
        df.writeNdjson(&aw.writer, f) catch {};
    }
}

// ── (1) hand-built frames: storage that disagrees with the declaration ───────────

fn hostileStorages(a: std.mem.Allocator, ty: ColumnType, n: usize) ![]const ColumnData {
    var out: std.ArrayList(ColumnData) = .empty;
    // The right array, shorter / longer than the frame, with short or missing bitmaps.
    inline for (widths) |t| {
        if (t == ty) {
            const T = if (t == .float32) f32 else dtype.IntOf(t);
            const Tc = fm.TypedColumn(T);
            const tag = @tagName(t);
            const short = try a.alloc(T, 2);
            @memset(short, 1);
            try out.append(a, @unionInit(ColumnData, tag, Tc{ .values = short }));
            const long = try a.alloc(T, n + 5);
            @memset(long, 1);
            try out.append(a, @unionInit(ColumnData, tag, Tc{ .values = long }));
            const exact = try a.alloc(T, n);
            @memset(exact, 1);
            try out.append(a, @unionInit(ColumnData, tag, Tc{ .values = exact, .valid = &.{} }));
            try out.append(a, @unionInit(ColumnData, tag, Tc{ .values = exact, .valid = &.{1} }));
            const garbage = try a.alloc(u64, (n + 63) / 64 + 3);
            @memset(garbage, ~@as(u64, 0));
            try out.append(a, @unionInit(ColumnData, tag, Tc{ .values = exact, .valid = garbage }));
            const maxes = try a.alloc(T, n);
            if (t == .float32) {
                for (maxes, 0..) |*m, i| m.* = ([_]f32{ std.math.nan(f32), std.math.inf(f32), -std.math.inf(f32), -0.0, 1e-45, 3.4028235e38 })[i % 6];
            } else {
                for (maxes, 0..) |*m, i| m.* = if (i % 2 == 0) std.math.maxInt(T) else std.math.minInt(T);
            }
            try out.append(a, @unionInit(ColumnData, tag, Tc{ .values = maxes }));
        }
    }
    // Another array under the declaration.
    const u64s = try a.alloc(u64, n);
    for (u64s, 0..) |*u, i| u.* = ([_]u64{ std.math.maxInt(u64), 1 << 63, 5, 0 })[i % 4];
    try out.append(a, .{ .uint64 = .{ .values = u64s } });
    const f32s = try a.alloc(f32, n);
    for (f32s, 0..) |*u, i| u.* = ([_]f32{ std.math.nan(f32), std.math.inf(f32), -0.0, 1e-45, 3.4028235e38, 300 })[i % 6];
    try out.append(a, .{ .float32 = .{ .values = f32s } });
    const i8s = try a.alloc(i8, n);
    for (i8s, 0..) |*u, i| u.* = @intCast(@as(i32, @intCast(i % 5)) * 60 - 120);
    try out.append(a, .{ .int8 = .{ .values = i8s } });
    const i64s = try a.alloc(i64, n);
    for (i64s, 0..) |*u, i| u.* = ([_]i64{ 1000, -1000, std.math.maxInt(i64), std.math.minInt(i64), 0, 255, 256 })[i % 7];
    try out.append(a, .{ .int = .{ .values = i64s } });
    const f64s = try a.alloc(f64, n);
    for (f64s, 0..) |*u, i| u.* = ([_]f64{ nan, inf, -inf, 1.5, 1e300, -0.0, 3 })[i % 7];
    try out.append(a, .{ .float = .{ .values = f64s } });
    const decs = try a.alloc(i128, n);
    for (decs, 0..) |*u, i| u.* = ([_]i128{ vm.decimal_scale, std.math.maxInt(i128), std.math.minInt(i128), 3 * vm.decimal_scale })[i % 4];
    try out.append(a, .{ .decimal = .{ .values = decs } });
    try out.append(a, try textColumn(a, &.{ "abc", "300", "", "-1", "18446744073709551615" }));
    try out.append(a, .nulls);
    const items = try a.create(ColumnData);
    items.* = .{ .int = .{ .values = try a.dupe(i64, &.{ 1, 2, 3 }) } };
    const boxed = try a.dupe(Value, &.{
        .{ .uint = big },
        .{ .uint = 5 },
        fv(nan),
        .{ .text = "x" },
        .{ .bool = true },
        .null,
        iv(std.math.minInt(i64)),
        .{ .decimal = std.math.maxInt(i128) },
        .{ .list = .{ .items = items, .start = 0, .end = 2 } },
        .{ .uint = std.math.maxInt(u64) },
    });
    try out.append(a, .{ .boxed = boxed });
    try out.append(a, .{ .boxed = boxed[0..2] }); // shorter than the frame
    return out.items;
}

test "hand-built frames whose storage disagrees with the declared width never panic (sweep W11-1)" {
    var v: Viol = .{ .a = testing.allocator, .hostile = true };
    defer {
        for (v.seen.items) |s| testing.allocator.free(s);
        v.seen.deinit(testing.allocator);
    }
    var total: usize = 0;
    for (widths) |ty| {
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        for ([_]usize{ 5, 130 }) |n| {
            const storages = try hostileStorages(a, ty, n);
            for (storages) |sd| {
                const f = try hand(a, ty, sd, n);
                total += 1;
                try battery(a, f, &v, false);
            }
        }
    }
    try testing.expect(total > 100);
    try v.report("hostile storage");
}

// ── (2)-(7): conforming frames at the edges of every type ────────────────────────

test "every numeric type at its edges through every operator, aggregate, window and verb (sweep W11-2)" {
    var v: Viol = .{ .a = testing.allocator };
    defer {
        for (v.seen.items) |s| testing.allocator.free(s);
        v.seen.deinit(testing.allocator);
    }
    for (numerics) |ty| {
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const f = try edgeFrame(a, ty, 12);
        try testing.expect(fm.widthsConform(f));
        try battery(a, f, &v, true);
    }
    try v.report("edge cells");
}

test "empty and one-row frames of every width (sweep W11-2)" {
    var v: Viol = .{ .a = testing.allocator };
    defer {
        for (v.seen.items) |s| testing.allocator.free(s);
        v.seen.deinit(testing.allocator);
    }
    for (numerics) |ty| {
        for ([_]usize{ 0, 1 }) |n| {
            var arena: std.heap.ArenaAllocator = .init(testing.allocator);
            defer arena.deinit();
            const a = arena.allocator();
            const f = try edgeFrame(a, ty, n);
            try battery(a, f, &v, false);
        }
    }
    try v.report("empty");
}

// ── (3) aggregates over a million rows near overflow ────────────────────────────

/// `n` rows of one width, every cell the max (or min), built as the array (no per-row append).
fn constColumn(a: std.mem.Allocator, ty: ColumnType, n: usize, hi: bool) !ColumnData {
    inline for (widths) |t| {
        if (t == ty) {
            const T = if (t == .float32) f32 else dtype.IntOf(t);
            const vals = try a.alloc(T, n);
            @memset(vals, if (hi) (if (t == .float32) @as(f32, 3.4028235e38) else std.math.maxInt(T)) else (if (t == .float32) @as(f32, -3.4028235e38) else std.math.minInt(T)));
            return @unionInit(ColumnData, @tagName(t), .{ .values = vals });
        }
    }
    unreachable;
}

test "2^18 rows of all-max and all-min cells through the aggregates and cumulative windows (sweep W11-3)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const n = 1 << 18;
    const ks = try a.alloc(i64, n);
    for (ks, 0..) |*k, i| k.* = @intCast(i & 1);
    var v: Viol = .{ .a = testing.allocator };
    defer {
        for (v.seen.items) |s| testing.allocator.free(s);
        v.seen.deinit(testing.allocator);
    }
    for (widths) |ty| {
        for ([_]bool{ true, false }) |hi| {
            // One arena per case: a 1M-row aggregate holds tens of MB of cells that nothing frees.
            var case: std.heap.ArenaAllocator = .init(testing.allocator);
            defer case.deinit();
            const c = case.allocator();
            const x = try constColumn(c, ty, n, hi);
            const cols = try c.dupe(Column, &.{ .{ .name = "x", .type = ty }, .{ .name = "k", .type = .int } });
            const f: Frame = .{ .columns = cols, .data = try c.dupe(ColumnData, &.{ x, .{ .int = .{ .values = ks } } }), .len = n };
            for ([_]df.AggFn{ .sum, .mean, .prod, .std, .min, .max, .first }) |fnn| {
                const r = try df.aggregate(c, f, .{ .group_by = &.{"k"}, .aggs = &.{.{ .src = "x", .out = "o", .func = fnn }} });
                try testing.expect(fm.widthsConform(r));
                try testing.expectEqual(@as(usize, 2), r.len);
            }
            for ([_]df.WindowOp{ .cum_sum, .cum_prod, .{ .diff = 1 } }) |op| {
                const r = try df.window(c, f, .{ .value_col = "x", .out = "o", .op = op });
                try testing.expect(fm.widthsConform(r));
            }
        }
    }
    try v.report("1M");
}

test "a sum that leaves its type is null, never a panic or a wrapped value (sweep W11-3)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const n = 1000;
    for ([_]ColumnType{ .int32, .uint32, .uint64 }) |ty| {
        const x = try constColumn(a, ty, n, true);
        const cols = try a.dupe(Column, &.{.{ .name = "x", .type = ty }});
        const f: Frame = .{ .columns = cols, .data = try a.dupe(ColumnData, &.{x}), .len = n };
        const r = try df.aggregate(a, f, .{ .group_by = &.{}, .aggs = &.{.{ .src = "x", .out = "o", .func = .sum }} });
        try testing.expect(r.columnAt(r.columnIndex("o").?).get(0) == .null);
        const c = try df.window(a, f, .{ .value_col = "x", .out = "o", .op = .cum_sum });
        const last = c.columnAt(c.columnIndex("o").?).get(n - 1);
        try testing.expect(last == .null);
    }
}

// ── (4) cast: every width to every type and back, hostile text ───────────────────

const hostile_texts = [_][]const u8{
    "0",                   "-0",                   "+",                    "",                     "\x00",
    "+5",                  "-",                    "300",                  "-129",                 "256",
    "255",                 "-128",                 "65536",                "4294967296",           "9223372036854775807",
    "9223372036854775808", "18446744073709551615", "18446744073709551616", "-9223372036854775808", "-9223372036854775809",
    "1e3",                 "1.5",                  "nan",                  "NaN",                  "inf",
    "-inf",                "0x10",                 "1_0",                  " 7 ",                  "3.4028236e38",
    "1e39",                "-1e39",                "1e-46",                "0.1",                  "1e400",
    "-1e400",
    "٣",
    "١٢",
    "True",                "false",                "2024-01-01",           "1.0",                  "5.",
    ".5",                  "1e",                   "1e+",                  "e5",                   "00000000000000000000000000000000000000000000001",
};

fn textFrame(a: std.mem.Allocator) !Frame {
    var cells: std.ArrayList(Value) = .empty;
    for (hostile_texts) |t| try cells.append(a, .{ .text = t });
    const d400 = try a.alloc(u8, 400);
    @memset(d400, '9');
    try cells.append(a, .{ .text = d400 });
    const m400 = try a.alloc(u8, 401);
    @memset(m400, '9');
    m400[0] = '-';
    try cells.append(a, .{ .text = m400 });
    const z400 = try a.alloc(u8, 400);
    @memset(z400, '0');
    try cells.append(a, .{ .text = z400 });
    const f400 = try a.alloc(u8, 402);
    @memset(f400, '1');
    f400[200] = '.';
    try cells.append(a, .{ .text = f400 });
    return frameOf(a, &.{.{ "x", .text, cells.items }}, cells.items.len);
}

const OnError = @TypeOf((df.CastSpec{ .col = "x", .to = .int }).on_error);

test "text cells cast to every width in every mode: a value in range, null, or an error (sweep W11-4)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try textFrame(a);
    for (widths ++ [_]ColumnType{ .int, .float, .decimal, .timestamp, .duration, .date, .bool }) |to| {
        for ([_]OnError{ .null, .fail, .wrap }) |oe| {
            const r = df.cast(a, f, .{ .col = "x", .to = to, .on_error = oe }) catch continue;
            try testing.expect(fm.widthsConform(r));
            if (dtype.isInteger(to)) {
                for (0..r.len) |ri| switch (r.columnAt(0).get(ri)) {
                    .int => |i| try testing.expect(dtype.fits(i, to)),
                    .uint => |u| try testing.expect(dtype.fits(u, to) and u > std.math.maxInt(i64)),
                    .null => {},
                    else => return error.WrongKind,
                };
            }
        }
    }
}

test "every width at its edges cast to every type and back (sweep W11-4)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (numerics) |from| {
        const f = try edgeFrame(a, from, 12);
        for (std.enums.values(ColumnType)) |mid| {
            for ([_]OnError{ .null, .fail, .wrap }) |oe| {
                const g = df.cast(a, f, .{ .col = "x", .to = mid, .on_error = oe }) catch continue;
                try testing.expect(fm.widthsConform(g));
                const back = df.cast(a, g, .{ .col = "x", .to = from, .on_error = oe }) catch continue;
                try testing.expect(fm.widthsConform(back));
            }
        }
    }
}

// ── (5) readers and writers with width types ─────────────────────────────────────

const csv_cells = hostile_texts ++ [_][]const u8{ "\"300\"", "\"\"", "NA", "null", "\"1,5\"" };

fn oneColCsv(a: std.mem.Allocator, cell: []const u8) ![]const u8 {
    return std.fmt.allocPrint(a, "x\n{s}\n", .{cell});
}

fn expectCellsFit(f: Frame, ty: ColumnType) !void {
    for (f.columns, 0..) |c, ci| {
        if (c.type != ty) continue;
        for (0..f.len) |ri| switch (f.columnAt(ci).get(ri)) {
            .int => |i| try testing.expect(!dtype.isInteger(ty) or dtype.fits(i, ty)),
            .uint => |u| try testing.expect(ty == .uint64 and u > std.math.maxInt(i64)),
            .float => |x| try testing.expect(ty == .float32 and (std.math.isNan(x) or @as(f64, @as(f32, @floatCast(x))) == x)),
            .null => {},
            else => return error.WrongKind,
        };
    }
}

test "readCsv with a width type reads each hostile cell as a value of the width or an error (sweep W11-5)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (widths) |ty| {
        for (csv_cells) |cell| {
            const bytes = try oneColCsv(a, cell);
            for ([_]bool{ true, false }) |infer| {
                const f = df.readCsv(a, bytes, .{ .types = &.{.{ .name = "x", .type = ty }}, .infer_types = infer }) catch continue;
                try testing.expect(fm.widthsConform(f));
                try expectCellsFit(f, ty);
            }
        }
    }
    var all: std.ArrayList(u8) = .empty;
    try all.appendSlice(a, "x\n");
    for (csv_cells) |c| {
        try all.appendSlice(a, c);
        try all.append(a, '\n');
    }
    for (widths) |ty| {
        const f = df.readCsv(a, all.items, .{ .types = &.{.{ .name = "x", .type = ty }}, .null_values = &.{ "", "NA", "null" } }) catch continue;
        try testing.expect(fm.widthsConform(f));
        try expectCellsFit(f, ty);
    }
    const digits = try a.alloc(u8, 400);
    @memset(digits, '7');
    for (widths) |ty| {
        const bytes = try oneColCsv(a, digits);
        const f = df.readCsv(a, bytes, .{ .types = &.{.{ .name = "x", .type = ty }} }) catch continue;
        try testing.expect(fm.widthsConform(f));
        try expectCellsFit(f, ty);
    }
}

const json_cells = [_][]const u8{
    "300",                 "-129",                     "1e3",                  "1.5",   "\"12\"",       "\"abc\"", "null",
    "true",                "18446744073709551615",     "18446744073709551616", "1e400", "-0",           "0.1",     "[1]",
    "{\"a\":1}",           "-9223372036854775809",     "255",                  "-0.0",  "3.4028236e38", "1e-46",   "\"\"",
    "9223372036854775808", "\"18446744073709551615\"", "1E3",                  "0.0",   "-1",           "[]",      "{}",
};

test "readJson and readNdjson with a width type: values of the width or an error (sweep W11-5)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (widths) |ty| {
        const types: []const df.TypeOverride = &.{.{ .name = "x", .type = ty }};
        for (json_cells) |cell| {
            const rec = try std.fmt.allocPrint(a, "[{{\"x\":{s}}}]", .{cell});
            const col = try std.fmt.allocPrint(a, "{{\"x\":[{s}]}}", .{cell});
            const nd = try std.fmt.allocPrint(a, "{{\"x\":{s}}}\n{{\"x\":null}}\n", .{cell});
            if (df.readJson(a, rec, .{ .types = types })) |f| {
                try testing.expect(fm.widthsConform(f));
                try expectCellsFit(f, ty);
            } else |_| {}
            if (df.readJson(a, col, .{ .types = types, .orient = .columns })) |f| {
                try testing.expect(fm.widthsConform(f));
                try expectCellsFit(f, ty);
            } else |_| {}
            if (df.readNdjson(a, nd, .{ .types = types })) |f| {
                try testing.expect(fm.widthsConform(f));
                try expectCellsFit(f, ty);
            } else |_| {}
        }
        var doc: std.ArrayList(u8) = .empty;
        try doc.append(a, '[');
        for (json_cells, 0..) |c, i| try doc.print(a, "{s}{{\"x\":{s}}}", .{ if (i == 0) "" else ",", c });
        try doc.append(a, ']');
        if (df.readJson(a, doc.items, .{ .types = types })) |f| {
            try testing.expect(fm.widthsConform(f));
            try expectCellsFit(f, ty);
        } else |_| {}
    }
}

test "the chunk readers keep the declared widths whatever a later chunk holds (sweep W11-5)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var all: std.ArrayList(u8) = .empty;
    try all.appendSlice(a, "x,y\n");
    for (csv_cells) |c| try all.print(a, "{s},{s}\n", .{ c, c });
    for (widths) |ty| {
        for ([_]df.ChunkOptions{ .{}, .{ .schema = .per_chunk }, .{ .infer_rows = 2 } }) |copts| {
            for ([_]usize{ 1, 3, 7 }) |n| {
                var r: std.Io.Reader = .fixed(all.items);
                var cr = df.CsvChunkReader.init(testing.allocator, &r, .{ .types = &.{.{ .name = "x", .type = ty }} }, copts) catch continue;
                defer cr.deinit();
                while (true) {
                    const f = (cr.next(a, n) catch break) orelse break;
                    try testing.expect(fm.widthsConform(f));
                    try expectCellsFit(f, ty);
                }
            }
        }
    }
    var nd: std.ArrayList(u8) = .empty;
    for (json_cells) |c| try nd.print(a, "{{\"x\":{s}}}\n", .{c});
    for (widths) |ty| {
        for ([_]usize{ 1, 4, 100 }) |n| {
            var r: std.Io.Reader = .fixed(nd.items);
            var cr = df.NdjsonChunkReader.init(testing.allocator, &r, .{ .types = &.{.{ .name = "x", .type = ty }} });
            defer cr.deinit();
            while (true) {
                const f = (cr.next(a, n) catch break) orelse break;
                try testing.expect(fm.widthsConform(f));
                try expectCellsFit(f, ty);
            }
        }
    }
}

/// `a` and `b` hold the same cells (NaN equals NaN).
fn sameCells(a: Frame, b: Frame) bool {
    if (a.len != b.len or a.columns.len != b.columns.len) return false;
    for (0..a.columns.len) |ci| for (0..a.len) |ri| {
        const x = a.columnAt(ci).get(ri);
        const y = b.columnAt(ci).get(ri);
        if (x == .float and y == .float and std.math.isNan(x.float) and std.math.isNan(y.float)) continue;
        if (x == .float and y == .null and std.math.isNan(x.float)) continue; // NaN is written as the null text
        if (!x.eql(y)) return false;
    };
    return true;
}

test "every width at its edges survives a CSV and a JSON round trip with its type declared (sweep W11-5)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (widths) |ty| {
        const f = try edgeFrame(a, ty, 12);
        const types: []const df.TypeOverride = &.{ .{ .name = "x", .type = ty }, .{ .name = "y", .type = ty } };
        var aw: std.Io.Writer.Allocating = .init(a);
        try df.writeCsv(a, &aw.writer, f, .{ .null_text = "NA" });
        const g = try df.readCsv(a, aw.written(), .{ .types = types, .null_values = &.{"NA"} });
        try testing.expect(fm.widthsConform(g));
        if (!sameCells(f, g)) {
            std.debug.print("csv round trip {s}: {s}\n", .{ @tagName(ty), aw.written() });
            return error.RoundTrip;
        }
        var jw: std.Io.Writer.Allocating = .init(a);
        try df.writeJson(&jw.writer, f, .records);
        const h = try df.readJson(a, jw.written(), .{ .types = types });
        try testing.expect(fm.widthsConform(h));
        if (ty != .float32) try testing.expect(sameCells(f, h));
        var nw: std.Io.Writer.Allocating = .init(a);
        try df.writeNdjson(&nw.writer, f);
        const n = try df.readNdjson(a, nw.written(), .{ .types = types });
        try testing.expect(fm.widthsConform(n));
        if (ty != .float32) try testing.expect(sameCells(f, n));
    }
}

// ── (6) keys: exact comparison across widths ─────────────────────────────────────

test "UInt64 above 2^63 joins, groups, sorts and dedups by its exact value (sweep W11-6)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const two63: u64 = 1 << 63;
    const left = try frameOf(a, &.{
        .{ "k", .uint64, &.{ .{ .uint = two63 }, .{ .uint = std.math.maxInt(u64) }, .{ .uint = big }, iv(5), .null } },
        .{ "l", .int, &.{ iv(1), iv(2), iv(3), iv(4), iv(5) } },
    }, 5);
    const right = try frameOf(a, &.{
        .{ "k", .float, &.{ fv(9223372036854775808.0), fv(18446744073709551616.0), fv(5), fv(nan), .null } },
        .{ "r", .int, &.{ iv(10), iv(20), iv(30), iv(40), iv(50) } },
    }, 5);
    const j = try df.join(a, left, right, .{ .on = "k", .how = .inner, .null_keys = .no_match });
    try testing.expect(fm.widthsConform(j));
    // 2^63 equals the float 2^63, 5 equals 5.0; 2^64-1 is not the float 2^64.
    try testing.expectEqual(@as(usize, 2), j.len);
    const dec = try frameOf(a, &.{
        .{ "k", .decimal, &.{ .{ .decimal = @as(i128, two63) * vm.decimal_scale }, .{ .decimal = @as(i128, std.math.maxInt(u64)) * vm.decimal_scale } } },
        .{ "r", .int, &.{ iv(1), iv(2) } },
    }, 2);
    const jd = try df.join(a, left, dec, .{ .on = "k", .how = .inner });
    try testing.expect(fm.widthsConform(jd));
    try testing.expectEqual(@as(usize, 2), jd.len);
    const g = try df.aggregate(a, left, .{ .group_by = &.{"k"}, .aggs = &.{.{ .src = "l", .out = "n", .func = .count }} });
    try testing.expectEqual(@as(usize, 5), g.len);
    const d = try df.distinct(a, left, .{ .keys = &.{"k"} });
    try testing.expectEqual(@as(usize, 5), d.len);
    const s = try df.sort(a, left, .{ .key = "k" });
    try testing.expect(fm.widthsConform(s));
    try testing.expect(s.columnAt(0).get(0) == .null);
    try testing.expectEqual(@as(i64, 5), s.columnAt(0).get(1).int);
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), s.columnAt(0).get(4).uint);
    const p = try df.pivot(a, left, .{ .row_key = "l", .col_key = "k", .value_col = "l" });
    try testing.expect(fm.widthsConform(p));
    const other = try frameOf(a, &.{ .{ "k", .float, &.{fv(1.5)} }, .{ "l", .int, &.{iv(1)} } }, 1);
    const c = try df.concat(a, &.{ left, other }, .vertical_relaxed);
    try testing.expect(fm.widthsConform(c));
}

test "joins across width types, every pair (sweep W11-6)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (numerics) |ta| for (numerics) |tb| {
        const fa = try edgeFrame(a, ta, 8);
        const fb = try edgeFrame(a, tb, 8);
        for ([_]df.JoinHow{ .inner, .full, .anti }) |how| {
            const j = df.join(a, fa, fb, .{ .on = "x", .how = how, .suffix = "_r" }) catch continue;
            try testing.expect(fm.widthsConform(j));
        }
        const c = df.concat(a, &.{ fa, fb }, .vertical_relaxed) catch continue;
        try testing.expect(fm.widthsConform(c));
        const m = df.mergeOrdered(a, fa, fb, .{ .on = &.{"k"} }) catch continue;
        try testing.expect(fm.widthsConform(m));
    };
}

// ── (2) arithmetic across kinds, ranges and weak literals ────────────────────────

test "every pair of numeric types through every arithmetic operator: the result type holds the cells (sweep W11-2)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const ops = [_]df.Binary{ .add, .sub, .mul, .div, .floordiv, .mod, .pow, .min, .max, .truncdiv, .eq, .lt, .bit_and, .bit_or, .bit_xor, .log_base, .atan2, .fill_nan };
    for (numerics) |ta| for (numerics) |tb| {
        const fa = try edgeFrame(a, ta, 12);
        const fb = try edgeFrame(a, tb, 12);
        const cols = try a.dupe(Column, &.{ .{ .name = "x", .type = ta }, .{ .name = "z", .type = tb } });
        const f: Frame = .{ .columns = cols, .data = try a.dupe(ColumnData, &.{ fa.columnAt(0), fb.columnAt(1) }), .len = 12 };
        const x = try colx(a, "x");
        const z = try colx(a, "z");
        for (ops) |op| {
            const r = df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .binary = .{ .op = op, .l = x, .r = z } } }}) catch continue;
            try testing.expect(fm.widthsConform(r));
            const t = r.columns[2].type;
            if (dtype.isInteger(t)) for (0..r.len) |ri| switch (r.columnAt(2).get(ri)) {
                .int => |i| try testing.expect(dtype.fits(i, t)),
                .uint => |u| if (!dtype.fits(u, t)) {
                    std.debug.print("arith {s} {s} {s} -> {s} cell {d}\n", .{ @tagName(ta), @tagName(tb), @tagName(op), @tagName(t), u });
                    return error.OutOfRange;
                },
                else => {},
            };
        }
    };
}

test "weak literals at the edges of i64 and u64 against every width, with huge exponents and the minimum divided by -1 (sweep W11-2)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const weak = [_]Value{ .{ .uint = 1 << 63 }, .{ .uint = std.math.maxInt(u64) }, iv(std.math.minInt(i64)), iv(-1), iv(0), iv(std.math.maxInt(i64)), .{ .float = 1e19 }, .{ .float = 18446744073709551616.0 } };
    for (numerics) |ty| {
        const f = try edgeFrame(a, ty, 12);
        const x = try colx(a, "x");
        for (weak) |l| {
            const lp = try litx(a, l);
            for ([_]df.Binary{ .add, .sub, .mul, .div, .floordiv, .mod, .pow, .truncdiv, .min, .max }) |op| {
                for ([_]bool{ true, false }) |lit_right| {
                    const e: Expr = if (lit_right) .{ .binary = .{ .op = op, .l = x, .r = lp } } else .{ .binary = .{ .op = op, .l = lp, .r = x } };
                    const r = df.mutate(a, f, &.{.{ .out = "r", .expr = e }}) catch continue;
                    try testing.expect(fm.widthsConform(r));
                }
            }
        }
        for ([_]i64{ 63, 64, 1 << 20, std.math.maxInt(i64), -1, std.math.minInt(i64) }) |p| {
            const pe = try litx(a, iv(p));
            const r = df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .binary = .{ .op = .pow, .l = x, .r = pe } } }}) catch continue;
            try testing.expect(fm.widthsConform(r));
        }
        const m1 = try litx(a, iv(-1));
        const z0 = try litx(a, iv(0));
        for ([_]df.Binary{ .div, .floordiv, .truncdiv, .mod }) |op| {
            for ([_]*const Expr{ m1, z0 }) |d| {
                const r = df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .binary = .{ .op = op, .l = x, .r = d } } }}) catch continue;
                try testing.expect(fm.widthsConform(r));
            }
        }
    }
}

// ── (7) accessors and renderings ─────────────────────────────────────────────────

test "floatColumn, seriesXY, cell and the text renderings read a width column exactly (sweep W11-7)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try frameOf(a, &.{
        .{ "u", .uint64, &.{ .{ .uint = std.math.maxInt(u64) }, iv(0), .null } },
        .{ "f", .float32, &.{ fv(0.1), fv(inf), fv(nan) } },
        .{ "i", .int8, &.{ iv(-128), iv(127), .null } },
    }, 3);
    const fc = try f.floatColumn(a, "u");
    try testing.expectEqual(@as(f64, 18446744073709551615.0), fc[0]);
    try testing.expectEqual(@as(f64, 0), fc[2]);
    const fl = try f.floatColumn(a, "f");
    try testing.expectEqual(@as(f64, @as(f32, 0.1)), fl[0]);
    const xy = try f.seriesXY(a, "i", "u");
    try testing.expectEqual(@as(f64, -128), xy[0][0]);
    try testing.expect(f.cell(0, "u").?.uint == std.math.maxInt(u64));
    try testing.expect(f.cell(3, "u") == null);
    const txt = try df.format(a, f, .{});
    try testing.expect(std.mem.indexOf(u8, txt, "18446744073709551615") != null);
    try testing.expect(std.mem.indexOf(u8, txt, "0.1") != null);
    const gl = try df.glimpse(a, f, .{});
    try testing.expect(std.mem.indexOf(u8, gl, "u64") != null);
}

test "a Float32 column holding an f64 past f32's range renders and writes as infinity or null (sweep W11-7)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const vals = try a.dupe(f64, &.{ 1e300, -1e300, 0.1, 3.4028235e38 });
    const cols = try a.dupe(Column, &.{.{ .name = "x", .type = .float32 }});
    const f: Frame = .{ .columns = cols, .data = try a.dupe(ColumnData, &.{.{ .float = .{ .values = vals } }}), .len = 4 };
    const txt = try df.format(a, f, .{});
    try testing.expect(std.mem.indexOf(u8, txt, "inf") != null);
    var cw: std.Io.Writer.Allocating = .init(a);
    try df.writeCsv(a, &cw.writer, f, .{});
    try testing.expect(std.mem.indexOf(u8, cw.written(), "inf") != null);
    var jw: std.Io.Writer.Allocating = .init(a);
    try df.writeJson(&jw.writer, f, .records);
    try testing.expect(std.mem.indexOf(u8, jw.written(), "null") != null);
    try testing.expect(std.mem.indexOf(u8, jw.written(), "inf") == null);
}

test "replace over a width column whose replacement does not fit leaves a conforming column (sweep W11-8)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try frameOf(a, &.{.{ "x", .int8, &.{ iv(1), iv(2), .null } }}, 3);
    const r = try df.replace(a, f, .{ .col = "x", .pairs = &.{ .{ .from = iv(1), .to = iv(300) }, .{ .from = iv(2), .to = fv(0.5) }, .{ .from = .null, .to = iv(-7) } } });
    try testing.expect(fm.widthsConform(r));
    try testing.expect(r.columnAt(0) == .int8);
    try testing.expect(r.columnAt(0).get(0) == .null); // 300 is not an Int8
    try testing.expect(r.columnAt(0).get(1) == .null); // 0.5 is not whole
    try testing.expectEqual(@as(i64, -7), r.columnAt(0).get(2).int);
}

// ── the independent review's findings (2026-11-10), each pinned (sweep W11-9) ────

fn cellAt(f: Frame, name: []const u8, i: usize) Value {
    return f.columnAt(f.columnIndex(name).?).get(i);
}

test "a Float32 column that a verb filled with an f64 past f32's range still renders and writes (sweep W11-9 H1)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // (a) replace, (c) replaceStrict: the replacement 1e300 is no Float32.
    const f = try frameOf(a, &.{.{ "x", .float32, &.{ fv(1.0), fv(2.0), .null } }}, 3);
    const r1 = try df.replace(a, f, .{ .col = "x", .pairs = &.{.{ .from = fv(1.0), .to = fv(1e300) }} });
    const r2 = try df.replaceStrict(a, f, .{ .col = "x", .pairs = &.{.{ .from = fv(1.0), .to = fv(1e300) }}, .default = fv(-1e300) });
    // (b) topN with a tail: 3e38 three times sums to 6e38 in an f64.
    const g = try frameOf(a, &.{ .{ "x", .float32, &.{ fv(3e38), fv(3e38), fv(3e38) } }, .{ "l", .text, &.{ .{ .text = "a" }, .{ .text = "b" }, .{ .text = "c" } } } }, 3);
    const r3 = try df.topN(a, g, .{ .n = 1, .tail = .{ .label_col = "l", .label = "rest", .value_col = "x" } });
    for ([_]Frame{ r1, r2, r3 }) |r| {
        try testing.expect(fm.widthsConform(r));
        const txt = try df.format(a, r, .{});
        try testing.expect(txt.len > 0);
        var cw: std.Io.Writer.Allocating = .init(a);
        try df.writeCsv(a, &cw.writer, r, .{});
        var jw: std.Io.Writer.Allocating = .init(a);
        try df.writeJson(&jw.writer, r, .records);
        var nw: std.Io.Writer.Allocating = .init(a);
        try df.writeNdjson(&nw.writer, r);
    }
}

test "a whole float near 2^127 in an integer-declared column does not overflow the width arithmetic (sweep W11-9 H2)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const vals = try a.dupe(f64, &.{ -1.7014118346046923e38, 1.7014118346046923e38, -9.223372036854775808e18, 5, 1e30 });
    const cols = try a.dupe(Column, &.{.{ .name = "x", .type = .int8 }});
    const f: Frame = .{ .columns = cols, .data = try a.dupe(ColumnData, &.{.{ .float = .{ .values = vals } }}), .len = 5 };
    const x = try colx(a, "x");
    const m1 = try litx(a, iv(-1));
    const big_pos = try litx(a, fv(8.507059173023462e37)); // 2^126
    for ([_]df.Unary{ .neg, .abs, .sign, .bit_not }) |u| {
        _ = df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .unary = .{ .op = u, .x = x } } }}) catch {};
    }
    for ([_]df.Binary{ .floordiv, .truncdiv, .mod, .add, .sub, .mul, .div }) |op| {
        for ([_]*const Expr{ m1, big_pos, x }) |d| {
            _ = df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .binary = .{ .op = op, .l = x, .r = d } } }}) catch {};
            _ = df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .binary = .{ .op = op, .l = d, .r = x } } }}) catch {};
        }
    }
    const w = try df.window(a, f, .{ .value_col = "x", .out = "d", .op = .{ .diff = 1 } });
    try testing.expect(cellAt(w, "d", 1) == .null);
    // The same state through the public verbs: replace writes the huge float into an Int8 column.
    const i8f = try frameOf(a, &.{.{ "x", .int8, &.{ iv(1), iv(2) } }}, 2);
    const rep = try df.replace(a, i8f, .{ .col = "x", .pairs = &.{.{ .from = iv(1), .to = fv(-1.7014118346046923e38) }} });
    try testing.expect(fm.widthsConform(rep));
    _ = try df.mutate(a, rep, &.{.{ .out = "r", .expr = .{ .unary = .{ .op = .neg, .x = x } } }});
}

test "unpivot of a width column with a text column keeps the text (sweep W11-9 M2)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try frameOf(a, &.{ .{ "a", .int8, &.{ iv(1), iv(2) } }, .{ "b", .text, &.{ .{ .text = "p" }, .{ .text = "q" } } } }, 2);
    const u = try df.unpivot(a, f, .{ .id_cols = &.{} });
    try testing.expect(fm.widthsConform(u));
    try testing.expectEqual(@as(usize, 4), u.len);
    try testing.expectEqualStrings("p", cellAt(u, "value", 1).text);
    try testing.expectEqual(@as(i64, 2), cellAt(u, "value", 2).int);
    const g = try frameOf(a, &.{ .{ "a", .float32, &.{fv(1.5)} }, .{ "b", .text, &.{.{ .text = "z" }} } }, 1);
    const ug = try df.unpivot(a, g, .{ .id_cols = &.{} });
    try testing.expectEqualStrings("z", cellAt(ug, "value", 1).text);
    try testing.expectEqual(@as(f64, 1.5), cellAt(ug, "value", 0).float);
}

test "aggregate with fx over an integer width keeps the converted cell (sweep W11-9 M3)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try frameOf(a, &.{
        .{ "g", .int, &.{ iv(1), iv(1) } },
        .{ "x", .int8, &.{ iv(3), iv(5) } },
        .{ "rate", .float, &.{ fv(1.5), fv(1.5) } },
    }, 2);
    for ([_]df.AggFn{ .min, .max, .first, .last, .mode }) |fnn| {
        const r = try df.aggregate(a, f, .{ .group_by = &.{"g"}, .aggs = &.{.{ .src = "x", .out = "o", .func = fnn }}, .fx = .{ .rate_col = "rate" } });
        try testing.expect(fm.widthsConform(r));
        const c = cellAt(r, "o", 0);
        try testing.expect(c == .float and (c.float == 4.5 or c.float == 7.5));
    }
}

test "frame arithmetic on a Float32 column divides to Float32 as Expr does (sweep W11-9 M4)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try frameOf(a, &.{.{ "x", .float32, &.{ fv(1), fv(0.1), .null } }}, 3);
    const s = try df.arithScalar(a, f, .div, iv(3), .{});
    try testing.expectEqual(ColumnType.float32, s.columns[0].type);
    try testing.expect(fm.widthsConform(s));
    const e = try df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .binary = .{ .op = .div, .l = try colx(a, "x"), .r = try litx(a, iv(3)) } } }});
    try testing.expectEqual(e.columns[1].type, s.columns[0].type);
    try testing.expectEqual(cellAt(e, "r", 1).float, cellAt(s, "x", 1).float);
    const g = try df.arith(a, f, f, .div, .{});
    try testing.expectEqual(ColumnType.float32, g.columns[0].type);
    // Float32 over Int32 is Float64, as in Expr.
    const h = try frameOf(a, &.{.{ "x", .int32, &.{ iv(1), iv(2), iv(3) } }}, 3);
    const gh = try df.arith(a, f, h, .div, .{});
    try testing.expectEqual(ColumnType.float, gh.columns[0].type);
}

test "wideToLong holds a UInt64 above Int64's top in a Float64 stub as a float (sweep W11-9 M5)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try frameOf(a, &.{
        .{ "id", .int, &.{iv(1)} },
        .{ "A1", .int, &.{iv(7)} },
        .{ "A2", .uint64, &.{.{ .uint = big }} },
    }, 1);
    const r = try df.wideToLong(a, f, .{ .stubnames = &.{"A"}, .i = &.{"id"}, .j = "t" });
    try testing.expect(fm.widthsConform(r));
    const ai = r.columnIndex("A").?;
    for (0..r.len) |ri| try testing.expect(r.columnAt(ai).get(ri) != .uint or r.columns[ai].type == .uint64);
}

test "UInt64 above Int64's top in sum_exact, horizontal, eq_missing and a list sum (sweep W11-9 L1)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try frameOf(a, &.{
        .{ "u", .uint64, &.{ .{ .uint = big }, iv(1) } },
        .{ "v", .uint64, &.{ iv(0), .{ .uint = big } } },
        .{ "k", .int, &.{ iv(0), iv(0) } },
    }, 2);
    const s = try df.aggregate(a, f, .{ .group_by = &.{"k"}, .aggs = &.{.{ .src = "u", .out = "s", .func = .sum_exact }} });
    // big + 1 as an exact decimal: the cell is not dropped.
    try testing.expectEqual(@as(i128, big + 1) * vm.decimal_scale, cellAt(s, "s", 0).decimal);
    const h = try df.horizontal(a, f, .{ .cols = &.{ "u", "v" }, .func = .any, .out = "o" });
    try testing.expect(cellAt(h, "o", 0).bool);
    const hall = try df.horizontal(a, f, .{ .cols = &.{ "u", "v" }, .func = .all, .out = "o" });
    try testing.expect(!cellAt(hall, "o", 0).bool); // v is 0 in row 0
    try testing.expect(cellAt(hall, "o", 1).bool);
    const mx = try df.horizontal(a, f, .{ .cols = &.{ "u", "v" }, .func = .max, .out = "o" });
    try testing.expect(fm.widthsConform(mx));
    try testing.expectEqual(big, cellAt(mx, "o", 0).uint);
    const sm = try df.horizontal(a, f, .{ .cols = &.{ "u", "v" }, .func = .sum, .out = "o" });
    try testing.expect(fm.widthsConform(sm));
    const eq = try df.mutate(a, f, &.{.{ .out = "r", .expr = .{ .binary = .{ .op = .eq_missing, .l = try litx(a, .{ .uint = 1 << 63 }), .r = try litx(a, fv(9223372036854775808.0)) } } }});
    if (cellAt(eq, "r", 0) != .bool or !cellAt(eq, "r", 0).bool) {
        std.debug.print("eq_missing cell {any}\n", .{cellAt(eq, "r", 0)});
        return error.EqMissing;
    }
}

test "scatter of 0.1 into a Float32 column rounds it as cast does (sweep W11-9 L2)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try frameOf(a, &.{.{ "x", .float32, &.{ fv(1), fv(2) } }}, 2);
    const r = try df.scatter(a, f, .{ .col = "x", .idx = &.{0}, .values = &.{fv(0.1)} });
    try testing.expect(fm.widthsConform(r));
    try testing.expectEqual(@as(f64, @as(f32, 0.1)), cellAt(r, "x", 0).float);
}

test "joining a width key to a text key keeps every key (sweep W11-9 L3)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const l = try frameOf(a, &.{ .{ "k", .int8, &.{ iv(1), iv(2) } }, .{ "l", .int, &.{ iv(1), iv(2) } } }, 2);
    const r = try frameOf(a, &.{ .{ "k", .text, &.{ .{ .text = "a" }, .{ .text = "b" } } }, .{ "r", .int, &.{ iv(1), iv(2) } } }, 2);
    for ([_]df.JoinHow{ .inner, .left, .right, .full }) |how| {
        const j = df.join(a, l, r, .{ .on = "k", .how = how, .coalesce_keys = true }) catch continue;
        try testing.expect(fm.widthsConform(j));
        if (how == .right or how == .full) {
            // The right-only keys are the texts "a" and "b", not nulls.
            var texts: usize = 0;
            for (0..j.len) |ri| texts += @intFromBool(cellAt(j, "k", ri) == .text);
            if (texts != 2) {
                std.debug.print("join {s}: {d} text keys of {d} rows\n", .{ @tagName(how), texts, j.len });
                return error.KeysLost;
            }
        }
    }
}
