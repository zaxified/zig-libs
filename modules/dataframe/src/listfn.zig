// SPDX-License-Identifier: MIT
//! The cell functions of the `list` and `struct` namespaces (S3 step 3, 2026-11-08):
//! polars' `list.*` and `struct.field`, the constructors `concat_list` and `struct`, and
//! the text functions whose result is a list (`str.split`, regex `extract_all`/`split`)
//! or a record (regex `extract_groups`). pandas has no list namespace of its own (its
//! `Series.list` accessor over Arrow lists has `len`, `[i]` and `flatten`), so polars'
//! documented behaviour is the reference here; where this module's rule differs, the
//! function says so. Each takes `Value`s and returns a `Value`; a result list or record
//! is built in the allocator given (the evaluator's budget), and `mutate` copies it into
//! the output column. Original work of the zig-libs authors (MIT).

const std = @import("std");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const keys = @import("keys.zig");
const core = @import("core.zig");
const fnx = @import("exprfn.zig");
const Value = vm.Value;
const isMissing = keys.isMissing;

pub const Error = error{ OutOfMemory, TooLarge };

/// One `list.*` function. A cell that is not a list (null, or any other kind) gives null.
/// "Missing" is null or NaN, as in every reduction of this module: the reductions skip
/// both (polars skips null but lets a NaN through `sum`/`mean`/`std`; pandas' `skipna`
/// skips NaN too).
pub const ListOp = union(enum) {
    /// The element count, null elements included (polars `list.len`).
    len,
    /// Element `i`, negative from the end; out of range null (polars `list.get(i,
    /// null_on_oob=True)`; its default raises, which a per-cell function cannot).
    get: i64,
    first,
    last,
    /// Whether an element equals `item` (`Value.eql`); a null `item` asks for a null
    /// element (polars `list.contains(item, nulls_equal=True)`).
    contains: Value,
    /// How many elements equal `item`, with `contains`' rule (polars `list.count_matches`).
    count_matches: Value,
    /// The text elements with `sep` between (polars `list.join`). A null element is
    /// left out with `ignore_nulls`, else the result is null; a non-text element makes
    /// the result null (polars refuses a list of anything but text).
    join: struct { sep: []const u8 = "", ignore_nulls: bool = true },
    /// Sum of the present numbers: an int list stays int (null on overflow, as `mutate`'s
    /// arithmetic), a decimal one decimal, any float float; bools count 1 and 0; an empty
    /// list 0 (polars); a text element null.
    sum,
    /// Mean of the present numbers; none: null.
    mean,
    /// Least / greatest present element by `Value.order` (polars ignores NaN here too).
    min,
    max,
    median,
    /// Sample standard deviation / variance, divisor `n - ddof` (polars `ddof`, default 1).
    std: u32,
    @"var": u32,
    /// Distinct elements, missing counted as one value (polars `list.n_unique`).
    n_unique,
    /// Position of the first least / greatest present element; none: null.
    arg_min,
    arg_max,
    /// Over bool elements, nulls skipped: an empty list is `any` false, `all` true; a
    /// non-bool element makes the result null.
    any,
    all,
    reverse,
    /// Stable, by `Value.order` (NaN after every number); nulls first unless
    /// `nulls_last` (polars `list.sort(descending, nulls_last)`).
    sort: struct { descending: bool = false, nulls_last: bool = false },
    /// The distinct elements in the order they first appear (polars
    /// `list.unique(maintain_order=True)`), missing as one value.
    unique,
    drop_nulls,
    /// `length` elements from `offset` (negative from the end), polars `list.slice`.
    slice: struct { offset: i64, length: ?usize = null },
    /// The first / last `n` elements (polars `list.head`/`list.tail`).
    head: usize,
    tail: usize,
};

/// `op` over the cell `v`.
pub fn listCell(a: std.mem.Allocator, v: Value, op: ListOp) Error!Value {
    if (v != .list) return .null;
    const l = v.list;
    const n = l.len();
    switch (op) {
        .len => return .{ .int = @intCast(n) }, // a view's length is a u32 difference
        .get => |i| return if (resolveIndex(i, n)) |k| l.get(k) else .null,
        .first => return if (n == 0) .null else l.get(0),
        .last => return if (n == 0) .null else l.get(n - 1),
        .contains => |item| {
            for (0..n) |i| if (matches(l.get(i), item)) return .{ .bool = true };
            return .{ .bool = false };
        },
        .count_matches => |item| {
            var c: i64 = 0;
            for (0..n) |i| c += @intFromBool(matches(l.get(i), item));
            return .{ .int = c };
        },
        .join => |j| return join(a, l, j.sep, j.ignore_nulls),
        .sum => return sum(l),
        .mean => {
            var s: f64 = 0;
            var c: usize = 0;
            for (0..n) |i| switch (number(l.get(i))) {
                .missing => {},
                .not_a_number => return .null,
                .x => |x| {
                    s += x;
                    c += 1;
                },
            };
            return if (c == 0) .null else .{ .float = s / @as(f64, @floatFromInt(c)) };
        },
        .min, .max => {
            var best: ?Value = null;
            for (0..n) |i| {
                const e = l.get(i);
                if (isMissing(e)) continue;
                if (best == null or e.order(best.?) == (if (op == .min) std.math.Order.lt else .gt)) best = e;
            }
            return best orelse .null;
        },
        .arg_min, .arg_max => {
            var best: ?usize = null;
            for (0..n) |i| {
                const e = l.get(i);
                if (isMissing(e)) continue;
                if (best == null or e.order(l.get(best.?)) == (if (op == .arg_min) std.math.Order.lt else .gt)) best = i;
            }
            return if (best) |b| .{ .int = @intCast(b) } else .null;
        },
        .median => {
            const xs = try a.alloc(f64, n);
            defer a.free(xs);
            var c: usize = 0;
            for (0..n) |i| switch (number(l.get(i))) {
                .missing => {},
                .not_a_number => return .null,
                .x => |x| {
                    xs[c] = x;
                    c += 1;
                },
            };
            return core.quantileInterp(xs[0..c], 0.5, .linear);
        },
        .std, .@"var" => |ddof| {
            var m: core.Moments = .{};
            for (0..n) |i| switch (number(l.get(i))) {
                .missing => {},
                .not_a_number => return .null,
                .x => |x| m.add2(x),
            };
            return core.momentResult(m, if (op == .std) .std else .@"var", ddof);
        },
        .n_unique => {
            const first = try a.alloc(bool, n);
            defer a.free(first);
            return .{ .int = @intCast(try markFirsts(a, l, first)) };
        },
        .any, .all => {
            var res = op == .all;
            for (0..n) |i| {
                const e = l.get(i);
                if (e == .null) continue;
                if (e != .bool) return .null;
                if (op == .any) res = res or e.bool else res = res and e.bool;
            }
            return .{ .bool = res };
        },
        // Contiguous pieces are views of the same elements: no copy.
        .slice => |s| {
            const b = sliceBounds(s.offset, s.length, n);
            return view(l, b[0], b[1]);
        },
        .head => |k| return view(l, 0, @min(k, n)),
        .tail => |k| return view(l, n - @min(k, n), n),
        .reverse, .sort, .unique, .drop_nulls => {
            const cells = try a.alloc(Value, n);
            defer a.free(cells);
            var m: usize = 0;
            switch (op) {
                .reverse => {
                    for (cells, 0..) |*c, i| c.* = l.get(n - 1 - i);
                    m = n;
                },
                .sort => |s| {
                    for (cells, 0..) |*c, i| c.* = l.get(i);
                    m = n;
                    sortCells(cells, s.descending, s.nulls_last);
                },
                .unique => {
                    const first = try a.alloc(bool, n);
                    defer a.free(first);
                    _ = try markFirsts(a, l, first);
                    for (first, 0..) |is_first, i| if (is_first) {
                        cells[m] = l.get(i);
                        m += 1;
                    };
                },
                .drop_nulls => for (0..n) |i| {
                    const e = l.get(i);
                    if (e == .null) continue;
                    cells[m] = e;
                    m += 1;
                },
                else => unreachable, // the prong names these four
            }
            return makeList(a, cells[0..m]);
        },
    }
}

/// `i` as a position in a list of `n`, negative from the end; null out of range.
fn resolveIndex(i: i64, n: usize) ?usize {
    if (i >= 0) {
        const u: u64 = @intCast(i);
        return if (u < n) @intCast(u) else null;
    }
    const back: u64 = @abs(i);
    return if (back <= n) n - @as(usize, @intCast(back)) else null;
}

/// `slice`'s `[start, stop)` in a list of `n`: polars' `slice_offsets` — a negative offset
/// counts from the end, the stop is the start plus `length` BEFORE both are clamped into
/// `0..n` (so `slice(-10, 3)` of 3 elements is empty; review R2 L4). No length: to the end.
fn sliceBounds(offset: i64, length: ?usize, n: usize) [2]usize {
    const len_n: i128 = @intCast(n);
    const start: i128 = if (offset < 0) @as(i128, offset) + len_n else offset;
    const stop: i128 = if (length) |l| start + @as(i128, @intCast(l)) else len_n;
    const lo = std.math.clamp(start, 0, len_n);
    const hi = std.math.clamp(stop, lo, len_n);
    return .{ @intCast(lo), @intCast(hi) };
}

fn view(l: vm.ListView, lo: usize, hi: usize) Value {
    // `lo <= hi <= l.len()`, which is a u32 difference: the sums fit u32.
    return .{ .list = .{ .items = l.items, .start = l.start + @as(u32, @intCast(lo)), .end = l.start + @as(u32, @intCast(hi)) } };
}

fn matches(e: Value, item: Value) bool {
    if (item == .null) return e == .null;
    return e.eql(item);
}

/// An element as a reduction reads it: a number (a bool as 1 or 0), missing (null, NaN),
/// or anything else, which makes every numeric reduction null, as `sum` (review R2 L7).
fn number(e: Value) union(enum) { x: f64, missing, not_a_number } {
    if (isMissing(e)) return .missing;
    return switch (e) {
        .bool => |b| .{ .x = if (b) 1 else 0 },
        else => if (e.asFloat()) |x| .{ .x = x } else .not_a_number,
    };
}

fn sum(l: vm.ListView) Value {
    var kind: enum { int, decimal, float } = .int;
    var si: i64 = 0;
    var sd: i128 = 0;
    var sf: f64 = 0;
    // Sticky, per running total: the int one decides an int list, the decimal one (which
    // also holds every int, scaled) a list with a decimal in it.
    var over_i = false;
    var over_d = false;
    for (0..l.len()) |i| {
        const e = l.get(i);
        if (isMissing(e)) continue;
        switch (e) {
            .int, .bool => {
                const x: i64 = if (e == .int) e.int else @intFromBool(e.bool);
                const r = @addWithOverflow(si, x);
                si = r[0];
                over_i = over_i or r[1] != 0;
                sf += @floatFromInt(x);
                const d = @addWithOverflow(sd, @as(i128, x) * vm.decimal_scale); // |x| < 2^63, scale < 2^40
                sd = d[0];
                over_d = over_d or d[1] != 0;
            },
            .decimal => |x| {
                if (kind == .int) kind = .decimal;
                const d = @addWithOverflow(sd, x);
                sd = d[0];
                over_d = over_d or d[1] != 0;
                sf += e.asFloat().?;
            },
            .float => |x| {
                kind = .float;
                sf += x;
            },
            else => return .null,
        }
    }
    return switch (kind) {
        .int => if (over_i) .null else .{ .int = si },
        .decimal => if (over_d) .null else .{ .decimal = sd },
        .float => .{ .float = sf },
    };
}

fn join(a: std.mem.Allocator, l: vm.ListView, sep: []const u8, ignore_nulls: bool) Error!Value {
    var total: usize = 0;
    var parts: usize = 0;
    for (0..l.len()) |i| {
        const e = l.get(i);
        if (e == .null) {
            if (!ignore_nulls) return .null;
            continue;
        }
        if (e != .text) return .null;
        total +|= e.text.len;
        parts += 1;
    }
    if (parts > 1) total +|= (parts - 1) *| sep.len;
    if (total > fnx.max_text_result) return error.TooLarge;
    const out = try a.alloc(u8, total);
    var at: usize = 0;
    var first = true;
    for (0..l.len()) |i| {
        const e = l.get(i);
        if (e != .text) continue;
        if (!first) {
            @memcpy(out[at..][0..sep.len], sep);
            at += sep.len;
        }
        first = false;
        @memcpy(out[at..][0..e.text.len], e.text);
        at += e.text.len;
    }
    return .{ .text = out };
}

fn sortCells(cells: []Value, descending: bool, nulls_last: bool) void {
    const Ctx = struct {
        desc: bool,
        nulls_last: bool,
        fn lessThan(c: @This(), x: Value, y: Value) bool {
            const xn = x == .null;
            const yn = y == .null;
            if (xn or yn) return if (c.nulls_last) !xn and yn else xn and !yn;
            const o = x.order(y);
            return if (c.desc) o == .gt else o == .lt;
        }
    };
    std.mem.sort(Value, cells, Ctx{ .desc = descending, .nulls_last = nulls_last }, Ctx.lessThan);
}

/// Which elements of `l` are the first of their canonical key (missing as one value):
/// `first[i]` set for those. The keys are sorted, not hashed, so everything this
/// allocates is freed before it returns (a cell function runs once per row, and the
/// module's hash table is built for a call's arena). Returns the distinct count.
fn markFirsts(a: std.mem.Allocator, l: vm.ListView, first: []bool) Error!usize {
    const n = l.len();
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(a);
    const offs = try a.alloc(usize, n + 1);
    defer a.free(offs);
    for (0..n) |i| {
        offs[i] = buf.items.len;
        try keys.encode(a, &buf, l.get(i), .as_null);
    }
    offs[n] = buf.items.len;
    const order = try a.alloc(u32, n);
    defer a.free(order);
    for (order, 0..) |*o, i| o.* = @intCast(i); // n is a u32 difference
    const Ctx = struct {
        bytes: []const u8,
        offs: []const usize,
        fn key(c: @This(), i: u32) []const u8 {
            return c.bytes[c.offs[i]..c.offs[i + 1]];
        }
        fn lessThan(c: @This(), x: u32, y: u32) bool {
            return switch (std.mem.order(u8, c.key(x), c.key(y))) {
                .lt => true,
                .gt => false,
                .eq => x < y, // equal keys by position: the first comes first
            };
        }
    };
    const ctx: Ctx = .{ .bytes = buf.items, .offs = offs };
    std.sort.pdq(u32, order, ctx, Ctx.lessThan);
    @memset(first, false);
    var count: usize = 0;
    for (order, 0..) |o, k| {
        if (k == 0 or !std.mem.eql(u8, ctx.key(o), ctx.key(order[k - 1]))) {
            first[o] = true;
            count += 1;
        }
    }
    return count;
}

/// A list cell holding `cells` (copied, text included).
pub fn makeList(a: std.mem.Allocator, cells: []const Value) Error!Value {
    if (cells.len > std.math.maxInt(u32)) return error.TooLarge;
    // The text reservation is what the cells hold, not the builder's guess from the first
    // one (which reserved up to 1 MiB per list cell, review R2 L2).
    var text: usize = 0;
    for (cells) |c| if (c == .text) {
        text +|= c.text.len;
    };
    var b: fm.ColBuilder = .{ .a = a, .hint = cells.len, .depth = 1, .text_cap = text };
    for (cells) |c| try b.append(c);
    const items = try a.create(fm.ColumnData);
    items.* = b.finish();
    return .{ .list = .{ .items = items, .start = 0, .end = @intCast(cells.len) } };
}

/// polars `concat_list`: the elements of each part in order, a part that is not a list
/// one element; a null part makes the result null (polars).
pub fn concatList(a: std.mem.Allocator, parts: []const Value) Error!Value {
    var total: usize = 0;
    for (parts) |p| {
        if (p == .null) return .null;
        total += if (p == .list) p.list.len() else 1;
    }
    if (total > std.math.maxInt(u32)) return error.TooLarge;
    var text: usize = 0;
    for (parts) |p| switch (p) {
        .text => |t| text +|= t.len,
        .list => |l| for (0..l.len()) |i| {
            const e = l.get(i);
            if (e == .text) text +|= e.text.len;
        },
        else => {},
    };
    var b: fm.ColBuilder = .{ .a = a, .hint = total, .depth = 1, .text_cap = text };
    for (parts) |p| {
        if (p == .list) {
            for (0..p.list.len()) |i| try b.append(p.list.get(i));
        } else try b.append(p);
    }
    const items = try a.create(fm.ColumnData);
    items.* = b.finish();
    return .{ .list = .{ .items = items, .start = 0, .end = @intCast(total) } };
}

/// A record cell with fields `names` holding `vals` (copied). `names` is borrowed.
pub fn makeRecord(a: std.mem.Allocator, names: []const []const u8, vals: []const Value) Error!Value {
    const children = try a.alloc(fm.ColumnData, vals.len);
    for (children, vals) |*c, v| {
        var b: fm.ColBuilder = .{ .a = a, .hint = 1, .depth = 1 };
        try b.append(v);
        c.* = b.finish();
    }
    const st = try a.create(fm.StructColumn);
    st.* = .{ .names = names, .children = children, .len = 1 };
    return .{ .record = .{ .fields = st, .row = 0 } };
}

/// polars `struct.field(name)`: the field of a record cell; null when the cell is not a
/// record or has no such field.
pub fn field(v: Value, name: []const u8) Value {
    if (v != .record) return .null;
    return v.record.field(name) orelse .null;
}

/// polars `str.split(by, inclusive)`, pandas `str.split(pat, n, regex=False)`: the pieces
/// of `t` between the occurrences of `by` (each piece keeps its separator with
/// `inclusive`), at most `limit` of them, the last the unsplit rest (pandas' `n` is
/// `limit - 1`). An empty `by` splits into characters (polars). "" is one empty piece.
pub fn splitLiteral(a: std.mem.Allocator, t: []const u8, by: []const u8, inclusive: bool, limit: ?usize) Error!Value {
    var pieces: std.ArrayList(Value) = .empty;
    defer pieces.deinit(a);
    const max = limit orelse std.math.maxInt(usize);
    if (by.len == 0) {
        const starts = try fnx.charStarts(a, t);
        defer a.free(starts);
        const chars = starts.len - 1;
        if (chars == 0) {
            try pieces.append(a, .{ .text = t });
            return makeList(a, pieces.items);
        }
        var i: usize = 0;
        while (i < chars) : (i += 1) {
            if (pieces.items.len + 1 == max) {
                try pieces.append(a, .{ .text = t[starts[i]..] });
                break;
            }
            try pieces.append(a, .{ .text = t[starts[i]..starts[i + 1]] });
        }
        return makeList(a, pieces.items);
    }
    var at: usize = 0;
    while (true) {
        if (pieces.items.len + 1 == max) break;
        const hit = std.mem.findPos(u8, t, at, by) orelse break;
        try pieces.append(a, .{ .text = t[at..if (inclusive) hit + by.len else hit] });
        at = hit + by.len;
    }
    try pieces.append(a, .{ .text = t[at..] });
    return makeList(a, pieces.items);
}

test "listfn: index and offset resolution" {
    try std.testing.expectEqual(@as(?usize, 0), resolveIndex(0, 3));
    try std.testing.expectEqual(@as(?usize, 2), resolveIndex(-1, 3));
    try std.testing.expectEqual(@as(?usize, 0), resolveIndex(-3, 3));
    try std.testing.expectEqual(@as(?usize, null), resolveIndex(-4, 3));
    try std.testing.expectEqual(@as(?usize, null), resolveIndex(3, 3));
    try std.testing.expectEqual(@as(?usize, null), resolveIndex(std.math.minInt(i64), 3));
    try std.testing.expectEqual(@as(?usize, null), resolveIndex(std.math.maxInt(i64), 3));
    const B = [2]usize;
    try std.testing.expectEqual(B{ 3, 3 }, sliceBounds(std.math.maxInt(i64), null, 3));
    try std.testing.expectEqual(B{ 0, 3 }, sliceBounds(std.math.minInt(i64), null, 3));
    try std.testing.expectEqual(B{ 0, 2 }, sliceBounds(std.math.minInt(i64), std.math.maxInt(usize) >> 1, 3)); // -2^63 + 3 + 2^63 - 1
    try std.testing.expectEqual(B{ 1, 3 }, sliceBounds(-2, null, 3));
    // polars: slice(-10, 3) of 3 elements is empty, slice(-5, 3) of 4 is the first two.
    try std.testing.expectEqual(B{ 0, 0 }, sliceBounds(-10, 3, 3));
    try std.testing.expectEqual(B{ 0, 2 }, sliceBounds(-5, 3, 4));
    try std.testing.expectEqual(B{ 1, 3 }, sliceBounds(1, std.math.maxInt(usize), 3));
}
