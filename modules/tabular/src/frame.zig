// SPDX-License-Identifier: MIT
//! The verbs on `dataset.Frame`, the columnar table. Same specs and the same answers,
//! cell for cell, as their row versions in `transforms` and `series`, which are this
//! file's differential oracle (`frame_test.zig`): a verb here must never change what a
//! table means, only what it costs. A column of mixed kinds is `.boxed` and takes the
//! same path through `Value`, so nothing is refused for being untyped.
//!
//! **A result borrows from its input.** Untouched columns are shared, not copied, so the
//! input (and the spec's names) must stay alive as long as the result. Same arena rule as
//! the rest of the module: temporaries are freed, a result has no `deinit`.

const std = @import("std");
const ds = @import("dataset");
const keys = @import("keys.zig");
const series = @import("series.zig");
const transforms = @import("transforms.zig");
const Column = ds.Column;
const ColumnData = ds.ColumnData;
const Frame = ds.Frame;
const Value = ds.Value;

pub const Error = series.Error;

fn mustIndex(f: Frame, name: []const u8) Error!usize {
    return f.columnIndex(name) orelse error.NoSuchColumn;
}

/// A hand-built frame may have fewer arrays than columns: those read as null.
inline fn colOf(f: Frame, ci: usize) ColumnData {
    return if (ci < f.data.len) f.data[ci] else .nulls;
}

fn bitsLen(rows: usize) usize {
    return rows / 64 + @intFromBool(rows % 64 != 0);
}

/// One bit per row, every row present.
fn allValid(a: std.mem.Allocator, rows: usize) Error![]u64 {
    const bits = try a.alloc(u64, bitsLen(rows));
    @memset(bits, ~@as(u64, 0));
    return bits;
}

inline fn clearBit(bits: []u64, row: usize) void {
    bits[row / 64] &= ~(@as(u64, 1) << @intCast(row % 64));
}

inline fn testBit(bits: []const u64, row: usize) bool {
    return (bits[row / 64] >> @intCast(row % 64)) & 1 == 1;
}

/// Numbers of one column as `Value.asFloat` reads them, a missing cell as 0, and which
/// cells were present (`valid == null`: all of them). `xs` may borrow from the column.
const Floats = struct { xs: []const f64, valid: ?[]const u64 };

fn readFloats(a: std.mem.Allocator, col: ColumnData, rows: usize) Error!Floats {
    switch (col) {
        .float => |c| if (c.valid == null and c.values.len == rows) return .{ .xs = c.values, .valid = null },
        .int => |c| if (c.valid == null and c.values.len == rows) {
            const xs = try a.alloc(f64, rows);
            for (xs, c.values) |*x, v| x.* = @floatFromInt(v);
            return .{ .xs = xs, .valid = null };
        },
        else => {},
    }
    const xs = try a.alloc(f64, rows);
    const bits = try allValid(a, rows);
    var any_missing = false;
    for (xs, 0..) |*x, ri| {
        if (col.get(ri).asFloat()) |v| {
            x.* = v;
        } else {
            x.* = 0;
            clearBit(bits, ri);
            any_missing = true;
        }
    }
    return .{ .xs = xs, .valid = if (any_missing) bits else null };
}

fn readOperand(a: std.mem.Allocator, f: Frame, op: transforms.Operand) Error!Floats {
    switch (op) {
        .col => |name| return readFloats(a, colOf(f, try mustIndex(f, name)), f.len),
        .num => |n| {
            const xs = try a.alloc(f64, f.len);
            @memset(xs, n);
            return .{ .xs = xs, .valid = null };
        },
    }
}

/// `f` plus one column, every other column shared.
fn appended(a: std.mem.Allocator, f: Frame, col: Column, data: ColumnData) Error!Frame {
    const w = f.columns.len;
    const cols = try a.alloc(Column, w + 1);
    @memcpy(cols[0..w], f.columns);
    cols[w] = col;
    const out = try a.alloc(ColumnData, w + 1);
    for (out[0..w], 0..) |*d, ci| d.* = colOf(f, ci);
    out[w] = data;
    return .{ .columns = cols, .data = out, .len = f.len };
}

/// As `transforms.map`: `out = lhs op rhs`.
pub fn map(a: std.mem.Allocator, f: Frame, spec: transforms.MapSpec) Error!Frame {
    const unary = spec.op == .abs or spec.op == .sqrt;
    const lhs = try readOperand(a, f, spec.lhs);
    const rhs: Floats = if (unary) .{ .xs = &.{}, .valid = null } else try readOperand(a, f, spec.rhs);
    const out = try a.alloc(f64, f.len);
    const as_null = spec.on_missing == .null;

    // Present in the result; only `.null` mode ever clears a bit.
    var valid: ?[]u64 = null;
    if (as_null and (lhs.valid != null or rhs.valid != null)) {
        const bits = try allValid(a, f.len);
        if (lhs.valid) |v| {
            for (bits, v) |*b, x| b.* &= x;
        }
        if (rhs.valid) |v| {
            for (bits, v) |*b, x| b.* &= x;
        }
        valid = bits;
    }

    const l = lhs.xs;
    const r = rhs.xs;
    switch (spec.op) {
        .add => for (out, l, r) |*o, x, y| {
            o.* = x + y;
        },
        .sub => for (out, l, r) |*o, x, y| {
            o.* = x - y;
        },
        .mul => for (out, l, r) |*o, x, y| {
            o.* = x * y;
        },
        .min => for (out, l, r) |*o, x, y| {
            o.* = @min(x, y);
        },
        .max => for (out, l, r) |*o, x, y| {
            o.* = @max(x, y);
        },
        .abs => for (out, l) |*o, x| {
            o.* = @abs(x);
        },
        .div => for (out, l, r, 0..) |*o, x, y, ri| {
            if (y == 0) {
                o.* = 0;
                if (as_null) {
                    if (valid == null) valid = try allValid(a, f.len);
                    clearBit(valid.?, ri);
                }
            } else {
                o.* = x / y;
            }
        },
        .sqrt => for (out, l, 0..) |*o, x, ri| {
            if (x < 0) {
                o.* = 0;
                if (as_null) {
                    if (valid == null) valid = try allValid(a, f.len);
                    clearBit(valid.?, ri);
                }
            } else {
                o.* = @sqrt(x);
            }
        },
    }
    // A null cell holds 0 in `values` (`TypedColumn`'s contract).
    if (valid) |bits| {
        for (out, 0..) |*o, ri| {
            if (!testBit(bits, ri)) o.* = 0;
        }
    }
    return appended(a, f, .{ .name = spec.out, .type = spec.out_type }, .{ .float = .{ .values = out, .valid = valid } });
}

fn valueFloats(a: std.mem.Allocator, f: Frame, name: []const u8) Error![]const f64 {
    return (try readFloats(a, colOf(f, try mustIndex(f, name)), f.len)).xs;
}

fn appendFloats(a: std.mem.Allocator, f: Frame, name: []const u8, out: []const f64) Error!Frame {
    return appended(a, f, .{ .name = name, .type = .float }, .{ .float = .{ .values = out } });
}

/// As `series.cumsum`.
pub fn cumsum(a: std.mem.Allocator, f: Frame, spec: series.ColSpec) Error!Frame {
    const v = try valueFloats(a, f, spec.value_col);
    const out = try a.alloc(f64, v.len);
    var acc: f64 = 0;
    for (out, v) |*o, x| {
        acc += x;
        o.* = acc;
    }
    return appendFloats(a, f, spec.out, out);
}

/// As `series.rolling`. Each window is summed from its start, as the row verb does, so
/// the answers agree to the bit; four neighbouring windows at a time keep that order per
/// lane and take the add chain's latency out of it.
pub fn rolling(a: std.mem.Allocator, f: Frame, spec: series.RollSpec) Error!Frame {
    const v = try valueFloats(a, f, spec.value_col);
    const col: Column = .{ .name = spec.out, .type = .float };
    const window = spec.window;
    if (window == 0 or window > v.len) return appended(a, f, col, .nulls);
    const work = std.math.mul(usize, v.len - window + 1, window) catch return error.TooLarge;
    if (work > series.max_rolling_work) return error.TooLarge;

    const out = try a.alloc(f64, v.len);
    @memset(out[0 .. window - 1], 0);
    const results = out[window - 1 ..];
    if (spec.func == .sum or spec.func == .mean) {
        rollingSums(results, v, window, spec.func == .mean);
    } else {
        for (results, 0..) |*o, start| o.* = series.windowAgg(v[start..][0..window], spec.func);
    }
    var valid: ?[]u64 = null;
    if (window > 1) {
        const bits = try allValid(a, v.len);
        for (0..window - 1) |ri| clearBit(bits, ri);
        valid = bits;
    }
    return appended(a, f, col, .{ .float = .{ .values = out, .valid = valid } });
}

fn rollingSums(results: []f64, v: []const f64, window: usize, mean: bool) void {
    const lanes = 4;
    const V = @Vector(lanes, f64);
    const w: f64 = @floatFromInt(window);
    var start: usize = 0;
    while (start + lanes <= results.len) : (start += lanes) {
        var s: V = @splat(0);
        for (0..window) |k| s += v[start + k ..][0..lanes].*;
        if (mean) s /= @as(V, @splat(w));
        results[start..][0..lanes].* = s;
    }
    while (start < results.len) : (start += 1) {
        var s: f64 = 0;
        for (v[start..][0..window]) |x| s += x;
        results[start] = if (mean) s / w else s;
    }
}

// ── join ────────────────────────────────────────────────────────────────────

fn nameIdxs(a: std.mem.Allocator, f: Frame, names: []const []const u8) Error![]const usize {
    const idxs = try a.alloc(usize, names.len);
    for (names, 0..) |name, i| idxs[i] = try mustIndex(f, name);
    return idxs;
}

fn joinKeyIdxs(a: std.mem.Allocator, f: Frame, spec: series.JoinSpec) Error![]const usize {
    return nameIdxs(a, f, if (spec.keys.len > 0) spec.keys else &.{spec.on});
}

/// The key cells as rows of their own, for the keyed path every shape of key can take.
/// The `keys` machinery reads rows, and this is what gives a Frame's join the row verb's
/// key equality without a second implementation of it.
fn keyRows(a: std.mem.Allocator, f: Frame, idxs: []const usize) Error![]const []const Value {
    const w = idxs.len;
    const n = std.math.mul(usize, f.len, w) catch return error.TooLarge;
    const cells = try a.alloc(Value, n);
    const rows = try a.alloc([]const Value, f.len);
    for (idxs, 0..) |ci, k| {
        const col = colOf(f, ci);
        for (0..f.len) |ri| cells[ri * w + k] = col.get(ri);
    }
    for (rows, 0..) |*r, ri| r.* = cells[ri * w ..][0..w];
    return rows;
}

/// Every cell of a single int column, when that is all a key is. No rows then.
fn plainInts(f: Frame, idxs: []const usize) ?[]const i64 {
    if (idxs.len != 1 or f.len == 0) return null;
    const col = colOf(f, idxs[0]);
    if (col != .int or col.int.valid != null or col.int.values.len != f.len) return null;
    return col.int.values;
}

const Lookup = struct {
    /// `hits[i]` = the build side's group of probe row `i`, or `keys.none`.
    hits: []u32,
    /// Group of each build row.
    ids: []u32,
    groups: usize,
};

fn lookupKeys(a: std.mem.Allocator, build: Frame, bk: []const usize, probe: Frame, pk: []const usize, skip_null: bool) Error!Lookup {
    const hits = try a.alloc(u32, probe.len);
    if (plainInts(build, bk)) |bi| {
        if (plainInts(probe, pk)) |pi| {
            const g = try keys.factorizeInts(a, bi);
            try keys.probeInts(&g.table, pi, hits);
            return .{ .hits = hits, .ids = g.ids, .groups = g.groups() };
        }
    }
    const positions = struct {
        fn of(al: std.mem.Allocator, n: usize) Error![]const usize {
            const p = try al.alloc(usize, n);
            for (p, 0..) |*x, i| x.* = i;
            return p;
        }
    };
    const bpos = try positions.of(a, bk.len);
    const ppos = try positions.of(a, pk.len);
    const g = try keys.factorize(a, try keyRows(a, build, bk), bpos, .as_null);
    try keys.probeAll(a, &g.table, try keyRows(a, probe, pk), ppos, .as_null, skip_null, hits);
    return .{ .hits = hits, .ids = g.ids, .groups = g.groups() };
}

fn takeTyped(comptime T: type, a: std.mem.Allocator, c: ds.TypedColumn(T), idx: []const u32, has_none: bool) Error!ds.TypedColumn(T) {
    const out = try a.alloc(T, idx.len);
    if (c.valid == null and !has_none) {
        var fits = true;
        for (idx) |i| fits = fits and i < c.values.len;
        if (fits) {
            for (out, idx) |*o, i| o.* = c.values[i];
            return .{ .values = out };
        }
    }
    const bits = try allValid(a, idx.len);
    var any_null = false;
    for (out, idx, 0..) |*o, i, ri| {
        if (i != keys.none and c.isValid(i)) {
            o.* = c.values[i];
        } else {
            o.* = std.mem.zeroes(T);
            clearBit(bits, ri);
            any_null = true;
        }
    }
    return .{ .values = out, .valid = if (any_null) bits else null };
}

fn takeText(a: std.mem.Allocator, c: ds.TextColumn, idx: []const u32) Error!ds.TextColumn {
    var total: usize = 0;
    for (idx) |i| {
        if (i == keys.none) continue;
        if (c.at(i)) |t| total += t.len;
    }
    const offsets = try a.alloc(usize, idx.len + 1);
    const bytes = try a.alloc(u8, total);
    const bits = try allValid(a, idx.len);
    var any_null = false;
    var at: usize = 0;
    for (idx, 0..) |i, ri| {
        offsets[ri] = at;
        const t = if (i == keys.none) null else c.at(i);
        if (t) |s| {
            @memcpy(bytes[at..][0..s.len], s);
            at += s.len;
        } else {
            clearBit(bits, ri);
            any_null = true;
        }
    }
    offsets[idx.len] = at;
    return .{ .offsets = offsets, .bytes = bytes, .valid = if (any_null) bits else null };
}

/// The rows `idx` names of one column, `keys.none` as null.
fn take(a: std.mem.Allocator, col: ColumnData, idx: []const u32, has_none: bool) Error!ColumnData {
    switch (col) {
        .nulls => return .nulls,
        .int => |c| return .{ .int = try takeTyped(i64, a, c, idx, has_none) },
        .float => |c| return .{ .float = try takeTyped(f64, a, c, idx, has_none) },
        .bool => |c| return .{ .bool = try takeTyped(bool, a, c, idx, has_none) },
        .decimal => |c| return .{ .decimal = try takeTyped(i128, a, c, idx, has_none) },
        .text => |c| return .{ .text = try takeText(a, c, idx) },
        .boxed => |c| {
            const out = try a.alloc(Value, idx.len);
            for (out, idx) |*o, i| o.* = if (i != keys.none and i < c.len) c[i] else .null;
            return .{ .boxed = out };
        },
    }
}

fn isIdentity(idx: []const u32, rows: usize) bool {
    if (idx.len != rows) return false;
    for (idx, 0..) |x, i| {
        if (x != i) return false;
    }
    return true;
}

fn hasNone(idx: []const u32) bool {
    for (idx) |x| {
        if (x == keys.none) return true;
    }
    return false;
}

/// As `series.join`, all its `how`s and options. A left side that comes out row for row
/// as it went in (a left join on a unique right key, say) is shared, not copied.
pub fn join(a: std.mem.Allocator, left: Frame, right: Frame, spec: series.JoinSpec) Error!Frame {
    // A row index is a u32 and `keys.none` is its top value. Only a hand-built frame can
    // be this long: a `Dataset`'s rows are a real slice.
    if (left.len >= keys.none or right.len >= keys.none) return error.TooLarge;
    const cross = spec.how == .cross;
    const lk: []const usize = if (cross) &.{} else try joinKeyIdxs(a, left, spec);
    const rk: []const usize = if (cross) &.{} else if (spec.right_on.len > 0)
        try nameIdxs(a, right, spec.right_on)
    else
        try joinKeyIdxs(a, right, spec);
    if (lk.len != rk.len) return error.NoSuchColumn;
    const skip_null = spec.null_keys == .no_match;

    if (spec.how == .semi or spec.how == .anti) {
        const found = try lookupKeys(a, right, rk, left, lk, skip_null);
        var kept: std.ArrayList(u32) = .empty;
        for (found.hits, 0..) |h, ri| {
            if ((spec.how == .semi) == (h != keys.none)) try kept.append(a, @intCast(ri));
        }
        const data = try a.alloc(ColumnData, left.columns.len);
        const same = isIdentity(kept.items, left.len);
        for (data, 0..) |*d, ci| d.* = if (same) colOf(left, ci) else try take(a, colOf(left, ci), kept.items, false);
        return .{ .columns = left.columns, .data = data, .len = kept.items.len };
    }

    const rmask = try a.alloc(bool, right.columns.len);
    @memset(rmask, false);
    for (rk) |ci| rmask[ci] = true;
    var keep: std.ArrayList(usize) = .empty;
    for (rmask, 0..) |is_key, ci| if (!is_key) try keep.append(a, ci);
    const cols = try a.alloc(Column, left.columns.len + keep.items.len);
    @memcpy(cols[0..left.columns.len], left.columns);
    for (keep.items, cols[left.columns.len..]) |ci, *c| {
        c.* = right.columns[ci];
        if (spec.suffix) |sfx| {
            if (left.columnIndex(c.name) != null) c.name = try a.print("{s}{s}", .{ c.name, sfx });
        }
    }

    const pairs = if (cross) try crossPairs(a, left.len, right.len, cols.len) else try keyedPairs(a, left, lk, right, rk, spec, skip_null, cols.len);

    const data = try a.alloc(ColumnData, cols.len);
    const left_has_none = hasNone(pairs.left);
    const right_has_none = hasNone(pairs.right);
    const left_same = isIdentity(pairs.left, left.len);
    for (data[0..left.columns.len], 0..) |*d, ci| {
        d.* = if (left_same) colOf(left, ci) else try take(a, colOf(left, ci), pairs.left, left_has_none);
    }
    for (keep.items, data[left.columns.len..]) |ci, *d| {
        d.* = try take(a, colOf(right, ci), pairs.right, right_has_none);
    }
    if (spec.coalesce_keys and left_has_none) {
        // A right-only row takes its key cells from the right, in key order, as the row
        // verb does. The kinds may differ between the sides, so the column is boxed.
        for (lk, rk) |l, m| {
            const out = try a.alloc(Value, pairs.left.len);
            const col = data[l];
            const from = colOf(right, m);
            for (out, pairs.left, pairs.right, 0..) |*o, li, ri, at| {
                o.* = if (li == keys.none) from.get(ri) else col.get(at);
            }
            data[l] = .{ .boxed = out };
        }
    }
    return .{ .columns = cols, .data = data, .len = pairs.left.len };
}

const Pairs = struct { left: []const u32, right: []const u32 };

/// Running output-row count, refused past `series.max_join_cells` like the row verb.
fn pairsAdd(total: usize, n: usize, width: usize) Error!usize {
    const t = std.math.add(usize, total, n) catch return error.TooLarge;
    const cells = std.math.mul(usize, t, @max(width, 1)) catch return error.TooLarge;
    if (cells > series.max_join_cells) return error.TooLarge;
    return t;
}

fn crossPairs(a: std.mem.Allocator, l: usize, r: usize, width: usize) Error!Pairs {
    const total = std.math.mul(usize, l, r) catch return error.TooLarge;
    _ = try pairsAdd(total, 0, width);
    if (total == 0) return .{ .left = &.{}, .right = &.{} };
    const li = try a.alloc(u32, total);
    const ri = try a.alloc(u32, total);
    var at: usize = 0;
    for (0..l) |x| {
        for (0..r) |y| {
            li[at] = @intCast(x);
            ri[at] = @intCast(y);
            at += 1;
        }
    }
    return .{ .left = li, .right = ri };
}

fn keyedPairs(a: std.mem.Allocator, left: Frame, lk: []const usize, right: Frame, rk: []const usize, spec: series.JoinSpec, skip_null: bool, width: usize) Error!Pairs {
    const drive_right = spec.how == .right;
    const build = if (drive_right) left else right;
    const probe = if (drive_right) right else left;
    const bk = if (drive_right) lk else rk;
    const pk = if (drive_right) rk else lk;

    const found = try lookupKeys(a, build, bk, probe, pk, skip_null);
    const mem = try keys.members(a, found.ids, found.groups);
    const none = keys.none;
    const keep_unmatched = spec.how != .inner;

    var total: usize = 0;
    for (found.hits) |h| {
        total += if (h != none) mem.of(h).len else @intFromBool(keep_unmatched);
        if (total > series.max_join_cells) return error.TooLarge;
    }
    total = try pairsAdd(total, 0, width);

    var only_right: std.ArrayList(u32) = .empty;
    if (spec.how == .full) {
        const seen = try a.alloc(bool, found.groups);
        defer a.free(seen);
        @memset(seen, false);
        for (found.hits) |h| {
            if (h != none) seen[h] = true;
        }
        for (found.ids, 0..) |g, ri| {
            if (!seen[g]) {
                try only_right.append(a, @intCast(ri));
                total = try pairsAdd(total, 1, width);
            }
        }
    }

    const li = try a.alloc(u32, total);
    const ri = try a.alloc(u32, total);
    var at: usize = 0;
    if (drive_right) {
        for (found.hits, 0..) |h, pi| {
            if (h == none) {
                li[at] = none;
                ri[at] = @intCast(pi);
                at += 1;
            } else {
                for (mem.of(h)) |mi| {
                    li[at] = mi;
                    ri[at] = @intCast(pi);
                    at += 1;
                }
            }
        }
    } else {
        for (found.hits, 0..) |h, pi| {
            if (h == none) {
                if (keep_unmatched) {
                    li[at] = @intCast(pi);
                    ri[at] = none;
                    at += 1;
                }
            } else {
                for (mem.of(h)) |mi| {
                    li[at] = @intCast(pi);
                    ri[at] = mi;
                    at += 1;
                }
            }
        }
        for (only_right.items) |r| {
            li[at] = none;
            ri[at] = r;
            at += 1;
        }
    }
    return .{ .left = li, .right = ri };
}

test {
    _ = @import("frame_test.zig");
}
