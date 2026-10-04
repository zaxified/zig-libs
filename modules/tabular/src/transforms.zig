// SPDX-License-Identifier: MIT
//! Dataset algebra **Tier 0** — the pure `dataset → dataset` primitives that
//! cover the bulk of dataset transform workloads. Each is a pure function of
//! `(allocator, Dataset, Spec) → Dataset`; nothing is mutated in place. The
//! allocator is normally a caller-owned arena for the whole pipeline (see the
//! memory model note in `dataset`).
//!
//! T0 set: map · aggregate(+fx) · weighted_group_sum(+fx) · sort (multi-key) ·
//! top_n / top_n_with_tail · page · pivot (numeric-aware col ordering) ·
//! unpivot · resample · reduce · clamp_range · format · filter / filterBy ·
//! select / drop / rename · dropna / fillna.
//!
//! `fx-convert-before-sum` is first-class on aggregate/weighted_group_sum — the
//! recurring multi-currency correctness fix (a null per-row rate means 1.0).

const std = @import("std");
const ds = @import("dataset");
const Dataset = ds.Dataset;
const Column = ds.Column;
const ColumnType = ds.ColumnType;
const Value = ds.Value;

pub const Error = error{ NoSuchColumn, OutOfMemory };

// ── shared helpers ──────────────────────────────────────────────────────────

fn mustIndex(d: Dataset, name: []const u8) Error!usize {
    return d.columnIndex(name) orelse Error.NoSuchColumn;
}

/// Effective fx rate for a row: value in `rate_col` (null / missing → 1.0).
fn fxRate(row: []const Value, rate_idx: ?usize) f64 {
    const ri = rate_idx orelse return 1.0;
    return row[ri].asFloat() orelse 1.0;
}

/// Append a value's canonical key bytes (for group-key strings).
fn appendValueKey(a: std.mem.Allocator, buf: *std.ArrayList(u8), v: Value) Error!void {
    switch (v) {
        .null => try buf.append(a, 0),
        .bool => |b| try buf.append(a, if (b) '1' else '0'),
        .int => |i| try buf.print(a, "{d}", .{i}),
        .float => |f| try buf.print(a, "{d}", .{f}),
        .text => |t| try buf.appendSlice(a, t),
        .decimal => |r| try buf.print(a, "d{d}", .{r}), // raw i128, exact key
    }
}

fn keyString(a: std.mem.Allocator, row: []const Value, idxs: []const usize) Error![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    for (idxs, 0..) |ci, n| {
        if (n > 0) try buf.append(a, 0x1f); // unit separator
        try appendValueKey(a, &buf, row[ci]);
    }
    return buf.toOwnedSlice(a);
}

// ── map ─────────────────────────────────────────────────────────────────────

pub const Operand = union(enum) {
    col: []const u8,
    num: f64,
};

/// `abs` and `sqrt` are unary: they read `lhs` and ignore `rhs`.
pub const BinOp = enum { add, sub, mul, div, min, max, abs, sqrt };

/// What `map` writes when an operand is missing (null or non-numeric) or the
/// result is undefined (`div` by zero, `sqrt` of a negative number).
pub const OnMissing = enum {
    /// A missing operand reads as 0 and an undefined result is 0 — the
    /// historical behaviour, kept as the default.
    zero,
    /// Null in, null out; an undefined result is null (SQL's rule, and
    /// pandas' NaN propagation).
    null,
};

pub const MapSpec = struct {
    /// Name of the appended column.
    out: []const u8,
    out_type: ColumnType = .float,
    lhs: Operand,
    op: BinOp,
    /// Ignored by the unary ops (`abs`, `sqrt`).
    rhs: Operand = .{ .num = 0 },
    on_missing: OnMissing = .zero,
};

/// Append `out = lhs op rhs` as a new float column (per-row arithmetic:
/// pl = mv - cost, base = gross * fx, …). Multi-term expressions compose via
/// successive `map` steps. `min`/`max` follow IEEE `@min`/`@max` (a NaN
/// operand loses to a number).
pub fn map(a: std.mem.Allocator, d: Dataset, spec: MapSpec) Error!Dataset {
    const li: ?usize = switch (spec.lhs) {
        .col => |c| try mustIndex(d, c),
        .num => null,
    };
    const unary = spec.op == .abs or spec.op == .sqrt;
    const rgi: ?usize = if (unary) null else switch (spec.rhs) {
        .col => |c| try mustIndex(d, c),
        .num => null,
    };

    const cols = try a.alloc(Column, d.columns.len + 1);
    @memcpy(cols[0..d.columns.len], d.columns);
    cols[d.columns.len] = .{ .name = spec.out, .type = spec.out_type };

    const rows = try a.alloc([]const Value, d.rows.len);
    const missing: Value = if (spec.on_missing == .null) .null else .{ .float = 0 };
    for (d.rows, 0..) |r, ri| {
        const nr = try a.alloc(Value, cols.len);
        @memcpy(nr[0..d.columns.len], r);
        rows[ri] = nr;
        const lo: ?f64 = if (li) |i| r[i].asFloat() else spec.lhs.num;
        const ro: ?f64 = if (unary) 0 else if (rgi) |i| r[i].asFloat() else spec.rhs.num;
        if (spec.on_missing == .null and (lo == null or ro == null)) {
            nr[d.columns.len] = .null;
            continue;
        }
        const lv = lo orelse 0;
        const rv = ro orelse 0;
        nr[d.columns.len] = switch (spec.op) {
            .add => .{ .float = lv + rv },
            .sub => .{ .float = lv - rv },
            .mul => .{ .float = lv * rv },
            .div => if (rv == 0) missing else .{ .float = lv / rv },
            .min => .{ .float = @min(lv, rv) },
            .max => .{ .float = @max(lv, rv) },
            .abs => .{ .float = @abs(lv) },
            .sqrt => if (lv < 0) missing else .{ .float = @sqrt(lv) },
        };
    }
    return .{ .columns = cols, .rows = rows };
}

// ── aggregate (+fx) ─────────────────────────────────────────────────────────

/// `sum`/`mean`/`count` count every row of the group (a null or non-numeric
/// cell adds 0 to `sum` and 1 to `count` — historical behaviour, unlike
/// pandas' skip-NA). The statistics added 2026-10-04 skip MISSING values
/// (null, non-numeric, NaN), as pandas does by default:
///   `std`/`var` — sample (n−1, pandas' default `ddof=1`), null below 2 values;
///   `median`, `quantile` (`AggCol.q`) — linear interpolation between order
///     statistics (numpy/pandas default, Hyndman–Fan type 7), null when empty;
///   `nunique` — distinct non-missing values of any kind, text included
///     (pandas `nunique()`, `dropna=True`); int 1 and float 1.0 are one value, text
///     "1" another; a `.decimal` keys on its raw i128, so decimal 1 and int 1
///     count twice;
///   `sum_exact` — i128 sum at `dataset.decimal_scale`, output `.decimal`:
///     `.decimal` cells exactly, `.int` cells exactly (× scale), `.float` cells
///     through `Value.cast(.decimal)`; null if the total overflows i128.
pub const AggFn = enum { sum, mean, count, min, max, first, last, std, @"var", median, quantile, nunique, sum_exact };

pub const AggCol = struct {
    src: []const u8,
    out: []const u8,
    func: AggFn,
    /// Probability for `func = .quantile`, in [0, 1]; anything else (or NaN)
    /// gives null. Ignored by the other functions.
    q: f64 = 0.5,
};

pub const FxConvert = struct {
    /// Column holding the per-row conversion rate (null/absent → 1.0). The
    /// numeric aggregate value is multiplied by this before accumulation.
    rate_col: []const u8,
};

pub const AggregateSpec = struct {
    group_by: []const []const u8,
    aggs: []const AggCol,
    fx: ?FxConvert = null,
};

const Acc = struct {
    sum: f64 = 0,
    count: u64 = 0,
    min: ?Value = null,
    max: ?Value = null,
    first: ?Value = null,
    last: ?Value = null,
    // Over non-missing numeric values only (Welford's update: stable where
    // the textbook Σx² − n·mean² cancels catastrophically).
    n_num: u64 = 0,
    mean: f64 = 0,
    m2: f64 = 0,
    exact: i128 = 0,
    exact_overflow: bool = false,
    /// Kept only for the functions that need every value.
    vals: std.ArrayList(f64) = .empty,
    distinct: std.StringHashMapUnmanaged(void) = .empty,
    keep_vals: bool = false,
    keep_distinct: bool = false,

    fn forFunc(func: AggFn) Acc {
        return .{
            .keep_vals = func == .median or func == .quantile,
            .keep_distinct = func == .nunique,
        };
    }

    /// `v` is the cell after any fx conversion, `raw` the cell as stored and
    /// `rate` the fx rate applied (1 without fx): `sum_exact` uses `raw` when
    /// the rate is exactly 1, so a null rate keeps a decimal exact.
    fn observe(self: *Acc, a: std.mem.Allocator, v: Value, raw: Value, rate: f64) Error!void {
        self.count += 1;
        self.sum += v.asFloat() orelse 0;
        if (self.first == null) self.first = v;
        self.last = v;
        if (self.min == null or v.order(self.min.?) == .lt) self.min = v;
        if (self.max == null or v.order(self.max.?) == .gt) self.max = v;

        if (isMissing(v)) return; // null, NaN: missing, as in pandas
        if (self.keep_distinct) {
            // Kind first: the group-key text alone makes text "1" and int 1
            // the same key.
            var buf: std.ArrayList(u8) = .empty;
            try buf.append(a, @intFromEnum(kindOf(v)));
            try appendValueKey(a, &buf, v);
            try self.distinct.put(a, try buf.toOwnedSlice(a), {});
        }
        const x = v.asFloat() orelse return; // text / bool: not a number
        self.n_num += 1;
        const delta = x - self.mean;
        self.mean += delta / @as(f64, @floatFromInt(self.n_num));
        self.m2 += delta * (x - self.mean);

        const term: ?i128 = switch (if (rate == 1) raw else v) {
            .decimal => |r| r,
            .int => |i| @as(i128, i) * ds.decimal_scale, // |i| < 2^63, scale < 2^40: fits
            .float => if (v.cast(.decimal)) |c| c.decimal else null,
            else => null,
        };
        if (term) |t| {
            // Sticky: once the running total has left i128, no later term can
            // make the result trustworthy again.
            const r = @addWithOverflow(self.exact, t);
            if (r[1] != 0) self.exact_overflow = true else self.exact = r[0];
        }
        if (self.keep_vals) try self.vals.append(a, x);
    }

    fn result(self: Acc, func: AggFn, q: f64) Value {
        return switch (func) {
            .sum => .{ .float = self.sum },
            .mean => .{ .float = if (self.count == 0) 0 else self.sum / @as(f64, @floatFromInt(self.count)) },
            .count => .{ .int = @intCast(self.count) },
            .min => self.min orelse .null,
            .max => self.max orelse .null,
            .first => self.first orelse .null,
            .last => self.last orelse .null,
            .@"var" => if (self.n_num < 2) .null else .{ .float = self.m2 / @as(f64, @floatFromInt(self.n_num - 1)) },
            .std => if (self.n_num < 2) .null else .{ .float = @sqrt(self.m2 / @as(f64, @floatFromInt(self.n_num - 1))) },
            .median => quantileOf(self.vals.items, 0.5),
            .quantile => quantileOf(self.vals.items, q),
            .nunique => .{ .int = @intCast(self.distinct.count()) },
            .sum_exact => if (self.exact_overflow) .null else .{ .decimal = self.exact },
        };
    }
};

/// Type-7 quantile (linear interpolation between the order statistics at
/// h = (n−1)·q): numpy's and pandas' default. Sorts `xs` in place.
fn quantileOf(xs: []f64, q: f64) Value {
    if (xs.len == 0 or !(q >= 0 and q <= 1)) return .null;
    std.mem.sort(f64, xs, {}, std.sort.asc(f64));
    const h = @as(f64, @floatFromInt(xs.len - 1)) * q;
    const lo: usize = @intFromFloat(@floor(h));
    const hi = @min(lo + 1, xs.len - 1);
    return .{ .float = xs[lo] + (h - @floor(h)) * (xs[hi] - xs[lo]) };
}

const Group = struct {
    keys: []Value, // group-by key values (from the first row seen)
    accs: []Acc, // one per agg
};

pub fn aggregate(a: std.mem.Allocator, d: Dataset, spec: AggregateSpec) Error!Dataset {
    const gidx = try a.alloc(usize, spec.group_by.len);
    for (spec.group_by, 0..) |name, i| gidx[i] = try mustIndex(d, name);
    const sidx = try a.alloc(usize, spec.aggs.len);
    for (spec.aggs, 0..) |ag, i| sidx[i] = try mustIndex(d, ag.src);
    const rate_idx: ?usize = if (spec.fx) |fx| try mustIndex(d, fx.rate_col) else null;

    var groups: std.StringArrayHashMapUnmanaged(Group) = .empty;
    for (d.rows) |r| {
        const key = try keyString(a, r, gidx);
        const gop = try groups.getOrPut(a, key);
        if (!gop.found_existing) {
            const keys = try a.alloc(Value, gidx.len);
            for (gidx, 0..) |ci, i| keys[i] = r[ci];
            const accs = try a.alloc(Acc, spec.aggs.len);
            for (accs, spec.aggs) |*acc, ag| acc.* = .forFunc(ag.func);
            gop.value_ptr.* = .{ .keys = keys, .accs = accs };
        }
        const rate = fxRate(r, rate_idx);
        for (sidx, 0..) |ci, i| {
            var v = r[ci];
            if (rate_idx != null) {
                if (v.asFloat()) |f| v = .{ .float = f * rate };
            }
            try gop.value_ptr.accs[i].observe(a, v, r[ci], rate);
        }
    }

    // output columns: group-by cols (source types) + one per agg
    const cols = try a.alloc(Column, gidx.len + spec.aggs.len);
    for (gidx, 0..) |ci, i| cols[i] = d.columns[ci];
    for (spec.aggs, 0..) |ag, i| {
        cols[gidx.len + i] = .{ .name = ag.out, .type = aggOutType(d, sidx[i], ag.func) };
    }

    const rows = try a.alloc([]const Value, groups.count());
    var it = groups.iterator();
    var ri: usize = 0;
    while (it.next()) |kv| : (ri += 1) {
        const g = kv.value_ptr.*;
        const nr = try a.alloc(Value, cols.len);
        for (g.keys, 0..) |kvv, i| nr[i] = kvv;
        for (spec.aggs, 0..) |ag, i| nr[gidx.len + i] = g.accs[i].result(ag.func, ag.q);
        rows[ri] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

fn aggOutType(d: Dataset, src_idx: usize, func: AggFn) ColumnType {
    return switch (func) {
        .sum, .mean, .std, .@"var", .median, .quantile => .float,
        .count, .nunique => .int,
        .sum_exact => .decimal,
        .min, .max, .first, .last => d.columns[src_idx].type,
    };
}

// ── weighted_group_sum (+fx) ────────────────────────────────────────────────

pub const WeightedGroupSumSpec = struct {
    /// Column naming the group (asset-class / region / currency). null/empty →
    /// the unassigned bucket.
    group_col: []const u8,
    value_col: []const u8,
    weight_col: []const u8,
    fx: ?FxConvert = null,
    out_group: []const u8 = "group",
    out_value: []const u8 = "value",
    unassigned_label: []const u8 = "(unassigned)",
};

/// Σ (value · weight · fxrate) per group. Each input row is one
/// (member, group, weight) tuple — multi-category expansion (one asset → several
/// (cat,weight) rows) is done upstream by a join/map. Rows with a null/empty
/// group fold into the `unassigned_label` bucket. Output: `{out_group, out_value}`.
pub fn weightedGroupSum(a: std.mem.Allocator, d: Dataset, spec: WeightedGroupSumSpec) Error!Dataset {
    const gi = try mustIndex(d, spec.group_col);
    const vi = try mustIndex(d, spec.value_col);
    const wi = try mustIndex(d, spec.weight_col);
    const rate_idx: ?usize = if (spec.fx) |fx| try mustIndex(d, fx.rate_col) else null;

    var groups: std.StringArrayHashMapUnmanaged(f64) = .empty;
    var labels: std.StringArrayHashMapUnmanaged([]const u8) = .empty; // key → display label

    for (d.rows) |r| {
        const gv = r[gi];
        const is_unassigned = gv == .null or (gv == .text and gv.text.len == 0);
        const label: []const u8 = if (is_unassigned) spec.unassigned_label else (gv.asText() orelse blk: {
            var buf: std.ArrayList(u8) = .empty;
            try appendValueKey(a, &buf, gv);
            break :blk try buf.toOwnedSlice(a);
        });
        const contrib = (r[vi].asFloat() orelse 0) * (r[wi].asFloat() orelse 0) * fxRate(r, rate_idx);
        const gop = try groups.getOrPut(a, label);
        if (!gop.found_existing) {
            gop.value_ptr.* = 0;
            try labels.put(a, label, label);
        }
        gop.value_ptr.* += contrib;
    }

    const cols = try a.alloc(Column, 2);
    cols[0] = .{ .name = spec.out_group, .type = .text };
    cols[1] = .{ .name = spec.out_value, .type = .float };
    const rows = try a.alloc([]const Value, groups.count());
    var it = groups.iterator();
    var ri: usize = 0;
    while (it.next()) |kv| : (ri += 1) {
        const nr = try a.alloc(Value, 2);
        nr[0] = .{ .text = kv.key_ptr.* };
        nr[1] = .{ .float = kv.value_ptr.* };
        rows[ri] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

// ── percent_of_total ─────────────────────────────────────────────────────────

pub const PercentSpec = struct {
    value_col: []const u8,
    out: []const u8,
    /// Scale: 100 → percent (default), 1 → fraction.
    scale: f64 = 100,
};

/// Append `out = value / Σvalue * scale` — each row's share of the column total.
pub fn percentOfTotal(a: std.mem.Allocator, d: Dataset, spec: PercentSpec) Error!Dataset {
    const vi = try mustIndex(d, spec.value_col);
    var total: f64 = 0;
    for (d.rows) |r| total += r[vi].asFloat() orelse 0;
    const cols = try a.alloc(Column, d.columns.len + 1);
    @memcpy(cols[0..d.columns.len], d.columns);
    cols[d.columns.len] = .{ .name = spec.out, .type = .float };
    const rows = try a.alloc([]const Value, d.rows.len);
    for (d.rows, 0..) |r, i| {
        const nr = try a.alloc(Value, cols.len);
        @memcpy(nr[0..d.columns.len], r);
        const share = if (total != 0) (r[vi].asFloat() orelse 0) / total * spec.scale else 0;
        nr[d.columns.len] = .{ .float = share };
        rows[i] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

// ── sort ────────────────────────────────────────────────────────────────────

pub const SortDir = enum { asc, desc };
pub const SortKey = struct { key: []const u8, dir: SortDir = .asc };
pub const SortSpec = struct {
    key: []const u8,
    dir: SortDir = .asc,
    /// Additional tie-break keys, applied in order after `key`/`dir`.
    then_by: []const SortKey = &.{},
};

const SortCtx = struct {
    idxs: []const usize,
    dirs: []const SortDir,
    fn lessThan(self: SortCtx, lhs: []const Value, rhs: []const Value) bool {
        for (self.idxs, self.dirs) |ki, dir| {
            const o = lhs[ki].order(rhs[ki]);
            if (o == .eq) continue;
            return switch (dir) {
                .asc => o == .lt,
                .desc => o == .gt,
            };
        }
        return false; // fully tied
    }
};

/// Stable sort rows by `key`/`dir`, breaking ties with `then_by` (in order).
pub fn sort(a: std.mem.Allocator, d: Dataset, spec: SortSpec) Error!Dataset {
    const n = 1 + spec.then_by.len;
    const idxs = try a.alloc(usize, n);
    const dirs = try a.alloc(SortDir, n);
    idxs[0] = try mustIndex(d, spec.key);
    dirs[0] = spec.dir;
    for (spec.then_by, 0..) |tb, i| {
        idxs[1 + i] = try mustIndex(d, tb.key);
        dirs[1 + i] = tb.dir;
    }
    const rows = try a.alloc([]const Value, d.rows.len);
    @memcpy(rows, d.rows);
    std.mem.sort([]const Value, rows, SortCtx{ .idxs = idxs, .dirs = dirs }, SortCtx.lessThan);
    return .{ .columns = d.columns, .rows = rows };
}

// ── top_n / top_n_with_tail ─────────────────────────────────────────────────

pub const TopNSpec = struct {
    n: usize,
    /// When set, rows beyond `n` are folded into one tail row whose `label_col`
    /// cell = `label` and whose `value_col` cell = Σ of the dropped values (all
    /// other cells null). When null, the tail is simply dropped.
    tail: ?struct {
        label_col: []const u8,
        label: []const u8,
        value_col: []const u8,
    } = null,
};

/// Keep the first `n` rows (call `sort` first to make "top" meaningful),
/// optionally folding the remainder into a labeled tail row.
pub fn topN(a: std.mem.Allocator, d: Dataset, spec: TopNSpec) Error!Dataset {
    const keep = @min(spec.n, d.rows.len);
    if (spec.tail == null or d.rows.len <= keep) {
        const rows = try a.alloc([]const Value, keep);
        @memcpy(rows, d.rows[0..keep]);
        return .{ .columns = d.columns, .rows = rows };
    }
    const t = spec.tail.?;
    const label_idx = try mustIndex(d, t.label_col);
    const value_idx = try mustIndex(d, t.value_col);
    var tail_sum: f64 = 0;
    for (d.rows[keep..]) |r| tail_sum += r[value_idx].asFloat() orelse 0;

    const rows = try a.alloc([]const Value, keep + 1);
    @memcpy(rows[0..keep], d.rows[0..keep]);
    const tail_row = try a.alloc(Value, d.columns.len);
    @memset(tail_row, .null);
    tail_row[label_idx] = .{ .text = t.label };
    tail_row[value_idx] = .{ .float = tail_sum };
    rows[keep] = tail_row;
    return .{ .columns = d.columns, .rows = rows };
}

// ── page (limit/offset) ─────────────────────────────────────────────────────

pub const PageSpec = struct {
    offset: usize = 0,
    /// Rows to keep after `offset`; null = to the end.
    limit: ?usize = null,
};

/// Windowed row slice: skip `offset` rows, then keep at most `limit`.
/// Complements `topN` (whose window always starts at row 0) for arbitrary
/// pagination. Out-of-range `offset` yields an empty (not erroring) result.
pub fn page(a: std.mem.Allocator, d: Dataset, spec: PageSpec) Error!Dataset {
    const start = @min(spec.offset, d.rows.len);
    const avail = d.rows.len - start;
    const take = if (spec.limit) |l| @min(l, avail) else avail;
    const rows = try a.alloc([]const Value, take);
    @memcpy(rows, d.rows[start .. start + take]);
    return .{ .columns = d.columns, .rows = rows };
}

// ── pivot ───────────────────────────────────────────────────────────────────

pub const PivotSpec = struct {
    row_key: []const u8,
    col_key: []const u8,
    value_col: []const u8,
    agg: AggFn = .sum,
    /// Probability when `agg = .quantile`.
    q: f64 = 0.5,
};

/// rowKey × colKey → agg(value) matrix (month×year heatmaps, …). Output: first
/// column = `row_key` (as text), then one float column per distinct col-key
/// (sorted ascending for determinism). Missing cells → null.
pub fn pivot(a: std.mem.Allocator, d: Dataset, spec: PivotSpec) Error!Dataset {
    const rki = try mustIndex(d, spec.row_key);
    const cki = try mustIndex(d, spec.col_key);
    const vi = try mustIndex(d, spec.value_col);

    var row_keys: std.StringArrayHashMapUnmanaged(Value) = .empty; // key→display value (insertion order)
    var col_keys: std.StringArrayHashMapUnmanaged(void) = .empty;
    var cells: std.StringArrayHashMapUnmanaged(Acc) = .empty; // "rk\x1fck" → acc

    for (d.rows) |r| {
        const rk = try keyString(a, r, &.{rki});
        const ck = try keyString(a, r, &.{cki});
        if (!row_keys.contains(rk)) try row_keys.put(a, rk, r[rki]);
        try col_keys.put(a, ck, {});
        const ckey = try std.fmt.allocPrint(a, "{s}\x1f{s}", .{ rk, ck });
        const cop = try cells.getOrPut(a, ckey);
        if (!cop.found_existing) cop.value_ptr.* = .forFunc(spec.agg);
        try cop.value_ptr.observe(a, r[vi], r[vi], 1);
    }

    // sorted distinct column keys — numeric-aware when EVERY key parses as a
    // number (so "2" sorts before "10"); falls back to lexicographic
    // otherwise (mixed/non-numeric keys), same as before.
    const col_list = try a.alloc([]const u8, col_keys.count());
    for (col_keys.keys(), 0..) |k, i| col_list[i] = k;
    if (allNumeric(col_list)) {
        std.mem.sort([]const u8, col_list, {}, numLess);
    } else {
        std.mem.sort([]const u8, col_list, {}, strLess);
    }

    const cols = try a.alloc(Column, 1 + col_list.len);
    cols[0] = .{ .name = spec.row_key, .type = d.columns[rki].type };
    for (col_list, 0..) |ck, i| cols[1 + i] = .{ .name = ck, .type = .float };

    const rows = try a.alloc([]const Value, row_keys.count());
    var it = row_keys.iterator();
    var ri: usize = 0;
    while (it.next()) |kv| : (ri += 1) {
        const nr = try a.alloc(Value, cols.len);
        nr[0] = kv.value_ptr.*;
        const rk = kv.key_ptr.*;
        for (col_list, 0..) |ck, ci| {
            const ckey = try std.fmt.allocPrint(a, "{s}\x1f{s}", .{ rk, ck });
            nr[1 + ci] = if (cells.get(ckey)) |acc| acc.result(spec.agg, spec.q) else .null;
        }
        rows[ri] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

fn strLess(_: void, l: []const u8, r: []const u8) bool {
    return std.mem.order(u8, l, r) == .lt;
}

/// True iff every key parses as an f64 (pivot col-key ordering guard: mixed or
/// non-numeric keys fall back to lexicographic so the comparator stays a
/// consistent total order).
fn allNumeric(keys: []const []const u8) bool {
    for (keys) |k| {
        _ = std.fmt.parseFloat(f64, k) catch return false;
    }
    return true;
}

fn numLess(_: void, l: []const u8, r: []const u8) bool {
    const lf = std.fmt.parseFloat(f64, l) catch unreachable; // allNumeric already verified
    const rf = std.fmt.parseFloat(f64, r) catch unreachable;
    return lf < rf;
}

// ── unpivot / melt ──────────────────────────────────────────────────────────

pub const UnpivotSpec = struct {
    /// Columns copied as-is (row identity) to every output row.
    id_cols: []const []const u8,
    /// Wide columns to melt into (key,value) row pairs. Empty (default) melts
    /// every column NOT in `id_cols`.
    value_cols: []const []const u8 = &.{},
    out_key: []const u8 = "variable",
    out_value: []const u8 = "value",
};

/// Wide → long reshape: one output row per (input row × melted column),
/// carrying the id columns plus `{out_key: <melted column's name>, out_value:
/// <that cell>}`. Loose inverse of `pivot` (round-trips when `pivot`'s `agg`
/// doesn't collapse information, e.g. one row per row_key×col_key already).
/// `out_value`'s declared type is the first melted column's type — melted
/// columns of mixed types are still carried correctly (`Value` is
/// self-describing), this only affects the type hint on the output column.
pub fn unpivot(a: std.mem.Allocator, d: Dataset, spec: UnpivotSpec) Error!Dataset {
    const id_idxs = try a.alloc(usize, spec.id_cols.len);
    for (spec.id_cols, 0..) |name, i| id_idxs[i] = try mustIndex(d, name);

    var val_idxs: std.ArrayList(usize) = .empty;
    if (spec.value_cols.len > 0) {
        for (spec.value_cols) |name| try val_idxs.append(a, try mustIndex(d, name));
    } else {
        col_loop: for (0..d.columns.len) |ci| {
            for (id_idxs) |ii| if (ii == ci) continue :col_loop;
            try val_idxs.append(a, ci);
        }
    }

    const out_value_type: ColumnType = if (val_idxs.items.len > 0) d.columns[val_idxs.items[0]].type else .text;
    const cols = try a.alloc(Column, id_idxs.len + 2);
    for (id_idxs, 0..) |ii, i| cols[i] = d.columns[ii];
    cols[id_idxs.len] = .{ .name = spec.out_key, .type = .text };
    cols[id_idxs.len + 1] = .{ .name = spec.out_value, .type = out_value_type };

    var rows: std.ArrayList([]const Value) = .empty;
    for (d.rows) |r| {
        for (val_idxs.items) |vi| {
            const nr = try a.alloc(Value, cols.len);
            for (id_idxs, 0..) |ii, ci| nr[ci] = r[ii];
            nr[id_idxs.len] = .{ .text = d.columns[vi].name };
            nr[id_idxs.len + 1] = r[vi];
            try rows.append(a, nr);
        }
    }
    return .{ .columns = cols, .rows = try rows.toOwnedSlice(a) };
}

// ── resample ────────────────────────────────────────────────────────────────

pub const Freq = enum { day, month, year };
pub const ResampleAgg = enum { sum, mean, last, first, compound };

pub const ResampleSpec = struct {
    date_col: []const u8,
    value_col: []const u8,
    freq: Freq,
    agg: ResampleAgg = .sum,
    out_date: []const u8 = "period",
    out_value: []const u8 = "value",
};

const ResAcc = struct {
    sum: f64 = 0,
    count: u64 = 0,
    first: f64 = 0,
    last: f64 = 0,
    compound: f64 = 1,
    has: bool = false,

    fn observe(self: *ResAcc, v: f64) void {
        self.sum += v;
        self.compound *= (1 + v);
        self.last = v;
        if (!self.has) self.first = v;
        self.has = true;
        self.count += 1;
    }
    fn result(self: ResAcc, agg: ResampleAgg) f64 {
        return switch (agg) {
            .sum => self.sum,
            .mean => if (self.count == 0) 0 else self.sum / @as(f64, @floatFromInt(self.count)),
            .first => self.first,
            .last => self.last,
            .compound => self.compound - 1,
        };
    }
};

/// Bucket a dated series by `freq`, aggregating the value. Bucket labels: day →
/// "YYYY-MM-DD", month → "YYYY-MM", year → "YYYY" (all lexicographically
/// ordered). `compound` = Π(1+v)−1 (return chaining). Rows with an unparseable
/// date are skipped. Output: `{out_date (text), out_value (float)}`, ascending.
pub fn resample(a: std.mem.Allocator, d: Dataset, spec: ResampleSpec) Error!Dataset {
    const di = try mustIndex(d, spec.date_col);
    const vi = try mustIndex(d, spec.value_col);

    var buckets: std.StringArrayHashMapUnmanaged(ResAcc) = .empty;
    for (d.rows) |r| {
        const date = rowDate(d, di, r) orelse continue;
        const label = try bucketLabel(a, date, spec.freq);
        const bop = try buckets.getOrPut(a, label);
        if (!bop.found_existing) bop.value_ptr.* = .{};
        bop.value_ptr.observe(r[vi].asFloat() orelse 0);
    }

    const keys = try a.alloc([]const u8, buckets.count());
    for (buckets.keys(), 0..) |k, i| keys[i] = k;
    std.mem.sort([]const u8, keys, {}, strLess);

    const cols = try a.alloc(Column, 2);
    cols[0] = .{ .name = spec.out_date, .type = if (spec.freq == .day) .date else .text };
    cols[1] = .{ .name = spec.out_value, .type = .float };
    const rows = try a.alloc([]const Value, keys.len);
    for (keys, 0..) |k, i| {
        const nr = try a.alloc(Value, 2);
        nr[0] = .{ .text = k };
        nr[1] = .{ .float = buckets.get(k).?.result(spec.agg) };
        rows[i] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

fn bucketLabel(a: std.mem.Allocator, date: ds.Date, freq: Freq) Error![]const u8 {
    // Cast the year to unsigned: zero-padding a signed int reserves a sign slot
    // ('+2024'). Real dates are positive; clamp defensively.
    const y: u32 = if (date.y < 0) 0 else @intCast(date.y);
    return switch (freq) {
        .day => std.fmt.allocPrint(a, "{d:0>4}-{d:0>2}-{d:0>2}", .{ y, date.m, date.d }),
        .month => std.fmt.allocPrint(a, "{d:0>4}-{d:0>2}", .{ y, date.m }),
        .year => std.fmt.allocPrint(a, "{d:0>4}", .{y}),
    };
}

/// The calendar date (UTC) of a row's date cell: ISO text in any column, or —
/// in a `.timestamp` column — an `.int` of microseconds since the epoch.
fn rowDate(d: Dataset, di: usize, r: []const Value) ?ds.Date {
    if (d.columns[di].type == .timestamp and r[di] == .int)
        return ds.Date.fromOrdinal(@divFloor(r[di].int, 86_400 * ds.timestamp_units_per_second));
    return ds.parseIsoDate(r[di].asText() orelse return null);
}

// ── reduce ──────────────────────────────────────────────────────────────────

/// KPI reduction: aggregate the whole table into a single row (aggregate with no
/// group-by). Output has one row and one column per `aggs` entry.
pub fn reduce(a: std.mem.Allocator, d: Dataset, aggs: []const AggCol) Error!Dataset {
    return aggregate(a, d, .{ .group_by = &.{}, .aggs = aggs });
}

// ── clamp_range ─────────────────────────────────────────────────────────────

pub const ClampRangeSpec = struct {
    date_col: []const u8,
    /// Inclusive ISO bounds; null = unbounded on that side.
    from: ?[]const u8 = null,
    to: ?[]const u8 = null,
};

/// Keep rows whose `date_col` (ISO) falls within [from, to] inclusive. Rows with
/// an unparseable date are dropped.
pub fn clampRange(a: std.mem.Allocator, d: Dataset, spec: ClampRangeSpec) Error!Dataset {
    const di = try mustIndex(d, spec.date_col);
    const from_ord: ?i64 = if (spec.from) |f| (ds.parseIsoDate(f) orelse return Error.NoSuchColumn).ordinal() else null;
    const to_ord: ?i64 = if (spec.to) |t| (ds.parseIsoDate(t) orelse return Error.NoSuchColumn).ordinal() else null;

    var kept: std.ArrayList([]const Value) = .empty;
    for (d.rows) |r| {
        const date = rowDate(d, di, r) orelse continue;
        const o = date.ordinal();
        if (from_ord) |f| if (o < f) continue;
        if (to_ord) |t| if (o > t) continue;
        try kept.append(a, r);
    }
    return .{ .columns = d.columns, .rows = try kept.toOwnedSlice(a) };
}

// ── filter ──────────────────────────────────────────────────────────────────

pub const CmpOp = enum { eq, ne, lt, le, gt, ge, is_null, not_null };

/// `col op value`. A MISSING cell (null, or a NaN float) satisfies only
/// `is_null` — every comparison against it is false, `ne` included (SQL's
/// three-valued rule: an absent value is not "different", it is unknown).
/// A comparison needs comparable kinds: number with number (int/float/decimal
/// by value, two decimals exactly), text with text (bytewise, so ISO dates
/// order correctly), bool with bool. A cell of another kind than `value`
/// matches nothing — a numeric cell never equals a text literal.
pub const Predicate = struct {
    col: []const u8,
    op: CmpOp,
    /// Ignored by `is_null` / `not_null`.
    value: Value = .null,
};

pub const FilterSpec = struct {
    where: []const Predicate,
    /// `.all`: a row is kept when every predicate holds (AND; an empty
    /// `where` keeps every row). `.any`: when at least one holds (OR; an
    /// empty `where` keeps none).
    mode: enum { all, any } = .all,
};

fn isMissing(v: Value) bool {
    return v == .null or (v == .float and std.math.isNan(v.float));
}

fn kindOf(v: Value) enum { number, text, bool, other } {
    return switch (v) {
        .int, .float, .decimal => .number,
        .text => .text,
        .bool => .bool,
        .null => .other,
    };
}

fn holds(p: Predicate, cell: Value) bool {
    const missing = isMissing(cell);
    switch (p.op) {
        .is_null => return missing,
        .not_null => return !missing,
        else => {},
    }
    if (missing or isMissing(p.value)) return false;
    if (kindOf(cell) != kindOf(p.value)) return false;
    const o = cell.order(p.value);
    return switch (p.op) {
        .eq => o == .eq,
        .ne => o != .eq,
        .lt => o == .lt,
        .le => o != .gt,
        .gt => o == .gt,
        .ge => o != .lt,
        .is_null, .not_null => unreachable,
    };
}

/// Keep the rows satisfying `spec` (rows are borrowed, not copied).
pub fn filter(a: std.mem.Allocator, d: Dataset, spec: FilterSpec) Error!Dataset {
    const idxs = try a.alloc(usize, spec.where.len);
    for (spec.where, 0..) |p, i| idxs[i] = try mustIndex(d, p.col);
    var kept: std.ArrayList([]const Value) = .empty;
    for (d.rows) |r| {
        const keep = switch (spec.mode) {
            .all => blk: {
                for (spec.where, idxs) |p, ci| if (!holds(p, r[ci])) break :blk false;
                break :blk true;
            },
            .any => blk: {
                for (spec.where, idxs) |p, ci| if (holds(p, r[ci])) break :blk true;
                break :blk false;
            },
        };
        if (keep) try kept.append(a, r);
    }
    return .{ .columns = d.columns, .rows = try kept.toOwnedSlice(a) };
}

/// Keep the rows for which `predicate(context, row)` is true — the escape
/// hatch for any logic `filter`'s spec cannot say. Rows are borrowed.
pub fn filterBy(
    a: std.mem.Allocator,
    d: Dataset,
    context: anytype,
    comptime predicate: fn (@TypeOf(context), []const Value) bool,
) Error!Dataset {
    var kept: std.ArrayList([]const Value) = .empty;
    for (d.rows) |r| if (predicate(context, r)) try kept.append(a, r);
    return .{ .columns = d.columns, .rows = try kept.toOwnedSlice(a) };
}

// ── select / drop / rename ──────────────────────────────────────────────────

/// `select`/`rename`'s error set: a result with two columns of the same name
/// is refused, since `Dataset.columnIndex` would only ever find the first.
pub const ColumnsError = Error || error{DuplicateColumn};

fn project(a: std.mem.Allocator, d: Dataset, idxs: []const usize) Error!Dataset {
    const cols = try a.alloc(Column, idxs.len);
    for (idxs, 0..) |ci, i| cols[i] = d.columns[ci];
    const rows = try a.alloc([]const Value, d.rows.len);
    for (d.rows, 0..) |r, ri| {
        const nr = try a.alloc(Value, idxs.len);
        for (idxs, 0..) |ci, i| nr[i] = r[ci];
        rows[ri] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

/// Keep exactly `names`, in that order.
pub fn select(a: std.mem.Allocator, d: Dataset, names: []const []const u8) ColumnsError!Dataset {
    const idxs = try a.alloc(usize, names.len);
    for (names, 0..) |n, i| {
        for (names[0..i]) |prev| if (std.mem.eql(u8, prev, n)) return error.DuplicateColumn;
        idxs[i] = try mustIndex(d, n);
    }
    return project(a, d, idxs);
}

/// Remove `names` (each must exist); the rest keep their order.
pub fn drop(a: std.mem.Allocator, d: Dataset, names: []const []const u8) Error!Dataset {
    const gone = try a.alloc(bool, d.columns.len);
    @memset(gone, false);
    for (names) |n| gone[try mustIndex(d, n)] = true;
    var idxs: std.ArrayList(usize) = .empty;
    for (gone, 0..) |g, ci| if (!g) try idxs.append(a, ci);
    return project(a, d, idxs.items);
}

pub const Rename = struct { from: []const u8, to: []const u8 };

/// Rename columns; rows are shared with `d` (only the schema is new). Each
/// `from` must exist; renames apply simultaneously (`a→b, b→a` swaps).
pub fn rename(a: std.mem.Allocator, d: Dataset, renames: []const Rename) ColumnsError!Dataset {
    const cols = try a.dupe(Column, d.columns);
    const touched = try a.alloc(bool, d.columns.len);
    @memset(touched, false);
    for (renames) |rn| {
        const ci = try mustIndex(d, rn.from);
        if (touched[ci]) return error.DuplicateColumn; // the same column renamed twice
        touched[ci] = true;
        cols[ci].name = rn.to;
    }
    for (cols, 0..) |c, i| {
        if (!touched[i]) continue;
        for (cols, 0..) |o, j| if (i != j and std.mem.eql(u8, c.name, o.name)) return error.DuplicateColumn;
    }
    return .{ .columns = cols, .rows = d.rows };
}

// ── dropna / fillna ─────────────────────────────────────────────────────────

/// Missing = null, or a NaN float (pandas' `isna`).
pub const DropNaSpec = struct {
    /// Columns to inspect; empty = every column.
    subset: []const []const u8 = &.{},
    /// `.any`: drop a row with any missing cell in `subset`; `.all`: only a
    /// row whose `subset` cells are all missing.
    how: enum { any, all } = .any,
};

fn subsetIdxs(a: std.mem.Allocator, d: Dataset, subset: []const []const u8) Error![]const usize {
    const n = if (subset.len == 0) d.columns.len else subset.len;
    const idxs = try a.alloc(usize, n);
    for (idxs, 0..) |*ix, i| ix.* = if (subset.len == 0) i else try mustIndex(d, subset[i]);
    return idxs;
}

pub fn dropna(a: std.mem.Allocator, d: Dataset, spec: DropNaSpec) Error!Dataset {
    const idxs = try subsetIdxs(a, d, spec.subset);
    var kept: std.ArrayList([]const Value) = .empty;
    for (d.rows) |r| {
        var n_missing: usize = 0;
        for (idxs) |ci| n_missing += @intFromBool(isMissing(r[ci]));
        const drop_row = switch (spec.how) {
            .any => n_missing > 0,
            .all => n_missing == idxs.len and idxs.len > 0,
        };
        if (!drop_row) try kept.append(a, r);
    }
    return .{ .columns = d.columns, .rows = try kept.toOwnedSlice(a) };
}

pub const FillNaSpec = struct {
    /// Columns to fill; empty = every column.
    subset: []const []const u8 = &.{},
    /// Written into every missing cell as is — the column's declared type is
    /// not changed, so fill a `.float` column with a `.float`.
    value: Value,
};

/// Replace missing cells (null, NaN). Rows without a missing cell in `subset`
/// are shared with `d`, not copied.
pub fn fillna(a: std.mem.Allocator, d: Dataset, spec: FillNaSpec) Error!Dataset {
    const idxs = try subsetIdxs(a, d, spec.subset);
    const rows = try a.alloc([]const Value, d.rows.len);
    for (d.rows, 0..) |r, ri| {
        rows[ri] = r;
        for (idxs) |ci| {
            if (!isMissing(r[ci])) continue;
            const nr = try a.dupe(Value, r);
            for (idxs) |cj| if (isMissing(nr[cj])) {
                nr[cj] = spec.value;
            };
            rows[ri] = nr;
            break;
        }
    }
    return .{ .columns = d.columns, .rows = rows };
}

// ── format ──────────────────────────────────────────────────────────────────

pub const FormatKind = enum { num, money, pct, compact, signed };
pub const FormatSpec = struct {
    kind: FormatKind = .num,
    decimals: u8 = 2,
    /// Symbol prefix for `money` (e.g. "$", "€", "" for none).
    symbol: []const u8 = "",
};

/// Format a numeric value for presentation. (Formatting is a presentation
/// modifier, not a dataset node — this is the value-level helper; `formatColumn`
/// wraps it into a dataset transform.)
pub fn format(a: std.mem.Allocator, value: f64, spec: FormatSpec) Error![]const u8 {
    const p: usize = spec.decimals; // runtime precision via named "{[n]d:.[p]}"
    return switch (spec.kind) {
        .num => std.fmt.allocPrint(a, "{[n]d:.[p]}", .{ .n = value, .p = p }),
        .money => std.fmt.allocPrint(a, "{[s]s}{[n]d:.[p]}", .{ .s = spec.symbol, .n = value, .p = p }),
        .pct => std.fmt.allocPrint(a, "{[n]d:.[p]}%", .{ .n = value * 100, .p = p }),
        .signed => std.fmt.allocPrint(a, "{[s]s}{[n]d:.[p]}", .{ .s = if (value >= 0) "+" else "", .n = value, .p = p }),
        .compact => blk: {
            const av = @abs(value);
            const suffix: []const u8, const div: f64 = if (av >= 1e9)
                .{ "B", 1e9 }
            else if (av >= 1e6)
                .{ "M", 1e6 }
            else if (av >= 1e3)
                .{ "K", 1e3 }
            else
                .{ "", 1 };
            break :blk std.fmt.allocPrint(a, "{[n]d:.[p]}{[s]s}", .{ .n = value / div, .p = p, .s = suffix });
        },
    };
}

/// Append a text column `out` = `format(row[src], spec)` (non-numeric → "").
pub fn formatColumn(a: std.mem.Allocator, d: Dataset, src: []const u8, out: []const u8, spec: FormatSpec) Error!Dataset {
    const si = try mustIndex(d, src);
    const cols = try a.alloc(Column, d.columns.len + 1);
    @memcpy(cols[0..d.columns.len], d.columns);
    cols[d.columns.len] = .{ .name = out, .type = .text };
    const rows = try a.alloc([]const Value, d.rows.len);
    for (d.rows, 0..) |r, ri| {
        const txt: []const u8 = if (r[si].asFloat()) |f| try format(a, f, spec) else "";
        const nr = try a.alloc(Value, cols.len);
        @memcpy(nr[0..d.columns.len], r);
        nr[d.columns.len] = .{ .text = txt };
        rows[ri] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

// ── tests ───────────────────────────────────────────────────────────────────
const testing = std.testing;

/// A fixture arena that frees everything on deinit — mirrors the pipeline arena.
const Fix = struct {
    arena: std.heap.ArenaAllocator,
    fn init() Fix {
        return .{ .arena = std.heap.ArenaAllocator.init(testing.allocator) };
    }
    fn deinit(self: *Fix) void {
        self.arena.deinit();
    }
    fn a(self: *Fix) std.mem.Allocator {
        return self.arena.allocator();
    }
};

test "map: pl = mv - cost" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "mv", .type = .float }, .{ .name = "cost", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .float = 100 }, .{ .float = 70 } },
        &.{ .{ .float = 50 }, .{ .float = 80 } },
    };
    const out = try map(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .out = "pl",
        .lhs = .{ .col = "mv" },
        .op = .sub,
        .rhs = .{ .col = "cost" },
    });
    try testing.expectEqual(@as(usize, 3), out.columns.len);
    try testing.expectEqual(@as(f64, 30), out.cell(0, "pl").?.float);
    try testing.expectEqual(@as(f64, -30), out.cell(1, "pl").?.float);
}

test "aggregate: group sum" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "cat", .type = .text }, .{ .name = "v", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "a" }, .{ .float = 1 } },
        &.{ .{ .text = "b" }, .{ .float = 10 } },
        &.{ .{ .text = "a" }, .{ .float = 2 } },
    };
    const out = try aggregate(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .group_by = &.{"cat"},
        .aggs = &.{.{ .src = "v", .out = "total", .func = .sum }},
    });
    try testing.expectEqual(@as(usize, 2), out.rows.len); // a, b in first-seen order
    try testing.expectEqualStrings("a", out.cell(0, "cat").?.text);
    try testing.expectEqual(@as(f64, 3), out.cell(0, "total").?.float);
    try testing.expectEqual(@as(f64, 10), out.cell(1, "total").?.float);
}

test "aggregate: fx-convert-before-sum (null rate = 1.0)" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{
        .{ .name = "ccy", .type = .text },
        .{ .name = "amt", .type = .float },
        .{ .name = "fx", .type = .float },
    };
    const rows = [_][]const Value{
        &.{ .{ .text = "x" }, .{ .float = 100 }, .{ .float = 2 } }, // 200
        &.{ .{ .text = "x" }, .{ .float = 50 }, .null }, // null rate → 50
    };
    const out = try aggregate(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .group_by = &.{"ccy"},
        .aggs = &.{.{ .src = "amt", .out = "base", .func = .sum }},
        .fx = .{ .rate_col = "fx" },
    });
    try testing.expectEqual(@as(f64, 250), out.cell(0, "base").?.float);
}

test "aggregate: mean/min/max/count/first/last" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "g", .type = .text }, .{ .name = "v", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "g" }, .{ .float = 4 } },
        &.{ .{ .text = "g" }, .{ .float = 2 } },
        &.{ .{ .text = "g" }, .{ .float = 6 } },
    };
    const out = try aggregate(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .group_by = &.{"g"},
        .aggs = &.{
            .{ .src = "v", .out = "mean", .func = .mean },
            .{ .src = "v", .out = "min", .func = .min },
            .{ .src = "v", .out = "max", .func = .max },
            .{ .src = "v", .out = "n", .func = .count },
            .{ .src = "v", .out = "first", .func = .first },
            .{ .src = "v", .out = "last", .func = .last },
        },
    });
    try testing.expectEqual(@as(f64, 4), out.cell(0, "mean").?.float);
    try testing.expectEqual(@as(f64, 2), out.cell(0, "min").?.float);
    try testing.expectEqual(@as(f64, 6), out.cell(0, "max").?.float);
    try testing.expectEqual(@as(i64, 3), out.cell(0, "n").?.int);
    try testing.expectEqual(@as(f64, 4), out.cell(0, "first").?.float);
    try testing.expectEqual(@as(f64, 6), out.cell(0, "last").?.float);
}

test "weightedGroupSum: weighted alloc + unassigned bucket" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{
        .{ .name = "cat", .type = .text },
        .{ .name = "mv", .type = .float },
        .{ .name = "w", .type = .float },
    };
    const rows = [_][]const Value{
        &.{ .{ .text = "equity" }, .{ .float = 100 }, .{ .float = 0.6 } }, // 60
        &.{ .{ .text = "bond" }, .{ .float = 100 }, .{ .float = 0.4 } }, // 40
        &.{ .null, .{ .float = 25 }, .{ .float = 1 } }, // 25 → (unassigned)
    };
    const out = try weightedGroupSum(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .group_col = "cat",
        .value_col = "mv",
        .weight_col = "w",
    });
    try testing.expectEqual(@as(usize, 3), out.rows.len);
    try testing.expectEqual(@as(f64, 60), out.cell(0, "value").?.float);
    try testing.expectEqual(@as(f64, 40), out.cell(1, "value").?.float);
    try testing.expectEqualStrings("(unassigned)", out.cell(2, "group").?.text);
    try testing.expectEqual(@as(f64, 25), out.cell(2, "value").?.float);
}

test "percentOfTotal shares sum to 100" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "cat", .type = .text }, .{ .name = "v", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "a" }, .{ .float = 30 } },
        &.{ .{ .text = "b" }, .{ .float = 10 } },
        &.{ .{ .text = "c" }, .{ .float = 60 } },
    };
    const out = try percentOfTotal(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .value_col = "v", .out = "pct" });
    try testing.expectApproxEqAbs(@as(f64, 30), out.cell(0, "pct").?.float, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 60), out.cell(2, "pct").?.float, 1e-9);
}

test "sort: desc by value" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "s", .type = .text }, .{ .name = "v", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "a" }, .{ .float = 1 } },
        &.{ .{ .text = "b" }, .{ .float = 3 } },
        &.{ .{ .text = "c" }, .{ .float = 2 } },
    };
    const out = try sort(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .key = "v", .dir = .desc });
    try testing.expectEqualStrings("b", out.cell(0, "s").?.text);
    try testing.expectEqualStrings("c", out.cell(1, "s").?.text);
    try testing.expectEqualStrings("a", out.cell(2, "s").?.text);
}

test "sort: multi-column tie-break" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "grp", .type = .text }, .{ .name = "v", .type = .float }, .{ .name = "s", .type = .text } };
    const rows = [_][]const Value{
        &.{ .{ .text = "b" }, .{ .float = 1 }, .{ .text = "b1" } },
        &.{ .{ .text = "a" }, .{ .float = 2 }, .{ .text = "a2" } },
        &.{ .{ .text = "a" }, .{ .float = 1 }, .{ .text = "a1" } },
    };
    // primary key `grp` alone would leave the two "a" rows in input order
    // (a2 before a1) — the tie-break on `v` must reorder them to a1, a2.
    const out = try sort(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .key = "grp",
        .then_by = &.{.{ .key = "v" }},
    });
    try testing.expectEqualStrings("a1", out.cell(0, "s").?.text);
    try testing.expectEqualStrings("a2", out.cell(1, "s").?.text);
    try testing.expectEqualStrings("b1", out.cell(2, "s").?.text);
}

test "page: limit/offset windows correctly" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{.{ .name = "v", .type = .int }};
    const rows = [_][]const Value{
        &.{.{ .int = 0 }}, &.{.{ .int = 1 }}, &.{.{ .int = 2 }}, &.{.{ .int = 3 }}, &.{.{ .int = 4 }},
    };
    const mid = try page(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .offset = 1, .limit = 2 });
    try testing.expectEqual(@as(usize, 2), mid.rows.len);
    try testing.expectEqual(@as(i64, 1), mid.cell(0, "v").?.int);
    try testing.expectEqual(@as(i64, 2), mid.cell(1, "v").?.int);

    const tail = try page(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .offset = 3 }); // no limit → to the end
    try testing.expectEqual(@as(usize, 2), tail.rows.len);
    try testing.expectEqual(@as(i64, 3), tail.cell(0, "v").?.int);

    const past_end = try page(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .offset = 99, .limit = 5 });
    try testing.expectEqual(@as(usize, 0), past_end.rows.len);
}

test "topN with tail fold" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "s", .type = .text }, .{ .name = "v", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "a" }, .{ .float = 10 } },
        &.{ .{ .text = "b" }, .{ .float = 5 } },
        &.{ .{ .text = "c" }, .{ .float = 3 } },
        &.{ .{ .text = "d" }, .{ .float = 2 } },
    };
    const out = try topN(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .n = 2,
        .tail = .{ .label_col = "s", .label = "Other", .value_col = "v" },
    });
    try testing.expectEqual(@as(usize, 3), out.rows.len);
    try testing.expectEqualStrings("Other", out.cell(2, "s").?.text);
    try testing.expectEqual(@as(f64, 5), out.cell(2, "v").?.float); // 3 + 2
}

test "pivot: month x year" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{
        .{ .name = "year", .type = .text },
        .{ .name = "month", .type = .text },
        .{ .name = "ret", .type = .float },
    };
    const rows = [_][]const Value{
        &.{ .{ .text = "2023" }, .{ .text = "01" }, .{ .float = 1 } },
        &.{ .{ .text = "2023" }, .{ .text = "02" }, .{ .float = 2 } },
        &.{ .{ .text = "2024" }, .{ .text = "01" }, .{ .float = 3 } },
    };
    const out = try pivot(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .row_key = "year",
        .col_key = "month",
        .value_col = "ret",
    });
    try testing.expectEqual(@as(usize, 3), out.columns.len); // year, "01", "02"
    try testing.expectEqual(@as(usize, 2), out.rows.len);
    try testing.expectEqual(@as(f64, 1), out.cell(0, "01").?.float);
    try testing.expectEqual(@as(f64, 2), out.cell(0, "02").?.float);
    try testing.expectEqual(@as(f64, 3), out.cell(1, "01").?.float);
    try testing.expect(out.cell(1, "02").?.isNull()); // 2024-02 missing
}

test "pivot: numeric-aware column ordering puts 10 after 2, not before" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{
        .{ .name = "row", .type = .text },
        .{ .name = "week", .type = .text }, // unpadded numeric text: "2", "10"
        .{ .name = "v", .type = .float },
    };
    const rows = [_][]const Value{
        &.{ .{ .text = "r1" }, .{ .text = "10" }, .{ .float = 1 } },
        &.{ .{ .text = "r1" }, .{ .text = "2" }, .{ .float = 2 } },
        &.{ .{ .text = "r1" }, .{ .text = "9" }, .{ .float = 3 } },
    };
    const out = try pivot(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .row_key = "row", .col_key = "week", .value_col = "v" });
    // lexicographic would order "10" < "2" < "9"; numeric-aware must be 2, 9, 10.
    try testing.expectEqualStrings("2", out.columns[1].name);
    try testing.expectEqualStrings("9", out.columns[2].name);
    try testing.expectEqualStrings("10", out.columns[3].name);
}

test "pivot: non-numeric column keys still sort lexicographically" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{
        .{ .name = "row", .type = .text },
        .{ .name = "cat", .type = .text },
        .{ .name = "v", .type = .float },
    };
    const rows = [_][]const Value{
        &.{ .{ .text = "r1" }, .{ .text = "beta" }, .{ .float = 1 } },
        &.{ .{ .text = "r1" }, .{ .text = "alpha" }, .{ .float = 2 } },
    };
    const out = try pivot(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .row_key = "row", .col_key = "cat", .value_col = "v" });
    try testing.expectEqualStrings("alpha", out.columns[1].name);
    try testing.expectEqualStrings("beta", out.columns[2].name);
}

test "unpivot: wide -> long round-trips a known wide table" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{
        .{ .name = "id", .type = .text },
        .{ .name = "jan", .type = .float },
        .{ .name = "feb", .type = .float },
    };
    const rows = [_][]const Value{
        &.{ .{ .text = "AAA" }, .{ .float = 10 }, .{ .float = 20 } },
        &.{ .{ .text = "BBB" }, .{ .float = 30 }, .{ .float = 40 } },
    };
    const out = try unpivot(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .id_cols = &.{"id"} });
    try testing.expectEqual(@as(usize, 4), out.rows.len); // 2 rows x 2 melted cols
    try testing.expectEqual(@as(usize, 3), out.columns.len); // id, variable, value
    try testing.expectEqualStrings("AAA", out.cell(0, "id").?.text);
    try testing.expectEqualStrings("jan", out.cell(0, "variable").?.text);
    try testing.expectApproxEqAbs(@as(f64, 10), out.cell(0, "value").?.float, 1e-9);
    try testing.expectEqualStrings("feb", out.cell(1, "variable").?.text);
    try testing.expectApproxEqAbs(@as(f64, 20), out.cell(1, "value").?.float, 1e-9);
    try testing.expectEqualStrings("BBB", out.cell(2, "id").?.text);
    try testing.expectEqualStrings("jan", out.cell(2, "variable").?.text);
    try testing.expectApproxEqAbs(@as(f64, 30), out.cell(2, "value").?.float, 1e-9);

    // round-trip: pivot the melted table back and recover the original cells.
    const back = try pivot(f.a(), out, .{ .row_key = "id", .col_key = "variable", .value_col = "value" });
    try testing.expectApproxEqAbs(@as(f64, 10), back.cell(0, "jan").?.float, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 20), back.cell(0, "feb").?.float, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 30), back.cell(1, "jan").?.float, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 40), back.cell(1, "feb").?.float, 1e-9);
}

test "resample: monthly compound + sum" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "d", .type = .date }, .{ .name = "r", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "2024-01-10" }, .{ .float = 0.1 } },
        &.{ .{ .text = "2024-01-20" }, .{ .float = 0.1 } },
        &.{ .{ .text = "2024-02-05" }, .{ .float = 0.5 } },
    };
    const comp = try resample(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .date_col = "d",
        .value_col = "r",
        .freq = .month,
        .agg = .compound,
    });
    try testing.expectEqual(@as(usize, 2), comp.rows.len);
    try testing.expectEqualStrings("2024-01", comp.cell(0, "period").?.text);
    try testing.expectApproxEqAbs(@as(f64, 0.21), comp.cell(0, "value").?.float, 1e-9); // 1.1*1.1-1
    try testing.expectApproxEqAbs(@as(f64, 0.5), comp.cell(1, "value").?.float, 1e-9);
}

test "resample: sum/mean/first/last aggregations" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "d", .type = .date }, .{ .name = "r", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "2024-01-10" }, .{ .float = 1 } },
        &.{ .{ .text = "2024-01-20" }, .{ .float = 2 } },
        &.{ .{ .text = "2024-01-25" }, .{ .float = 3 } },
    };
    const sum_out = try resample(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .date_col = "d",
        .value_col = "r",
        .freq = .month,
        .agg = .sum,
    });
    try testing.expectApproxEqAbs(@as(f64, 6), sum_out.cell(0, "value").?.float, 1e-9);

    const mean_out = try resample(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .date_col = "d",
        .value_col = "r",
        .freq = .month,
        .agg = .mean,
    });
    try testing.expectApproxEqAbs(@as(f64, 2), mean_out.cell(0, "value").?.float, 1e-9);

    const first_out = try resample(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .date_col = "d",
        .value_col = "r",
        .freq = .month,
        .agg = .first,
    });
    try testing.expectApproxEqAbs(@as(f64, 1), first_out.cell(0, "value").?.float, 1e-9);

    const last_out = try resample(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .date_col = "d",
        .value_col = "r",
        .freq = .month,
        .agg = .last,
    });
    try testing.expectApproxEqAbs(@as(f64, 3), last_out.cell(0, "value").?.float, 1e-9);
}

test "formatColumn: numeric cells formatted, non-numeric -> empty string" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "amt", .type = .float }, .{ .name = "tag", .type = .text } };
    const rows = [_][]const Value{
        &.{ .{ .float = 1234.5 }, .{ .text = "x" } },
        &.{ .{ .text = "n/a" }, .{ .text = "y" } }, // non-numeric src cell
    };
    const out = try formatColumn(f.a(), .{ .columns = &cols, .rows = &rows }, "amt", "amt_fmt", .{ .kind = .money, .symbol = "$" });
    try testing.expectEqual(@as(usize, 3), out.columns.len);
    try testing.expectEqualStrings("$1234.50", out.cell(0, "amt_fmt").?.text);
    try testing.expectEqualStrings("", out.cell(1, "amt_fmt").?.text);
}

test "reduce: table to one KPI row" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{.{ .name = "v", .type = .float }};
    const rows = [_][]const Value{
        &.{.{ .float = 3 }}, &.{.{ .float = 4 }}, &.{.{ .float = 5 }},
    };
    const out = try reduce(f.a(), .{ .columns = &cols, .rows = &rows }, &.{
        .{ .src = "v", .out = "total", .func = .sum },
        .{ .src = "v", .out = "n", .func = .count },
    });
    try testing.expectEqual(@as(usize, 1), out.rows.len);
    try testing.expectEqual(@as(f64, 12), out.cell(0, "total").?.float);
    try testing.expectEqual(@as(i64, 3), out.cell(0, "n").?.int);
}

test "clampRange: inclusive date window" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "d", .type = .date }, .{ .name = "v", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "2024-01-01" }, .{ .float = 1 } },
        &.{ .{ .text = "2024-06-15" }, .{ .float = 2 } },
        &.{ .{ .text = "2024-12-31" }, .{ .float = 3 } },
    };
    const out = try clampRange(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .date_col = "d",
        .from = "2024-03-01",
        .to = "2024-09-01",
    });
    try testing.expectEqual(@as(usize, 1), out.rows.len);
    try testing.expectEqual(@as(f64, 2), out.cell(0, "v").?.float);
}

test "clampRange: from/to bounds are inclusive at the exact edge" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "d", .type = .date }, .{ .name = "v", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "2024-03-01" }, .{ .float = 1 } }, // exactly `from`
        &.{ .{ .text = "2024-06-15" }, .{ .float = 2 } },
        &.{ .{ .text = "2024-09-01" }, .{ .float = 3 } }, // exactly `to`
    };
    const out = try clampRange(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .date_col = "d",
        .from = "2024-03-01",
        .to = "2024-09-01",
    });
    try testing.expectEqual(@as(usize, 3), out.rows.len); // all three kept, boundaries included
}

test "format: kinds" {
    var f = Fix.init();
    defer f.deinit();
    try testing.expectEqualStrings("1234.50", try format(f.a(), 1234.5, .{ .kind = .num }));
    try testing.expectEqualStrings("$1234.50", try format(f.a(), 1234.5, .{ .kind = .money, .symbol = "$" }));
    try testing.expectEqualStrings("12.30%", try format(f.a(), 0.123, .{ .kind = .pct }));
    try testing.expectEqualStrings("+5.00", try format(f.a(), 5, .{ .kind = .signed }));
    try testing.expectEqualStrings("-5.00", try format(f.a(), -5, .{ .kind = .signed }));
    try testing.expectEqualStrings("1.50M", try format(f.a(), 1_500_000, .{ .kind = .compact, .decimals = 2 }));
}

// ── 2026-10-04: filter / columns / NA / map ops / statistics ────────────────

const nan = std.math.nan(f64);

const filt_cols = [_]Column{ .{ .name = "x", .type = .float }, .{ .name = "s", .type = .text } };
const filt_rows = [_][]const Value{
    &.{ .{ .float = 1 }, .{ .text = "a" } },
    &.{ .null, .{ .text = "b" } },
    &.{ .{ .float = 3 }, .null },
    &.{ .{ .float = nan }, .{ .text = "a" } },
    &.{ .{ .int = 5 }, .{ .text = "c" } },
};
const filt_ds: Dataset = .{ .columns = &filt_cols, .rows = &filt_rows };

fn keptRows(d: Dataset) [8]usize {
    // Index of each kept row in `filt_rows` (they are borrowed, so pointer
    // identity tells which), padded with maxInt.
    var out = [_]usize{std.math.maxInt(usize)} ** 8;
    for (d.rows, 0..) |r, i| {
        for (filt_rows, 0..) |orig, j| if (r.ptr == orig.ptr) {
            out[i] = j;
        };
    }
    return out;
}

fn expectKept(d: Dataset, want: []const usize) !void {
    try testing.expectEqual(want.len, d.rows.len);
    const got = keptRows(d);
    try testing.expectEqualSlices(usize, want, got[0..want.len]);
}

test "filter: SQL three-valued rule — a missing cell (null or NaN) matches only is_null" {
    var f = Fix.init();
    defer f.deinit();
    const a = f.a();
    // x > 2: 3 and the int 5 (int and float compare by value).
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "x", .op = .gt, .value = .{ .float = 2 } }} }), &.{ 2, 4 });
    // x != 1: NOT the null row and NOT the NaN row — unknown is not "different".
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "x", .op = .ne, .value = .{ .int = 1 } }} }), &.{ 2, 4 });
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "x", .op = .is_null }} }), &.{ 1, 3 });
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "x", .op = .not_null }} }), &.{ 0, 2, 4 });
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "x", .op = .le, .value = .{ .float = 3 } }} }), &.{ 0, 2 });
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "x", .op = .ge, .value = .{ .float = 3 } }} }), &.{ 2, 4 });
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "x", .op = .lt, .value = .{ .float = 3 } }} }), &.{0});
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "x", .op = .eq, .value = .{ .float = 3 } }} }), &.{2});
    // Text compares bytewise; a number never equals text, either way round.
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "s", .op = .eq, .value = .{ .text = "a" } }} }), &.{ 0, 3 });
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "s", .op = .gt, .value = .{ .text = "a" } }} }), &.{ 1, 4 });
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "x", .op = .eq, .value = .{ .text = "1" } }} }), &.{});
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "x", .op = .ne, .value = .{ .text = "1" } }} }), &.{});
    // A null literal compares with nothing.
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "x", .op = .ne }} }), &.{});
    // AND / OR, and the empty identities (all-of-nothing = true, any-of-nothing = false).
    const two = [_]Predicate{
        .{ .col = "x", .op = .lt, .value = .{ .float = 2 } },
        .{ .col = "s", .op = .eq, .value = .{ .text = "c" } },
    };
    try expectKept(try filter(a, filt_ds, .{ .where = &two, .mode = .any }), &.{ 0, 4 });
    try expectKept(try filter(a, filt_ds, .{ .where = &two }), &.{});
    const both = [_]Predicate{
        .{ .col = "x", .op = .not_null },
        .{ .col = "s", .op = .eq, .value = .{ .text = "a" } },
    };
    try expectKept(try filter(a, filt_ds, .{ .where = &both }), &.{0});
    try expectKept(try filter(a, filt_ds, .{ .where = &.{} }), &.{ 0, 1, 2, 3, 4 });
    try expectKept(try filter(a, filt_ds, .{ .where = &.{}, .mode = .any }), &.{});
    try testing.expectError(error.NoSuchColumn, filter(a, filt_ds, .{ .where = &.{.{ .col = "nope", .op = .is_null }} }));
    // Two decimals one raw unit apart are different values; f64 could not tell.
    const dc = [_]Column{.{ .name = "m", .type = .decimal }};
    const dr = [_][]const Value{ &.{.{ .decimal = (1 << 60) + 1 }}, &.{.{ .decimal = 1 << 60 }} };
    const dd = try filter(a, .{ .columns = &dc, .rows = &dr }, .{ .where = &.{.{ .col = "m", .op = .gt, .value = .{ .decimal = 1 << 60 } }} });
    try testing.expectEqual(@as(usize, 1), dd.rows.len);
    try testing.expectEqual(@as(i128, (1 << 60) + 1), dd.rows[0][0].decimal);
}

fn evenX(min: f64, row: []const Value) bool {
    const x = row[0].asFloat() orelse return false;
    return x >= min and @mod(x, 2) == 1;
}

test "filterBy: arbitrary predicate with context" {
    var f = Fix.init();
    defer f.deinit();
    try expectKept(try filterBy(f.a(), filt_ds, @as(f64, 2), evenX), &.{ 2, 4 });
}

test "select / drop / rename" {
    var f = Fix.init();
    defer f.deinit();
    const a = f.a();
    const cols = [_]Column{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .text }, .{ .name = "c", .type = .float } };
    const rows = [_][]const Value{&.{ .{ .int = 1 }, .{ .text = "x" }, .{ .float = 2.5 } }};
    const d: Dataset = .{ .columns = &cols, .rows = &rows };

    const s1 = try select(a, d, &.{ "c", "a" });
    try testing.expectEqual(@as(usize, 2), s1.columns.len);
    try testing.expectEqualStrings("c", s1.columns[0].name);
    try testing.expectEqual(ColumnType.float, s1.columns[0].type);
    try testing.expectEqual(@as(f64, 2.5), s1.rows[0][0].float);
    try testing.expectEqual(@as(i64, 1), s1.rows[0][1].int);
    try testing.expectError(error.DuplicateColumn, select(a, d, &.{ "a", "a" }));
    try testing.expectError(error.NoSuchColumn, select(a, d, &.{"z"}));

    const d1 = try drop(a, d, &.{"b"});
    try testing.expectEqual(@as(usize, 2), d1.columns.len);
    try testing.expectEqualStrings("a", d1.columns[0].name);
    try testing.expectEqualStrings("c", d1.columns[1].name);
    try testing.expectEqual(@as(f64, 2.5), d1.rows[0][1].float);
    try testing.expectError(error.NoSuchColumn, drop(a, d, &.{"z"}));
    try testing.expectEqual(@as(usize, 0), (try drop(a, d, &.{ "a", "b", "c" })).columns.len);

    // Simultaneous: a<->b swaps names, the cells stay where they were.
    const r1 = try rename(a, d, &.{ .{ .from = "a", .to = "b" }, .{ .from = "b", .to = "a" } });
    try testing.expectEqualStrings("b", r1.columns[0].name);
    try testing.expectEqualStrings("a", r1.columns[1].name);
    try testing.expectEqual(ColumnType.int, r1.columns[0].type);
    try testing.expect(r1.rows.ptr == d.rows.ptr); // rows shared, only the schema is new
    try testing.expectEqualStrings("a", d.columns[0].name); // input untouched
    try testing.expectError(error.DuplicateColumn, rename(a, d, &.{.{ .from = "a", .to = "c" }}));
    try testing.expectError(error.DuplicateColumn, rename(a, d, &.{ .{ .from = "a", .to = "p" }, .{ .from = "a", .to = "q" } }));
    try testing.expectError(error.NoSuchColumn, rename(a, d, &.{.{ .from = "z", .to = "y" }}));
    // Renaming to its own name is not a collision.
    _ = try rename(a, d, &.{.{ .from = "a", .to = "a" }});
}

test "dropna / fillna: null and NaN are missing" {
    var f = Fix.init();
    defer f.deinit();
    const a = f.a();
    try expectKept(try dropna(a, filt_ds, .{}), &.{ 0, 4 });
    try expectKept(try dropna(a, filt_ds, .{ .subset = &.{"x"} }), &.{ 0, 2, 4 });
    try expectKept(try dropna(a, filt_ds, .{ .subset = &.{"s"} }), &.{ 0, 1, 3, 4 });
    // how=all: no row here has BOTH cells missing.
    try expectKept(try dropna(a, filt_ds, .{ .how = .all }), &.{ 0, 1, 2, 3, 4 });
    const allnull = [_][]const Value{ &.{ .null, .null }, &.{ .{ .float = nan }, .{ .text = "k" } } };
    try testing.expectEqual(@as(usize, 1), (try dropna(a, .{ .columns = &filt_cols, .rows = &allnull }, .{ .how = .all })).rows.len);
    try testing.expectError(error.NoSuchColumn, dropna(a, filt_ds, .{ .subset = &.{"z"} }));

    const filled = try fillna(a, filt_ds, .{ .subset = &.{"x"}, .value = .{ .float = 0 } });
    try testing.expectEqual(@as(usize, 5), filled.rows.len);
    try testing.expectEqual(@as(f64, 0), filled.rows[1][0].float);
    try testing.expectEqual(@as(f64, 0), filled.rows[3][0].float); // NaN filled too
    try testing.expect(filled.rows[2][1] == .null); // outside the subset
    try testing.expect(filled.rows[0].ptr == filt_rows[0].ptr); // untouched rows shared
    try testing.expect(filled.rows[1].ptr != filt_rows[1].ptr);
    try testing.expect(filt_rows[1][0] == .null); // input not mutated
    const all = try fillna(a, filt_ds, .{ .value = .{ .text = "?" } });
    try testing.expectEqualStrings("?", all.rows[2][1].text);
    try testing.expectEqualStrings("?", all.rows[1][0].text);
}

test "map: abs / sqrt / min / max, and on_missing" {
    var f = Fix.init();
    defer f.deinit();
    const a = f.a();
    const cols = [_]Column{ .{ .name = "x", .type = .float }, .{ .name = "y", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .float = -4 }, .{ .float = 1 } },
        &.{ .{ .float = 9 }, .{ .float = 2 } },
        &.{ .null, .{ .float = 3 } },
        &.{ .{ .float = 6 }, .{ .float = 0 } },
    };
    const d: Dataset = .{ .columns = &cols, .rows = &rows };
    const Case = struct { op: BinOp, zero: [4]?f64, nul: [4]?f64 };
    const cases = [_]Case{
        // abs ignores rhs; null reads as 0 under .zero.
        .{ .op = .abs, .zero = .{ 4, 9, 0, 6 }, .nul = .{ 4, 9, null, 6 } },
        // sqrt(-4) has no real root: 0 / null; sqrt(9) = 3, sqrt(6) = 2.449…
        .{ .op = .sqrt, .zero = .{ 0, 3, 0, @sqrt(6.0) }, .nul = .{ null, 3, null, @sqrt(6.0) } },
        .{ .op = .min, .zero = .{ -4, 2, 0, 0 }, .nul = .{ -4, 2, null, 0 } },
        .{ .op = .max, .zero = .{ 1, 9, 3, 6 }, .nul = .{ 1, 9, null, 6 } },
        // 6 / 0 is undefined: 0 (historical) or null.
        .{ .op = .div, .zero = .{ -4, 4.5, 0, 0 }, .nul = .{ -4, 4.5, null, null } },
    };
    for (cases) |c| {
        for ([_]OnMissing{ .zero, .null }) |om| {
            const out = try map(a, d, .{ .out = "o", .lhs = .{ .col = "x" }, .op = c.op, .rhs = .{ .col = "y" }, .on_missing = om });
            const want = if (om == .zero) c.zero else c.nul;
            for (want, 0..) |w, i| {
                const got = out.rows[i][2];
                if (w) |wv| try testing.expectEqual(wv, got.float) else try testing.expect(got == .null);
            }
        }
    }
    // A unary op needs no rhs column — not even an existing one.
    const u = try map(a, d, .{ .out = "o", .lhs = .{ .col = "x" }, .op = .abs, .rhs = .{ .col = "missing" } });
    try testing.expectEqual(@as(f64, 4), u.rows[0][2].float);
    try testing.expectError(error.NoSuchColumn, map(a, d, .{ .out = "o", .lhs = .{ .col = "x" }, .op = .min, .rhs = .{ .col = "missing" } }));
}

test "aggregate: std / var / median / quantile / nunique skip missing values" {
    var f = Fix.init();
    defer f.deinit();
    const a = f.a();
    // Group "g": 2 4 4 4 5 5 7 9 plus a null, a NaN and a text cell. The
    // eight numbers are the textbook example with population sd 2: Σ(x−5)² = 32,
    // so the sample variance is 32/7.
    const cols = [_]Column{ .{ .name = "k", .type = .text }, .{ .name = "v", .type = .float } };
    var rows: std.ArrayList([]const Value) = .empty;
    for ([_]f64{ 2, 4, 4, 4, 5, 5, 7, 9 }) |x| try rows.append(a, try a.dupe(Value, &.{ .{ .text = "g" }, .{ .float = x } }));
    try rows.append(a, try a.dupe(Value, &.{ .{ .text = "g" }, .null }));
    try rows.append(a, try a.dupe(Value, &.{ .{ .text = "g" }, .{ .float = nan } }));
    try rows.append(a, try a.dupe(Value, &.{ .{ .text = "g" }, .{ .text = "x" } }));
    try rows.append(a, try a.dupe(Value, &.{ .{ .text = "h" }, .{ .int = 3 } }));
    const d: Dataset = .{ .columns = &cols, .rows = rows.items };
    const out = try aggregate(a, d, .{ .group_by = &.{"k"}, .aggs = &.{
        .{ .src = "v", .out = "sd", .func = .std },
        .{ .src = "v", .out = "var", .func = .@"var" },
        .{ .src = "v", .out = "med", .func = .median },
        .{ .src = "v", .out = "q25", .func = .quantile, .q = 0.25 },
        .{ .src = "v", .out = "q90", .func = .quantile, .q = 0.9 },
        .{ .src = "v", .out = "qbad", .func = .quantile, .q = 1.5 },
        .{ .src = "v", .out = "qnan", .func = .quantile, .q = nan },
        .{ .src = "v", .out = "nu", .func = .nunique },
        .{ .src = "v", .out = "q0", .func = .quantile, .q = 0 },
        .{ .src = "v", .out = "q1", .func = .quantile, .q = 1 },
    } });
    try testing.expectEqual(@as(usize, 2), out.rows.len);
    const g = out.rows[0];
    try testing.expectApproxEqRel(@sqrt(32.0 / 7.0), g[1].float, 1e-15);
    try testing.expectApproxEqRel(32.0 / 7.0, g[2].float, 1e-15);
    // Median of 8: mean of the 4th and 5th order statistics, (4 + 5) / 2.
    try testing.expectEqual(@as(f64, 4.5), g[3].float);
    // Type 7: h = 7·0.25 = 1.75 → x[1] + 0.75·(x[2] − x[1]) = 4 + 0.75·0 = 4.
    try testing.expectEqual(@as(f64, 4), g[4].float);
    // h = 7·0.9 = 6.3 → x[6] + 0.3·(x[7] − x[6]) = 7 + 0.3·2 = 7.6.
    try testing.expectApproxEqAbs(@as(f64, 7.6), g[5].float, 1e-12);
    try testing.expect(g[6] == .null);
    try testing.expect(g[7] == .null);
    // Distinct non-missing: 2 4 5 7 9 and the text "x" = 6 (null and NaN skipped).
    try testing.expectEqual(@as(i64, 6), g[8].int);
    try testing.expectEqual(@as(f64, 2), g[9].float);
    try testing.expectEqual(@as(f64, 9), g[10].float);
    // Group "h" has one value: no sample variance; the median is the value.
    const h = out.rows[1];
    try testing.expect(h[1] == .null);
    try testing.expect(h[2] == .null);
    try testing.expectEqual(@as(f64, 3), h[3].float);
    try testing.expectEqual(@as(i64, 1), h[8].int);
    try testing.expectEqual(ColumnType.float, out.columns[1].type);
    try testing.expectEqual(ColumnType.int, out.columns[8].type);
}

test "aggregate: nunique keys by kind — text \"1\" is not the number 1, float 1.0 is" {
    var f = Fix.init();
    defer f.deinit();
    const a = f.a();
    const cols = [_]Column{.{ .name = "v", .type = .text }};
    const rows = [_][]const Value{ &.{.{ .text = "1" }}, &.{.{ .int = 1 }}, &.{.{ .float = 1.0 }}, &.{.null} };
    const out = try reduce(a, .{ .columns = &cols, .rows = &rows }, &.{.{ .src = "v", .out = "n", .func = .nunique }});
    try testing.expectEqual(@as(i64, 2), out.rows[0][0].int);
}

test "aggregate: sum_exact is i128 addition, null on overflow" {
    var f = Fix.init();
    defer f.deinit();
    const a = f.a();
    const tenth: i128 = @divExact(ds.decimal_scale, 10);
    const cols = [_]Column{ .{ .name = "k", .type = .text }, .{ .name = "m", .type = .decimal }, .{ .name = "fx", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "a" }, .{ .decimal = tenth }, .null },
        &.{ .{ .text = "a" }, .{ .decimal = tenth }, .null },
        &.{ .{ .text = "a" }, .{ .decimal = tenth }, .null },
        &.{ .{ .text = "a" }, .{ .int = 2 }, .null },
        &.{ .{ .text = "a" }, .null, .null },
        &.{ .{ .text = "b" }, .{ .decimal = std.math.maxInt(i128) }, .null },
        &.{ .{ .text = "b" }, .{ .decimal = 1 }, .null },
        &.{ .{ .text = "b" }, .{ .decimal = -5 }, .null },
        &.{ .{ .text = "c" }, .{ .decimal = 3 * @divExact(ds.decimal_scale, 2) }, .{ .float = 2 } },
    };
    const d: Dataset = .{ .columns = &cols, .rows = &rows };
    const out = try aggregate(a, d, .{ .group_by = &.{"k"}, .aggs = &.{
        .{ .src = "m", .out = "exact", .func = .sum_exact },
        .{ .src = "m", .out = "f64", .func = .sum },
    } });
    try testing.expectEqual(ColumnType.decimal, out.columns[1].type);
    // 0.1 + 0.1 + 0.1 + 2 = 2.3 exactly; the null is skipped.
    try testing.expectEqual(@as(i128, 23 * tenth), out.rows[0][1].decimal);
    // Ten 0.1s: exactly 1 in i128; the f64 path gives Python's well-known
    // sum([0.1] * 10) = 0.9999999999999999.
    var ten: [10][]const Value = undefined;
    for (&ten) |*r| r.* = &.{ .{ .text = "a" }, .{ .decimal = tenth }, .null };
    const t = try aggregate(a, .{ .columns = &cols, .rows = &ten }, .{ .group_by = &.{"k"}, .aggs = &.{
        .{ .src = "m", .out = "exact", .func = .sum_exact },
        .{ .src = "m", .out = "f64", .func = .sum },
    } });
    try testing.expectEqual(ds.decimal_scale, t.rows[0][1].decimal);
    try testing.expectEqual(@as(f64, 0.9999999999999999), t.rows[0][2].float);
    // maxInt + 1 overflows; a later −5 must not "repair" it.
    try testing.expect(out.rows[1][1] == .null);
    // With fx: a null rate keeps decimals exact (groups a/b above went through
    // the same code without fx); rate 2 goes through f64: 1.5 × 2 = 3 exactly.
    const fxd = try aggregate(a, d, .{ .group_by = &.{"k"}, .aggs = &.{.{ .src = "m", .out = "exact", .func = .sum_exact }}, .fx = .{ .rate_col = "fx" } });
    try testing.expectEqual(@as(i128, 23 * tenth), fxd.rows[0][1].decimal);
    try testing.expectEqual(@as(i128, 3 * ds.decimal_scale), fxd.rows[2][1].decimal);
}

test "pivot: a statistical agg per cell" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "r", .type = .text }, .{ .name = "c", .type = .text }, .{ .name = "v", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "x" }, .{ .text = "p" }, .{ .float = 1 } },
        &.{ .{ .text = "x" }, .{ .text = "p" }, .{ .float = 10 } },
        &.{ .{ .text = "x" }, .{ .text = "p" }, .{ .float = 2 } },
    };
    // Median of {1, 10, 2} is 2; quantile 0.75: h = 1.5 → 2 + 0.5·(10 − 2) = 6.
    const med = try pivot(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .row_key = "r", .col_key = "c", .value_col = "v", .agg = .median });
    try testing.expectEqual(@as(f64, 2), med.rows[0][1].float);
    const q = try pivot(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .row_key = "r", .col_key = "c", .value_col = "v", .agg = .quantile, .q = 0.75 });
    try testing.expectEqual(@as(f64, 6), q.rows[0][1].float);
}

test "resample / clampRange read a .timestamp column (UTC calendar day)" {
    var f = Fix.init();
    defer f.deinit();
    const a = f.a();
    const us = ds.timestamp_units_per_second;
    const cols = [_]Column{ .{ .name = "t", .type = .timestamp }, .{ .name = "v", .type = .float } };
    const rows = [_][]const Value{
        // 1969-12-31T23:59:59Z — one second before the epoch is still 1969.
        &.{ .{ .int = -us }, .{ .float = 1 } },
        // 2024-01-31T23:00:00Z and 2024-02-01T01:00:00Z (1706742000, 1706749200).
        &.{ .{ .int = 1706742000 * us }, .{ .float = 2 } },
        &.{ .{ .int = 1706749200 * us }, .{ .float = 4 } },
        &.{ .null, .{ .float = 8 } },
    };
    const d: Dataset = .{ .columns = &cols, .rows = &rows };
    const m = try resample(a, d, .{ .date_col = "t", .value_col = "v", .freq = .month });
    try testing.expectEqual(@as(usize, 3), m.rows.len);
    try testing.expectEqualStrings("1969-12", m.rows[0][0].text);
    try testing.expectEqualStrings("2024-01", m.rows[1][0].text);
    try testing.expectEqualStrings("2024-02", m.rows[2][0].text);
    try testing.expectEqual(@as(f64, 4), m.rows[2][1].float);
    const c = try clampRange(a, d, .{ .date_col = "t", .from = "2024-02-01" });
    try testing.expectEqual(@as(usize, 1), c.rows.len);
    try testing.expectEqual(@as(f64, 4), c.rows[0][1].float);
}

test "edge cases the mutation run asked for (transforms)" {
    var f = Fix.init();
    defer f.deinit();
    const a = f.a();
    const cols = [_]Column{ .{ .name = "x", .type = .float }, .{ .name = "y", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .float = -0.25 }, .null },
        &.{ .{ .float = 4 }, .{ .float = 1 } },
    };
    const d: Dataset = .{ .columns = &cols, .rows = &rows };
    // A null RHS is missing too (only the LHS was checked by the earlier test).
    const m = try map(a, d, .{ .out = "o", .lhs = .{ .col = "x" }, .op = .add, .rhs = .{ .col = "y" }, .on_missing = .null });
    try testing.expect(m.rows[0][2] == .null);
    try testing.expectEqual(@as(f64, 5), m.rows[1][2].float);
    // sqrt of a negative number above −1 is still undefined (not NaN).
    const s = try map(a, d, .{ .out = "o", .lhs = .{ .col = "x" }, .op = .sqrt, .rhs = .{ .col = "no such" }, .on_missing = .null });
    try testing.expect(s.rows[0][2] == .null);
    try testing.expectEqual(@as(f64, 2), s.rows[1][2].float);
    // A NaN literal is missing: `x < NaN` holds for no row (Value.order would
    // otherwise rank NaN above every number).
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "x", .op = .lt, .value = .{ .float = nan } }} }), &.{});
    // fillna leaves a row's present cells alone.
    const all = try fillna(a, filt_ds, .{ .value = .{ .text = "?" } });
    try testing.expectEqual(@as(f64, 3), all.rows[2][0].float);
    // dropna(how = all) over zero columns: "all of nothing is missing" must
    // not drop every row.
    const empty_rows = [_][]const Value{ &.{}, &.{} };
    try testing.expectEqual(@as(usize, 2), (try dropna(a, .{ .columns = &.{}, .rows = &empty_rows }, .{ .how = .all })).rows.len);
    // An int in a column that is NOT `.timestamp` is not a date.
    const dc = [_]Column{ .{ .name = "t", .type = .date }, .{ .name = "v", .type = .float } };
    const dr = [_][]const Value{ &.{ .{ .int = 0 }, .{ .float = 1 } }, &.{ .{ .text = "2024-05-06" }, .{ .float = 2 } } };
    const r = try resample(a, .{ .columns = &dc, .rows = &dr }, .{ .date_col = "t", .value_col = "v", .freq = .year });
    try testing.expectEqual(@as(usize, 1), r.rows.len);
    try testing.expectEqualStrings("2024", r.rows[0][0].text);
    // sum_exact with a null fx rate keeps a decimal that f64 cannot hold:
    // 123456789.012345678901 has 21 significant digits, f64 carries ~16.
    const big: i128 = 123456789_012345678901;
    const fc = [_]Column{ .{ .name = "m", .type = .decimal }, .{ .name = "fx", .type = .float } };
    const fr = [_][]const Value{&.{ .{ .decimal = big }, .null }};
    const fx = try aggregate(a, .{ .columns = &fc, .rows = &fr }, .{ .group_by = &.{}, .aggs = &.{.{ .src = "m", .out = "s", .func = .sum_exact }}, .fx = .{ .rate_col = "fx" } });
    try testing.expectEqual(big, fx.rows[0][0].decimal);
}
