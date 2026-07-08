// SPDX-License-Identifier: MIT
//! Dataset algebra **Tier 0** — the pure `dataset → dataset` primitives that
//! unlock ~85% of the seed project's compute. Each is a pure function of
//! `(allocator, Dataset, Spec) → Dataset`; nothing is mutated in place. The
//! allocator is normally a caller-owned arena for the whole pipeline (see the
//! memory model note in `dataset`).
//!
//! T0 set: map · aggregate(+fx) · weighted_group_sum(+fx) · sort ·
//! top_n / top_n_with_tail · pivot · resample · reduce · clamp_range · format.
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

pub const BinOp = enum { add, sub, mul, div };

pub const MapSpec = struct {
    /// Name of the appended column.
    out: []const u8,
    out_type: ColumnType = .float,
    lhs: Operand,
    op: BinOp,
    rhs: Operand,
};

/// Append `out = lhs op rhs` as a new float column (per-row arithmetic:
/// pl = mv - cost, base = gross * fx, …). Multi-term expressions compose via
/// successive `map` steps.
pub fn map(a: std.mem.Allocator, d: Dataset, spec: MapSpec) Error!Dataset {
    const li: ?usize = switch (spec.lhs) {
        .col => |c| try mustIndex(d, c),
        .num => null,
    };
    const rgi: ?usize = switch (spec.rhs) {
        .col => |c| try mustIndex(d, c),
        .num => null,
    };

    const cols = try a.alloc(Column, d.columns.len + 1);
    @memcpy(cols[0..d.columns.len], d.columns);
    cols[d.columns.len] = .{ .name = spec.out, .type = spec.out_type };

    const rows = try a.alloc([]const Value, d.rows.len);
    for (d.rows, 0..) |r, ri| {
        const lv = if (li) |i| (r[i].asFloat() orelse 0) else spec.lhs.num;
        const rv = if (rgi) |i| (r[i].asFloat() orelse 0) else spec.rhs.num;
        const out: f64 = switch (spec.op) {
            .add => lv + rv,
            .sub => lv - rv,
            .mul => lv * rv,
            .div => if (rv == 0) 0 else lv / rv,
        };
        const nr = try a.alloc(Value, cols.len);
        @memcpy(nr[0..d.columns.len], r);
        nr[d.columns.len] = .{ .float = out };
        rows[ri] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

// ── aggregate (+fx) ─────────────────────────────────────────────────────────

pub const AggFn = enum { sum, mean, count, min, max, first, last };

pub const AggCol = struct {
    src: []const u8,
    out: []const u8,
    func: AggFn,
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

    fn observe(self: *Acc, v: Value) void {
        self.count += 1;
        self.sum += v.asFloat() orelse 0;
        if (self.first == null) self.first = v;
        self.last = v;
        if (self.min == null or v.order(self.min.?) == .lt) self.min = v;
        if (self.max == null or v.order(self.max.?) == .gt) self.max = v;
    }

    fn result(self: Acc, func: AggFn) Value {
        return switch (func) {
            .sum => .{ .float = self.sum },
            .mean => .{ .float = if (self.count == 0) 0 else self.sum / @as(f64, @floatFromInt(self.count)) },
            .count => .{ .int = @intCast(self.count) },
            .min => self.min orelse .null,
            .max => self.max orelse .null,
            .first => self.first orelse .null,
            .last => self.last orelse .null,
        };
    }
};

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
            @memset(accs, .{});
            gop.value_ptr.* = .{ .keys = keys, .accs = accs };
        }
        const rate = fxRate(r, rate_idx);
        for (sidx, 0..) |ci, i| {
            var v = r[ci];
            if (rate_idx != null) {
                if (v.asFloat()) |f| v = .{ .float = f * rate };
            }
            gop.value_ptr.accs[i].observe(v);
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
        for (spec.aggs, 0..) |ag, i| nr[gidx.len + i] = g.accs[i].result(ag.func);
        rows[ri] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

fn aggOutType(d: Dataset, src_idx: usize, func: AggFn) ColumnType {
    return switch (func) {
        .sum, .mean => .float,
        .count => .int,
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
pub const SortSpec = struct {
    key: []const u8,
    dir: SortDir = .asc,
};

const SortCtx = struct {
    key_idx: usize,
    dir: SortDir,
    fn lessThan(self: SortCtx, lhs: []const Value, rhs: []const Value) bool {
        const o = lhs[self.key_idx].order(rhs[self.key_idx]);
        return switch (self.dir) {
            .asc => o == .lt,
            .desc => o == .gt,
        };
    }
};

/// Stable sort rows by a single key column.
pub fn sort(a: std.mem.Allocator, d: Dataset, spec: SortSpec) Error!Dataset {
    const ki = try mustIndex(d, spec.key);
    const rows = try a.alloc([]const Value, d.rows.len);
    @memcpy(rows, d.rows);
    std.mem.sort([]const Value, rows, SortCtx{ .key_idx = ki, .dir = spec.dir }, SortCtx.lessThan);
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

// ── pivot ───────────────────────────────────────────────────────────────────

pub const PivotSpec = struct {
    row_key: []const u8,
    col_key: []const u8,
    value_col: []const u8,
    agg: AggFn = .sum,
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
        if (!cop.found_existing) cop.value_ptr.* = .{};
        cop.value_ptr.observe(r[vi]);
    }

    // sorted distinct column keys
    const col_list = try a.alloc([]const u8, col_keys.count());
    for (col_keys.keys(), 0..) |k, i| col_list[i] = k;
    std.mem.sort([]const u8, col_list, {}, strLess);

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
            nr[1 + ci] = if (cells.get(ckey)) |acc| acc.result(spec.agg) else .null;
        }
        rows[ri] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

fn strLess(_: void, l: []const u8, r: []const u8) bool {
    return std.mem.order(u8, l, r) == .lt;
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
        const dt_text = r[di].asText() orelse continue;
        const date = ds.parseIsoDate(dt_text) orelse continue;
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
        const dt_text = r[di].asText() orelse continue;
        const date = ds.parseIsoDate(dt_text) orelse continue;
        const o = date.ordinal();
        if (from_ord) |f| if (o < f) continue;
        if (to_ord) |t| if (o > t) continue;
        try kept.append(a, r);
    }
    return .{ .columns = d.columns, .rows = try kept.toOwnedSlice(a) };
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
