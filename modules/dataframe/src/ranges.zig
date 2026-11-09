// SPDX-License-Identifier: MIT
//! Constructors that make a column from nothing (dataframe S2 wave W3): polars
//! `int_range`/`int_ranges`/`linear_space`/`repeat`/`date_range`/`datetime_range`, pandas
//! and numpy `arange`/`linspace`/`ones`/`zeros`/`full`/`date_range`/`bdate_range`. Each returns a
//! one-column `Frame` named `name`, which `hstack`/`concat`/`join` take like any other.
//!
//! Output is capped at `max_range_rows` rows: a range longer than that is
//! `error.TooLarge`, found by arithmetic before any allocation, never a huge
//! allocation. Calendar ranges step from the start by whole multiples of the interval
//! (`start + k * interval`, as polars), so a month-end start does not drift: Jan 31
//! every `1mo` is Jan 31, Feb 28, Mar 31. Original work of the zig-libs authors (MIT);
//! the engines' documentation was read, no source.

const std = @import("std");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const sp = @import("spec.zig");
const dtf = @import("dtfn.zig");
const lf = @import("listfn.zig");
const ex = @import("expr.zig");
const Column = vm.Column;
const ColumnType = vm.ColumnType;
const ColumnData = fm.ColumnData;
const Frame = fm.Frame;
const Value = vm.Value;

/// `error.BadArgument`: a zero step, bounds of different lengths. `error.BadInterval`:
/// an interval string `parseDuration` refuses, a negative or zero one, one that mixes
/// months with a fixed part, or one finer than a day for a date range.
pub const RangeError = sp.Error || error{ BadArgument, BadInterval };

/// Most rows a constructor builds (the same bound as `upsample`).
pub const max_range_rows: usize = 1 << 22;

/// Which ends of a range belong to it (polars `closed=`; numpy's `endpoint` is `.both` vs
/// `.left`).
pub const Closed = @import("expr.zig").Closed;

fn single(a: std.mem.Allocator, name: []const u8, ty: ColumnType, data: ColumnData, len: usize, inner: []const Column) RangeError!Frame {
    const cols = try a.alloc(Column, 1);
    cols[0] = .{ .name = name, .type = ty, .inner = inner };
    const ds = try a.alloc(ColumnData, 1);
    ds[0] = data;
    return .{ .columns = cols, .data = ds, .len = len };
}

fn fromCells(a: std.mem.Allocator, name: []const u8, ty: ColumnType, cells: []const Value, inner: []const Column) RangeError!Frame {
    return single(a, name, ty, try fm.columnFromCells(a, cells), cells.len, inner);
}

/// How many values `start, start + step, ...` lie before `end` (exclusive), 0 when the step
/// points away from it.
fn intCount(start: i64, end: i64, step: i64) RangeError!usize {
    if (step == 0) return error.BadArgument;
    const span: i128 = if (step > 0) @as(i128, end) - start else @as(i128, start) - end;
    if (span <= 0) return 0;
    const st: i128 = if (step > 0) step else -@as(i128, step);
    const n = @divFloor(span - 1, st) + 1;
    if (n > max_range_rows) return error.TooLarge;
    return @intCast(n);
}

/// polars `int_range(start, end, step)`, numpy/pandas `arange`: `start, start + step, ...`
/// up to but not including `end`; empty when the step points away from `end`. A zero step is
/// `error.BadArgument` (polars and numpy raise); a range of more than `max_range_rows`
/// values is `error.TooLarge`.
pub fn intRange(a: std.mem.Allocator, name: []const u8, start: i64, end: i64, step: i64) RangeError!Frame {
    const n = try intCount(start, end, step);
    const vals = try a.alloc(i64, n);
    var x: i128 = start;
    for (vals) |*v| {
        v.* = @intCast(x); // x stays between start and end
        x += step;
    }
    return single(a, name, .int, .{ .int = .{ .values = vals } }, n, &.{});
}

/// polars `int_ranges(start, end, step)`: one list of ints per row, `intRange(start[i], end[i])`.
/// `starts` and `ends` have the same length, or one of them has one entry that is used for
/// every row; a null bound makes the row's list null. All lists together hold at most
/// `max_range_rows` values.
pub fn intRanges(a: std.mem.Allocator, name: []const u8, starts: []const ?i64, ends: []const ?i64, step: i64) RangeError!Frame {
    if (step == 0) return error.BadArgument;
    if (starts.len != ends.len and starts.len != 1 and ends.len != 1) return error.BadArgument;
    const rows = if (starts.len == 1) ends.len else starts.len;
    var total: usize = 0;
    for (0..rows) |i| {
        const s = starts[if (starts.len == 1) 0 else i] orelse continue;
        const e = ends[if (ends.len == 1) 0 else i] orelse continue;
        total += try intCount(s, e, step);
        if (total > max_range_rows) return error.TooLarge;
    }
    const cells = try a.alloc(Value, rows);
    defer a.free(cells);
    var items: std.ArrayList(Value) = .empty;
    defer items.deinit(a);
    for (cells, 0..) |*c, i| {
        const s = starts[if (starts.len == 1) 0 else i] orelse {
            c.* = .null;
            continue;
        };
        const e = ends[if (ends.len == 1) 0 else i] orelse {
            c.* = .null;
            continue;
        };
        items.clearRetainingCapacity();
        const n = try intCount(s, e, step);
        var x: i128 = s;
        for (0..n) |_| {
            try items.append(a, .{ .int = @intCast(x) });
            x += step;
        }
        c.* = try lf.makeList(a, items.items);
    }
    const inner = try a.dupe(Column, &[_]Column{.{ .name = "", .type = .int }});
    return fromCells(a, name, .list, cells, inner);
}

/// polars `linear_space(start, end, num_samples, closed)`, numpy `linspace`
/// (`closed = .both`, or `.left` for `endpoint=False`): `n` evenly spaced floats. `.both`
/// puts the first at `start` and the last exactly at `end`; `.left` leaves `end` out;
/// `.right` leaves `start` out; `.none` both. `n = 1` with `.both` is `start`; `n = 0` is
/// empty. A bound that is not finite gives NaN cells (numpy).
pub fn linearSpace(a: std.mem.Allocator, name: []const u8, start: f64, end: f64, n: usize, closed: Closed) RangeError!Frame {
    if (n > max_range_rows) return error.TooLarge;
    const vals = try a.alloc(f64, n);
    const nf: f64 = @floatFromInt(n);
    const step: f64 = switch (closed) {
        .both => if (n > 1) (end - start) / (nf - 1) else 0,
        .left, .right => if (n > 0) (end - start) / nf else 0,
        .none => (end - start) / (nf + 1),
    };
    const first: f64 = switch (closed) {
        .both, .left => 0,
        .right, .none => 1,
    };
    for (vals, 0..) |*v, i| v.* = start + (first + @as(f64, @floatFromInt(i))) * step;
    if (closed == .both and n > 1) vals[n - 1] = end;
    return single(a, name, .float, .{ .float = .{ .values = vals } }, n, &.{});
}

/// Most bytes `repeatValue` may copy: `n` times the value's text or nested elements (each
/// row of the column holds its own copy). 2^30, as `max_eval_bytes`.
pub const max_repeat_bytes: usize = 1 << 30;

/// What one copy of `v` costs: a slot, the bytes of a text and 16 bytes per element of a
/// list or field of a record, at every level down to `max_nesting_depth` (the copy goes that
/// deep). Saturating, and it stops once the sum passes `max_repeat_bytes`, so a huge value is
/// not walked to the end (sweep A-10: the one-level weight let a list holding a 1 MiB text
/// count as 17 bytes).
fn copyWeight(v: Value, depth: u8) usize {
    var w: usize = 1;
    switch (Value.capped(v, depth)) {
        .text => |t| w +|= t.len,
        .list => |l| for (0..l.len()) |i| {
            w +|= 16 +| copyWeight(l.get(i), depth + 1);
            if (w > max_repeat_bytes) break;
        },
        .record => |r| for (0..r.len()) |i| {
            w +|= 16 +| copyWeight(r.get(i), depth + 1);
            if (w > max_repeat_bytes) break;
        },
        else => {},
    }
    return w;
}

/// polars `repeat(value, n)`, numpy `full`: `n` copies of `v`. `ty` declares the column
/// (default: the value's own kind, a null value a float column of nulls); a `ty` other than
/// the value's kind converts the cells by `cast`'s rule (an unconvertible value is
/// `error.BadArgument`), so storage and declaration agree. More than `max_repeat_bytes` of
/// copies is `error.TooLarge`.
pub fn repeatValue(a: std.mem.Allocator, name: []const u8, v: Value, n: usize, ty: ?ColumnType) RangeError!Frame {
    if (n > max_range_rows) return error.TooLarge;
    const weight = copyWeight(v, 0);
    if (n *| weight > max_repeat_bytes) return error.TooLarge;
    const cells = try a.alloc(Value, n);
    defer a.free(cells);
    @memset(cells, v);
    const own: ColumnType = switch (v) {
        .int => ColumnType.int,
        .text => .text,
        .bool => .bool,
        .decimal => .decimal,
        .list => .list,
        .record => .@"struct",
        .float, .null => .float,
    };
    const f = try fromCells(a, name, if (v == .null) ty orelse own else own, cells, &.{});
    const want = ty orelse return f;
    if (v == .null or want == own) return f;
    return ex.cast(a, f, .{ .col = name, .to = want, .on_error = .fail }) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.TooLarge => error.TooLarge,
        else => error.BadArgument,
    };
}

/// numpy `ones(n)`: `n` ones, an int column or (`as_float`) a float one.
pub fn ones(a: std.mem.Allocator, name: []const u8, n: usize, as_float: bool) RangeError!Frame {
    return repeatValue(a, name, if (as_float) .{ .float = 1 } else .{ .int = 1 }, n, null);
}

/// numpy `zeros(n)`.
pub fn zeros(a: std.mem.Allocator, name: []const u8, n: usize, as_float: bool) RangeError!Frame {
    return repeatValue(a, name, if (as_float) .{ .float = 0 } else .{ .int = 0 }, n, null);
}

// ── calendar ranges ──────────────────────────────────────────────────────────

pub const CalendarSpec = struct {
    /// polars' duration language (`"1d"`, `"2w"`, `"1mo"`, `"6h"`, `"90m"`); pandas' `freq`
    /// aliases are written the same way (`D` is `1d`, `MS` is `1mo` from a first of month).
    /// Must be positive. A date range needs whole days.
    interval: []const u8 = "1d",
    /// Which of the first and last point are kept; `.both` is pandas' default and polars'.
    closed: Closed = .both,
    /// Count in Monday-to-Friday days (pandas `bdate_range`, `freq="B"`): `interval` must
    /// be whole days, `"2d"` is every second business day, and a start on a weekend rolls
    /// forward to Monday.
    business: bool = false,
};

const day_us: i64 = 86_400 * vm.timestamp_units_per_second;

fn parseInterval(spec: CalendarSpec, whole_days: bool) RangeError!dtf.Duration {
    const d = dtf.parseDuration(spec.interval) orelse return error.BadInterval;
    const months_only = d.months > 0 and d.us == 0;
    const fixed_only = d.months == 0 and d.us > 0;
    if (!months_only and !fixed_only) return error.BadInterval;
    if ((whole_days or spec.business) and fixed_only and @mod(d.us, day_us) != 0) return error.BadInterval;
    if (spec.business and months_only) return error.BadInterval;
    return d;
}

/// The point `k` intervals after `start`, null past the representable range.
fn point(start: i64, d: dtf.Duration, k: usize, business: bool) ?i64 {
    const kk = std.math.cast(i64, k) orelse return null;
    if (business) {
        const per = @divExact(d.us, day_us);
        const n = std.math.mul(i64, kk, per) catch return null;
        const v = dtf.addBusinessDaysInt(start, n) orelse return null;
        return v;
    }
    return dtf.stepInstant(start, d, kk);
}

/// The instants from `start` to `end` by `d`, `closed` honoured.
fn instantsBetween(a: std.mem.Allocator, start: i64, end: i64, d: dtf.Duration, closed: Closed, business: bool) RangeError![]const i64 {
    var out: std.ArrayList(i64) = .empty;
    errdefer out.deinit(a);
    var k: usize = 0;
    while (point(start, d, k, business)) |t| : (k += 1) {
        if (t > end or (t == end and (closed == .left or closed == .none))) break;
        // The roll of a business start can move the first point; `k = 0` is still the start.
        if (k == 0 and (closed == .right or closed == .none)) continue;
        if (out.items.len >= max_range_rows) return error.TooLarge;
        try out.append(a, t);
    }
    return out.toOwnedSlice(a);
}

/// `periods` instants from `start` by `d` (pandas `date_range(start, periods=, freq=)`).
fn instantsFor(a: std.mem.Allocator, start: i64, periods: usize, d: dtf.Duration, business: bool) RangeError![]const i64 {
    if (periods > max_range_rows) return error.TooLarge;
    var out: std.ArrayList(i64) = .empty;
    errdefer out.deinit(a);
    try out.ensureTotalCapacityPrecise(a, periods);
    for (0..periods) |k| {
        const t = point(start, d, k, business) orelse break;
        out.appendAssumeCapacity(t);
    }
    return out.toOwnedSlice(a);
}

fn timestampColumn(a: std.mem.Allocator, name: []const u8, ts: []const i64) RangeError!Frame {
    return single(a, name, .timestamp, .{ .int = .{ .values = ts } }, ts.len, &.{});
}

fn dateColumn(a: std.mem.Allocator, name: []const u8, ts: []const i64) RangeError!Frame {
    const cells = try a.alloc(Value, ts.len);
    defer a.free(cells);
    for (cells, ts) |*c, t| c.* = try dtf.dayText(a, @divFloor(t, day_us));
    return fromCells(a, name, .date, cells, &.{});
}

/// The first microsecond of `d`. A caller-built `Date` can carry any `i32` year; one whose
/// first instant does not fit an `i64` timestamp is `error.BadArgument`, not an overflow.
fn dayStart(d: vm.Date) RangeError!i64 {
    return std.math.mul(i64, d.ordinal(), day_us) catch error.BadArgument;
}

/// polars `date_range(start, end, interval, closed)`, pandas `date_range(start, end,
/// freq=)` / `bdate_range` (`spec.business`): a `.date` column, `start + k * interval` for
/// k = 0, 1, ... while it is not past `end`. An `end` before `start` is empty. A date past
/// year 9999 (or before 0) reads as null in the column, as every date cell does.
pub fn dateRange(a: std.mem.Allocator, name: []const u8, start: vm.Date, end: vm.Date, spec: CalendarSpec) RangeError!Frame {
    const d = try parseInterval(spec, true);
    return dateColumn(a, name, try instantsBetween(a, try dayStart(start), try dayStart(end), d, spec.closed, spec.business));
}

/// pandas `date_range(start, periods=, freq=)`: `periods` dates from `start`; `spec.closed`
/// plays no part.
pub fn dateRangePeriods(a: std.mem.Allocator, name: []const u8, start: vm.Date, periods: usize, spec: CalendarSpec) RangeError!Frame {
    const d = try parseInterval(spec, true);
    return dateColumn(a, name, try instantsFor(a, try dayStart(start), periods, d, spec.business));
}

/// polars `datetime_range(start, end, interval, closed)`, pandas `date_range` over
/// timestamps: a `.timestamp` column; `start` and `end` are microseconds since the epoch
/// (UTC). Otherwise as `dateRange`, with any positive interval.
pub fn datetimeRange(a: std.mem.Allocator, name: []const u8, start: i64, end: i64, spec: CalendarSpec) RangeError!Frame {
    const d = try parseInterval(spec, false);
    return timestampColumn(a, name, try instantsBetween(a, start, end, d, spec.closed, spec.business));
}

/// pandas `date_range(start, periods=, freq=)` over timestamps.
pub fn datetimeRangePeriods(a: std.mem.Allocator, name: []const u8, start: i64, periods: usize, spec: CalendarSpec) RangeError!Frame {
    const d = try parseInterval(spec, false);
    return timestampColumn(a, name, try instantsFor(a, start, periods, d, spec.business));
}

/// pandas `date_range(start, end, periods=)` (no `freq`): `periods` timestamps evenly spaced
/// from `start` to `end` inclusive, each rounded to the nanosecond and then cut to the microsecond (pandas). One period is `start`.
pub fn datetimeSpace(a: std.mem.Allocator, name: []const u8, start: i64, end: i64, periods: usize) RangeError!Frame {
    if (periods > max_range_rows) return error.TooLarge;
    const out = try a.alloc(i64, periods);
    const span: i128 = @as(i128, end) - start;
    for (out, 0..) |*t, i| {
        if (periods == 1) {
            t.* = start;
            continue;
        }
        // pandas works in nanoseconds: the point is rounded to a nanosecond, then the
        // microsecond cell truncates (an instant of 1/6 s ends in ...166666, not ...167).
        const num = span * 1000 * @as(i128, @intCast(i));
        const den: i128 = @intCast(periods - 1);
        const q_ns = @divTrunc(num * 2 + (if (num >= 0) den else -den), den * 2);
        t.* = @intCast(start + @divFloor(q_ns, 1000));
    }
    return timestampColumn(a, name, out);
}
