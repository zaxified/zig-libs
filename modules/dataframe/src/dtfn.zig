// SPDX-License-Identifier: MIT
//! The `dt` accessor and the temporal parse and format of `Expr` (survey rows 95, 98,
//! 99): calendar components, `strptime`/`strftime` with pandas' and polars' `%`
//! directives, `offset_by` and `truncate` with polars' duration strings, business days.
//! The calendar is the sibling module `datefmt`'s (proleptic Gregorian, UTC).
//!
//! A temporal cell is one of three shapes, and a temporal result keeps the shape:
//! - `.int`: a timestamp, microseconds since 1970-01-01T00:00:00Z (the module's
//!   `.timestamp` cell, whatever the column's declared type);
//! - `.text` of exactly `YYYY-MM-DD`: a date (the module's `.date` cell);
//! - other `.text`: an ISO timestamp, as `parseIsoTimestamp` reads it; a result is
//!   written back by `formatIsoTimestamp`.
//! Anything else, or text that does not parse, is null. Original work of the zig-libs
//! authors (MIT); pandas' and polars' documentation read, no source.

const std = @import("std");
const datefmt = @import("datefmt");
const vm = @import("value.zig");
const keys = @import("keys.zig");
const Value = vm.Value;

const us_per_s: i64 = vm.timestamp_units_per_second;
const us_per_day: i64 = 86_400 * us_per_s;

pub const DtPart = enum {
    year,
    month,
    day,
    hour,
    minute,
    second,
    /// The fraction of the second in milliseconds, 0..999 (polars `millisecond`).
    millisecond,
    /// The fraction of the second in microseconds, 0..999_999 (pandas and polars).
    microsecond,
    /// The fraction in nanoseconds (a microsecond cell: a multiple of 1000).
    nanosecond,
    /// ISO weekday, Monday 1 … Sunday 7 (polars `weekday`; pandas' `dayofweek` is
    /// Monday 0 … Sunday 6: subtract 1).
    weekday,
    /// 1..366 (pandas `dayofyear`, polars `ordinal_day`).
    day_of_year,
    /// ISO 8601 week number, 1..53 (pandas `isocalendar().week`, polars `week`).
    iso_week,
    /// The ISO week-year (polars `iso_year`).
    iso_year,
    quarter,
    days_in_month,
    is_leap_year,
    is_month_start,
    is_month_end,
    is_quarter_start,
    is_quarter_end,
    is_year_start,
    is_year_end,
    /// Monday to Friday (polars `is_business_day` with its default week mask, no
    /// holidays).
    is_business_day,
    /// English names (pandas `month_name()`, `day_name()`).
    month_name,
    day_name,
    /// Days, seconds, milliseconds, microseconds since the epoch, floored (polars
    /// `epoch(time_unit)`, pandas' `timestamp()` for seconds).
    epoch_days,
    epoch_seconds,
    epoch_ms,
    epoch_us,
    /// The date as `YYYY-MM-DD` text (pandas and polars `date`).
    date,
    /// The time of day as `HH:MM:SS`, `.ffffff` added when there is a fraction
    /// (pandas and polars `time`, as text).
    time,
    /// The first / last day of the month, time of day kept, the input's shape (polars
    /// `month_start`/`month_end`, pandas `+ MonthBegin(-1)`/`MonthEnd(0)` style).
    month_start,
    month_end,
};

const Shape = enum { int, date, text_ts };

const Inst = struct {
    us: i64,
    shape: Shape,
};

fn read(v: Value) ?Inst {
    switch (v) {
        .int => |i| return .{ .us = i, .shape = .int },
        .text => |t| {
            if (t.len == 10) {
                const d = vm.parseIsoDate(t) orelse return null;
                return .{ .us = d.ordinal() * us_per_day, .shape = .date };
            }
            return .{ .us = vm.parseIsoTimestamp(t) orelse return null, .shape = .text_ts };
        },
        else => return null,
    }
}

fn dateText(a: std.mem.Allocator, day: i64) error{OutOfMemory}!Value {
    const p = datefmt.epochDayToYmd(day);
    if (p.year < 0 or p.year > 9999) return .null;
    return .{ .text = try a.print("{d:0>4}-{d:0>2}-{d:0>2}", .{ @as(u32, @intCast(p.year)), p.month, p.day }) };
}

/// `us` in the shape of `shape`; a date drops the time of day.
fn write(a: std.mem.Allocator, us: i64, shape: Shape) error{OutOfMemory}!Value {
    switch (shape) {
        .int => return .{ .int = us },
        .date => return dateText(a, @divFloor(us, us_per_day)),
        .text_ts => {
            var buf: [vm.max_iso_timestamp_len]u8 = undefined;
            return .{ .text = try a.dupe(u8, vm.formatIsoTimestamp(&buf, us)) };
        },
    }
}

fn partsOf(us: i64) datefmt.DateParts {
    var p = datefmt.unixToParts(@divFloor(us, us_per_s));
    p.nanosecond = @intCast(@mod(us, us_per_s) * 1000);
    return p;
}

/// `us` from parts, null outside `i64`.
fn usOf(p: datefmt.DateParts) ?i64 {
    const s = @as(i128, datefmt.partsToUnix(p)) * us_per_s + @divFloor(p.nanosecond, 1000);
    return std.math.cast(i64, s);
}

const month_names = [_][]const u8{ "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December" };
const day_names = [_][]const u8{ "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday" };

/// One calendar component of a temporal cell; null for anything else.
pub fn part(a: std.mem.Allocator, v: Value, which: DtPart) error{OutOfMemory}!Value {
    const in = read(v) orelse return .null;
    const p = partsOf(in.us);
    const day = @divFloor(in.us, us_per_day);
    const frac_us = @mod(in.us, us_per_s);
    const dim = datefmt.daysInMonth(p.year, p.month);
    return switch (which) {
        .year => .{ .int = p.year },
        .month => .{ .int = p.month },
        .day => .{ .int = p.day },
        .hour => .{ .int = p.hour },
        .minute => .{ .int = p.minute },
        .second => .{ .int = p.second },
        .millisecond => .{ .int = @divFloor(frac_us, 1000) },
        .microsecond => .{ .int = frac_us },
        .nanosecond => .{ .int = frac_us * 1000 },
        .weekday => .{ .int = datefmt.isoWeekday(day) },
        .day_of_year => .{ .int = datefmt.dayOfYear(p) },
        .iso_week => .{ .int = datefmt.isoWeek(p).week },
        .iso_year => .{ .int = datefmt.isoWeek(p).year },
        .quarter => .{ .int = (p.month - 1) / 3 + 1 },
        .days_in_month => .{ .int = dim },
        .is_leap_year => .{ .bool = datefmt.isLeapYear(p.year) },
        .is_month_start => .{ .bool = p.day == 1 },
        .is_month_end => .{ .bool = p.day == dim },
        .is_quarter_start => .{ .bool = p.day == 1 and (p.month - 1) % 3 == 0 },
        .is_quarter_end => .{ .bool = p.day == dim and p.month % 3 == 0 },
        .is_year_start => .{ .bool = p.day == 1 and p.month == 1 },
        .is_year_end => .{ .bool = p.day == 31 and p.month == 12 },
        .is_business_day => .{ .bool = datefmt.isoWeekday(day) <= 5 },
        .month_name => .{ .text = month_names[p.month - 1] },
        .day_name => .{ .text = day_names[datefmt.isoWeekday(day) - 1] },
        .epoch_days => .{ .int = day },
        .epoch_seconds => .{ .int = @divFloor(in.us, us_per_s) },
        .epoch_ms => .{ .int = @divFloor(in.us, 1000) },
        .epoch_us => .{ .int = in.us },
        .date => dateText(a, day),
        .time => .{ .text = if (frac_us == 0)
            try a.print("{d:0>2}:{d:0>2}:{d:0>2}", .{ p.hour, p.minute, p.second })
        else
            try a.print("{d:0>2}:{d:0>2}:{d:0>2}.{d:0>6}", .{ p.hour, p.minute, p.second, @as(u64, @intCast(frac_us)) }) },
        .month_start, .month_end => blk: {
            var q = p;
            q.day = if (which == .month_start) 1 else dim;
            break :blk write(a, usOf(q) orelse return .null, in.shape);
        },
    };
}

// ── formats ─────────────────────────────────────────────────────────────────

pub const FormatError = error{ OutOfMemory, BadFormat };

/// pandas' and polars' `%` directives (C `strftime`, chrono) as a `datefmt` layout:
/// `%Y %y %m %d %H %I %M %S %p %f %z %:z %b %h %B %a %A %j %u %V %G %F %T %R %D %%`,
/// the text between them literal. Another directive, or a `[` or `]` in the literal
/// text, is `error.BadFormat`.
pub fn translateFormat(a: std.mem.Allocator, fmt: []const u8) FormatError![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var lit: std.ArrayList(u8) = .empty;
    defer lit.deinit(a);
    var i: usize = 0;
    while (i < fmt.len) {
        const c = fmt[i];
        if (c != '%') {
            if (c == '[' or c == ']') return error.BadFormat;
            try lit.append(a, c);
            i += 1;
            continue;
        }
        if (i + 1 >= fmt.len) return error.BadFormat;
        var d = fmt[i + 1];
        var step: usize = 2;
        if (d == ':' and i + 2 < fmt.len and fmt[i + 2] == 'z') {
            d = 'Z'; // `%:z`, an internal marker
            step = 3;
        }
        if (d == '%') {
            try lit.append(a, '%');
            i += step;
            continue;
        }
        const tok: []const u8 = switch (d) {
            'Y' => "YYYY",
            'y' => "YY",
            'm' => "MM",
            'd' => "DD",
            'H' => "hh",
            'I' => "ii",
            'M' => "mm",
            'S' => "ss",
            'p' => "A",
            'f' => "SSSSSS",
            'z' => "ZZZ",
            'Z' => "ZZ",
            'b', 'h' => "MMM",
            'B' => "MMMM",
            'a' => "EEE",
            'A' => "EEEE",
            'j' => "DDDD",
            'u' => "e",
            'V' => "WW",
            'G' => "GGGG",
            'F' => "YYYY[-]MM[-]DD",
            'T' => "hh[:]mm[:]ss",
            'R' => "hh[:]mm",
            'D' => "MM[/]DD[/]YY",
            else => return error.BadFormat,
        };
        if (lit.items.len > 0) {
            try out.append(a, '[');
            try out.appendSlice(a, lit.items);
            try out.append(a, ']');
            lit.clearRetainingCapacity();
        }
        try out.appendSlice(a, tok);
        i += step;
    }
    if (lit.items.len > 0) {
        try out.append(a, '[');
        try out.appendSlice(a, lit.items);
        try out.append(a, ']');
    }
    // `datefmt` refuses a layout it cannot tokenize; find out now, not per cell.
    _ = datefmt.format(a, .{}, out.items) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.BadFormat,
    };
    return out.items;
}

pub const ParseTo = enum { date, timestamp };

/// pandas `to_datetime(format=)`, polars `str.strptime`/`to_date`/`to_datetime`: the
/// whole text must match `layout` (`translateFormat`'s output), else null (polars'
/// `strict=False`, pandas' `errors="coerce"`). An offset in the text is applied, so a
/// timestamp is UTC; a date drops the time of day.
pub fn strptime(a: std.mem.Allocator, v: Value, layout: []const u8, to: ParseTo) error{OutOfMemory}!Value {
    if (v != .text) return .null;
    const m = datefmt.parsePrefix(v.text, layout) catch return .null;
    if (m.len != v.text.len) return .null;
    const p = if (m.parts.off_min != null) datefmt.toUtc(m.parts) else m.parts;
    const us = usOf(p) orelse return .null;
    return write(a, us, if (to == .date) .date else .int);
}

/// pandas `dt.strftime`, polars `dt.strftime`/`to_string`.
pub fn strftime(a: std.mem.Allocator, v: Value, layout: []const u8) error{OutOfMemory}!Value {
    const in = read(v) orelse return .null;
    var p = partsOf(in.us);
    p.off_min = 0;
    const t = datefmt.format(a, p, layout) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .null,
    };
    return .{ .text = t };
}

// ── durations ───────────────────────────────────────────────────────────────

/// A polars duration string: calendar months and a fixed number of microseconds.
pub const Duration = struct {
    months: i64 = 0,
    us: i64 = 0,
    /// Whole weeks given (`truncate` aligns those to Monday).
    weeks: i64 = 0,
};

/// polars' duration language: `[-]` then integer-unit pairs, units `ns us ms s m h d w
/// mo q y` (`"1y2mo"`, `"-3d12h"`, `"90m"`). Nanoseconds are cut to microseconds.
/// Anything else, an empty string or an overflow is null.
pub fn parseDuration(s: []const u8) ?Duration {
    var i: usize = 0;
    var neg = false;
    if (i < s.len and s[i] == '-') {
        neg = true;
        i += 1;
    }
    if (i >= s.len) return null;
    var d: Duration = .{};
    while (i < s.len) {
        const st = i;
        while (i < s.len and std.ascii.isDigit(s[i])) i += 1;
        if (i == st) return null;
        const n = std.fmt.parseInt(i64, s[st..i], 10) catch return null;
        const us_ = i;
        while (i < s.len and std.ascii.isAlphabetic(s[i])) i += 1;
        const unit = s[us_..i];
        const eq = struct {
            fn f(x: []const u8, y: []const u8) bool {
                return std.mem.eql(u8, x, y);
            }
        }.f;
        if (eq(unit, "mo") or eq(unit, "q") or eq(unit, "y")) {
            const k: i64 = if (eq(unit, "mo")) 1 else if (eq(unit, "q")) 3 else 12;
            d.months = std.math.add(i64, d.months, std.math.mul(i64, n, k) catch return null) catch return null;
            continue;
        }
        const per: i64 = if (eq(unit, "ns"))
            0
        else if (eq(unit, "us"))
            1
        else if (eq(unit, "ms"))
            1000
        else if (eq(unit, "s"))
            us_per_s
        else if (eq(unit, "m"))
            60 * us_per_s
        else if (eq(unit, "h"))
            3600 * us_per_s
        else if (eq(unit, "d"))
            us_per_day
        else if (eq(unit, "w"))
            7 * us_per_day
        else
            return null;
        const add = if (per == 0) @divTrunc(n, 1000) else std.math.mul(i64, n, per) catch return null;
        d.us = std.math.add(i64, d.us, add) catch return null;
        if (eq(unit, "w")) d.weeks += n;
    }
    if (neg) {
        d.months = -d.months;
        d.us = -d.us;
        d.weeks = -d.weeks;
    }
    return d;
}

/// polars `dt.offset_by`, pandas `+ DateOffset(...)`: the months first (the day
/// clamped to the new month, Jan 31 + 1mo = Feb 28/29), then the fixed part. The
/// input's shape; null past the representable range.
pub fn offsetBy(a: std.mem.Allocator, v: Value, d: Duration) error{OutOfMemory}!Value {
    const in = read(v) orelse return .null;
    var us = in.us;
    if (d.months != 0) {
        const p = partsOf(us);
        const months = std.math.cast(i32, d.months) orelse return .null;
        var q = datefmt.addMonths(p, months);
        q.nanosecond = p.nanosecond;
        us = usOf(q) orelse return .null;
    }
    us = std.math.add(i64, us, d.us) catch return .null;
    return write(a, us, in.shape);
}

/// polars `dt.truncate(every)`, pandas `dt.floor`: down to a multiple of `every`
/// counted from 1970-01-01 (months from January 1970, weeks from Monday 1969-12-29,
/// as polars). The compiler refuses an `every` that is zero, negative, or mixes months
/// with a fixed part.
pub fn truncate(a: std.mem.Allocator, v: Value, d: Duration) error{OutOfMemory}!Value {
    const in = read(v) orelse return .null;
    if (d.months > 0) {
        const p = partsOf(in.us);
        const idx = (@as(i64, p.year) - 1970) * 12 + (@as(i64, p.month) - 1);
        const t = @divFloor(idx, d.months) * d.months;
        const year = std.math.cast(i32, 1970 + @divFloor(t, 12)) orelse return .null;
        const q: datefmt.DateParts = .{ .year = year, .month = @intCast(@mod(t, 12) + 1), .day = 1 };
        return write(a, usOf(q) orelse return .null, in.shape);
    }
    const origin: i64 = if (d.weeks != 0 and @mod(d.us, 7 * us_per_day) == 0) -3 * us_per_day else 0;
    const shifted = @as(i128, in.us) - origin;
    const t = std.math.cast(i64, @divFloor(shifted, d.us) * d.us + origin) orelse return .null;
    return write(a, t, in.shape);
}

/// Monday to Friday after `n` business days (polars `add_business_days` with
/// `roll="forward"`; pandas' `+ BDay(n)` agrees from a weekday, but from a weekend it
/// counts the roll as the first day): a start on a weekend first rolls to the next
/// Monday. The time of day is kept; the input's shape.
pub fn addBusinessDays(a: std.mem.Allocator, v: Value, n: i64) error{OutOfMemory}!Value {
    const in = read(v) orelse return .null;
    var day = @divFloor(in.us, us_per_day);
    const tod = @mod(in.us, us_per_day);
    const wd = datefmt.isoWeekday(day);
    if (wd > 5) day += 8 - @as(i64, wd);
    // Business-day index from Monday 1969-12-29 (epoch day -3).
    const rel = day + 3;
    const week = @divFloor(rel, 7);
    const idx = @mod(rel, 7); // 0..4 after the roll
    const step = std.math.add(i64, idx, n) catch return .null;
    const total = std.math.add(i64, std.math.mul(i64, week, 5) catch return .null, step) catch return .null;
    const nweek = @divFloor(total, 5);
    const nidx = @mod(total, 5);
    const nday = std.math.add(i64, std.math.mul(i64, nweek, 7) catch return .null, nidx - 3) catch return .null;
    const us = std.math.add(i64, std.math.mul(i64, nday, us_per_day) catch return .null, tod) catch return .null;
    return write(a, us, in.shape);
}

pub fn isMissing(v: Value) bool {
    return keys.isMissing(v);
}
