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
const tz = @import("tz");
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
    /// A `.duration` cell (an `.int` of microseconds) in whole units, truncated toward
    /// zero (polars `dt.total_days()` … `total_microseconds()`; pandas
    /// `dt.total_seconds()` gives a float, take `x / 1e6` for that). Not a calendar
    /// part: a text cell is null.
    total_days,
    total_hours,
    total_minutes,
    total_seconds,
    total_milliseconds,
    total_microseconds,
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

/// A temporal cell as microseconds since the epoch, null when it is not one.
pub fn instantOf(v: Value) ?i64 {
    return if (read(v)) |i| i.us else null;
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
    const per: i64 = switch (which) {
        .total_days => us_per_day,
        .total_hours => 3600 * us_per_s,
        .total_minutes => 60 * us_per_s,
        .total_seconds => us_per_s,
        .total_milliseconds => 1000,
        .total_microseconds => 1,
        else => 0,
    };
    if (per != 0) return if (v == .int) .{ .int = @divTrunc(v.int, per) } else .null;
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
        .total_days, .total_hours, .total_minutes, .total_seconds, .total_milliseconds, .total_microseconds => unreachable, // answered above
    };
}

// ── formats ─────────────────────────────────────────────────────────────────

pub const FormatError = error{ OutOfMemory, BadFormat };

/// pandas' and polars' `%` directives (C `strftime`, chrono) as a `datefmt` layout:
/// `%Y %y %m %d %H %I %M %S %p %f %z %:z %b %h %B %a %A %j %u %V %G %F %T %R %D %%`,
/// the text between them literal (`[` and `]` included). Another directive, or a `%`
/// at the end, is `error.BadFormat`.
pub fn translateFormat(a: std.mem.Allocator, fmt: []const u8) FormatError![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var lit: std.ArrayList(u8) = .empty;
    defer lit.deinit(a);
    var i: usize = 0;
    while (i < fmt.len) {
        const c = fmt[i];
        if (c != '%') {
            // `[` is fine inside a `[...]` literal; a `]` ends it, so it is written
            // bare, which `datefmt` takes as a literal run of its own.
            if (c == ']') {
                if (lit.items.len > 0) {
                    try out.append(a, '[');
                    try out.appendSlice(a, lit.items);
                    try out.append(a, ']');
                    lit.clearRetainingCapacity();
                }
                try out.append(a, ']');
            } else try lit.append(a, c);
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
        if (d == 'Z' and step == 2) {
            // `%Z`, the zone name: every instant here is UTC.
            try lit.appendSlice(a, "UTC");
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
/// counted from 1970-01-01 (months from January 1970, weeks from Monday 1970-01-05,
/// as polars). The compiler refuses an `every` that is zero, negative, or mixes months
/// with a fixed part.
pub fn truncate(a: std.mem.Allocator, v: Value, d: Duration) error{OutOfMemory}!Value {
    return roundTo(a, v, d, .floor);
}

/// Which end of its `every` bucket a temporal goes to.
pub const RoundTo = enum {
    /// The bucket's start (polars `dt.truncate`, pandas `dt.floor`).
    floor,
    /// The next bucket's start unless already on one (pandas `dt.ceil`).
    ceil,
    /// The nearer of the two, a tie to the later (polars `dt.round`; pandas
    /// `dt.round` ties to the even multiple).
    nearest,
};

/// The start of the `every` bucket holding `us` (null past the i64 range) and of the
/// next one (null when that alone is past it).
fn bucket(us: i64, d: Duration) ?struct { lo: i64, hi: ?i64 } {
    if (d.months > 0) {
        const p = partsOf(us);
        const idx = (@as(i64, p.year) - 1970) * 12 + (@as(i64, p.month) - 1);
        const t = @divFloor(idx, d.months) * d.months;
        return .{ .lo = monthStart(t) orelse return null, .hi = monthStart(t + d.months) };
    }
    // Weeks count from Monday 1970-01-05 (polars; a two-week step shows it: from Monday
    // 1969-12-29 it would land on the other Mondays).
    const origin: i64 = if (d.weeks != 0 and @mod(d.us, 7 * us_per_day) == 0) 4 * us_per_day else 0;
    const lo = @divFloor(@as(i128, us) - origin, d.us) * d.us + origin;
    return .{ .lo = std.math.cast(i64, lo) orelse return null, .hi = std.math.cast(i64, lo + d.us) };
}

/// Microseconds at the first day of month `m` counted from January 1970.
fn monthStart(m: i64) ?i64 {
    const year = std.math.cast(i32, 1970 + @divFloor(m, 12)) orelse return null;
    return usOf(.{ .year = year, .month = @intCast(@mod(m, 12) + 1), .day = 1 });
}

/// `truncate` with a choice of end: see `RoundTo`. The compiler refuses the same
/// `every` values. A value already on a bucket start stays (all three modes); null
/// when the answer is past the i64 range.
pub fn roundTo(a: std.mem.Allocator, v: Value, d: Duration, mode: RoundTo) error{OutOfMemory}!Value {
    const in = read(v) orelse return .null;
    const b = bucket(in.us, d) orelse return .null;
    const t = switch (mode) {
        .floor => b.lo,
        .ceil => if (b.lo == in.us) b.lo else b.hi orelse return .null,
        // i128: the differences of two i64 values.
        .nearest => blk: {
            const hi = b.hi orelse break :blk b.lo; // only `lo` exists: it is the nearer
            break :blk if (@as(i128, in.us) - b.lo >= @as(i128, hi) - in.us) hi else b.lo;
        },
    };
    return write(a, t, in.shape);
}

/// Monday to Friday after `n` business days (polars `add_business_days` with
/// `roll="forward"`; pandas' `+ BDay(n)` agrees from a weekday, but from a weekend it
/// counts the roll as the first day): a start on a weekend first rolls to the next
/// Monday. The time of day is kept; the input's shape.
pub fn addBusinessDays(a: std.mem.Allocator, v: Value, n: i64) error{OutOfMemory}!Value {
    const in = read(v) orelse return .null;
    const us = addBusinessDaysInt(in.us, n) orelse return .null;
    return write(a, us, in.shape);
}

/// `addBusinessDays` on microseconds since the epoch; null past the i64 range.
pub fn addBusinessDaysInt(at_us: i64, n: i64) ?i64 {
    var day = @divFloor(at_us, us_per_day);
    const tod = @mod(at_us, us_per_day);
    const wd = datefmt.isoWeekday(day);
    if (wd > 5) day += 8 - @as(i64, wd);
    // Business-day index from Monday 1969-12-29 (epoch day -3).
    const rel = day + 3;
    const week = @divFloor(rel, 7);
    const idx = @mod(rel, 7); // 0..4 after the roll
    const step = std.math.add(i64, idx, n) catch return null;
    const total = std.math.add(i64, std.math.mul(i64, week, 5) catch return null, step) catch return null;
    const nweek = @divFloor(total, 5);
    const nidx = @mod(total, 5);
    const nday = std.math.add(i64, std.math.mul(i64, nweek, 7) catch return null, nidx - 3) catch return null;
    return std.math.add(i64, std.math.mul(i64, nday, us_per_day) catch return null, tod) catch null;
}

/// How `fromLocal` settles a wall-clock time a zone shows twice (a fold) or never
/// (a gap). polars `replace_time_zone(ambiguous=, non_existent=)`, pandas
/// `tz_localize(ambiguous=, nonexistent=)`.
pub const TzPolicy = enum {
    /// Fold: the earlier instant; gap: moved forward by the gap's size (Python's
    /// `fold=0`, java.time, Temporal's `compatible`).
    compatible,
    /// Fold and gap: the earlier instant (polars `ambiguous="earliest"`).
    earlier,
    /// Fold and gap: the later instant (polars `ambiguous="latest"`).
    later,
    /// Either: null (polars `"null"`, pandas `"NaT"`).
    null,
};

/// The UTC instant `v` as the wall clock of `zone` shows it, as a zone-less temporal
/// (polars `convert_time_zone(zone)` then reading the wall clock, pandas
/// `tz_convert(zone).tz_localize(None)`). A timestamp cell stays an `.int`, an ISO
/// text stays text without its `Z`; a date is null (it names no instant). Offsets are the zone's from
/// 1970 on (`tz.zones`); before that, the zone's state at the epoch.
pub fn toLocal(a: std.mem.Allocator, v: Value, zone: *const tz.Zone) error{OutOfMemory}!Value {
    const in = read(v) orelse return .null;
    if (in.shape == .date) return .null;
    const off = tz.offsetAt(zone, @divFloor(in.us, us_per_s)).off;
    const us = std.math.add(i64, in.us, @as(i64, off) * us_per_s) catch return .null;
    if (in.shape == .text_ts) {
        // A wall-clock time has no zone: the ISO text without the `Z` (pandas and
        // polars print a zone-less timestamp the same way).
        var buf: [vm.max_iso_timestamp_len]u8 = undefined;
        const t = vm.formatIsoTimestamp(&buf, us);
        return .{ .text = try a.dupe(u8, t[0 .. t.len - 1]) };
    }
    return write(a, us, in.shape);
}

/// The wall-clock time `v` read in `zone`, as the UTC instant it names (polars
/// `replace_time_zone(zone)` then `convert_time_zone("UTC")`, pandas
/// `tz_localize(zone).tz_convert("UTC")`); `policy` settles folds and gaps. Shapes
/// as `toLocal`.
pub fn fromLocal(a: std.mem.Allocator, v: Value, zone: *const tz.Zone, policy: TzPolicy) error{OutOfMemory}!Value {
    const in = read(v) orelse return .null;
    if (in.shape == .date) return .null;
    const secs = @divFloor(in.us, us_per_s);
    const frac = @mod(in.us, us_per_s);
    const utc = tz.localToUtc(zone, secs, switch (policy) {
        .compatible => .compatible,
        .earlier => .earlier,
        .later => .later,
        .null => .reject,
    }) catch return .null;
    // `utc` is within a day or two of `secs`, which came from an i64 of microseconds:
    // the product only overflows at the very edge of the range.
    const us = std.math.add(i64, std.math.mul(i64, utc, us_per_s) catch return .null, frac) catch return .null;
    return write(a, us, in.shape);
}

pub fn isMissing(v: Value) bool {
    return keys.isMissing(v);
}

// ── constructors and business-day counts (dataframe S2 wave W3) ──────────────

/// `d` repeated `k` times (`k * d`), null on overflow. Ranges step from the start by
/// whole multiples of the interval, never from the previous point, so a month-end start
/// does not drift (Jan 31 + 1mo + 1mo is Mar 31, not Mar 28).
pub fn scaleDuration(d: Duration, k: i64) ?Duration {
    return .{
        .months = std.math.mul(i64, d.months, k) catch return null,
        .us = std.math.mul(i64, d.us, k) catch return null,
        .weeks = d.weeks,
    };
}

/// The point `k` intervals after the instant `us` (whole microseconds since the epoch),
/// null past the representable range. The months go first, the day clamped to the new
/// month (`offsetBy`).
pub fn stepInstant(us: i64, d: Duration, k: i64) ?i64 {
    const s = scaleDuration(d, k) orelse return null;
    var t = us;
    if (s.months != 0) {
        const p = partsOf(t);
        const months = std.math.cast(i32, s.months) orelse return null;
        var q = datefmt.addMonths(p, months);
        q.nanosecond = p.nanosecond;
        t = usOf(q) orelse return null;
    }
    return std.math.add(i64, t, s.us) catch null;
}

/// Monday-first week mask of polars' default (Mon to Fri are business days).
pub const monday_to_friday: [7]bool = .{ true, true, true, true, true, false, false };

/// polars `business_day_count(start, end, week_mask, holidays)`, numpy `busday_count`:
/// the days of `[start_day, end_day)` (epoch days) whose weekday is on in `mask`
/// (index 0 = Monday) and that are not in `holidays` (sorted ascending, no duplicates;
/// a holiday on an off weekday is not counted twice). `end_day < start_day` gives the
/// negated count of `[end_day, start_day)`, as numpy.
pub fn businessDayCount(start_day: i64, end_day: i64, mask: [7]bool, holidays: []const i64) i64 {
    if (end_day < start_day) return -businessDayCount(end_day, start_day, mask, holidays);
    var per_week: i64 = 0;
    for (mask) |m| per_week += @intFromBool(m);
    const n = end_day - start_day;
    var count = @divFloor(n, 7) * per_week;
    var i: i64 = 0;
    while (i < @mod(n, 7)) : (i += 1) {
        count += @intFromBool(mask[datefmt.isoWeekday(start_day + i) - 1]);
    }
    for (holidays) |h| {
        if (h < start_day) continue;
        if (h >= end_day) break;
        count -= @intFromBool(mask[datefmt.isoWeekday(h) - 1]);
    }
    return count;
}

/// The date part of a temporal cell (a date, a timestamp, an ISO timestamp text) as an
/// epoch day, null when the cell is none of those.
pub fn dayOf(v: Value) ?i64 {
    const in = read(v) orelse return null;
    return @divFloor(in.us, us_per_day);
}

/// The unit an integer epoch count is in (polars `from_epoch(time_unit=)`).
pub const EpochUnit = enum { day, s, ms, us, ns };

/// polars `from_epoch`, pandas `to_datetime(unit=)`: an integer count of `unit` since
/// 1970-01-01 as a timestamp (microseconds, `.int`) or, for `.day`, as an ISO date text.
/// `ns` truncates toward the earlier microsecond. Not an int, or past the range (a date
/// outside years 0 to 9999): null.
pub fn fromEpoch(a: std.mem.Allocator, v: Value, unit: EpochUnit) error{OutOfMemory}!Value {
    if (v != .int) return .null;
    const n = v.int;
    switch (unit) {
        .day => return dateText(a, n),
        .s => return .{ .int = std.math.mul(i64, n, us_per_s) catch return .null },
        .ms => return .{ .int = std.math.mul(i64, n, 1000) catch return .null },
        .us => return v,
        .ns => return .{ .int = @divFloor(n, 1000) },
    }
}

/// polars `pl.date(year, month, day)`: the ISO date text, null when the day does not exist
/// or the year is outside 0 to 9999.
pub fn makeDate(a: std.mem.Allocator, y: i64, m: i64, d: i64) error{OutOfMemory}!Value {
    const day = civilDay(y, m, d) orelse return .null;
    return dateText(a, day);
}

fn civilDay(y: i64, m: i64, d: i64) ?i64 {
    const yy = std.math.cast(i32, y) orelse return null;
    if (m < 1 or m > 12 or d < 1) return null;
    if (d > vm.Date.daysInMonth(yy, @intCast(m))) return null;
    return datefmt.ymdToEpochDay(yy, @intCast(m), @intCast(d));
}

/// polars `pl.datetime(year, month, day, hour, minute, second, microsecond)`: the
/// instant as microseconds since the epoch (a `.timestamp` cell). A day that does not
/// exist, an hour past 23, a minute or second past 59 or a microsecond past 999999: null.
pub fn makeDatetime(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64, micro: i64) Value {
    const day = civilDay(y, mo, d) orelse return .null;
    if (h < 0 or h > 23 or mi < 0 or mi > 59 or s < 0 or s > 59 or micro < 0 or micro > 999_999) return .null;
    const tod = (h * 3600 + mi * 60 + s) * us_per_s + micro;
    const t = std.math.add(i64, std.math.mul(i64, day, us_per_day) catch return .null, tod) catch return .null;
    return .{ .int = t };
}

/// polars `pl.duration(weeks, days, hours, minutes, seconds, milliseconds, microseconds)`:
/// the sum as microseconds (a `.duration` cell); overflow is null.
pub fn makeDuration(parts: [7]i64) Value {
    const per = [7]i64{ 7 * us_per_day, us_per_day, 3600 * us_per_s, 60 * us_per_s, us_per_s, 1000, 1 };
    var total: i64 = 0;
    for (parts, per) |p, u| {
        const x = std.math.mul(i64, p, u) catch return .null;
        total = std.math.add(i64, total, x) catch return .null;
    }
    return .{ .int = total };
}

/// ISO date text of epoch day `day` (null outside years 0 to 9999).
pub fn dayText(a: std.mem.Allocator, day: i64) error{OutOfMemory}!Value {
    return dateText(a, day);
}
