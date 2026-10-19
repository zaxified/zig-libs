// SPDX-License-Identifier: MIT
//! datefmt — civil calendar (Hinnant days-from-civil, correct pre-1970) +
//! token-based parse/format + date arithmetic. std-only.
//!
//! Two layers:
//!   1. Civil core — `ymdToEpochDay` / `epochDayToYmd` / `isoWeekday`,
//!      leap-year + days-in-month, name tables. `i64` epoch-day math
//!      (`@divFloor`), so every function here is correct for dates before the
//!      Unix epoch — unlike a `u64`-seconds-since-epoch core, which silently
//!      floors any pre-1970 date to 1970-01-01.
//!   2. Token I/O — `parse` (string + format → `DateParts`) and `format`
//!      (`DateParts` + format → string). A parse→format reshuffle never
//!      round-trips through an epoch timestamp, so it has no lower-year limit.
//!
//! Format token vocabulary (parse and format share it):
//!   YYYY 4-digit year · YY 2-digit year (00-69→2000s, 70-99→1900s)
//!   MM/M month (2-digit / 1-2-digit) · MMM short name · MMMM full name
//!   DD/D day · hh/h hour 24h · ii/i hour 12h (needs A/a) · mm/m minute
//!   ss/s second · A/a AM-PM (upper/lower) · ZZ UTC offset ±HH:MM (or Z)
//!   EEEE full day name · EEE/EE/E short day name · e day-of-week 1-7 (Mon=1)
//!   SSS/SSSSSS/SSSSSSSSS fraction of a second, 3/6/9 digits (ms/µs/ns)
//!   GGGG ISO week-year · WW/W ISO week number (01-53 / 1-53)
//!   [text] literal · [*] wildcard (skip until next token)

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Civil calendar, token-based date/time parse/format, RFC 3339/5322/HTTP dates, Go-style durations and calendar arithmetic, correct before 1970.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{ .linux64, .windows },
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "Howard Hinnant chrono civil algorithms; strftime tokens",
    .deps = .{},
};

/// One format token, documented alongside the parse/format vocabulary (see
/// the module header). A single source for the token reference so it can't
/// drift from the parser/formatter.
pub const DateTokenDoc = struct {
    token: []const u8,
    meaning: []const u8,
    example: []const u8,
};

pub const date_tokens = [_]DateTokenDoc{
    .{ .token = "YYYY", .meaning = "4-digit year", .example = "2026" },
    .{ .token = "YY", .meaning = "2-digit year (00–69 → 2000s, 70–99 → 1900s)", .example = "26" },
    .{ .token = "MM", .meaning = "2-digit month (01–12)", .example = "03" },
    .{ .token = "M", .meaning = "1–2 digit month", .example = "3" },
    .{ .token = "MMMM", .meaning = "Full month name", .example = "March" },
    .{ .token = "MMM", .meaning = "3-char month abbreviation", .example = "Mar" },
    .{ .token = "DD", .meaning = "2-digit day (01–31)", .example = "07" },
    .{ .token = "D", .meaning = "1–2 digit day", .example = "7" },
    .{ .token = "hh", .meaning = "2-digit hour, 24h (00–23)", .example = "14" },
    .{ .token = "h", .meaning = "1–2 digit hour, 24h", .example = "14" },
    .{ .token = "ii", .meaning = "2-digit hour, 12h (01–12)", .example = "02" },
    .{ .token = "i", .meaning = "1–2 digit hour, 12h", .example = "2" },
    .{ .token = "mm", .meaning = "2-digit minute", .example = "05" },
    .{ .token = "m", .meaning = "1–2 digit minute", .example = "5" },
    .{ .token = "ss", .meaning = "2-digit second", .example = "09" },
    .{ .token = "s", .meaning = "1–2 digit second", .example = "9" },
    .{ .token = "A", .meaning = "AM/PM uppercase", .example = "PM" },
    .{ .token = "a", .meaning = "am/pm lowercase", .example = "pm" },
    .{ .token = "ZZ", .meaning = "UTC offset ±HH:MM (parses a literal Z as +00:00)", .example = "+02:00" },
    .{ .token = "EEEE", .meaning = "Full day name", .example = "Monday" },
    .{ .token = "EEE/EE/E", .meaning = "Short day name", .example = "Mon" },
    .{ .token = "e", .meaning = "Day of week as number (1 = Mon … 7 = Sun)", .example = "1" },
    .{ .token = "SSS", .meaning = "Fraction of a second, 3 digits (milliseconds; format truncates)", .example = "123" },
    .{ .token = "SSSSSS", .meaning = "Fraction of a second, 6 digits (microseconds; format truncates)", .example = "123456" },
    .{ .token = "SSSSSSSSS", .meaning = "Fraction of a second, 9 digits (nanoseconds)", .example = "123456789" },
    .{ .token = "GGGG", .meaning = "4-digit ISO week-year (the year owning the ISO week)", .example = "2009" },
    .{ .token = "WW", .meaning = "2-digit ISO week number (01–53)", .example = "53" },
    .{ .token = "W", .meaning = "1–2 digit ISO week number", .example = "5" },
    .{ .token = "[text]", .meaning = "Literal text (escaped inside format string)", .example = "[T] → T" },
    .{ .token = "[*]", .meaning = "Wildcard — skip until the next token", .example = "skips Z, timezone suffix" },
};

pub const ParseError = error{
    InvalidFormat,
    InvalidDate,
    InvalidTime,
    InvalidFormatString,
    TooManyTokens,
};

/// Calendar date + wall-clock time. Time fields default to 0. `year` is
/// signed so pre-epoch years round-trip cleanly through the civil core.
pub const DateParts = struct {
    year: i32 = 1970,
    month: u32 = 1,
    day: u32 = 1,
    hour: u32 = 0,
    minute: u32 = 0,
    second: u32 = 0,
    /// Sub-second part in nanoseconds (0..999_999_999), the finest unit any
    /// token carries. Set by the `SSS`/`SSSSSS`/`SSSSSSSSS` tokens and by
    /// `parseXsdDateTimeNs`; `format` truncates it to the token's width.
    /// Calendar arithmetic (`addDays`/`addMonths`) preserves it; `partsToUnix`
    /// ignores it (whole seconds).
    nanosecond: u32 = 0,
    /// UTC offset in minutes carried by a `ZZ` token (`+02:00` → 120, `Z` → 0);
    /// null when the format has no offset token. Only the parse→format reshuffle
    /// and TZ-aware callers read it; calendar arithmetic ignores it.
    off_min: ?i32 = null,
};

// ---------------------------------------------------------------------------
// Civil core — Howard Hinnant's algorithms (pre-1970 safe)
// Reference: https://howardhinnant.github.io/date_algorithms.html
// ---------------------------------------------------------------------------

/// Days since the Unix epoch (1970-01-01) for a proleptic-Gregorian Y/M/D.
/// Negative for dates before the epoch. Valid for any month in 1..12.
pub fn ymdToEpochDay(year: i32, month: u32, day: u32) i64 {
    const y: i64 = if (month <= 2) @as(i64, year) - 1 else year;
    const era: i64 = @divFloor(if (y >= 0) y else y - 399, 400);
    const yoe: u64 = @intCast(y - era * 400); // [0, 399]
    const m_idx: u64 = if (month > 2) month - 3 else month + 9;
    const doy: u64 = (153 * m_idx + 2) / 5 + day - 1; // [0, 365]
    const doe: u64 = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    return era * 146097 + @as(i64, @intCast(doe)) - 719468;
}

/// Inverse of `ymdToEpochDay`: civil Y/M/D for a (possibly negative) epoch day.
pub fn epochDayToYmd(epoch_day: i64) DateParts {
    const z: i64 = epoch_day + 719468;
    const era: i64 = @divFloor(if (z >= 0) z else z - 146096, 146097);
    const doe: u64 = @intCast(z - era * 146097); // [0, 146096]
    const yoe: u64 = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    const y: i64 = @as(i64, @intCast(yoe)) + era * 400;
    const doy: u64 = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    const mp: u64 = (5 * doy + 2) / 153; // [0, 11]
    const d: u32 = @intCast(doy - (153 * mp + 2) / 5 + 1); // [1, 31]
    const m: u32 = if (mp < 10) @intCast(mp + 3) else @intCast(mp - 9); // [1, 12]
    // Saturates at the i32 range instead of trapping (Debug/ReleaseSafe) or
    // being undefined (ReleaseFast): an `i64` Unix instant reaches years of
    // ~2.9e11, beyond `DateParts.year`.
    const year = if (m <= 2) y + 1 else y;
    return .{ .year = @intCast(std.math.clamp(year, std.math.minInt(i32), std.math.maxInt(i32))), .month = m, .day = d };
}

/// ISO weekday: Monday=1 … Sunday=7. 1970-01-01 (epoch day 0) was Thursday=4.
pub fn isoWeekday(epoch_day: i64) u32 {
    return @intCast(@mod(epoch_day + 3, 7) + 1);
}

/// ISO 8601 week date of a civil day: the week-year (the year owning the
/// week — differs from the calendar year near Jan 1 / Dec 31) and week number.
pub const IsoWeek = struct {
    year: i32,
    week: u32, // 1..53
};

/// ISO 8601 week of `parts` (Monday-based weeks; week 1 is the one holding the
/// year's first Thursday). Pre-1970 safe; only year/month/day are read.
pub fn isoWeek(parts: DateParts) IsoWeek {
    const day = ymdToEpochDay(parts.year, parts.month, parts.day);
    // The Thursday of the same ISO week decides the week-year.
    const thursday = day - @as(i64, isoWeekday(day)) + 4;
    const ty = epochDayToYmd(thursday).year;
    const week: u32 = @intCast(@divFloor(thursday - ymdToEpochDay(ty, 1, 1), 7) + 1);
    return .{ .year = ty, .week = week };
}

/// Number of ISO weeks (52 or 53) in ISO week-year `iso_year`. Dec 28 always
/// lies in the last ISO week of its year.
pub fn isoWeeksInYear(iso_year: i32) u32 {
    return isoWeek(.{ .year = iso_year, .month = 12, .day = 28 }).week;
}

/// Inverse of `isoWeek`: epoch day of ISO `weekday` (Mon=1 … Sun=7) in week
/// `week` of ISO week-year `iso_year`. Null when `week` is not in
/// 1..`isoWeeksInYear(iso_year)` or `weekday` is not in 1..7.
pub fn isoWeekDateToEpochDay(iso_year: i32, week: u32, weekday: u32) ?i64 {
    if (weekday < 1 or weekday > 7) return null;
    if (week < 1 or week > isoWeeksInYear(iso_year)) return null;
    // Jan 4 always lies in week 1; back up to that week's Monday.
    const jan4 = ymdToEpochDay(iso_year, 1, 4);
    const week1_monday = jan4 - @as(i64, isoWeekday(jan4)) + 1;
    return week1_monday + (@as(i64, week) - 1) * 7 + (@as(i64, weekday) - 1);
}

/// Unix seconds for a UTC wall-clock `DateParts` (offset field ignored — the
/// caller decides whether the parts are UTC or a zone-local pseudo-instant).
/// Pre-1970 safe via the civil core.
pub fn partsToUnix(p: DateParts) i64 {
    const days = ymdToEpochDay(p.year, p.month, p.day);
    return days * 86400 + @as(i64, p.hour) * 3600 + @as(i64, p.minute) * 60 + @as(i64, p.second);
}

/// Inverse of `partsToUnix`: UTC wall-clock `DateParts` for a Unix instant.
pub fn unixToParts(unix: i64) DateParts {
    const day = @divFloor(unix, 86400);
    // `@mod`, not `unix - day * 86400`: that product is below minInt(i64) for
    // unix == minInt(i64) and overflowed.
    const rem: u32 = @intCast(@mod(unix, 86400)); // [0, 86399]
    var r = epochDayToYmd(day);
    r.hour = rem / 3600;
    r.minute = (rem % 3600) / 60;
    r.second = rem % 60;
    return r;
}

/// Unix nanoseconds for a UTC wall-clock `DateParts`, `nanosecond` included
/// (offset ignored, as `partsToUnix`). Null outside the `i64` range, which is
/// 1677-09-21 .. 2262-04-11 -- Go's `UnixNano` range, where Go's result is
/// undefined instead.
pub fn partsToUnixNs(p: DateParts) ?i64 {
    // Through i128: at the low edge the whole seconds alone are below minInt(i64).
    const ns = @as(i128, partsToUnix(p)) * std.time.ns_per_s + p.nanosecond;
    return std.math.cast(i64, ns);
}

/// Inverse of `partsToUnixNs`: UTC wall-clock `DateParts` for Unix nanoseconds
/// (Go's `time.Unix(0, ns)`). `nanosecond` is the non-negative fraction, floor
/// semantics as `unixToParts`.
pub fn unixNsToParts(ns: i64) DateParts {
    var r = unixToParts(@divFloor(ns, std.time.ns_per_s));
    r.nanosecond = @intCast(@mod(ns, std.time.ns_per_s));
    return r;
}

/// The same instant as UTC wall-clock parts: `off_min` subtracted, then 0
/// (`10:00+02:00` → `08:00Z`). A null `off_min` is taken as UTC. Valid input
/// assumed (`validate`); the fraction is carried. What a caller of
/// `parseRfc2822`/`parseRfc3339` needs before `partsToUnix`.
pub fn toUtc(p: DateParts) DateParts {
    const off: i64 = p.off_min orelse 0;
    var r = unixToParts(partsToUnix(p) - off * 60);
    r.nanosecond = p.nanosecond;
    r.off_min = 0;
    return r;
}

pub fn isLeapYear(year: i32) bool {
    return (@mod(year, 4) == 0 and @mod(year, 100) != 0) or (@mod(year, 400) == 0);
}

pub fn daysInMonth(year: i32, month: u32) u32 {
    const lengths = [_]u32{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    if (month < 1 or month > 12) return 0;
    if (month == 2 and isLeapYear(year)) return 29;
    return lengths[month - 1];
}

/// True when every field of `p` is in range (month 1-12, day valid for the
/// month, hour 0-23, minute/second 0-59, nanosecond < 1e9). Year is
/// unconstrained.
pub fn validate(p: DateParts) bool {
    if (p.month < 1 or p.month > 12) return false;
    if (p.day < 1 or p.day > daysInMonth(p.year, p.month)) return false;
    if (p.hour > 23 or p.minute > 59 or p.second > 59) return false;
    if (p.nanosecond > 999_999_999) return false;
    return true;
}

// ---------------------------------------------------------------------------
// Name tables
// ---------------------------------------------------------------------------

const short_month_names = [_][]const u8{
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
};
const full_month_names = [_][]const u8{
    "January",   "February", "March",    "April",
    "May",       "June",     "July",     "August",
    "September", "October",  "November", "December",
};
const short_day_names = [_][]const u8{ "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun" };
const full_day_names = [_][]const u8{
    "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday",
};

fn shortMonthName(month: u32) []const u8 {
    if (month < 1 or month > 12) return "???";
    return short_month_names[month - 1];
}
fn fullMonthName(month: u32) []const u8 {
    if (month < 1 or month > 12) return "Unknown";
    return full_month_names[month - 1];
}
fn shortDayName(dow: u32) []const u8 {
    if (dow < 1 or dow > 7) return "???";
    return short_day_names[dow - 1];
}
fn fullDayName(dow: u32) []const u8 {
    if (dow < 1 or dow > 7) return "Unknown";
    return full_day_names[dow - 1];
}

/// 24h hour → 12h hour (1-12).
fn to12Hour(hour: u32) u32 {
    if (hour == 0) return 12;
    if (hour <= 12) return hour;
    return hour - 12;
}

// ---------------------------------------------------------------------------
// Format-string tokenizer (allocation-free)
// ---------------------------------------------------------------------------

const Token = union(enum) {
    year_full, // YYYY
    year_short, // YY
    month_full, // MM
    month_short, // M
    month_name_short, // MMM
    month_name_long, // MMMM
    day_full, // DD
    day_short, // D
    day_name_long, // EEEE
    day_name_short, // EEE / EE / E
    day_of_week, // e
    hour_24_full, // hh
    hour_24_short, // h
    hour_12_full, // ii
    hour_12_short, // i
    minute_full, // mm
    minute_short, // m
    second_full, // ss
    second_short, // s
    ampm_upper, // A
    ampm_lower, // a
    tz_offset, // ZZ — UTC offset ±HH:MM (or a literal Z = +00:00)
    fraction: u8, // SSS / SSSSSS / SSSSSSSSS — payload = digit count (3/6/9)
    iso_year, // GGGG — ISO week-year
    iso_week_full, // WW
    iso_week_short, // W
    wildcard, // [*]
    literal: []const u8, // [text] or any unrecognised run
};

/// Real format strings are short (~10-20 tokens). 64 is a generous ceiling
/// that keeps the token array on the stack — no allocator, no syscalls on
/// the format/parse hot path.
const MAX_TOKENS = 64;

/// A format string tokenized once, for callers that format or parse many
/// values with the same format: `Layout.compile` does the work `format` and
/// `parse` repeat on every call. Compile a constant format at comptime
/// (`const rfc = comptime datefmt.Layout.compile("YYYY-MM-DD") catch unreachable;`).
/// Literal tokens point into the format string, which must outlive the layout.
///
/// No field defaults on purpose: in Zig 0.16 ReleaseFast `.{}` with an
/// `undefined` array default compiles to a byte-wise memset of all 1.5 KB --
/// 63 % of `format`'s time (bench 2026-10-10). Build it as `undefined` + `n = 0`.
pub const Layout = struct {
    toks: [MAX_TOKENS]Token,
    n: usize,
    /// Upper bound of `format`'s output: every literal plus `max_field_len`
    /// per other token.
    bound: usize,
    /// A weekday token (`E*`/`e`) is present, so `format` needs the weekday.
    needs_dow: bool,

    /// Tokenize `fmt` (`InvalidFormatString` cannot happen today; a format
    /// with more than 64 tokens is `TooManyTokens`).
    pub fn compile(fmt: []const u8) ParseError!Layout {
        var l: Layout = undefined;
        try tokenize(fmt, &l);
        return l;
    }

    /// `datefmt.format` with this layout's format.
    pub fn format(l: *const Layout, alloc: std.mem.Allocator, parts: DateParts) ![]u8 {
        return formatLayout(alloc, parts, l);
    }

    /// `datefmt.parse` with this layout's format.
    pub fn parse(l: *const Layout, input: []const u8) ParseError!DateParts {
        return parseTokens(input, l.toks[0..l.n]);
    }
};

fn matchAt(s: []const u8, pos: usize, needle: []const u8) bool {
    if (pos + needle.len > s.len) return false;
    return std.mem.eql(u8, s[pos .. pos + needle.len], needle);
}

/// Ordered longest-first so e.g. "YYYY" wins over "YY" and "MMMM" over "MMM".
const token_table = [_]struct { lit: []const u8, tok: Token }{
    .{ .lit = "SSSSSSSSS", .tok = .{ .fraction = 9 } },
    .{ .lit = "SSSSSS", .tok = .{ .fraction = 6 } },
    .{ .lit = "SSS", .tok = .{ .fraction = 3 } },
    .{ .lit = "YYYY", .tok = .year_full },
    .{ .lit = "GGGG", .tok = .iso_year },
    .{ .lit = "MMMM", .tok = .month_name_long },
    .{ .lit = "EEEE", .tok = .day_name_long },
    .{ .lit = "MMM", .tok = .month_name_short },
    .{ .lit = "EEE", .tok = .day_name_short },
    .{ .lit = "MM", .tok = .month_full },
    .{ .lit = "DD", .tok = .day_full },
    .{ .lit = "ii", .tok = .hour_12_full },
    .{ .lit = "hh", .tok = .hour_24_full },
    .{ .lit = "mm", .tok = .minute_full },
    .{ .lit = "ss", .tok = .second_full },
    .{ .lit = "ZZ", .tok = .tz_offset },
    .{ .lit = "WW", .tok = .iso_week_full },
    .{ .lit = "YY", .tok = .year_short },
    .{ .lit = "EE", .tok = .day_name_short },
    .{ .lit = "W", .tok = .iso_week_short },
    .{ .lit = "M", .tok = .month_short },
    .{ .lit = "D", .tok = .day_short },
    .{ .lit = "i", .tok = .hour_12_short },
    .{ .lit = "h", .tok = .hour_24_short },
    .{ .lit = "m", .tok = .minute_short },
    .{ .lit = "s", .tok = .second_short },
    .{ .lit = "E", .tok = .day_name_short },
    .{ .lit = "e", .tok = .day_of_week },
    .{ .lit = "A", .tok = .ampm_upper },
    .{ .lit = "a", .tok = .ampm_lower },
};

/// `token_table` indexed by first character. Every token literal is a run of
/// one character ("YYYY", "SSS", "e"), so the longest-first match at `pos` is
/// the longest entry for `fmt[pos]` that fits the run of that character there
/// -- one lookup instead of a scan of the whole table per position (the scan
/// made format/parse 7-18x slower than Go's `time`, bench 2026-10-10).
const ByChar = struct {
    lens: [max_per_char]u8 = @splat(0),
    toks: [max_per_char]Token = undefined,
    n: u8 = 0,
};
const max_per_char = 4;
const max_token_len = blk: {
    var m: usize = 0;
    for (token_table) |e| m = @max(m, e.lit.len);
    break :blk m;
};
const by_char: [128]ByChar = blk: {
    var t: [128]ByChar = @splat(.{});
    for (token_table) |e| {
        for (e.lit) |c| if (c != e.lit[0]) @compileError("token literal is not a single-character run: " ++ e.lit);
        const slot = &t[e.lit[0]];
        if (slot.n > 0 and slot.lens[slot.n - 1] <= e.lit.len) @compileError("token_table is not longest-first for " ++ e.lit);
        slot.lens[slot.n] = e.lit.len;
        slot.toks[slot.n] = e.tok;
        slot.n += 1;
    }
    break :blk t;
};

const TokenMatch = struct { tok: Token, len: usize };

/// The token `tokenize` would match at `fmt[pos]`, longest first; null when
/// `fmt[pos]` starts no token (a `[` is handled by the caller).
fn tokenAt(fmt: []const u8, pos: usize) ?TokenMatch {
    const c = fmt[pos];
    if (c >= by_char.len) return null;
    const e = &by_char[c];
    if (e.n == 0) return null;
    var run: usize = 1;
    while (run < max_token_len and pos + run < fmt.len and fmt[pos + run] == c) run += 1;
    for (e.lens[0..e.n], e.toks[0..e.n]) |len, tok| {
        if (len <= run) return .{ .tok = tok, .len = len };
    }
    return null;
}

fn isTokenStart(fmt: []const u8, pos: usize) bool {
    return fmt[pos] == '[' or tokenAt(fmt, pos) != null;
}

/// Tokenize into the caller's `out` (a 1.5 KB value returned through an error
/// union is copied on every call).
fn tokenize(fmt: []const u8, out: *Layout) ParseError!void {
    out.n = 0;
    var pos: usize = 0;
    while (pos < fmt.len) {
        if (out.n >= MAX_TOKENS) return ParseError.TooManyTokens;

        // [text] literal or [*] wildcard.
        if (fmt[pos] == '[') {
            // A plain loop: bracketed literals are a few bytes, shorter than
            // the setup of a vectorized search.
            var end = pos + 1;
            while (end < fmt.len and fmt[end] != ']') end += 1;
            if (end > pos + 1) {
                const content = fmt[pos + 1 .. end];
                out.toks[out.n] = if (content.len == 1 and content[0] == '*')
                    .wildcard
                else
                    .{ .literal = content };
                out.n += 1;
                pos = end + 1;
                continue;
            }
        }

        // Longest-first token match.
        if (tokenAt(fmt, pos)) |m| {
            out.toks[out.n] = m.tok;
            out.n += 1;
            pos += m.len;
            continue;
        }

        // Literal run: consume until the next token start.
        const start = pos;
        pos += 1;
        while (pos < fmt.len and !isTokenStart(fmt, pos)) pos += 1;
        out.toks[out.n] = .{ .literal = fmt[start..pos] };
        out.n += 1;
    }

    out.bound = 0;
    out.needs_dow = false;
    for (out.toks[0..out.n]) |t| switch (t) {
        .literal => |lit| out.bound += lit.len,
        .day_name_long, .day_name_short, .day_of_week => {
            out.bound += max_field_len;
            out.needs_dow = true;
        },
        else => out.bound += max_field_len,
    };
}

// ---------------------------------------------------------------------------
// Parsing: string + format → DateParts
// ---------------------------------------------------------------------------

fn findNumberEnd(s: []const u8, start: usize, max_digits: usize) usize {
    var pos = start;
    var count: usize = 0;
    while (pos < s.len and count < max_digits) : ({
        pos += 1;
        count += 1;
    }) {
        if (s[pos] < '0' or s[pos] > '9') break;
    }
    return pos;
}

fn parseShortMonthName(s: []const u8) ParseError!u32 {
    if (s.len < 3) return ParseError.InvalidFormat;
    for (short_month_names, 0..) |name, i| {
        if (std.ascii.eqlIgnoreCase(s[0..3], name)) return @intCast(i + 1);
    }
    return ParseError.InvalidDate;
}

fn parseLongMonthName(s: []const u8) ParseError!struct { month: u32, len: usize } {
    for (full_month_names, 0..) |name, i| {
        if (s.len >= name.len and std.ascii.eqlIgnoreCase(s[0..name.len], name)) {
            return .{ .month = @intCast(i + 1), .len = name.len };
        }
    }
    return ParseError.InvalidDate;
}

fn parseDayName(s: []const u8) ParseError!usize {
    for (full_day_names) |name| {
        if (s.len >= name.len and std.ascii.eqlIgnoreCase(s[0..name.len], name)) return name.len;
    }
    for (short_day_names) |name| {
        if (s.len >= name.len and std.ascii.eqlIgnoreCase(s[0..name.len], name)) return name.len;
    }
    return ParseError.InvalidFormat;
}

fn isAllDigits(s: []const u8) bool {
    for (s) |c| if (c < '0' or c > '9') return false;
    return true;
}

/// Locate where `next` could start, scanning forward from `pos` (drives [*]).
fn skipUntilNextToken(s: []const u8, pos: usize, next: Token) ParseError!usize {
    switch (next) {
        .literal => |lit| {
            var i = pos;
            while (i + lit.len <= s.len) : (i += 1) {
                if (std.mem.eql(u8, s[i .. i + lit.len], lit)) return i;
            }
            return ParseError.InvalidFormat;
        },
        .year_full, .iso_year => {
            var i = pos;
            while (i + 4 <= s.len) : (i += 1) if (isAllDigits(s[i .. i + 4])) return i;
            return ParseError.InvalidFormat;
        },
        .fraction => |n| {
            var i = pos;
            while (i + n <= s.len) : (i += 1) if (isAllDigits(s[i .. i + n])) return i;
            return ParseError.InvalidFormat;
        },
        .year_short, .month_full, .day_full, .hour_24_full, .hour_12_full, .minute_full, .second_full, .iso_week_full => {
            var i = pos;
            while (i + 2 <= s.len) : (i += 1) if (isAllDigits(s[i .. i + 2])) return i;
            return ParseError.InvalidFormat;
        },
        .month_short, .day_short, .hour_24_short, .hour_12_short, .minute_short, .second_short, .day_of_week, .iso_week_short => {
            var i = pos;
            while (i < s.len) : (i += 1) if (s[i] >= '0' and s[i] <= '9') return i;
            return ParseError.InvalidFormat;
        },
        .month_name_short => {
            var i = pos;
            while (i + 3 <= s.len) : (i += 1) {
                for (short_month_names) |name| if (std.ascii.eqlIgnoreCase(s[i .. i + 3], name)) return i;
            }
            return ParseError.InvalidFormat;
        },
        .month_name_long => return skipUntilName(s, pos, &full_month_names),
        .day_name_short => {
            var i = pos;
            while (i + 3 <= s.len) : (i += 1) {
                for (short_day_names) |name| if (std.ascii.eqlIgnoreCase(s[i .. i + 3], name)) return i;
            }
            return ParseError.InvalidFormat;
        },
        .day_name_long => return skipUntilName(s, pos, &full_day_names),
        .ampm_upper, .ampm_lower => {
            var i = pos;
            while (i + 2 <= s.len) : (i += 1) {
                if (std.ascii.eqlIgnoreCase(s[i .. i + 2], "AM") or std.ascii.eqlIgnoreCase(s[i .. i + 2], "PM")) return i;
            }
            return ParseError.InvalidFormat;
        },
        .tz_offset => {
            var i = pos;
            while (i < s.len) : (i += 1) {
                const c = s[i];
                if (c == '+' or c == '-' or c == 'Z' or c == 'z') return i;
            }
            return ParseError.InvalidFormat;
        },
        .wildcard => return ParseError.InvalidFormat, // wildcard cannot follow wildcard
    }
}

fn skipUntilName(s: []const u8, pos: usize, names: []const []const u8) ParseError!usize {
    var i = pos;
    while (i < s.len) : (i += 1) {
        for (names) |name| {
            if (i + name.len <= s.len and std.ascii.eqlIgnoreCase(s[i .. i + name.len], name)) return i;
        }
    }
    return ParseError.InvalidFormat;
}

const Builder = struct {
    year: ?i32 = null,
    month: ?u32 = null,
    day: ?u32 = null,
    hour: u32 = 0,
    minute: u32 = 0,
    second: u32 = 0,
    nanosecond: u32 = 0,
    is_pm: ?bool = null,
    off_min: ?i32 = null,
    iso_year: ?i32 = null,
    iso_week: ?u32 = null,
    iso_dow: ?u32 = null,
};

/// A numeric field of the input: ASCII digits only. `std.fmt.parseInt` alone
/// also reads a leading `+`/`-` and `_` separators, so a fixed-width field
/// such as `MM` accepted `+1`, and the `ZZ` offset hour `-1` became a negative
/// hour that passed the `oh > 23` check (audit 2026-10-04) -- the same class
/// `parseDigitField` exists to rule out for `parseXsdDateTime`.
fn parseUint(comptime T: type, s: []const u8, err: ParseError) ParseError!T {
    if (s.len == 0) return err;
    var v: T = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return err;
        v = std.math.mul(T, v, 10) catch return err;
        v = std.math.add(T, v, c - '0') catch return err;
    }
    return v;
}

/// Read exactly `digits` ASCII digits at `input[p..]` as a fraction of a
/// second and scale to nanoseconds ("5" width 3 is not accepted; "500" → 5e8).
fn parseFraction(input: []const u8, p: usize, digits: u8) ParseError!u32 {
    if (p + digits > input.len) return ParseError.InvalidFormat;
    const field = input[p .. p + digits];
    if (!isAllDigits(field)) return ParseError.InvalidTime; // no sign, no '_'
    var v: u32 = 0;
    for (field) |c| v = v * 10 + (c - '0'); // ≤ 999_999_999 fits u32
    var scale: u32 = 1;
    for (0..@as(usize, 9 - digits)) |_| scale *= 10;
    return v * scale;
}

/// Parse `input` against `fmt`, returning the extracted `DateParts`. Missing
/// date components default to the epoch (1970-01-01); missing time defaults to
/// 00:00:00. Ranges are validated (`InvalidDate` / `InvalidTime`) but the year
/// has no lower bound — pre-1970 dates parse fine. This never converts to an
/// epoch timestamp, so a parse→format reshuffle round-trips any year losslessly.
///
/// Fraction tokens (`SSS`/`SSSSSS`/`SSSSSSSSS`) read exactly 3/6/9 digits into
/// `nanosecond`. ISO week tokens: when the format has `GGGG` and/or `W`/`WW`,
/// the date is derived from the ISO week date (`GGGG` defaults to `YYYY`, then
/// 1970; week defaults to 1; the `e` token supplies the weekday, default
/// Monday) and overrides any `YYYY`/`MM`/`DD` in the same format. A week that
/// does not exist in that week-year (0, or 53 in a 52-week year) is
/// `InvalidDate`.
pub fn parse(input: []const u8, fmt: []const u8) ParseError!DateParts {
    var tk: Layout = undefined;
    try tokenize(fmt, &tk);
    return parseTokens(input, tk.toks[0..tk.n]);
}

fn parseTokens(input: []const u8, toks: []const Token) ParseError!DateParts {
    var b = Builder{};
    var p: usize = 0;

    for (toks, 0..) |token, idx| {
        if (p >= input.len) {
            // Only a zero-length trailing literal is allowed past end-of-input.
            switch (token) {
                .literal => |lit| if (lit.len > 0) return ParseError.InvalidFormat,
                else => return ParseError.InvalidFormat,
            }
            continue;
        }
        switch (token) {
            .year_full => {
                if (p + 4 > input.len) return ParseError.InvalidFormat;
                b.year = try parseUint(i32, input[p .. p + 4], ParseError.InvalidDate);
                p += 4;
            },
            .year_short => {
                if (p + 2 > input.len) return ParseError.InvalidFormat;
                const yy = try parseUint(i32, input[p .. p + 2], ParseError.InvalidDate);
                b.year = if (yy < 70) yy + 2000 else yy + 1900;
                p += 2;
            },
            .month_full => {
                if (p + 2 > input.len) return ParseError.InvalidFormat;
                b.month = try parseUint(u32, input[p .. p + 2], ParseError.InvalidDate);
                p += 2;
            },
            .month_short => {
                const end = findNumberEnd(input, p, 2);
                b.month = try parseUint(u32, input[p..end], ParseError.InvalidDate);
                p = end;
            },
            .month_name_short => {
                b.month = try parseShortMonthName(input[p..]);
                p += 3;
            },
            .month_name_long => {
                const r = try parseLongMonthName(input[p..]);
                b.month = r.month;
                p += r.len;
            },
            .day_full => {
                if (p + 2 > input.len) return ParseError.InvalidFormat;
                b.day = try parseUint(u32, input[p .. p + 2], ParseError.InvalidDate);
                p += 2;
            },
            .day_short => {
                const end = findNumberEnd(input, p, 2);
                b.day = try parseUint(u32, input[p..end], ParseError.InvalidDate);
                p = end;
            },
            .day_name_long, .day_name_short => {
                p += try parseDayName(input[p..]); // informational, not stored
            },
            .day_of_week => {
                const end = findNumberEnd(input, p, 1);
                if (end == p) return ParseError.InvalidFormat;
                const dow = try parseUint(u32, input[p..end], ParseError.InvalidDate);
                if (dow < 1 or dow > 7) return ParseError.InvalidDate;
                p = end;
                b.iso_dow = dow; // informational unless a week token is present
            },
            .fraction => |n| {
                b.nanosecond = try parseFraction(input, p, n);
                p += n;
            },
            .iso_year => {
                if (p + 4 > input.len) return ParseError.InvalidFormat;
                if (!isAllDigits(input[p .. p + 4])) return ParseError.InvalidDate;
                b.iso_year = try parseUint(i32, input[p .. p + 4], ParseError.InvalidDate);
                p += 4;
            },
            .iso_week_full => {
                if (p + 2 > input.len) return ParseError.InvalidFormat;
                b.iso_week = try parseUint(u32, input[p .. p + 2], ParseError.InvalidDate);
                p += 2;
            },
            .iso_week_short => {
                const end = findNumberEnd(input, p, 2);
                b.iso_week = try parseUint(u32, input[p..end], ParseError.InvalidDate);
                p = end;
            },
            .hour_24_full, .hour_12_full => {
                if (p + 2 > input.len) return ParseError.InvalidFormat;
                b.hour = try parseUint(u32, input[p .. p + 2], ParseError.InvalidTime);
                p += 2;
            },
            .hour_24_short, .hour_12_short => {
                const end = findNumberEnd(input, p, 2);
                b.hour = try parseUint(u32, input[p..end], ParseError.InvalidTime);
                p = end;
            },
            .minute_full => {
                if (p + 2 > input.len) return ParseError.InvalidFormat;
                b.minute = try parseUint(u32, input[p .. p + 2], ParseError.InvalidTime);
                p += 2;
            },
            .minute_short => {
                const end = findNumberEnd(input, p, 2);
                b.minute = try parseUint(u32, input[p..end], ParseError.InvalidTime);
                p = end;
            },
            .second_full => {
                if (p + 2 > input.len) return ParseError.InvalidFormat;
                b.second = try parseUint(u32, input[p .. p + 2], ParseError.InvalidTime);
                p += 2;
            },
            .second_short => {
                const end = findNumberEnd(input, p, 2);
                b.second = try parseUint(u32, input[p..end], ParseError.InvalidTime);
                p = end;
            },
            .ampm_upper, .ampm_lower => {
                if (p + 2 > input.len) return ParseError.InvalidFormat;
                const ap = input[p .. p + 2];
                if (std.ascii.eqlIgnoreCase(ap, "AM")) {
                    b.is_pm = false;
                } else if (std.ascii.eqlIgnoreCase(ap, "PM")) {
                    b.is_pm = true;
                } else return ParseError.InvalidTime;
                p += 2;
            },
            .tz_offset => {
                // Either a literal Z/z (= +00:00) or a signed ±HH[:]MM offset.
                if (input[p] == 'Z' or input[p] == 'z') {
                    b.off_min = 0;
                    p += 1;
                } else {
                    const sign: i32 = switch (input[p]) {
                        '+' => 1,
                        '-' => -1,
                        else => return ParseError.InvalidTime,
                    };
                    p += 1;
                    if (p + 2 > input.len) return ParseError.InvalidTime;
                    const oh = try parseUint(i32, input[p .. p + 2], ParseError.InvalidTime);
                    p += 2;
                    if (p < input.len and input[p] == ':') p += 1; // optional colon
                    if (p + 2 > input.len) return ParseError.InvalidTime;
                    const om = try parseUint(i32, input[p .. p + 2], ParseError.InvalidTime);
                    p += 2;
                    if (oh > 23 or om > 59) return ParseError.InvalidTime;
                    b.off_min = sign * (oh * 60 + om);
                }
            },
            .wildcard => {
                if (idx + 1 < toks.len) {
                    p = try skipUntilNextToken(input, p, toks[idx + 1]);
                } else {
                    p = input.len;
                }
            },
            .literal => |lit| {
                if (p + lit.len > input.len) return ParseError.InvalidFormat;
                if (!std.mem.eql(u8, input[p .. p + lit.len], lit)) return ParseError.InvalidFormat;
                p += lit.len;
            },
        }
    }

    // 12h → 24h.
    if (b.is_pm) |pm| {
        if (b.hour == 12) {
            if (!pm) b.hour = 0; // 12 AM = 00, 12 PM = 12
        } else if (pm) {
            b.hour += 12; // 1-11 PM = 13-23
        }
    }

    var result = DateParts{
        .year = b.year orelse 1970,
        .month = b.month orelse 1,
        .day = b.day orelse 1,
        .hour = b.hour,
        .minute = b.minute,
        .second = b.second,
        .nanosecond = b.nanosecond,
        .off_min = b.off_min,
    };
    // ISO week date: resolve to the civil date it names.
    if (b.iso_year != null or b.iso_week != null) {
        const ed = isoWeekDateToEpochDay(b.iso_year orelse result.year, b.iso_week orelse 1, b.iso_dow orelse 1) orelse
            return ParseError.InvalidDate;
        const ymd = epochDayToYmd(ed);
        result.year = ymd.year;
        result.month = ymd.month;
        result.day = ymd.day;
    }
    if (!validate(result)) {
        if (result.hour > 23 or result.minute > 59 or result.second > 59 or result.nanosecond > 999_999_999) return ParseError.InvalidTime;
        return ParseError.InvalidDate;
    }
    return result;
}

// ---------------------------------------------------------------------------
// Formatting: DateParts + format → string
// ---------------------------------------------------------------------------

/// Render `parts` according to `fmt`. The full token vocabulary is supported,
/// including derived tokens (weekday names/number) computed via the civil core.
pub fn format(alloc: std.mem.Allocator, parts: DateParts, fmt: []const u8) ![]u8 {
    var tk: Layout = undefined;
    tokenize(fmt, &tk) catch |err| switch (err) {
        error.TooManyTokens => return error.TooManyTokens,
        else => return error.InvalidFormatString,
    };
    return formatLayout(alloc, parts, &tk);
}

fn formatLayout(alloc: std.mem.Allocator, parts: DateParts, l: *const Layout) ![]u8 {
    // A negative year is only reachable from extreme date arithmetic across
    // year 0. `@intCast` of it into u32 is silent UB in ReleaseSmall (and a
    // panic in safe modes). Reject as InvalidDate — the same contract as
    // month 13 / Feb 30 — so the field yields "" rather than garbage.
    // (`year_short` uses `@mod` and is already safe for negatives.)
    if (parts.year < 0) return error.InvalidDate;

    // Render into a buffer sized by an upper bound, then allocate the result
    // once. The bound fits the stack for any ordinary format; only long
    // literals take a heap scratch buffer.
    var stack: [256]u8 = undefined;
    if (l.bound <= stack.len) {
        const n = try render(&stack, parts, l);
        return alloc.dupe(u8, stack[0..n]);
    }
    const scratch = try alloc.alloc(u8, l.bound);
    defer alloc.free(scratch);
    const n = try render(scratch, parts, l);
    return alloc.dupe(u8, scratch[0..n]);
}

/// Longest text one non-literal token renders: `ZZ` of the most extreme
/// `off_min` ("-35791394:08", 12), ahead of a u32 field (10) or a name (9).
const max_field_len = 12;

/// Render `l` into `out`, which holds at least `l.bound` bytes; returns the
/// length written.
fn render(out: []u8, parts: DateParts, l: *const Layout) error{ InvalidDate, InvalidTime }!usize {
    const dow = if (l.needs_dow) isoWeekday(ymdToEpochDay(parts.year, parts.month, parts.day)) else 0;
    const year_u: u32 = @intCast(parts.year); // format() refused a negative year
    var n: usize = 0;

    for (l.toks[0..l.n]) |token| {
        switch (token) {
            .year_full => n = putDec(out, n, year_u, 4),
            .year_short => n = putDec(out, n, @intCast(@mod(parts.year, 100)), 2),
            .month_full => n = putDec(out, n, parts.month, 2),
            .month_short => n = putDec(out, n, parts.month, 1),
            .month_name_short => n = put(out, n, shortMonthName(parts.month)),
            .month_name_long => n = put(out, n, fullMonthName(parts.month)),
            .day_full => n = putDec(out, n, parts.day, 2),
            .day_short => n = putDec(out, n, parts.day, 1),
            .day_name_long => n = put(out, n, fullDayName(dow)),
            .day_name_short => n = put(out, n, shortDayName(dow)),
            .day_of_week => n = putDec(out, n, dow, 1),
            .hour_24_full => n = putDec(out, n, parts.hour, 2),
            .hour_24_short => n = putDec(out, n, parts.hour, 1),
            .hour_12_full => n = putDec(out, n, to12Hour(parts.hour), 2),
            .hour_12_short => n = putDec(out, n, to12Hour(parts.hour), 1),
            .minute_full => n = putDec(out, n, parts.minute, 2),
            .minute_short => n = putDec(out, n, parts.minute, 1),
            .second_full => n = putDec(out, n, parts.second, 2),
            .second_short => n = putDec(out, n, parts.second, 1),
            .ampm_upper => n = put(out, n, if (parts.hour < 12) "AM" else "PM"),
            .ampm_lower => n = put(out, n, if (parts.hour < 12) "am" else "pm"),
            .tz_offset => {
                const om = parts.off_min orelse 0;
                const mag: u32 = @intCast(if (om < 0) -@as(i64, om) else om);
                out[n] = if (om < 0) '-' else '+';
                n = putDec(out, n + 1, mag / 60, 2);
                out[n] = ':';
                n = putDec(out, n + 1, mag % 60, 2);
            },
            .fraction => |digits| {
                if (parts.nanosecond > 999_999_999) return error.InvalidTime;
                n = switch (digits) { // truncates (never rounds) to the token's width
                    3 => putDec(out, n, parts.nanosecond / 1_000_000, 3),
                    6 => putDec(out, n, parts.nanosecond / 1_000, 6),
                    else => putDec(out, n, parts.nanosecond, 9),
                };
            },
            .iso_year => {
                const iy = isoWeek(parts).year;
                if (iy < 0) return error.InvalidDate; // same contract as YYYY
                n = putDec(out, n, @intCast(iy), 4);
            },
            .iso_week_full => n = putDec(out, n, isoWeek(parts).week, 2),
            .iso_week_short => n = putDec(out, n, isoWeek(parts).week, 1),
            .wildcard => {}, // nothing to emit on the format side
            .literal => |lit| n = put(out, n, lit),
        }
    }
    return n;
}

/// "00" "01" … "99" back to back.
const two_digits: [200]u8 = blk: {
    var t: [200]u8 = undefined;
    for (0..100) |i| {
        t[2 * i] = '0' + i / 10;
        t[2 * i + 1] = '0' + i % 10;
    }
    break :blk t;
};

fn put(out: []u8, n: usize, s: []const u8) usize {
    if (s.len == 1) { // the common separator literal; skips a memcpy call
        out[n] = s[0];
        return n + 1;
    }
    @memcpy(out[n..][0..s.len], s);
    return n + s.len;
}

/// `v` in decimal at `out[n..]`, zero-padded to at least `min_width` (≤ 10)
/// digits -- what `print("{d:0>N}")` produces, without the generic formatter.
fn putDec(out: []u8, n: usize, v: u32, comptime min_width: u8) usize {
    comptime std.debug.assert(min_width >= 1 and min_width <= 10);
    // Fast paths for the common field widths: fixed-size stores, no loop.
    if (min_width == 1 and v < 10) {
        out[n] = '0' + @as(u8, @intCast(v));
        return n + 1;
    }
    if (min_width <= 2 and v < 100) { // width 1 with v < 10 returned above
        out[n..][0..2].* = two_digits[v * 2 ..][0..2].*;
        return n + 2;
    }
    if (min_width == 4 and v < 10000) {
        out[n..][0..2].* = two_digits[(v / 100) * 2 ..][0..2].*;
        out[n + 2 ..][0..2].* = two_digits[(v % 100) * 2 ..][0..2].*;
        return n + 4;
    }
    var digits: [10]u8 = undefined;
    var i: usize = digits.len;
    var x = v;
    while (true) {
        i -= 1;
        digits[i] = '0' + @as(u8, @intCast(x % 10));
        x /= 10;
        if (x == 0) break;
    }
    while (digits.len - i < min_width) {
        i -= 1;
        digits[i] = '0';
    }
    return put(out, n, digits[i..]);
}

// ---------------------------------------------------------------------------
// Calendar arithmetic (pre-1970 safe — operates on civil days, never u64)
// ---------------------------------------------------------------------------

/// Add `n` calendar days, preserving the time of day (incl. the fraction).
pub fn addDays(parts: DateParts, n: i64) DateParts {
    var r = epochDayToYmd(ymdToEpochDay(parts.year, parts.month, parts.day) + n);
    r.hour = parts.hour;
    r.minute = parts.minute;
    r.second = parts.second;
    r.nanosecond = parts.nanosecond;
    return r;
}

/// Add `n` months, clamping the day to the new month's length
/// (Jan 31 + 1 month → Feb 28/29). Preserves the time of day.
pub fn addMonths(parts: DateParts, n: i32) DateParts {
    const total = @as(i32, @intCast(parts.month)) - 1 + n;
    const new_year = parts.year + @divFloor(total, 12);
    const new_month: u32 = @intCast(@mod(total, 12) + 1);
    const clamped_day = @min(parts.day, daysInMonth(new_year, new_month));
    return .{
        .year = new_year,
        .month = new_month,
        .day = clamped_day,
        .hour = parts.hour,
        .minute = parts.minute,
        .second = parts.second,
        .nanosecond = parts.nanosecond,
    };
}

pub fn addYears(parts: DateParts, n: i32) DateParts {
    return addMonths(parts, n * 12);
}

/// Whole calendar days from `b` to `a` (positive when `a` is later).
pub fn diffInDays(a: DateParts, b: DateParts) i64 {
    return ymdToEpochDay(a.year, a.month, a.day) - ymdToEpochDay(b.year, b.month, b.day);
}

/// Whole calendar months from `b` to `a` (ignores day-of-month).
pub fn diffInMonths(a: DateParts, b: DateParts) i32 {
    return (a.year * 12 + @as(i32, @intCast(a.month))) -
        (b.year * 12 + @as(i32, @intCast(b.month)));
}

pub fn diffInYears(a: DateParts, b: DateParts) i32 {
    return a.year - b.year;
}

pub fn startOfDay(parts: DateParts) DateParts {
    return .{ .year = parts.year, .month = parts.month, .day = parts.day };
}
pub fn endOfDay(parts: DateParts) DateParts {
    return .{ .year = parts.year, .month = parts.month, .day = parts.day, .hour = 23, .minute = 59, .second = 59 };
}
pub fn startOfMonth(parts: DateParts) DateParts {
    return .{ .year = parts.year, .month = parts.month, .day = 1 };
}
pub fn endOfMonth(parts: DateParts) DateParts {
    return .{ .year = parts.year, .month = parts.month, .day = daysInMonth(parts.year, parts.month), .hour = 23, .minute = 59, .second = 59 };
}
/// Date of the `n`-th occurrence of ISO weekday `weekday` (Mon=1 … Sun=7) in
/// `year`/`month`. Positive `n` counts from the start (`1` = first); negative
/// `n` counts from the end (`-1` = last, `-2` = second-to-last). Returns null
/// when any argument is out of range or the occurrence doesn't exist (e.g. a
/// 5th Friday in a month that has only four).
///
/// This is the calendar primitive behind DST-boundary math: EU summer time
/// runs from the **last Sunday of March** to the **last Sunday of October** —
/// `nthWeekdayOfMonth(y, 3, 7, -1)` and `(y, 10, 7, -1)`.
pub fn nthWeekdayOfMonth(year: i32, month: i32, weekday: i32, n: i32) ?DateParts {
    if (month < 1 or month > 12) return null;
    if (weekday < 1 or weekday > 7) return null;
    if (n == 0) return null;
    const m: u32 = @intCast(month);
    const dim: i32 = @intCast(daysInMonth(year, m));

    const day: i32 = if (n > 0) blk: {
        const first_dow: i32 = @intCast(isoWeekday(ymdToEpochDay(year, m, 1)));
        const offset = @mod(weekday - first_dow, 7); // 0..6 to first match
        break :blk 1 + offset + (n - 1) * 7;
    } else blk: {
        const last_dow: i32 = @intCast(isoWeekday(ymdToEpochDay(year, m, @intCast(dim))));
        const offset = @mod(last_dow - weekday, 7); // 0..6 back to last match
        break :blk dim - offset + (n + 1) * 7;
    };

    if (day < 1 or day > dim) return null;
    return .{ .year = year, .month = m, .day = @intCast(day) };
}

pub fn startOfYear(parts: DateParts) DateParts {
    return .{ .year = parts.year, .month = 1, .day = 1 };
}
pub fn endOfYear(parts: DateParts) DateParts {
    return .{ .year = parts.year, .month = 12, .day = 31, .hour = 23, .minute = 59, .second = 59 };
}

// ---------------------------------------------------------------------------
// Strict ISO helpers
// ---------------------------------------------------------------------------

/// Parse a strict canonical `YYYY-MM-DD` date (time defaults to 00:00:00).
/// Stricter than `parse` — for callers that already have normalised ISO
/// input and want a fast, unambiguous read.
pub fn parseIsoDate(s: []const u8) ParseError!DateParts {
    if (s.len != 10 or s[4] != '-' or s[7] != '-') return ParseError.InvalidDate;
    const y = parseUint(i32, s[0..4], ParseError.InvalidDate) catch return ParseError.InvalidDate;
    const m = parseUint(u32, s[5..7], ParseError.InvalidDate) catch return ParseError.InvalidDate;
    const d = parseUint(u32, s[8..10], ParseError.InvalidDate) catch return ParseError.InvalidDate;
    // The day must exist in THAT month: `d > 31` let `2023-02-30` through as
    // a "strict" date, which every later `ymdToEpochDay` silently rolled into
    // March (audit 2026-10-04; `parseXsdDateTimeNs` had the same bug fixed).
    if (m < 1 or m > 12 or d < 1 or d > daysInMonth(y, m)) return ParseError.InvalidDate;
    return .{ .year = y, .month = m, .day = d };
}

/// Render a date as canonical `YYYY-MM-DD`.
pub fn formatIsoDate(alloc: std.mem.Allocator, parts: DateParts) ![]const u8 {
    // See `format` above: reject negative years (UB on `@intCast` to u32 in
    // ReleaseSmall) as InvalidDate rather than emit garbage.
    if (parts.year < 0) return error.InvalidDate;
    const y_u: u32 = @intCast(parts.year);
    return alloc.print("{d:0>4}-{d:0>2}-{d:0>2}", .{ y_u, parts.month, parts.day });
}

// ---------------------------------------------------------------------------
// Canned formats: RFC 3339 and the HTTP date (IMF-fixdate)
// ---------------------------------------------------------------------------
//
// Fixed-shape writers with no format string to read and, in the `buf*` form,
// no allocator: what an HTTP server or a log line needs on every request (qap
// `access.zig` and `http` `Server.zig` hand-rolled both before these existed).
// Unlike `format`, they validate: a field out of range or a year outside
// 0000..9999 (four digits is all either grammar can say) is an error, never
// garbage in a header.

/// Longest `bufRfc3339` output: `YYYY-MM-DDThh:mm:ss.nnnnnnnnn+hh:mm`.
pub const rfc3339_max_len = 35;

/// `parts` as RFC 3339 (`YYYY-MM-DDThh:mm:ss[.f…](Z|±hh:mm)`) into `buf`;
/// returns the written prefix. `frac_digits` (0..9) fraction digits are
/// written, truncated (0 = none: Go's `time.RFC3339`; 9 = always nine, unlike
/// Go's `RFC3339Nano`, which trims trailing zeros). The offset is
/// `parts.off_min`: null or 0 is `Z`, anything else `±hh:mm`, as in Go.
/// `InvalidDate`: a date out of range or a year outside 0..9999.
/// `InvalidTime`: a time out of range, an offset of a day or more, or
/// `frac_digits` > 9.
pub fn bufRfc3339(buf: *[rfc3339_max_len]u8, parts: DateParts, frac_digits: u8) error{ InvalidDate, InvalidTime }![]u8 {
    try checkCanned(parts);
    if (frac_digits > 9) return error.InvalidTime;
    const om: i32 = parts.off_min orelse 0;
    if (om <= -24 * 60 or om >= 24 * 60) return error.InvalidTime;

    var n = putDec(buf, 0, @intCast(parts.year), 4);
    buf[n] = '-';
    n = putDec(buf, n + 1, parts.month, 2);
    buf[n] = '-';
    n = putDec(buf, n + 1, parts.day, 2);
    buf[n] = 'T';
    n = putDec(buf, n + 1, parts.hour, 2);
    buf[n] = ':';
    n = putDec(buf, n + 1, parts.minute, 2);
    buf[n] = ':';
    n = putDec(buf, n + 1, parts.second, 2);
    if (frac_digits > 0) {
        var digits: [9]u8 = undefined;
        _ = putDec(&digits, 0, parts.nanosecond, 9);
        buf[n] = '.';
        @memcpy(buf[n + 1 ..][0..frac_digits], digits[0..frac_digits]);
        n += 1 + frac_digits;
    }
    if (om == 0) {
        buf[n] = 'Z';
        return buf[0 .. n + 1];
    }
    const mag: u32 = @intCast(@abs(om));
    buf[n] = if (om < 0) '-' else '+';
    n = putDec(buf, n + 1, mag / 60, 2);
    buf[n] = ':';
    n = putDec(buf, n + 1, mag % 60, 2);
    return buf[0..n];
}

/// `bufRfc3339` into a new allocation (caller frees).
pub fn formatRfc3339(alloc: std.mem.Allocator, parts: DateParts, frac_digits: u8) ![]u8 {
    var buf: [rfc3339_max_len]u8 = undefined;
    return alloc.dupe(u8, try bufRfc3339(&buf, parts, frac_digits));
}

/// Parse RFC 3339 `YYYY-MM-DD(T|t)hh:mm:ss[.f…](Z|z|±hh:mm)` into wall-clock
/// `DateParts` with `off_min` set (0 for `Z`) -- the parse→format reshuffle
/// keeps the offset, where `parseXsdDateTimeNs` folds it into a Unix instant.
/// Stricter than `parseXsdDateTimeNs`, as RFC 3339 is: the offset is
/// required. Any number (≥ 1) of fraction digits; the first 9 are kept, the
/// rest truncated. A leap second (`:60`) is `InvalidTime`, as in Go's
/// `time.Parse` -- `DateParts` cannot hold it. The whole input must match.
pub fn parseRfc3339(s: []const u8) ParseError!DateParts {
    if (s.len < 20) return ParseError.InvalidFormat; // "YYYY-MM-DDThh:mm:ssZ"
    if (s[4] != '-' or s[7] != '-' or (s[10] != 'T' and s[10] != 't') or s[13] != ':' or s[16] != ':')
        return ParseError.InvalidFormat;
    var p = DateParts{
        .year = try parseUint(i32, s[0..4], ParseError.InvalidDate),
        .month = try parseUint(u32, s[5..7], ParseError.InvalidDate),
        .day = try parseUint(u32, s[8..10], ParseError.InvalidDate),
        .hour = try parseUint(u32, s[11..13], ParseError.InvalidTime),
        .minute = try parseUint(u32, s[14..16], ParseError.InvalidTime),
        .second = try parseUint(u32, s[17..19], ParseError.InvalidTime),
    };
    var i: usize = 19;
    if (s[i] == '.') {
        i += 1;
        const start = i;
        var scale: u32 = 100_000_000; // weight of the next digit
        while (i < s.len and s[i] >= '0' and s[i] <= '9') : (i += 1) {
            p.nanosecond += @as(u32, s[i] - '0') * scale;
            scale /= 10;
        }
        if (i == start) return ParseError.InvalidFormat;
    }
    if (i >= s.len) return ParseError.InvalidFormat; // the offset is required
    switch (s[i]) {
        'Z', 'z' => {
            p.off_min = 0;
            i += 1;
        },
        '+', '-' => {
            if (i + 6 > s.len or s[i + 3] != ':') return ParseError.InvalidFormat;
            const oh = try parseUint(i32, s[i + 1 .. i + 3], ParseError.InvalidTime);
            const om = try parseUint(i32, s[i + 4 .. i + 6], ParseError.InvalidTime);
            if (oh > 23 or om > 59) return ParseError.InvalidTime;
            p.off_min = if (s[i] == '-') -(oh * 60 + om) else oh * 60 + om;
            i += 6;
        },
        else => return ParseError.InvalidFormat,
    }
    if (i != s.len) return ParseError.InvalidFormat;
    try checkParsed(p);
    return p;
}

/// Length of an IMF-fixdate (RFC 9110 §5.6.7): `Sun, 06 Nov 1994 08:49:37 GMT`.
pub const imf_fixdate_len = 29;

/// `parts` (UTC; `off_min` is ignored -- the format is always GMT) as the
/// HTTP date `EEE, DD MMM YYYY hh:mm:ss GMT` into `buf`. Errors as `bufRfc3339`.
pub fn bufImfFixdate(buf: *[imf_fixdate_len]u8, parts: DateParts) error{ InvalidDate, InvalidTime }!void {
    try checkCanned(parts);
    const dow = isoWeekday(ymdToEpochDay(parts.year, parts.month, parts.day));
    buf[0..3].* = short_day_names[dow - 1][0..3].*;
    buf[3..5].* = ", ".*;
    _ = putDec(buf, 5, parts.day, 2);
    buf[7] = ' ';
    buf[8..11].* = short_month_names[parts.month - 1][0..3].*;
    buf[11] = ' ';
    _ = putDec(buf, 12, @intCast(parts.year), 4);
    buf[16] = ' ';
    _ = putDec(buf, 17, parts.hour, 2);
    buf[19] = ':';
    _ = putDec(buf, 20, parts.minute, 2);
    buf[22] = ':';
    _ = putDec(buf, 23, parts.second, 2);
    buf[25..29].* = " GMT".*;
}

/// `bufImfFixdate` into a new allocation (caller frees).
pub fn formatImfFixdate(alloc: std.mem.Allocator, parts: DateParts) ![]u8 {
    var buf: [imf_fixdate_len]u8 = undefined;
    try bufImfFixdate(&buf, parts);
    return alloc.dupe(u8, &buf);
}

/// Parse an IMF-fixdate exactly (`Sun, 06 Nov 1994 08:49:37 GMT`, names in
/// that case, `GMT` literal) into UTC `DateParts` (`off_min` 0). The day name
/// must be the date's real weekday. RFC 9110's obsolete forms (RFC 850,
/// asctime) are not accepted; a recipient that must take them parses with
/// `parse` and their format strings.
pub fn parseImfFixdate(s: []const u8) ParseError!DateParts {
    if (s.len != imf_fixdate_len) return ParseError.InvalidFormat;
    if (!std.mem.eql(u8, s[3..5], ", ") or s[7] != ' ' or s[11] != ' ' or s[16] != ' ' or
        s[19] != ':' or s[22] != ':' or !std.mem.eql(u8, s[25..29], " GMT")) return ParseError.InvalidFormat;
    const month: u32 = for (short_month_names, 1..) |name, m| {
        if (std.mem.eql(u8, s[8..11], name)) break @intCast(m);
    } else return ParseError.InvalidDate;
    const p = DateParts{
        .year = try parseUint(i32, s[12..16], ParseError.InvalidDate),
        .month = month,
        .day = try parseUint(u32, s[5..7], ParseError.InvalidDate),
        .hour = try parseUint(u32, s[17..19], ParseError.InvalidTime),
        .minute = try parseUint(u32, s[20..22], ParseError.InvalidTime),
        .second = try parseUint(u32, s[23..25], ParseError.InvalidTime),
        .off_min = 0,
    };
    try checkParsed(p);
    const dow = isoWeekday(ymdToEpochDay(p.year, p.month, p.day));
    if (!std.mem.eql(u8, s[0..3], short_day_names[dow - 1])) return ParseError.InvalidDate;
    return p;
}

// ---------------------------------------------------------------------------
// Canned format: the Internet Message Format date (RFC 5322 §3.3, ex-2822)
// ---------------------------------------------------------------------------

/// Length of a `bufRfc2822` date: `Fri, 21 Nov 1997 09:55:06 -0600`.
pub const rfc2822_len = 31;

/// `parts` as an RFC 5322 date-time, `EEE, DD MMM YYYY hh:mm:ss ±hhmm` (Go's
/// `time.RFC1123Z`, chrono's `to_rfc2822`). The zone is `parts.off_min`; null
/// is written `+0000`, as `bufRfc3339` writes `Z`. Errors as `bufRfc3339`.
pub fn bufRfc2822(buf: *[rfc2822_len]u8, parts: DateParts) error{ InvalidDate, InvalidTime }!void {
    try checkCanned(parts);
    const om: i32 = parts.off_min orelse 0;
    if (om <= -24 * 60 or om >= 24 * 60) return error.InvalidTime;
    const dow = isoWeekday(ymdToEpochDay(parts.year, parts.month, parts.day));
    buf[0..3].* = short_day_names[dow - 1][0..3].*;
    buf[3..5].* = ", ".*;
    _ = putDec(buf, 5, parts.day, 2);
    buf[7] = ' ';
    buf[8..11].* = short_month_names[parts.month - 1][0..3].*;
    buf[11] = ' ';
    _ = putDec(buf, 12, @intCast(parts.year), 4);
    buf[16] = ' ';
    _ = putDec(buf, 17, parts.hour, 2);
    buf[19] = ':';
    _ = putDec(buf, 20, parts.minute, 2);
    buf[22] = ':';
    _ = putDec(buf, 23, parts.second, 2);
    buf[25] = ' ';
    buf[26] = if (om < 0) '-' else '+';
    const mag: u32 = @intCast(@abs(om));
    _ = putDec(buf, 27, mag / 60, 2);
    _ = putDec(buf, 29, mag % 60, 2);
}

/// `bufRfc2822` into a new allocation (caller frees).
pub fn formatRfc2822(alloc: std.mem.Allocator, parts: DateParts) ![]u8 {
    var buf: [rfc2822_len]u8 = undefined;
    try bufRfc2822(&buf, parts);
    return alloc.dupe(u8, &buf);
}

/// Parse an RFC 5322 date-time (the `Date:` header of mail; RFC 2822/822
/// before it) into wall-clock `DateParts` with `off_min` set; `toUtc` gives
/// the instant. The whole input must match the grammar, obsolete forms of
/// §4.3 included:
///   - optional day name and `,`; when present it must be the date's real
///     weekday (`InvalidDate`), as chrono checks -- Go and Python ignore it;
///   - day 1-2 digits; month name and day name in any case;
///   - year 4 digits, or the obsolete 2 digits (00-49 → 20xx, 50-99 → 19xx)
///     or 3 digits (+1900) -- RFC 5322 §4.3; Go and Python put 50-68 in 20xx;
///   - `hh:mm` with optional `:ss`; a leap second (`:60`) is `InvalidTime`;
///   - zone `±hhmm` (under 24 h, minutes under 60, else `InvalidTime`), or an
///     obsolete name: `UT`/`GMT` = 0, `EST`/`EDT`/`CST`/`CDT`/`MST`/`MDT`/
///     `PST`/`PDT` = their US offsets, a military letter = 0 (§4.3: "SHOULD
///     all be considered equivalent to -0000"). `-0000` ("no zone
///     information") reads as 0 too: `DateParts` cannot say "unknown";
///   - CFWS -- spaces, tabs, folding (CRLF + space/tab) and nested `( … )`
///     comments with `\` quoted pairs -- wherever the obsolete grammar allows
///     it, around `:` too. Trailing text that is not CFWS is `InvalidFormat`
///     (Go and Python ignore it).
pub fn parseRfc2822(s: []const u8) ParseError!DateParts {
    var c: Cfws = .{ .s = s };
    _ = try c.skip();
    var dow: ?u32 = null;
    if (c.i < s.len and std.ascii.isAlphabetic(s[c.i])) {
        dow = try c.name(&short_day_names);
        _ = try c.skip();
        if (!c.eat(',')) return ParseError.InvalidFormat;
        _ = try c.skip();
    }
    const day_digits = c.digits();
    if (day_digits.len < 1 or day_digits.len > 2) return ParseError.InvalidFormat;
    if (!try c.skip()) return ParseError.InvalidFormat;
    const month = try c.name(&short_month_names);
    if (!try c.skip()) return ParseError.InvalidFormat;
    const year_digits = c.digits();
    if (year_digits.len < 2) return ParseError.InvalidFormat;
    // DateParts holds more than 4 digits, the canned writers do not.
    if (year_digits.len > 4) return ParseError.InvalidDate;
    var year = try parseUint(i32, year_digits, ParseError.InvalidFormat);
    switch (year_digits.len) {
        2 => year += if (year < 50) 2000 else 1900,
        3 => year += 1900,
        else => {},
    }
    if (!try c.skip()) return ParseError.InvalidFormat;
    var p = DateParts{
        .year = year,
        .month = month,
        .day = try parseUint(u32, day_digits, ParseError.InvalidFormat),
        .hour = try c.twoDigits(),
    };
    _ = try c.skip();
    if (!c.eat(':')) return ParseError.InvalidFormat;
    _ = try c.skip();
    p.minute = try c.twoDigits();
    _ = try c.skip();
    if (c.eat(':')) {
        _ = try c.skip();
        p.second = try c.twoDigits();
        _ = try c.skip();
    }
    p.off_min = try c.zone();
    _ = try c.skip();
    if (c.i != s.len) return ParseError.InvalidFormat;
    try checkParsed(p);
    if (dow) |d| if (d != isoWeekday(ymdToEpochDay(p.year, p.month, p.day))) return ParseError.InvalidDate;
    return p;
}

/// A cursor over RFC 5322 text that steps over CFWS (§3.2.2): white space,
/// folding and comments. Every reader leaves the cursor after what it read.
const Cfws = struct {
    s: []const u8,
    i: usize = 0,

    /// Skip CFWS; true when anything was skipped. An unclosed comment, or a
    /// CR not followed by LF and a space or tab, is `InvalidFormat`.
    fn skip(c: *Cfws) ParseError!bool {
        const start = c.i;
        while (c.i < c.s.len) {
            switch (c.s[c.i]) {
                ' ', '\t' => c.i += 1,
                '\r' => {
                    if (c.i + 2 >= c.s.len or c.s[c.i + 1] != '\n' or (c.s[c.i + 2] != ' ' and c.s[c.i + 2] != '\t'))
                        return ParseError.InvalidFormat;
                    c.i += 3;
                },
                '(' => {
                    // Nesting by a counter, not recursion: the depth is the
                    // sender's to choose.
                    var depth: usize = 0;
                    while (c.i < c.s.len) : (c.i += 1) {
                        switch (c.s[c.i]) {
                            '(' => depth += 1,
                            ')' => {
                                depth -= 1;
                                if (depth == 0) break;
                            },
                            '\\' => c.i += 1, // quoted-pair: the next byte is literal
                            else => {},
                        }
                    }
                    if (c.i >= c.s.len) return ParseError.InvalidFormat;
                    c.i += 1;
                },
                else => break,
            }
        }
        return c.i != start;
    }

    fn eat(c: *Cfws, ch: u8) bool {
        if (c.i < c.s.len and c.s[c.i] == ch) {
            c.i += 1;
            return true;
        }
        return false;
    }

    /// The run of ASCII digits at the cursor (maybe empty).
    fn digits(c: *Cfws) []const u8 {
        const start = c.i;
        while (c.i < c.s.len and std.ascii.isDigit(c.s[c.i])) c.i += 1;
        return c.s[start..c.i];
    }

    /// Exactly two digits (an hour, minute or second).
    fn twoDigits(c: *Cfws) ParseError!u32 {
        const d = c.digits();
        if (d.len != 2) return ParseError.InvalidFormat;
        return parseUint(u32, d, ParseError.InvalidFormat);
    }

    /// The run of letters at the cursor as a 1-based index into `names`,
    /// compared without case.
    fn name(c: *Cfws, names: []const []const u8) ParseError!u32 {
        const start = c.i;
        while (c.i < c.s.len and std.ascii.isAlphabetic(c.s[c.i])) c.i += 1;
        for (names, 1..) |n, k| {
            if (std.ascii.eqlIgnoreCase(c.s[start..c.i], n)) return @intCast(k);
        }
        return ParseError.InvalidFormat;
    }

    /// `±hhmm` or an obsolete zone name, as minutes east of UTC.
    fn zone(c: *Cfws) ParseError!i32 {
        if (c.i >= c.s.len) return ParseError.InvalidFormat;
        const sign = c.s[c.i];
        if (sign == '+' or sign == '-') {
            c.i += 1;
            const d = c.digits();
            if (d.len != 4) return ParseError.InvalidFormat;
            const oh = try parseUint(i32, d[0..2], ParseError.InvalidFormat);
            const om = try parseUint(i32, d[2..4], ParseError.InvalidFormat);
            if (oh > 23 or om > 59) return ParseError.InvalidTime;
            return if (sign == '-') -(oh * 60 + om) else oh * 60 + om;
        }
        const start = c.i;
        while (c.i < c.s.len and std.ascii.isAlphabetic(c.s[c.i])) c.i += 1;
        const z = c.s[start..c.i];
        if (z.len == 1) {
            // Military zones, all but J (§4.3): treated as -0000.
            return if (std.ascii.toLower(z[0]) == 'j') ParseError.InvalidFormat else 0;
        }
        for (obs_zones) |o| {
            if (std.ascii.eqlIgnoreCase(z, o.name)) return o.off_min;
        }
        return ParseError.InvalidFormat;
    }
};

/// RFC 5322 §4.3 obs-zone names with their offsets.
const obs_zones = [_]struct { name: []const u8, off_min: i32 }{
    .{ .name = "UT", .off_min = 0 },
    .{ .name = "GMT", .off_min = 0 },
    .{ .name = "EST", .off_min = -5 * 60 },
    .{ .name = "EDT", .off_min = -4 * 60 },
    .{ .name = "CST", .off_min = -6 * 60 },
    .{ .name = "CDT", .off_min = -5 * 60 },
    .{ .name = "MST", .off_min = -7 * 60 },
    .{ .name = "MDT", .off_min = -6 * 60 },
    .{ .name = "PST", .off_min = -8 * 60 },
    .{ .name = "PDT", .off_min = -7 * 60 },
};

// ---------------------------------------------------------------------------
// Durations: Go's `time.ParseDuration` / `Duration.String` text
// ---------------------------------------------------------------------------
//
// A duration is plain `i64` nanoseconds -- what `std.Io.Duration` and Go's
// `time.Duration` hold -- so there is no wrapper type to convert. The text is
// Go's: `1h2m3.5s`, `300ms`, `-1.5h`, the shape config files and CLIs took
// from Go. Checked against Go 1.26.0 by `tools/go_time_oracle`.

/// Room for any `bufDuration` text; the longest, `-2562047h47m16.854775808s`,
/// is 25 bytes. 32 as Go's buffer.
pub const duration_max_len = 32;

/// `ns` as Go's `Duration.String`: `0s`; under a second in the largest of
/// `ns`/`µs`/`ms` with a trimmed fraction (`1.5µs`, U+00B5); otherwise
/// `[h]h[m]m s.fff…s` with leading zero units dropped (`1h0m0s`, `2m3.5s`).
/// Returns the written suffix of `buf`.
pub fn bufDuration(buf: *[duration_max_len]u8, ns: i64) []u8 {
    var w: usize = buf.len;
    var u: u64 = @abs(ns);
    if (u < std.time.ns_per_s) {
        if (u == 0) {
            buf[w - 2 ..][0..2].* = "0s".*;
            return buf[w - 2 ..];
        }
        var unit: []const u8 = "ns";
        var prec: u8 = 0;
        if (u >= std.time.ns_per_ms) {
            unit = "ms";
            prec = 6;
        } else if (u >= std.time.ns_per_us) {
            unit = "\u{b5}s";
            prec = 3;
        }
        w -= unit.len;
        @memcpy(buf[w..][0..unit.len], unit);
        w = putFrac(buf, w, &u, prec);
        w = putIntLeft(buf, w, u);
    } else {
        w -= 1;
        buf[w] = 's';
        w = putFrac(buf, w, &u, 9);
        w = putIntLeft(buf, w, u % 60);
        u /= 60;
        if (u > 0) {
            w -= 1;
            buf[w] = 'm';
            w = putIntLeft(buf, w, u % 60);
            u /= 60;
            if (u > 0) {
                w -= 1;
                buf[w] = 'h';
                w = putIntLeft(buf, w, u);
            }
        }
    }
    if (ns < 0) {
        w -= 1;
        buf[w] = '-';
    }
    return buf[w..];
}

/// `bufDuration` into a new allocation (caller frees).
pub fn formatDuration(alloc: std.mem.Allocator, ns: i64) ![]u8 {
    var buf: [duration_max_len]u8 = undefined;
    return alloc.dupe(u8, bufDuration(&buf, ns));
}

/// The low `prec` decimal digits of `u.*` as `.ddd` ending before `buf[w]`,
/// trailing zeros dropped (nothing at all when every digit is 0); `u.*` keeps
/// the rest. Returns the new start.
fn putFrac(buf: []u8, w_end: usize, u: *u64, prec: u8) usize {
    var w = w_end;
    var printing = false;
    for (0..prec) |_| {
        const digit: u8 = @intCast(u.* % 10);
        printing = printing or digit != 0;
        if (printing) {
            w -= 1;
            buf[w] = '0' + digit;
        }
        u.* /= 10;
    }
    if (printing) {
        w -= 1;
        buf[w] = '.';
    }
    return w;
}

/// `v` in decimal ending before `buf[w]`; returns the new start.
fn putIntLeft(buf: []u8, w_end: usize, v: u64) usize {
    var w = w_end;
    var x = v;
    while (true) {
        w -= 1;
        buf[w] = '0' + @as(u8, @intCast(x % 10));
        x /= 10;
        if (x == 0) return w;
    }
}

/// Parse Go's duration text: an optional sign, then one or more
/// `<decimal><unit>` with units `ns`, `us`, `µs` (U+00B5), `μs` (U+03BC),
/// `ms`, `s`, `m`, `h` (`1h30m`, `1.5s`, `.5ms`, `-2m3s`); a bare `0` is 0.
/// Exactly Go's `time.ParseDuration`: a fraction is scaled through `f64` as
/// Go does (so `0.3333333333h` gives Go's nanosecond, not the nearest one),
/// fraction digits past `u63` precision are ignored, and anything outside
/// `i64` is an error (`-2562047h47m16.854775808s`, the minimum, is not).
pub fn parseDuration(s: []const u8) error{InvalidDuration}!i64 {
    const limit: u64 = 1 << 63; // the magnitude of minInt(i64)
    var rest = s;
    var neg = false;
    if (rest.len != 0 and (rest[0] == '-' or rest[0] == '+')) {
        neg = rest[0] == '-';
        rest = rest[1..];
    }
    if (std.mem.eql(u8, rest, "0")) return 0;
    if (rest.len == 0) return error.InvalidDuration;
    var total: u64 = 0;
    while (rest.len != 0) {
        if (rest[0] != '.' and !std.ascii.isDigit(rest[0])) return error.InvalidDuration;
        // The integer part: an overflow is an error.
        var v: u64 = 0;
        var i: usize = 0;
        while (i < rest.len and std.ascii.isDigit(rest[i])) : (i += 1) {
            if (v > limit / 10) return error.InvalidDuration;
            v = v * 10 + (rest[i] - '0');
            if (v > limit) return error.InvalidDuration;
        }
        const had_int = i != 0;
        rest = rest[i..];
        // The fraction: digits past what u63 holds stop counting, no error.
        var f: u64 = 0;
        var scale: f64 = 1;
        var had_frac = false;
        if (rest.len != 0 and rest[0] == '.') {
            rest = rest[1..];
            i = 0;
            var full = false;
            while (i < rest.len and std.ascii.isDigit(rest[i])) : (i += 1) {
                if (full) continue;
                if (f > (limit - 1) / 10) {
                    full = true;
                    continue;
                }
                const y = f * 10 + (rest[i] - '0');
                if (y > limit) {
                    full = true;
                    continue;
                }
                f = y;
                scale *= 10;
            }
            had_frac = i != 0;
            rest = rest[i..];
        }
        if (!had_int and !had_frac) return error.InvalidDuration;
        i = 0;
        while (i < rest.len and rest[i] != '.' and !std.ascii.isDigit(rest[i])) i += 1;
        if (i == 0) return error.InvalidDuration; // no unit
        const unit = durationUnit(rest[0..i]) orelse return error.InvalidDuration;
        rest = rest[i..];
        if (v > limit / unit) return error.InvalidDuration;
        v *= unit;
        if (f > 0) {
            // Go's arithmetic, in Go's order: f * (unit / scale), truncated.
            v += @intFromFloat(@as(f64, @floatFromInt(f)) * (@as(f64, @floatFromInt(unit)) / scale));
            if (v > limit) return error.InvalidDuration;
        }
        // Checked: two 2^63 terms wrap Go's uint64 to 0 and pass; here an error.
        total = std.math.add(u64, total, v) catch return error.InvalidDuration;
        if (total > limit) return error.InvalidDuration;
    }
    if (neg) return @bitCast(0 -% total);
    if (total > limit - 1) return error.InvalidDuration;
    return @intCast(total);
}

fn durationUnit(u: []const u8) ?u64 {
    const units = [_]struct { []const u8, u64 }{
        .{ "ns", 1 },
        .{ "us", std.time.ns_per_us },
        .{ "\u{b5}s", std.time.ns_per_us },
        .{ "\u{3bc}s", std.time.ns_per_us },
        .{ "ms", std.time.ns_per_ms },
        .{ "s", std.time.ns_per_s },
        .{ "m", std.time.ns_per_min },
        .{ "h", std.time.ns_per_hour },
    };
    for (units) |e| if (std.mem.eql(u8, u, e[0])) return e[1];
    return null;
}

/// The range check the canned writers share: a valid date and time, year
/// 0000..9999 (four digits).
fn checkCanned(p: DateParts) error{ InvalidDate, InvalidTime }!void {
    if (p.hour > 23 or p.minute > 59 or p.second > 59 or p.nanosecond > 999_999_999) return error.InvalidTime;
    if (p.year < 0 or p.year > 9999 or !validate(p)) return error.InvalidDate;
}

/// `validate` with `parse`'s error split.
fn checkParsed(p: DateParts) ParseError!void {
    if (p.hour > 23 or p.minute > 59 or p.second > 59) return ParseError.InvalidTime;
    if (!validate(p)) return ParseError.InvalidDate;
}

/// Parse an `xsd:dateTime` (SAML/XML-Schema) timestamp to Unix seconds:
/// `YYYY-MM-DDThh:mm:ss(.frac)?(Z|±hh:mm)?`. Fractional seconds (any number
/// of digits, ≥ 1) are accepted and dropped — this returns whole seconds; use
/// `parseXsdDateTimeNs` to keep the fraction. A missing timezone is treated as
/// UTC.
///
/// This is deliberately a SEPARATE entry point from `parse`, not a `fmt`
/// string fed through it — `xsd:dateTime` and generic ISO-8601 are not the
/// same grammar and a single token-based function cannot honestly serve both:
///   - the timezone offset here REQUIRES the `:` (`+02:00`, never `+0200`),
///     which `parse`'s `ZZ` token deliberately accepts either way;
///   - the fraction has a variable digit count and is optional, which the
///     fixed-width `SSS`/`SSSSSS`/`SSSSSSSSS` tokens of `parse` cannot say
///     (a format string has no way to say "optionally `.ddd`, then optionally
///     a zone");
///   - `parse` has no end-of-input check — trailing garbage after the last
///     token is silently ignored. This parser requires the whole string to be
///     consumed;
///   - a leap second (`:60`) is accepted here (`xsd:dateTime` allows it);
///     `parse`'s range validation caps seconds at 59.
/// Loosening any of the above to reuse `parse` directly would make this
/// function wrong for its one caller (SAML assertion validity windows).
///
/// The day-in-month / leap-year rules ARE shared with `parse` (`daysInMonth`,
/// `ymdToEpochDay`) — this used to be a hand-duplicated copy in `saml` that
/// had drifted: it normalised `2024-02-31` to `2024-03-02` instead of
/// rejecting it, silently extending a `NotOnOrAfter` validity window by up to
/// three days. Sharing the civil core here is what keeps that class of bug
/// from recurring.
///
/// The narrow `error{InvalidDateTime}` return (rather than the wider
/// `ParseError`) is intentional: Zig's error-set coercion widens it into any
/// caller's own error set automatically, so `saml` (and any future xsd:dateTime
/// consumer) can `try` this directly into its own typed errors without an
/// explicit conversion at every call site.
pub fn parseXsdDateTime(s: []const u8) error{InvalidDateTime}!i64 {
    return (try parseXsdDateTimeNs(s)).unix;
}

/// An `xsd:dateTime` / RFC 3339 instant: whole Unix seconds (UTC, offset
/// applied) plus the sub-second part.
pub const XsdInstant = struct {
    unix: i64,
    /// Fraction of the second in nanoseconds, 0..999_999_999. It is always the
    /// non-negative fraction of the wall-clock second: for an instant before
    /// the epoch the true time is `unix` seconds PLUS `nanosecond` ns
    /// (floor semantics, like `unixToParts`), never minus.
    nanosecond: u32,
};

/// Same grammar and strictness as `parseXsdDateTime`, but keeps the fraction.
/// Any number (≥ 1) of fraction digits is accepted, as RFC 3339 / XSD allow;
/// digits beyond the 9th (sub-nanosecond) are validated as digits and then
/// TRUNCATED, never rounded. A leap second (`:60`) is returned as-is: `unix`
/// is the second after `:59` (`23:59:60Z` == next-day `00:00:00Z`).
pub fn parseXsdDateTimeNs(s: []const u8) error{InvalidDateTime}!XsdInstant {
    // Minimum: "YYYY-MM-DDThh:mm:ss" = 19 chars.
    if (s.len < 19) return error.InvalidDateTime;
    if (s[4] != '-' or s[7] != '-' or (s[10] != 'T' and s[10] != 't') or s[13] != ':' or s[16] != ':') {
        return error.InvalidDateTime;
    }
    const year = try parseDigitField(i32, s[0..4]);
    const month = try parseDigitField(u32, s[5..7]);
    const day = try parseDigitField(u32, s[8..10]);
    const hour = try parseDigitField(i64, s[11..13]);
    const min = try parseDigitField(i64, s[14..16]);
    const sec = try parseDigitField(i64, s[17..19]);
    if (month < 1 or month > 12 or day < 1) return error.InvalidDateTime;
    // The day must exist in THAT month — see the doc comment above for why
    // this check exists (`ymdToEpochDay` happily rolls Feb 31 into Mar 2).
    if (day > daysInMonth(year, month)) return error.InvalidDateTime;
    if (hour > 23 or min > 59 or sec > 60) return error.InvalidDateTime; // :60 = leap second

    var i: usize = 19;
    // Optional fractional seconds: keep the first 9 digits, truncate the rest.
    var nanos: u32 = 0;
    if (i < s.len and s[i] == '.') {
        i += 1;
        const frac_start = i;
        var scale: u32 = 100_000_000; // weight of the next digit
        while (i < s.len and s[i] >= '0' and s[i] <= '9') : (i += 1) {
            if (scale > 0) {
                nanos += @as(u32, s[i] - '0') * scale;
                scale /= 10;
            }
        }
        if (i == frac_start) return error.InvalidDateTime;
    }
    // Optional timezone: `Z`/`z`, or a signed `±hh:mm` (colon required).
    var tz_offset_secs: i64 = 0;
    if (i < s.len) {
        const c = s[i];
        if (c == 'Z' or c == 'z') {
            i += 1;
        } else if (c == '+' or c == '-') {
            if (i + 6 > s.len or s[i + 3] != ':') return error.InvalidDateTime;
            const oh = try parseDigitField(i64, s[i + 1 .. i + 3]);
            const om = try parseDigitField(i64, s[i + 4 .. i + 6]);
            if (oh > 23 or om > 59) return error.InvalidDateTime;
            tz_offset_secs = (oh * 60 + om) * 60;
            if (c == '-') tz_offset_secs = -tz_offset_secs;
            i += 6;
        } else return error.InvalidDateTime;
    }
    if (i != s.len) return error.InvalidDateTime;

    const days = ymdToEpochDay(year, month, day);
    const secs = days * 86400 + hour * 3600 + min * 60 + sec;
    return .{ .unix = secs - tz_offset_secs, .nanosecond = nanos };
}

/// Digit-only fixed-field parse: every byte must be `0`-`9` (no sign, no
/// whitespace) — unlike `std.fmt.parseInt`, which would happily read a `-`
/// inside a slice meant to be an unsigned calendar field. Used by
/// `parseXsdDateTime`, where a slice like `s[11..13]` (the hour field) must
/// never silently become negative just because the byte at that offset was
/// `-` rather than a digit.
fn parseDigitField(comptime T: type, s: []const u8) error{InvalidDateTime}!T {
    var v: T = 0;
    if (s.len == 0) return error.InvalidDateTime;
    for (s) |c| {
        if (c < '0' or c > '9') return error.InvalidDateTime;
        v = v * 10 + @as(T, c - '0');
    }
    return v;
}

// ---------------------------------------------------------------------------
// Format-string validation
// ---------------------------------------------------------------------------

/// Scan a format string for a letter that is NOT part of the token vocabulary
/// and NOT inside a `[...]` literal/wildcard. Returns the 0-based offset of the
/// first offender, or null when every letter is a valid token. Lets a caller
/// flag a typo like `YYYY-MM-DZ` before the runtime would error.
pub fn firstInvalidFormatChar(fmt: []const u8) ?usize {
    var pos: usize = 0;
    while (pos < fmt.len) {
        if (fmt[pos] == '[') {
            const end = std.mem.findScalarPos(u8, fmt, pos + 1, ']') orelse return null;
            pos = end + 1;
            continue;
        }
        if (tokenAt(fmt, pos)) |m| {
            pos += m.len;
            continue;
        }
        // A bare ASCII letter that isn't a token is a likely typo.
        if (std.ascii.isAlphabetic(fmt[pos])) return pos;
        pos += 1; // punctuation / separators are fine as literals
    }
    return null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "civil core: epoch-day round-trips across the 1970 boundary" {
    try testing.expectEqual(@as(i64, 0), ymdToEpochDay(1970, 1, 1));
    try testing.expectEqual(@as(i64, -1), ymdToEpochDay(1969, 12, 31));
    try testing.expectEqual(@as(i64, 11016), ymdToEpochDay(2000, 2, 29)); // leap day
    // Far pre-epoch date round-trips exactly.
    const d = ymdToEpochDay(1924, 10, 10);
    const back = epochDayToYmd(d);
    try testing.expectEqual(@as(i32, 1924), back.year);
    try testing.expectEqual(@as(u32, 10), back.month);
    try testing.expectEqual(@as(u32, 10), back.day);
}

test "isoWeekday: known anchors" {
    try testing.expectEqual(@as(u32, 4), isoWeekday(0)); // 1970-01-01 Thursday
    try testing.expectEqual(@as(u32, 3), isoWeekday(ymdToEpochDay(2024, 1, 31))); // Wednesday
}

test "leap year + days in month" {
    try testing.expect(isLeapYear(2000));
    try testing.expect(!isLeapYear(1900));
    try testing.expect(isLeapYear(2024));
    try testing.expectEqual(@as(u32, 29), daysInMonth(2024, 2));
    try testing.expectEqual(@as(u32, 28), daysInMonth(2023, 2));
    try testing.expectEqual(@as(u32, 31), daysInMonth(2024, 12));
}

test "parse: real-world template formats" {
    const a = try parse("31.12.2024", "DD.MM.YYYY");
    try testing.expectEqual(DateParts{ .year = 2024, .month = 12, .day = 31 }, a);

    const b = try parse("03/15/2024 02:30:00 PM", "MM/DD/YYYY hh:mm:ss A");
    try testing.expectEqual(@as(u32, 14), b.hour); // 2 PM → 14
    try testing.expectEqual(@as(u32, 30), b.minute);

    const c = try parse("12312024", "MMDDYYYY");
    try testing.expectEqual(DateParts{ .year = 2024, .month = 12, .day = 31 }, c);

    const d = try parse("7 Jun 2022, 16:02:36", "D MMM YYYY, hh:mm:ss");
    try testing.expectEqual(DateParts{ .year = 2022, .month = 6, .day = 7, .hour = 16, .minute = 2, .second = 36 }, d);
}

test "parse: wildcard + literal escapes" {
    // [*] skips the timezone suffix; [T]/[Z] are literals.
    const a = try parse("2024-01-15T10:30:45+02:00", "YYYY-MM-DD[T]hh:mm:ss[*]");
    try testing.expectEqual(DateParts{ .year = 2024, .month = 1, .day = 15, .hour = 10, .minute = 30, .second = 45 }, a);

    const b = try parse("2024-01-15T10:30:45Z", "YYYY-MM-DD[T]hh:mm:ss[Z]");
    try testing.expectEqual(@as(u32, 45), b.second);
}

test "parse: 2-digit year pivot + month names" {
    try testing.expectEqual(@as(i32, 2024), (try parse("24-01-01", "YY-MM-DD")).year);
    try testing.expectEqual(@as(i32, 1999), (try parse("99-01-01", "YY-MM-DD")).year);
    try testing.expectEqual(@as(u32, 9), (try parse("15 September 2024", "D MMMM YYYY")).month);
}

test "parse: a numeric field is digits only -- no sign, no separator" {
    // Every token reads ASCII digits (`date_tokens`: "4-digit year", "2-digit
    // month", ...); `std.fmt.parseInt` alone also takes `+`/`-` and `_`.
    // Before 2026-10-04 `+1/05/2024` parsed as January, `1_00` as a year, and
    // an offset hour of `-1` slipped past the `oh > 23` range check as a
    // negative number.
    try testing.expectError(ParseError.InvalidDate, parse("+1/05/2024", "MM/DD/YYYY"));
    try testing.expectError(ParseError.InvalidDate, parse("01/05/+024", "MM/DD/YYYY"));
    try testing.expectError(ParseError.InvalidDate, parse("1_00-01-01", "YYYY-MM-DD"));
    try testing.expectError(ParseError.InvalidTime, parse("+1:30", "hh:mm"));
    try testing.expectError(ParseError.InvalidTime, parse("2024-01-01+-1:30", "YYYY-MM-DDZZ"));
    // The well-formed counterparts still parse.
    try testing.expectEqual(@as(u32, 1), (try parse("01/05/2024", "MM/DD/YYYY")).month);
    try testing.expectEqual(@as(?i32, 90), (try parse("2024-01-01+01:30", "YYYY-MM-DDZZ")).off_min);
}

test "parseIsoDate: the day must exist in its month, and fields are digits only" {
    // "Strict canonical YYYY-MM-DD": a calendar date, so day <= the month's
    // length (Gregorian leap rule), not merely <= 31; and no sign anywhere.
    // Before 2026-10-04 `2023-02-30` and `2024-04-31` were accepted (and
    // rolled into March/May by every caller's `ymdToEpochDay`), as was
    // `+024-01-01`.
    try testing.expectError(ParseError.InvalidDate, parseIsoDate("2023-02-29"));
    try testing.expectError(ParseError.InvalidDate, parseIsoDate("2023-02-30"));
    try testing.expectError(ParseError.InvalidDate, parseIsoDate("2024-04-31"));
    try testing.expectError(ParseError.InvalidDate, parseIsoDate("+024-01-01"));
    try testing.expectError(ParseError.InvalidDate, parseIsoDate("2024-+1-01"));
    try testing.expectEqual(DateParts{ .year = 2024, .month = 2, .day = 29 }, try parseIsoDate("2024-02-29"));
    try testing.expectEqual(DateParts{ .year = 2024, .month = 4, .day = 30 }, try parseIsoDate("2024-04-30"));
}

test "parse: token edges from the date_tokens table (mutation 2026-10-04)" {
    // Each assertion is a documented edge no test touched; the mutation run
    // of 2026-10-04 survived a flip of each one.
    // YY: "00-69 -> 2000s, 70-99 -> 1900s".
    try testing.expectEqual(@as(i32, 2069), (try parse("69-01-01", "YY-MM-DD")).year);
    try testing.expectEqual(@as(i32, 1970), (try parse("70-01-01", "YY-MM-DD")).year);
    // M / D read "1-2 digits": `115` with `MD` is month 11, day 5.
    const md = try parse("115", "MD");
    try testing.expectEqual(@as(u32, 11), md.month);
    try testing.expectEqual(@as(u32, 5), md.day);
    // hh is "00-23": 24 is no hour.
    try testing.expectError(ParseError.InvalidTime, parse("24:00", "hh:mm"));
    // 12h clock: 12 AM is 00, 12 PM is 12; anything but AM/PM is no meridiem.
    try testing.expectEqual(@as(u32, 0), (try parse("12:30 AM", "ii:mm A")).hour);
    try testing.expectEqual(@as(u32, 12), (try parse("12:30 PM", "ii:mm A")).hour);
    try testing.expectError(ParseError.InvalidTime, parse("12:30 XM", "ii:mm A"));
    // e: a digit 1-7 must be there.
    try testing.expectError(ParseError.InvalidFormat, parse("x", "e"));
    // ZZ: hours 00-23.
    try testing.expectError(ParseError.InvalidTime, parse("+24:00", "ZZ"));
    // A literal must match, must fit, and may not be left over past the input.
    try testing.expectError(ParseError.InvalidFormat, parse("2024/01", "YYYY-MM"));
    try testing.expectError(ParseError.InvalidFormat, parse("2024-1", "YYYY-12"));
    try testing.expectError(ParseError.InvalidFormat, parse("2024", "YYYY[!]"));
    // [*] "skip until the next token": a literal, or a 4-digit year.
    try testing.expectEqual(@as(i32, 2024), (try parse("abc-2024", "[*]-YYYY")).year);
    try testing.expectEqual(@as(i32, 2024), (try parse("foo2024", "[*]YYYY")).year);
}

/// The tokenizer before the by-first-character lookup (2026-10-10): scan
/// `token_table` in order at every position. The oracle for the test below.
fn tokenizeByTableScan(fmt: []const u8) ParseError!Layout {
    var out: Layout = undefined;
    out.n = 0;
    var pos: usize = 0;
    while (pos < fmt.len) {
        if (out.n >= MAX_TOKENS) return ParseError.TooManyTokens;
        if (fmt[pos] == '[') {
            const end = std.mem.findScalarPos(u8, fmt, pos + 1, ']') orelse fmt.len;
            if (end > pos + 1) {
                const content = fmt[pos + 1 .. end];
                out.toks[out.n] = if (std.mem.eql(u8, content, "*")) .wildcard else .{ .literal = content };
                out.n += 1;
                pos = end + 1;
                continue;
            }
        }
        const hit = for (token_table) |entry| {
            if (matchAt(fmt, pos, entry.lit)) break entry;
        } else null;
        if (hit) |entry| {
            out.toks[out.n] = entry.tok;
            out.n += 1;
            pos += entry.lit.len;
            continue;
        }
        const start = pos;
        pos += 1;
        while (pos < fmt.len and fmt[pos] != '[' and for (token_table) |entry| {
            if (matchAt(fmt, pos, entry.lit)) break false;
        } else true) pos += 1;
        out.toks[out.n] = .{ .literal = fmt[start..pos] };
        out.n += 1;
    }
    return out;
}

test "tokenize: by-first-character lookup splits every short format like the table scan" {
    // Every string up to 4 characters over the token letters, their
    // neighbours and the bracket syntax: same tokens, same literal slices.
    const alphabet = "YMDEShimsZWGeAa[]*x-";
    var buf: [4]u8 = undefined;
    var idx: [4]usize = undefined;
    for (1..buf.len + 1) |len| {
        @memset(idx[0..len], 0);
        while (true) {
            for (idx[0..len], buf[0..len]) |i, *c| c.* = alphabet[i];
            const s = buf[0..len];
            const want = try tokenizeByTableScan(s);
            var got: Layout = undefined;
            try tokenize(s, &got);
            try testing.expectEqual(want.n, got.n);
            for (want.toks[0..want.n], got.toks[0..got.n]) |a, b| {
                try testing.expectEqual(std.meta.activeTag(a), std.meta.activeTag(b));
                switch (a) {
                    .literal => |l| try testing.expectEqualStrings(l, b.literal),
                    .fraction => |n| try testing.expectEqual(n, b.fraction),
                    else => {},
                }
            }
            // odometer
            var k: usize = 0;
            while (k < len) : (k += 1) {
                idx[k] += 1;
                if (idx[k] < alphabet.len) break;
                idx[k] = 0;
            }
            if (k == len) break;
        }
    }
    // Runs longer than any token: "SSSSSSSSSSSS" = 9 + 3, "YYYYY" = YYYY + literal Y.
    for ([_][]const u8{ "SSSSSSSSSSSS", "YYYYY", "SSSSSSSS", "MMMMMMMMM", "ZZZ", "GGG" }) |s| {
        const want = try tokenizeByTableScan(s);
        var got: Layout = undefined;
        try tokenize(s, &got);
        try testing.expectEqual(want.n, got.n);
        for (want.toks[0..want.n], got.toks[0..got.n]) |a, b|
            try testing.expectEqual(std.meta.activeTag(a), std.meta.activeTag(b));
    }
}

test "putDec: same text as print {d:0>N}" {
    var buf: [32]u8 = undefined;
    const values = [_]u32{ 0, 1, 9, 10, 99, 100, 999, 1000, 9999, 10000, 123_456_789, 999_999_999, std.math.maxInt(u32) };
    inline for (.{ 1, 2, 3, 4, 6, 9 }) |width| {
        for (values) |v| {
            const len = putDec(&buf, 0, v, width);
            var want: [32]u8 = undefined;
            const exp = try std.mem.print(&want, "{d:0>" ++ std.fmt.comptimePrint("{d}", .{width}) ++ "}", .{v});
            try testing.expectEqualStrings(exp, buf[0..len]);
        }
    }
}

test "format: max_field_len bounds every field, extreme values included" {
    // The widest rendering of each non-literal token stays within max_field_len.
    const extreme = DateParts{ .year = std.math.maxInt(i32), .month = 9, .day = 30, .hour = std.math.maxInt(u32), .minute = std.math.maxInt(u32), .second = std.math.maxInt(u32), .nanosecond = 999_999_999, .off_min = std.math.minInt(i32) };
    for (token_table) |e| {
        const s = format(testing.allocator, extreme, e.lit) catch continue;
        defer testing.allocator.free(s);
        try testing.expect(s.len <= max_field_len);
    }
    const s = try format(testing.allocator, extreme, "ZZ");
    defer testing.allocator.free(s);
    try testing.expectEqualStrings("-35791394:08", s);
}

test "format: a bound past the stack buffer takes a heap scratch buffer, same text" {
    const parts = DateParts{ .year = 2024, .month = 3, .day = 7, .hour = 14, .minute = 5, .second = 9 };
    const lit = "[" ++ strRepeat("x", 150) ++ "]";
    const s = try format(testing.allocator, parts, "YYYY" ++ lit ++ "MM-DD");
    defer testing.allocator.free(s);
    try testing.expectEqualStrings("2024" ++ strRepeat("x", 150) ++ "03-07", s);
    // "[q…]DD" bounds to n + 10: just under, at and past the 256-byte stack buffer.
    for ([_]usize{ 245, 246, 247, 260 }) |n| {
        var fmt_buf: [270]u8 = undefined;
        fmt_buf[0] = '[';
        @memset(fmt_buf[1 .. n - 1], 'q');
        fmt_buf[n - 1] = ']';
        @memcpy(fmt_buf[n .. n + 2], "DD");
        const out = try format(testing.allocator, parts, fmt_buf[0 .. n + 2]);
        defer testing.allocator.free(out);
        try testing.expectEqual(n - 2 + 2, out.len);
        try testing.expectEqualStrings("07", out[out.len - 2 ..]);
    }
    // Every allocation failure surfaces as an error, never a leak.
    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn f(a: std.mem.Allocator, p: DateParts) !void {
            a.free(try format(a, p, "YYYY-MM-DD"));
            a.free(try format(a, p, "YYYY" ++ ("[" ++ strRepeat("y", 300) ++ "]")));
        }
    }.f, .{parts});
}

fn expectLayoutMatches(l: *const Layout, fmt: []const u8, p: DateParts) !void {
    const a = try l.format(testing.allocator, p);
    defer testing.allocator.free(a);
    const b = try format(testing.allocator, p, fmt);
    defer testing.allocator.free(b);
    try testing.expectEqualStrings(b, a);
    try testing.expectEqualDeep(try parse(a, fmt), try l.parse(a));
}

test "Layout: same result as format/parse with the format string, also compiled at comptime" {
    const rfc = comptime Layout.compile("YYYY-MM-DD[T]hh:mm:ss.SSSZZ") catch unreachable;
    const imf = try Layout.compile("EEE, DD MMM YYYY hh:mm:ss [GMT]");
    var prng = std.Random.DefaultPrng.init(0x1a70_7);
    for (0..500) |_| {
        var p = unixToParts(prng.random().intRangeAtMost(i64, -62_135_596_800, 253_402_300_799));
        p.nanosecond = prng.random().uintLessThan(u32, 1_000_000_000);
        p.off_min = prng.random().intRangeAtMost(i32, -23 * 60, 23 * 60);
        try expectLayoutMatches(&rfc, "YYYY-MM-DD[T]hh:mm:ss.SSSZZ", p);
        try expectLayoutMatches(&imf, "EEE, DD MMM YYYY hh:mm:ss [GMT]", p);
    }
    try testing.expectError(ParseError.TooManyTokens, Layout.compile(strRepeat("YYYY-", 40)));
}

test "canned: RFC 9110 and RFC 3339 examples" {
    // RFC 9110 §5.6.7.
    const imf = try parseImfFixdate("Sun, 06 Nov 1994 08:49:37 GMT");
    try testing.expectEqual(@as(i64, 784111777), partsToUnix(imf));
    var ib: [imf_fixdate_len]u8 = undefined;
    try bufImfFixdate(&ib, unixToParts(784111777));
    try testing.expectEqualStrings("Sun, 06 Nov 1994 08:49:37 GMT", &ib);

    // RFC 3339 §5.8.
    const a = try parseRfc3339("1985-04-12T23:20:50.52Z");
    try testing.expectEqual(DateParts{ .year = 1985, .month = 4, .day = 12, .hour = 23, .minute = 20, .second = 50, .nanosecond = 520_000_000, .off_min = 0 }, a);
    const b = try parseRfc3339("1996-12-19T16:39:57-08:00");
    try testing.expectEqual(@as(?i32, -480), b.off_min);
    const c = try parseRfc3339("1937-01-01T12:00:27.87+00:20");
    try testing.expectEqual(@as(?i32, 20), c.off_min);
    try testing.expectEqual(@as(u32, 870_000_000), c.nanosecond);
    var rb: [rfc3339_max_len]u8 = undefined;
    try testing.expectEqualStrings("1985-04-12T23:20:50.52Z", try bufRfc3339(&rb, a, 2));
    try testing.expectEqualStrings("1996-12-19T16:39:57-08:00", try bufRfc3339(&rb, b, 0));
    try testing.expectEqualStrings("1937-01-01T12:00:27.870000000+00:20", try bufRfc3339(&rb, c, 9));
    try testing.expectEqualStrings("1985-04-12T23:20:50Z", try bufRfc3339(&rb, .{ .year = 1985, .month = 4, .day = 12, .hour = 23, .minute = 20, .second = 50 }, 0));
    // The leap second of the RFC's own example: DateParts cannot hold it.
    try testing.expectError(ParseError.InvalidTime, parseRfc3339("1990-12-31T23:59:60Z"));
}

test "canned: agree with the token engine and parseXsdDateTimeNs over random instants" {
    var prng = std.Random.DefaultPrng.init(0xca_77ed);
    const r = prng.random();
    var rb: [rfc3339_max_len]u8 = undefined;
    var ib: [imf_fixdate_len]u8 = undefined;
    for (0..2000) |_| {
        var p = unixToParts(r.intRangeAtMost(i64, -62_167_219_200, 253_402_300_799)); // 0000..9999
        p.nanosecond = r.uintLessThan(u32, 1_000_000_000);
        const utc = p;
        p.off_min = r.intRangeAtMost(i32, -1439, 1439);

        try bufImfFixdate(&ib, utc);
        const want_imf = try format(testing.allocator, utc, "EEE, DD MMM YYYY hh:mm:ss [GMT]");
        defer testing.allocator.free(want_imf);
        try testing.expectEqualStrings(want_imf, &ib);
        var back = try parseImfFixdate(&ib);
        back.nanosecond = utc.nanosecond;
        back.off_min = null;
        try testing.expectEqual(utc, back);

        const fd: u8 = r.uintAtMost(u8, 9);
        const s = try bufRfc3339(&rb, p, fd);
        const want = try format(testing.allocator, p, if (p.off_min.? == 0) "YYYY-MM-DD[T]hh:mm:ss.SSSSSSSSS[Z]" else "YYYY-MM-DD[T]hh:mm:ss.SSSSSSSSSZZ");
        defer testing.allocator.free(want);
        // The token engine always writes nine digits; cut to fd (and the dot).
        const head = if (fd == 0) want[0..19] else want[0 .. 20 + fd];
        try testing.expectEqualStrings(head, s[0..head.len]);
        try testing.expectEqualStrings(want[29..], s[head.len..]);
        const q = try parseRfc3339(s);
        const ns_kept = p.nanosecond - p.nanosecond % std.math.pow(u32, 10, 9 - fd);
        try testing.expectEqual(ns_kept, q.nanosecond);
        try testing.expectEqual(p.off_min, q.off_min);
        const inst = try parseXsdDateTimeNs(s);
        try testing.expectEqual(partsToUnix(q) - @as(i64, q.off_min.?) * 60, inst.unix);
        try testing.expectEqual(q.nanosecond, inst.nanosecond);
    }
}

test "canned: out-of-range values are errors, malformed input is refused" {
    var rb: [rfc3339_max_len]u8 = undefined;
    var ib: [imf_fixdate_len]u8 = undefined;
    const ok = DateParts{ .year = 2024, .month = 2, .day = 29, .hour = 23, .minute = 59, .second = 59 };
    _ = try bufRfc3339(&rb, ok, 9);
    try bufImfFixdate(&ib, ok);
    for ([_]DateParts{
        .{ .year = -1 },                          .{ .year = 10000 },
        .{ .year = 2023, .month = 2, .day = 29 }, .{ .month = 13 },
        .{ .day = 0 },
    }) |bad| {
        try testing.expectError(error.InvalidDate, bufRfc3339(&rb, bad, 0));
        try testing.expectError(error.InvalidDate, bufImfFixdate(&ib, bad));
    }
    for ([_]DateParts{ .{ .hour = 24 }, .{ .minute = 60 }, .{ .second = 60 }, .{ .nanosecond = 1_000_000_000 } }) |bad| {
        try testing.expectError(error.InvalidTime, bufRfc3339(&rb, bad, 0));
        try testing.expectError(error.InvalidTime, bufImfFixdate(&ib, bad));
    }
    try testing.expectError(error.InvalidTime, bufRfc3339(&rb, .{ .off_min = 1440 }, 0));
    try testing.expectError(error.InvalidTime, bufRfc3339(&rb, .{ .off_min = -1440 }, 0));
    try testing.expectError(error.InvalidTime, bufRfc3339(&rb, .{}, 10));
    try testing.expectEqualStrings("1970-01-01T00:00:00+23:59", try bufRfc3339(&rb, .{ .off_min = 1439 }, 0));
    try testing.expectEqualStrings("0000-01-01T00:00:00Z", try bufRfc3339(&rb, .{ .year = 0 }, 0));
    try testing.expectEqualStrings("9999-12-31T23:59:59Z", try bufRfc3339(&rb, .{ .year = 9999, .month = 12, .day = 31, .hour = 23, .minute = 59, .second = 59 }, 0));

    for ([_][]const u8{
        "2024-01-01T00:00:00", // no offset
        "2024-01-01T00:00:00.Z", // empty fraction
        "2024-01-01 00:00:00Z", // space separator
        "2024-01-01T00:00:00+0100", // offset without colon
        "2024-01-01T00:00:00Zx", // trailing
        "2024-01-01T00:00:00+01:0", // short offset
    }) |bad| try testing.expectError(ParseError.InvalidFormat, parseRfc3339(bad));
    try testing.expectError(ParseError.InvalidTime, parseRfc3339("2024-01-01T00:00:00+24:00"));
    try testing.expectError(ParseError.InvalidTime, parseRfc3339("2024-01-01T24:00:00Z"));
    try testing.expectError(ParseError.InvalidDate, parseRfc3339("2023-02-29T00:00:00Z"));
    try testing.expectError(ParseError.InvalidDate, parseRfc3339("2024-1a-01T00:00:00Z"));
    try testing.expectError(ParseError.InvalidDate, parseRfc3339("+024-01-01T00:00:00Z")); // sign in a field
    _ = try parseRfc3339("2024-01-01t00:00:00z");

    for ([_][]const u8{
        "Sun, 06 Nov 1994 08:49:37 UTC", // not GMT
        "Sun, 6 Nov 1994 08:49:37 GMT", // one-digit day
        "Sunday, 06-Nov-94 08:49:37 GMT", // RFC 850 (obsolete)
        "Sun Nov  6 08:49:37 1994", // asctime (obsolete)
        "Sun, 06 Nov 1994 08:49:37 GMT ", // trailing
    }) |bad| try testing.expectError(ParseError.InvalidFormat, parseImfFixdate(bad));
    try testing.expectError(ParseError.InvalidDate, parseImfFixdate("Mon, 06 Nov 1994 08:49:37 GMT")); // wrong weekday
    try testing.expectError(ParseError.InvalidDate, parseImfFixdate("Sun, 06 nov 1994 08:49:37 GMT")); // case
    try testing.expectError(ParseError.InvalidDate, parseImfFixdate("Fri, 31 Feb 1994 08:49:37 GMT"));
    try testing.expectError(ParseError.InvalidTime, parseImfFixdate("Sun, 06 Nov 1994 08:60:37 GMT"));
}

test "canned parsers: mutated and random input is an error or a valid date, never a panic" {
    // Header input is untrusted (`If-Modified-Since`): byte flips, cuts and
    // random bytes, in a safety-checked build.
    var prng = std.Random.DefaultPrng.init(0xbad_da7e);
    const r = prng.random();
    const seeds = [_][]const u8{ "Sun, 06 Nov 1994 08:49:37 GMT", "1937-01-01T12:00:27.87+00:20", "2024-02-29T23:59:59.123456789Z" };
    var buf: [40]u8 = undefined;
    for (0..20_000) |i| {
        const seed = seeds[i % seeds.len];
        var len = seed.len;
        @memcpy(buf[0..len], seed);
        switch (r.uintLessThan(u8, 3)) {
            0 => for (0..r.uintAtMost(u8, 3)) |_| {
                buf[r.uintLessThan(usize, len)] = r.int(u8);
            },
            1 => len = r.uintAtMost(usize, len),
            else => {
                len = r.uintAtMost(usize, buf.len);
                r.bytes(buf[0..len]);
            },
        }
        if (parseRfc3339(buf[0..len])) |p| try testing.expect(validate(p)) else |_| {}
        if (parseImfFixdate(buf[0..len])) |p| try testing.expect(validate(p)) else |_| {}
    }
}

test "tokenize: more than MAX_TOKENS tokens is TooManyTokens, not an overrun" {
    // `MAX_TOKENS` (64) sizes the on-stack token array; a longer format is
    // refused (`ParseError.TooManyTokens`). Mutation 2026-10-04: dropping the
    // check survived -- nothing fed a format that long. `M-` is two tokens.
    const long = strRepeat("M-", 33);
    try testing.expectError(ParseError.TooManyTokens, parse("1-", long));
    try testing.expectError(error.TooManyTokens, format(testing.allocator, .{ .year = 2024, .month = 1, .day = 1 }, long));
}

test "format: the 12-hour clock at noon" {
    // 12:xx is "12 PM" (`ii` = "2-digit hour, 12h (01-12)"); mutation
    // 2026-10-04 survived printing it as 00 and labelling it AM.
    const a = testing.allocator;
    const s = try format(a, .{ .year = 2024, .month = 1, .day = 1, .hour = 12, .minute = 5 }, "ii:mm A");
    defer a.free(s);
    try testing.expectEqualStrings("12:05 PM", s);
}

test "nthWeekdayOfMonth: an occurrence one day past the month end is null" {
    // Feb 2023 starts on a Wednesday (1 Feb 2023 = ISO weekday 3), so its
    // 5th Wednesday would be "29 Feb 2023", which does not exist. Mutation
    // 2026-10-04: admitting day = dim + 1 survived.
    try testing.expect(nthWeekdayOfMonth(2023, 2, 3, 5) == null);
    try testing.expectEqual(@as(u32, 22), nthWeekdayOfMonth(2023, 2, 3, 4).?.day);
}

test "parseIsoDate / parseXsdDateTime: exact shape (mutation 2026-10-04)" {
    // `parseIsoDate` is "strict canonical YYYY-MM-DD": exactly 10 bytes.
    try testing.expectError(ParseError.InvalidDate, parseIsoDate("2024-01-01x"));
    // xsd:dateTime (XML Schema 1.1 Part 2 §3.3.8): `T` separates date and
    // time; the zone is `Z` or `(+|-)hh:mm` with the colon and minutes
    // 00-59; every field is digits (`parseDigitField` doc).
    try testing.expectError(error.InvalidDateTime, parseXsdDateTime("2024-01-01 12:00:00Z"));
    try testing.expectError(error.InvalidDateTime, parseXsdDateTime("2024-01-01T12:00:00+02_00"));
    try testing.expectError(error.InvalidDateTime, parseXsdDateTime("2024-01-01T12:00:00+02:60"));
    try testing.expectError(error.InvalidDateTime, parseXsdDateTime("20x4-01-01T12:00:00Z"));
    try testing.expectEqual(@as(i64, 1704103200), try parseXsdDateTime("2024-01-01T12:00:00+02:00"));
}

test "parse: pre-1970 dates no longer rejected (BUG-3)" {
    const a = try parse("1924-10-10", "YYYY-MM-DD");
    try testing.expectEqual(DateParts{ .year = 1924, .month = 10, .day = 10 }, a);
    const b = try parse("31.12.1969", "DD.MM.YYYY");
    try testing.expectEqual(DateParts{ .year = 1969, .month = 12, .day = 31 }, b);
}

test "parse: range violations are rejected" {
    try testing.expectError(ParseError.InvalidDate, parse("2024-13-01", "YYYY-MM-DD"));
    try testing.expectError(ParseError.InvalidDate, parse("2024-02-30", "YYYY-MM-DD"));
    try testing.expectError(ParseError.InvalidTime, parse("2024-01-01 25:00:00", "YYYY-MM-DD hh:mm:ss"));
    try testing.expectError(ParseError.InvalidFormat, parse("2024-01", "YYYY-MM-DD")); // truncated
}

test "format: token vocabulary round-trip" {
    const a = testing.allocator;
    const p = DateParts{ .year = 2024, .month = 3, .day = 7, .hour = 14, .minute = 5, .second = 9 };

    const cases = [_]struct { fmt: []const u8, want: []const u8 }{
        .{ .fmt = "YYYY-MM-DD", .want = "2024-03-07" },
        .{ .fmt = "YYYY-MM-DD[T]hh:mm:ss[Z]", .want = "2024-03-07T14:05:09Z" },
        .{ .fmt = "YYYYMMDDhhmmss", .want = "20240307140509" },
        .{ .fmt = "D MMM YYYY", .want = "7 Mar 2024" },
        .{ .fmt = "MMMM D, YYYY", .want = "March 7, 2024" },
        .{ .fmt = "ii:mm A", .want = "02:05 PM" },
        .{ .fmt = "EEEE", .want = "Thursday" }, // 2024-03-07 is a Thursday
        .{ .fmt = "YY/M/D", .want = "24/3/7" },
    };
    for (cases) |c| {
        const got = try format(a, p, c.fmt);
        defer a.free(got);
        try testing.expectEqualStrings(c.want, got);
    }
}

test "format: lowercase am/pm ('a' token) — only 'A' (uppercase) was ever exercised" {
    const a = testing.allocator;
    const morning = try format(a, .{ .year = 2024, .month = 3, .day = 7, .hour = 9 }, "hh:mm a");
    defer a.free(morning);
    try testing.expectEqualStrings("09:00 am", morning);
    const afternoon = try format(a, .{ .year = 2024, .month = 3, .day = 7, .hour = 21 }, "hh:mm a");
    defer a.free(afternoon);
    try testing.expectEqualStrings("21:00 pm", afternoon);
}

test "format+parse: day-of-week ('e' token) — zero coverage in either direction before this" {
    // 2024-03-07 is a Thursday: ISO weekday 4.
    const a = testing.allocator;
    const s = try format(a, .{ .year = 2024, .month = 3, .day = 7 }, "e");
    defer a.free(s);
    try testing.expectEqualStrings("4", s);

    const p = try parse("4", "e");
    // The token is "informational, not stored" (no year/month/day carried) —
    // parse must still accept a valid 1-7 value and reject out-of-range ones.
    try testing.expectEqual(@as(i32, 1970), p.year); // untouched default
    try testing.expectError(ParseError.InvalidDate, parse("8", "e"));
    try testing.expectError(ParseError.InvalidDate, parse("0", "e"));
}

test "format+parse: day-name-short (EEE/EE/E) and day-name-long (EEEE) — parse side had zero coverage" {
    // Format side: only EEEE (full name) had a test; EEE/EE/E never did.
    const a = testing.allocator;
    const short = try format(a, .{ .year = 2024, .month = 3, .day = 7 }, "EEE"); // Thursday
    defer a.free(short);
    try testing.expectEqualStrings("Thu", short);

    // Parse side: parseDayName (shared by EEEE and EEE/EE/E) had NO call site
    // via the public `parse()` entry point anywhere in this suite.
    const got_short = try parse("Thu, 2024-03-07", "EEE, YYYY-MM-DD");
    try testing.expectEqual(DateParts{ .year = 2024, .month = 3, .day = 7 }, got_short);
    const got_long = try parse("Thursday, 2024-03-07", "EEEE, YYYY-MM-DD");
    try testing.expectEqual(DateParts{ .year = 2024, .month = 3, .day = 7 }, got_long);
    // An unrecognized day name is rejected, not silently skipped.
    try testing.expectError(ParseError.InvalidFormat, parse("Blah, 2024-03-07", "EEE, YYYY-MM-DD"));
}

test "format: pre-1970 date renders correctly" {
    const a = testing.allocator;
    const got = try format(a, .{ .year = 1924, .month = 10, .day = 10 }, "YYYY-MM-DD");
    defer a.free(got);
    try testing.expectEqualStrings("1924-10-10", got);
}

test "DATE_CONVERT-style reshuffle handles pre-1970 (no epoch round-trip)" {
    const a = testing.allocator;
    const parts = try parse("10/10/1924", "MM/DD/YYYY");
    const got = try format(a, parts, "YYYY-MM-DD");
    defer a.free(got);
    try testing.expectEqualStrings("1924-10-10", got);
}

test "arithmetic: addDays/addMonths clamp + pre-1970" {
    // Day clamp: Jan 31 + 1 month → Feb 29 (2024 leap).
    try testing.expectEqual(DateParts{ .year = 2024, .month = 2, .day = 29 }, addMonths(.{ .year = 2024, .month = 1, .day = 31 }, 1));
    // addDays preserves time of day.
    const t = addDays(.{ .year = 2024, .month = 1, .day = 31, .hour = 12 }, 1);
    try testing.expectEqual(@as(u32, 12), t.hour);
    try testing.expectEqual(DateParts{ .year = 2024, .month = 2, .day = 1, .hour = 12 }, t); // Jan 31 + 1d = Feb 1
    // Crossing below the epoch works.
    try testing.expectEqual(DateParts{ .year = 1969, .month = 12, .day = 31 }, addDays(.{ .year = 1970, .month = 1, .day = 1 }, -1));
    try testing.expectEqual(@as(i32, 1965), addYears(.{ .year = 1970, .month = 6, .day = 15 }, -5).year);
}

test "arithmetic: diff + boundaries" {
    try testing.expectEqual(@as(i64, 365), diffInDays(.{ .year = 2024, .month = 12, .day = 31 }, .{ .year = 2024, .month = 1, .day = 1 }));
    try testing.expectEqual(@as(i64, -1), diffInDays(.{ .year = 1969, .month = 12, .day = 31 }, .{ .year = 1970, .month = 1, .day = 1 }));
    try testing.expectEqual(@as(i32, 14), diffInMonths(.{ .year = 2025, .month = 3, .day = 1 }, .{ .year = 2024, .month = 1, .day = 1 }));
    try testing.expectEqual(@as(u32, 29), endOfMonth(.{ .year = 2024, .month = 2, .day = 10 }).day);
    try testing.expectEqual(DateParts{ .year = 2024, .month = 1, .day = 1 }, startOfYear(.{ .year = 2024, .month = 7, .day = 4 }));
}

test "nthWeekdayOfMonth: DST boundaries, nth-from-start, and overflow" {
    // EU DST 2024: last Sunday of March = 31st, last Sunday of October = 27th.
    try testing.expectEqual(DateParts{ .year = 2024, .month = 3, .day = 31 }, nthWeekdayOfMonth(2024, 3, 7, -1).?);
    try testing.expectEqual(DateParts{ .year = 2024, .month = 10, .day = 27 }, nthWeekdayOfMonth(2024, 10, 7, -1).?);
    // US DST: 2nd Sunday of March 2024 = 10th, 1st Sunday of November = 3rd.
    try testing.expectEqual(@as(u32, 10), nthWeekdayOfMonth(2024, 3, 7, 2).?.day);
    try testing.expectEqual(@as(u32, 3), nthWeekdayOfMonth(2024, 11, 7, 1).?.day);
    // First Monday of Jan 2024 = 1st (Jan 1 2024 is a Monday).
    try testing.expectEqual(@as(u32, 1), nthWeekdayOfMonth(2024, 1, 1, 1).?.day);
    // Second-to-last Sunday of March 2024 = 24th.
    try testing.expectEqual(@as(u32, 24), nthWeekdayOfMonth(2024, 3, 7, -2).?.day);
    // Works pre-1970.
    try testing.expectEqual(@as(u32, 30), nthWeekdayOfMonth(1924, 3, 7, -1).?.day);
    // Non-existent (Feb 2023 has only four Sundays) and out-of-range args → null.
    try testing.expect(nthWeekdayOfMonth(2023, 2, 7, 5) == null);
    try testing.expect(nthWeekdayOfMonth(2024, 13, 7, 1) == null);
    try testing.expect(nthWeekdayOfMonth(2024, 3, 8, 1) == null);
    try testing.expect(nthWeekdayOfMonth(2024, 3, 7, 0) == null);
}

test "strict ISO helpers" {
    try testing.expectEqual(DateParts{ .year = 2024, .month = 3, .day = 15 }, try parseIsoDate("2024-03-15"));
    try testing.expectError(ParseError.InvalidDate, parseIsoDate("2024/03/15"));
    try testing.expectError(ParseError.InvalidDate, parseIsoDate("2024-13-01"));
    const a = testing.allocator;
    const s = try formatIsoDate(a, .{ .year = 1924, .month = 10, .day = 10 });
    defer a.free(s);
    try testing.expectEqualStrings("1924-10-10", s);
}

test "parseXsdDateTime: UTC Z form" {
    try testing.expectEqual(@as(i64, 1717243200), try parseXsdDateTime("2024-06-01T12:00:00Z"));
}

test "parseXsdDateTime: fractional seconds truncated, lowercase t/z tolerated" {
    try testing.expectEqual(@as(i64, 1717243200), try parseXsdDateTime("2024-06-01t12:00:00.123456z"));
}

test "parseXsdDateTimeNs: keeps the fraction, 1..9+ digits, truncates beyond 9" {
    const base: i64 = 1717243200; // 2024-06-01T12:00:00Z
    const cases = [_]struct { s: []const u8, ns: u32 }{
        .{ .s = "2024-06-01T12:00:00.5Z", .ns = 500_000_000 },
        .{ .s = "2024-06-01T12:00:00.12Z", .ns = 120_000_000 },
        .{ .s = "2024-06-01T12:00:00.123Z", .ns = 123_000_000 },
        .{ .s = "2024-06-01T12:00:00.1234Z", .ns = 123_400_000 },
        .{ .s = "2024-06-01T12:00:00.123456Z", .ns = 123_456_000 },
        .{ .s = "2024-06-01T12:00:00.1234567Z", .ns = 123_456_700 },
        .{ .s = "2024-06-01T12:00:00.12345678Z", .ns = 123_456_780 },
        .{ .s = "2024-06-01T12:00:00.123456789Z", .ns = 123_456_789 },
        .{ .s = "2024-06-01T12:00:00.1234567899Z", .ns = 123_456_789 }, // 10th digit truncated, not rounded
        .{ .s = "2024-06-01T12:00:00.999999999999Z", .ns = 999_999_999 },
        .{ .s = "2024-06-01T12:00:00.000000001Z", .ns = 1 },
        .{ .s = "2024-06-01T12:00:00.000Z", .ns = 0 },
        .{ .s = "2024-06-01T12:00:00Z", .ns = 0 }, // no fraction
    };
    for (cases) |c| {
        const r = try parseXsdDateTimeNs(c.s);
        try testing.expectEqual(base, r.unix);
        try testing.expectEqual(c.ns, r.nanosecond);
    }
    // The fraction survives an offset and does not disturb it.
    const off = try parseXsdDateTimeNs("2024-06-01T12:00:00.25+02:00");
    try testing.expectEqual(@as(i64, 1717236000), off.unix);
    try testing.expectEqual(@as(u32, 250_000_000), off.nanosecond);
    // Malformed fractions stay typed errors.
    try testing.expectError(error.InvalidDateTime, parseXsdDateTimeNs("2024-06-01T12:00:00.Z"));
    try testing.expectError(error.InvalidDateTime, parseXsdDateTimeNs("2024-06-01T12:00:00.1x2Z"));
    try testing.expectError(error.InvalidDateTime, parseXsdDateTimeNs("2024-06-01T12:00:00."));
}

test "parseXsdDateTime: numeric timezone offset applied" {
    try testing.expectEqual(@as(i64, 1717236000), try parseXsdDateTime("2024-06-01T12:00:00+02:00"));
    try testing.expectEqual(@as(i64, 1717250400), try parseXsdDateTime("2024-06-01T12:00:00-02:00"));
}

test "parseXsdDateTime: epoch and a pre-epoch date" {
    try testing.expectEqual(@as(i64, 0), try parseXsdDateTime("1970-01-01T00:00:00Z"));
    try testing.expectEqual(@as(i64, -86400), try parseXsdDateTime("1969-12-31T00:00:00Z"));
}

test "parseXsdDateTime: malformed inputs are typed errors, never panics" {
    try testing.expectError(error.InvalidDateTime, parseXsdDateTime("2024-06-01"));
    try testing.expectError(error.InvalidDateTime, parseXsdDateTime("2024/06/01T12:00:00Z"));
    try testing.expectError(error.InvalidDateTime, parseXsdDateTime("2024-13-01T12:00:00Z"));
    try testing.expectError(error.InvalidDateTime, parseXsdDateTime("2024-06-01T25:00:00Z"));
    try testing.expectError(error.InvalidDateTime, parseXsdDateTime("2024-06-01T12:00:00Q"));
    // xsd:dateTime requires the ':' in the offset — unlike `parse`'s `ZZ`
    // token, which tolerates its absence. This is the divergence documented
    // on `parseXsdDateTime` itself.
    try testing.expectError(error.InvalidDateTime, parseXsdDateTime("2024-06-01T12:00:00+0200"));
    try testing.expectError(error.InvalidDateTime, parseXsdDateTime(""));
}

test "parseXsdDateTime: leap second (:60) accepted — xsd:dateTime allows it, parse()'s range check does not" {
    try testing.expectEqual(@as(i64, 1719792000), try parseXsdDateTime("2024-06-30T23:59:60Z"));
}

test "parseXsdDateTime: trailing garbage after a complete timestamp is rejected" {
    // `parse()` has no end-of-input check; this parser does — see doc comment.
    try testing.expectError(error.InvalidDateTime, parseXsdDateTime("2024-06-01T12:00:00Zgarbage"));
}

test "parseXsdDateTime: a day that does not exist in its month is rejected, not rolled over (regression, eb3edc6)" {
    // Before this check, the previous saml-local copy of this parser
    // normalised the overflow, so "2024-02-31T…" parsed as 2024-03-02 — a
    // `NotOnOrAfter` two days later than the document actually said, i.e. an
    // assertion validity window an attacker could stretch with a typo-shaped
    // timestamp rather than a signature.
    for ([_][]const u8{
        "2024-02-30T00:00:00Z",
        "2024-02-31T00:00:00Z",
        "2023-02-29T00:00:00Z", // 2023 is not a leap year
        "2024-04-31T00:00:00Z",
        "2024-06-31T00:00:00Z",
        "2024-09-31T00:00:00Z",
        "2024-11-31T00:00:00Z",
        "2024-01-32T00:00:00Z",
        "2024-01-00T00:00:00Z",
    }) |bad| {
        try testing.expectError(error.InvalidDateTime, parseXsdDateTime(bad));
    }

    // The real boundaries still parse, including both leap-year rules.
    try testing.expectEqual(@as(i64, 1709164800), try parseXsdDateTime("2024-02-29T00:00:00Z"));
    try testing.expectEqual(@as(i64, 951782400), try parseXsdDateTime("2000-02-29T00:00:00Z")); // /400
    try testing.expectError(error.InvalidDateTime, parseXsdDateTime("1900-02-29T00:00:00Z")); // /100
    try testing.expectEqual(@as(i64, 1709251200), try parseXsdDateTime("2024-03-01T00:00:00Z"));
    try testing.expectEqual(@as(i64, 1735603200), try parseXsdDateTime("2024-12-31T00:00:00Z"));
}

test "firstInvalidFormatChar: flags stray letters, accepts tokens + literals" {
    try testing.expect(firstInvalidFormatChar("YYYY-MM-DD") == null);
    try testing.expect(firstInvalidFormatChar("YYYY-MM-DD[T]hh:mm:ss[Z]") == null);
    try testing.expect(firstInvalidFormatChar("DD.MM.YYYY") == null);
    // 'Z' outside brackets is not a token → flagged at its offset.
    try testing.expectEqual(@as(?usize, 8), firstInvalidFormatChar("YYYY-MM-Z"));
}

test "format/formatIsoDate reject negative years instead of @intCast UB" {
    const a = testing.allocator;
    const neg: DateParts = .{ .year = -9000, .month = 6, .day = 15 };
    try testing.expectError(error.InvalidDate, formatIsoDate(a, neg));
    try testing.expectError(error.InvalidDate, format(a, neg, "YYYY-MM-DD"));
    // Year 0 is non-negative → formats fine (no false positive on the boundary).
    const zero: DateParts = .{ .year = 0, .month = 1, .day = 1 };
    const s = try formatIsoDate(a, zero);
    defer a.free(s);
    try testing.expectEqualStrings("0000-01-01", s);
}

test "ZZ offset token: parse (Z / ±HH:MM / ±HHMM) and format" {
    try testing.expectEqual(@as(?i32, 120), (try parse("2024-03-15T14:23:01+02:00", "YYYY-MM-DD[T]hh:mm:ssZZ")).off_min);
    try testing.expectEqual(@as(?i32, 0), (try parse("2024-03-15T14:23:01Z", "YYYY-MM-DD[T]hh:mm:ssZZ")).off_min);
    try testing.expectEqual(@as(?i32, -300), (try parse("2024-03-15 14:23:01-0500", "YYYY-MM-DD hh:mm:ssZZ")).off_min);
    // A format with no ZZ token leaves off_min null.
    try testing.expectEqual(@as(?i32, null), (try parse("2024-03-15", "YYYY-MM-DD")).off_min);
    // Format emits ±HH:MM (and +00:00 when the offset is absent).
    const a = testing.allocator;
    const s1 = try format(a, .{ .year = 2024, .month = 3, .day = 15, .off_min = 120 }, "ZZ");
    defer a.free(s1);
    try testing.expectEqualStrings("+02:00", s1);
    const s2 = try format(a, .{ .year = 2024, .month = 3, .day = 15, .off_min = -330 }, "ZZ");
    defer a.free(s2);
    try testing.expectEqualStrings("-05:30", s2);
}

test "partsToUnix / unixToParts round-trip across the epoch" {
    const u = partsToUnix(.{ .year = 2024, .month = 7, .day = 15, .hour = 12, .minute = 30, .second = 45 });
    const b = unixToParts(u);
    try testing.expectEqual(@as(i32, 2024), b.year);
    try testing.expectEqual(@as(u32, 7), b.month);
    try testing.expectEqual(@as(u32, 15), b.day);
    try testing.expectEqual(@as(u32, 12), b.hour);
    try testing.expectEqual(@as(u32, 30), b.minute);
    try testing.expectEqual(@as(u32, 45), b.second);
    try testing.expectEqual(@as(i64, 0), partsToUnix(.{ .year = 1970, .month = 1, .day = 1 }));
    // One second before the epoch is 1969-12-31 23:59:59.
    const pre = unixToParts(-1);
    try testing.expectEqual(@as(i32, 1969), pre.year);
    try testing.expectEqual(@as(u32, 23), pre.hour);
    try testing.expectEqual(@as(u32, 59), pre.second);
}

test "fraction tokens: format at 3/6/9 digits truncates, never rounds" {
    const a = testing.allocator;
    const p = DateParts{ .year = 2024, .month = 3, .day = 7, .hour = 14, .minute = 5, .second = 9, .nanosecond = 123_456_789 };
    const cases = [_]struct { fmt: []const u8, want: []const u8 }{
        .{ .fmt = "hh:mm:ss.SSS", .want = "14:05:09.123" },
        .{ .fmt = "hh:mm:ss.SSSSSS", .want = "14:05:09.123456" },
        .{ .fmt = "hh:mm:ss.SSSSSSSSS", .want = "14:05:09.123456789" },
        .{ .fmt = "YYYY-MM-DD[T]hh:mm:ss.SSS[Z]", .want = "2024-03-07T14:05:09.123Z" },
    };
    for (cases) |c| {
        const got = try format(a, p, c.fmt);
        defer a.free(got);
        try testing.expectEqualStrings(c.want, got);
    }
    // Leading zeros are kept; 999_999_999 ns is .999 in ms (truncated, not 1.000).
    const z = try format(a, .{ .nanosecond = 5_000_000 }, "SSS/SSSSSS/SSSSSSSSS");
    defer a.free(z);
    try testing.expectEqualStrings("005/005000/005000000", z);
    const t = try format(a, .{ .nanosecond = 999_999_999 }, "SSS");
    defer a.free(t);
    try testing.expectEqualStrings("999", t);
    // Default nanosecond is 0 → zeros; an out-of-range value is an error, not garbage.
    const d = try format(a, .{}, "SSS");
    defer a.free(d);
    try testing.expectEqualStrings("000", d);
    try testing.expectError(error.InvalidTime, format(a, .{ .nanosecond = 1_000_000_000 }, "SSS"));
}

test "fraction tokens: parse scales to nanoseconds, fixed width, never panics" {
    const f = "YYYY-MM-DD[T]hh:mm:ss.";
    try testing.expectEqual(@as(u32, 123_000_000), (try parse("2024-03-07T14:05:09.123", f ++ "SSS")).nanosecond);
    try testing.expectEqual(@as(u32, 123_456_000), (try parse("2024-03-07T14:05:09.123456", f ++ "SSSSSS")).nanosecond);
    try testing.expectEqual(@as(u32, 123_456_789), (try parse("2024-03-07T14:05:09.123456789", f ++ "SSSSSSSSS")).nanosecond);
    try testing.expectEqual(@as(u32, 7_000_000), (try parse("2024-03-07T14:05:09.007", f ++ "SSS")).nanosecond);
    // Trailing zone after the fraction still works.
    const z = try parse("2024-03-07T14:05:09.250+02:00", f ++ "SSSZZ");
    try testing.expectEqual(@as(u32, 250_000_000), z.nanosecond);
    try testing.expectEqual(@as(?i32, 120), z.off_min);
    // No fraction token → 0.
    try testing.expectEqual(@as(u32, 0), (try parse("2024-03-07T14:05:09", "YYYY-MM-DD[T]hh:mm:ss")).nanosecond);
    // Too short / not digits / signed → typed errors.
    try testing.expectError(ParseError.InvalidFormat, parse("2024-03-07T14:05:09.12", f ++ "SSS"));
    try testing.expectError(ParseError.InvalidTime, parse("2024-03-07T14:05:09.1x3", f ++ "SSS"));
    try testing.expectError(ParseError.InvalidTime, parse("2024-03-07T14:05:09.+12", f ++ "SSS"));
    // [*] before a fraction token skips to the first 3-digit run.
    try testing.expectEqual(@as(u32, 250_000_000), (try parse("09,250", "ss[*]SSS")).nanosecond);
}

test "fraction: parse → format round trip, and arithmetic preserves it" {
    const a = testing.allocator;
    const fmt = "YYYY-MM-DD[T]hh:mm:ss.SSSSSSSSS";
    const s = "2024-03-07T14:05:09.123456789";
    const p = try parse(s, fmt);
    const back = try format(a, p, fmt);
    defer a.free(back);
    try testing.expectEqualStrings(s, back);
    try testing.expectEqual(@as(u32, 123_456_789), addDays(p, 30).nanosecond);
    try testing.expectEqual(@as(u32, 123_456_789), addMonths(p, 1).nanosecond);
    try testing.expect(validate(p));
    try testing.expect(!validate(.{ .nanosecond = 1_000_000_000 }));
    // XSD → parts → format keeps the fraction too.
    const x = try parseXsdDateTimeNs("2024-03-07T14:05:09.5Z");
    const xp = unixToParts(x.unix);
    var q = xp;
    q.nanosecond = x.nanosecond;
    const xs = try format(a, q, "hh:mm:ss.SSS");
    defer a.free(xs);
    try testing.expectEqualStrings("14:05:09.500", xs);
}

test "isoWeek: dates checked against Python datetime.date(y,m,d).isocalendar()" {
    // Expected values come from an EXTERNAL oracle, run 2026-09-30:
    //   python3 -c "import datetime; print(datetime.date(y,m,d).isocalendar())"
    //   2004-12-31 (2004, 53, 5)   2005-01-01 (2004, 53, 6)   2005-01-02 (2004, 53, 7)
    //   2007-12-31 (2008,  1, 1)   2008-12-28 (2008, 52, 7)   2008-12-29 (2009,  1, 1)
    //   2009-12-31 (2009, 53, 4)   2010-01-03 (2009, 53, 7)   2020-12-31 (2020, 53, 4)
    //   2021-01-03 (2020, 53, 7)   2024-12-30 (2025,  1, 1)   2026-09-30 (2026, 40, 3)
    const cases = [_]struct { y: i32, m: u32, d: u32, iy: i32, w: u32, wd: u32 }{
        .{ .y = 2004, .m = 12, .d = 31, .iy = 2004, .w = 53, .wd = 5 },
        .{ .y = 2005, .m = 1, .d = 1, .iy = 2004, .w = 53, .wd = 6 },
        .{ .y = 2005, .m = 1, .d = 2, .iy = 2004, .w = 53, .wd = 7 },
        .{ .y = 2007, .m = 12, .d = 31, .iy = 2008, .w = 1, .wd = 1 },
        .{ .y = 2008, .m = 12, .d = 28, .iy = 2008, .w = 52, .wd = 7 },
        .{ .y = 2008, .m = 12, .d = 29, .iy = 2009, .w = 1, .wd = 1 },
        .{ .y = 2009, .m = 12, .d = 31, .iy = 2009, .w = 53, .wd = 4 },
        .{ .y = 2010, .m = 1, .d = 3, .iy = 2009, .w = 53, .wd = 7 },
        .{ .y = 2020, .m = 12, .d = 31, .iy = 2020, .w = 53, .wd = 4 },
        .{ .y = 2021, .m = 1, .d = 3, .iy = 2020, .w = 53, .wd = 7 },
        .{ .y = 2024, .m = 12, .d = 30, .iy = 2025, .w = 1, .wd = 1 },
        .{ .y = 2026, .m = 9, .d = 30, .iy = 2026, .w = 40, .wd = 3 },
    };
    for (cases) |c| {
        const r = isoWeek(.{ .year = c.y, .month = c.m, .day = c.d });
        try testing.expectEqual(c.iy, r.year);
        try testing.expectEqual(c.w, r.week);
        const ed = ymdToEpochDay(c.y, c.m, c.d);
        try testing.expectEqual(c.wd, isoWeekday(ed));
        // The inverse must land back on the same civil day.
        try testing.expectEqual(@as(?i64, ed), isoWeekDateToEpochDay(c.iy, c.w, c.wd));
    }
}

test "isoWeek: brute-force inverse over 1900..2100, 53-week years, pre-1970" {
    var d: i64 = ymdToEpochDay(1900, 1, 1);
    const end = ymdToEpochDay(2100, 12, 31);
    while (d <= end) : (d += 1) {
        const ymd = epochDayToYmd(d);
        const w = isoWeek(ymd);
        try testing.expect(w.week >= 1 and w.week <= isoWeeksInYear(w.year));
        try testing.expectEqual(@as(?i64, d), isoWeekDateToEpochDay(w.year, w.week, isoWeekday(d)));
    }
    // 53-week years (2004, 2009, 2015, 2020, 2026) vs 52-week neighbours.
    try testing.expectEqual(@as(u32, 53), isoWeeksInYear(2004));
    try testing.expectEqual(@as(u32, 53), isoWeeksInYear(2020));
    try testing.expectEqual(@as(u32, 53), isoWeeksInYear(2026));
    try testing.expectEqual(@as(u32, 52), isoWeeksInYear(2025));
    try testing.expectEqual(@as(u32, 52), isoWeeksInYear(2008));
    // Nonexistent weeks / weekdays are null, not rolled over.
    try testing.expect(isoWeekDateToEpochDay(2025, 53, 1) == null);
    try testing.expect(isoWeekDateToEpochDay(2025, 0, 1) == null);
    try testing.expect(isoWeekDateToEpochDay(2025, 1, 0) == null);
    try testing.expect(isoWeekDateToEpochDay(2025, 1, 8) == null);
}

test "ISO week tokens: format (GGGG, WW, W, e)" {
    const a = testing.allocator;
    const cases = [_]struct { p: DateParts, fmt: []const u8, want: []const u8 }{
        .{ .p = .{ .year = 2005, .month = 1, .day = 1 }, .fmt = "GGGG-[W]WW-e", .want = "2004-W53-6" }, // oracle: (2004, 53, 6)
        .{ .p = .{ .year = 2007, .month = 12, .day = 31 }, .fmt = "GGGG-[W]WW-e", .want = "2008-W01-1" }, // (2008, 1, 1)
        .{ .p = .{ .year = 2024, .month = 12, .day = 30 }, .fmt = "GGGG-[W]W-e", .want = "2025-W1-1" }, // (2025, 1, 1)
        .{ .p = .{ .year = 2026, .month = 9, .day = 30 }, .fmt = "YYYY/GGGG [W]WW", .want = "2026/2026 W40" }, // (2026, 40, 3)
        .{ .p = .{ .year = 2010, .month = 1, .day = 3 }, .fmt = "YYYY-MM-DD → GGGG-[W]WW", .want = "2010-01-03 → 2009-W53" }, // (2009, 53, 7)
    };
    for (cases) |c| {
        const got = try format(a, c.p, c.fmt);
        defer a.free(got);
        try testing.expectEqualStrings(c.want, got);
    }
}

test "ISO week tokens: parse resolves the civil date; round-trips with format" {
    const a = testing.allocator;
    const fmt = "GGGG-[W]WW-e";
    // (input, expected civil date) — dates from the Python oracle rows above.
    const cases = [_]struct { s: []const u8, want: DateParts }{
        .{ .s = "2004-W53-6", .want = .{ .year = 2005, .month = 1, .day = 1 } },
        .{ .s = "2004-W53-5", .want = .{ .year = 2004, .month = 12, .day = 31 } },
        .{ .s = "2008-W01-1", .want = .{ .year = 2007, .month = 12, .day = 31 } },
        .{ .s = "2009-W01-1", .want = .{ .year = 2008, .month = 12, .day = 29 } },
        .{ .s = "2020-W53-7", .want = .{ .year = 2021, .month = 1, .day = 3 } },
        .{ .s = "2025-W01-1", .want = .{ .year = 2024, .month = 12, .day = 30 } },
        .{ .s = "2026-W40-3", .want = .{ .year = 2026, .month = 9, .day = 30 } },
    };
    for (cases) |c| {
        const got = try parse(c.s, fmt);
        try testing.expectEqual(c.want, got);
        const back = try format(a, got, fmt);
        defer a.free(back);
        try testing.expectEqualStrings(c.s, back);
    }
    // Weekday defaults to Monday; short week token; week combined with time + fraction.
    try testing.expectEqual(DateParts{ .year = 2024, .month = 12, .day = 30 }, try parse("2025-W1", "GGGG-[W]W"));
    const t = try parse("2026-W40-3 08:30:00.500", "GGGG-[W]WW-e hh:mm:ss.SSS");
    try testing.expectEqual(DateParts{ .year = 2026, .month = 9, .day = 30, .hour = 8, .minute = 30, .nanosecond = 500_000_000 }, t);
    // Nonexistent weeks / bad weekdays are rejected, never rolled over.
    try testing.expectError(ParseError.InvalidDate, parse("2025-W53-1", fmt)); // 2025 has 52 weeks
    try testing.expectError(ParseError.InvalidDate, parse("2025-W00-1", fmt));
    try testing.expectError(ParseError.InvalidDate, parse("2025-W54-1", fmt));
    try testing.expectError(ParseError.InvalidDate, parse("2025-W10-8", fmt));
    try testing.expectError(ParseError.InvalidDate, parse("2025-W10-0", fmt));
    try testing.expectError(ParseError.InvalidDate, parse("20x5-W10-1", fmt));
    try testing.expectError(ParseError.InvalidFormat, parse("2025-W1", fmt)); // truncated
    // A format without week tokens is unaffected: `e` stays informational.
    try testing.expectEqual(@as(i32, 1970), (try parse("4", "e")).year);
}

test "new tokens are in the vocabulary (firstInvalidFormatChar) and doc table" {
    try testing.expect(firstInvalidFormatChar("GGGG-[W]WW-e hh:mm:ss.SSS") == null);
    try testing.expect(firstInvalidFormatChar("ss.SSSSSSSSS") == null);
    try testing.expect(firstInvalidFormatChar("ss.SS") != null); // only 3/6/9 wide
    var found: usize = 0;
    for (date_tokens) |t| {
        for ([_][]const u8{ "SSS", "SSSSSS", "SSSSSSSSS", "GGGG", "WW", "W" }) |want| {
            if (std.mem.eql(u8, t.token, want)) found += 1;
        }
    }
    try testing.expectEqual(@as(usize, 6), found);
}

test "unixToParts: any i64 instant saturates the year instead of trapping" {
    // Audit S7 2026-10-19: maxInt(i64) seconds is year ~2.9e11; the `i32`
    // cast of the year panicked (Debug/ReleaseSafe) or was UB (ReleaseFast).
    const hi = unixToParts(std.math.maxInt(i64));
    try testing.expectEqual(@as(i32, std.math.maxInt(i32)), hi.year);
    try testing.expect(validate(hi));
    const lo = unixToParts(std.math.minInt(i64));
    try testing.expectEqual(@as(i32, std.math.minInt(i32)), lo.year);
    try testing.expect(validate(lo));
    // In-range instants are unchanged.
    try testing.expectEqual(@as(i32, 1970), unixToParts(0).year);
    try testing.expectEqual(@as(i32, 9999), unixToParts(253402300799).year);
}

test {
    _ = @import("go_oracle_test.zig");
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    const rep_result = comptime blk: {
        @setEvalBranchQuota(n * (s.len + 4) + 1000);
        var buf: [s.len * n:0]u8 = undefined;
        for (0..n) |i| @memcpy(buf[i * s.len ..][0..s.len], s);
        const rep_final = buf;
        break :blk rep_final;
    };
    return &rep_result;
}
