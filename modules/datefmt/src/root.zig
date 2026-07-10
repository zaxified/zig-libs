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
//!   [text] literal · [*] wildcard (skip until next token)

const std = @import("std");

pub const meta = .{
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
    return .{ .year = @intCast(if (m <= 2) y + 1 else y), .month = m, .day = d };
}

/// ISO weekday: Monday=1 … Sunday=7. 1970-01-01 (epoch day 0) was Thursday=4.
pub fn isoWeekday(epoch_day: i64) u32 {
    return @intCast(@mod(epoch_day + 3, 7) + 1);
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
    const rem: u32 = @intCast(unix - day * 86400); // [0, 86399]
    var r = epochDayToYmd(day);
    r.hour = rem / 3600;
    r.minute = (rem % 3600) / 60;
    r.second = rem % 60;
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
/// month, hour 0-23, minute/second 0-59). Year is unconstrained.
pub fn validate(p: DateParts) bool {
    if (p.month < 1 or p.month > 12) return false;
    if (p.day < 1 or p.day > daysInMonth(p.year, p.month)) return false;
    if (p.hour > 23 or p.minute > 59 or p.second > 59) return false;
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
    wildcard, // [*]
    literal: []const u8, // [text] or any unrecognised run
};

/// Real format strings are short (~10-20 tokens). 64 is a generous ceiling
/// that keeps the token array on the stack — no allocator, no syscalls on
/// the format/parse hot path.
const MAX_TOKENS = 64;

const Tokenized = struct {
    toks: [MAX_TOKENS]Token = undefined,
    n: usize = 0,
};

fn matchAt(s: []const u8, pos: usize, needle: []const u8) bool {
    if (pos + needle.len > s.len) return false;
    return std.mem.eql(u8, s[pos .. pos + needle.len], needle);
}

/// Ordered longest-first so e.g. "YYYY" wins over "YY" and "MMMM" over "MMM".
const token_table = [_]struct { lit: []const u8, tok: Token }{
    .{ .lit = "YYYY", .tok = .year_full },
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
    .{ .lit = "YY", .tok = .year_short },
    .{ .lit = "EE", .tok = .day_name_short },
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

fn isTokenStart(fmt: []const u8, pos: usize) bool {
    if (fmt[pos] == '[') return true;
    for (token_table) |entry| {
        if (matchAt(fmt, pos, entry.lit)) return true;
    }
    return false;
}

fn tokenize(fmt: []const u8) ParseError!Tokenized {
    var out = Tokenized{};
    var pos: usize = 0;
    while (pos < fmt.len) {
        if (out.n >= MAX_TOKENS) return ParseError.TooManyTokens;

        // [text] literal or [*] wildcard.
        if (fmt[pos] == '[') {
            const end = std.mem.indexOfScalarPos(u8, fmt, pos + 1, ']') orelse fmt.len;
            if (end > pos + 1) {
                const content = fmt[pos + 1 .. end];
                out.toks[out.n] = if (std.mem.eql(u8, content, "*"))
                    .wildcard
                else
                    .{ .literal = content };
                out.n += 1;
                pos = end + 1;
                continue;
            }
        }

        // Longest-first token match.
        var matched = false;
        for (token_table) |entry| {
            if (matchAt(fmt, pos, entry.lit)) {
                out.toks[out.n] = entry.tok;
                out.n += 1;
                pos += entry.lit.len;
                matched = true;
                break;
            }
        }
        if (matched) continue;

        // Literal run: consume until the next token start.
        const start = pos;
        pos += 1;
        while (pos < fmt.len and !isTokenStart(fmt, pos)) pos += 1;
        out.toks[out.n] = .{ .literal = fmt[start..pos] };
        out.n += 1;
    }
    return out;
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
        .year_full => {
            var i = pos;
            while (i + 4 <= s.len) : (i += 1) if (isAllDigits(s[i .. i + 4])) return i;
            return ParseError.InvalidFormat;
        },
        .year_short, .month_full, .day_full, .hour_24_full, .hour_12_full, .minute_full, .second_full => {
            var i = pos;
            while (i + 2 <= s.len) : (i += 1) if (isAllDigits(s[i .. i + 2])) return i;
            return ParseError.InvalidFormat;
        },
        .month_short, .day_short, .hour_24_short, .hour_12_short, .minute_short, .second_short, .day_of_week => {
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
    is_pm: ?bool = null,
    off_min: ?i32 = null,
};

fn parseUint(comptime T: type, s: []const u8, err: ParseError) ParseError!T {
    return std.fmt.parseInt(T, s, 10) catch return err;
}

/// Parse `input` against `fmt`, returning the extracted `DateParts`. Missing
/// date components default to the epoch (1970-01-01); missing time defaults to
/// 00:00:00. Ranges are validated (`InvalidDate` / `InvalidTime`) but the year
/// has no lower bound — pre-1970 dates parse fine. This never converts to an
/// epoch timestamp, so a parse→format reshuffle round-trips any year losslessly.
pub fn parse(input: []const u8, fmt: []const u8) ParseError!DateParts {
    const tk = try tokenize(fmt);
    var b = Builder{};
    var p: usize = 0;

    for (tk.toks[0..tk.n], 0..) |token, idx| {
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
                p = end; // informational
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
                if (idx + 1 < tk.n) {
                    p = try skipUntilNextToken(input, p, tk.toks[idx + 1]);
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

    const result = DateParts{
        .year = b.year orelse 1970,
        .month = b.month orelse 1,
        .day = b.day orelse 1,
        .hour = b.hour,
        .minute = b.minute,
        .second = b.second,
        .off_min = b.off_min,
    };
    if (!validate(result)) {
        if (result.hour > 23 or result.minute > 59 or result.second > 59) return ParseError.InvalidTime;
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
    const tk = tokenize(fmt) catch |err| switch (err) {
        error.TooManyTokens => return error.TooManyTokens,
        else => return error.InvalidFormatString,
    };

    var aw: std.Io.Writer.Allocating = .init(alloc);
    errdefer aw.deinit();
    const w = &aw.writer;

    // Weekday is only needed for E*/e tokens; compute lazily-ish (cheap anyway).
    const dow = isoWeekday(ymdToEpochDay(parts.year, parts.month, parts.day));
    // A negative year is only reachable from extreme date arithmetic across
    // year 0. `@intCast` of it into u32 is silent UB in ReleaseSmall (and a
    // panic in safe modes). Reject as InvalidDate — the same contract as
    // month 13 / Feb 30 — so the field yields "" rather than garbage.
    // (`year_short` below uses `@mod` and is already safe for negatives.)
    if (parts.year < 0) return error.InvalidDate;
    const year_u: u32 = @intCast(parts.year);

    for (tk.toks[0..tk.n]) |token| {
        switch (token) {
            .year_full => try w.print("{d:0>4}", .{year_u}),
            .year_short => try w.print("{d:0>2}", .{@as(u32, @intCast(@mod(parts.year, 100)))}),
            .month_full => try w.print("{d:0>2}", .{parts.month}),
            .month_short => try w.print("{d}", .{parts.month}),
            .month_name_short => try w.writeAll(shortMonthName(parts.month)),
            .month_name_long => try w.writeAll(fullMonthName(parts.month)),
            .day_full => try w.print("{d:0>2}", .{parts.day}),
            .day_short => try w.print("{d}", .{parts.day}),
            .day_name_long => try w.writeAll(fullDayName(dow)),
            .day_name_short => try w.writeAll(shortDayName(dow)),
            .day_of_week => try w.print("{d}", .{dow}),
            .hour_24_full => try w.print("{d:0>2}", .{parts.hour}),
            .hour_24_short => try w.print("{d}", .{parts.hour}),
            .hour_12_full => try w.print("{d:0>2}", .{to12Hour(parts.hour)}),
            .hour_12_short => try w.print("{d}", .{to12Hour(parts.hour)}),
            .minute_full => try w.print("{d:0>2}", .{parts.minute}),
            .minute_short => try w.print("{d}", .{parts.minute}),
            .second_full => try w.print("{d:0>2}", .{parts.second}),
            .second_short => try w.print("{d}", .{parts.second}),
            .ampm_upper => try w.writeAll(if (parts.hour < 12) "AM" else "PM"),
            .ampm_lower => try w.writeAll(if (parts.hour < 12) "am" else "pm"),
            .tz_offset => {
                const om = parts.off_min orelse 0;
                const sign: u8 = if (om < 0) '-' else '+';
                const mag: u32 = @intCast(if (om < 0) -om else om);
                try w.print("{c}{d:0>2}:{d:0>2}", .{ sign, mag / 60, mag % 60 });
            },
            .wildcard => {}, // nothing to emit on the format side
            .literal => |lit| try w.writeAll(lit),
        }
    }
    return aw.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// Calendar arithmetic (pre-1970 safe — operates on civil days, never u64)
// ---------------------------------------------------------------------------

/// Add `n` calendar days, preserving the time of day.
pub fn addDays(parts: DateParts, n: i64) DateParts {
    var r = epochDayToYmd(ymdToEpochDay(parts.year, parts.month, parts.day) + n);
    r.hour = parts.hour;
    r.minute = parts.minute;
    r.second = parts.second;
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
    if (m < 1 or m > 12 or d < 1 or d > 31) return ParseError.InvalidDate;
    return .{ .year = y, .month = m, .day = d };
}

/// Render a date as canonical `YYYY-MM-DD`.
pub fn formatIsoDate(alloc: std.mem.Allocator, parts: DateParts) ![]const u8 {
    // See `format` above: reject negative years (UB on `@intCast` to u32 in
    // ReleaseSmall) as InvalidDate rather than emit garbage.
    if (parts.year < 0) return error.InvalidDate;
    const y_u: u32 = @intCast(parts.year);
    return std.fmt.allocPrint(alloc, "{d:0>4}-{d:0>2}-{d:0>2}", .{ y_u, parts.month, parts.day });
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
            const end = std.mem.indexOfScalarPos(u8, fmt, pos + 1, ']') orelse return null;
            pos = end + 1;
            continue;
        }
        var matched = false;
        for (token_table) |entry| {
            if (matchAt(fmt, pos, entry.lit)) {
                pos += entry.lit.len;
                matched = true;
                break;
            }
        }
        if (matched) continue;
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
