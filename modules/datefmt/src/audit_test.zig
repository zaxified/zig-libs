// SPDX-License-Identifier: MIT

//! Tests added by the 2026-10-25 grade-1 audit (mutant schemata over the
//! non-test source of root.zig). Each test names what a mutant of the source
//! would have changed; they pin boundaries the earlier tables and oracles
//! never reached. Public API only.

const std = @import("std");
const testing = std.testing;
const dt = @import("root.zig");

const DateParts = dt.DateParts;
const gpa = testing.allocator;

fn fmtEq(expected: []const u8, parts: DateParts, fmt: []const u8) !void {
    const out = try dt.format(gpa, parts, fmt);
    defer gpa.free(out);
    try testing.expectEqualStrings(expected, out);
}

fn parsed(input: []const u8, fmt: []const u8) !DateParts {
    return dt.parse(input, fmt);
}

fn mdays(y: i32, m: u32) u32 {
    const leap = (@mod(y, 4) == 0 and @mod(y, 100) != 0) or @mod(y, 400) == 0;
    return switch (m) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        else => if (leap) 29 else 28,
    };
}

// ---------------------------------------------------------------------------
// Civil core
// ---------------------------------------------------------------------------

test "audit: day-by-day walk 0000-03-01 .. 2800-01-01 agrees with an independent calendar" {
    // Kills the century / 400-year corrections of epochDayToYmd (36524, 146096),
    // the y >= 0 / z >= 0 pivots at their first day, and any slip of the
    // month table in either direction. 1M days, a few ms.
    var y: i32 = 0;
    var m: u32 = 3;
    var d: u32 = 1;
    var ed: i64 = -719468;
    var wd: u32 = dt.isoWeekday(ed);
    while (y < 2800) : (ed += 1) {
        if (dt.ymdToEpochDay(y, m, d) != ed) {
            std.debug.print("ymdToEpochDay({d}-{d}-{d}) != {d}\n", .{ y, m, d, ed });
            return error.TestUnexpectedResult;
        }
        const back = dt.epochDayToYmd(ed);
        if (back.year != y or back.month != m or back.day != d) {
            std.debug.print("epochDayToYmd({d}) = {d}-{d}-{d}, want {d}-{d}-{d}\n", .{ ed, back.year, back.month, back.day, y, m, d });
            return error.TestUnexpectedResult;
        }
        if (dt.isoWeekday(ed) != wd) return error.TestUnexpectedResult;
        wd = wd % 7 + 1;
        d += 1;
        if (d > mdays(y, m)) {
            d = 1;
            m += 1;
            if (m > 12) {
                m = 1;
                y += 1;
            }
        }
    }
    try testing.expectEqual(ed, dt.ymdToEpochDay(2800, 1, 1));
}

/// Finding D1 (see the audit report): `ymdToEpochDay` / `epochDayToYmd` use
/// `@divFloor(if (x >= 0) x else x - K, K')`. Hinnant's `x - K + 1` adjustment is
/// for TRUNCATING division; with `@divFloor` it makes every day before
/// 0000-03-01 land one era too low (year 0 Jan/Feb and every negative year are
/// off by a day or decode to the wrong date). The two tests below hold the
/// correct behavior and run only once `d1Fixed()` is flipped to true.
fn d1Fixed() bool {
    return true;
}

test "audit D1a: ymdToEpochDay for years <= 0 (walk backwards from 0000-03-01)" {
    if (!d1Fixed()) return;
    var y: i32 = 0;
    var m: u32 = 3;
    var d: u32 = 1;
    var ed: i64 = -719468;
    while (y > -1200) : (ed -= 1) {
        if (dt.ymdToEpochDay(y, m, d) != ed) return error.TestUnexpectedResult;
        if (d > 1) {
            d -= 1;
        } else {
            if (m > 1) m -= 1 else {
                m = 12;
                y -= 1;
            }
            d = mdays(y, m);
        }
    }
}

test "audit D1b: epochDayToYmd for days before 0000-03-01 (walk backwards)" {
    if (!d1Fixed()) return;
    var y: i32 = 0;
    var m: u32 = 3;
    var d: u32 = 1;
    var ed: i64 = -719468;
    while (y > -1200) : (ed -= 1) {
        const back = dt.epochDayToYmd(ed);
        if (back.year != y or back.month != m or back.day != d) return error.TestUnexpectedResult;
        if (d > 1) {
            d -= 1;
        } else {
            if (m > 1) m -= 1 else {
                m = 12;
                y -= 1;
            }
            d = mdays(y, m);
        }
    }
}

test "audit: leap years, month lengths, validate at the nanosecond edge" {
    // 2002 and 2022 are divisible by 2 but not by 4.
    try testing.expect(!dt.isLeapYear(2022));
    try testing.expect(!dt.isLeapYear(2026));
    try testing.expect(!dt.isLeapYear(2100));
    try testing.expect(dt.isLeapYear(2000));
    try testing.expect(dt.isLeapYear(2024));
    try testing.expect(dt.isLeapYear(0));
    try testing.expect(dt.isLeapYear(-4));
    try testing.expect(!dt.isLeapYear(-100));
    try testing.expect(dt.isLeapYear(-400));
    try testing.expectEqual(@as(u32, 28), dt.daysInMonth(2022, 2));
    try testing.expectEqual(@as(u32, 29), dt.daysInMonth(2024, 2));
    try testing.expect(dt.validate(.{ .nanosecond = 999_999_999 }));
    try testing.expect(!dt.validate(.{ .nanosecond = 1_000_000_000 }));
}

test "audit: month and weekday names at both ends of their tables" {
    // 2024-01-01 is a Monday, 2024-01-07 a Sunday.
    try fmtEq("January Monday Mon", .{ .year = 2024, .month = 1, .day = 1 }, "MMMM EEEE EEE");
    try fmtEq("December Sunday Sun", .{ .year = 2024, .month = 12, .day = 1 }, "MMMM EEEE EEE");
    try fmtEq("Jan Sun", .{ .year = 2024, .month = 1, .day = 7 }, "MMM EEE");
    try fmtEq("Dec", .{ .year = 2024, .month = 12, .day = 7 }, "MMM");
    // out-of-range months are rendered, not trapped
    try fmtEq("??? Unknown", .{ .year = 2024, .month = 13, .day = 1 }, "MMM MMMM");
    try fmtEq("??? Unknown", .{ .year = 2024, .month = 0, .day = 1 }, "MMM MMMM");
}

test "audit: 12-hour clock midnight, one o'clock, am/pm at noon and 11:59" {
    try fmtEq("12 AM", .{ .hour = 0 }, "ii A");
    try fmtEq("01 AM", .{ .hour = 1 }, "ii A");
    try fmtEq("1 am", .{ .hour = 1 }, "i a");
    try fmtEq("12 pm", .{ .hour = 12 }, "i a");
    try fmtEq("12 PM", .{ .hour = 12 }, "i A");
    try fmtEq("11 am", .{ .hour = 11 }, "i a");
    try fmtEq("1 pm", .{ .hour = 13 }, "i a");
    try fmtEq("11 PM", .{ .hour = 23 }, "i A");
}

test "audit: short numeric tokens do not pad, long ones do; ZZ of a zero offset is +00:00" {
    const p = DateParts{ .year = 2005, .month = 3, .day = 7, .hour = 4, .minute = 5, .second = 6 };
    try fmtEq("3/7 4:5:6 4", p, "M/D h:m:s i");
    try fmtEq("03/07 04:05:06 04", p, "MM/DD hh:mm:ss ii");
    try fmtEq("05 2005", p, "YY YYYY");
    try fmtEq("0005", .{ .year = 5 }, "YYYY");
    try fmtEq("+00:00", p, "ZZ");
    var q = p;
    q.off_min = 0;
    try fmtEq("+00:00", q, "ZZ");
    q.off_min = -90;
    try fmtEq("-01:30", q, "ZZ");
    q.off_min = 23 * 60 + 59;
    try fmtEq("+23:59", q, "ZZ");
    q.off_min = -(23 * 60 + 59);
    try fmtEq("-23:59", q, "ZZ");
}

test "audit: a byte 0x80 in a format string is a literal (the by-char table ends at 127)" {
    try fmtEq("\x80", .{}, "\x80");
    try fmtEq("\xc3\xa9", .{}, "\xc3\xa9");
}

test "audit: format output bound -- heap scratch and stack paths agree at the 256-byte edge" {
    var buf: [300]u8 = undefined;

    // bound == 256 exactly takes the stack path: one allocation (the result).
    @memset(buf[0..244], 'x');
    buf[244] = 'Z';
    buf[245] = 'Z';
    var fa = testing.FailingAllocator.init(gpa, .{ .fail_index = 1 });
    const out = try dt.format(fa.allocator(), .{ .off_min = 60 }, buf[0..246]);
    defer gpa.free(out);
    try testing.expectEqual(@as(usize, 244 + 6), out.len);
    try testing.expectEqualStrings("+01:00", out[244..]);

    // a day name needs its 12-byte share of the bound: 250 + 9 > 256 bytes of output.
    @memset(buf[0..250], 'x');
    @memcpy(buf[250..254], "EEEE");
    const wed = try dt.format(gpa, .{ .year = 2024, .month = 1, .day = 3 }, buf[0..254]);
    defer gpa.free(wed);
    try testing.expectEqual(@as(usize, 259), wed.len);
    try testing.expectEqualStrings("Wednesday", wed[250..]);

    // the widest ZZ (minInt offset, 12 bytes) after 245 literal bytes: 257 bytes.
    @memset(buf[0..245], 'x');
    buf[245] = 'Z';
    buf[246] = 'Z';
    const wide = try dt.format(gpa, .{ .off_min = std.math.minInt(i32) }, buf[0..247]);
    defer gpa.free(wide);
    try testing.expectEqual(@as(usize, 257), wide.len);
    try testing.expectEqualStrings("-35791394:08", wide[245..]);
}

test "audit: format of an unterminated bracket and of SSSS" {
    // '[' without ']' makes the rest a literal -- tokenizer and firstInvalidFormatChar agree.
    try fmtEq("YYYY", .{}, "[YYYY");
    try testing.expectEqual(@as(?usize, null), dt.firstInvalidFormatChar("[YYYY"));
    try testing.expectEqual(@as(?usize, null), dt.firstInvalidFormatChar("YYYY[abc"));
    // four S: the first three are SSS, the fourth is a literal letter.
    try fmtEq("123S", .{ .nanosecond = 123_456_789 }, "SSSS");
}

test "audit: ISO week-year 0 renders, week-year tokens at the year edges" {
    // 0000-01-04 is a Tuesday in ISO week 1 of week-year 0.
    try fmtEq("0000-W01", .{ .year = 0, .month = 1, .day = 4 }, "GGGG-[W]WW");
    // 2021-01-03 (Sunday) belongs to week 53 of 2020; 2024-12-30 (Monday) to week 1 of 2025.
    try fmtEq("2020-W53", .{ .year = 2021, .month = 1, .day = 3 }, "GGGG-[W]WW");
    try fmtEq("2025-W01", .{ .year = 2024, .month = 12, .day = 30 }, "GGGG-[W]WW");
}

// ---------------------------------------------------------------------------
// parse: boundaries of the token engine
// ---------------------------------------------------------------------------

test "audit: parse -- a field that ends exactly at the end of the input" {
    try testing.expectEqual(@as(i32, 2024), (try parsed("24", "YY")).year);
    try testing.expectEqual(@as(u32, 12), (try parsed("12", "MM")).month);
    try testing.expectEqual(@as(u32, 3), (try parsed("Mar", "MMM")).month);
    try testing.expectEqual(@as(u32, 3), (try parsed("March", "MMMM")).month);
    _ = try parsed("Monday", "EEEE");
    _ = try parsed("Mon", "EEE");
    // GGGG alone: week 1 of the week-year, Monday
    const g = try parsed("2024", "GGGG");
    try testing.expectEqual(@as(u32, 1), g.day);
    try testing.expectEqual(@as(u32, 1), g.month);
    try testing.expectEqual(@as(i32, 2024), g.year);
    const w = try parsed("05", "WW");
    try testing.expectEqual(@as(u32, 26), w.day); // 1970-W05-1 = 1970-01-26
    try testing.expectEqual(@as(u32, 10), (try parsed("10", "hh")).hour);
    // two-digit short tokens read two digits
    const hms = try parsed("23:59:58", "h:m:s");
    try testing.expectEqual(@as(u32, 23), hms.hour);
    try testing.expectEqual(@as(u32, 59), hms.minute);
    try testing.expectEqual(@as(u32, 58), hms.second);
    const wk = try parsed("12", "W"); // 1970-W12-1 = 1970-03-16
    try testing.expectEqual(@as(u32, 3), wk.month);
    try testing.expectEqual(@as(u32, 16), wk.day);
    // `e` reads exactly one digit; the second is left unread
    _ = try parsed("12", "e");
    // digits next to the range ends: '9' is a digit, ':' is not
    try testing.expectEqual(@as(u32, 9), (try parsed("9/9/2024", "M/D/YYYY")).month);
    try testing.expectEqual(@as(u32, 9), (try parsed("9/9/2024", "M/D/YYYY")).day);
}

test "audit: parse -- a missing value is the typed error of its field, not a zero" {
    try testing.expectError(error.InvalidTime, parsed("x", "h"));
    try testing.expectError(error.InvalidTime, parsed("x", "m"));
    try testing.expectError(error.InvalidTime, parsed("x", "s"));
    // truncated input: a token with nothing left is InvalidFormat, never InvalidDate
    try testing.expectError(error.InvalidFormat, parsed("2024", "YYYYM"));
    try testing.expectError(error.InvalidFormat, parsed("2024", "YYYYh"));
    try testing.expectError(error.InvalidFormat, parsed("2024", "YYYY-"));
    try testing.expectError(error.InvalidFormat, parsed("202", "YYYY"));
}

test "audit: parse -- [*] before each kind of token, with the match at the very end" {
    try testing.expectEqual(@as(i32, 2024), (try parsed("2024xT", "YYYY[*][T]")).year);
    try testing.expectEqual(@as(u32, 12), (try parsed("ab12", "[*]MM")).month);
    try testing.expectEqual(@as(u32, 1), (try parsed("xxJan", "[*]MMM")).month);
    _ = try parsed("xxMon", "[*]EEE");
    try testing.expectEqual(@as(u32, 3), (try parsed("xxMarch", "[*]MMMM")).month);
    _ = try parsed("xxMonday", "[*]EEEE");
    try testing.expectEqual(@as(u32, 12), (try parsed("xxPM", "[*]A")).hour);
    try testing.expectEqual(@as(u32, 0), (try parsed("xxAM", "[*]A")).hour);
    try testing.expectEqual(@as(u32, 0), (try parsed("x0", "[*]m")).minute);
    try testing.expectEqual(@as(u32, 9), (try parsed("x9", "[*]m")).minute);
    try testing.expectEqual(@as(?i32, 0), (try parsed("abc z", "[*]ZZ")).off_min);
    try testing.expectEqual(@as(?i32, -300), (try parsed("abc-05:00", "[*]ZZ")).off_min);
    try testing.expectEqual(@as(?i32, 120), (try parsed("abc+02:00", "[*]ZZ")).off_min);
}

test "audit: parse -- am/pm in either case, noon, midnight, 13 PM" {
    try testing.expectEqual(@as(u32, 7), (try parsed("07:05 am", "hh:mm a")).hour);
    try testing.expectEqual(@as(u32, 19), (try parsed("07:05 pm", "hh:mm a")).hour);
    try testing.expectEqual(@as(u32, 7), (try parsed("07:05 AM", "hh:mm A")).hour);
    try testing.expectEqual(@as(u32, 19), (try parsed("07:05 PM", "hh:mm A")).hour);
    try testing.expectEqual(@as(u32, 12), (try parsed("12 PM", "ii A")).hour);
    try testing.expectEqual(@as(u32, 0), (try parsed("12 AM", "ii A")).hour);
    try testing.expectEqual(@as(u32, 13), (try parsed("01 PM", "ii A")).hour);
    try testing.expectError(error.InvalidTime, parsed("13 PM", "ii A"));
    try testing.expectError(error.InvalidTime, parsed("07 XM", "ii A"));
    // lower-case z is UTC
    try testing.expectEqual(@as(?i32, 0), (try parsed("10:00z", "hh:mmZZ")).off_min);
}

test "audit: parse -- defaults of the absent fields, ISO week fallbacks" {
    const y = try parsed("2024", "YYYY");
    try testing.expectEqual(@as(u32, 1), y.month);
    try testing.expectEqual(@as(u32, 1), y.day);
    try testing.expectEqual(@as(u32, 0), y.hour);
    // GGGG without W: week 1 (Monday); the civil default 1970 must not win
    const g = try parsed("2021", "GGGG");
    try testing.expectEqual(@as(i32, 2021), g.year);
    try testing.expectEqual(@as(u32, 1), g.month);
    try testing.expectEqual(@as(u32, 4), g.day);
    // W with a YYYY: the week-year defaults to YYYY, not to 1970
    const w = try parsed("2021 05", "YYYY WW");
    try testing.expectEqual(@as(i32, 2021), w.year);
    try testing.expectEqual(@as(u32, 2), w.month);
    try testing.expectEqual(@as(u32, 1), w.day);
    // week 1 by default when only the week-year is there; weekday 1 by default
    try testing.expectEqual(@as(u32, 4), (try parsed("2021", "GGGG")).day);
    try testing.expectEqual(@as(u32, 5), (try parsed("2021 2", "GGGG e")).day); // Tuesday of week 1
}

test "audit: parse -- a bad date with a time at the edge of its range is InvalidDate" {
    try testing.expectError(error.InvalidDate, parsed("2023-02-30 23:10:00", "YYYY-MM-DD hh:mm:ss"));
    try testing.expectError(error.InvalidDate, parsed("2023-02-30 10:59:00", "YYYY-MM-DD hh:mm:ss"));
    try testing.expectError(error.InvalidDate, parsed("2023-02-30 10:10:59", "YYYY-MM-DD hh:mm:ss"));
    try testing.expectError(error.InvalidTime, parsed("2023-02-28 24:00:00", "YYYY-MM-DD hh:mm:ss"));
    try testing.expectError(error.InvalidTime, parsed("2023-02-28 10:60:00", "YYYY-MM-DD hh:mm:ss"));
    try testing.expectError(error.InvalidTime, parsed("2023-02-28 10:10:60", "YYYY-MM-DD hh:mm:ss"));
}

// ---------------------------------------------------------------------------
// Arithmetic
// ---------------------------------------------------------------------------

test "audit: addDays / addMonths / addYears keep the whole time of day" {
    const t = DateParts{ .year = 2024, .month = 1, .day = 31, .hour = 10, .minute = 20, .second = 30, .nanosecond = 500 };
    const d1 = dt.addDays(t, 1);
    try testing.expectEqual(DateParts{ .year = 2024, .month = 2, .day = 1, .hour = 10, .minute = 20, .second = 30, .nanosecond = 500 }, d1);
    const m1 = dt.addMonths(t, 1);
    try testing.expectEqual(DateParts{ .year = 2024, .month = 2, .day = 29, .hour = 10, .minute = 20, .second = 30, .nanosecond = 500 }, m1);
    const y1 = dt.addYears(.{ .year = 2024, .month = 3, .day = 1, .hour = 1, .minute = 2, .second = 3 }, 1);
    try testing.expectEqual(DateParts{ .year = 2025, .month = 3, .day = 1, .hour = 1, .minute = 2, .second = 3 }, y1);
    const leap = dt.addYears(.{ .year = 2024, .month = 2, .day = 29 }, 1);
    try testing.expectEqual(@as(u32, 28), leap.day);
    try testing.expectEqual(@as(i32, 2025), leap.year);
    const back = dt.addYears(.{ .year = 2024, .month = 2, .day = 29 }, -4);
    try testing.expectEqual(@as(i32, 2020), back.year);
    try testing.expectEqual(@as(u32, 29), back.day);
    try testing.expectEqual(@as(i32, 6), dt.diffInYears(.{ .year = 2030 }, .{ .year = 2024 }));
    try testing.expectEqual(@as(i32, -6), dt.diffInYears(.{ .year = 2024 }, .{ .year = 2030 }));
}

test "audit: startOf / endOf" {
    const t = DateParts{ .year = 2024, .month = 2, .day = 10, .hour = 10, .minute = 20, .second = 30, .nanosecond = 5 };
    const sd = dt.startOfDay(t);
    try testing.expectEqual(@as(u32, 10), sd.day);
    try testing.expectEqual(@as(u32, 0), sd.hour);
    const ed = dt.endOfDay(t);
    try testing.expectEqual(@as(u32, 10), ed.day);
    try testing.expectEqual(@as(u32, 23), ed.hour);
    try testing.expectEqual(@as(u32, 59), ed.minute);
    try testing.expectEqual(@as(u32, 59), ed.second);
    const sm = dt.startOfMonth(t);
    try testing.expectEqual(@as(u32, 1), sm.day);
    try testing.expectEqual(@as(u32, 2), sm.month);
    const em = dt.endOfMonth(t);
    try testing.expectEqual(@as(u32, 29), em.day);
    try testing.expectEqual(@as(u32, 23), em.hour);
    try testing.expectEqual(@as(u32, 59), em.minute);
    try testing.expectEqual(@as(u32, 59), em.second);
    const sy = dt.startOfYear(t);
    try testing.expectEqual(@as(u32, 1), sy.month);
    try testing.expectEqual(@as(u32, 1), sy.day);
    const ey = dt.endOfYear(t);
    try testing.expectEqual(@as(u32, 12), ey.month);
    try testing.expectEqual(@as(u32, 31), ey.day);
    try testing.expectEqual(@as(u32, 23), ey.hour);
    try testing.expectEqual(@as(u32, 59), ey.minute);
    try testing.expectEqual(@as(u32, 59), ey.second);
}

test "audit: nthWeekdayOfMonth in December, and the range edges of its arguments" {
    const mon = dt.nthWeekdayOfMonth(2024, 12, 1, 1).?; // Monday 2024-12-02
    try testing.expectEqual(@as(u32, 2), mon.day);
    const last = dt.nthWeekdayOfMonth(2024, 12, 2, -1).?; // last Tuesday: 2024-12-31
    try testing.expectEqual(@as(u32, 31), last.day);
    try testing.expect(dt.nthWeekdayOfMonth(2024, 1, 7, 1) != null);
    try testing.expect(dt.nthWeekdayOfMonth(2024, 12, 7, 1) != null); // weekday 7 is valid
    try testing.expect(dt.nthWeekdayOfMonth(2024, 13, 1, 1) == null);
    try testing.expect(dt.nthWeekdayOfMonth(2024, 0, 1, 1) == null);
    try testing.expect(dt.nthWeekdayOfMonth(2024, 1, 8, 1) == null);
    try testing.expect(dt.nthWeekdayOfMonth(2024, 1, 0, 1) == null);
    try testing.expect(dt.nthWeekdayOfMonth(2024, 1, 1, 0) == null);
}

// ---------------------------------------------------------------------------
// Strict / canned formats
// ---------------------------------------------------------------------------

test "audit: parseIsoDate -- first and last month, first day, and each separator" {
    const a = try dt.parseIsoDate("2024-01-01");
    try testing.expectEqual(@as(u32, 1), a.month);
    try testing.expectEqual(@as(u32, 1), a.day);
    const b = try dt.parseIsoDate("2024-12-31");
    try testing.expectEqual(@as(u32, 12), b.month);
    try testing.expectEqual(@as(u32, 31), b.day);
    try testing.expectError(error.InvalidDate, dt.parseIsoDate("2024/01-15"));
    try testing.expectError(error.InvalidDate, dt.parseIsoDate("2024-01/15"));
    try testing.expectError(error.InvalidDate, dt.parseIsoDate("2024-00-15"));
    try testing.expectError(error.InvalidDate, dt.parseIsoDate("2024-13-15"));
    try testing.expectError(error.InvalidDate, dt.parseIsoDate("2024-01-00"));
}

test "audit: RFC 3339 -- every separator, the colon of the offset, the largest fraction" {
    try testing.expectError(error.InvalidFormat, dt.parseRfc3339("2024/01-01T00:00:00Z"));
    try testing.expectError(error.InvalidFormat, dt.parseRfc3339("2024-01/01T00:00:00Z"));
    try testing.expectError(error.InvalidFormat, dt.parseRfc3339("2024-01-01T00-00:00Z"));
    try testing.expectError(error.InvalidFormat, dt.parseRfc3339("2024-01-01T00:00-00Z"));
    try testing.expectError(error.InvalidFormat, dt.parseRfc3339("2024-01-01T00:00:00+02x00"));
    var buf: [dt.rfc3339_max_len]u8 = undefined;
    const s = try dt.bufRfc3339(&buf, .{ .year = 2024, .month = 5, .day = 6, .hour = 7, .minute = 8, .second = 9, .nanosecond = 999_999_999 }, 9);
    try testing.expectEqualStrings("2024-05-06T07:08:09.999999999Z", s);
    const s3 = try dt.bufRfc3339(&buf, .{ .year = 2024, .month = 5, .day = 6, .nanosecond = 999_999_999 }, 3);
    try testing.expectEqualStrings("2024-05-06T00:00:00.999Z", s3);
    // the widest output: 9 fraction digits and a numeric offset
    const wide = try dt.bufRfc3339(&buf, .{ .year = 9999, .month = 12, .day = 31, .hour = 23, .minute = 59, .second = 59, .nanosecond = 999_999_999, .off_min = -(23 * 60 + 59) }, 9);
    try testing.expectEqual(@as(usize, dt.rfc3339_max_len), wide.len);
    try testing.expectEqualStrings("9999-12-31T23:59:59.999999999-23:59", wide);
}

test "audit: IMF-fixdate -- each separator is checked" {
    const good = "Sun, 06 Nov 1994 08:49:37 GMT";
    _ = try dt.parseImfFixdate(good);
    const bad_at = [_]usize{ 3, 4, 7, 11, 16, 19, 22 };
    for (bad_at) |i| {
        var s: [good.len]u8 = good.*;
        s[i] = 'x';
        try testing.expectError(error.InvalidFormat, dt.parseImfFixdate(&s));
    }
}

test "audit: RFC 2822 -- offsets of a whole day, digit counts of day and year, a bare CR" {
    var buf: [dt.rfc2822_len]u8 = undefined;
    try testing.expectError(error.InvalidTime, dt.bufRfc2822(&buf, .{ .off_min = -24 * 60 }));
    try testing.expectError(error.InvalidTime, dt.bufRfc2822(&buf, .{ .off_min = 24 * 60 }));
    try dt.bufRfc2822(&buf, .{ .year = 1997, .month = 11, .day = 21, .hour = 9, .minute = 55, .second = 6, .off_min = -(23 * 60 + 59) });
    try testing.expectEqualStrings("Fri, 21 Nov 1997 09:55:06 -2359", &buf);
    try dt.bufRfc2822(&buf, .{ .year = 1997, .month = 11, .day = 21, .hour = 9, .minute = 55, .second = 6 });
    try testing.expectEqualStrings("Fri, 21 Nov 1997 09:55:06 +0000", &buf);
    try testing.expectError(error.InvalidFormat, dt.parseRfc2822("123 Jan 2024 10:00 +0000"));
    try testing.expectError(error.InvalidFormat, dt.parseRfc2822("1 Jan 5 10:00 +0000"));
    try testing.expectError(error.InvalidDate, dt.parseRfc2822("1 Jan 12345 10:00 +0000"));
    try testing.expectError(error.InvalidFormat, dt.parseRfc2822("Fri,\rx 21 Nov 1997 09:55:06 -0600"));
    // a folded header is fine
    const folded = try dt.parseRfc2822("Fri, 21 Nov 1997\r\n 09:55:06 -0600");
    try testing.expectEqual(@as(u32, 9), folded.hour);
}

test "audit: parseDuration reaches minInt(i64) through a fraction" {
    try testing.expectEqual(@as(i64, std.math.minInt(i64)), try dt.parseDuration("-9223372036854775.808us"));
    try testing.expectEqual(@as(i64, std.math.maxInt(i64)), try dt.parseDuration("9223372036854775.807us"));
    try testing.expectError(error.InvalidDuration, dt.parseDuration("9223372036854775.808us"));
}

test "audit: xsd:dateTime -- the shortest form and each separator" {
    try testing.expectEqual(@as(i64, 1705312800), try dt.parseXsdDateTime("2024-01-15T10:00:00"));
    try testing.expectError(error.InvalidDateTime, dt.parseXsdDateTime("2024/01-15T10:00:00Z"));
    try testing.expectError(error.InvalidDateTime, dt.parseXsdDateTime("2024-01/15T10:00:00Z"));
    try testing.expectError(error.InvalidDateTime, dt.parseXsdDateTime("2024-01-15T10-00:00Z"));
    try testing.expectError(error.InvalidDateTime, dt.parseXsdDateTime("2024-01-15T10:00-00Z"));
    try testing.expectError(error.InvalidDateTime, dt.parseXsdDateTime("2024-01-15T10:00:0"));
}

test "audit MED1: calendar arithmetic at the integer edges saturates instead of trapping" {
    const p = DateParts{ .year = 2024, .month = 3, .day = 15 };
    // `n * 12` overflowed i32 above ~178 million years; the year itself fits.
    try testing.expectEqual(@as(i32, 200_002_024), dt.addYears(p, 200_000_000).year);
    try testing.expectEqual(@as(i32, -199_997_976), dt.addYears(p, -200_000_000).year);
    try testing.expectEqual(@as(i32, std.math.maxInt(i32)), dt.addYears(p, std.math.maxInt(i32)).year);
    try testing.expectEqual(@as(i32, std.math.minInt(i32) + 2024), dt.addYears(p, std.math.minInt(i32)).year);
    try testing.expectEqual(@as(i32, 2024 + (11 + std.math.maxInt(i32)) / 12), dt.addMonths(.{ .year = 2024, .month = 12, .day = 1 }, std.math.maxInt(i32)).year);
    try testing.expectEqual(@as(i32, std.math.maxInt(i32)), dt.diffInMonths(.{ .year = std.math.maxInt(i32) }, .{ .year = std.math.minInt(i32) }));
    try testing.expectEqual(@as(i32, std.math.maxInt(i32)), dt.addDays(p, std.math.maxInt(i64)).year);
    try testing.expectEqual(@as(i32, std.math.minInt(i32)), dt.epochDayToYmd(std.math.minInt(i64)).year);
    try testing.expect(dt.nthWeekdayOfMonth(2024, 3, 7, std.math.minInt(i32)) == null);
    try testing.expect(dt.nthWeekdayOfMonth(2024, 3, 7, std.math.maxInt(i32)) == null);
    try testing.expect(dt.nthWeekdayOfMonth(2024, 3, 5, 5) != null); // March 2024 has five Fridays
}

test "audit MED2: an out-of-month day extrapolates instead of trapping" {
    try testing.expectEqual(dt.ymdToEpochDay(2024, 2, 29), dt.ymdToEpochDay(2024, 3, 0));
    const s = try dt.format(testing.allocator, .{ .year = 2024, .month = 3, .day = 0 }, "e");
    defer testing.allocator.free(s);
    try testing.expectEqualStrings("4", s); // 2024-02-29 was a Thursday
}

test "audit MED3: endOf* is never earlier than any instant of its period" {
    const t = DateParts{ .year = 2024, .month = 2, .day = 29, .hour = 23, .minute = 59, .second = 59, .nanosecond = 500 };
    try testing.expectEqual(@as(u32, 999_999_999), dt.endOfDay(t).nanosecond);
    try testing.expectEqual(@as(u32, 999_999_999), dt.endOfMonth(t).nanosecond);
    try testing.expectEqual(@as(u32, 999_999_999), dt.endOfYear(t).nanosecond);
}
