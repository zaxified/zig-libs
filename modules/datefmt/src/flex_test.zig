// SPDX-License-Identifier: MIT

//! `ParseOptions` (flexible width, strict), the strftime syntax, and the
//! `Weekday` / `Month` / `WeekdaySet` / `Week` / `addTimeOfDay` helpers.
//! Public API only; expected values written by hand from chrono's and
//! Python's documented reading rules.

const std = @import("std");
const testing = std.testing;
const dt = @import("root.zig");

const DateParts = dt.DateParts;
const flex: dt.ParseOptions = .{ .flexible_width = true };

test "flexible_width: 1..width digits unless a digit follows" {
    const p = try dt.parseOpts("2021-3-4", "YYYY-MM-DD", flex);
    try testing.expectEqual(DateParts{ .year = 2021, .month = 3, .day = 4 }, p);
    try testing.expectError(error.InvalidDate, dt.parse("2021-3-4", "YYYY-MM-DD"));
    const t = try dt.parseOpts("2021-03-04 9:5:1", "YYYY-MM-DD hh:mm:ss", flex);
    try testing.expectEqual(@as(u32, 9), t.hour);
    try testing.expectEqual(@as(u32, 5), t.minute);
    try testing.expectEqual(@as(u32, 1), t.second);
    // Adjacent digits keep their width: `MM` stays two digits in front of `DD`.
    const c = try dt.parseOpts("20210304", "YYYYMMDD", flex);
    try testing.expectEqual(DateParts{ .year = 2021, .month = 3, .day = 4 }, c);
    try testing.expectError(error.InvalidFormat, dt.parseOpts("2021034", "YYYYMMDD", .{}));
    const c2 = try dt.parseOpts("2021034", "YYYYMMDD", flex);
    try testing.expectEqual(@as(u32, 4), c2.day); // 03 then the last field reads one digit
    // No digit at all is still an error, and so is a one-digit year.
    try testing.expectError(error.InvalidDate, dt.parseOpts("2021--4", "YYYY-MM-DD", flex));
    try testing.expectError(error.InvalidDate, dt.parseOpts("21-3-4", "YYYY-MM-DD", flex));
    // `ii`, `WW`.
    const h = try dt.parseOpts("9:05 PM", "ii:mm A", flex);
    try testing.expectEqual(@as(u32, 21), h.hour);
    const w = try dt.parseOpts("2021-W9-1", "GGGG-[W]WW-e", flex);
    try testing.expectEqual(DateParts{ .year = 2021, .month = 3, .day = 1 }, w);
}

test "flexible_width: short fractions and +hh offsets" {
    const f = try dt.parseOpts("05.5", "ss.SSS", flex);
    try testing.expectEqual(@as(u32, 500_000_000), f.nanosecond);
    const f2 = try dt.parseOpts("05.123456 UTC", "ss.SSSSSSSSS[ UTC]", flex);
    try testing.expectEqual(@as(u32, 123_456_000), f2.nanosecond);
    try testing.expectError(error.InvalidFormat, dt.parse("05.5", "ss.SSS"));
    try testing.expectError(error.InvalidFormat, dt.parseOpts("05.", "ss.SSS", flex));
    try testing.expectError(error.InvalidTime, dt.parseOpts("05.x", "ss.SSS", flex));
    const a = try dt.parseOpts("12:00 +09", "hh:mm ZZ", flex);
    try testing.expectEqual(@as(?i32, 540), a.off_min);
    const b = try dt.parseOpts("12:00 -0930", "hh:mm ZZ", flex);
    try testing.expectEqual(@as(?i32, -570), b.off_min);
    const c = try dt.parseOpts("12:00 +09:30", "hh:mm ZZ", flex);
    try testing.expectEqual(@as(?i32, 570), c.off_min);
    try testing.expectError(error.InvalidTime, dt.parse("12:00 +09", "hh:mm ZZ"));
    // Not minutes: `+09` then a non-digit.
    const d = try dt.parseOpts("12:00 +09 x", "hh:mm ZZ[ x]", flex);
    try testing.expectEqual(@as(?i32, 540), d.off_min);
}

test "strict: whole input, 12-hour range, real weekday" {
    const s: dt.ParseOptions = .{ .strict = true };
    _ = try dt.parseOpts("2021-03-04", "YYYY-MM-DD", s);
    try testing.expectError(error.InvalidFormat, dt.parseOpts("2021-03-04x", "YYYY-MM-DD", s));
    _ = try dt.parse("2021-03-04x", "YYYY-MM-DD");
    try testing.expectError(error.InvalidTime, dt.parseOpts("13:00 AM", "ii:mm A", s));
    try testing.expectError(error.InvalidTime, dt.parseOpts("0:00 AM", "ii:mm A", s));
    try testing.expectError(error.InvalidTime, dt.parseOpts("13:00 AM", "i:mm A", s));
    const lax = try dt.parse("13:00 AM", "ii:mm A");
    try testing.expectEqual(@as(u32, 13), lax.hour);
    _ = try dt.parseOpts("12:00 AM", "ii:mm A", s);
    _ = try dt.parseOpts("Thu 2021-03-04", "EEE YYYY-MM-DD", s);
    try testing.expectError(error.InvalidDate, dt.parseOpts("Mon 2021-03-04", "EEE YYYY-MM-DD", s));
    try testing.expectError(error.InvalidDate, dt.parseOpts("Monday 2021-03-04", "EEEE YYYY-MM-DD", s));
    try testing.expectError(error.InvalidDate, dt.parseOpts("1 2021-03-04", "e YYYY-MM-DD", s));
    _ = try dt.parseOpts("4 2021-03-04", "e YYYY-MM-DD", s);
    _ = try dt.parse("Mon 2021-03-04", "EEE YYYY-MM-DD");
    // A wildcard to the end is the whole input.
    _ = try dt.parseOpts("2021-03-04 trailing", "YYYY-MM-DD[*]", s);
    // The prefix form has no end to check.
    const m = try dt.parsePrefixOpts("2021-03-04x", "YYYY-MM-DD", .{ .strict = true, .flexible_width = true });
    try testing.expectEqual(@as(usize, 10), m.len);
}

test "strftime: parse reads flexible fields, format writes padded ones" {
    const gpa = testing.allocator;
    const p = try dt.parseStrftime("2021-3-4 9:05:01", "%Y-%m-%d %H:%M:%S");
    try testing.expectEqual(DateParts{ .year = 2021, .month = 3, .day = 4, .hour = 9, .minute = 5, .second = 1 }, p);
    const q = try dt.parseStrftime("2021-03-04T09:05:01+0530", "%FT%T%z");
    try testing.expectEqual(@as(?i32, 330), q.off_min);
    const r = try dt.parseStrftime("Thu, 04 Mar 2021 21:05:01 +09", "%a, %d %b %Y %T %z");
    try testing.expectEqual(@as(u32, 21), r.hour);
    try testing.expectEqual(@as(?i32, 540), r.off_min);
    const x = try dt.parseStrftime("03/04/21 09:05:01 PM", "%D %r");
    try testing.expectEqual(DateParts{ .year = 2021, .month = 3, .day = 4, .hour = 21, .minute = 5, .second = 1 }, x);
    const f = try dt.parseStrftime("12:00:01.5", "%T.%f");
    try testing.expectEqual(@as(u32, 500_000_000), f.nanosecond);
    const f2 = try dt.parseStrftime("12:00:01.250", "%T%.3f");
    try testing.expectEqual(@as(u32, 250_000_000), f2.nanosecond);
    const o = try dt.parseStrftime("100%", "%j%%");
    try testing.expectEqual(DateParts{ .year = 1970, .month = 4, .day = 10 }, o);

    const parts = DateParts{ .year = 2021, .month = 3, .day = 4, .hour = 21, .minute = 5, .second = 1, .nanosecond = 123_456_789, .off_min = 330 };
    const cases = [_]struct { fmt: []const u8, want: []const u8 }{
        .{ .fmt = "%Y-%m-%d %H:%M:%S", .want = "2021-03-04 21:05:01" },
        .{ .fmt = "%F %T", .want = "2021-03-04 21:05:01" },
        .{ .fmt = "%-d/%-m/%y %-H:%-M:%-S", .want = "4/3/21 21:5:1" },
        .{ .fmt = "%A %a %B %b %h %j", .want = "Thursday Thu March Mar Mar 063" },
        .{ .fmt = "%I:%M %p %P|%r|%R", .want = "09:05 PM pm|09:05:01 PM|21:05" },
        .{ .fmt = "%z|%:z", .want = "+0530|+05:30" },
        .{ .fmt = "%f|%3f|%6f|%9f", .want = "123456789|123|123456|123456789" },
        .{ .fmt = "%S%.3f|%S%.6f", .want = "01.123|01.123456" },
        .{ .fmt = "%G-W%V-%u", .want = "2021-W09-4" },
        .{ .fmt = "%D %x %X", .want = "03/04/21 03/04/21 21:05:01" },
        .{ .fmt = "100%% a%tb%nc", .want = "100% a\tb\nc" },
    };
    for (cases) |c| {
        const got = try dt.formatStrftime(gpa, parts, c.fmt);
        defer gpa.free(got);
        try testing.expectEqualStrings(c.want, got);
    }
    // The same layout through the compiled form, strict and flexible.
    const l = try dt.Layout.compileStrftime("%Y-%m-%d");
    try testing.expectError(error.InvalidDate, l.parse("2021-3-4"));
    _ = try l.parseOpts("2021-3-4", flex);
}

test "strftime: directives without a token are refused by name" {
    const refused = [_][]const u8{
        "%e",  "%k",  "%l", "%_d", "%Z", "%s", "%c", "%U", "%W", "%w",  "%C", "%g", "%.f", "%.2f",
        "%-y", "%-j", "%+", "%E",  "%q", "%",  "%-", "%:", "%3", "%3d", "%v",
    };
    for (refused) |f| {
        try testing.expectError(error.InvalidFormatString, dt.parseStrftime("x", f));
        try testing.expectError(error.InvalidFormatString, dt.formatStrftime(testing.allocator, .{}, f));
    }
    try testing.expectError(error.TooManyTokens, dt.Layout.compileStrftime("%F%F%F%F%F%F%F%F%F%F%F%F%F%F"));
}

test "Weekday and Month" {
    try testing.expectEqual(dt.Weekday.thu, dt.Weekday.of(.{ .year = 2021, .month = 3, .day = 4 }));
    try testing.expectEqual(@as(?dt.Weekday, .sun), dt.Weekday.fromNumber(7));
    try testing.expectEqual(@as(?dt.Weekday, null), dt.Weekday.fromNumber(0));
    try testing.expectEqual(@as(?dt.Weekday, null), dt.Weekday.fromNumber(8));
    try testing.expectEqualStrings("Wednesday", dt.Weekday.wed.name());
    try testing.expectEqualStrings("Wed", dt.Weekday.wed.short());
    try testing.expectEqual(@as(?dt.Weekday, .fri), dt.Weekday.parse("FRIDAY"));
    try testing.expectEqual(@as(?dt.Weekday, .fri), dt.Weekday.parse("fri"));
    try testing.expectEqual(@as(?dt.Weekday, null), dt.Weekday.parse("Fr"));
    try testing.expectEqual(@as(?dt.Weekday, null), dt.Weekday.parse("Fridays"));
    try testing.expectEqual(dt.Weekday.mon, dt.Weekday.sun.next());
    try testing.expectEqual(dt.Weekday.sun, dt.Weekday.mon.prev());
    try testing.expectEqual(dt.Weekday.tue, dt.Weekday.mon.next());
    try testing.expectEqual(dt.Weekday.sat, dt.Weekday.sun.prev());
    try testing.expectEqual(@as(u32, 3), dt.Weekday.fri.daysUntil(.mon));
    try testing.expectEqual(@as(u32, 0), dt.Weekday.fri.daysUntil(.fri));
    for (1..8) |n| {
        const d = dt.Weekday.fromNumber(@intCast(n)).?;
        try testing.expectEqual(@as(u32, @intCast(n)), d.number());
        try testing.expectEqual(d, d.next().prev());
        try testing.expectEqual(d, dt.Weekday.parse(d.name()).?);
    }

    try testing.expectEqual(@as(?dt.Month, .dec), dt.Month.fromNumber(12));
    try testing.expectEqual(@as(?dt.Month, null), dt.Month.fromNumber(13));
    try testing.expectEqual(@as(?dt.Month, null), dt.Month.fromNumber(0));
    try testing.expectEqual(@as(?dt.Month, .mar), dt.Month.of(.{ .year = 2021, .month = 3, .day = 4 }));
    try testing.expectEqualStrings("September", dt.Month.sep.name());
    try testing.expectEqualStrings("Sep", dt.Month.sep.short());
    try testing.expectEqual(@as(?dt.Month, .sep), dt.Month.parse("sEpTeMbEr"));
    try testing.expectEqual(@as(?dt.Month, .sep), dt.Month.parse("SEP"));
    try testing.expectEqual(@as(?dt.Month, null), dt.Month.parse("Sept"));
    try testing.expectEqual(dt.Month.jan, dt.Month.dec.next());
    try testing.expectEqual(dt.Month.dec, dt.Month.jan.prev());
    try testing.expectEqual(@as(u32, 29), dt.Month.feb.days(2024));
    try testing.expectEqual(@as(u32, 28), dt.Month.feb.days(2023));
    for (1..13) |n| {
        const m = dt.Month.fromNumber(@intCast(n)).?;
        try testing.expectEqual(@as(u32, @intCast(n)), m.number());
        try testing.expectEqual(m, m.next().prev());
        try testing.expectEqual(m, dt.Month.parse(m.name()).?);
        try testing.expectEqual(m, dt.Month.parse(m.short()).?);
    }
}

test "WeekdaySet" {
    const s = dt.WeekdaySet.of(&.{ .mon, .wed, .wed });
    try testing.expectEqual(@as(u32, 2), s.len());
    try testing.expect(s.contains(.mon) and s.contains(.wed) and !s.contains(.tue));
    try testing.expect(dt.WeekdaySet.empty.isEmpty());
    try testing.expectEqual(@as(u32, 7), dt.WeekdaySet.all.len());
    try testing.expectEqual(@as(u32, 5), dt.WeekdaySet.weekdays.len());
    try testing.expect(dt.WeekdaySet.weekend.contains(.sat) and dt.WeekdaySet.weekend.contains(.sun));
    try testing.expectEqual(dt.WeekdaySet.all, dt.WeekdaySet.weekdays.unionWith(dt.WeekdaySet.weekend));
    try testing.expect(dt.WeekdaySet.weekdays.intersect(dt.WeekdaySet.weekend).isEmpty());
    try testing.expectEqual(dt.WeekdaySet.weekend, dt.WeekdaySet.all.difference(dt.WeekdaySet.weekdays));
    try testing.expect(!s.without(.mon).contains(.mon) and s.with(.sun).contains(.sun));
    try testing.expect(s.containsDate(.{ .year = 2021, .month = 3, .day = 1 })); // a Monday
    try testing.expect(!s.containsDate(.{ .year = 2021, .month = 3, .day = 2 }));
    try testing.expectEqual(@as(?dt.Weekday, .wed), s.firstFrom(.tue));
    try testing.expectEqual(@as(?dt.Weekday, .mon), s.firstFrom(.thu)); // wraps
    try testing.expectEqual(@as(?dt.Weekday, null), dt.WeekdaySet.empty.firstFrom(.mon));
    try testing.expectEqual(@as(?dt.Weekday, .sun), dt.WeekdaySet.of(&.{.sun}).firstFrom(.sun));
}

test "Week" {
    const thu = DateParts{ .year = 2021, .month = 3, .day = 4 };
    const mon_week = dt.Week.of(thu, .mon);
    try testing.expectEqual(DateParts{ .year = 2021, .month = 3, .day = 1 }, mon_week.firstDay());
    try testing.expectEqual(DateParts{ .year = 2021, .month = 3, .day = 7 }, mon_week.lastDay());
    const sun_week = dt.Week.of(thu, .sun);
    try testing.expectEqual(DateParts{ .year = 2021, .month = 2, .day = 28 }, sun_week.firstDay());
    try testing.expectEqual(DateParts{ .year = 2021, .month = 3, .day = 6 }, sun_week.lastDay());
    // The first day itself, and the last day of the week, belong to their week.
    try testing.expectEqual(mon_week.first_epoch_day, dt.Week.of(.{ .year = 2021, .month = 3, .day = 1 }, .mon).first_epoch_day);
    try testing.expectEqual(mon_week.first_epoch_day, dt.Week.of(.{ .year = 2021, .month = 3, .day = 7 }, .mon).first_epoch_day);
    try testing.expectEqual(mon_week.first_epoch_day + 7, dt.Week.of(.{ .year = 2021, .month = 3, .day = 8 }, .mon).first_epoch_day);
    try testing.expectEqual(mon_week.day(3), thu);
    try testing.expectEqual(mon_week.day(9), mon_week.lastDay()); // clamped
    // Across a year boundary and before 1970.
    const ny = dt.Week.of(.{ .year = 2021, .month = 1, .day = 1 }, .mon);
    try testing.expectEqual(DateParts{ .year = 2020, .month = 12, .day = 28 }, ny.firstDay());
    const old = dt.Week.of(.{ .year = 1969, .month = 12, .day = 31 }, .mon);
    try testing.expectEqual(DateParts{ .year = 1969, .month = 12, .day = 29 }, old.firstDay());
}

test "addTimeOfDay wraps and reports the days" {
    const p = DateParts{ .year = 2021, .month = 3, .day = 4, .hour = 23, .minute = 30, .second = 0, .nanosecond = 500 };
    const a = dt.addTimeOfDay(p, 3_600 * 1_000_000_000);
    try testing.expectEqual(@as(i64, 1), a.days);
    try testing.expectEqual(@as(u32, 0), a.parts.hour);
    try testing.expectEqual(@as(u32, 30), a.parts.minute);
    try testing.expectEqual(@as(u32, 500), a.parts.nanosecond);
    try testing.expectEqual(@as(u32, 4), a.parts.day); // the date is not touched
    const b = dt.addTimeOfDay(.{ .hour = 0, .minute = 0, .second = 1 }, -2 * 1_000_000_000);
    try testing.expectEqual(@as(i64, -1), b.days);
    try testing.expectEqual(@as(u32, 23), b.parts.hour);
    try testing.expectEqual(@as(u32, 59), b.parts.minute);
    try testing.expectEqual(@as(u32, 59), b.parts.second);
    const c = dt.addTimeOfDay(p, 0);
    try testing.expectEqual(@as(i64, 0), c.days);
    try testing.expectEqual(p, c.parts);
    // The i64 extremes do not overflow.
    const lo = dt.addTimeOfDay(.{}, std.math.minInt(i64));
    try testing.expectEqual(@as(i64, -106752), lo.days);
    try testing.expectEqual(@as(u32, 12), lo.parts.minute);
    try testing.expectEqual(@as(u32, 43), lo.parts.second);
    try testing.expectEqual(@as(u32, 145_224_192), lo.parts.nanosecond);
    const hi = dt.addTimeOfDay(.{}, std.math.maxInt(i64));
    try testing.expectEqual(@as(i64, 106751), hi.days);
    try testing.expectEqual(@as(u32, 23), hi.parts.hour);
    try testing.expectEqual(@as(u32, 854_775_807), hi.parts.nanosecond);
    // Whole-day multiples round-trip through addDays.
    const d = dt.addTimeOfDay(p, 5 * 86_400 * 1_000_000_000);
    try testing.expectEqual(@as(i64, 5), d.days);
    try testing.expectEqual(p.hour, d.parts.hour);
    try testing.expectEqual(@as(u32, 9), dt.addDays(d.parts, d.days).day);
}
