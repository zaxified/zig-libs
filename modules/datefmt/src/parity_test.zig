// SPDX-License-Identifier: MIT

//! The 2026-11-05 parity row against chrono 0.4.45 and Go `time`: day of
//! year (`DDDD`, `%j`), the compact offset (`ZZZ`, `%z`), the trimmed
//! fraction (`FFF`, Go `.999`, chrono `%.f`), `parsePrefix`
//! (`parse_and_remainder`), `Layout.formatBuf` (`AppendFormat`),
//! `parseHttpDate` (RFC 9110 §5.6.7's three forms) and `truncateNs`/`roundNs`.

const std = @import("std");
const testing = std.testing;
const d = @import("root.zig");

fn fmtAlloc(parts: d.DateParts, f: []const u8) ![]u8 {
    return d.format(testing.allocator, parts, f);
}

fn expectFormat(expected: []const u8, parts: d.DateParts, f: []const u8) !void {
    const got = try fmtAlloc(parts, f);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(expected, got);
}

test "dayOfYear and quarter" {
    try testing.expectEqual(@as(u32, 1), d.dayOfYear(.{ .year = 2023, .month = 1, .day = 1 }));
    try testing.expectEqual(@as(u32, 60), d.dayOfYear(.{ .year = 2023, .month = 3, .day = 1 }));
    try testing.expectEqual(@as(u32, 61), d.dayOfYear(.{ .year = 2024, .month = 3, .day = 1 }));
    try testing.expectEqual(@as(u32, 366), d.dayOfYear(.{ .year = 2024, .month = 12, .day = 31 }));
    try testing.expectEqual(@as(u32, 365), d.dayOfYear(.{ .year = 1900, .month = 12, .day = 31 }));
    try testing.expectEqual(@as(u32, 366), d.dayOfYear(.{ .year = -4, .month = 12, .day = 31 }));
    // Out of range: 0, never a trap.
    try testing.expectEqual(@as(u32, 0), d.dayOfYear(.{ .year = 2023, .month = 2, .day = 29 }));
    try testing.expectEqual(@as(u32, 0), d.dayOfYear(.{ .year = 2023, .month = 13, .day = 1 }));
    try testing.expectEqual(@as(u32, 0), d.dayOfYear(.{ .year = 2023, .month = 0, .day = 1 }));
    try testing.expectEqual(@as(u32, 0), d.dayOfYear(.{ .year = std.math.maxInt(i32), .month = 1, .day = 0 }));
    try testing.expectEqual(@as(u32, 366), d.dayOfYear(.{ .year = std.math.minInt(i32), .month = 12, .day = 31 }));

    for (1..13) |m| try testing.expectEqual(@as(u32, @intCast((m - 1) / 3 + 1)), d.quarter(.{ .month = @intCast(m) }));
    try testing.expectEqual(@as(u32, 0), d.quarter(.{ .month = 0 }));
    try testing.expectEqual(@as(u32, 0), d.quarter(.{ .month = 13 }));
}

test "DDDD: format and parse the day of year" {
    try expectFormat("2024-060", .{ .year = 2024, .month = 2, .day = 29 }, "YYYY-DDDD");
    try expectFormat("2023-001", .{ .year = 2023, .month = 1, .day = 1 }, "YYYY-DDDD");
    try expectFormat("2024-366", .{ .year = 2024, .month = 12, .day = 31 }, "YYYY-DDDD");

    const p = try d.parse("2024-060", "YYYY-DDDD");
    try testing.expectEqual(@as(u32, 2), p.month);
    try testing.expectEqual(@as(u32, 29), p.day);
    const q = try d.parse("2023-365T10:00", "YYYY-DDDDThh:mm");
    try testing.expectEqual(@as(u32, 12), q.month);
    try testing.expectEqual(@as(u32, 31), q.day);
    try testing.expectEqual(@as(u32, 10), q.hour);
    // DDDD overrides MM/DD, as a week token does.
    const r = try d.parse("2024-05-05 032", "YYYY-MM-DD DDDD");
    try testing.expectEqual(@as(u32, 2), r.month);
    try testing.expectEqual(@as(u32, 1), r.day);

    try testing.expectError(d.ParseError.InvalidDate, d.parse("2023-366", "YYYY-DDDD"));
    try testing.expectError(d.ParseError.InvalidDate, d.parse("2023-000", "YYYY-DDDD"));
    try testing.expectError(d.ParseError.InvalidDate, d.parse("2023-999", "YYYY-DDDD"));
    try testing.expectError(d.ParseError.InvalidDate, d.parse("2023-+01", "YYYY-DDDD"));
    try testing.expectError(d.ParseError.InvalidFormat, d.parse("2023-01", "YYYY-DDDD"));

    // Round trip over two whole years, leap and common.
    for ([_]i32{ 2023, 2024 }) |y| {
        var day: i64 = d.ymdToEpochDay(y, 1, 1);
        while (d.epochDayToYmd(day).year == y) : (day += 1) {
            const parts = d.epochDayToYmd(day);
            const s = try fmtAlloc(parts, "YYYY.DDDD");
            defer testing.allocator.free(s);
            const back = try d.parse(s, "YYYY.DDDD");
            try testing.expectEqual(parts.month, back.month);
            try testing.expectEqual(parts.day, back.day);
        }
    }
}

test "ZZZ: compact offset" {
    try expectFormat("-0530", .{ .off_min = -330 }, "ZZZ");
    try expectFormat("+0100", .{ .off_min = 60 }, "ZZZ");
    try expectFormat("+0000", .{}, "ZZZ");
    try expectFormat("+00:00 +0000", .{ .off_min = 0 }, "ZZ ZZZ");
    try expectFormat("+2359", .{ .off_min = 23 * 60 + 59 }, "ZZZ");

    try testing.expectEqual(@as(?i32, 330), (try d.parse("+0530", "ZZZ")).off_min);
    try testing.expectEqual(@as(?i32, -60), (try d.parse("-01:00", "ZZZ")).off_min);
    try testing.expectEqual(@as(?i32, 0), (try d.parse("Z", "ZZZ")).off_min);
    try testing.expectError(d.ParseError.InvalidTime, d.parse("+2400", "ZZZ"));
    try testing.expectError(d.ParseError.InvalidTime, d.parse("+05", "ZZZ"));
    // A single Z stays a literal, as before.
    try expectFormat("12Z", .{ .hour = 12 }, "hhZ");
}

test "FFF: trimmed fraction, format" {
    const t: d.DateParts = .{ .hour = 12, .minute = 0, .second = 5 };
    var p = t;
    p.nanosecond = 120_000_000;
    try expectFormat("12:00:05.12", p, "hh:mm:ss.FFF");
    try expectFormat("12:00:05.12", p, "hh:mm:ss.FFFFFFFFF");
    try expectFormat("12:00:05,12", p, "hh:mm:ss,FFF");
    p.nanosecond = 123_456_789;
    try expectFormat("12:00:05.123", p, "hh:mm:ss.FFF"); // truncated, as SSS
    try expectFormat("12:00:05.123456", p, "hh:mm:ss.FFFFFF");
    try expectFormat("12:00:05.123456789", p, "hh:mm:ss.FFFFFFFFF");
    p.nanosecond = 100; // below the 6-digit width: a zero fraction
    try expectFormat("12:00:05", p, "hh:mm:ss.FFFFFF");
    try expectFormat("12:00:05.0000001", p, "hh:mm:ss.FFFFFFFFF");
    // A zero fraction drops the separator, and only that.
    try expectFormat("12:00:05Z", t, "hh:mm:ss.FFFZ");
    try expectFormat("12:00:05", t, "hh:mm:ss,FFF");
    try expectFormat("12:00:05 x", t, "hh:mm:ss[ x]FFF"); // no separator to drop
    try expectFormat("12:00:05 sec", t, "hh:mm:ss[ sec.]FFF"); // a bracketed separator drops its last byte only
    try expectFormat("", t, "FFF"); // first token, nothing in front
    p.nanosecond = 1_000_000_000;
    try testing.expectError(error.InvalidTime, fmtAlloc(p, "FFF"));
}

test "FFF: trimmed fraction, parse" {
    try testing.expectEqual(@as(u32, 0), (try d.parse("12:00:05", "hh:mm:ss.FFF")).nanosecond);
    try testing.expectEqual(@as(u32, 500_000_000), (try d.parse("12:00:05.5", "hh:mm:ss.FFF")).nanosecond);
    try testing.expectEqual(@as(u32, 120_000_000), (try d.parse("12:00:05,12", "hh:mm:ss,FFF")).nanosecond);
    try testing.expectEqual(@as(u32, 123_456_789), (try d.parse("12:00:05.123456789", "hh:mm:ss.FFFFFFFFF")).nanosecond);
    // No separator, no digits, then the next literal.
    const z = try d.parse("12:00:05Z", "hh:mm:ss.FFFZZ");
    try testing.expectEqual(@as(u32, 0), z.nanosecond);
    try testing.expectEqual(@as(?i32, 0), z.off_min);
    const off = try d.parse("12:00:05.25+01:00", "hh:mm:ss.FFFZZ");
    try testing.expectEqual(@as(u32, 250_000_000), off.nanosecond);
    try testing.expectEqual(@as(?i32, 60), off.off_min);
    // At most the token's width is read; the rest is left over.
    const m = try d.parsePrefix("12:00:05.1234", "hh:mm:ss.FFF");
    try testing.expectEqual(@as(u32, 123_000_000), m.parts.nanosecond);
    try testing.expectEqual(@as(usize, 12), m.len);
    // Without the separator nothing is read as a fraction.
    try testing.expectError(d.ParseError.InvalidFormat, d.parse("12:00:0512", "hh:mm:ss.FFF[x]"));
    // A bracketed separator: all of it, or all but its last byte.
    try testing.expectEqual(@as(u32, 0), (try d.parse("12:00:05 sec", "hh:mm:ss[ sec.]FFF")).nanosecond);
    try testing.expectEqual(@as(u32, 700_000_000), (try d.parse("12:00:05 sec.7", "hh:mm:ss[ sec.]FFF")).nanosecond);
    try testing.expectError(d.ParseError.InvalidFormat, d.parse("12:00:05 se", "hh:mm:ss[ sec.]FFF"));
    // An absent separator is only a zero fraction: the rest is left over.
    const left = try d.parsePrefix("12:00:05;5", "hh:mm:ss.FFF");
    try testing.expectEqual(@as(usize, 8), left.len);
    try testing.expectEqual(@as(u32, 0), left.parts.nanosecond);
}

test "FFF: format then parse returns the truncated fraction" {
    var prng = std.Random.DefaultPrng.init(0x0511);
    const rnd = prng.random();
    for (0..20_000) |_| {
        const ns = switch (rnd.uintLessThan(u8, 4)) {
            0 => 0,
            1 => rnd.uintLessThan(u32, 1000) * 1_000_000,
            2 => rnd.uintLessThan(u32, 10) * 100_000_000,
            else => rnd.uintLessThan(u32, 1_000_000_000),
        };
        const width: u8 = switch (rnd.uintLessThan(u8, 3)) {
            0 => 3,
            1 => 6,
            else => 9,
        };
        const sep: u8 = if (rnd.boolean()) '.' else ',';
        var fbuf: [32]u8 = undefined;
        const f = try std.fmt.bufPrint(&fbuf, "ss{c}{s}ZZ", .{ sep, "FFFFFFFFF"[0..width] });
        const parts: d.DateParts = .{ .second = 7, .nanosecond = ns, .off_min = 0 };
        const s = try fmtAlloc(parts, f);
        defer testing.allocator.free(s);
        const back = try d.parse(s, f);
        var scale: u32 = 1;
        for (0..9 - width) |_| scale *= 10;
        try testing.expectEqual(ns / scale * scale, back.nanosecond);
        try testing.expectEqual(@as(u32, 7), back.second);
    }
}

test "parsePrefix: how much input the format consumed" {
    const m = try d.parsePrefix("2024-01-02 rest", "YYYY-MM-DD");
    try testing.expectEqual(@as(usize, 10), m.len);
    try testing.expectEqual(@as(u32, 2), m.parts.day);
    const all = try d.parsePrefix("2024-01-02", "YYYY-MM-DD");
    try testing.expectEqual(@as(usize, 10), all.len);
    const w = try d.parsePrefix("2024 anything", "YYYY[*]");
    try testing.expectEqual(@as(usize, 13), w.len);
    const short = try d.parsePrefix("7/3/2024!", "D/M/YYYY");
    try testing.expectEqual(@as(usize, 8), short.len);
    try testing.expectError(d.ParseError.InvalidFormat, d.parsePrefix("2024-01", "YYYY-MM-DD"));

    const l = comptime d.Layout.compile("hh:mm") catch unreachable;
    const lm = try l.parsePrefix("09:30:00");
    try testing.expectEqual(@as(usize, 5), lm.len);
    try testing.expectEqual(@as(u32, 30), lm.parts.minute);
}

test "Layout.formatBuf: no allocation, NoSpaceLeft when short" {
    const l = comptime d.Layout.compile("YYYY-MM-DD hh:mm:ss.FFF") catch unreachable;
    const parts: d.DateParts = .{ .year = 2026, .month = 11, .day = 5, .hour = 9, .minute = 1, .second = 2, .nanosecond = 500_000_000 };
    var big: [128]u8 = undefined;
    try testing.expect(l.maxLen() <= big.len);
    try testing.expectEqualStrings("2026-11-05 09:01:02.5", try l.formatBuf(&big, parts));
    // Exactly the length fits, even though it is below maxLen().
    var exact: [21]u8 = undefined;
    try testing.expect(exact.len < l.maxLen());
    try testing.expectEqualStrings("2026-11-05 09:01:02.5", try l.formatBuf(&exact, parts));
    var short: [20]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, l.formatBuf(&short, parts));
    var none: [0]u8 = .{};
    try testing.expectError(error.NoSpaceLeft, l.formatBuf(&none, parts));
    try testing.expectError(error.InvalidDate, l.formatBuf(&big, .{ .year = -1 }));
    // Same text as format.
    const s = try l.format(testing.allocator, parts);
    defer testing.allocator.free(s);
    try testing.expectEqualStrings(s, try l.formatBuf(&big, parts));

    // A layout whose bound exceeds the stack scratch: a short buffer is
    // NoSpaceLeft, a maxLen() buffer works.
    const long_lit = "[" ++ @as([300]u8, @splat('x')) ++ "]YYYY";
    const ll = comptime d.Layout.compile(long_lit) catch unreachable;
    var small: [64]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, ll.formatBuf(&small, parts));
    const buf = try testing.allocator.alloc(u8, ll.maxLen());
    defer testing.allocator.free(buf);
    try testing.expectEqual(@as(usize, 304), (try ll.formatBuf(buf, parts)).len);
}

test "parseHttpDate: RFC 9110 §5.6.7's three forms" {
    const forms = [_][]const u8{
        "Sun, 06 Nov 1994 08:49:37 GMT", // IMF-fixdate
        "Sunday, 06-Nov-94 08:49:37 GMT", // RFC 850
        "Sun Nov  6 08:49:37 1994", // asctime
        "Sun Nov 06 08:49:37 1994", // asctime, 2DIGIT day
    };
    for (forms) |f| {
        const p = try d.parseHttpDate(f);
        try testing.expectEqual(@as(i32, 1994), p.year);
        try testing.expectEqual(@as(u32, 11), p.month);
        try testing.expectEqual(@as(u32, 6), p.day);
        try testing.expectEqual(@as(u32, 8), p.hour);
        try testing.expectEqual(@as(u32, 49), p.minute);
        try testing.expectEqual(@as(u32, 37), p.second);
        try testing.expectEqual(@as(?i32, 0), p.off_min);
    }
    // Two-digit year pivot, as YY.
    try testing.expectEqual(@as(i32, 2069), (try d.parseHttpDate("Tuesday, 01-Jan-69 00:00:00 GMT")).year);
    try testing.expectEqual(@as(i32, 1970), (try d.parseHttpDate("Thursday, 01-Jan-70 00:00:00 GMT")).year);
    try testing.expectEqual(@as(u32, 16), (try d.parseHttpDate("Wed Nov 16 08:49:37 1994")).day);

    // Wrong weekday in each form.
    try testing.expectError(d.ParseError.InvalidDate, d.parseHttpDate("Mon, 06 Nov 1994 08:49:37 GMT"));
    try testing.expectError(d.ParseError.InvalidDate, d.parseHttpDate("Monday, 06-Nov-94 08:49:37 GMT"));
    try testing.expectError(d.ParseError.InvalidDate, d.parseHttpDate("Mon Nov  6 08:49:37 1994"));
    try testing.expectError(d.ParseError.InvalidDate, d.parseHttpDate("Sun, 06-Nov-94 08:49:37 GMT")); // short name in RFC 850
    // Case-sensitive names.
    try testing.expectError(d.ParseError.InvalidDate, d.parseHttpDate("sunday, 06-Nov-94 08:49:37 GMT"));
    try testing.expectError(d.ParseError.InvalidDate, d.parseHttpDate("Sun nov  6 08:49:37 1994"));
    // Ranges.
    try testing.expectError(d.ParseError.InvalidDate, d.parseHttpDate("Thursday, 31-Feb-94 08:49:37 GMT"));
    try testing.expectError(d.ParseError.InvalidTime, d.parseHttpDate("Sun Nov  6 24:49:37 1994"));
    try testing.expectError(d.ParseError.InvalidDate, d.parseHttpDate("Sun Nov  0 08:49:37 1994"));
    // Shapes.
    for ([_][]const u8{
        "",
        ",",
        "Sun",
        "Sunday,",
        "Sunday, 06-Nov-94 08:49:37 UTC",
        "Sunday, 06 Nov 94 08:49:37 GMT",
        "Sunday,06-Nov-94 08:49:37 GMT ",
        "Sun Nov 6 08:49:37 1994",
        "Sun Nov  6 08:49:37 1994 ",
        "Sun  Nov 6 08:49:37 1994",
        "Sun, 06 Nov 1994 08:49:37 GMT ",
    }) |bad| {
        if (d.parseHttpDate(bad)) |_| {
            std.debug.print("accepted: '{s}'\n", .{bad});
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

test "parseHttpDate: no panic on any short input" {
    var prng = std.Random.DefaultPrng.init(0x9110);
    const rnd = prng.random();
    const alphabet = "SunModay, 0123456789-:NvGMTJ ";
    var buf: [40]u8 = undefined;
    for (0..50_000) |_| {
        const len = rnd.uintLessThan(usize, buf.len + 1);
        for (buf[0..len]) |*c| c.* = alphabet[rnd.uintLessThan(usize, alphabet.len)];
        _ = d.parseHttpDate(buf[0..len]) catch {};
    }
}

test "truncateNs and roundNs (Go Truncate/Round)" {
    const s: i64 = std.time.ns_per_s;
    try testing.expectEqual(@as(i64, 1000), d.truncateNs(1999, 1000));
    try testing.expectEqual(@as(i64, -1000), d.truncateNs(-1, 1000)); // toward the past
    try testing.expectEqual(@as(i64, 0), d.truncateNs(0, 1000));
    try testing.expectEqual(@as(i64, 1999), d.truncateNs(1999, 0)); // unit <= 0: unchanged
    try testing.expectEqual(@as(i64, 1999), d.truncateNs(1999, -5));
    try testing.expectEqual(@as(i64, 2000), d.roundNs(1500, 1000)); // halfway up
    try testing.expectEqual(@as(i64, 1000), d.roundNs(1499, 1000));
    try testing.expectEqual(@as(i64, -1000), d.roundNs(-1500, 1000)); // halfway up, also below zero
    try testing.expectEqual(@as(i64, -2000), d.roundNs(-1501, 1000));
    try testing.expectEqual(@as(i64, 7), d.roundNs(7, -1));
    // Edges saturate instead of trapping.
    const max = std.math.maxInt(i64);
    const min = std.math.minInt(i64);
    try testing.expectEqual(max, d.roundNs(max, s));
    try testing.expectEqual(min, d.truncateNs(min, s));
    try testing.expectEqual(min, d.roundNs(min, s));
    try testing.expectEqual(@as(i64, 0), d.truncateNs(max - 1, max));
    try testing.expectEqual(max, d.roundNs(max - 1, max));
    try testing.expectEqual(@as(i64, 0), d.roundNs(1, max));

    // Invariants on random values: a multiple of unit, below by less than unit.
    var prng = std.Random.DefaultPrng.init(0x7a);
    const rnd = prng.random();
    for (0..20_000) |_| {
        const ns = rnd.intRangeAtMost(i64, -(1 << 62), 1 << 62);
        const unit = rnd.intRangeAtMost(i64, 1, 1 << 40);
        const t = d.truncateNs(ns, unit);
        try testing.expectEqual(@as(i64, 0), @mod(t, unit));
        try testing.expect(t <= ns and ns - t < unit);
        const r = d.roundNs(ns, unit);
        try testing.expectEqual(@as(i64, 0), @mod(r, unit));
        const dist = if (r >= ns) r - ns else ns - r;
        try testing.expect(2 * dist <= unit);
    }
}

test "new tokens are in the vocabulary and the doc table" {
    try testing.expect(d.firstInvalidFormatChar("YYYY-DDDD hh:mm:ss.FFFZZZ") == null);
    try testing.expect(d.firstInvalidFormatChar("ss.FFFFFF ss.FFFFFFFFF") == null);
    try testing.expect(d.firstInvalidFormatChar("ss.FF") != null); // only 3/6/9 wide
    var found: usize = 0;
    for (d.date_tokens) |tok| {
        for ([_][]const u8{ "DDDD", "ZZZ", "FFF/FFFFFF/FFFFFFFFF" }) |want| {
            if (std.mem.eql(u8, tok.token, want)) found += 1;
        }
    }
    try testing.expectEqual(@as(usize, 3), found);
}

test "FFF: the missing-separator state does not leak into a later FFF" {
    // First separator absent (zero fraction), second present.
    const p = try d.parse("05 06.5", "ss.FFF mm.FFF");
    try testing.expectEqual(@as(u32, 5), p.second);
    try testing.expectEqual(@as(u32, 6), p.minute);
    try testing.expectEqual(@as(u32, 500_000_000), p.nanosecond);
    // Both present.
    const q = try d.parse("05.25 06.5", "ss.FFF mm.FFF");
    try testing.expectEqual(@as(u32, 500_000_000), q.nanosecond);
    // Past the end of input only the one-byte separator in front of FFF may stay.
    try testing.expectEqual(@as(u32, 0), (try d.parse("12", "ss.FFF")).nanosecond);
    try testing.expectError(d.ParseError.InvalidFormat, d.parse("12", "ss.FFF FFF"));
    try testing.expectError(d.ParseError.InvalidFormat, d.parse("12", "ss."));
    try testing.expectError(d.ParseError.InvalidFormat, d.parse("12", "ss.Z"));
    try testing.expectError(d.ParseError.InvalidFormat, d.parse("12", "ss:.FFF"));
    try testing.expectError(d.ParseError.InvalidFormat, d.parse("12", "ss.FFF ZZ"));
    // A comma in front of FFF is a separator too, a semicolon is not.
    try testing.expectEqual(@as(u32, 0), (try d.parse("12", "ss,FFF")).nanosecond);
    try testing.expectError(d.ParseError.InvalidFormat, d.parse("12", "ss;FFF"));
}

test "FFF and DDDD behind the [*] wildcard" {
    // The wildcard ends at the first digit, or at the end of the input.
    try testing.expectEqual(@as(u32, 0), (try d.parse("05 abc", "ss[*]FFF")).nanosecond);
    try testing.expectEqual(@as(u32, 50_000_000), (try d.parse("05 x05", "ss[*]FFF")).nanosecond);
    try testing.expectEqual(@as(u32, 700_000_000), (try d.parse("05 abc 7", "ss[*]FFF")).nanosecond);
    // DDDD whose three digits end the input.
    const p = try d.parse("x 060", "[*]DDDD");
    try testing.expectEqual(@as(u32, 3), p.month);
    try testing.expectEqual(@as(u32, 1), p.day);
    try testing.expectError(d.ParseError.InvalidFormat, d.parse("x 06", "[*]DDDD"));
    // Digits after a missing separator are not a fraction.
    const m = try d.parsePrefix("0512", "ss.FFF");
    try testing.expectEqual(@as(u32, 0), m.parts.nanosecond);
    try testing.expectEqual(@as(usize, 2), m.len);
}

test "parseHttpDate: every separator is checked, in each form" {
    const rfc850 = "Sunday, 06-Nov-94 08:49:37 GMT";
    const asctime = "Sun Nov  6 08:49:37 1994";
    _ = try d.parseHttpDate(rfc850);
    _ = try d.parseHttpDate(asctime);
    var buf: [40]u8 = undefined;
    // RFC 850: the comma is at 6; the rest is relative to it.
    for ([_]usize{ 7, 10, 14, 17, 20, 23, 26 }) |at| {
        @memcpy(buf[0..rfc850.len], rfc850);
        buf[at] = '#';
        try testing.expect(std.meta.isError(d.parseHttpDate(buf[0..rfc850.len])));
    }
    // asctime: the spaces and colons, and the byte after the weekday name.
    for ([_]usize{ 3, 7, 10, 13, 16, 19 }) |at| {
        @memcpy(buf[0..asctime.len], asctime);
        buf[at] = '#';
        try testing.expect(std.meta.isError(d.parseHttpDate(buf[0..asctime.len])));
    }
    // A 24-byte string that is not asctime is not read as one.
    try testing.expect(std.meta.isError(d.parseHttpDate("Sun,Nov  6 08:49:37 1994")));
    // Two-digit day with a leading space and a one-digit day both read; a bare digit does not.
    try testing.expectEqual(@as(u32, 6), (try d.parseHttpDate("Sun Nov 06 08:49:37 1994")).day);
    // The pivot year 70 is 1970, 69 is 2069 (the YY rule).
    try testing.expectEqual(@as(i32, 1970), (try d.parseHttpDate("Thursday, 01-Jan-70 00:00:00 GMT")).year);
    // An out-of-range field is an error in RFC 850 too.
    try testing.expectError(d.ParseError.InvalidDate, d.parseHttpDate("Sunday, 31-Feb-94 08:49:37 GMT"));
    try testing.expectError(d.ParseError.InvalidTime, d.parseHttpDate("Sunday, 06-Nov-94 25:49:37 GMT"));
    // A lower-case month is not the grammar's month.
    try testing.expectError(d.ParseError.InvalidDate, d.parseHttpDate("Sunday, 06-nov-94 08:49:37 GMT"));
    try testing.expectError(d.ParseError.InvalidDate, d.parseHttpDate("Sun nov  6 08:49:37 1994"));
}

test "roundNs and truncateNs with unit 0" {
    try testing.expectEqual(@as(i64, 7), d.roundNs(7, 0));
    try testing.expectEqual(@as(i64, -7), d.roundNs(-7, 0));
    try testing.expectEqual(@as(i64, 7), d.truncateNs(7, 0));
}

test "Layout.formatBuf: a bound of exactly the scratch size takes the stack path" {
    // 244 literal bytes + one 12-byte field bound = 256.
    const lit = "[" ++ @as([244]u8, @splat('x')) ++ "]YYYY";
    const l = comptime d.Layout.compile(lit) catch unreachable;
    try testing.expectEqual(@as(usize, 256), l.maxLen());
    var buf: [250]u8 = undefined; // below maxLen, above the 248-byte text
    const out = try l.formatBuf(&buf, .{ .year = 2026, .month = 1, .day = 1 });
    try testing.expectEqual(@as(usize, 248), out.len);
    try testing.expectEqualStrings("2026", out[244..]);
    var tiny: [247]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, l.formatBuf(&tiny, .{ .year = 2026, .month = 1, .day = 1 }));
}
