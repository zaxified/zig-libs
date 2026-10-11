// SPDX-License-Identifier: MIT
//! Replays the committed answers of two foreign implementations -- Go's
//! `time` (`go_time_vectors.zig`, from `tools/go_time_oracle`) and Python's
//! `email.utils` (`mail_date_vectors.zig`, from `tools/mail_date_oracle.py`)
//! -- against `parseDuration`/`bufDuration`, `bufRfc2822` and
//! `parseRfc2822`. No foreign toolchain at test time.

const std = @import("std");
const testing = std.testing;
const datefmt = @import("root.zig");
const go = @import("go_time_vectors.zig");
const mail = @import("mail_date_vectors.zig");

test "parseDuration: Go time.ParseDuration's answer on every case" {
    for (go.parse_cases) |c| {
        const got: ?i64 = datefmt.parseDuration(c.in) catch null;
        if (got != c.ns) {
            std.debug.print("parseDuration({f}): ours {?d}, Go {?d}\n", .{ std.zig.fmtString(c.in), got, c.ns });
            return error.TestUnexpectedResult;
        }
    }
}

test "parseDuration: a sum past 2^64 is an error (Go wraps it to 0)" {
    try testing.expectError(error.InvalidDuration, datefmt.parseDuration("9223372036854775808ns9223372036854775808ns"));
    try testing.expectError(error.InvalidDuration, datefmt.parseDuration("-9223372036854775808ns9223372036854775808ns"));
}

test "bufDuration: Go Duration.String's text on every case, and parseDuration reads it back" {
    var buf: [datefmt.duration_max_len]u8 = undefined;
    for (go.format_cases) |c| {
        const got = datefmt.bufDuration(&buf, c.ns);
        try testing.expectEqualStrings(c.out, got);
        try testing.expectEqual(c.ns, try datefmt.parseDuration(got));
    }
}

test "bufRfc2822: Go's time.RFC1123Z text on every case, and parseRfc2822 reads it back" {
    var buf: [datefmt.rfc2822_len]u8 = undefined;
    for (go.rfc1123z_cases) |c| {
        var p = datefmt.unixToParts(c.unix + @as(i64, c.off_min) * 60);
        p.off_min = c.off_min;
        try datefmt.bufRfc2822(&buf, p);
        try testing.expectEqualStrings(c.out, &buf);
        const back = try datefmt.parseRfc2822(&buf);
        try testing.expectEqual(p, back);
        try testing.expectEqual(c.unix, datefmt.partsToUnix(datefmt.toUtc(back)));
    }
}

fn expectValue(want: mail.Value, got: datefmt.DateParts) !void {
    try testing.expectEqual(want.y, got.year);
    try testing.expectEqual(want.mo, got.month);
    try testing.expectEqual(want.d, got.day);
    try testing.expectEqual(want.h, got.hour);
    try testing.expectEqual(want.mi, got.minute);
    try testing.expectEqual(want.s, got.second);
    // Python's "no zone information" (a military letter) is 0 here.
    try testing.expectEqual(want.off_min orelse 0, got.off_min.?);
}

test "parseRfc2822: Python email.utils agrees, or the row says why not" {
    for (mail.cases) |c| {
        const got = datefmt.parseRfc2822(c.in);
        errdefer std.debug.print("parseRfc2822({f}): {any} (expected .{t}, Python {any})\n", .{ std.zig.fmtString(c.in), got, c.expect, c.py });
        switch (c.expect) {
            .agree => try expectValue(c.py.?, try got),
            .own => try expectValue(c.own.?, try got),
            .reject => if (got) |_| return error.TestUnexpectedResult else |_| {},
        }
    }
}

test "parseRfc2822: error classes" {
    const E = datefmt.ParseError;
    try testing.expectError(E.InvalidDate, datefmt.parseRfc2822("Sat, 21 Nov 1997 09:55:06 -0600"));
    try testing.expectError(E.InvalidDate, datefmt.parseRfc2822("Fri, 31 Nov 1997 09:55:06 -0600"));
    try testing.expectError(E.InvalidDate, datefmt.parseRfc2822("Fri, 21 Nov 19970 09:55:06 -0600"));
    try testing.expectError(E.InvalidTime, datefmt.parseRfc2822("Fri, 21 Nov 1997 09:55:60 -0600"));
    try testing.expectError(E.InvalidTime, datefmt.parseRfc2822("Fri, 21 Nov 1997 09:55:06 +2400"));
    try testing.expectError(E.InvalidFormat, datefmt.parseRfc2822("Fri, 21 Nov 1997 09:55:06 -0600 x"));
    try testing.expectError(E.InvalidFormat, datefmt.parseRfc2822("Fri, 21 Nov 1997 09:55:06 -0600 ((("));
}

test "bufRfc2822: null offset is +0000, out-of-range values are errors" {
    var buf: [datefmt.rfc2822_len]u8 = undefined;
    try datefmt.bufRfc2822(&buf, .{ .year = 1994, .month = 11, .day = 6, .hour = 8, .minute = 49, .second = 37 });
    try testing.expectEqualStrings("Sun, 06 Nov 1994 08:49:37 +0000", &buf);
    try testing.expectError(error.InvalidDate, datefmt.bufRfc2822(&buf, .{ .year = 10000 }));
    try testing.expectError(error.InvalidDate, datefmt.bufRfc2822(&buf, .{ .month = 2, .day = 30 }));
    try testing.expectError(error.InvalidTime, datefmt.bufRfc2822(&buf, .{ .off_min = 24 * 60 }));
    try testing.expectError(error.InvalidTime, datefmt.bufRfc2822(&buf, .{ .hour = 24 }));
}

test "parseRfc2822 / parseDuration: mutated and random input is an error or a valid value, never a panic" {
    // A mail `Date:` header and a config-file duration are untrusted text.
    var prng = std.Random.DefaultPrng.init(0x2822_d0);
    const r = prng.random();
    const seeds = [_][]const u8{
        "Fri, 21 Nov 1997 09:55:06 -0600 (a (nested) comment)",
        "Fri,(c)21(c)Nov(c)97(c)09 : 55 : 06(\\)) EST",
        "-2562047h47m16.854775808s",
        "1h2m3.5\xc2\xb5s.5ns",
    };
    var buf: [64]u8 = undefined;
    for (0..40_000) |i| {
        const seed = seeds[i % seeds.len];
        var len = seed.len;
        @memcpy(buf[0..len], seed);
        switch (r.uintLessThan(u8, 3)) {
            0 => for (0..r.uintAtMost(u8, 3)) |_| {
                const alphabet = "0123456789:+-() \r\n\t\\.,ZJmshµ";
                buf[r.uintLessThan(usize, len)] = alphabet[r.uintLessThan(usize, alphabet.len)];
            },
            1 => len = r.uintAtMost(usize, len),
            else => {
                len = r.uintAtMost(usize, buf.len);
                r.bytes(buf[0..len]);
            },
        }
        if (datefmt.parseRfc2822(buf[0..len])) |p| {
            try testing.expect(datefmt.validate(p));
            try testing.expect(@abs(p.off_min.?) < 24 * 60);
        } else |_| {}
        if (datefmt.parseDuration(buf[0..len])) |ns| {
            var out: [datefmt.duration_max_len]u8 = undefined;
            try testing.expectEqual(ns, try datefmt.parseDuration(datefmt.bufDuration(&out, ns)));
        } else |_| {}
    }
}

test "partsToUnixNs / unixNsToParts / toUtc" {
    const p: datefmt.DateParts = .{ .year = 1969, .month = 12, .day = 31, .hour = 23, .minute = 59, .second = 59, .nanosecond = 500_000_000 };
    try testing.expectEqual(@as(?i64, -500_000_000), datefmt.partsToUnixNs(p));
    try testing.expectEqual(p, datefmt.unixNsToParts(-500_000_000));
    // The i64 edges: Go's UnixNano range.
    const lo = datefmt.unixNsToParts(std.math.minInt(i64));
    try testing.expectEqual(@as(?i64, std.math.minInt(i64)), datefmt.partsToUnixNs(lo));
    try testing.expectEqual(@as(i32, 1677), lo.year);
    const hi = datefmt.unixNsToParts(std.math.maxInt(i64));
    try testing.expectEqual(@as(?i64, std.math.maxInt(i64)), datefmt.partsToUnixNs(hi));
    try testing.expectEqual(@as(i32, 2262), hi.year);
    try testing.expectEqual(@as(?i64, null), datefmt.partsToUnixNs(.{ .year = 2263 }));
    try testing.expectEqual(@as(?i64, null), datefmt.partsToUnixNs(.{ .year = 1677 }));

    const local = try datefmt.parseRfc3339("2026-01-01T00:30:00.25+02:00");
    const utc = datefmt.toUtc(local);
    try testing.expectEqual(datefmt.DateParts{ .year = 2025, .month = 12, .day = 31, .hour = 22, .minute = 30, .nanosecond = 250_000_000, .off_min = 0 }, utc);
    try testing.expectEqual(datefmt.parseXsdDateTimeNs("2026-01-01T00:30:00.25+02:00") catch unreachable, datefmt.XsdInstant{ .unix = datefmt.partsToUnix(utc), .nanosecond = utc.nanosecond });
    var no_zone = local;
    no_zone.off_min = null;
    try testing.expectEqual(datefmt.partsToUnix(no_zone), datefmt.partsToUnix(datefmt.toUtc(no_zone)));
}
