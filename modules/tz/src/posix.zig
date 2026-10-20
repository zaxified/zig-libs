// SPDX-License-Identifier: MIT
//! The POSIX-TZ footer grammar (RFC 9636 §3.3 / tzfile(5)):
//!   stdoffset[dst[offset][,start[/time],end[/time]]]
//! parsed into a `Footer`. Imports only `std`, so the generator
//! (`scripts/gen/tz-gen`) compiles THIS file: the footer it stores in
//! `tz_data.zig` and the one the runtime fallback parses are the same parser.
//!
//! Evaluation (which needs `datefmt`'s calendar) lives in `root.zig`.

const std = @import("std");

/// POSIX default for a rule without `/time`: 02:00 local.
pub const default_dst_time: i32 = 2 * 3600;

pub const Rule = union(enum) {
    /// `Mm.w.d`: day `d` (0 = Sunday) of week `w` (5 = last) of month `m`.
    mwd: struct { month: i32, week: i32, day: i32 },
    /// `Jn` — 1..365, Feb 29 never counted (day 60 == March 1 always).
    julian: i32,
    /// `n` — 0..365, Feb 29 counted in leap years.
    yday: i32,
};

pub const Dst = struct {
    /// Abbreviation without the angle brackets (`<+05>` -> `+05`).
    abbr: []const u8,
    /// UTC offset in seconds, east positive.
    utc_dst: i32,
    start: Rule,
    /// Seconds past local midnight (standard time), may be negative or > 24 h.
    start_time: i32,
    end: Rule,
    /// Seconds past local midnight (daylight time).
    end_time: i32,
};

/// A parsed POSIX-TZ footer: a constant offset, or standard + daylight
/// offsets with the two yearly rules.
pub const Footer = struct {
    std_abbr: []const u8,
    /// UTC offset in seconds, east positive (POSIX writes it west positive).
    utc_std: i32,
    dst: ?Dst,
};

/// Parse `s`; null when it is not a footer this module can evaluate
/// (empty, malformed, or DST named without rules). The abbreviations are
/// slices of `s`.
pub fn parse(s: []const u8) ?Footer {
    if (s.len == 0) return null;
    var i: usize = 0;

    const std_abbr = readAbbrev(s, &i);
    const std_written = parseOffsetSeconds(s, &i) orelse return null;
    const utc_std: i32 = -std_written; // POSIX offset is add-to-local-for-UTC

    if (i >= s.len) return .{ .std_abbr = std_abbr, .utc_std = utc_std, .dst = null }; // no DST → constant

    const dst_abbr = readAbbrev(s, &i);
    // Optional explicit DST offset; default is one hour east of standard.
    var utc_dst: i32 = utc_std +| 3600;
    if (i < s.len and s[i] != ',') {
        const dst_written = parseOffsetSeconds(s, &i) orelse return null;
        utc_dst = -dst_written;
    }

    if (i >= s.len or s[i] != ',') return null; // no rules → cannot place DST
    i += 1;
    const start = parseRule(s, &i) orelse return null;
    const start_time = parseRuleTime(s, &i);
    if (i >= s.len or s[i] != ',') return null;
    i += 1;
    const end = parseRule(s, &i) orelse return null;
    const end_time = parseRuleTime(s, &i);
    return .{ .std_abbr = std_abbr, .utc_std = utc_std, .dst = .{
        .abbr = dst_abbr,
        .utc_dst = utc_dst,
        .start = start,
        .start_time = start_time,
        .end = end,
        .end_time = end_time,
    } };
}

/// The abbreviation at `i` (alphabetic run, or `<...>`), advancing past it
/// (and past the closing `>`); the result excludes the brackets.
fn readAbbrev(s: []const u8, i: *usize) []const u8 {
    if (i.* < s.len and s[i.*] == '<') {
        const start = i.* + 1;
        var j = start;
        while (j < s.len and s[j] != '>') j += 1;
        i.* = if (j < s.len) j + 1 else j; // consume '>'
        return s[start..j];
    }
    const start = i.*;
    while (i.* < s.len and std.ascii.isAlphabetic(s[i.*])) i.* += 1;
    return s[start..i.*];
}

fn readInt(s: []const u8, i: *usize) ?i32 {
    const start = i.*;
    while (i.* < s.len and s[i.*] >= '0' and s[i.*] <= '9') i.* += 1;
    if (i.* == start) return null;
    return std.fmt.parseInt(i32, s[start..i.*], 10) catch null;
}

/// `[+-]hh[:mm[:ss]]` → seconds (as written; POSIX west-positive sign).
/// Null on a missing number or on a value that overflows `i32` seconds.
fn parseOffsetSeconds(s: []const u8, i: *usize) ?i32 {
    var neg = false;
    if (i.* < s.len and (s[i.*] == '+' or s[i.*] == '-')) {
        neg = s[i.*] == '-';
        i.* += 1;
    }
    const h = readInt(s, i) orelse return null;
    var secs: i32 = std.math.mul(i32, h, 3600) catch return null;
    if (i.* < s.len and s[i.*] == ':') {
        i.* += 1;
        const m = readInt(s, i) orelse return null;
        secs = std.math.add(i32, secs, std.math.mul(i32, m, 60) catch return null) catch return null;
        if (i.* < s.len and s[i.*] == ':') {
            i.* += 1;
            const sec = readInt(s, i) orelse return null;
            secs = std.math.add(i32, secs, sec) catch return null;
        }
    }
    return if (neg) -secs else secs;
}

fn parseRule(s: []const u8, i: *usize) ?Rule {
    if (i.* >= s.len) return null;
    if (s[i.*] == 'M') {
        i.* += 1;
        const m = readInt(s, i) orelse return null;
        if (i.* >= s.len or s[i.*] != '.') return null;
        i.* += 1;
        const w = readInt(s, i) orelse return null;
        if (i.* >= s.len or s[i.*] != '.') return null;
        i.* += 1;
        const d = readInt(s, i) orelse return null;
        return .{ .mwd = .{ .month = m, .week = w, .day = d } };
    }
    if (s[i.*] == 'J') {
        i.* += 1;
        const n = readInt(s, i) orelse return null;
        if (n < 1 or n > 365) return null;
        return .{ .julian = n };
    }
    if (s[i.*] >= '0' and s[i.*] <= '9') {
        const n = readInt(s, i) orelse return null;
        if (n < 0 or n > 365) return null;
        return .{ .yday = n };
    }
    return null;
}

/// Optional `/time` after a rule; POSIX default is 02:00:00 local.
fn parseRuleTime(s: []const u8, i: *usize) i32 {
    if (i.* < s.len and s[i.*] == '/') {
        i.* += 1;
        return parseOffsetSeconds(s, i) orelse default_dst_time;
    }
    return default_dst_time;
}

test "parse: the shapes the footer grammar allows" {
    const p = parse("CET-1CEST,M3.5.0,M10.5.0/3").?;
    try std.testing.expectEqualStrings("CET", p.std_abbr);
    try std.testing.expectEqual(@as(i32, 3600), p.utc_std);
    try std.testing.expectEqualStrings("CEST", p.dst.?.abbr);
    try std.testing.expectEqual(@as(i32, 7200), p.dst.?.utc_dst);
    try std.testing.expectEqual(@as(i32, 3 * 3600), p.dst.?.end_time);
    try std.testing.expectEqual(default_dst_time, p.dst.?.start_time);

    const b = parse("<+0330>-3:30").?;
    try std.testing.expectEqualStrings("+0330", b.std_abbr);
    try std.testing.expectEqual(@as(i32, 12600), b.utc_std);
    try std.testing.expect(b.dst == null);

    const l = parse("<-03>3<-02>,M3.5.0/-2,M10.5.0/-1").?;
    try std.testing.expectEqualStrings("-02", l.dst.?.abbr);
    try std.testing.expectEqual(@as(i32, -2 * 3600), l.dst.?.start_time);

    try std.testing.expect(parse("") == null);
    try std.testing.expect(parse("AAA") == null);
    try std.testing.expect(parse("EST5EDT") == null); // DST named, no rules
    try std.testing.expect(parse("A99999999") == null); // overflowing hours: null, not a panic
}
