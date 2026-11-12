// SPDX-License-Identifier: MIT

//! timefmt.zig -- Apache `%{format}t` for `LogFormat`: `strftime`-style
//! formats on top of `datefmt`, plus `begin:` / `end:` and the keywords
//! `sec`, `msec`, `usec`, `msec_frac`, `usec_frac` (httpd 2.4
//! `mod_log_config`).
//!
//! No time formatter lives here. A strftime format is split at its literal
//! text and its directives that have no `datefmt` token; the rest is
//! translated to a `datefmt` layout (`%Y` -> `YYYY`, ...) and rendered by
//! `datefmt.Layout.formatBuf`. The same walk runs at parse time with no
//! writer, so every format that parses also renders.
//!
//! ## Directives (C locale, English names)
//!
//! `%a %A %b %B %h %d %H %I %j %m %M %p %S %y %Y %z %u %V %G %%` map to
//! `datefmt` tokens; `%e %k %l` (space padded), `%P` (lowercase am/pm), `%w`
//! (Sunday = 0), `%C` (century) and `%s` (epoch seconds) are printed here from
//! values `datefmt` gives; `%F %T %R %D %r %c %x %X` expand to the above.
//! **Not supported** (`error.BadTimeFormat`): `%U %W %g %Z` (no `datefmt`
//! token; `Entry` carries an offset, not a zone name), `%n %t` (control
//! bytes), `%E`/`%O` modifiers and glibc flags (`%-d`).
//!
//! ## Which instant
//!
//! `Entry.timestamp_ns` is the request's **begin** time; `end:` adds
//! `Entry.latency_ns` (equal to begin when not timed). Wall clock is UTC
//! shifted by `Entry.utc_offset_min` (default 0, so `%z` is `+0000`).

const std = @import("std");
const datefmt = @import("datefmt");
const root = @import("root.zig");
const Entry = root.Entry;

/// Longest strftime format a template may carry.
pub const max_format_len = 128;

pub const Mode = enum { strftime, sec, msec, usec, msec_frac, usec_frac };

pub const Spec = struct {
    mode: Mode,
    end: bool,
    /// `.strftime`: the format (borrowed from the template).
    fmt: []const u8 = "",
};

pub const ParseError = error{ BadTimeFormat, ControlByteInLiteral, EmptyName };

/// Parse the text between the braces of `%{...}t`.
pub fn parseSpec(name: []const u8) ParseError!Spec {
    var rest = name;
    var end = false;
    if (std.mem.startsWith(u8, rest, "begin:")) {
        rest = rest["begin:".len..];
    } else if (std.mem.startsWith(u8, rest, "end:")) {
        rest = rest["end:".len..];
        end = true;
    }
    if (rest.len == 0) return error.EmptyName;
    const kw = [_]struct { []const u8, Mode }{
        .{ "sec", .sec }, .{ "msec", .msec }, .{ "usec", .usec }, .{ "msec_frac", .msec_frac }, .{ "usec_frac", .usec_frac },
    };
    for (kw) |k| if (std.mem.eql(u8, rest, k[0])) return .{ .mode = k[1], .end = end };
    if (rest.len > max_format_len) return error.BadTimeFormat;
    for (rest) |c| if (c < 0x20 or c == 0x7F) return error.ControlByteInLiteral;
    var t: Ctx = .{ .w = null, .parts = .{}, .unix = 0 };
    t.walk(rest, 0) catch return error.BadTimeFormat;
    return .{ .mode = .strftime, .end = end, .fmt = rest };
}

/// Write the time for `spec` and `entry`. On an unrepresentable instant
/// writes `-`.
pub fn write(w: *std.Io.Writer, spec: Spec, entry: Entry) std.Io.Writer.Error!void {
    const lat: i64 = if (entry.latency_ns) |n| @intCast(@min(n, std.math.maxInt(i64))) else 0;
    const ns: i64 = if (spec.end) entry.timestamp_ns +| lat else entry.timestamp_ns;
    switch (spec.mode) {
        .sec => return w.print("{d}", .{@divFloor(ns, std.time.ns_per_s)}),
        .msec => return w.print("{d}", .{@divFloor(ns, std.time.ns_per_ms)}),
        .usec => return w.print("{d}", .{@divFloor(ns, std.time.ns_per_us)}),
        .msec_frac => return w.print("{d:0>3}", .{@as(u32, @intCast(@divFloor(@mod(ns, std.time.ns_per_s), std.time.ns_per_ms)))}),
        .usec_frac => return w.print("{d:0>6}", .{@as(u32, @intCast(@divFloor(@mod(ns, std.time.ns_per_s), std.time.ns_per_us)))}),
        .strftime => {},
    }
    const off: i32 = std.math.clamp(@as(i32, entry.utc_offset_min), -1439, 1439);
    const local = ns +| @as(i64, off) * 60 * std.time.ns_per_s;
    var parts = datefmt.unixNsToParts(local);
    parts.off_min = off;
    var t: Ctx = .{ .w = w, .parts = parts, .unix = @divFloor(ns, std.time.ns_per_s) };
    t.walk(spec.fmt, 0) catch |e| switch (e) {
        error.WriteFailed => return error.WriteFailed,
        error.BadTimeFormat => try w.writeByte('-'),
    };
}

const Ctx = struct {
    w: ?*std.Io.Writer,
    parts: datefmt.DateParts,
    unix: i64,
    lay: [768]u8 = undefined,
    n: usize = 0,

    const Err = error{ BadTimeFormat, WriteFailed };

    fn flush(t: *Ctx) Err!void {
        if (t.n == 0) return;
        defer t.n = 0;
        const w = t.w orelse {
            _ = datefmt.Layout.compile(t.lay[0..t.n]) catch return error.BadTimeFormat;
            return;
        };
        const l = datefmt.Layout.compile(t.lay[0..t.n]) catch return error.BadTimeFormat;
        var out: [1024]u8 = undefined;
        const s = l.formatBuf(&out, t.parts) catch return error.BadTimeFormat;
        w.writeAll(s) catch return error.WriteFailed;
    }

    fn tok(t: *Ctx, s: []const u8) Err!void {
        // Two tokens of one letter side by side would merge ("YY"+"YY" = "YYYY").
        if (t.n > 0 and t.lay[t.n - 1] == s[0]) try t.flush();
        if (t.n + s.len > t.lay.len) try t.flush();
        @memcpy(t.lay[t.n..][0..s.len], s);
        t.n += s.len;
    }

    fn lit(t: *Ctx, s: []const u8) Err!void {
        try t.flush();
        if (t.w) |w| w.writeAll(s) catch return error.WriteFailed;
    }

    fn print(t: *Ctx, comptime f: []const u8, args: anytype) Err!void {
        try t.flush();
        if (t.w) |w| w.print(f, args) catch return error.WriteFailed;
    }

    fn walk(t: *Ctx, fmt: []const u8, depth: u8) Err!void {
        if (depth > 2) return error.BadTimeFormat;
        var i: usize = 0;
        var run: usize = 0; // start of the pending literal run
        while (i < fmt.len) {
            if (fmt[i] != '%') {
                i += 1;
                continue;
            }
            if (i > run) try t.lit(fmt[run..i]);
            if (i + 1 >= fmt.len) return error.BadTimeFormat;
            const c = fmt[i + 1];
            i += 2;
            run = i;
            const p = t.parts;
            switch (c) {
                '%' => try t.lit("%"),
                'a' => try t.tok("EEE"),
                'A' => try t.tok("EEEE"),
                'b', 'h' => try t.tok("MMM"),
                'B' => try t.tok("MMMM"),
                'd' => try t.tok("DD"),
                'H' => try t.tok("hh"),
                'I' => try t.tok("ii"),
                'j' => try t.tok("DDDD"),
                'm' => try t.tok("MM"),
                'M' => try t.tok("mm"),
                'p' => try t.tok("A"),
                'S' => try t.tok("ss"),
                'y' => try t.tok("YY"),
                'Y' => try t.tok("YYYY"),
                'z' => try t.tok("ZZZ"),
                'u' => try t.tok("e"),
                'V' => try t.tok("WW"),
                'G' => try t.tok("GGGG"),
                'P' => {
                    try t.flush();
                    const pm = p.hour >= 12;
                    try t.lit(if (pm) "pm" else "am");
                },
                'e' => try t.print("{d: >2}", .{p.day}),
                'k' => try t.print("{d: >2}", .{p.hour}),
                'l' => try t.print("{d: >2}", .{if (p.hour % 12 == 0) 12 else p.hour % 12}),
                'w' => try t.print("{d}", .{datefmt.isoWeekday(datefmt.ymdToEpochDay(p.year, p.month, p.day)) % 7}),
                'C' => try t.print("{d:0>2}", .{@as(u32, @intCast(@divFloor(@max(p.year, 0), 100)))}),
                's' => try t.print("{d}", .{t.unix}),
                'F' => try t.walk("%Y-%m-%d", depth + 1),
                'T', 'X' => try t.walk("%H:%M:%S", depth + 1),
                'R' => try t.walk("%H:%M", depth + 1),
                'D', 'x' => try t.walk("%m/%d/%y", depth + 1),
                'r' => try t.walk("%I:%M:%S %p", depth + 1),
                'c' => try t.walk("%a %b %e %H:%M:%S %Y", depth + 1),
                else => return error.BadTimeFormat,
            }
        }
        if (fmt.len > run) try t.lit(fmt[run..]);
        try t.flush();
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

// 2026-11-06 14:05:09.123456789 UTC, a Friday
const t0: i64 = 1_793_973_909_123_456_789;

fn fmtAt(template: []const u8, e: Entry) ![]const u8 {
    const S = struct {
        var buf: [256]u8 = undefined;
    };
    const spec = try parseSpec(template);
    var w: std.Io.Writer = .fixed(&S.buf);
    try write(&w, spec, e);
    return w.buffered();
}

fn entryAt(ns: i64) Entry {
    return .{ .timestamp_ns = ns, .method = "GET", .target = "/", .status = 200 };
}

test "timefmt: strftime directives, exact bytes" {
    const e = entryAt(t0);
    try testing.expectEqualStrings("06/Nov/2026:14:05:09 +0000", try fmtAt("%d/%b/%Y:%H:%M:%S %z", e));
    try testing.expectEqualStrings("Friday, November 06 26 310 02:05 PM pm", try fmtAt("%A, %B %d %y %j %I:%M %p %P", e));
    try testing.expectEqualStrings("2026-11-06 14:05:09 | 14:05 | 11/06/26 | 02:05:09 PM", try fmtAt("%F %T | %R | %D | %r", e));
    try testing.expectEqualStrings("Fri Nov  6 14:05:09 2026", try fmtAt("%c", e));
    try testing.expectEqualStrings(" 6|14|can  2|5|20|1793973909|100%", try fmtAt("%e|%k|can %l|%w|%C|%s|100%%", e));
    try testing.expectEqualStrings("5 2026 45", try fmtAt("%u %G %V", e));
    // adjacent same-letter tokens stay separate
    try testing.expectEqualStrings("262026", try fmtAt("%y%Y", e));
    try testing.expectEqualStrings("2626", try fmtAt("%y%y", e));
    // literal text with datefmt token letters and brackets goes through untouched
    try testing.expectEqualStrings("YYYY [ok] ] 14", try fmtAt("YYYY [ok] ] %H", e));
}

test "timefmt: begin/end, utc offset, keywords" {
    var e = entryAt(t0);
    e.latency_ns = 2_000_000_000;
    try testing.expectEqualStrings("14:05:09", try fmtAt("%H:%M:%S", e));
    try testing.expectEqualStrings("14:05:09", try fmtAt("begin:%H:%M:%S", e));
    try testing.expectEqualStrings("14:05:11", try fmtAt("end:%H:%M:%S", e));
    try testing.expectEqualStrings("1793973909", try fmtAt("sec", e));
    try testing.expectEqualStrings("1793973909123", try fmtAt("msec", e));
    try testing.expectEqualStrings("1793973909123456", try fmtAt("usec", e));
    try testing.expectEqualStrings("123", try fmtAt("msec_frac", e));
    try testing.expectEqualStrings("123456", try fmtAt("usec_frac", e));
    try testing.expectEqualStrings("1793973911", try fmtAt("end:sec", e));
    try testing.expectEqualStrings("123", try fmtAt("end:msec_frac", e));
    var e2 = entryAt(1_000_005_000_000); // 1000.005 s
    try testing.expectEqualStrings("005", try fmtAt("msec_frac", e2));
    try testing.expectEqualStrings("005000", try fmtAt("usec_frac", e2));
    e.utc_offset_min = 120;
    try testing.expectEqualStrings("16:05:09 +0200", try fmtAt("%H:%M:%S %z", e));
    e.utc_offset_min = -330;
    try testing.expectEqualStrings("08:35:09 -0530", try fmtAt("%H:%M:%S %z", e));
    e2.utc_offset_min = 30000; // clamped, never traps
    _ = try fmtAt("%c %z", e2);
    // before the epoch: floor semantics
    const e3 = entryAt(-1);
    try testing.expectEqualStrings("-1", try fmtAt("sec", e3));
    try testing.expectEqualStrings("999", try fmtAt("msec_frac", e3));
}

test "timefmt: parse errors" {
    try testing.expectError(error.EmptyName, parseSpec(""));
    try testing.expectError(error.EmptyName, parseSpec("end:"));
    for ([_][]const u8{ "%", "abc%", "%Z", "%U", "%W", "%g", "%Ez", "%-d", "%n", "%t", "%q", "%E" }) |f|
        try testing.expectError(error.BadTimeFormat, parseSpec(f));
    try testing.expectError(error.ControlByteInLiteral, parseSpec("a\nb"));
    try testing.expectError(error.ControlByteInLiteral, parseSpec("a\x7fb"));
    var long: [max_format_len + 1]u8 = @splat('x');
    try testing.expectError(error.BadTimeFormat, parseSpec(&long));
    _ = try parseSpec(long[0..max_format_len]);
    // the longest format (64 directives, no literal between) still fits a layout
    var dense: [max_format_len]u8 = undefined;
    for (0..max_format_len / 2) |k| {
        dense[2 * k] = '%';
        dense[2 * k + 1] = if (k % 2 == 0) 'd' else 'm';
    }
    _ = try parseSpec(&dense);
    _ = try fmtAt(&dense, entryAt(t0));
    // keywords are exact: "SEC" is just literal text
    try testing.expectEqualStrings("SEC", try fmtAt("SEC", entryAt(0)));
}

test "timefmt: output never leaves the template's own bytes (extreme instants)" {
    for ([_]i64{ std.math.minInt(i64), std.math.maxInt(i64), 0, -1 }) |ns| {
        var e = entryAt(ns);
        e.latency_ns = std.math.maxInt(u64);
        e.utc_offset_min = 1439;
        const s = try fmtAt("end:%c %z %s", e);
        for (s) |c| try testing.expect(c >= 0x20 and c < 0x7F);
        _ = try fmtAt("end:usec_frac", e);
    }
}

test "timefmt: 12-hour clock, weekday, padding and offset clamp at the edges" {
    // 2026-11-08 (a Sunday) 00:30:00 UTC and 12:00:00 UTC, 2026-11-06 11:59:59 and 13:00:00
    const cases = [_]struct { ns: i64, want: []const u8 }{
        .{ .ns = 1_794_097_800 * 1_000_000_000, .want = "Sun 0 | 0|12:30 AM am|12" },
        .{ .ns = 1_794_139_200 * 1_000_000_000, .want = "Sun 0 |12|12:00 PM pm|12" },
        .{ .ns = 1_793_966_399 * 1_000_000_000, .want = "Fri 5 |11|11:59 AM am|11" },
        .{ .ns = 1_793_970_000 * 1_000_000_000, .want = "Fri 5 |13|01:00 PM pm| 1" },
    };
    for (cases) |c|
        try testing.expectEqualStrings(c.want, try fmtAt("%a %w |%k|%I:%M %p %P|%l", entryAt(c.ns)));
    var e = entryAt(t0);
    e.utc_offset_min = 1500; // clamped to +23:59
    try testing.expectEqualStrings("+2359", try fmtAt("%z", e));
    e.utc_offset_min = -1500;
    try testing.expectEqualStrings("-2359", try fmtAt("%z", e));
    e.utc_offset_min = 1439;
    try testing.expectEqualStrings("+2359 1793973909", try fmtAt("%z %s", e)); // %s is the instant, not the wall clock
    // negative instants: usec_frac floors too; %C of a 21st-century year
    try testing.expectEqualStrings("999999", try fmtAt("usec_frac", entryAt(-1)));
    try testing.expectEqualStrings("-1", try fmtAt("msec", entryAt(-1)));
    try testing.expectEqualStrings("-1", try fmtAt("usec", entryAt(-1)));
    // the latency saturates instead of wrapping
    var big = entryAt(std.math.maxInt(i64) - 5);
    big.latency_ns = 1 << 40;
    try testing.expectEqualStrings("9223372036", try fmtAt("end:sec", big));
}

test "timefmt: %x %X %h, ISO week below 10, a latency beyond i64 saturates" {
    const e = entryAt(t0);
    try testing.expectEqualStrings("11/06/26 14:05:09 Nov", try fmtAt("%x %X %h", e));
    // 2026-01-05 12:00 UTC is ISO week 2: the week is zero padded
    try testing.expectEqualStrings("02 2026", try fmtAt("%V %G", entryAt(1_767_614_400 * 1_000_000_000)));
    var big = entryAt(1_000_000_000_000_000_000);
    big.latency_ns = std.math.maxInt(u64);
    try testing.expectEqualStrings("9223372036", try fmtAt("end:sec", big));
    try testing.expectEqualStrings("1000000000", try fmtAt("sec", big));
}

// ── mutation run 2026-11-07 (whole module): tests for the survivors ──────

fn fmtInto(buf: []u8, template: []const u8, e: Entry) ![]const u8 {
    const spec = try parseSpec(template);
    var w: std.Io.Writer = .fixed(buf);
    try write(&w, spec, e);
    return w.buffered();
}

test "mutation 2026-11-07: control bytes in a format are refused at their exact bounds, UTF-8 text is not" {
    for ([_]u8{ 0x00, 0x01, 0x0A, 0x1F, 0x7F }) |c| {
        const t = [_]u8{ 'a', c, 'b' };
        try testing.expectError(error.ControlByteInLiteral, parseSpec(&t));
    }
    for ([_]u8{ 0x20, 0x7E, 0x80, 0xC3, 0xFF }) |c| {
        const t = [_]u8{ 'a', c, 'b' };
        _ = try parseSpec(&t);
    }
    try testing.expectEqualStrings("\xc3\xa9 2026", try fmtAt("\xc3\xa9 %Y", entryAt(t0)));
}

test "mutation 2026-11-07: the saturated latency, the shifted wall clock at the top of i64, %s before the epoch" {
    // -807 ns + maxInt(i64) is exactly 9223372036854775000: one nanosecond less crosses a microsecond
    var e = entryAt(-807);
    e.latency_ns = std.math.maxInt(u64);
    try testing.expectEqualStrings("9223372036854775", try fmtAt("end:usec", e));
    var late = entryAt(std.math.maxInt(i64));
    late.utc_offset_min = 60;
    try testing.expectEqualStrings("2262", try fmtAt("%Y", late)); // saturates, never wraps to 1677
    try testing.expectEqualStrings("-1", try fmtAt("%s", entryAt(-1))); // floor, not truncation
}

test "mutation 2026-11-07: two adjacent directives render as the two rendered alone, for every pair" {
    const chars = "%aAbhBdHIjmMpSyYzuVGPeklwCsFTXRDxrc";
    var e = entryAt(t0);
    e.latency_ns = 1;
    var b1: [256]u8 = undefined;
    var b2: [256]u8 = undefined;
    var b3: [256]u8 = undefined;
    for (chars) |a| for (chars) |b| {
        const pair = [_]u8{ '%', a, '%', b };
        const x = try fmtInto(&b1, &pair, e);
        const y = try fmtInto(&b2, pair[0..2], e);
        const z = try fmtInto(&b3, pair[2..4], e);
        try testing.expectEqual(y.len + z.len, x.len);
        try testing.expectEqualStrings(y, x[0..y.len]);
        try testing.expectEqualStrings(z, x[y.len..]);
    };
}

test "mutation 2026-11-07: a Spec built by hand never panics: a bad or oversized format is -, a dead writer is WriteFailed" {
    const e = entryAt(t0);
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try write(&w, .{ .mode = .strftime, .end = false, .fmt = "%Z" }, e);
    try testing.expectEqualStrings("-", w.buffered());
    // 400 one-token directives overflow the 768-byte layout buffer (and the 64-token layout)
    var long: [800]u8 = undefined;
    for (0..200) |k| {
        long[4 * k] = '%';
        long[4 * k + 1] = 'd';
        long[4 * k + 2] = '%';
        long[4 * k + 3] = 'm';
    }
    w = .fixed(&buf);
    try write(&w, .{ .mode = .strftime, .end = false, .fmt = &long }, e);
    try testing.expectEqualStrings("-", w.buffered());
    var dead = std.Io.Writer.failing;
    try testing.expectError(error.WriteFailed, write(&dead, .{ .mode = .strftime, .end = false, .fmt = "%Y" }, e));
    // a writer that takes one byte at a time but refuses the 4-byte year: still WriteFailed, never a `-`
    var thin: OneByte = .{ .interface = .{ .vtable = &.{ .drain = OneByte.drain }, .buffer = &.{} } };
    try testing.expectError(error.WriteFailed, write(&thin.interface, .{ .mode = .strftime, .end = false, .fmt = "%Y" }, e));
    try testing.expectEqual(@as(usize, 0), thin.taken);
}

/// An unbuffered writer that accepts a single byte per call and fails on anything longer.
const OneByte = struct {
    interface: std.Io.Writer,
    taken: usize = 0,

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const c: *OneByte = @alignCast(@fieldParentPtr("interface", w));
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| n += d.len;
        n += data[data.len - 1].len * splat;
        if (n > 1) return error.WriteFailed;
        c.taken += n;
        return n;
    }
};

test "mutation 2026-11-12: end: without a latency adds nothing, not even a nanosecond before a boundary" {
    var e = entryAt(999_999_999); // 0.999999999 s, latency_ns null
    try testing.expectEqualStrings("0", try fmtAt("end:sec", e));
    try testing.expectEqualStrings("999", try fmtAt("end:msec_frac", e));
    try testing.expectEqualStrings("999999", try fmtAt("end:usec_frac", e));
    try testing.expectEqualStrings("00:00:00", try fmtAt("end:%H:%M:%S", e));
    e.latency_ns = 1; // one nanosecond does cross it
    try testing.expectEqualStrings("1", try fmtAt("end:sec", e));
}

test "mutation 2026-11-12: a one-letter token after another token, and the century divisor" {
    const e = entryAt(t0);
    // `%p` and `%u` are one-letter layout tokens: the merge guard reads their first byte only
    try testing.expectEqualStrings("55", try fmtAt("%u%u", e));
    try testing.expectEqualStrings("PMPM", try fmtAt("%p%p", e));
    try testing.expectEqualStrings("14PM", try fmtAt("%H%p", e));
    // 1999-12-31T23:59:59Z and 2100-01-01T00:00:00Z tell /100 from /99 and /101
    try testing.expectEqualStrings("19", try fmtAt("%C", entryAt(946_684_799 * std.time.ns_per_s)));
    try testing.expectEqualStrings("21", try fmtAt("%C", entryAt(4_102_444_800 * std.time.ns_per_s)));
}
