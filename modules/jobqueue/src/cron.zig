// SPDX-License-Identifier: MIT
//! Five-field cron expressions for `jobqueue` repeating schedules: parse once,
//! then ask for the next fire time after a wall-clock instant and pass that as
//! `EnqueueOptions.run_at`. There is no scheduler thread here (see the SPEC):
//! the caller enqueues the next run when the current one is done.
//!
//! Syntax (Vixie cron, which Sidekiq-cron, Asynq's scheduler and most others
//! follow): `minute hour day-of-month month day-of-week`, each a comma list of
//! `*`, `n`, `a-b`, `*/s`, `n/s` and `a-b/s`; `?` is accepted as `*`; month
//! and weekday names (`JAN`..`DEC`, `SUN`..`SAT`, case-insensitive) work as
//! values; weekday 7 is Sunday; the aliases `@yearly`/`@annually`, `@monthly`,
//! `@weekly`, `@daily`/`@midnight` and `@hourly` are accepted. Day-of-month
//! and day-of-week combine as in Vixie cron: when both are restricted a day
//! matches if EITHER does, when one is `*` the other alone decides.
//! All times are UTC, with minute resolution.

const std = @import("std");
const epoch = std.time.epoch;

pub const ParseError = error{InvalidCron};

const ns_per_min: i64 = 60 * std.time.ns_per_s;

pub const Cron = struct {
    minutes: u64,
    hours: u32,
    dom: u32,
    months: u16,
    dow: u8,
    dom_star: bool,
    dow_star: bool,

    pub fn parse(expr: []const u8) ParseError!Cron {
        const e = std.mem.trim(u8, expr, " \t");
        if (e.len != 0 and e[0] == '@') return parseAlias(e);
        var it = std.mem.tokenizeAny(u8, e, " \t");
        const f_min = it.next() orelse return error.InvalidCron;
        const f_hour = it.next() orelse return error.InvalidCron;
        const f_dom = it.next() orelse return error.InvalidCron;
        const f_mon = it.next() orelse return error.InvalidCron;
        const f_dow = it.next() orelse return error.InvalidCron;
        if (it.next() != null) return error.InvalidCron;
        var dow = try field(f_dow, 0, 7, &dow_names);
        if (dow & (1 << 7) != 0) dow = (dow | 1) & ~@as(u64, 1 << 7);
        return .{
            .minutes = try field(f_min, 0, 59, &.{}),
            .hours = @intCast(try field(f_hour, 0, 23, &.{})),
            .dom = @intCast(try field(f_dom, 1, 31, &.{})),
            .months = @intCast(try field(f_mon, 1, 12, &month_names)),
            .dow = @intCast(dow),
            .dom_star = isStar(f_dom),
            .dow_star = isStar(f_dow),
        };
    }

    /// The first fire time strictly after `after_ns` (wall ns since the Unix
    /// epoch; a time before 1970 counts as 1970), or null when the expression
    /// can never fire (`0 0 31 2 *`).
    pub fn next(self: Cron, after_ns: i64) ?i64 {
        const secs: u64 = @intCast(@max(@divFloor(after_ns, std.time.ns_per_s), 0));
        // Start at the next whole minute.
        var t: u64 = (secs / 60 + 1) * 60;
        const start_year = epoch.EpochSeconds.getEpochDay(.{ .secs = t }).calculateYearDay().year;
        while (true) {
            const es: epoch.EpochSeconds = .{ .secs = t };
            const day = es.getEpochDay();
            const yd = day.calculateYearDay();
            if (yd.year > start_year + 9) return null; // never (Feb 29 recurs within 8)
            const md = yd.calculateMonthDay();
            const mon: u4 = md.month.numeric();
            if (self.months & (@as(u16, 1) << mon) == 0) {
                t = (@as(u64, day.day) + epoch.getDaysInMonth(yd.year, md.month) - md.day_index) * 86400;
                continue;
            }
            const dom_ok = self.dom & (@as(u32, 1) << (md.day_index + 1)) != 0;
            // Epoch day 0 (1970-01-01) was a Thursday = 4.
            const wd: u3 = @intCast((day.day + 4) % 7);
            const dow_ok = self.dow & (@as(u8, 1) << wd) != 0;
            const day_ok = if (self.dom_star or self.dow_star) dom_ok and dow_ok else dom_ok or dow_ok;
            if (!day_ok) {
                t = (@as(u64, day.day) + 1) * 86400;
                continue;
            }
            const ds = es.getDaySeconds();
            const h = ds.getHoursIntoDay();
            if (self.hours & (@as(u32, 1) << h) == 0) {
                t = (t / 3600 + 1) * 3600;
                continue;
            }
            const m = ds.getMinutesIntoHour();
            if (self.minutes & (@as(u64, 1) << m) == 0) {
                t += 60;
                continue;
            }
            return @as(i64, @intCast(t)) * std.time.ns_per_s;
        }
    }

    /// True when `at_ns` falls in a minute this expression fires in.
    pub fn matches(self: Cron, at_ns: i64) bool {
        const minute_start = @divFloor(at_ns, ns_per_min) * ns_per_min;
        const n = self.next(minute_start - 1) orelse return false;
        return n == minute_start;
    }
};

fn parseAlias(e: []const u8) ParseError!Cron {
    const map = [_]struct { []const u8, []const u8 }{
        .{ "@yearly", "0 0 1 1 *" },
        .{ "@annually", "0 0 1 1 *" },
        .{ "@monthly", "0 0 1 * *" },
        .{ "@weekly", "0 0 * * 0" },
        .{ "@daily", "0 0 * * *" },
        .{ "@midnight", "0 0 * * *" },
        .{ "@hourly", "0 * * * *" },
    };
    for (map) |m| if (std.ascii.eqlIgnoreCase(e, m[0])) return Cron.parse(m[1]);
    return error.InvalidCron;
}

const month_names = [_][]const u8{ "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec" };
const dow_names = [_][]const u8{ "sun", "mon", "tue", "wed", "thu", "fri", "sat" };

fn isStar(f: []const u8) bool {
    return f.len != 0 and (f[0] == '*' or f[0] == '?');
}

/// Bit i set = value i fires.
fn field(f: []const u8, lo: u8, hi: u8, names: []const []const u8) ParseError!u64 {
    var mask: u64 = 0;
    var parts = std.mem.splitScalar(u8, f, ',');
    while (parts.next()) |part| {
        if (part.len == 0) return error.InvalidCron;
        var range = part;
        var step: u8 = 1;
        if (std.mem.indexOfScalar(u8, part, '/')) |i| {
            range = part[0..i];
            step = std.fmt.parseInt(u8, part[i + 1 ..], 10) catch return error.InvalidCron;
            if (step == 0) return error.InvalidCron;
        }
        var a: u8 = lo;
        var b: u8 = hi;
        if (std.mem.eql(u8, range, "*") or std.mem.eql(u8, range, "?")) {
            // full range
        } else if (std.mem.indexOfScalar(u8, range, '-')) |i| {
            a = try value(range[0..i], lo, hi, names);
            b = try value(range[i + 1 ..], lo, hi, names);
            if (a > b) return error.InvalidCron;
        } else {
            a = try value(range, lo, hi, names);
            // `n/s` runs from n to the end of the field; plain `n` is just n.
            b = if (std.mem.indexOfScalar(u8, part, '/') != null) hi else a;
        }
        var v: u16 = a;
        while (v <= b) : (v += step) mask |= @as(u64, 1) << @intCast(v);
    }
    return mask;
}

fn value(s: []const u8, lo: u8, hi: u8, names: []const []const u8) ParseError!u8 {
    if (s.len == 0) return error.InvalidCron;
    if (std.ascii.isDigit(s[0])) {
        const v = std.fmt.parseInt(u8, s, 10) catch return error.InvalidCron;
        if (v < lo or v > hi) return error.InvalidCron;
        return v;
    }
    for (names, 0..) |n, i| {
        if (std.ascii.eqlIgnoreCase(s, n)) return @intCast(i + lo);
    }
    return error.InvalidCron;
}

fn ts(y: i64, mo: u8, d: u8, h: u8, mi: u8) i64 {
    // days from civil (Hinnant)
    const yy = if (mo <= 2) y - 1 else y;
    const era = @divFloor(yy, 400);
    const yoe = yy - era * 400;
    const mp: i64 = if (mo > 2) mo - 3 else mo + 9;
    const doy = @divFloor(153 * mp + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    const days = era * 146097 + doe - 719468;
    return ((days * 24 + h) * 60 + mi) * ns_per_min;
}

test "next: common expressions" {
    const t = std.testing;
    const c1 = try Cron.parse("*/15 * * * *");
    try t.expectEqual(@as(?i64, ts(2026, 11, 21, 10, 15)), c1.next(ts(2026, 11, 21, 10, 0)));
    try t.expectEqual(@as(?i64, ts(2026, 11, 21, 10, 15)), c1.next(ts(2026, 11, 21, 10, 14) + 59_000_000_000));
    try t.expectEqual(@as(?i64, ts(2026, 11, 21, 11, 0)), c1.next(ts(2026, 11, 21, 10, 45)));
    const c2 = try Cron.parse("30 2 * * *");
    try t.expectEqual(@as(?i64, ts(2026, 11, 22, 2, 30)), c2.next(ts(2026, 11, 21, 2, 30)));
    try t.expectEqual(@as(?i64, ts(2026, 12, 1, 0, 0)), (try Cron.parse("@monthly")).next(ts(2026, 11, 21, 0, 0)));
    try t.expectEqual(@as(?i64, ts(2027, 1, 1, 0, 0)), (try Cron.parse("@yearly")).next(ts(2026, 12, 31, 23, 59)));
    // 2026-11-21 is a Saturday; the next Monday is the 23rd.
    try t.expectEqual(@as(?i64, ts(2026, 11, 23, 9, 0)), (try Cron.parse("0 9 * * MON")).next(ts(2026, 11, 21, 12, 0)));
    try t.expectEqual(@as(?i64, ts(2026, 11, 22, 0, 0)), (try Cron.parse("@weekly")).next(ts(2026, 11, 21, 12, 0)));
    // 7 is Sunday too.
    try t.expectEqual(@as(?i64, ts(2026, 11, 22, 0, 0)), (try Cron.parse("0 0 * * 7")).next(ts(2026, 11, 21, 12, 0)));
}

test "next: dom and dow are ORed when both are restricted, ANDed with a star" {
    const t = std.testing;
    // the 1st OR any Friday: from Sat 2026-11-21 the next hit is Fri 2026-11-27
    const c = try Cron.parse("0 0 1 * FRI");
    try t.expectEqual(@as(?i64, ts(2026, 11, 27, 0, 0)), c.next(ts(2026, 11, 21, 12, 0)));
    try t.expectEqual(@as(?i64, ts(2026, 12, 1, 0, 0)), c.next(ts(2026, 11, 27, 0, 0)));
    // `*/2` in dom counts as a star: Fridays among odd days only
    const s = try Cron.parse("0 0 */2 * FRI");
    try t.expectEqual(@as(?i64, ts(2026, 11, 27, 0, 0)), s.next(ts(2026, 11, 21, 12, 0)));
}

test "next: leap day, impossible dates, lists, ranges and steps" {
    const t = std.testing;
    const leap = try Cron.parse("0 0 29 2 *");
    try t.expectEqual(@as(?i64, ts(2028, 2, 29, 0, 0)), leap.next(ts(2026, 11, 21, 0, 0)));
    try t.expectEqual(@as(?i64, null), (try Cron.parse("0 0 31 2 *")).next(ts(2026, 1, 1, 0, 0)));
    try t.expectEqual(@as(?i64, null), (try Cron.parse("0 0 31 4,6,9,11 *")).next(ts(2026, 1, 1, 0, 0)));
    const c = try Cron.parse("5,10-20/5,45 8-9 * JAN,mar *");
    try t.expectEqual(@as(?i64, ts(2027, 1, 1, 8, 5)), c.next(ts(2026, 11, 21, 0, 0)));
    try t.expectEqual(@as(?i64, ts(2027, 1, 1, 8, 10)), c.next(ts(2027, 1, 1, 8, 5)));
    try t.expectEqual(@as(?i64, ts(2027, 1, 1, 8, 15)), c.next(ts(2027, 1, 1, 8, 10)));
    try t.expectEqual(@as(?i64, ts(2027, 1, 1, 8, 20)), c.next(ts(2027, 1, 1, 8, 15)));
    try t.expectEqual(@as(?i64, ts(2027, 1, 1, 8, 45)), c.next(ts(2027, 1, 1, 8, 20)));
    try t.expectEqual(@as(?i64, ts(2027, 1, 1, 9, 5)), c.next(ts(2027, 1, 1, 8, 45)));
    // `n/s` runs from n to the end of the field
    const ns = try Cron.parse("50/5 0 * * *");
    try t.expectEqual(@as(?i64, ts(2026, 11, 22, 0, 50)), ns.next(ts(2026, 11, 21, 12, 0)));
    try t.expectEqual(@as(?i64, ts(2026, 11, 22, 0, 55)), ns.next(ts(2026, 11, 22, 0, 50)));
    try t.expect(ns.matches(ts(2026, 11, 22, 0, 55) + 1));
    try t.expect(!ns.matches(ts(2026, 11, 22, 0, 56)));
    try t.expectEqual(@as(?i64, ts(1970, 1, 1, 0, 1)), (try Cron.parse("* * * * *")).next(-5 * ns_per_min));
}

test "parse: refusals" {
    const t = std.testing;
    for ([_][]const u8{ "", "* * * *", "* * * * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * 32 * *", "* * * 13 *", "* * * * 8", "*/0 * * * *", "5-1 * * * *", "a * * * *", "1,,2 * * * *", "@never", "-1 * * * *", "1- * * * *", "*/ * * * *", "* * * FOO *" }) |e| {
        try t.expectError(error.InvalidCron, Cron.parse(e));
    }
}
