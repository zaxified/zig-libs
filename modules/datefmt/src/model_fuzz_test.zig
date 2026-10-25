// SPDX-License-Identifier: MIT

//! Differential fuzz against an independent model (the card's
//! `**Evidence:** model-fuzz`). The model is the Fliegel–Van Flandern
//! Julian Day Number formula (CACM 11(10), 1968) -- a different algorithm
//! from the Hinnant civil core under test, with C's truncating division,
//! valid for every JDN >= 0 (years from -4713). Against it, per drawn date:
//!   * `ymdToEpochDay` / `epochDayToYmd` both ways, and `isoWeekday` (from
//!     the JDN, `(jdn + 1) mod 7` is Sunday=0);
//!   * `partsToUnix` / `unixToParts` with a drawn time of day, and the
//!     nanosecond pair;
//!   * `addDays` against the model's day count, `diffInDays` likewise;
//!   * for years 0..9999, the canned writers read back by their parsers:
//!     `bufRfc3339` -> `parseRfc3339` (0..9 fraction digits, truncation),
//!     `bufImfFixdate` -> `parseImfFixdate` and `parseRfc2822`, and the
//!     token engine `format` -> `parse` over formats with every field.
//! The audit's D1 (2026-10-25: every date before 0000-03-01 one day off) is
//! the defect class this would have caught: the year range reaches -4713.
//!
//! `DATEFMT_FUZZ=<runs>[,<seed>]` runs the deterministic driver; 400 seeds
//! run in every test run.

const std = @import("std");
const testing = std.testing;
const dt = @import("root.zig");
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;

/// Fliegel–Van Flandern: Gregorian Y/M/D to Julian Day Number.
fn modelJdn(y: i64, m: i64, d: i64) i64 {
    const a = @divTrunc(m - 14, 12);
    return @divTrunc(1461 * (y + 4800 + a), 4) +
        @divTrunc(367 * (m - 2 - 12 * a), 12) -
        @divTrunc(3 * @divTrunc(y + 4900 + a, 100), 4) +
        d - 32075;
}

/// Unix epoch day 0 (1970-01-01) is JDN 2440588.
const jdn_epoch = 2_440_588;

fn modelDaysInMonth(y: i64, m: i64) i64 {
    // From the model itself: the next month's first day minus this one's.
    const ny = if (m == 12) y + 1 else y;
    const nm = if (m == 12) 1 else m + 1;
    return modelJdn(ny, nm, 1) - modelJdn(y, m, 1);
}

const Label = enum { negative_year, before_0000_03_01, leap_feb29, canned_roundtrip, token_roundtrip, frac_digits };
var reach: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    reach[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

const token_formats = [_][]const u8{
    "YYYY-MM-DD[T]hh:mm:ss",
    "EEE, DD MMM YYYY hh:mm:ss [GMT]",
    "EEEE DD MMMM YYYY hh:mm:ss.SSS",
    "YYYY/MM/DD hh:mm:ss",
};

fn harness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    for (0..16) |_| {
        // Mostly the canned range, a quarter from the model's whole range.
        const wide = src.valueRangeAtMost(u8, 0, 3) == 0;
        const y: i32 = if (wide) src.valueRangeAtMost(i32, -4712, 100_000) else src.valueRangeAtMost(i32, 0, 9999);
        const m = src.valueRangeAtMost(u32, 1, 12);
        const dim: u32 = @intCast(modelDaysInMonth(y, m));
        const d = src.valueRangeAtMost(u32, 1, dim);
        if (y < 0) mark(.negative_year);
        if (y < 0 or (y == 0 and m <= 2)) mark(.before_0000_03_01);
        if (m == 2 and d == 29) mark(.leap_feb29);

        const jdn = modelJdn(y, m, d);
        const want_day = jdn - jdn_epoch;
        if (dim != dt.daysInMonth(y, m)) return error.DaysInMonthDiffers;
        if (dt.ymdToEpochDay(y, m, d) != want_day) return error.EpochDayDiffers;
        const back = dt.epochDayToYmd(want_day);
        if (back.year != y or back.month != m or back.day != d) return error.EpochDayInverseDiffers;
        const sun0: u32 = @intCast(@mod(jdn + 1, 7)); // Sunday = 0
        if (dt.isoWeekday(want_day) != (if (sun0 == 0) 7 else sun0)) return error.WeekdayDiffers;

        const p: dt.DateParts = .{
            .year = y,
            .month = m,
            .day = d,
            .hour = src.valueRangeAtMost(u32, 0, 23),
            .minute = src.valueRangeAtMost(u32, 0, 59),
            .second = src.valueRangeAtMost(u32, 0, 59),
            .nanosecond = src.valueRangeAtMost(u32, 0, 999_999_999),
        };
        const want_unix = want_day * 86400 + @as(i64, p.hour) * 3600 + @as(i64, p.minute) * 60 + p.second;
        if (dt.partsToUnix(p) != want_unix) return error.UnixDiffers;
        const u = dt.unixToParts(want_unix);
        if (u.year != y or u.month != m or u.day != d or u.hour != p.hour or u.minute != p.minute or u.second != p.second) return error.UnixInverseDiffers;
        if (dt.partsToUnixNs(p)) |ns| {
            if (ns != want_unix * 1_000_000_000 + p.nanosecond) return error.UnixNsDiffers;
            if (dt.unixNsToParts(ns).nanosecond != p.nanosecond) return error.UnixNsInverseDiffers;
        }

        const n = src.valueRangeAtMost(i64, -400_000, 400_000);
        const moved = dt.addDays(p, n);
        if (moved.year >= -4712) {
            if (modelJdn(moved.year, moved.month, moved.day) != jdn + n) return error.AddDaysDiffers;
            if (dt.diffInDays(moved, p) != n) return error.DiffInDaysDiffers;
        }

        if (y < 0 or y > 9999) continue;
        // The canned writers, read back.
        mark(.canned_roundtrip);
        const digits = src.valueRangeAtMost(u8, 0, 9);
        if (digits > 0) mark(.frac_digits);
        var rb: [dt.rfc3339_max_len]u8 = undefined;
        const r = try dt.bufRfc3339(&rb, p, digits);
        const rp = try dt.parseRfc3339(r);
        var scale: u32 = 1;
        for (0..9 - digits) |_| scale *= 10;
        if (dt.partsToUnix(rp) != want_unix or rp.nanosecond != p.nanosecond / scale * scale) return error.Rfc3339RoundTripDiffers;
        var ib: [dt.imf_fixdate_len]u8 = undefined;
        try dt.bufImfFixdate(&ib, p);
        if (dt.partsToUnix(try dt.parseImfFixdate(&ib)) != want_unix) return error.ImfRoundTripDiffers;
        const m2822 = try dt.parseRfc2822(&ib);
        if (dt.partsToUnix(m2822) - @as(i64, m2822.off_min orelse 0) * 60 != want_unix) return error.Rfc2822OfImfDiffers;

        // The token engine, read back.
        mark(.token_roundtrip);
        const f = token_formats[src.valueRangeAtMost(u32, 0, token_formats.len - 1)];
        const s = try dt.format(gpa, p, f);
        defer gpa.free(s);
        const tp = try dt.parse(s, f);
        if (tp.year != y or tp.month != m or tp.day != d or tp.hour != p.hour or tp.minute != p.minute or tp.second != p.second) return error.TokenRoundTripDiffers;
    }
}

test "model fuzz driver: DATEFMT_FUZZ" {
    try fuzz_driver.run(harness, .{ .prefix = "DATEFMT_FUZZ", .name = "datefmt-model" });
}

test "model fuzz: 400 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..400) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("datefmt model seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 400 seeds\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}

test "model: the formula agrees with the published anchors" {
    // JDN 2451545 = 2000-01-01 (J2000.0's day); 0 = -4713-11-24 (proleptic Gregorian).
    try testing.expectEqual(@as(i64, 2_451_545), modelJdn(2000, 1, 1));
    try testing.expectEqual(@as(i64, jdn_epoch), modelJdn(1970, 1, 1));
    try testing.expectEqual(@as(i64, 0), modelJdn(-4713, 11, 24));
}
