// SPDX-License-Identifier: MIT
//! The cell model's tests, taken with the code from `dataset` (its own tests of `Value`,
//! `Date` and the ISO helpers), and a differential sweep: every pair of awkward cells
//! orders, compares and casts here as it does in `dataset`, whose row verbs are the
//! oracle of this module's verbs.

const std = @import("std");
const testing = std.testing;
const root = @import("value.zig");
const ds = @import("dataset");
const Value = root.Value;
const Column = root.Column;
const Date = root.Date;
const parseIsoDate = root.parseIsoDate;
const parseIsoTimestamp = root.parseIsoTimestamp;
const formatIsoTimestamp = root.formatIsoTimestamp;
const max_iso_timestamp_len = root.max_iso_timestamp_len;
const timestamp_units_per_second = root.timestamp_units_per_second;
const decimal_scale = root.decimal_scale;
const us_per_day: i64 = 86_400 * timestamp_units_per_second;

test "Value.eql and order" {
    try testing.expect(Value.eql(.{ .int = 3 }, .{ .float = 3.0 }));
    try testing.expect(!Value.eql(.{ .text = "a" }, .{ .text = "b" }));
    try testing.expectEqual(std.math.Order.lt, Value.order(.{ .float = 1 }, .{ .float = 2 }));
    try testing.expectEqual(std.math.Order.lt, Value.order(.null, .{ .int = 0 }));
}

test "Value.order: NaN sorts as the greatest value, not `unreachable` -- F1" {
    // `deserialize` hands a `.float` cell any wire bit pattern with no
    // finiteness check (tag `2`, `Cursor.f64v`), so NaN is directly
    // reachable from 8 attacker-supplied bytes. `std.math.order(af, bf)`
    // used to reach `unreachable` on it: Debug/ReleaseSafe panic, ReleaseFast
    // undefined behaviour. Before the fix this test panicked on its first
    // line instead of reaching any `expectEqual` -- that IS the regression.
    const nan = std.math.nan(f64);
    try testing.expectEqual(std.math.Order.gt, Value.order(.{ .float = nan }, .{ .float = 1.0 }));
    try testing.expectEqual(std.math.Order.lt, Value.order(.{ .float = 1.0 }, .{ .float = nan }));
    try testing.expectEqual(std.math.Order.gt, Value.order(.{ .float = nan }, .{ .float = std.math.inf(f64) }));
    try testing.expectEqual(std.math.Order.eq, Value.order(.{ .float = nan }, .{ .float = nan }));
    // Sibling `eql` already handled NaN without panicking (`af == bf` is
    // `false` for any NaN operand) -- pin that it still does, so the two
    // don't drift into disagreeing about what NaN means.
    try testing.expect(!Value.eql(.{ .float = nan }, .{ .float = nan }));
    try testing.expect(!Value.eql(.{ .float = nan }, .{ .float = 1.0 }));
}

test "Value.eql/order: bool values compared by actual value, and bool's type rank sits between null and numeric" {
    // Neither eql's .bool arm nor order's .bool arm (nor typeRank's bool=1
    // placement) had ANY test anywhere in this suite before this — every
    // existing eql/order test used int/float/text/decimal/null only.
    try testing.expect(Value.eql(.{ .bool = true }, .{ .bool = true }));
    try testing.expect(Value.eql(.{ .bool = false }, .{ .bool = false }));
    try testing.expect(!Value.eql(.{ .bool = true }, .{ .bool = false }));
    try testing.expect(!Value.eql(.{ .bool = false }, .{ .bool = true }));

    try testing.expectEqual(std.math.Order.eq, Value.order(.{ .bool = true }, .{ .bool = true }));
    try testing.expectEqual(std.math.Order.lt, Value.order(.{ .bool = false }, .{ .bool = true }));
    try testing.expectEqual(std.math.Order.gt, Value.order(.{ .bool = true }, .{ .bool = false }));

    // Documented ordering: null < bool < numeric < text.
    try testing.expectEqual(std.math.Order.lt, Value.order(.null, .{ .bool = false }));
    try testing.expectEqual(std.math.Order.lt, Value.order(.{ .bool = true }, .{ .int = 0 }));
    try testing.expectEqual(std.math.Order.lt, Value.order(.{ .bool = true }, .{ .text = "" }));
}

test "Value.asInt and cast" {
    try testing.expectEqual(@as(?i64, 3), (Value{ .int = 3 }).asInt());
    try testing.expectEqual(@as(?i64, 3), (Value{ .float = 3.9 }).asInt()); // truncates
    try testing.expectEqual(@as(?i64, null), (Value{ .text = "x" }).asInt());

    try testing.expectEqual(@as(?f64, 3.0), (Value{ .int = 3 }).cast(.float).?.asFloat());
    try testing.expect((Value{ .float = 1.0 }).cast(.bool).?.bool);
    try testing.expect(!(Value{ .int = 0 }).cast(.bool).?.bool);
    try testing.expectEqual(@as(?Value, null), (Value{ .text = "x" }).cast(.bool));
    try testing.expectEqualStrings("AAA", (Value{ .text = "AAA" }).cast(.date).?.text);
    try testing.expectEqual(@as(?Value, null), (Value{ .bool = true }).cast(.int));
}

test "parseIsoDate and ordinal monotonicity" {
    const a = parseIsoDate("2024-01-31").?;
    const b = parseIsoDate("2024-02-01").?;
    try testing.expect(a.ordinal() < b.ordinal());
    try testing.expectEqual(@as(i64, 1), b.ordinal() - a.ordinal());
    try testing.expectEqual(@as(?Date, null), parseIsoDate("bad"));
    // a well-known anchor: 1970-01-01 is ordinal 0
    try testing.expectEqual(@as(i64, 0), (parseIsoDate("1970-01-01").?).ordinal());
}

test "parseIsoDate: digits only, and the day must exist in its month" {
    // Gregorian leap rule: divisible by 4, except centuries, except every 400th.
    try testing.expect(parseIsoDate("2024-02-29") != null);
    try testing.expect(parseIsoDate("2000-02-29") != null);
    try testing.expectEqual(@as(?Date, null), parseIsoDate("2023-02-29"));
    try testing.expectEqual(@as(?Date, null), parseIsoDate("1900-02-29"));
    try testing.expectEqual(@as(?Date, null), parseIsoDate("2024-04-31")); // April has 30
    try testing.expect(parseIsoDate("2024-12-31") != null);
    try testing.expectEqual(@as(?Date, null), parseIsoDate("2024-00-10"));
    try testing.expectEqual(@as(?Date, null), parseIsoDate("2024-13-10"));
    try testing.expectEqual(@as(?Date, null), parseIsoDate("2024-01-00"));
    // `std.fmt.parseInt` takes a sign; a date field must not.
    try testing.expectEqual(@as(?Date, null), parseIsoDate("2024-+1-01"));
    try testing.expectEqual(@as(?Date, null), parseIsoDate("+024-01-01"));
    try testing.expectEqual(@as(?Date, null), parseIsoDate("2024-01- 1"));
    // Trailing text is still ignored (the documented contract).
    try testing.expectEqual(Date{ .y = 2024, .m = 1, .d = 2 }, parseIsoDate("2024-01-02T10:00").?);
}

test "Date.fromOrdinal inverts ordinal, anchored on known day counts" {
    // 0000-01-01 is 719528 days before the epoch: Python's
    // date(1970,1,1).toordinal() - date(1,1,1).toordinal() = 719162, plus the
    // 366 days of the (leap) year 0 that Python's calendar does not have.
    try testing.expectEqual(@as(i64, -719528), (Date{ .y = 0, .m = 1, .d = 1 }).ordinal());
    try testing.expectEqual(Date{ .y = 0, .m = 1, .d = 1 }, Date.fromOrdinal(-719528).?);
    try testing.expectEqual(Date{ .y = -1, .m = 12, .d = 31 }, Date.fromOrdinal(-719529).?);
    // -0400-03-01 is exactly one 400-year era (146097 days) before 0000-03-01,
    // which is 0000-01-01 + 31 + 29 (year 0 is a leap year) = -719468. The
    // pre-fix `ordinal` put it one more era earlier.
    try testing.expectEqual(@as(i64, -719468), (Date{ .y = 0, .m = 3, .d = 1 }).ordinal());
    try testing.expectEqual(@as(i64, -719468 - 146097), (Date{ .y = -400, .m = 3, .d = 1 }).ordinal());
    try testing.expectEqual(@as(i64, -719528 - 365), (Date{ .y = -1, .m = 1, .d = 1 }).ordinal()); // -1 is not leap
    try testing.expectEqual(Date{ .y = 1970, .m = 1, .d = 1 }, Date.fromOrdinal(0).?);
    try testing.expectEqual(Date{ .y = 1969, .m = 12, .d = 31 }, Date.fromOrdinal(-1).?);
    // 2000-03-01 is day 11017 (Unix time 951868800 / 86400): just past a
    // 400-year leap day, the case the era arithmetic exists for.
    try testing.expectEqual(Date{ .y = 2000, .m = 3, .d = 1 }, Date.fromOrdinal(11017).?);
    try testing.expectEqual(Date{ .y = 2000, .m = 2, .d = 29 }, Date.fromOrdinal(11016).?);
    // Round trip over five 400-year eras around the epoch, each step checked
    // against the calendar itself (the day after d is d+1, or the 1st of the
    // next month, or 1 January), not against the code under test.
    var prev = Date.fromOrdinal(-1_000_000).?;
    var day: i64 = -999_999;
    while (day <= 1_000_000) : (day += 1) {
        const d = Date.fromOrdinal(day).?;
        try testing.expectEqual(day, d.ordinal());
        if (prev.d < Date.daysInMonth(prev.y, prev.m)) {
            try testing.expectEqual(Date{ .y = prev.y, .m = prev.m, .d = prev.d + 1 }, d);
        } else if (prev.m < 12) {
            try testing.expectEqual(Date{ .y = prev.y, .m = prev.m + 1, .d = 1 }, d);
        } else try testing.expectEqual(Date{ .y = prev.y + 1, .m = 1, .d = 1 }, d);
        prev = d;
    }
    try testing.expectEqual(@as(?Date, null), Date.fromOrdinal(std.math.maxInt(i64)));
}

test "parseIsoTimestamp: well-known Unix times, offsets and fractions" {
    const s = timestamp_units_per_second;
    try testing.expectEqual(@as(?i64, 0), parseIsoTimestamp("1970-01-01T00:00:00Z"));
    try testing.expectEqual(@as(?i64, 0), parseIsoTimestamp("1970-01-01"));
    // Published anchors: Y2K = 946684800, the "1234567890" moment, and the
    // last second a signed 32-bit time_t can hold.
    try testing.expectEqual(@as(?i64, 946684800 * s), parseIsoTimestamp("2000-01-01T00:00:00Z"));
    try testing.expectEqual(@as(?i64, 1234567890 * s), parseIsoTimestamp("2009-02-13T23:31:30Z"));
    try testing.expectEqual(@as(?i64, 2147483647 * s), parseIsoTimestamp("2038-01-19T03:14:07Z"));
    // The same instant in other zones: local = UTC + offset.
    try testing.expectEqual(@as(?i64, 1234567890 * s), parseIsoTimestamp("2009-02-14T00:31:30+01:00"));
    try testing.expectEqual(@as(?i64, 1234567890 * s), parseIsoTimestamp("2009-02-13T18:01:30-05:30"));
    try testing.expectEqual(@as(?i64, 1234567890 * s), parseIsoTimestamp("2009-02-13T18:01:30-0530"));
    try testing.expectEqual(@as(?i64, 1234567890 * s), parseIsoTimestamp("2009-02-14T00:31:30+01"));
    // Separators: `t` and a space are RFC 3339 §5.6's allowed alternatives to `T`.
    try testing.expectEqual(@as(?i64, 1234567890 * s), parseIsoTimestamp("2009-02-13 23:31:30z"));
    try testing.expectEqual(@as(?i64, 1234567890 * s), parseIsoTimestamp("2009-02-13t23:31:30"));
    // Seconds are optional; no zone means UTC.
    try testing.expectEqual(@as(?i64, 1234567860 * s), parseIsoTimestamp("2009-02-13T23:31"));
    // Fractions: scaled to microseconds, digits 7..9 dropped, `,` accepted.
    try testing.expectEqual(@as(?i64, 500_000), parseIsoTimestamp("1970-01-01T00:00:00.5Z"));
    try testing.expectEqual(@as(?i64, 250_000), parseIsoTimestamp("1970-01-01T00:00:00,25"));
    try testing.expectEqual(@as(?i64, 123_456), parseIsoTimestamp("1970-01-01T00:00:00.123456789Z"));
    try testing.expectEqual(@as(?i64, 1), parseIsoTimestamp("1970-01-01T00:00:00.000001Z"));
    // Before the epoch: the fraction still counts forward from its second.
    try testing.expectEqual(@as(?i64, -1), parseIsoTimestamp("1969-12-31T23:59:59.999999Z"));
    try testing.expectEqual(@as(?i64, -s), parseIsoTimestamp("1969-12-31T23:59:59Z"));
    // Extremes of the accepted range: 0000-01-01 is day -719528 (see the
    // fromOrdinal test); 10000-01-01 is 253402300800 (9999-12-31T23:59:59 is
    // the commonly quoted 253402300799).
    try testing.expectEqual(@as(?i64, -719528 * 86400 * s), parseIsoTimestamp("0000-01-01"));
    try testing.expectEqual(@as(?i64, 253402300799 * s + 999_999), parseIsoTimestamp("9999-12-31T23:59:59.999999Z"));
}

test "parseIsoTimestamp: refuses everything outside the grammar" {
    const bad = [_][]const u8{
        "",                "2024-01-0",        "2024-02-30",
        "2024-01-01T",     "2024-01-01T10",    "2024-01-01T10:0",
        "2024-01-01T1:00", "2024-01-01X10:00", "2024-01-01T24:00:00Z",
        "2024-01-01T23:60:00Z", "2024-01-01T23:59:60Z", // no leap second
        "2024-01-01T10:00:",    "2024-01-01T10:00:5",
        "2024-01-01T10:00:00.",
        "2024-01-01T10:00:00.Z",     "2024-01-01T10:00:00.1234567890Z", // 10 fraction digits
        "2024-01-01T10:00:00Zjunk",  "2024-01-01T10:00:00+24:00",
        "2024-01-01T10:00:00+01:60", "2024-01-01T10:00:00+1",
        "2024-01-01T10:00:00+01:",   "2024-01-01T10:00:00+01:0",
        "2024-01-01T10:00:00 ",      "2024-01-01T+1:00",
        "2024-01-01T10:00:00+0100x", "2024-01-01T10:00:00Q",
    };
    for (bad) |b| {
        if (parseIsoTimestamp(b)) |v| {
            std.debug.print("accepted {s} as {d}\n", .{ b, v });
            return error.TestUnexpectedResult;
        }
    }
}

test "formatIsoTimestamp: RFC 3339 UTC, trimmed fraction, expanded years" {
    var buf: [max_iso_timestamp_len]u8 = undefined;
    const s = timestamp_units_per_second;
    try testing.expectEqualStrings("1970-01-01T00:00:00Z", formatIsoTimestamp(&buf, 0));
    try testing.expectEqualStrings("2009-02-13T23:31:30.123456Z", formatIsoTimestamp(&buf, 1234567890 * s + 123_456));
    try testing.expectEqualStrings("1970-01-01T00:00:00.5Z", formatIsoTimestamp(&buf, 500_000));
    try testing.expectEqualStrings("1970-01-01T00:00:00.00001Z", formatIsoTimestamp(&buf, 10));
    try testing.expectEqualStrings("1969-12-31T23:59:59.999999Z", formatIsoTimestamp(&buf, -1));
    try testing.expectEqualStrings("9999-12-31T23:59:59Z", formatIsoTimestamp(&buf, 253402300799 * s));
    try testing.expectEqualStrings("+10000-01-01T00:00:00Z", formatIsoTimestamp(&buf, 253402300800 * s));
    try testing.expectEqualStrings("-0001-12-31T00:00:00Z", formatIsoTimestamp(&buf, -719529 * 86400 * s));
    // The i64 limits, as numpy prints datetime64[us] at +/-(2**63-1)
    // ('294247-01-10T04:00:54.775807', '-290308-12-21T19:59:05.224193'),
    // and minInt is one microsecond before the latter. DuckDB documents the
    // same maximum for its microsecond TIMESTAMP.
    try testing.expectEqualStrings("+294247-01-10T04:00:54.775807Z", formatIsoTimestamp(&buf, std.math.maxInt(i64)));
    try testing.expectEqualStrings("-290308-12-21T19:59:05.224192Z", formatIsoTimestamp(&buf, std.math.minInt(i64)));
}

test "formatIsoTimestamp / parseIsoTimestamp round-trip across years 0000..9999" {
    var prng = std.Random.DefaultPrng.init(0x7173);
    const r = prng.random();
    const lo: i64 = -719528 * us_per_day;
    const hi: i64 = 253402300800 * timestamp_units_per_second - 1;
    var buf: [max_iso_timestamp_len]u8 = undefined;
    for (0..20_000) |_| {
        const us = r.intRangeAtMost(i64, lo, hi);
        const text = formatIsoTimestamp(&buf, us);
        try testing.expectEqual(@as(?i64, us), parseIsoTimestamp(text));
    }
}

test "Value.decimal: asFloat/asInt coercion" {
    const v = Value{ .decimal = 1_500_000_000_000 }; // 1.5 at scale 1e12
    try testing.expectEqual(@as(f64, 1.5), v.asFloat().?);
    try testing.expectEqual(@as(?i64, 1), v.asInt().?); // truncates toward zero

    const neg = Value{ .decimal = -2_250_000_000_000 }; // -2.25
    try testing.expectEqual(@as(f64, -2.25), neg.asFloat().?);
    try testing.expectEqual(@as(?i64, -2), neg.asInt().?);

    try testing.expectEqual(@as(?[]const u8, null), v.asText());
}

test "Value.decimal: eql/order compare exactly on the raw i128, not lossy f64" {
    const a = Value{ .decimal = 1_000_000_000_001 }; // 1.000000000001
    const b = Value{ .decimal = 1_000_000_000_002 }; // 1.000000000002 — 1 ULP apart at scale 1e12
    try testing.expect(!Value.eql(a, b));
    try testing.expectEqual(std.math.Order.lt, Value.order(a, b));
    try testing.expect(Value.eql(a, .{ .decimal = 1_000_000_000_001 }));

    // Cross-type: decimal vs int/float still compares numerically via the
    // asFloat path (documented lossy fallback for mixed-type comparison).
    try testing.expect(Value.eql(.{ .decimal = 3_000_000_000_000 }, .{ .int = 3 }));
    try testing.expectEqual(std.math.Order.lt, Value.order(.{ .decimal = 1_000_000_000_000 }, .{ .int = 2 }));

    // null < bool < numeric(int/float/decimal) < text — decimal shares the
    // numeric rank.
    try testing.expectEqual(std.math.Order.lt, Value.order(.null, .{ .decimal = 0 }));
    try testing.expectEqual(std.math.Order.lt, Value.order(.{ .decimal = 0 }, .{ .text = "x" }));
}

test "Value.cast: float<->decimal and int<->decimal coercion" {
    const from_int = (Value{ .int = 7 }).cast(.decimal).?;
    try testing.expectEqual(@as(i128, 7_000_000_000_000), from_int.decimal);

    const from_float = (Value{ .float = 2.5 }).cast(.decimal).?;
    try testing.expectEqual(@as(i128, 2_500_000_000_000), from_float.decimal);

    // -0.5 is exact in binary floating point, so this exercises the negative
    // path with no rounding ambiguity.
    const from_neg_float = (Value{ .float = -0.5 }).cast(.decimal).?;
    try testing.expectEqual(@as(i128, -500_000_000_000), from_neg_float.decimal);

    // non-finite float -> null, not a crash/UB.
    try testing.expectEqual(@as(?Value, null), (Value{ .float = std.math.inf(f64) }).cast(.decimal));
    try testing.expectEqual(@as(?Value, null), (Value{ .float = std.math.nan(f64) }).cast(.decimal));

    // decimal -> float / int round-trips through the general asFloat/asInt path.
    const d = Value{ .decimal = 4_250_000_000_000 };
    try testing.expectEqual(@as(f64, 4.25), d.cast(.float).?.float);
    try testing.expectEqual(@as(i64, 4), d.cast(.int).?.int);

    // decimal passthrough.
    try testing.expectEqual(@as(i128, 4_250_000_000_000), d.cast(.decimal).?.decimal);

    // text -> decimal intentionally not attempted (documented: would need the
    // `decimal` module's parser).
    try testing.expectEqual(@as(?Value, null), (Value{ .text = "1.5" }).cast(.decimal));
}

test "Value.order / eql: ints above 2^53 are told apart, never rounded through f64 (sweep DS5)" {
    const big: i64 = 1 << 53;
    try testing.expectEqual(std.math.Order.lt, (Value{ .int = big }).order(.{ .int = big + 1 }));
    try testing.expectEqual(std.math.Order.gt, (Value{ .int = std.math.maxInt(i64) }).order(.{ .int = std.math.maxInt(i64) - 1 }));
    try testing.expect(!(Value{ .int = big }).eql(.{ .int = big + 1 }));
    try testing.expect((Value{ .int = big + 1 }).eql(.{ .int = big + 1 }));
    // int against float, exactly: 2^53 + 1 is above the float 2^53
    try testing.expectEqual(std.math.Order.gt, (Value{ .int = big + 1 }).order(.{ .float = 9007199254740992.0 }));
    try testing.expectEqual(std.math.Order.eq, (Value{ .int = big }).order(.{ .float = 9007199254740992.0 }));
    try testing.expectEqual(std.math.Order.lt, (Value{ .int = std.math.maxInt(i64) }).order(.{ .float = 9223372036854775808.0 }));
    try testing.expectEqual(std.math.Order.gt, (Value{ .int = std.math.minInt(i64) }).order(.{ .float = -9223372036854777856.0 }));
    // int against decimal, exactly
    try testing.expectEqual(std.math.Order.eq, (Value{ .int = 3 }).order(.{ .decimal = 3 * root.decimal_scale }));
    try testing.expectEqual(std.math.Order.lt, (Value{ .int = 3 }).order(.{ .decimal = 3 * root.decimal_scale + 1 }));
}

test "Value.order: float against decimal is exact on the fraction, down to the subnormals (sweep DS6)" {
    const D = struct {
        fn f(x: f64, raw: i128) std.math.Order {
            return (Value{ .float = x }).order(.{ .decimal = raw });
        }
    };
    try testing.expectEqual(std.math.Order.eq, D.f(0.5, 500_000_000_000));
    try testing.expectEqual(std.math.Order.eq, D.f(0.25, 250_000_000_000));
    // 0.1 as a double is a hair ABOVE 1/10, 0.3 a hair BELOW 3/10
    try testing.expectEqual(std.math.Order.gt, D.f(0.1, 100_000_000_000));
    try testing.expectEqual(std.math.Order.lt, D.f(0.3, 300_000_000_000));
    try testing.expectEqual(std.math.Order.gt, D.f(0.7, 600_000_000_000));
    try testing.expectEqual(std.math.Order.lt, D.f(0.7, 800_000_000_000));
    try testing.expectEqual(std.math.Order.gt, D.f(5e-324, 0));
    try testing.expectEqual(std.math.Order.lt, D.f(5e-324, 1));
    try testing.expectEqual(std.math.Order.lt, D.f(-0.5, 0));
    try testing.expectEqual(std.math.Order.eq, D.f(-0.5, -500_000_000_000));
    try testing.expectEqual(std.math.Order.gt, D.f(1e30, std.math.maxInt(i128)));
    try testing.expectEqual(std.math.Order.lt, D.f(-1e30, std.math.minInt(i128)));
    try testing.expectEqual(std.math.Order.lt, D.f(-std.math.inf(f64), std.math.minInt(i128)));
    try testing.expectEqual(std.math.Order.gt, D.f(std.math.inf(f64), std.math.maxInt(i128)));
}

test "Value.order is a strict weak order over a pool of awkward numbers, null, bool and text (sweep DS7)" {
    const nan = std.math.nan(f64);
    const inf = std.math.inf(f64);
    const sc = root.decimal_scale;
    const pool = [_]Value{
        .null,                                           .{ .bool = false },                        .{ .bool = true },
        .{ .text = "" },                                 .{ .text = "a" },                          .{ .int = std.math.minInt(i64) },
        .{ .int = -1 },                                  .{ .int = 0 },                             .{ .int = 1 },
        .{ .int = 1 << 53 },                             .{ .int = (1 << 53) + 1 },                 .{ .int = std.math.maxInt(i64) },
        .{ .float = -inf },                              .{ .float = -1.5 },                        .{ .float = 0 },
        .{ .float = 0.1 },                               .{ .float = 0.5 },                         .{ .float = 1 },
        .{ .float = 9007199254740992.0 },                .{ .float = 9007199254740994.0 },          .{ .float = 9223372036854775808.0 },
        .{ .float = 1e30 },                              .{ .float = inf },                         .{ .float = nan },
        .{ .float = 5e-324 },                            .{ .decimal = 0 },                         .{ .decimal = 1 },
        .{ .decimal = sc / 10 },                         .{ .decimal = sc / 2 },                    .{ .decimal = sc },
        .{ .decimal = -sc / 2 },                         .{ .decimal = (@as(i128, 1) << 53) * sc }, .{ .decimal = (@as(i128, 1) << 53) * sc + 1 },
        .{ .decimal = ((@as(i128, 1) << 53) + 1) * sc }, .{ .decimal = std.math.maxInt(i128) },     .{ .decimal = std.math.minInt(i128) },
    };
    const lt = std.math.Order.lt;
    const gt = std.math.Order.gt;
    for (pool) |a| {
        try testing.expectEqual(std.math.Order.eq, a.order(a));
        for (pool) |b| {
            try testing.expectEqual(b.order(a).invert(), a.order(b)); // antisymmetry
            const nan_involved = (a == .float and std.math.isNan(a.float)) or (b == .float and std.math.isNan(b.float));
            if (!nan_involved and a.order(b) == .eq) try testing.expect(a.eql(b));
            for (pool) |c| {
                // transitivity of <= and of equivalence
                if (a.order(b) != gt and b.order(c) != gt) try testing.expect(a.order(c) != gt);
                if (a.order(b) == lt and b.order(c) != gt) try testing.expect(a.order(c) == lt);
                if (a.order(b) == .eq and b.order(c) == .eq) try testing.expect(a.order(c) == .eq);
            }
        }
    }
}

test "Value.order: float limits, negative fractions and the 2^-76 shift boundary are exact (sweep audit GW-DS8)" {
    const D = struct {
        fn f(x: f64, raw: i128) std.math.Order {
            return (Value{ .float = x }).order(.{ .decimal = raw });
        }
    };
    // -2^63 as a float IS the smallest i64: equal, not "below every i64"
    try testing.expectEqual(std.math.Order.eq, (Value{ .float = -9223372036854775808.0 }).order(.{ .int = std.math.minInt(i64) }));
    try testing.expect((Value{ .float = -9223372036854775808.0 }).eql(.{ .int = std.math.minInt(i64) }));
    // 2^127 exactly is above every decimal, and must not reach @intFromFloat(i128)
    const two127 = std.math.ldexp(@as(f64, 1), 127);
    try testing.expectEqual(std.math.Order.gt, D.f(two127, std.math.maxInt(i128)));
    // negative non-half fractions: floor + positive remainder (not trunc / |rem|)
    try testing.expectEqual(std.math.Order.eq, D.f(-1.25, -1_250_000_000_000));
    try testing.expectEqual(std.math.Order.eq, D.f(-0.25, -250_000_000_000));
    try testing.expectEqual(std.math.Order.lt, D.f(-0.25, -249_999_999_999));
    try testing.expectEqual(std.math.Order.gt, D.f(-0.25, -250_000_000_001));
    // frac = m * 2^-s with s = 128 and 127 (float 2^-76 and 2^-75): shift by >= 128 is skipped
    try testing.expectEqual(std.math.Order.gt, D.f(std.math.ldexp(@as(f64, 1), -76), 0));
    try testing.expectEqual(std.math.Order.gt, D.f(std.math.ldexp(@as(f64, 1), -75), 0));
    try testing.expectEqual(std.math.Order.lt, D.f(std.math.ldexp(@as(f64, 1), -76), 1));
}

// ── against `dataset` ───────────────────────────────────────────────────────

fn toDs(v: Value) ds.Value {
    return switch (v) {
        .null => .null,
        .int => |x| .{ .int = x },
        .float => |x| .{ .float = x },
        .text => |x| .{ .text = x },
        .bool => |x| .{ .bool = x },
        .decimal => |x| .{ .decimal = x },
        .list, .record => unreachable, // the pool below holds no nested cell
    };
}

fn sameAsDs(want: ?ds.Value, got: ?Value) bool {
    if (want == null or got == null) return want == null and got == null;
    const w = want.?;
    const g = got.?;
    if (!std.mem.eql(u8, @tagName(std.meta.activeTag(w)), @tagName(std.meta.activeTag(g)))) return false;
    return switch (g) {
        .null => true,
        .int => |x| x == w.int,
        .float => |x| @as(u64, @bitCast(x)) == @as(u64, @bitCast(w.float)),
        .text => |x| std.mem.eql(u8, x, w.text),
        .bool => |x| x == w.bool,
        .decimal => |x| x == w.decimal,
        .list, .record => false, // `dataset` has no nested cell
    };
}

test "Value: order, eql, the coercions and every cast agree with dataset's, over a pool of awkward cells" {
    const nan = std.math.nan(f64);
    const inf = std.math.inf(f64);
    const big: i64 = (1 << 53) + 1;
    const pool = [_]Value{
        .null,                                 .{ .bool = false },                               .{ .bool = true },
        .{ .int = 0 },                         .{ .int = -1 },                                   .{ .int = big },
        .{ .int = std.math.maxInt(i64) },      .{ .int = std.math.minInt(i64) },                 .{ .float = 0 },
        .{ .float = -0.0 },                    .{ .float = 0.5 },                                .{ .float = -2.75 },
        .{ .float = 9007199254740992.0 },      .{ .float = 1e300 },                              .{ .float = -1e300 },
        .{ .float = inf },                     .{ .float = -inf },                               .{ .float = nan },
        .{ .float = 5e-324 },                  .{ .float = 0x1p63 },                             .{ .float = -0x1p63 },
        .{ .decimal = 0 },                     .{ .decimal = decimal_scale / 2 },                .{ .decimal = -decimal_scale },
        .{ .decimal = std.math.maxInt(i128) }, .{ .decimal = std.math.minInt(i128) },            .{ .text = "" },
        .{ .text = "a" },                      .{ .text = "2024-02-29" },                        .{ .text = "2024-02-30" },
        .{ .text = "2009-02-13T23:31:30Z" },   .{ .text = "1999-12-31T23:59:59.9999999+01:00" }, .{ .text = "x\x00y" },
    };
    for (pool) |x| {
        const dx = toDs(x);
        try testing.expect(sameAsDs(dx, x));
        const wf = dx.asFloat();
        const gf = x.asFloat();
        try testing.expectEqual(wf == null, gf == null);
        if (gf) |g| try testing.expectEqual(@as(u64, @bitCast(wf.?)), @as(u64, @bitCast(g)));
        try testing.expectEqual(dx.asInt(), x.asInt());
        try testing.expectEqual(dx.isNull(), x.isNull());
        inline for (@typeInfo(root.ColumnType).@"enum".field_names) |name| {
            // `categorical` and `duration` are this module's own (dataset has neither).
            if (comptime !@hasField(ds.ColumnType, name)) continue;
            const to = @field(root.ColumnType, name);
            try testing.expect(sameAsDs(dx.cast(@field(ds.ColumnType, name)), x.cast(to)));
        }
        for (pool) |y| {
            const dy = toDs(y);
            try testing.expectEqual(ds.Value.order(dx, dy), Value.order(x, y));
            try testing.expectEqual(ds.Value.eql(dx, dy), Value.eql(x, y));
        }
    }
}

test "ISO helpers agree with dataset's, over every cut of a few long instants" {
    const inputs = [_][]const u8{
        "2024-02-29T12:34:56.123456789+05:30", "0000-01-01T00:00:00Z", "9999-12-31 23:59:59,5-23:59",
        "2023-02-29",                          "1970-01-01t00:00z",    "+001-01-01",
    };
    for (inputs) |full| {
        for (0..full.len + 1) |n| {
            const s = full[0..n];
            try testing.expectEqual(ds.parseIsoTimestamp(s), parseIsoTimestamp(s));
            const want = ds.parseIsoDate(s);
            const got = parseIsoDate(s);
            try testing.expectEqual(want == null, got == null);
            if (got) |g| try testing.expectEqual(want.?.ordinal(), g.ordinal());
        }
    }
    var prng = std.Random.DefaultPrng.init(0xda7a);
    const r = prng.random();
    for (0..2000) |_| {
        const us: i64 = @bitCast(r.int(u64));
        var b1: [max_iso_timestamp_len]u8 = undefined;
        var b2: [ds.max_iso_timestamp_len]u8 = undefined;
        try testing.expectEqualStrings(ds.formatIsoTimestamp(&b2, us), formatIsoTimestamp(&b1, us));
    }
}
