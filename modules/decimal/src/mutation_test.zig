// SPDX-License-Identifier: MIT
//! Tests added by the 2026-11-27 whole-module mutation run (one per survivor group).
//! Expected values come from the documented range and rounding contract (SPEC.md,
//! doc comments) and, for the rounding tables, from Python's `decimal`; never from
//! running the module.
const std = @import("std");
const root = @import("root.zig");
const Decimal = root.Decimal;
const BigDecimal = root.BigDecimal;
const RoundingMode = root.RoundingMode;

const testing = std.testing;
const talloc = testing.allocator;

const min_raw: i128 = std.math.minInt(i128);
const max_raw: i128 = std.math.maxInt(i128);
const dmin: Decimal = .{ .raw = min_raw };
const dmax: Decimal = .{ .raw = max_raw };

fn dd(s: []const u8) Decimal {
    return Decimal.parse(s) catch unreachable;
}

test "mutation 2026-11-27: mul and div hit the i128 extremes exactly and overflow past them, both signs" {
    // The range is inclusive: min * 1 and max * 1 are representable.
    try testing.expectEqual(dmin, try dmin.mul(Decimal.one));
    try testing.expectEqual(dmax, try dmax.mul(Decimal.one));
    try testing.expectEqual(dmin, try dmin.div(Decimal.one));
    try testing.expectEqual(dmax, try dmax.div(Decimal.one));
    const two = dd("2");
    const half = dd("0.5");
    const neg_two = dd("-2");
    try testing.expectError(error.Overflow, dmax.mul(two));
    try testing.expectError(error.Overflow, dmin.mul(two));
    try testing.expectError(error.Overflow, dmax.mul(neg_two));
    try testing.expectError(error.Overflow, dmin.mul(neg_two));
    try testing.expectError(error.Overflow, dmax.div(half));
    try testing.expectError(error.Overflow, dmin.div(half));
    try testing.expectError(error.Overflow, dmax.div(dd("-0.5")));
    try testing.expectError(error.Overflow, dmin.div(dd("-0.5")));
    // -2^127 / -1 = +2^127 is one past the maximum.
    try testing.expectError(error.Overflow, dmin.div(dd("-1")));
}

test "mutation 2026-11-27: round returns the value unchanged when rounding would leave the range" {
    // 170141183460469231731687303.715884105727 rounds (half away) to ...304, above the maximum.
    try testing.expectEqual(dmax, dmax.round(0));
    try testing.expectEqual(dmin, dmin.round(0));
}

test "mutation 2026-11-27: rescale errors where the rounded value leaves the range, in the directed modes" {
    try testing.expectError(error.Overflow, dmax.rescale(0, .up));
    try testing.expectError(error.Overflow, dmax.rescale(0, .ceiling));
    try testing.expectError(error.Overflow, dmin.rescale(0, .up));
    try testing.expectError(error.Overflow, dmin.rescale(0, .floor));
    // down / floor at the maximum and ceiling at the minimum are exact truncations
    try testing.expectEqual(@as(i128, 170141183460469231731687303_000000000000), (try dmax.rescale(0, .down)).raw);
    try testing.expectEqual(@as(i128, -170141183460469231731687303_000000000000), (try dmin.rescale(0, .ceiling)).raw);
}

test "mutation 2026-11-27: divideInteger at the i128 extremes" {
    const one_ulp: Decimal = .{ .raw = 1 };
    const neg_ulp: Decimal = .{ .raw = -1 };
    try testing.expectEqual(max_raw, try dmax.divideInteger(one_ulp));
    try testing.expectEqual(min_raw, try dmin.divideInteger(one_ulp));
    try testing.expectError(error.Overflow, dmin.divideInteger(neg_ulp));
    try testing.expectEqual(-max_raw, try dmax.divideInteger(neg_ulp));
}

test "mutation 2026-11-27: roundToMultiple lands exactly on the extremes and overflows past them" {
    const ulp: Decimal = .{ .raw = 1 };
    const three: Decimal = .{ .raw = 3 };
    try testing.expectEqual(dmax, try dmax.roundToMultiple(ulp, .half_even));
    try testing.expectEqual(dmin, try dmin.roundToMultiple(ulp, .half_even));
    // 2^127 / 3 = ...242.67 rounds away to ...243, and 243 * 3 = 2^127 + 1 is below the minimum;
    // (2^127 - 1) / 3 = ...242.33 rounds away to ...243, and 243 * 3 = 2^127 + 2 is above the maximum.
    try testing.expectError(error.Overflow, dmin.roundToMultiple(three, .up));
    try testing.expectError(error.Overflow, dmax.roundToMultiple(three, .up));
    // truncating instead: 2^127 / 3 = ...242 (x3 = 2^127 - 2, representable)
    try testing.expectEqual(@as(i128, -170141183460469231731687303715884105726), (try dmin.roundToMultiple(three, .down)).raw);
}

test "mutation 2026-11-27: pow decides |x| >= 2 and |x| <= 1/2 with a huge exponent before computing" {
    // 2^1e9 is out of range (the clear case, decided up front: Overflow, not ResultTooLarge);
    // 0.5^1e9 is below half an ulp and half_even rounds it to 0.
    try testing.expectError(error.Overflow, dd("2").pow(talloc, 1_000_000_000));
    try testing.expectError(error.Overflow, dd("-2").pow(talloc, 1_000_000_001));
    try testing.expectEqual(Decimal.zero, try dd("0.5").pow(talloc, 1_000_000_000));
    try testing.expectEqual(Decimal.zero, try dd("-0.5").pow(talloc, 1_000_000_001));
}

test "mutation 2026-11-27: fixedBufLen counts the point only when there are places" {
    try testing.expectEqual(@as(usize, 28), Decimal.fixedBufLen(0));
    try testing.expectEqual(@as(usize, 30), Decimal.fixedBufLen(1));
    try testing.expectEqual(@as(usize, 40), Decimal.fixedBufLen(11));
}

test "mutation 2026-11-27: toStringFixed counts the sign in the space it needs" {
    var buf: [8]u8 = undefined;
    const neg = dd("-1.5");
    try testing.expectEqualStrings("-1.5", try neg.toStringFixed(buf[0..4], 1, .half_even));
    try testing.expectError(error.NoSpaceLeft, neg.toStringFixed(buf[0..3], 1, .half_even));
    const pos = dd("1.5");
    try testing.expectEqualStrings("1.5", try pos.toStringFixed(buf[0..3], 1, .half_even));
    try testing.expectError(error.NoSpaceLeft, pos.toStringFixed(buf[0..2], 1, .half_even));
}

test "mutation 2026-11-27: parse rounds a drop of exactly 60 digits, and refuses the minimum minus one ulp" {
    // 5e59 * 10^-72 = 5e-13: half away from zero at 12 places is 1e-12 (a drop of exactly 60 digits).
    var buf: [70]u8 = undefined;
    @memset(&buf, '0');
    buf[0] = '-';
    buf[1] = '5';
    @memcpy(buf[61..65], "e-72");
    try testing.expectEqual(@as(i128, 1), (try Decimal.parse(buf[1..65])).raw);
    try testing.expectEqual(@as(i128, -1), (try Decimal.parse(buf[0..65])).raw);
    try testing.expectError(error.Overflow, Decimal.parse("-170141183460469231731687303.715884105729"));
    try testing.expectError(error.Overflow, Decimal.parse("170141183460469231731687303.715884105728"));
    try testing.expectEqual(min_raw, (try Decimal.parse("-170141183460469231731687303.715884105728")).raw);
}

fn bigStr(s: []const u8) !BigDecimal {
    return BigDecimal.parse(talloc, s);
}

fn expectBig(b: BigDecimal, want: []const u8) !void {
    const got = try b.toSci(talloc);
    defer talloc.free(got);
    try testing.expectEqualStrings(want, got);
}

test "mutation 2026-11-27: BigDecimal.parse accepts a leading plus sign" {
    var a = try bigStr("+1.50");
    defer a.deinit();
    try expectBig(a, "1.50");
    var z = try bigStr("+0E+3");
    defer z.deinit();
    try expectBig(z, "0E+3");
}

test "mutation 2026-11-27: BigDecimal.sub subtracts (Python Decimal('1.5') - Decimal('0.25') == Decimal('1.25'))" {
    var a = try bigStr("1.5");
    defer a.deinit();
    var b = try bigStr("0.25");
    defer b.deinit();
    var r = try BigDecimal.sub(talloc, a, b);
    defer r.deinit();
    try expectBig(r, "1.25");
    var five = try bigStr("5");
    defer five.deinit();
    var three = try bigStr("3");
    defer three.deinit();
    var r2 = try BigDecimal.sub(talloc, three, five);
    defer r2.deinit();
    try expectBig(r2, "-2");
    var r3 = try BigDecimal.sub(talloc, five, three);
    defer r3.deinit();
    try expectBig(r3, "2");
}

test "mutation 2026-11-27: mul and scaleByPowerOfTen refuse an exponent outside i32, both ends" {
    var hi = try bigStr("1e2000000000");
    defer hi.deinit();
    var lo = try bigStr("1e-2000000000");
    defer lo.deinit();
    try testing.expectError(error.Overflow, BigDecimal.mul(talloc, hi, hi));
    try testing.expectError(error.Overflow, BigDecimal.mul(talloc, lo, lo));
    try testing.expectError(error.Overflow, hi.scaleByPowerOfTen(2_000_000_000));
    try testing.expectError(error.Overflow, lo.scaleByPowerOfTen(-2_000_000_000));
    var fine = try BigDecimal.mul(talloc, hi, lo);
    defer fine.deinit();
    try expectBig(fine, "1");
}

test "mutation 2026-11-27: toFloat past the cut-offs by digit count alone keeps the sign" {
    // 1e20 * 10^291 = 1e311 (above f64 max 1.8e308) with a coefficient wide enough that the
    // bit-length bound alone (lower bound 310) does not decide: the second cut-off does.
    var big = try bigStr("100000000000000000000e291");
    defer big.deinit();
    try testing.expectEqual(std.math.inf(f64), try big.toFloat(talloc));
    var nbig = try bigStr("-100000000000000000000e291");
    defer nbig.deinit();
    try testing.expectEqual(-std.math.inf(f64), try nbig.toFloat(talloc));
    // ~1e-327 is below half the smallest subnormal (2.47e-324): a signed zero.
    var tiny = try bigStr("99999999999999999999e-346");
    defer tiny.deinit();
    const t = try tiny.toFloat(talloc);
    try testing.expect(t == 0 and !std.math.signbit(t));
    var ntiny = try bigStr("-99999999999999999999e-346");
    defer ntiny.deinit();
    const nt = try ntiny.toFloat(talloc);
    try testing.expect(nt == 0 and std.math.signbit(nt));
}

fn expectRounded(r: BigDecimal.Rounded, want: []const u8, inexact: bool, rounded: bool) !void {
    var rr = r;
    defer rr.deinit();
    try expectBig(rr.value, want);
    try testing.expectEqual(inexact, rr.inexact);
    try testing.expectEqual(rounded, rr.rounded);
}

test "mutation 2026-11-27: sqrt of an exact half-way root follows the tie rule (6.25 and 12.25 at 1 digit)" {
    var a = try bigStr("6.25");
    defer a.deinit();
    var b = try bigStr("12.25");
    defer b.deinit();
    // 2.5 and 3.5: half_even takes the even neighbour (Python: Context(prec=1).sqrt -> 2 and 4);
    // half_up goes up, half_down goes down (the rule of each mode; Python only has half_even here).
    inline for (.{
        .{ RoundingMode.half_even, "2", "4" },
        .{ RoundingMode.half_up, "3", "4" },
        .{ RoundingMode.half_down, "2", "3" },
    }) |row| {
        var ra = try BigDecimal.sqrt(talloc, a, 1, row[0]);
        defer ra.deinit();
        try expectBig(ra, row[1]);
        var rb = try BigDecimal.sqrt(talloc, b, 1, row[0]);
        defer rb.deinit();
        try expectBig(rb, row[2]);
    }
}

test "mutation 2026-11-27: divPrec accepts prec == max_result_digits and refuses one more" {
    var one = try bigStr("1");
    defer one.deinit();
    try expectRounded(try BigDecimal.divPrec(talloc, one, one, BigDecimal.max_result_digits, .half_even), "1", false, false);
    try testing.expectError(error.PrecisionTooLarge, BigDecimal.divPrec(talloc, one, one, BigDecimal.max_result_digits + 1, .half_even));
}

test "mutation 2026-11-27: divPrec ideal exponent at and beyond the i32 limits" {
    var hi = try bigStr("1E+2147483647");
    defer hi.deinit();
    var lo = try bigStr("1E-2147483648");
    defer lo.deinit();
    var one = try bigStr("1");
    defer one.deinit();
    var neg_big = try bigStr("1E-2000000000");
    defer neg_big.deinit();
    var big = try bigStr("1E+2000000000");
    defer big.deinit();
    // ideal exponent = a.exponent - b.exponent: exactly maxInt / minInt is representable
    try expectRounded(try BigDecimal.divPrec(talloc, hi, one, 5, .half_even), "1E+2147483647", false, false);
    try expectRounded(try BigDecimal.divPrec(talloc, lo, one, 5, .half_even), "1E-2147483648", false, false);
    // one past either end is Overflow
    try testing.expectError(error.Overflow, BigDecimal.divPrec(talloc, big, neg_big, 5, .half_even));
    try testing.expectError(error.Overflow, BigDecimal.divPrec(talloc, neg_big, big, 5, .half_even));
}

test "mutation 2026-11-27: divPrec result exponent leaves i32 only when the digits push it out" {
    var one = try bigStr("1");
    defer one.deinit();
    var three = try bigStr("3");
    defer three.deinit();
    // 12345E+2147483644 / 1 at 2 digits: 12.345 -> 12 times 10^(2147483644+3) = 12E+2147483647, the largest exponent
    var a_ok = try bigStr("12345E+2147483644");
    defer a_ok.deinit();
    try expectRounded(try BigDecimal.divPrec(talloc, a_ok, one, 2, .half_even), "1.2E+2147483648", true, true);
    var a_over = try bigStr("12345E+2147483645");
    defer a_over.deinit();
    try testing.expectError(error.Overflow, BigDecimal.divPrec(talloc, a_over, one, 2, .half_even));
    // 1E-2147483648 / 3 at 2 digits: 0.33 -> 33E-2147483650 is below the smallest exponent
    var tiny = try bigStr("1E-2147483648");
    defer tiny.deinit();
    try testing.expectError(error.Overflow, BigDecimal.divPrec(talloc, tiny, three, 2, .half_even));
    // ... and exactly minInt is fine: 1E-2147483646 / 3 at 2 digits = 33E-2147483648
    var t2 = try bigStr("1E-2147483646");
    defer t2.deinit();
    try expectRounded(try BigDecimal.divPrec(talloc, t2, three, 2, .half_even), "3.3E-2147483647", true, true);
    // wide operands take the general path: same answers
    var wide = try bigStr("123450000000000000000000000000000000000000000000E+2147483647");
    defer wide.deinit();
    try testing.expectError(error.Overflow, BigDecimal.divPrec(talloc, wide, one, 2, .half_even));
}

test "mutation 2026-11-27: power takes the exact path up to the digit budget and not beyond" {
    // 1E+1 has one significant digit: 1 * 100000 == max_result_digits is still exact (Python: 1E+100000, no flags)
    var base = try bigStr("1E+1");
    defer base.deinit();
    var y = try bigStr("100000");
    defer y.deinit();
    try expectRounded(try BigDecimal.power(talloc, base, y, 5, .half_even), "1E+100000", false, false);
}

test "mutation 2026-11-27: power with an exponent of adjusted size 15 is computed, 1e16 is Overflow, tiny exponents hit the alignment cap" {
    var base = try bigStr("1.0000001");
    defer base.deinit();
    var y15 = try bigStr("1E+15");
    defer y15.deinit();
    // Python (prec 80, Emax raised): 1.0000001 ** 1E+15 = 1.04436646499527...E+43429446
    try expectRounded(try BigDecimal.power(talloc, base, y15, 5, .half_even), "1.0444E+43429446", true, true);
    var y16 = try bigStr("1E+16");
    defer y16.deinit();
    try testing.expectError(error.Overflow, BigDecimal.power(talloc, base, y16, 5, .half_even));
    // 2 ** 1E-999997 = 1.0000 (Inexact, Rounded) exactly at the alignment cap; one more digit is Overflow
    var two = try bigStr("2");
    defer two.deinit();
    var t_ok = try bigStr("1E-999997");
    defer t_ok.deinit();
    try expectRounded(try BigDecimal.power(talloc, two, t_ok, 5, .half_even), "1.0000", true, true);
    var t_over = try bigStr("1E-999998");
    defer t_over.deinit();
    try testing.expectError(error.Overflow, BigDecimal.power(talloc, two, t_over, 5, .half_even));
}

test "mutation 2026-11-27: toStringFixed places at the i32 limits (zero never needs alignment)" {
    var z = try bigStr("0");
    defer z.deinit();
    // places = -2147483647 asks for exponent +2147483647 (representable): a zero prints as a bare 0
    const s = try z.toStringFixed(talloc, -2147483647, .half_even);
    defer talloc.free(s);
    try testing.expectEqualStrings("0", s);
    // places = minInt would need exponent 2^31, one past i32
    try testing.expectError(error.Overflow, z.toStringFixed(talloc, std.math.minInt(i32), .half_even));
}

test "mutation 2026-11-27: power detects an exact fractional-exponent result when digits * |p| is exactly the digit budget" {
    // (10^32)^(3125/32) = 10^3125 exactly; the base has 32 coefficient digits and |p| = 3125,
    // so 32 * 3125 == max_result_digits (100000). Python (ROUND_UP, prec 5): 1.0000E+3125.
    var text: [40]u8 = undefined;
    @memset(&text, '0');
    text[0] = '1';
    @memcpy(text[32..35], "E+1");
    var base = try bigStr(text[0..35]);
    defer base.deinit();
    var y = try bigStr("97.65625");
    defer y.deinit();
    try expectRounded(try BigDecimal.power(talloc, base, y, 5, .up), "1.0000E+3125", true, true);
}

test "mutation 2026-11-27: power detects an exact root when digits(candidate) * q is exactly the digit budget" {
    // (2^20000)^(1/20000) = 2 exactly. y = 5E-5 = 1/20000 in lowest terms, the 5-digit candidate
    // 2.0000 has 5 digits, and 5 * 20000 == max_result_digits. Python (ROUND_UP, prec 5): 2.0000.
    var two = try std.math.big.int.Managed.initSet(talloc, 2);
    defer two.deinit();
    var p = try std.math.big.int.Managed.init(talloc);
    try p.pow(&two, 20000);
    var base: BigDecimal = .{ .coeff = p, .exponent = 0 };
    defer base.deinit();
    var y = try bigStr("0.00005");
    defer y.deinit();
    try expectRounded(try BigDecimal.power(talloc, base, y, 5, .up), "2.0000", true, true);
}

test "mutation 2026-11-27: a zero product never carries a negative sign" {
    var zero = try bigStr("0");
    defer zero.deinit();
    var neg5 = try bigStr("-5");
    defer neg5.deinit();
    var z = try BigDecimal.mul(talloc, zero, neg5);
    defer z.deinit();
    try testing.expect(z.coeff.isPositive());
    var z2 = try BigDecimal.mul(talloc, neg5, zero);
    defer z2.deinit();
    try testing.expect(z2.coeff.isPositive());
}

test "mutation 2026-11-27: max and min prefer +0 over -0 whichever operand holds the negative zero" {
    // GDA: equal values, differing signs: max picks the positive, min the negative operand,
    // whatever the exponents say. -0E+2 is built with negate (the only way a negative zero exists).
    var pos = try bigStr("0");
    defer pos.deinit();
    var neg = try bigStr("0E+2");
    defer neg.deinit();
    neg.negate();
    var mx = try BigDecimal.max(talloc, pos, neg);
    defer mx.deinit();
    try expectBig(mx, "0");
    var mx2 = try BigDecimal.max(talloc, neg, pos);
    defer mx2.deinit();
    try expectBig(mx2, "0");
    var mn = try BigDecimal.min(talloc, pos, neg);
    defer mn.deinit();
    try expectBig(mn, "0E+2");
    var mn2 = try BigDecimal.min(talloc, neg, pos);
    defer mn2.deinit();
    try expectBig(mn2, "0E+2");
}

test "mutation 2026-11-27: divPrec general path (3-limb operands) lands exactly on the exponent limits; a zero dividend is checked too" {
    var one = try bigStr("1");
    defer one.deinit();
    // 46-digit coefficient 12345 0..0 1 at E+2147483603, / 1, 2 digits: 12.345... -> 12E+2147483647 (Python: 1.2E+2147483648)
    var wide_text: [60]u8 = undefined;
    @memset(&wide_text, '0');
    @memcpy(wide_text[0..5], "12345");
    wide_text[45] = '1';
    @memcpy(wide_text[46..58], "E+2147483603");
    var wide = try bigStr(wide_text[0..58]);
    defer wide.deinit();
    try expectRounded(try BigDecimal.divPrec(talloc, wide, one, 2, .half_even), "1.2E+2147483648", true, true);
    // 1E-2147483602 / (3 followed by 43 zeros and a 1, 45 digits), 2 digits: 33E-2147483648 (Python: 3.3E-2147483647)
    var tiny = try bigStr("1E-2147483602");
    defer tiny.deinit();
    var div_text: [45]u8 = undefined;
    @memset(&div_text, '0');
    div_text[0] = '3';
    div_text[44] = '1';
    var den = try bigStr(&div_text);
    defer den.deinit();
    try expectRounded(try BigDecimal.divPrec(talloc, tiny, den, 2, .half_even), "3.3E-2147483647", true, true);
    // a zero dividend with an ideal exponent outside i32 is Overflow, not a wrapped exponent
    var zero_hi = try bigStr("0E+2000000000");
    defer zero_hi.deinit();
    var tiny_b = try bigStr("1E-2000000000");
    defer tiny_b.deinit();
    try testing.expectError(error.Overflow, BigDecimal.divPrec(talloc, zero_hi, tiny_b, 5, .half_even));
    var zero_lo = try bigStr("0E-2000000000");
    defer zero_lo.deinit();
    var big_b = try bigStr("1E+2000000000");
    defer big_b.deinit();
    try testing.expectError(error.Overflow, BigDecimal.divPrec(talloc, zero_lo, big_b, 5, .half_even));
}
