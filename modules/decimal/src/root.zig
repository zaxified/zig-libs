// SPDX-License-Identifier: MIT
//! decimal — exact base-10 fixed-point decimal for money and ETL math.
//!
//! Values are stored as an `i128` scaled by a constant `10^12` (12 fractional
//! digits), like a database `DECIMAL(38,12)`. `0.1 + 0.2` is exactly `0.3` and
//! `0.02 + 0.08` is exactly `0.10` — no binary-float noise: parse, arithmetic
//! and format are pure integer paths (no `f64`/`f128` anywhere).
//!
//! Range (i128 @ 1e12):
//!   max  +170141183460469231731687303.715884105727
//!   min  -170141183460469231731687303.715884105728
//!   step  0.000000000001
//!
//! The integer-part ceiling (~1.7e26) is far beyond world money supply. `× ÷`
//! widen to `i256` intermediates so a product of two large operands cannot
//! overflow before the rescale.
//!
//! Rounding contract (the classic ops round half-away-from-zero — "school"
//! rounding, matching what Excel / LibreOffice present):
//!   `+ −`   exact; a result beyond the i128 range → `error.Overflow`.
//!   `× ÷`   round the 12th fractional digit half-away-from-zero (a product or
//!           quotient with more than 12 fractional digits is rounded, not
//!           truncated); result beyond i128 → `error.Overflow`.
//!   `round` re-quantises with the same mode.
//!
//! Controlled rounding (IEEE 754-2008 / General Decimal Arithmetic): the
//! `RoundingMode` enum — `half_even` (banker's, the GDA default), `half_up`,
//! `half_down`, `up`, `down`, `ceiling`, `floor` — drives `rescale`,
//! `roundToIntegral`, `quantize` and `divRound` (division computed at an
//! explicit result scale). Modelled after Java `BigDecimal.RoundingMode` and
//! the IBM General Decimal Arithmetic spec; pure integer paths, overflow →
//! typed `error.Overflow`.
//! No Inf/NaN, no silent wrap-around, never UB: everything that can exceed the
//! range returns a clean error (`round`/`floor`/`ceil` return the value
//! unchanged instead — see their doc comments).
//!
//! Extracted from bxp `bxp-core/src/decimal.zig` (same authors); semantics are
//! preserved, only the `?Decimal` results became explicit error unions and the
//! overflow checks were completed (div quotient + parse accumulator).

const std = @import("std");

pub const meta = .{
    .status = .extract, // seeded in bxp bxp-core/src/decimal.zig (proven on 40M-row ETL)
    .platform = .any, // pure integer logic, no OS calls
    .role = .util,
    .concurrency = .reentrant, // no shared state, no allocation
    .model_after = "Java BigDecimal (incl. RoundingMode) / IBM General Decimal Arithmetic / DB DECIMAL(38,12)",
    .deps = .{}, // std only
};

/// IEEE 754-2008 / General Decimal Arithmetic rounding modes. Clean-room from
/// the published definitions (Java `BigDecimal.RoundingMode` javadoc, IBM GDA
/// spec, Python `decimal` docs) — every mode is exact on the discarded
/// remainder, no floating point involved.
pub const RoundingMode = enum {
    /// Round to nearest; a tie goes to the even neighbour (banker's rounding,
    /// IEEE 754 roundTiesToEven, the GDA default). 2.5 → 2, 3.5 → 4, -2.5 → -2.
    half_even,
    /// Round to nearest; a tie goes away from zero (Excel ROUND, "school"
    /// rounding). 2.5 → 3, -2.5 → -3.
    half_up,
    /// Round to nearest; a tie goes toward zero. 2.5 → 2, -2.5 → -2.
    half_down,
    /// Round away from zero: any nonzero discarded fraction increments the
    /// magnitude. 2.1 → 3, -2.1 → -3.
    up,
    /// Round toward zero: truncate the discarded fraction. 2.9 → 2, -2.9 → -2.
    down,
    /// Round toward +infinity. 2.1 → 3, -2.9 → -2.
    ceiling,
    /// Round toward -infinity. 2.9 → 2, -2.1 → -3.
    floor,

    /// The IEEE 754 / GDA default mode.
    pub const default: RoundingMode = .half_even;
};

pub const Decimal = struct {
    raw: i128, // value × 10^scale

    /// Number of fractional digits (fixed).
    pub const scale: u32 = 12;
    /// 10^scale — the raw-representation multiplier.
    pub const scale_factor: i128 = 1_000_000_000_000;
    const scale_factor_256: i256 = scale_factor;

    /// Worst-case `toString` length: sign + 27 integer digits + '.' + 12
    /// fractional digits (the i128 minimum formats to exactly this).
    pub const str_buf_len: usize = 41;

    pub const zero: Decimal = .{ .raw = 0 };
    pub const one: Decimal = .{ .raw = scale_factor };

    /// Result exceeds the representable i128 range (≈ ±1.7e26).
    pub const Error = error{Overflow};
    pub const DivError = error{ Overflow, DivisionByZero };
    /// `InvalidCharacter` = malformed input (junk, empty, double dot, bad
    /// exponent, embedded spaces, thousands separators). `Overflow` = well
    /// formed but out of the representable range (also the >60-digit width cap).
    pub const ParseError = error{ InvalidCharacter, Overflow };

    /// Largest power-of-ten exponent we materialise for scaling. 10^48 fits an
    /// i256 (max ≈ 5.7e76) with wide margin; anything past this overflows the
    /// i128 result anyway, so it is rejected as out-of-range.
    const max_pow10: u32 = 48;

    /// Whole number → Decimal. `error.Overflow` if |n| exceeds ~1.7e26.
    pub fn fromInt(n: i128) Error!Decimal {
        const r = @mulWithOverflow(n, scale_factor);
        return if (r[1] != 0) error.Overflow else .{ .raw = r[0] };
    }

    /// Integer part, truncated toward zero (`3.99 → 3`, `-3.99 → -3`).
    pub fn trunc(self: Decimal) i128 {
        return @divTrunc(self.raw, scale_factor);
    }

    pub fn isZero(self: Decimal) bool {
        return self.raw == 0;
    }

    // Arithmetic is overflow-checked: a result beyond the fixed-point range
    // (≈ ±1.7e26) returns error.Overflow so the caller can surface a clean
    // error rather than trapping. Real bounded-ETL values never approach the
    // ceiling; only pathological inputs (e.g. 1e14 × 1e14) reach it.

    /// Exact addition. `error.Overflow` beyond the i128 range.
    pub fn add(a: Decimal, b: Decimal) Error!Decimal {
        const r = @addWithOverflow(a.raw, b.raw);
        return if (r[1] != 0) error.Overflow else .{ .raw = r[0] };
    }

    /// Exact subtraction. `error.Overflow` beyond the i128 range.
    pub fn sub(a: Decimal, b: Decimal) Error!Decimal {
        const r = @subWithOverflow(a.raw, b.raw);
        return if (r[1] != 0) error.Overflow else .{ .raw = r[0] };
    }

    /// Negation. `error.Overflow` only at the i128 minimum (|min| > max).
    pub fn neg(self: Decimal) Error!Decimal {
        if (self.raw == std.math.minInt(i128)) return error.Overflow;
        return .{ .raw = -self.raw };
    }

    /// Absolute value. `error.Overflow` only at the i128 minimum.
    pub fn abs(self: Decimal) Error!Decimal {
        return if (self.raw >= 0) self else self.neg();
    }

    /// (a×S)(b×S)/S = a·b·S. Widen so the a.raw×b.raw product (up to ~2.9e76)
    /// can't overflow the i256 intermediate; the final value may still exceed
    /// i128 (→ `error.Overflow`). Rounds the 12th fractional digit
    /// half-away-from-zero, matching how Excel/LibreOffice present results.
    pub fn mul(a: Decimal, b: Decimal) Error!Decimal {
        const p: i256 = @as(i256, a.raw) * @as(i256, b.raw);
        const q = divRoundHalfAway(p, scale_factor_256);
        if (q > std.math.maxInt(i128) or q < std.math.minInt(i128)) return error.Overflow;
        return .{ .raw = @intCast(q) };
    }

    /// a/b rounded to 12 fractional digits, half-away-from-zero (Excel/
    /// LibreOffice display rounding). `error.DivisionByZero` on b = 0;
    /// `error.Overflow` when the quotient exceeds the i128 range (dividing a
    /// large value by a sub-1e-12-scale divisor).
    pub fn div(a: Decimal, b: Decimal) DivError!Decimal {
        if (b.raw == 0) return error.DivisionByZero;
        const num: i256 = @as(i256, a.raw) * scale_factor_256;
        const q = divRoundHalfAway(num, @as(i256, b.raw));
        if (q > std.math.maxInt(i128) or q < std.math.minInt(i128)) return error.Overflow;
        return .{ .raw = @intCast(q) };
    }

    /// Largest Decimal ≤ self with zero fractional part. Returns self
    /// unchanged in the single unrepresentable case (within one unit of the
    /// i128 minimum, where the true floor falls outside the range).
    pub fn floor(self: Decimal) Decimal {
        const q = @divFloor(@as(i256, self.raw), scale_factor_256) * scale_factor_256;
        if (q < std.math.minInt(i128)) return self;
        return .{ .raw = @intCast(q) };
    }

    /// Smallest Decimal ≥ self with zero fractional part. Returns self
    /// unchanged in the single unrepresentable case (within one unit of the
    /// i128 maximum, where the true ceiling falls outside the range).
    pub fn ceil(self: Decimal) Decimal {
        const q = -(@divFloor(-@as(i256, self.raw), scale_factor_256) * scale_factor_256);
        if (q > std.math.maxInt(i128)) return self;
        return .{ .raw = @intCast(q) };
    }

    /// Re-quantise to `n` fractional digits, **round-half-away-from-zero**
    /// (Excel's ROUND: `ROUND(2.5, 0) = 3`, `ROUND(-2.5, 0) = -3`) — the same
    /// mode `× ÷` use. `n >= 12` is a no-op (already max precision); `n < 0`
    /// rounds to tens/hundreds/… Returns self unchanged if the result would
    /// overflow.
    pub fn round(self: Decimal, n: i32) Decimal {
        if (n >= @as(i32, @intCast(scale))) return self;
        const drop: u32 = @intCast(@as(i64, scale) - n); // 1..(12+|n|)
        if (drop > max_pow10) return self;
        const divisor = pow10_256(drop);
        const q = divRoundHalfAway(@as(i256, self.raw), divisor);
        const scaled = q * divisor;
        if (scaled > std.math.maxInt(i128) or scaled < std.math.minInt(i128)) return self;
        return .{ .raw = @intCast(scaled) };
    }

    /// Re-quantise to `new_scale` fractional digits with an explicit rounding
    /// mode (Java `setScale(new_scale, mode)`). Increasing the scale is exact:
    /// this fixed-point representation already carries 12 fractional digits,
    /// so `new_scale >= 12` is the identity (a pure zero-pad). Decreasing the
    /// scale drops digits and resolves the discarded remainder with `mode`
    /// (exact half-way detection on the remainder — no floats). A negative
    /// `new_scale` rounds to tens/hundreds/…. `error.Overflow` when the
    /// rounded value leaves the i128 range (e.g. `ceiling` at the maximum).
    pub fn rescale(self: Decimal, new_scale: i32, mode: RoundingMode) Error!Decimal {
        if (new_scale >= @as(i32, @intCast(scale))) return self;
        const drop64: i64 = @as(i64, scale) - new_scale; // >= 1
        // Past 10^48 every representable value truncates to 0 and any nonzero
        // rounded result overflows i128 anyway — clamping keeps the discarded
        // remainder strictly below the half-way point, so results (0 or
        // error.Overflow) are identical to the un-clamped math.
        const drop: u32 = if (drop64 > max_pow10) max_pow10 else @intCast(drop64);
        const divisor = pow10_256(drop);
        const q = divRoundWithMode(@as(i256, self.raw), divisor, mode);
        const scaled = q * divisor;
        if (scaled > std.math.maxInt(i128) or scaled < std.math.minInt(i128)) return error.Overflow;
        return .{ .raw = @intCast(scaled) };
    }

    /// Round to an integral value with an explicit mode (GDA
    /// round-to-integral-value; Java `setScale(0, mode)`). Sugar for
    /// `rescale(0, mode)`.
    pub fn roundToIntegral(self: Decimal, mode: RoundingMode) Error!Decimal {
        return self.rescale(0, mode);
    }

    /// Python/GDA-style quantize: round so the last significant place is
    /// `10^exponent` — exponent −2 keeps two fractional digits, +2 rounds to
    /// hundreds. Equivalent to `rescale(-exponent, mode)`.
    pub fn quantize(self: Decimal, exponent: i32, mode: RoundingMode) Error!Decimal {
        const ns: i64 = -@as(i64, exponent);
        if (ns >= @as(i64, scale)) return self; // at/beyond max precision: exact
        return self.rescale(@intCast(ns), mode);
    }

    /// a/b with the quotient computed at `result_scale` fractional digits and
    /// the discarded remainder resolved by `mode` (Java
    /// `divide(b, scale, roundingMode)`) — the operation exact fixed-point
    /// cannot express otherwise. `result_scale` above 12 is clamped to 12
    /// (the representation's precision ceiling); a negative scale rounds the
    /// quotient to tens/hundreds/…. `error.DivisionByZero` on b = 0;
    /// `error.Overflow` when the rounded quotient leaves the i128 range.
    pub fn divRound(a: Decimal, b: Decimal, result_scale: i32, mode: RoundingMode) DivError!Decimal {
        if (b.raw == 0) return error.DivisionByZero;
        if (a.raw == 0) return Decimal.zero;
        const result_neg = (a.raw < 0) != (b.raw < 0);
        const s: i64 = @min(@as(i64, result_scale), @as(i64, scale));
        const back: i64 = @as(i64, scale) - s; // digits to re-pad below the rounding place
        var num: i256 = a.raw;
        if (num < 0) num = -num;
        var den: i256 = b.raw;
        if (den < 0) den = -den;
        // Quotient magnitude at the rounding place: |a.raw|·10^s / |b.raw|.
        var q: i256 = undefined;
        if (s >= 0) {
            // s <= 12: num <= ~1.7e38 · 1e12 = 1.7e50, comfortably inside i256.
            q = divRoundMag(num * pow10_256(@intCast(s)), den, result_neg, mode);
        } else if (-s <= 60) {
            // Negative scale: scale the divisor instead. den·10^60 can exceed
            // i256 — an overflowed divisor dwarfs 2·num, so the quotient is a
            // fraction strictly below one half.
            const m = @mulWithOverflow(den, pow10_256(@intCast(-s)));
            q = if (m[1] != 0)
                @intFromBool(roundsAwayWhenBelowHalf(result_neg, mode))
            else
                divRoundMag(num, m[0], result_neg, mode);
        } else {
            // 10^61+ alone dwarfs any representable numerator: fraction < 1/2.
            q = @intFromBool(roundsAwayWhenBelowHalf(result_neg, mode));
        }
        if (q == 0) return Decimal.zero;
        // A nonzero digit at a place past 10^48 cannot fit the i128 range.
        if (back > max_pow10) return error.Overflow;
        const scaled = q * pow10_256(@intCast(back));
        const signed: i256 = if (result_neg) -scaled else scaled;
        if (signed > std.math.maxInt(i128) or signed < std.math.minInt(i128)) return error.Overflow;
        return .{ .raw = @intCast(signed) };
    }

    pub fn order(a: Decimal, b: Decimal) std.math.Order {
        return std.math.order(a.raw, b.raw);
    }

    pub fn eql(a: Decimal, b: Decimal) bool {
        return a.raw == b.raw;
    }

    /// Parse a plain numeric string (optional sign, decimal point, scientific
    /// notation) into a fixed-point Decimal. Float-free.
    /// `error.InvalidCharacter` on any non-numeric input or empty input;
    /// `error.Overflow` on a value beyond the i128 range (or past the
    /// 60-digit mantissa width cap). Thousands-grouped input ("1,234.56") is
    /// intentionally rejected — the caller handles grouping separately.
    ///
    /// Fractional digits beyond 12 are rounded half-away-from-zero into the
    /// 12th (matching `divRoundHalfAway` and the rest of the module).
    pub fn parse(s: []const u8) ParseError!Decimal {
        if (s.len == 0) return error.InvalidCharacter;
        var i: usize = 0;
        var is_neg = false;
        if (s[i] == '+') {
            i += 1;
        } else if (s[i] == '-') {
            is_neg = true;
            i += 1;
        }

        // Mantissa: integer digits, optional '.', fractional digits.
        var mant: i256 = 0;
        var digits_seen: u32 = 0;
        var frac_digits: i64 = 0;
        var seen_dot = false;
        while (i < s.len) : (i += 1) {
            const c = s[i];
            if (c == '.') {
                if (seen_dot) return error.InvalidCharacter;
                seen_dot = true;
                continue;
            }
            if (c == 'e' or c == 'E') break;
            if (!std.ascii.isDigit(c)) return error.InvalidCharacter;
            digits_seen += 1;
            // Cap mantissa width so the i256 accumulator can't overflow; far
            // more digits than any representable value needs.
            if (digits_seen > 60) return error.Overflow;
            mant = mant * 10 + @as(i256, c - '0');
            if (seen_dot) frac_digits += 1;
        }
        if (digits_seen == 0) return error.InvalidCharacter;

        // Optional exponent.
        var exp: i64 = 0;
        if (i < s.len and (s[i] == 'e' or s[i] == 'E')) {
            i += 1;
            var exp_neg = false;
            if (i < s.len and (s[i] == '+' or s[i] == '-')) {
                exp_neg = s[i] == '-';
                i += 1;
            }
            var exp_digits: u32 = 0;
            while (i < s.len) : (i += 1) {
                if (!std.ascii.isDigit(s[i])) return error.InvalidCharacter;
                exp = exp * 10 + @as(i64, s[i] - '0');
                exp_digits += 1;
                if (exp_digits > 4) return error.InvalidCharacter; // |exp| ≤ 9999 is ample
            }
            if (exp_digits == 0) return error.InvalidCharacter;
            if (exp_neg) exp = -exp;
        }
        if (i != s.len) return error.InvalidCharacter;

        // value = mant × 10^(exp - frac_digits); raw = value × 10^12.
        const shift: i64 = exp - frac_digits + @as(i64, scale);
        var raw256: i256 = undefined;
        if (shift >= 0) {
            if (shift > max_pow10) return error.Overflow; // overflows i128
            // Checked: a ≤60-digit mantissa times 10^48 can exceed i256.
            const m = @mulWithOverflow(mant, pow10_256(@intCast(shift)));
            if (m[1] != 0) return error.Overflow;
            raw256 = m[0];
        } else {
            const drop: i64 = -shift;
            if (drop > max_pow10) return error.Overflow; // rounds to zero / unrepresentable
            raw256 = divRoundHalfAway(mant, pow10_256(@intCast(drop)));
        }
        if (is_neg) raw256 = -raw256;
        if (raw256 > std.math.maxInt(i128) or raw256 < std.math.minInt(i128)) return error.Overflow;
        return .{ .raw = @intCast(raw256) };
    }

    /// Canonical string into a caller buffer: integer part, then up to 12
    /// fractional digits with trailing zeros trimmed and the dot dropped when
    /// no fraction remains. Integer digit extraction only — no float
    /// formatter. Infallible: `str_buf_len` covers the worst case.
    pub fn toString(self: Decimal, buf: *[str_buf_len]u8) []const u8 {
        const negative = self.raw < 0;
        // Magnitude in u128 so i128's asymmetric minimum is representable.
        const mag: u128 = if (negative)
            @as(u128, @intCast(-(self.raw + 1))) + 1
        else
            @intCast(self.raw);
        const scale_u: u128 = @intCast(scale_factor);
        const int_part = mag / scale_u;
        const frac = mag % scale_u;

        var i: usize = 0;
        if (negative) {
            buf[i] = '-';
            i += 1;
        }
        // Integer digits, extracted least-significant-first then reversed.
        var tmp: [27]u8 = undefined; // max integer part is 27 digits
        var n: usize = 0;
        var v = int_part;
        while (true) {
            tmp[n] = @intCast('0' + v % 10);
            n += 1;
            v /= 10;
            if (v == 0) break;
        }
        while (n > 0) {
            n -= 1;
            buf[i] = tmp[n];
            i += 1;
        }
        if (frac != 0) {
            // 12-digit zero-padded fraction, trailing zeros trimmed.
            var fbuf: [scale]u8 = undefined;
            var f = frac;
            var k: usize = scale;
            while (k > 0) {
                k -= 1;
                fbuf[k] = @intCast('0' + f % 10);
                f /= 10;
            }
            var end: usize = scale;
            while (end > 0 and fbuf[end - 1] == '0') end -= 1;
            buf[i] = '.';
            i += 1;
            @memcpy(buf[i..][0..end], fbuf[0..end]);
            i += end;
        }
        return buf[0..i];
    }

    /// `std.fmt` integration — `{f}` prints the canonical string.
    pub fn format(self: Decimal, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        var buf: [str_buf_len]u8 = undefined;
        try writer.writeAll(self.toString(&buf));
    }
};

/// 10^e as i256, for e in [0, 60] (10^60 ≪ i256 max ≈ 5.7e76; callers bound
/// e — most at `max_pow10`, `divRound` up to 60). Runtime loop — the exponent
/// is bounded and small, so this is not a hot path worth a lookup table.
fn pow10_256(e: u32) i256 {
    var r: i256 = 1;
    var k: u32 = 0;
    while (k < e) : (k += 1) r *= 10;
    return r;
}

/// num / den rounded half-away-from-zero, sign-aware. `den` must be non-zero.
/// Excel-compatible: 2.5 → 3, −2.5 → −3. (Half-away-from-zero is exactly
/// `RoundingMode.half_up` — this legacy entry point now shares the one
/// mode-aware implementation.)
fn divRoundHalfAway(num: i256, den: i256) i256 {
    return divRoundWithMode(num, den, .half_up);
}

/// Sign-aware rounded division: num / den with the discarded remainder
/// resolved by `mode`. `den` must be non-zero.
fn divRoundWithMode(num: i256, den: i256, mode: RoundingMode) i256 {
    const result_neg = (num < 0) != (den < 0);
    const n: i256 = if (num < 0) -num else num;
    const d: i256 = if (den < 0) -den else den;
    const q = divRoundMag(n, d, result_neg, mode);
    return if (result_neg) -q else q;
}

/// Rounded division on non-negative magnitudes: n/d with the discarded
/// remainder resolved by `mode`; `result_neg` is the sign of the eventual
/// result (the directed modes `ceiling`/`floor` depend on it). `d` must be
/// positive. Half-way detection is exact integer math: `r == d - r` iff
/// `2r == d` (written subtraction-side to rule out doubling overflow).
fn divRoundMag(n: i256, d: i256, result_neg: bool, mode: RoundingMode) i256 {
    var q = @divTrunc(n, d);
    const r = @rem(n, d);
    if (r != 0) {
        const bump = switch (mode) {
            .up => true,
            .down => false,
            .ceiling => !result_neg,
            .floor => result_neg,
            .half_up => r >= d - r,
            .half_down => r > d - r,
            .half_even => if (r != d - r) r > d - r else @rem(q, 2) != 0,
        };
        if (bump) q += 1;
    }
    return q;
}

/// Rounding decision for a quotient whose magnitude is a fraction strictly
/// inside (0, 1/2): the truncated quotient is 0 and no half-way tie is
/// possible, so only the away-from-zero directions produce a nonzero result.
fn roundsAwayWhenBelowHalf(result_neg: bool, mode: RoundingMode) bool {
    return switch (mode) {
        .up => true,
        .ceiling => !result_neg,
        .floor => result_neg,
        .down, .half_up, .half_down, .half_even => false,
    };
}

// ---------------------------------------------------------------------------
// Tests (ported from the bxp seed + extraction additions)
// ---------------------------------------------------------------------------

const testing = std.testing;

fn expectStr(d: Decimal, want: []const u8) !void {
    var buf: [Decimal.str_buf_len]u8 = undefined;
    try testing.expectEqualStrings(want, d.toString(&buf));
}

/// Test shorthand: parse a known-good literal.
fn dec(s: []const u8) Decimal {
    return Decimal.parse(s) catch unreachable;
}

test "parse + format roundtrip" {
    try expectStr(dec("0"), "0");
    try expectStr(dec("123"), "123");
    try expectStr(dec("-123"), "-123");
    try expectStr(dec("1.5"), "1.5");
    try expectStr(dec("1.25"), "1.25");
    try expectStr(dec("-3.0"), "-3");
    try expectStr(dec("1000.00"), "1000");
    try expectStr(dec("0.0313646200"), "0.03136462");
    try expectStr(dec("+42"), "42");
    try expectStr(dec("-123.456"), "-123.456");
}

test "parse rejects" {
    try testing.expectError(error.InvalidCharacter, Decimal.parse(""));
    try testing.expectError(error.InvalidCharacter, Decimal.parse("abc"));
    try testing.expectError(error.InvalidCharacter, Decimal.parse("1,234.56")); // grouping not handled here
    try testing.expectError(error.InvalidCharacter, Decimal.parse("1.2.3"));
    try testing.expectError(error.InvalidCharacter, Decimal.parse("1e"));
    try testing.expectError(error.InvalidCharacter, Decimal.parse("--1"));
    try testing.expectError(error.InvalidCharacter, Decimal.parse("1 "));
    try testing.expectError(error.InvalidCharacter, Decimal.parse("."));
    try testing.expectError(error.InvalidCharacter, Decimal.parse("-"));
    try testing.expectError(error.InvalidCharacter, Decimal.parse("1e2.5"));
}

test "parse dot edge forms (seed policy: bare dot sides allowed)" {
    try expectStr(dec(".5"), "0.5");
    try expectStr(dec("5."), "5");
}

test "scientific notation" {
    try expectStr(dec("2.08e9"), "2080000000");
    try expectStr(dec("1.5E2"), "150");
    try expectStr(dec("1e-3"), "0.001");
    try expectStr(dec("1.23e-4"), "0.000123");
}

test "12-digit quantise, half-away-from-zero on 13th" {
    // 13 fractional digits → rounds into the 12th, half away from zero.
    try expectStr(dec("0.1234567890125"), "0.123456789013"); // exact half → up
    try expectStr(dec("0.1234567890124"), "0.123456789012"); // below half → down
    try expectStr(dec("0.0000000000005"), "0.000000000001"); // exact half → up
    try expectStr(dec("0.0000000000004"), "0"); // below half → down
    try expectStr(dec("-0.0000000000005"), "-0.000000000001"); // away from zero (negative)
}

test "exact decimal arithmetic" {
    try expectStr(try dec("0.02").add(dec("0.08")), "0.1"); // the headline: no binary-float noise
    try expectStr(try dec("100").sub(dec("0.01")), "99.99");
    // 0.1 + 0.2 == 0.3, exactly (impossible in binary float).
    try testing.expect((try dec("0.1").add(dec("0.2"))).eql(dec("0.3")));
}

test "mul and div" {
    try expectStr(try dec("1.5").mul(dec("2")), "3");
    try expectStr(try dec("0.1").mul(dec("0.1")), "0.01");
    try expectStr(try dec("10").div(dec("4")), "2.5");
    // 1/3, 2/3 → 12 digits (13th digit isn't a tie, so mode is moot here).
    try expectStr(try dec("1").div(dec("3")), "0.333333333333");
    try expectStr(try dec("2").div(dec("3")), "0.666666666667");
    // mul below 1e-12 rounds half-away (not truncates): 1.5e-12 → 2e-12.
    try expectStr(try dec("0.000001").mul(dec("0.0000015")), "0.000000000002");
    try testing.expectError(error.DivisionByZero, dec("1").div(Decimal.zero));
}

test "mul/div half-away-from-zero at the 12th-digit boundary, incl. negatives" {
    // 3e-12 / 2 = 1.5e-12 → tie → 2e-12, away from zero on both signs.
    try expectStr(try dec("0.000000000003").div(dec("2")), "0.000000000002");
    try expectStr(try dec("-0.000000000003").div(dec("2")), "-0.000000000002");
    // Below the tie stays down: 5e-12 / 4 = 1.25e-12 → 1e-12.
    try expectStr(try dec("0.000000000005").div(dec("4")), "0.000000000001");
    try expectStr(try dec("-0.000000000005").div(dec("4")), "-0.000000000001");
    // Negative mul tie: -1.5e-12 → -2e-12.
    try expectStr(try dec("-0.000001").mul(dec("0.0000015")), "-0.000000000002");
    try expectStr(try dec("0.000001").mul(dec("-0.0000015")), "-0.000000000002");
    try expectStr(try dec("-0.000001").mul(dec("-0.0000015")), "0.000000000002");
}

test "i256 intermediate: large products don't overflow prematurely" {
    // raw(1e13)² = 1e50 ≫ i128 max (~1.7e38): only correct with the i256
    // intermediate; the final value 1e26 is still in range.
    try expectStr(try dec("10000000000000").mul(dec("10000000000000")), "100000000000000000000000000");
    // Same shape for div: numerator a.raw×1e12 needs the widening.
    try expectStr(try dec("100000000000000000000000000").div(dec("10000000000000")), "10000000000000");
}

test "arithmetic overflow returns a clean error (no trap)" {
    // 1e14 × 1e14 = 1e28, beyond the ±1.7e26 range.
    const big = dec("100000000000000");
    try testing.expectError(error.Overflow, big.mul(big));
    // add/sub near the i128 ceiling overflow too.
    const near_max = Decimal{ .raw = std.math.maxInt(i128) };
    try testing.expectError(error.Overflow, near_max.add(Decimal.one));
    const near_min = Decimal{ .raw = std.math.minInt(i128) };
    try testing.expectError(error.Overflow, near_min.sub(Decimal.one));
    try testing.expectError(error.Overflow, near_min.neg()); // |i128 min| is unrepresentable
    try testing.expectError(error.Overflow, near_min.abs());
    // Quotient overflow: 2e14 / 1e-12 = 2e26, beyond the range.
    try testing.expectError(error.Overflow, dec("200000000000000").div(dec("0.000000000001")));
    // fromInt beyond the integer-part ceiling (~1.7e26).
    try testing.expectError(error.Overflow, Decimal.fromInt(200_000_000_000_000_000_000_000_000));
    // A realistic product is fine.
    try expectStr(try dec("1000000").mul(dec("1000000")), "1000000000000");
}

test "round — half away from zero (Excel/ROUND surface)" {
    try expectStr(dec("1.2345").round(2), "1.23");
    try expectStr(dec("1.2355").round(2), "1.24");
    try expectStr(dec("2.5").round(0), "3"); // tie → away from zero
    try expectStr(dec("3.5").round(0), "4");
    try expectStr(dec("-2.5").round(0), "-3"); // tie → away from zero
    try expectStr(dec("0.125").round(2), "0.13"); // tie at 3rd place → up
    try expectStr(dec("1250").round(-2), "1300"); // 12.5 → away → 13 → 1300
    try expectStr(dec("1.5").round(12), "1.5"); // no-op
}

test "floor and ceil" {
    try expectStr(dec("3.7").floor(), "3");
    try expectStr(dec("-3.2").floor(), "-4");
    try expectStr(dec("3.2").ceil(), "4");
    try expectStr(dec("-3.7").ceil(), "-3");
    try expectStr(dec("5").floor(), "5"); // already integral: unchanged
    try expectStr(dec("5").ceil(), "5");
    // At the i128 boundary the true floor/ceil is unrepresentable → self.
    const near_min = Decimal{ .raw = std.math.minInt(i128) };
    try testing.expect(near_min.floor().eql(near_min));
    const near_max = Decimal{ .raw = std.math.maxInt(i128) };
    try testing.expect(near_max.ceil().eql(near_max));
}

test "fromInt and trunc" {
    try expectStr(try Decimal.fromInt(2025), "2025");
    try expectStr(try Decimal.fromInt(-12), "-12");
    try testing.expectEqual(@as(i128, 3), dec("3.99").trunc());
    try testing.expectEqual(@as(i128, -3), dec("-3.99").trunc());
    try testing.expectEqual(@as(i128, 0), Decimal.zero.trunc());
}

test "range boundaries" {
    // Max representable integer part region.
    try expectStr(dec("170141183460469231731687303.715884105727"), "170141183460469231731687303.715884105727");
    // Just beyond → overflow → clean error.
    try testing.expectError(error.Overflow, Decimal.parse("1e30"));
    try testing.expectError(error.Overflow, Decimal.parse("999999999999999999999999999999"));
    // The asymmetric i128 minimum formats exactly (fills str_buf_len).
    const min = Decimal{ .raw = std.math.minInt(i128) };
    try expectStr(min, "-170141183460469231731687303.715884105728");
}

test "parse hardening: huge mantissa × exponent doesn't trap" {
    // 29 significant digits with e36: the naive mant×10^48 would overflow
    // even the i256 accumulator — must be a clean error, not UB.
    try testing.expectError(error.Overflow, Decimal.parse("99999999999999999999999999999e36"));
    // Width cap: >60 mantissa digits rejected outright.
    try testing.expectError(
        error.Overflow,
        Decimal.parse("1000000000000000000000000000000000000000000000000000000000000"),
    );
}

test "order and eql" {
    try testing.expect(dec("1.5").eql(dec("1.50")));
    try testing.expect(dec("1.5").order(dec("1.6")) == .lt);
    try testing.expect(dec("2").order(dec("1")) == .gt);
    try testing.expect(dec("-1").order(dec("1")) == .lt);
    try testing.expect(dec("7").order(dec("7.0")) == .eq);
}

test "zero, neg, abs edges" {
    try testing.expect(Decimal.zero.isZero());
    try testing.expect(dec("0.0").isZero());
    try testing.expect(!dec("0.000000000001").isZero());
    try testing.expect((try Decimal.zero.neg()).isZero()); // no "-0"
    try expectStr(try Decimal.zero.neg(), "0");
    try expectStr(try dec("-2.5").neg(), "2.5");
    try expectStr(try dec("2.5").neg(), "-2.5");
    try expectStr(try dec("-2.5").abs(), "2.5");
    try expectStr(try dec("2.5").abs(), "2.5");
    try expectStr(try Decimal.zero.abs(), "0");
    try testing.expect(Decimal.one.eql(dec("1")));
}

test "std.fmt {f} integration" {
    var buf: [64]u8 = undefined;
    const s = try std.fmt.bufPrint(&buf, "{f}", .{dec("-12.75")});
    try testing.expectEqualStrings("-12.75", s);
}

// ---------------------------------------------------------------------------
// RoundingMode tests — clean-room: expected values hand-derived from the Java
// BigDecimal.RoundingMode javadoc table, the IBM General Decimal Arithmetic
// spec and the Python `decimal` docs (definitions only, no code copied).
// ---------------------------------------------------------------------------

test "rounding truth table — all modes at scale 0 (BigDecimal javadoc inputs)" {
    try testing.expect(RoundingMode.default == .half_even);
    const modes = [_]RoundingMode{ .up, .down, .ceiling, .floor, .half_up, .half_down, .half_even };
    const Case = struct { in: []const u8, want: [7][]const u8 };
    // Column order matches `modes`: up, down, ceiling, floor, half_up,
    // half_down, half_even.
    const cases = [_]Case{
        .{ .in = "5.5", .want = .{ "6", "5", "6", "5", "6", "5", "6" } },
        .{ .in = "3.5", .want = .{ "4", "3", "4", "3", "4", "3", "4" } },
        .{ .in = "2.6", .want = .{ "3", "2", "3", "2", "3", "3", "3" } },
        .{ .in = "2.5", .want = .{ "3", "2", "3", "2", "3", "2", "2" } },
        .{ .in = "2.4", .want = .{ "3", "2", "3", "2", "2", "2", "2" } },
        .{ .in = "1.6", .want = .{ "2", "1", "2", "1", "2", "2", "2" } },
        .{ .in = "1.1", .want = .{ "2", "1", "2", "1", "1", "1", "1" } },
        .{ .in = "1.0", .want = .{ "1", "1", "1", "1", "1", "1", "1" } },
        .{ .in = "-1.0", .want = .{ "-1", "-1", "-1", "-1", "-1", "-1", "-1" } },
        .{ .in = "-1.1", .want = .{ "-2", "-1", "-1", "-2", "-1", "-1", "-1" } },
        .{ .in = "-1.6", .want = .{ "-2", "-1", "-1", "-2", "-2", "-2", "-2" } },
        .{ .in = "-2.4", .want = .{ "-3", "-2", "-2", "-3", "-2", "-2", "-2" } },
        .{ .in = "-2.5", .want = .{ "-3", "-2", "-2", "-3", "-3", "-2", "-2" } },
        .{ .in = "-2.6", .want = .{ "-3", "-2", "-2", "-3", "-3", "-3", "-3" } },
        .{ .in = "-3.5", .want = .{ "-4", "-3", "-3", "-4", "-4", "-3", "-4" } },
        .{ .in = "-5.5", .want = .{ "-6", "-5", "-5", "-6", "-6", "-5", "-6" } },
    };
    for (cases) |c| {
        const v = dec(c.in);
        for (modes, c.want) |m, w| {
            try expectStr(try v.roundToIntegral(m), w);
        }
    }
}

test "half-way at two fractional digits — every mode, both signs" {
    // 0.125 → 2 dp: the discarded remainder is an exact half.
    try expectStr(try dec("0.125").rescale(2, .half_even), "0.12"); // 12 even → stay
    try expectStr(try dec("0.135").rescale(2, .half_even), "0.14"); // 13 odd → bump
    try expectStr(try dec("0.125").rescale(2, .half_up), "0.13");
    try expectStr(try dec("0.125").rescale(2, .half_down), "0.12");
    try expectStr(try dec("0.125").rescale(2, .up), "0.13");
    try expectStr(try dec("0.125").rescale(2, .down), "0.12");
    try expectStr(try dec("0.125").rescale(2, .ceiling), "0.13");
    try expectStr(try dec("0.125").rescale(2, .floor), "0.12");
    try expectStr(try dec("-0.125").rescale(2, .half_even), "-0.12");
    try expectStr(try dec("-0.125").rescale(2, .half_up), "-0.13");
    try expectStr(try dec("-0.125").rescale(2, .half_down), "-0.12");
    try expectStr(try dec("-0.125").rescale(2, .up), "-0.13");
    try expectStr(try dec("-0.125").rescale(2, .down), "-0.12");
    try expectStr(try dec("-0.125").rescale(2, .ceiling), "-0.12");
    try expectStr(try dec("-0.125").rescale(2, .floor), "-0.13");
}

test "rescale — scale up exact, scale down rounds, overflow is typed" {
    // Scale-up / identity: at or above the internal 12-digit precision.
    try testing.expect((try dec("1.5").rescale(12, .down)).eql(dec("1.5")));
    try testing.expect((try dec("1.5").rescale(30, .down)).eql(dec("1.5")));
    // Exact when nothing is discarded — the mode is irrelevant.
    try expectStr(try dec("1.5").rescale(4, .floor), "1.5");
    try expectStr(try dec("-2.44").rescale(2, .up), "-2.44");
    // Negative scale rounds to tens/hundreds.
    try expectStr(try dec("1250").rescale(-2, .half_even), "1200"); // 12.5 tie → 12 (even)
    try expectStr(try dec("1250").rescale(-2, .half_up), "1300");
    try expectStr(try dec("1350").rescale(-2, .half_even), "1400"); // 13.5 tie → 14 (even)
    // Rounding place beyond the whole range: toward zero → 0, away → error.
    try expectStr(try dec("5").rescale(-40, .down), "0");
    try expectStr(try dec("-5").rescale(-40, .half_even), "0");
    try testing.expectError(error.Overflow, dec("5").rescale(-40, .up));
    try testing.expectError(error.Overflow, dec("-5").rescale(-40, .floor));
    // At the i128 boundary a step outward is unrepresentable → error.Overflow.
    const near_max = Decimal{ .raw = std.math.maxInt(i128) };
    try testing.expectError(error.Overflow, near_max.rescale(0, .ceiling));
    try expectStr(try near_max.rescale(0, .floor), "170141183460469231731687303");
    const near_min = Decimal{ .raw = std.math.minInt(i128) };
    try testing.expectError(error.Overflow, near_min.rescale(0, .floor));
    try expectStr(try near_min.rescale(0, .ceiling), "-170141183460469231731687303");
}

test "divRound — quotient at an explicit scale" {
    try expectStr(try dec("1").divRound(dec("3"), 4, .half_even), "0.3333");
    try expectStr(try dec("2").divRound(dec("3"), 4, .half_even), "0.6667");
    try expectStr(try dec("1").divRound(dec("8"), 3, .down), "0.125"); // exact — mode moot
    try expectStr(try dec("1").divRound(dec("8"), 3, .up), "0.125");
    try expectStr(try dec("10").divRound(dec("4"), 1, .half_even), "2.5");
    try expectStr(try dec("10").divRound(dec("4"), 0, .half_even), "2"); // 2.5 tie → even
    try expectStr(try dec("10").divRound(dec("4"), 0, .half_up), "3");
    try expectStr(try dec("7").divRound(dec("2"), 0, .half_even), "4"); // 3.5 tie → even
    try expectStr(try dec("7").divRound(dec("2"), 0, .half_down), "3");
    // Directed modes on a non-terminating quotient, both signs.
    try expectStr(try dec("1").divRound(dec("3"), 4, .ceiling), "0.3334");
    try expectStr(try dec("1").divRound(dec("3"), 4, .floor), "0.3333");
    try expectStr(try dec("-1").divRound(dec("3"), 4, .half_even), "-0.3333");
    try expectStr(try dec("-1").divRound(dec("3"), 4, .ceiling), "-0.3333");
    try expectStr(try dec("-1").divRound(dec("3"), 4, .floor), "-0.3334");
    try expectStr(try dec("-1").divRound(dec("3"), 4, .up), "-0.3334");
    try expectStr(try dec("-1").divRound(dec("3"), 4, .down), "-0.3333");
    // result_scale above 12 clamps to the representation's precision ceiling.
    try testing.expect((try dec("1").divRound(dec("3"), 20, .down)).eql(dec("0.333333333333")));
    // Negative scale: 100/3 = 33.33… rounded to tens.
    try expectStr(try dec("100").divRound(dec("3"), -1, .half_even), "30");
    try expectStr(try dec("100").divRound(dec("3"), -1, .up), "40");
}

test "divRound — errors and edges" {
    try testing.expectError(error.DivisionByZero, dec("1").divRound(Decimal.zero, 2, .half_even));
    // 2e14 / 1e-12 = 2e26, beyond the ±1.7e26 range → typed overflow.
    try testing.expectError(
        error.Overflow,
        dec("200000000000000").divRound(dec("0.000000000001"), 12, .half_even),
    );
    // Zero dividend is zero at any scale and any mode.
    try testing.expect((try Decimal.zero.divRound(dec("3"), -100, .up)).isZero());
    // A rounding place too coarse for any nonzero value: toward zero → 0,
    // away from zero → the ±10^40 result overflows → error.
    try expectStr(try dec("5").divRound(dec("1"), -40, .down), "0");
    try testing.expectError(error.Overflow, dec("5").divRound(dec("1"), -40, .up));
    try expectStr(try dec("5").divRound(dec("1"), -100, .half_even), "0");
    try testing.expectError(error.Overflow, dec("-5").divRound(dec("1"), -100, .floor));
}

test "quantize — GDA/Python-style exponent" {
    try expectStr(try dec("1.2345").quantize(-2, .half_even), "1.23");
    try expectStr(try dec("2.665").quantize(-2, .half_even), "2.66"); // tie, 66 even
    try expectStr(try dec("2.665").quantize(-2, .half_up), "2.67");
    try expectStr(try dec("2.675").quantize(-2, .half_even), "2.68"); // tie, 67 odd
    try expectStr(try dec("1250").quantize(2, .half_even), "1200"); // +2 → hundreds
    try expectStr(try dec("1250").quantize(2, .half_up), "1300");
    try expectStr(try dec("1.5").quantize(-12, .down), "1.5"); // exponent −12 = full precision
    try expectStr(try dec("1.5").quantize(-30, .down), "1.5"); // beyond precision: exact
    try testing.expectError(error.Overflow, dec("5").quantize(40, .up));
}
