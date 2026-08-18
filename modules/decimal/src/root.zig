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
//! Provenance: original work of the zig-libs authors (MIT). Results are
//! explicit error unions and every operation that can exceed the range is
//! overflow-checked (div quotient + parse accumulator).

const std = @import("std");

pub const meta = .{
    .targets = .{ .linux64, .windows },
    .platform = .any, // pure integer logic, no OS calls
    .role = .util,
    .concurrency = .reentrant, // no shared state, no allocation
    .model_after = "Java BigDecimal (incl. RoundingMode) / IBM General Decimal Arithmetic / DB DECIMAL(38,12)",
    .deps = .{}, // std only
};

/// IEEE 754-2008 / General Decimal Arithmetic rounding modes, shared with the
/// arbitrary-precision `BigDecimal` (big.zig) — see rounding_mode.zig.
pub const RoundingMode = @import("rounding_mode.zig").RoundingMode;

/// Arbitrary-precision decimal (`std.math.big.int`-backed significand ×
/// 10^exponent). Rounding core complete and KAT-covered against the IBM/
/// Mike Cowlishaw decTest suite — see big.zig's module doc for the full
/// status writeup (no open backlog).
pub const BigDecimal = @import("big.zig").BigDecimal;

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

    // -----------------------------------------------------------------
    // Bridge to/from the arbitrary-precision `BigDecimal` (big.zig).
    //
    // The two types are a pair — fixed `i128 @ 1e12` for bounded money/ETL
    // math, unbounded significand × 10^exponent for everything else — and a
    // consumer has to be able to move a value between them. Both directions
    // live here rather than on `BigDecimal` so the dependency stays one-way
    // (root.zig already imports big.zig; big.zig imports nothing of root's).
    //
    // Direction asymmetry is the whole story: widening is exact and total,
    // narrowing is neither, so only the narrowing direction takes a
    // `RoundingMode` and returns an error union.
    // -----------------------------------------------------------------

    /// Widen to `BigDecimal`. **Exact and total** — a `Decimal` *is*
    /// `raw × 10^-12`, which is a `BigDecimal` verbatim — so the only
    /// failure mode is allocation.
    ///
    /// Boundary note: the result always carries exactly 12 fractional digits,
    /// trailing zeros included (`1.5` widens to `1.500000000000`), because
    /// that is this type's scale and `BigDecimal` preserves stored scale (see
    /// its `toStringAlloc` doc). Call `BigDecimal.normalize` on the result for
    /// the shortest equal form. Round-tripping `toBigDecimal` then
    /// `fromBigDecimal` is the identity for every `Decimal`, in every rounding
    /// mode — nothing is discarded in either step.
    pub fn toBigDecimal(self: Decimal, allocator: std.mem.Allocator) std.mem.Allocator.Error!BigDecimal {
        return .{
            .coeff = try std.math.big.int.Managed.initSet(allocator, self.raw),
            .exponent = -@as(i32, @intCast(scale)),
        };
    }

    /// `Overflow` = the `BigDecimal`'s magnitude is outside this type's
    /// ≈ ±1.7e26 range (or, pathologically, its coefficient is wider than
    /// `BigDecimal.max_align_shift` digits — see the narrowing note below).
    pub const FromBigError = error{Overflow} || std.mem.Allocator.Error;

    /// Narrow a `BigDecimal` to this fixed-scale type. Unlike `toBigDecimal`
    /// this is partial in two independent ways, and both are surfaced as
    /// typed outcomes rather than silent behaviour — the module's standing
    /// discipline (never trap, never truncate silently):
    ///
    ///   * **Precision** — fractional digits past the 12th cannot be stored,
    ///     so they are *rounded* into the 12th with `mode` (never truncated;
    ///     `mode` is applied by the same `BigDecimal.rescale` path every other
    ///     rounding-sensitive op uses). A value smaller than half an ulp is
    ///     not an error: it rounds to `0` under `down`/`half_up`/`half_down`/
    ///     `half_even` and to ±1e-12 under `up`/`ceiling`/`floor` (whichever
    ///     of the two is away from zero), exactly like `divRound` at a
    ///     too-coarse scale.
    ///   * **Range** — a magnitude beyond ≈ ±1.7e26 is `error.Overflow`. This
    ///     includes the case where rounding *creates* the overflow (a value
    ///     one ulp under the ceiling rounded with `ceiling`), because the
    ///     range check happens after the rounding, on the final coefficient.
    ///
    /// Both checks are made *before* materialising any power of ten, so a
    /// hostile input (`1e2000000000`, or a coefficient at exponent −2e9)
    /// returns a clean error / a rounded zero instead of attempting an
    /// astronomically large allocation.
    ///
    /// Pathological corner, stated for completeness: a coefficient with more
    /// than `BigDecimal.max_align_shift` (10^6) digits whose exponent also
    /// needs that many digits dropped hits `BigDecimal.rescale`'s alignment
    /// ceiling and reports `error.Overflow` even though the value itself might
    /// be in range. That is the pre-existing `max_align_shift` guard, not a
    /// separate rule.
    pub fn fromBigDecimal(allocator: std.mem.Allocator, b: BigDecimal, mode: RoundingMode) FromBigError!Decimal {
        if (b.isZero()) return Decimal.zero;
        const target: i32 = -@as(i32, @intCast(scale)); // 12 fractional digits
        const digits: i64 = @intCast(try b.precision(allocator));
        const result_neg = !b.coeff.isPositive();

        if (b.exponent >= target) {
            // Widening the exponent to −12 is exact; the resulting raw has
            // `digits + shift` digits and i128 tops out at 39 of them. Checked
            // here so `1e2000000000` errors instead of trying to build a
            // 2-billion-digit integer on the way to a guaranteed overflow.
            const shift: i64 = @as(i64, b.exponent) - target;
            if (digits + shift > 39) return error.Overflow;
        } else {
            const drop: i64 = @as(i64, target) - @as(i64, b.exponent);
            if (drop > digits) {
                // |coeff| < 10^digits ≤ 10^(drop−1), so the quotient is 0 and
                // twice the discarded remainder is strictly below 10^drop:
                // no tie is possible and only the away-from-zero modes give a
                // nonzero result. Identical to what `rescale` would return,
                // without materialising 10^drop.
                if (!roundsAwayWhenBelowHalf(result_neg, mode)) return Decimal.zero;
                return .{ .raw = if (result_neg) -1 else 1 };
            }
        }

        var r = try BigDecimal.rescale(allocator, b, target, mode);
        defer r.deinit();
        return .{ .raw = r.coeff.toConst().toInt(i128) catch return error.Overflow };
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
// Sub-module test aggregation (CONVENTIONS.md §6.3: a bare `pub const x =
// @import("x.zig")` re-export does not pull x's tests into the test binary —
// they must be reached from a `test {}` block here).
// ---------------------------------------------------------------------------

test {
    _ = @import("big.zig");
}

// ---------------------------------------------------------------------------
// Tests
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

// ---------------------------------------------------------------------------
// Bridge tests — Decimal <-> BigDecimal. No external vectors needed: the two
// types' own parse/format and this type's documented range limits are the
// oracle.
// ---------------------------------------------------------------------------

const all_modes = [_]RoundingMode{ .up, .down, .ceiling, .floor, .half_up, .half_down, .half_even };

fn expectBigStr(b: BigDecimal, want: []const u8) !void {
    const s = try b.toStringAlloc(testing.allocator);
    defer testing.allocator.free(s);
    try testing.expectEqualStrings(want, s);
}

test "bridge: widening is exact and carries the fixed 12-digit scale" {
    var a = try dec("1.5").toBigDecimal(testing.allocator);
    defer a.deinit();
    // Trailing zeros are the point: BigDecimal preserves stored scale, and
    // this type's scale IS 12 — so the widened form says so.
    try expectBigStr(a, "1.500000000000");
    try testing.expectEqual(@as(i32, -12), a.exponent);

    var n = try BigDecimal.normalize(testing.allocator, a);
    defer n.deinit();
    try expectBigStr(n, "1.5");

    // The i128 extremes widen exactly — nothing about them is special here.
    var mx = try (Decimal{ .raw = std.math.maxInt(i128) }).toBigDecimal(testing.allocator);
    defer mx.deinit();
    try expectBigStr(mx, "170141183460469231731687303.715884105727");
    var mn = try (Decimal{ .raw = std.math.minInt(i128) }).toBigDecimal(testing.allocator);
    defer mn.deinit();
    try expectBigStr(mn, "-170141183460469231731687303.715884105728");
}

test "bridge: round-trip is the identity, in every rounding mode" {
    const raws = [_]i128{
        0,                         1,                     -1,
        Decimal.scale_factor,      -Decimal.scale_factor, 123_456_789,
        std.math.maxInt(i128),     std.math.minInt(i128), std.math.maxInt(i128) - 1,
        std.math.minInt(i128) + 1,
    };
    for (raws) |raw| {
        const d = Decimal{ .raw = raw };
        var b = try d.toBigDecimal(testing.allocator);
        defer b.deinit();
        for (all_modes) |m| {
            const back = try Decimal.fromBigDecimal(testing.allocator, b, m);
            try testing.expectEqual(raw, back.raw);
        }
    }
}

test "bridge: narrowing rounds the 13th digit with the caller's mode" {
    var b = try BigDecimal.parse(testing.allocator, "0.1234567890125");
    defer b.deinit();
    // Exact half-way at the 13th fractional digit — every mode is visible.
    try expectStr(try Decimal.fromBigDecimal(testing.allocator, b, .half_up), "0.123456789013");
    try expectStr(try Decimal.fromBigDecimal(testing.allocator, b, .half_down), "0.123456789012");
    try expectStr(try Decimal.fromBigDecimal(testing.allocator, b, .half_even), "0.123456789012"); // …012 even
    try expectStr(try Decimal.fromBigDecimal(testing.allocator, b, .up), "0.123456789013");
    try expectStr(try Decimal.fromBigDecimal(testing.allocator, b, .down), "0.123456789012");
    try expectStr(try Decimal.fromBigDecimal(testing.allocator, b, .ceiling), "0.123456789013");
    try expectStr(try Decimal.fromBigDecimal(testing.allocator, b, .floor), "0.123456789012");

    var nb = try BigDecimal.parse(testing.allocator, "-0.1234567890125");
    defer nb.deinit();
    try expectStr(try Decimal.fromBigDecimal(testing.allocator, nb, .half_up), "-0.123456789013");
    try expectStr(try Decimal.fromBigDecimal(testing.allocator, nb, .ceiling), "-0.123456789012");
    try expectStr(try Decimal.fromBigDecimal(testing.allocator, nb, .floor), "-0.123456789013");

    // Arbitrary precision far past 12 digits, no tie: rounds, never truncates.
    var wide = try BigDecimal.parse(testing.allocator, "1." ++ "9" ** 60);
    defer wide.deinit();
    try expectStr(try Decimal.fromBigDecimal(testing.allocator, wide, .half_even), "2");
    try expectStr(try Decimal.fromBigDecimal(testing.allocator, wide, .down), "1.999999999999");
}

test "bridge: below half an ulp is a rounding decision, not an error" {
    var tiny = try BigDecimal.parse(testing.allocator, "0.0000000000001"); // 1e-13
    defer tiny.deinit();
    try expectStr(try Decimal.fromBigDecimal(testing.allocator, tiny, .down), "0");
    try expectStr(try Decimal.fromBigDecimal(testing.allocator, tiny, .half_even), "0");
    try expectStr(try Decimal.fromBigDecimal(testing.allocator, tiny, .half_up), "0");
    try expectStr(try Decimal.fromBigDecimal(testing.allocator, tiny, .up), "0.000000000001");
    try expectStr(try Decimal.fromBigDecimal(testing.allocator, tiny, .ceiling), "0.000000000001");
    try expectStr(try Decimal.fromBigDecimal(testing.allocator, tiny, .floor), "0");

    var ntiny = try BigDecimal.parse(testing.allocator, "-0.0000000000001");
    defer ntiny.deinit();
    try expectStr(try Decimal.fromBigDecimal(testing.allocator, ntiny, .up), "-0.000000000001");
    try expectStr(try Decimal.fromBigDecimal(testing.allocator, ntiny, .ceiling), "0");
    try expectStr(try Decimal.fromBigDecimal(testing.allocator, ntiny, .floor), "-0.000000000001");
    try expectStr(try Decimal.fromBigDecimal(testing.allocator, ntiny, .down), "0");

    // A wildly out-of-scale exponent takes the same short-circuit — this must
    // NOT try to materialise 10^2000000000 on the way to the answer.
    var absurd = try BigDecimal.parse(testing.allocator, "1e-2000000000");
    defer absurd.deinit();
    try expectStr(try Decimal.fromBigDecimal(testing.allocator, absurd, .half_even), "0");
    try expectStr(try Decimal.fromBigDecimal(testing.allocator, absurd, .up), "0.000000000001");
}

test "bridge: out-of-range narrowing is a typed error, checked before allocating" {
    var big = try BigDecimal.parse(testing.allocator, "1e30");
    defer big.deinit();
    try testing.expectError(error.Overflow, Decimal.fromBigDecimal(testing.allocator, big, .half_even));

    // Same shape, absurd magnitude: rejected on the digit-count estimate, so
    // no 2-billion-digit integer is ever built.
    var absurd = try BigDecimal.parse(testing.allocator, "1e2000000000");
    defer absurd.deinit();
    try testing.expectError(error.Overflow, Decimal.fromBigDecimal(testing.allocator, absurd, .down));

    // A coefficient far wider than i128, at a benign exponent.
    var wide = try BigDecimal.parse(testing.allocator, "9" ** 45 ++ ".5");
    defer wide.deinit();
    try testing.expectError(error.Overflow, Decimal.fromBigDecimal(testing.allocator, wide, .down));
}

test "bridge: rounding that creates the overflow still errors" {
    // One ulp under the ceiling with a 13th digit: rounding up leaves the
    // range, rounding down does not. The range check must therefore happen
    // AFTER the rounding, not on the input.
    var over = try BigDecimal.parse(testing.allocator, "170141183460469231731687303.7158841057275");
    defer over.deinit();
    try testing.expectError(error.Overflow, Decimal.fromBigDecimal(testing.allocator, over, .half_up));
    try testing.expectError(error.Overflow, Decimal.fromBigDecimal(testing.allocator, over, .ceiling));
    try expectStr(
        try Decimal.fromBigDecimal(testing.allocator, over, .down),
        "170141183460469231731687303.715884105727",
    );
    // The i128 minimum is asymmetric: -…105728 is representable, -…105729 is not.
    var under = try BigDecimal.parse(testing.allocator, "-170141183460469231731687303.7158841057285");
    defer under.deinit();
    try testing.expectError(error.Overflow, Decimal.fromBigDecimal(testing.allocator, under, .floor));
    try expectStr(
        try Decimal.fromBigDecimal(testing.allocator, under, .ceiling),
        "-170141183460469231731687303.715884105728",
    );
}

test "bridge: the two types agree on arithmetic they can both express" {
    const pairs = [_][2][]const u8{
        .{ "0.1", "0.2" },
        .{ "5.75", "3.3" },
        .{ "-7", "2.5" },
        .{ "1234567.891011", "-0.000000000001" },
    };
    for (pairs) |p| {
        const fa = dec(p[0]);
        const fb = dec(p[1]);
        var ba = try fa.toBigDecimal(testing.allocator);
        defer ba.deinit();
        var bb = try fb.toBigDecimal(testing.allocator);
        defer bb.deinit();

        var bsum = try BigDecimal.add(testing.allocator, ba, bb);
        defer bsum.deinit();
        try testing.expect((try Decimal.fromBigDecimal(testing.allocator, bsum, .half_even)).eql(try fa.add(fb)));

        var bprod = try BigDecimal.mul(testing.allocator, ba, bb);
        defer bprod.deinit();
        // BigDecimal.mul is exact at 24 fractional digits; narrowing back with
        // the fixed type's own mode (half-away-from-zero) must reproduce
        // Decimal.mul exactly.
        try testing.expect((try Decimal.fromBigDecimal(testing.allocator, bprod, .half_up)).eql(try fa.mul(fb)));
    }
}

// ── fuzz: decimal string parse, never panics ────────────────────────────────
//
// `parse` reads a decimal literal straight out of a config file, a CSV
// column, or a user-typed amount — text this process did not produce, with
// no structural guarantee (sign/exponent/digit-run lengths are all
// attacker/user chosen). Bias toward digit/sign/dot/exponent characters so
// the mantissa and scientific-notation paths are actually reached.

test "fuzz: parse never panics on arbitrary text" {
    try testing.fuzz({}, fuzzParse, .{});
}

test "parse hardening: mantissa width cap prevents i256 accumulator overflow" {
    // 90 significant digits: past i256's ~77-digit capacity. The width cap
    // (digits_seen > 60) must fire during the digit loop, BEFORE the
    // `mant = mant * 10 + digit` multiply ever risks overflowing the i256
    // accumulator itself. A cap that is merely "wide enough to also be
    // caught later by the final i128-range check" is not enough — the
    // 61-digit case above passes even with a much larger (buggy) cap because
    // the i128 bounds check independently rejects it too. Only an input this
    // long distinguishes "cap fires early and cleanly" from "accumulator
    // traps with an unchecked overflow panic".
    var buf: [90]u8 = undefined;
    @memset(&buf, '9');
    try testing.expectError(error.Overflow, Decimal.parse(buf[0..90]));
}

fn fuzzParse(_: void, smith: *std.testing.Smith) !void {
    const alphabet = "0123456789+-.eE";
    var buf: [80]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    for (buf[0..len]) |*c| {
        if (smith.boolWeighted(1, 4)) c.* = alphabet[c.* % alphabet.len];
    }
    _ = Decimal.parse(buf[0..len]) catch return;
}
