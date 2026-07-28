// SPDX-License-Identifier: MIT
//! BigDecimal — arbitrary-precision base-10 decimal: an unbounded significand
//! (`std.math.big.int.Managed`) × `10^exponent`. Companion to the fixed-scale
//! `Decimal` (root.zig, `i128 @ 1e12`, `DECIMAL(38,12)`-shaped) for values
//! whose precision or magnitude cannot be bounded ahead of time.
//!
//! ## Status: rounding core complete — read this before extending it
//!
//! `std.math.big.int.Managed` already supplies every arbitrary-precision
//! **integer** primitive this module needs: exact multiplication (`mul`),
//! exact truncating division with remainder (`divTrunc` — Knuth Algorithm D
//! under the hood), exact magnitude comparison (`order`/`orderAgainstScalar`),
//! exact integer powers (`pow`, used here to materialise `10^k`), and even
//! digit-string parse/format in base 10 (`setString`/`toStringAlloc`) and a
//! base-10 digit-count (`log10`/`log10Alloc`). **None of that bignum core is
//! reimplemented here** — see the `std.math.big.int` inventory in SPEC.md's
//! "BigDecimal" section for the full list with line references.
//!
//! What std does *not* give you is a judgment call: once a division doesn't
//! terminate in base 10 (`1/3`), or a rescale/quantize drops digits, *how
//! many digits to keep and which way to round the discarded remainder* is
//! General-Decimal-Arithmetic / `java.math.BigDecimal` domain knowledge, not
//! bignum plumbing — std has no opinion on it (nor should it). That single
//! judgment call is centralised in `roundedDivMag` below. Every
//! rounding-*sensitive* op (`div`, the precision-*narrowing* branch of
//! `rescale`/`quantize`/`roundToIntegral`) is thin wiring on top of it.
//! Everything else — parse, format, add, sub, mul, compare, normalize, and
//! the precision-*widening* branch of `rescale` — needs no rounding decision
//! (arbitrary precision makes `+ − ×` exact, and widening precision is a pure
//! multiply). All of it is implemented and KAT-tested below.
//!
//! Honest sizing verdict (see SPEC.md for the full writeup): because
//! `std.math.big.int` already owns the actual bignum algorithms, this module
//! is *not* "implement a bignum library" — it's "compose existing bignum
//! primitives with exhaustive, spec-literal correctness in the one place
//! (`roundedDivMag`) where a rounding-mode judgment call happens." That is
//! real, correctness-critical, money-adjacent work worth an exhaustive KAT
//! pass — but it is not an irreducibly novel algorithm the way, say,
//! Knuth Algorithm D or a hash-to-curve map is.
//!
//! Provenance: original scaffold by the zig-libs authors (MIT), modeled
//! after Java `BigDecimal` / IBM General Decimal Arithmetic (design
//! reference only). The KAT vectors wired in below are drawn from the actual
//! IBM/Mike Cowlishaw `decTest` suite v2.62 (add.decTest / multiply.decTest /
//! quantize.decTest / rounding.decTest), "Reproduced with permission ...
//! Copyright 1997, 2009 by International Business Machines Corporation" per
//! https://speleotrove.com/decimal/dectest.html — see per-block provenance
//! comments below and NOTICE.

const std = @import("std");
const Allocator = std.mem.Allocator;
const bigint = std.math.big.int;
const Managed = bigint.Managed;
const RoundingMode = @import("rounding_mode.zig").RoundingMode;

pub const BigDecimal = struct {
    /// Significand. `std.math.big.int` is sign-magnitude — the sign lives on
    /// `coeff.metadata`'s high bit, independent of the magnitude, so a
    /// "negative zero" coefficient is representable (see `negate`'s doc
    /// comment) even though this module chooses not to surface it.
    coeff: Managed,
    /// value = coeff × 10^exponent. May be negative (fractional values);
    /// unlike `coeff`, this is a bounded `i32` — see `max_align_shift`.
    exponent: i32,

    pub const meta = .{
        .platform = .any,
        .role = .util,
        .concurrency = .reentrant, // no shared/global state; caller owns the allocator
        .model_after = "Java BigDecimal / IBM General Decimal Arithmetic, built on std.math.big.int",
        .deps = .{}, // std only
    };

    /// Exponent-arithmetic overflow (the `i32` exponent, or the
    /// `max_align_shift` safety ceiling below) — **not** a precision limit.
    /// The significand (`coeff`) is a `Managed` and has no width bound; only
    /// the base-10 exponent and the alignment-shift safety ceiling are.
    pub const Error = error{Overflow} || Allocator.Error;
    pub const DivError = Error || error{DivisionByZero};
    /// `InvalidCharacter` = malformed input; `Overflow` = a well-formed
    /// literal exponent too large to fit `i32` (again: the coefficient
    /// itself has no width limit — only its base-10 exponent is bounded).
    pub const ParseError = error{ InvalidCharacter, Overflow } || Allocator.Error;

    /// Safety ceiling on how large an exponent *difference* this module will
    /// materialise as `10^k` when aligning two operands (`add`/`sub`) or
    /// widening precision (`rescale` toward a smaller/more-negative
    /// exponent). This is a pragmatic guard, **not** a General Decimal
    /// Arithmetic rule (GDA itself has no such limit) — it exists so a
    /// hostile or typo'd exponent (e.g. `"1e9999999999"`) can't force an
    /// unbounded allocation before the caller gets a clean error:
    /// `10^1_000_000` is already a ~415KB integer, far past any real
    /// financial or scientific use of this module.
    pub const max_align_shift: u32 = 1_000_000;

    pub fn deinit(self: *BigDecimal) void {
        self.coeff.deinit();
    }

    pub fn initZero(allocator: Allocator) Allocator.Error!BigDecimal {
        return .{ .coeff = try Managed.init(allocator), .exponent = 0 };
    }

    /// Whole number → BigDecimal at exponent 0. No overflow is possible
    /// (unlike the fixed-scale `Decimal.fromInt`) — `i128` always fits.
    pub fn fromInt(allocator: Allocator, n: i128) Allocator.Error!BigDecimal {
        return .{ .coeff = try Managed.initSet(allocator, n), .exponent = 0 };
    }

    pub fn clone(self: BigDecimal) Allocator.Error!BigDecimal {
        return .{ .coeff = try self.coeff.clone(), .exponent = self.exponent };
    }

    pub fn isZero(self: BigDecimal) bool {
        return self.coeff.eqlZero();
    }

    /// In-place negation. `Managed.negate` unconditionally flips the sign
    /// bit — including on a zero coefficient, which is how a "negative
    /// zero" `BigDecimal` can exist internally (`std.math.big.int` doesn't
    /// forbid it). `toStringAlloc` deliberately does not surface that sign
    /// on a zero value; see its doc comment.
    pub fn negate(self: *BigDecimal) void {
        self.coeff.negate();
    }

    pub fn absVal(self: *BigDecimal) void {
        self.coeff.abs();
    }

    // -----------------------------------------------------------------
    // Parse / format — no rounding decision, no width limit; fully
    // implemented. The actual "turn a long digit string into a bignum" /
    // "turn a bignum into a long digit string" algorithms are
    // `std.math.big.int.Managed.setString` / `Const.toStringAlloc` — this
    // function's job is only splitting GDA text notation
    // (sign / int-digits / '.' / frac-digits / exponent) into that digit
    // string + an `i32` exponent, which is ordinary scanning, not bignum
    // math.
    // -----------------------------------------------------------------

    /// Parse a plain or scientific-notation decimal string into a
    /// `BigDecimal`. No width limit on the significand (unlike the
    /// fixed-scale `Decimal.parse`'s 60-digit mantissa cap) — only the
    /// literal exponent is bounded (`error.Overflow` past ~`i32` range).
    pub fn parse(allocator: Allocator, s: []const u8) ParseError!BigDecimal {
        if (s.len == 0) return error.InvalidCharacter;
        var i: usize = 0;
        var is_neg = false;
        if (s[i] == '+') {
            i += 1;
        } else if (s[i] == '-') {
            is_neg = true;
            i += 1;
        }

        var digits: std.ArrayList(u8) = .empty;
        defer digits.deinit(allocator);
        if (is_neg) try digits.append(allocator, '-');

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
            try digits.append(allocator, c);
            digits_seen += 1;
            if (seen_dot) frac_digits += 1;
        }
        if (digits_seen == 0) return error.InvalidCharacter;

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
                // Cap accumulation width (not value range): ~15 digits is
                // already far past i32, so this only stops the i64
                // accumulator itself from overflowing on a pathological
                // input like a 40-digit exponent literal.
                if (exp_digits < 15) exp = exp * 10 + @as(i64, s[i] - '0');
                exp_digits += 1;
            }
            if (exp_digits == 0) return error.InvalidCharacter;
            if (exp_neg) exp = -exp;
        }
        if (i != s.len) return error.InvalidCharacter;

        const exponent64: i64 = exp - frac_digits;
        if (exponent64 > std.math.maxInt(i32) or exponent64 < std.math.minInt(i32)) {
            return error.Overflow;
        }

        var coeff = try Managed.init(allocator);
        errdefer coeff.deinit();
        coeff.setString(10, digits.items) catch |err| switch (err) {
            error.InvalidCharacter => return error.InvalidCharacter,
            error.InvalidBase => unreachable, // base is a fixed literal 10
            error.OutOfMemory => return error.OutOfMemory,
        };

        return .{ .coeff = coeff, .exponent = @intCast(exponent64) };
    }

    /// Canonical **plain-notation** string — this module never emits
    /// scientific notation (a deliberate scope cut; see SPEC.md). Unlike the
    /// fixed-scale `Decimal.toString`, trailing zeros are **not** trimmed:
    /// `coeff`/`exponent` *is* the value's actual stored precision (Java
    /// `BigDecimal` / GDA semantics — `1.50` and `1.5` are distinct
    /// `BigDecimal`s with different scales that happen to `order()` equal;
    /// see the `mulx011`/`mulx012`/`addx007`/`addx008` KAT below, which only
    /// pass because trailing zeros are preserved). Zero always prints as
    /// plain `"0"` regardless of `exponent` or its sign bit — GDA's "ideal
    /// exponent" preservation for zero (`0.00`, `-0.00`, `0E+2`) is a
    /// documented non-goal, not an oversight (see `negate`'s doc comment).
    pub fn toStringAlloc(self: BigDecimal, allocator: Allocator) Allocator.Error![]u8 {
        if (self.isZero()) return allocator.dupe(u8, "0");

        const digits = try self.coeff.toConst().toStringAlloc(allocator, 10, .lower);
        defer allocator.free(digits);
        const neg = digits[0] == '-';
        const mag = if (neg) digits[1..] else digits[0..];
        const sign_len: usize = if (neg) 1 else 0;

        if (self.exponent >= 0) {
            const zeros: usize = @intCast(self.exponent);
            const out = try allocator.alloc(u8, sign_len + mag.len + zeros);
            var w: usize = 0;
            if (neg) {
                out[0] = '-';
                w = 1;
            }
            @memcpy(out[w..][0..mag.len], mag);
            w += mag.len;
            @memset(out[w..], '0');
            return out;
        }

        const frac_len: usize = @intCast(-@as(i64, self.exponent));
        if (mag.len > frac_len) {
            // Integer part is nonempty: split mag at the decimal point.
            const int_len = mag.len - frac_len;
            const out = try allocator.alloc(u8, sign_len + mag.len + 1);
            var w: usize = 0;
            if (neg) {
                out[0] = '-';
                w = 1;
            }
            @memcpy(out[w..][0..int_len], mag[0..int_len]);
            w += int_len;
            out[w] = '.';
            w += 1;
            @memcpy(out[w..][0..frac_len], mag[int_len..]);
            return out;
        }

        // Integer part is "0": left-pad the fraction with zeros.
        const lead_zeros = frac_len - mag.len;
        const out = try allocator.alloc(u8, sign_len + 2 + lead_zeros + mag.len);
        var w: usize = 0;
        if (neg) {
            out[0] = '-';
            w = 1;
        }
        out[w] = '0';
        out[w + 1] = '.';
        w += 2;
        @memset(out[w..][0..lead_zeros], '0');
        w += lead_zeros;
        @memcpy(out[w..][0..mag.len], mag);
        return out;
    }

    // Note: no `std.fmt` `{f}` formatter is provided. The fixed-scale
    // `Decimal.format` can be allocation-free because its output length is
    // bounded (`str_buf_len`); an arbitrary-precision significand has no
    // such bound, so formatting genuinely needs an allocator, and
    // `std.Io.Writer`'s `format(self, writer)` callback signature has
    // nowhere to thread one through. Call `toStringAlloc` directly instead.

    // -----------------------------------------------------------------
    // Comparison — exact. Aligning exponents by exact widening (never
    // rounding) and then comparing magnitudes is enough; no Fable stub
    // needed here.
    // -----------------------------------------------------------------

    /// Three-way compare. Allocates a scratch difference when exponents
    /// differ (cross-scaling by `10^k` to align is exact — unlike division,
    /// it never loses information, so this needs no rounding mode).
    pub fn order(allocator: Allocator, a: BigDecimal, b: BigDecimal) Error!std.math.Order {
        if (a.exponent == b.exponent) return a.coeff.toConst().order(b.coeff.toConst());
        var diff = try sub(allocator, a, b);
        defer diff.deinit();
        return diff.coeff.toConst().orderAgainstScalar(0);
    }

    pub fn eql(allocator: Allocator, a: BigDecimal, b: BigDecimal) Error!bool {
        return (try order(allocator, a, b)) == .eq;
    }

    // -----------------------------------------------------------------
    // Exact arithmetic. Arbitrary precision means +/-/× never need to
    // round: no Fable stub anywhere in this section.
    // -----------------------------------------------------------------

    /// Exact addition. Result exponent is `min(a.exponent, b.exponent)`
    /// (the GDA `add` rule) — the operand with the larger exponent is
    /// exactly widened (multiplied by `10^k`) to match before adding.
    pub fn add(allocator: Allocator, a: BigDecimal, b: BigDecimal) Error!BigDecimal {
        if (a.exponent == b.exponent) {
            var r = try Managed.init(allocator);
            errdefer r.deinit();
            try r.add(&a.coeff, &b.coeff);
            return .{ .coeff = r, .exponent = a.exponent };
        }
        const lo_exp = @min(a.exponent, b.exponent);
        if (a.exponent > b.exponent) {
            const shift = try alignShift(a.exponent, lo_exp);
            var a_scaled = try scaleUp(allocator, &a.coeff, shift);
            defer a_scaled.deinit();
            var r = try Managed.init(allocator);
            errdefer r.deinit();
            try r.add(&a_scaled, &b.coeff);
            return .{ .coeff = r, .exponent = lo_exp };
        } else {
            const shift = try alignShift(b.exponent, lo_exp);
            var b_scaled = try scaleUp(allocator, &b.coeff, shift);
            defer b_scaled.deinit();
            var r = try Managed.init(allocator);
            errdefer r.deinit();
            try r.add(&a.coeff, &b_scaled);
            return .{ .coeff = r, .exponent = lo_exp };
        }
    }

    /// Exact subtraction: `add(a, -b)`.
    pub fn sub(allocator: Allocator, a: BigDecimal, b: BigDecimal) Error!BigDecimal {
        var neg_b = try b.clone();
        defer neg_b.deinit();
        neg_b.negate();
        return add(allocator, a, neg_b);
    }

    /// Exact multiplication: `a.coeff × b.coeff` at `a.exponent + b.exponent`.
    /// Multiplication never loses digits, so — unlike the fixed-scale
    /// `Decimal.mul`, which widens to `i256` and still rounds the 12th
    /// digit — this needs no rounding mode at all.
    pub fn mul(allocator: Allocator, a: BigDecimal, b: BigDecimal) Error!BigDecimal {
        const exp64: i64 = @as(i64, a.exponent) + @as(i64, b.exponent);
        if (exp64 > std.math.maxInt(i32) or exp64 < std.math.minInt(i32)) return error.Overflow;
        var r = try Managed.init(allocator);
        errdefer r.deinit();
        try r.mul(&a.coeff, &b.coeff);
        return .{ .coeff = r, .exponent = @intCast(exp64) };
    }

    /// Strip exact trailing zero digits from the coefficient, incrementing
    /// `exponent` to compensate — e.g. `1200` at exponent `-2` (i.e. `12.00`)
    /// normalizes to `12` at exponent `0` (i.e. `12`), the identical value in
    /// canonical form. Exact: each step is a divisibility-by-10 check via
    /// `Managed.divTrunc`, no rounding decision — unlike `roundedDivMag`,
    /// this does **not** need to be a Fable stub. Zero is returned unchanged
    /// (its exponent carries no information once normalized, and GDA leaves
    /// zero's exponent alone rather than collapsing it to 0).
    pub fn normalize(allocator: Allocator, a: BigDecimal) Error!BigDecimal {
        var r = try a.clone();
        errdefer r.coeff.deinit();
        if (r.coeff.eqlZero()) return r;

        var ten = try Managed.initSet(allocator, 10);
        defer ten.deinit();
        var q = try Managed.init(allocator);
        defer q.deinit();
        var rem = try Managed.init(allocator);
        defer rem.deinit();

        while (r.exponent < std.math.maxInt(i32)) {
            try q.divTrunc(&rem, &r.coeff, &ten);
            if (!rem.eqlZero()) break;
            r.coeff.swap(&q);
            r.exponent += 1;
        }
        return r;
    }

    // -----------------------------------------------------------------
    // Rounding-sensitive ops. `div` always needs a rounding decision
    // (division is the one op arbitrary precision can't make exact in
    // general — `1/3` never terminates in base 10). `rescale`/`quantize`/
    // `roundToIntegral` only need one when *narrowing* precision (dropping
    // digits); widening is exact and handled without touching the stub.
    // -----------------------------------------------------------------

    /// a / b, quotient computed to `target_scale` fractional digits (result
    /// exponent = `-target_scale`) with the discarded remainder resolved by
    /// `mode` — the GDA / `BigDecimal.divide(divisor, scale, roundingMode)`
    /// shape, matching the fixed-scale module's `divRound`. Always routes
    /// through `roundedDivMag` except for the unconditionally-exact
    /// zero-dividend case.
    pub fn div(allocator: Allocator, a: BigDecimal, b: BigDecimal, target_scale: i32, mode: RoundingMode) DivError!BigDecimal {
        if (b.isZero()) return error.DivisionByZero;
        if (a.isZero()) return .{ .coeff = try Managed.init(allocator), .exponent = -target_scale };

        const result_neg = a.coeff.isPositive() != b.coeff.isPositive();

        // Scale so the quotient's implied exponent is -target_scale:
        // shift = target_scale + a.exponent - b.exponent. A negative shift
        // means the *divisor* effectively needs scaling instead (equivalent
        // to scaling the numerator by a negative power of ten) — handled by
        // scaling `den` up by -shift rather than `num`.
        const shift64: i64 = @as(i64, target_scale) + @as(i64, a.exponent) - @as(i64, b.exponent);

        var num = try a.coeff.clone();
        defer num.deinit();
        num.abs();
        var den = try b.coeff.clone();
        defer den.deinit();
        den.abs();

        if (shift64 >= 0) {
            if (shift64 > max_align_shift) return error.Overflow;
            var scaled = try scaleUp(allocator, &num, @intCast(shift64));
            defer scaled.deinit();
            var q = try roundedDivMag(allocator, &scaled, &den, result_neg, mode);
            errdefer q.deinit();
            if (result_neg) q.negate();
            return .{ .coeff = q, .exponent = -target_scale };
        } else {
            const den_shift = -shift64;
            if (den_shift > max_align_shift) return error.Overflow;
            var scaled_den = try scaleUp(allocator, &den, @intCast(den_shift));
            defer scaled_den.deinit();
            var q = try roundedDivMag(allocator, &num, &scaled_den, result_neg, mode);
            errdefer q.deinit();
            if (result_neg) q.negate();
            return .{ .coeff = q, .exponent = -target_scale };
        }
    }

    /// Re-express `a` at a new `exponent`. **Widening** precision
    /// (`new_exponent <= a.exponent`, i.e. equal or more fractional digits)
    /// is exact — pure multiplication, no rounding decision involved.
    /// **Narrowing** precision (`new_exponent > a.exponent`) discards digits
    /// and needs `mode` to resolve them, so it routes through
    /// `roundedDivMag` — except for the unconditionally-exact zero case.
    pub fn rescale(allocator: Allocator, a: BigDecimal, new_exponent: i32, mode: RoundingMode) Error!BigDecimal {
        if (a.isZero()) {
            var r = try a.clone();
            r.exponent = new_exponent;
            return r;
        }
        if (new_exponent <= a.exponent) {
            const shift = try alignShift(a.exponent, new_exponent);
            var r = try scaleUp(allocator, &a.coeff, shift);
            errdefer r.deinit();
            return .{ .coeff = r, .exponent = new_exponent };
        }
        const drop = try alignShift(new_exponent, a.exponent); // new_exponent - a.exponent > 0
        var ten_k = try Managed.init(allocator);
        defer ten_k.deinit();
        {
            var ten = try Managed.initSet(allocator, 10);
            defer ten.deinit();
            try ten_k.pow(&ten, drop);
        }
        var num = try a.coeff.clone();
        defer num.deinit();
        const result_neg = !num.isPositive();
        num.abs();
        var q = try roundedDivMag(allocator, &num, &ten_k, result_neg, mode);
        errdefer q.deinit();
        if (result_neg) q.negate();
        return .{ .coeff = q, .exponent = new_exponent };
    }

    /// Sugar for `rescale(a, 0, mode)` (GDA round-to-integral-value; Java
    /// `BigDecimal.setScale(0, mode)`).
    pub fn roundToIntegral(allocator: Allocator, a: BigDecimal, mode: RoundingMode) Error!BigDecimal {
        return rescale(allocator, a, 0, mode);
    }

    /// GDA/Python-style quantize: round so the last significant place is
    /// `10^exponent`. Sugar for `rescale(a, exponent, mode)` — `BigDecimal`
    /// stores its exponent directly (unlike the fixed-scale module's
    /// `quantize`, which negates its argument to convert to a fractional-
    /// digit count), so no sign flip is needed here.
    pub fn quantize(allocator: Allocator, a: BigDecimal, exponent: i32, mode: RoundingMode) Error!BigDecimal {
        return rescale(allocator, a, exponent, mode);
    }
};

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Exact: multiply `coeff` by `10^shift`. This is the "gain precision"
/// direction (used by `add`/`sub` alignment and `rescale`'s widening
/// branch) — never a rounding decision, so — unlike `roundedDivMag` — it
/// does not need to be a Fable stub.
fn scaleUp(allocator: Allocator, coeff: *const Managed, shift: u32) BigDecimal.Error!Managed {
    var ten = try Managed.initSet(allocator, 10);
    defer ten.deinit();
    var p = try Managed.init(allocator);
    defer p.deinit();
    try p.pow(&ten, shift);
    var r = try Managed.init(allocator);
    errdefer r.deinit();
    try r.mul(coeff, &p);
    return r;
}

/// `hi_exp - lo_exp` as a `u32`, capped at `max_align_shift`. Asserts
/// `hi_exp >= lo_exp` (callers always pass the pair in that order).
fn alignShift(hi_exp: i32, lo_exp: i32) BigDecimal.Error!u32 {
    const diff: i64 = @as(i64, hi_exp) - @as(i64, lo_exp);
    std.debug.assert(diff >= 0);
    if (diff > BigDecimal.max_align_shift) return error.Overflow;
    return @intCast(diff);
}

/// **THE Fable-tier primitive.** Given nonnegative `num`/`den` (`den != 0`)
/// and the intended result sign, return `round(num/den)` as an exact
/// arbitrary-precision integer, using `mode` to resolve a nonzero
/// remainder — round-half-even and friends, generalized from
/// `root.zig`'s `divRoundMag` (which does exactly this on fixed-width
/// `i256` operands) to unbounded `std.math.big.int.Managed` operands.
///
/// Every primitive this needs already exists in std — this function's job
/// is composing them correctly, not inventing a new algorithm:
///   - `Managed.divTrunc(q, r, num, den)` — exact truncating division +
///     remainder (Knuth Algorithm D).
///   - Doubling the remainder (`Managed.add(r2, r, r)` or `shiftLeft(r2, r,
///     1)`) then `Const.order`/`orderAgainstScalar` to compare `2·remainder`
///     vs `den` for the exact half-way test. `Managed` grows its own limb
///     storage on demand, so — unlike `root.zig`'s `i256` version, which has
///     to write the comparison as `r >= d - r` specifically to dodge a
///     doubling-overflow case — there is no analogous overflow to guard
///     against here; `2·remainder` simply always fits.
///   - `Managed.addScalar(q, q, 1)` to bump the quotient by one on the
///     rounding decision; `q.isOdd()` for the `half_even` tie-break.
///
/// What's *not* free is getting every sign × mode × tie combination exactly
/// right — this is money-adjacent code where an off-by-one is a real
/// correctness bug, and it deserves the same exhaustive-KAT treatment as
/// `root.zig`'s "rounding truth table — all modes" test, generalized to
/// non-terminating arbitrary-precision quotients. See `div_kat_vectors` /
/// `rescale_kat_vectors` below (the live regression suite) and SPEC.md's
/// "BigDecimal — Fable worklist" section.
fn roundedDivMag(
    allocator: Allocator,
    num: *const Managed,
    den: *const Managed,
    result_neg: bool,
    mode: RoundingMode,
) Allocator.Error!Managed {
    // Exact truncating division: q = ⌊num/den⌋, r = num − q·den, both
    // nonnegative because `num`/`den` are magnitudes (callers pass abs values
    // and reapply the sign afterward). Knuth Algorithm D under the hood.
    var q = try Managed.init(allocator);
    errdefer q.deinit();
    var r = try Managed.init(allocator);
    defer r.deinit();
    try q.divTrunc(&r, num, den);

    // A zero remainder is exact — no rounding decision, every mode agrees.
    if (r.eqlZero()) return q;

    // Half-way test, exact integer math: compare 2·remainder against the
    // divisor. `.lt` = below half, `.eq` = an exact tie, `.gt` = above half.
    // Unlike root.zig's i256 `divRoundMag` — which writes the compare as
    // `r >= d − r` to dodge a doubling overflow — `Managed` grows its own
    // limbs, so 2·remainder always fits and the direct doubling is safe.
    var two_r = try Managed.init(allocator);
    defer two_r.deinit();
    try two_r.add(&r, &r);
    const half = two_r.order(den.*);

    // Mirrors root.zig `divRoundMag`'s switch exactly, mode-for-mode:
    //   half_up   bump on 2r >= d   (r >= d−r)          → half != .lt
    //   half_down bump on 2r >  d   (r >  d−r)          → half == .gt
    //   half_even above/below half decide; a tie rounds to even (bump iff q odd)
    //   up/down   unconditional; ceiling/floor sign-directed (q is a magnitude,
    //             so the eventual sign is `result_neg`).
    const bump = switch (mode) {
        .up => true,
        .down => false,
        .ceiling => !result_neg,
        .floor => result_neg,
        .half_up => half != .lt,
        .half_down => half == .gt,
        .half_even => switch (half) {
            .gt => true,
            .lt => false,
            .eq => q.isOdd(),
        },
    };
    if (bump) try q.addScalar(&q, 1);
    return q;
}

// ---------------------------------------------------------------------------
// Tests — exact ops (parse/format/add/sub/mul/compare/normalize/widen-rescale)
// ---------------------------------------------------------------------------

const testing = std.testing;
const talloc = testing.allocator;

fn expectStr(d: BigDecimal, want: []const u8) !void {
    const s = try d.toStringAlloc(talloc);
    defer talloc.free(s);
    try testing.expectEqualStrings(want, s);
}

/// Test shorthand: parse a known-good literal.
fn dec(s: []const u8) BigDecimal {
    return BigDecimal.parse(talloc, s) catch unreachable;
}

test "parse + format roundtrip" {
    var a = dec("0");
    defer a.deinit();
    try expectStr(a, "0");

    var b = dec("123");
    defer b.deinit();
    try expectStr(b, "123");

    var c = dec("-123.456");
    defer c.deinit();
    try expectStr(c, "-123.456");

    var d = dec("0.001");
    defer d.deinit();
    try expectStr(d, "0.001");

    // Trailing zeros are preserved (NOT trimmed) — distinguishes BigDecimal
    // from the fixed-scale Decimal.toString.
    var e = dec("1.50");
    defer e.deinit();
    try expectStr(e, "1.50");

    var f = dec("2.08e9");
    defer f.deinit();
    try expectStr(f, "2080000000");

    var g = dec("1.23e-4");
    defer g.deinit();
    try expectStr(g, "0.000123");
}

test "arbitrary precision exceeds the fixed-scale Decimal's i128 range" {
    // 40 nines followed by 40 more digits — far beyond i128's ~1.7e38
    // ceiling that bounds the fixed-scale Decimal.
    const huge = "9" ** 40 ++ "." ++ "1" ** 40;
    var d = dec(huge);
    defer d.deinit();
    try expectStr(d, huge);
}

test "parse rejects" {
    try testing.expectError(error.InvalidCharacter, BigDecimal.parse(talloc, ""));
    try testing.expectError(error.InvalidCharacter, BigDecimal.parse(talloc, "abc"));
    try testing.expectError(error.InvalidCharacter, BigDecimal.parse(talloc, "1.2.3"));
    try testing.expectError(error.InvalidCharacter, BigDecimal.parse(talloc, "1e"));
    try testing.expectError(error.InvalidCharacter, BigDecimal.parse(talloc, "--1"));
    try testing.expectError(error.InvalidCharacter, BigDecimal.parse(talloc, "."));
}

test "parse — literal exponent overflow is a clean error, not a trap" {
    // A 20-digit exponent literal is nowhere near representable as i32.
    try testing.expectError(error.Overflow, BigDecimal.parse(talloc, "1e99999999999999999999"));
}

test "isZero, negate, absVal" {
    var z = dec("0");
    defer z.deinit();
    try testing.expect(z.isZero());

    var a = dec("-2.5");
    defer a.deinit();
    a.negate();
    try expectStr(a, "2.5");
    a.negate();
    try expectStr(a, "-2.5");
    a.absVal();
    try expectStr(a, "2.5");
}

test "order and eql" {
    var a = dec("1.5");
    defer a.deinit();
    var b = dec("1.50");
    defer b.deinit();
    try testing.expect(try BigDecimal.eql(talloc, a, b)); // equal value, different scale
    var c = dec("1.6");
    defer c.deinit();
    try testing.expect((try BigDecimal.order(talloc, a, c)) == .lt);
    var d = dec("-1");
    defer d.deinit();
    try testing.expect((try BigDecimal.order(talloc, d, a)) == .lt);
}

test "normalize strips exact trailing zeros, adjusting exponent" {
    var a = dec("12.00");
    defer a.deinit();
    var n = try BigDecimal.normalize(talloc, a);
    defer n.deinit();
    try expectStr(n, "12");
    try testing.expectEqual(@as(i32, 0), n.exponent);

    var z = dec("0.000");
    defer z.deinit();
    var nz = try BigDecimal.normalize(talloc, z);
    defer nz.deinit();
    try testing.expect(nz.isZero()); // zero is left unchanged, not collapsed
}

test "rescale — widening precision is exact (no Fable stub involved)" {
    var a = dec("1.5");
    defer a.deinit();
    var r = try BigDecimal.rescale(talloc, a, -4, .half_even);
    defer r.deinit();
    try expectStr(r, "1.5000");

    // Identity (new_exponent == a.exponent).
    var r2 = try BigDecimal.rescale(talloc, a, a.exponent, .half_even);
    defer r2.deinit();
    try expectStr(r2, "1.5");

    // Zero at any exponent is exact in both directions.
    var z = dec("0");
    defer z.deinit();
    var zr = try BigDecimal.rescale(talloc, z, 5, .half_even);
    defer zr.deinit();
    try testing.expect(zr.isZero());
}

test "div — division-by-zero and zero-dividend short-circuits" {
    // Division-by-zero and the zero-dividend short-circuit both return
    // before ever reaching roundedDivMag — the exact error/zero paths that
    // bypass the rounding core entirely.
    var a = dec("5");
    defer a.deinit();
    var zero = dec("0");
    defer zero.deinit();
    try testing.expectError(error.DivisionByZero, BigDecimal.div(talloc, a, zero, 2, .half_even));

    var q = try BigDecimal.div(talloc, zero, a, 2, .half_even);
    defer q.deinit();
    try testing.expect(q.isZero());
}

// ---------------------------------------------------------------------------
// KAT — exact add/mul, from the IBM/Mike Cowlishaw General Decimal
// Arithmetic Testcases v2.62, "Reproduced with permission ... Copyright
// 1997, 2009 by International Business Machines Corporation"
// (https://speleotrove.com/decimal/dectest.html), files add.decTest /
// multiply.decTest. Test IDs kept for traceability to the source file.
//
// Only vectors with NO `Inexact`/`Rounded` flag in the source are used here:
// those flags reflect the *reference implementation's* fixed context
// precision (9 significant digits in these files), which this
// arbitrary-precision `add`/`mul` has no equivalent of — an unflagged
// vector's expected value is the mathematically exact result, which is
// exactly what unbounded add/mul must reproduce. (Zero-result vectors, e.g.
// multiply.decTest's `-1.20 * 0 -> -0.00`, are also excluded: this module's
// `toStringAlloc` deliberately drops the exponent/sign on a zero result —
// see its doc comment — so it cannot reproduce GDA's signed/scaled zero
// display, only the value zero.)
// ---------------------------------------------------------------------------

test "KAT: add.decTest exact vectors" {
    const Case = struct { a: []const u8, b: []const u8, want: []const u8, id: []const u8 };
    const cases = [_]Case{
        .{ .id = "addx001", .a = "1", .b = "1", .want = "2" },
        .{ .id = "addx002", .a = "2", .b = "3", .want = "5" },
        .{ .id = "addx003", .a = "5.75", .b = "3.3", .want = "9.05" },
        .{ .id = "addx004", .a = "5", .b = "-3", .want = "2" },
        .{ .id = "addx005", .a = "-5", .b = "-3", .want = "-8" },
        .{ .id = "addx006", .a = "-7", .b = "2.5", .want = "-4.5" },
        .{ .id = "addx007", .a = "0.7", .b = "0.3", .want = "1.0" },
        .{ .id = "addx008", .a = "1.25", .b = "1.25", .want = "2.50" },
        .{ .id = "addx009", .a = "1.23456789", .b = "1.00000000", .want = "2.23456789" },
        .{ .id = "addx010", .a = "1.23456789", .b = "1.00000011", .want = "2.23456800" },
    };
    for (cases) |c| {
        var a = try BigDecimal.parse(talloc, c.a);
        defer a.deinit();
        var b = try BigDecimal.parse(talloc, c.b);
        defer b.deinit();
        var got = try BigDecimal.add(talloc, a, b);
        defer got.deinit();
        expectStr(got, c.want) catch |err| {
            std.debug.print("KAT {s} (add.decTest) failed\n", .{c.id});
            return err;
        };
    }
}

test "KAT: multiply.decTest exact vectors" {
    const Case = struct { a: []const u8, b: []const u8, want: []const u8, id: []const u8 };
    const cases = [_]Case{
        .{ .id = "mulx000", .a = "2", .b = "2", .want = "4" },
        .{ .id = "mulx001", .a = "2", .b = "3", .want = "6" },
        .{ .id = "mulx002", .a = "5", .b = "1", .want = "5" },
        .{ .id = "mulx003", .a = "5", .b = "2", .want = "10" },
        .{ .id = "mulx004", .a = "1.20", .b = "2", .want = "2.40" },
        .{ .id = "mulx006", .a = "1.20", .b = "-2", .want = "-2.40" },
        .{ .id = "mulx007", .a = "-1.20", .b = "2", .want = "-2.40" },
        .{ .id = "mulx009", .a = "-1.20", .b = "-2", .want = "2.40" },
        .{ .id = "mulx010", .a = "5.09", .b = "7.1", .want = "36.139" },
        .{ .id = "mulx011", .a = "2.5", .b = "4", .want = "10.0" },
        .{ .id = "mulx012", .a = "2.50", .b = "4", .want = "10.00" },
    };
    for (cases) |c| {
        var a = try BigDecimal.parse(talloc, c.a);
        defer a.deinit();
        var b = try BigDecimal.parse(talloc, c.b);
        defer b.deinit();
        var got = try BigDecimal.mul(talloc, a, b);
        defer got.deinit();
        expectStr(got, c.want) catch |err| {
            std.debug.print("KAT {s} (multiply.decTest) failed\n", .{c.id});
            return err;
        };
    }
}

test "KAT: quantize.decTest widening vectors (exact — no stub involved)" {
    const Case = struct { a: []const u8, exponent: i32, want: []const u8, id: []const u8 };
    // Only the *widening* (new_exponent <= a.exponent) vectors from
    // quantize.decTest: these exercise rescale's fully-implemented exact
    // branch. Narrowing vectors (e.g. quax012) are in the roundedDivMag KAT
    // block below instead.
    const cases = [_]Case{
        .{ .id = "quax007", .a = "0.1", .exponent = -1, .want = "0.1" },
        .{ .id = "quax008", .a = "0.1", .exponent = -2, .want = "0.10" },
        .{ .id = "quax014", .a = "0.9", .exponent = -2, .want = "0.90" },
    };
    for (cases) |c| {
        var a = try BigDecimal.parse(talloc, c.a);
        defer a.deinit();
        var got = try BigDecimal.rescale(talloc, a, c.exponent, .half_up);
        defer got.deinit();
        expectStr(got, c.want) catch |err| {
            std.debug.print("KAT {s} (quantize.decTest) failed\n", .{c.id});
            return err;
        };
    }
}

// ---------------------------------------------------------------------------
// Fable worklist — KAT vectors for roundedDivMag, exercised via div/rescale.
//
// Provenance: same IBM/Mike Cowlishaw decTest v2.62 suite as above; files
// divide.decTest, quantize.decTest and rounding.decTest. The rounding.decTest
// vectors originally test a fixed-context-precision `add` (5 significant
// digits) under each rounding mode; they're re-expressed here as a single
// `rescale` call on the already-summed value (e.g. `radx194`'s
// `add(12345, 0.5)` under `half_even` becomes `rescale("12345.5", 0,
// .half_even)`) since BigDecimal has no context-precision concept — see
// SPEC.md. Test IDs kept for traceability to the source file/testcase.
//
// These all reach `roundedDivMag` (now implemented): a live regression suite
// for the sign-aware arbitrary-precision rounding core.
// ---------------------------------------------------------------------------

const DivCase = struct { a: []const u8, b: []const u8, scale: i32, mode: RoundingMode, want: []const u8, id: []const u8 };

/// GDA's context rounding for divide.decTest is `half_up`.
pub const div_kat_vectors = [_]DivCase{
    .{ .id = "divx001", .a = "1", .b = "1", .scale = 0, .mode = .half_up, .want = "1" },
    .{ .id = "divx003", .a = "1", .b = "2", .scale = 1, .mode = .half_up, .want = "0.5" },
    .{ .id = "divx007", .a = "1", .b = "3", .scale = 9, .mode = .half_up, .want = "0.333333333" },
    .{ .id = "divx008", .a = "2", .b = "3", .scale = 9, .mode = .half_up, .want = "0.666666667" },
    .{ .id = "divx021", .a = "5", .b = "2", .scale = 1, .mode = .half_up, .want = "2.5" },
    .{ .id = "divx028", .a = "5", .b = "0.20", .scale = 0, .mode = .half_up, .want = "25" },
    // Exact half-way ties (2r == d) under half_up — the audit-F1 gap: the vectors
    // above are all terminating or non-tie, so the half_up bump-on-tie branch had
    // no positive control (a mutation skipping the bump passed the suite clean).
    .{ .id = "divTIE1", .a = "5", .b = "2", .scale = 0, .mode = .half_up, .want = "3" }, // 2.5 -> 3
    .{ .id = "divTIE2", .a = "1", .b = "2", .scale = 0, .mode = .half_up, .want = "1" }, // 0.5 -> 1
    .{ .id = "divTIE3", .a = "7", .b = "2", .scale = 0, .mode = .half_up, .want = "4" }, // 3.5 -> 4
};

const RescaleCase = struct { a: []const u8, exponent: i32, mode: RoundingMode, want: []const u8, id: []const u8 };

/// quax012 is a genuine narrowing quantize; the radx* vectors are the
/// rounding.decTest half_even-tie-break block, recombined as described
/// above (source: `add 12345 0.5 -> 12346` etc. under `rounding: half_even`).
pub const rescale_kat_vectors = [_]RescaleCase{
    .{ .id = "quax012", .a = "0.9", .exponent = 0, .mode = .half_up, .want = "1" },
    .{ .id = "radx194", .a = "12345.5", .exponent = 0, .mode = .half_even, .want = "12346" }, // tie, odd -> bumps to even
    .{ .id = "radx186", .a = "12346.5", .exponent = 0, .mode = .half_even, .want = "12346" }, // tie, even -> stays
    .{ .id = "radx190", .a = "12345.4", .exponent = 0, .mode = .half_even, .want = "12345" }, // below tie -> down
    .{ .id = "radx199", .a = "12345.6", .exponent = 0, .mode = .half_even, .want = "12346" }, // above tie -> up
};

test "Fable worklist: div/rescale KAT (roundedDivMag)" {
    for (div_kat_vectors) |c| {
        var a = try BigDecimal.parse(talloc, c.a);
        defer a.deinit();
        var b = try BigDecimal.parse(talloc, c.b);
        defer b.deinit();
        var got = try BigDecimal.div(talloc, a, b, c.scale, c.mode);
        defer got.deinit();
        expectStr(got, c.want) catch |err| {
            std.debug.print("KAT {s} (divide.decTest) failed\n", .{c.id});
            return err;
        };
    }
    for (rescale_kat_vectors) |c| {
        var a = try BigDecimal.parse(talloc, c.a);
        defer a.deinit();
        var got = try BigDecimal.rescale(talloc, a, c.exponent, c.mode);
        defer got.deinit();
        expectStr(got, c.want) catch |err| {
            std.debug.print("KAT {s} (rounding/quantize.decTest) failed\n", .{c.id});
            return err;
        };
    }
}

// ── fuzz: arbitrary-precision decimal string parse, never panics ───────────
//
// Same untrusted-text boundary as `Decimal.parse`, but unbounded in
// significand width — a hostile digit run of thousands of characters is
// exactly the shape this arena-backed parser has to reject or accept
// without a fixed-width assumption tripping it up.

test "fuzz: parse never panics on arbitrary text" {
    try testing.fuzz({}, fuzzParse, .{});
}

fn fuzzParse(_: void, smith: *std.testing.Smith) !void {
    const alphabet = "0123456789+-.eE";
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    for (buf[0..len]) |*c| {
        if (smith.boolWeighted(1, 4)) c.* = alphabet[c.* % alphabet.len];
    }
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    _ = BigDecimal.parse(arena.allocator(), buf[0..len]) catch return;
}
