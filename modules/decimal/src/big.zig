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
//! ## Operation surface beyond the rounding core
//!
//! `remainder`, `min`/`max`, `precision`, `signum`, `scaleByPowerOfTen`,
//! `stripTrailingZeros`, `sqrt` and `pow` fill in the rest of the
//! `java.math.BigDecimal` / GDA surface. The first six are exact and need no
//! rounding decision at all. The last two are the only operations here that
//! can make a value *grow*, and they are the only ones with an explicit digit
//! budget (`max_result_digits`) checked before allocating — see that
//! constant's doc comment for why `pow` in particular cannot be left
//! unbounded. `pow` is deliberately integer-exponent-only; the general GDA
//! `power` needs `exp`/`ln` on bignums and is out of scope (stated in `pow`'s
//! doc comment).
//!
//! Provenance: original scaffold by the zig-libs authors (MIT), modeled
//! after Java `BigDecimal` / IBM General Decimal Arithmetic (design
//! reference only). The KAT vectors wired in below are drawn from the actual
//! IBM/Mike Cowlishaw `decTest` suite v2.62 (add.decTest / multiply.decTest /
//! quantize.decTest / rounding.decTest inline; remainder / min / max /
//! squareroot / power as `src/testdata/*.vec`), "Reproduced with permission
//! ... Copyright 1997, 2009 by International Business Machines Corporation"
//! per https://speleotrove.com/decimal/dectest.html — see per-block
//! provenance comments below, each vector file's header, and NOTICE.

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

    /// Number of significant decimal digits in the coefficient — Java
    /// `BigDecimal.precision()` / GDA's "number of digits". Zero has
    /// precision **1** (Java and GDA both treat `0`'s coefficient as one
    /// digit), not 0. The sign and the exponent play no part: `-0.00123`
    /// (coefficient `-123`) has precision 3.
    ///
    /// Exact, via `std.math.big.int`'s base-10 logarithm (`log10Alloc`) —
    /// not `sizeInBaseUpperBound`, which is only an upper bound. The scratch
    /// buffer it needs is why this takes an allocator and can fail.
    pub fn precision(self: BigDecimal, allocator: Allocator) Allocator.Error!u32 {
        if (self.coeff.eqlZero()) return 1;
        // Borrow the limbs as a positive Const: log10 asserts a positive,
        // nonzero operand, and cloning just to drop a sign bit would be
        // wasteful on a large coefficient.
        const mag: bigint.Const = .{ .limbs = self.coeff.limbs[0..self.coeff.len()], .positive = true };
        return @intCast(try mag.log10Alloc(allocator) + 1);
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

    /// Java `BigDecimal.stripTrailingZeros`. This is `normalize` under its
    /// other name — same operation, same semantics, no second implementation:
    /// remove exact trailing zero digits from the coefficient and raise the
    /// exponent to compensate, leaving the value unchanged. Both names are
    /// kept because callers arriving from Java look for one and callers
    /// arriving from GDA (where the operation is `reduce`/`normalize`) look
    /// for the other.
    pub const stripTrailingZeros = normalize;

    // -----------------------------------------------------------------
    // Accessors — no arithmetic, no rounding decision.
    // -----------------------------------------------------------------

    /// Java `BigDecimal.signum` / GDA's sign: `-1`, `0`, `+1`. Reads the
    /// coefficient's sign only — the exponent cannot change a sign, and a
    /// zero coefficient is `0` whatever its stored sign bit (see `negate`).
    pub fn signum(self: BigDecimal) i8 {
        return switch (self.coeff.toConst().orderAgainstScalar(0)) {
            .lt => -1,
            .eq => 0,
            .gt => 1,
        };
    }

    /// Java `BigDecimal.scaleByPowerOfTen` — multiply by `10^n` by adjusting
    /// the exponent alone. Exact and free: the coefficient is untouched, so
    /// no digits are gained or lost and no rounding decision arises. Only the
    /// resulting exponent can fail (`error.Overflow` past `i32`).
    pub fn scaleByPowerOfTen(a: BigDecimal, n: i32) Error!BigDecimal {
        const exp64: i64 = @as(i64, a.exponent) + @as(i64, n);
        if (exp64 > std.math.maxInt(i32) or exp64 < std.math.minInt(i32)) return error.Overflow;
        var r = try a.clone();
        errdefer r.coeff.deinit();
        r.exponent = @intCast(exp64);
        return r;
    }

    // -----------------------------------------------------------------
    // remainder / min / max — exact, no rounding decision.
    // -----------------------------------------------------------------

    /// GDA `remainder` / Java `BigDecimal.remainder`: the remainder of the
    /// **truncated** integer division, `a − trunc(a/b) × b`.
    ///
    /// The result takes the sign of the **dividend**, never the divisor —
    /// `-2.4 rem 1 = -0.4` while `2.4 rem -1 = 0.4` (decTest remx011/remx012).
    /// The result exponent is `min(a.exponent, b.exponent)`, the GDA rule, so
    /// `5 rem 2.000` is `1.000` and not `1`.
    ///
    /// Exact, and therefore takes no rounding mode: both operands are widened
    /// to a common exponent (exact — pure multiplication) and the remainder of
    /// an exact integer division is exact.
    ///
    /// Deliberate divergence from GDA, stated so it isn't mistaken for a bug:
    /// GDA raises `Division_impossible` when the *integer quotient* would need
    /// more digits than the context precision. This module has no context
    /// precision, so it just returns the exact answer. Those decTest cases are
    /// skipped rather than asserted — see the vector file header.
    pub fn remainder(allocator: Allocator, a: BigDecimal, b: BigDecimal) DivError!BigDecimal {
        if (b.isZero()) return error.DivisionByZero;
        const lo_exp = @min(a.exponent, b.exponent);

        var an = if (a.exponent == lo_exp)
            try a.coeff.clone()
        else
            try scaleUp(allocator, &a.coeff, try alignShift(a.exponent, lo_exp));
        defer an.deinit();
        var bn = if (b.exponent == lo_exp)
            try b.coeff.clone()
        else
            try scaleUp(allocator, &b.coeff, try alignShift(b.exponent, lo_exp));
        defer bn.deinit();

        var q = try Managed.init(allocator);
        defer q.deinit();
        var r = try Managed.init(allocator);
        errdefer r.deinit();
        // Truncating division: the remainder carries the dividend's sign,
        // which is exactly the GDA/Java rule. (`divFloor` would instead take
        // the divisor's sign — that is `modulo`, a different operation, and
        // remx011/remx012 tell the two apart.)
        try q.divTrunc(&r, &an, &bn);
        return .{ .coeff = r, .exponent = lo_exp };
    }

    /// GDA `max` / Java `BigDecimal.max` — the numerically larger operand,
    /// returned as an independent clone the caller owns.
    ///
    /// When the operands are numerically *equal* but differ in scale (`1.0`
    /// vs `1`) GDA still has to name one, and the rule is not "either will
    /// do": ties go to the operand with the **larger** exponent when the value
    /// is positive and the **smaller** exponent when it is negative — i.e.
    /// always the one whose representation is "further from zero" in scale
    /// terms (decTest maxx282/maxx283). Signs never actually differ on a
    /// numeric tie except for zeros, where GDA prefers `+0`.
    pub fn max(allocator: Allocator, a: BigDecimal, b: BigDecimal) Error!BigDecimal {
        return if (try pickA(allocator, a, b, true)) a.clone() else b.clone();
    }

    /// GDA `min` / Java `BigDecimal.min` — the mirror of `max`, including the
    /// tie rule: equal values go to the **smaller** exponent when positive and
    /// the **larger** exponent when negative.
    pub fn min(allocator: Allocator, a: BigDecimal, b: BigDecimal) Error!BigDecimal {
        return if (try pickA(allocator, a, b, false)) a.clone() else b.clone();
    }

    // -----------------------------------------------------------------
    // sqrt / pow — the two operations that can GROW a value without bound,
    // and therefore the two with explicit digit budgets. See
    // `max_result_digits`.
    // -----------------------------------------------------------------

    /// Safety ceiling on the number of significant decimal digits `sqrt` and
    /// `pow` will *produce*. Like `max_align_shift` this is a pragmatic guard
    /// and **not** a General Decimal Arithmetic rule — GDA bounds results by
    /// the context precision, which this module does not have. It exists
    /// because `pow` in particular turns a small input into an unbounded
    /// output: `1.1 ^ 1000000007` (a real case in the decTest `power` file)
    /// has on the order of 10^8 decimal digits, and computing it would exhaust
    /// memory long before returning. The budget is checked **before** any
    /// allocation, from the operand's digit count, never after the fact.
    ///
    /// 100_000 digits is a ~42KB integer — orders of magnitude past any
    /// financial or scientific use of this module, and small enough that a
    /// mistake costs a fast error instead of the machine.
    pub const max_result_digits: u32 = 100_000;

    pub const SqrtError = Error || error{ NegativeOperand, PrecisionTooLarge };

    /// GDA `square-root`: the square root of `a` **correctly rounded to
    /// `prec` significant digits**.
    ///
    /// "Correctly rounded" is the whole specification and it is *not* the same
    /// as "iterate Newton until the digits stop moving" — that gives a result
    /// good to within an ulp, which is wrong at every point where the true
    /// root sits near a rounding boundary. What is computed here instead is
    /// exact: `⌊√N⌋` on an integer scaled up by `10^(2(prec+1))`
    /// (`std.math.big.int`'s `sqrt`, Brent–Zimmermann SqrtInt), and then a
    /// single exact integer comparison of `4N` against `((2Q+1)·10^drop)²` to
    /// decide which side of the half-way point the true root lies on. No
    /// floating point, no iteration-to-fixpoint, no ulp slack.
    ///
    /// Exponent rules, straight from GDA:
    ///   * If the root is **exact** and fits in `prec` digits, the result
    ///     carries the *ideal exponent* `⌊operand exponent / 2⌋` — which is
    ///     why `√1.00` is `1.0` and not `1`, and `√4.00` is `2.0`.
    ///   * Otherwise the result has exactly `prec` significant digits.
    ///   * `√0` is zero at the ideal exponent (`√0E+5` = `0E+2`).
    ///
    /// `mode` is a generalisation: GDA fixes square-root at round-half-even.
    /// A tie is possible only when the scaled root is an exact integer ending
    /// in `5·10^(drop−1)`, so the mode is almost never observable — it is
    /// exposed for consistency with the rest of the module, and the decTest
    /// blocks are replayed under whichever mode their `rounding:` directive
    /// names.
    ///
    /// `error.NegativeOperand` on a negative `a` (GDA's `Invalid_operation`);
    /// `error.PrecisionTooLarge` when `prec` exceeds `max_result_digits`.
    pub fn sqrt(allocator: Allocator, a: BigDecimal, prec: u32, mode: RoundingMode) SqrtError!BigDecimal {
        if (prec == 0 or prec > max_result_digits) return error.PrecisionTooLarge;
        if (!a.coeff.isPositive() and !a.coeff.eqlZero()) return error.NegativeOperand;

        // Ideal exponent: e = 2m + t with t ∈ {0,1}, so √(c·10^e) =
        // √(c·10^t) · 10^m and the integer part of the work is √(c·10^t).
        const m: i64 = @divFloor(@as(i64, a.exponent), 2);
        const t: u32 = @intCast(@as(i64, a.exponent) - 2 * m);

        if (a.isZero()) {
            var z = try Managed.init(allocator);
            errdefer z.deinit();
            if (m > std.math.maxInt(i32) or m < std.math.minInt(i32)) return error.Overflow;
            return .{ .coeff = z, .exponent = @intCast(m) };
        }

        // Budget check before scaling: the working integer is
        // c·10^(t + 2(prec+1)), whose digit count is bounded below.
        const c_digits: u64 = try a.precision(allocator);
        if (c_digits > max_result_digits) return error.PrecisionTooLarge;

        var n0 = try scaleUp(allocator, &a.coeff, t);
        defer n0.deinit();

        // Exact-root fast path — and it must be exact in the strict sense
        // (I² == N), not "close enough": a mis-detected exact root would emit
        // the ideal exponent for an inexact value.
        {
            var exact_root = try Managed.init(allocator);
            errdefer exact_root.deinit();
            exact_root.sqrt(&n0) catch |err| switch (err) {
                error.SqrtOfNegativeNumber => unreachable, // sign checked above
                error.OutOfMemory => return error.OutOfMemory,
            };
            var sq = try Managed.init(allocator);
            defer sq.deinit();
            try sq.mul(&exact_root, &exact_root);
            const is_exact = sq.toConst().order(n0.toConst()) == .eq;
            const fits = is_exact and
                (try (BigDecimal{ .coeff = exact_root, .exponent = 0 }).precision(allocator)) <= prec;
            if (fits) {
                if (m > std.math.maxInt(i32) or m < std.math.minInt(i32)) return error.Overflow;
                return .{ .coeff = exact_root, .exponent = @intCast(m) };
            }
            exact_root.deinit();
        }

        // Rounding path. Gain k = prec+1 decimal digits of root by scaling the
        // radicand by 10^(2k); √(N·10^2k) = √N·10^k, so ⌊√·⌋ then has at least
        // k+1 ≥ prec+2 digits — enough to place the half-way point exactly.
        const k: u32 = prec + 1;
        var n = try scaleUp(allocator, &n0, 2 * k);
        defer n.deinit();

        var root = try Managed.init(allocator);
        defer root.deinit();
        root.sqrt(&n) catch |err| switch (err) {
            error.SqrtOfNegativeNumber => unreachable,
            error.OutOfMemory => return error.OutOfMemory,
        };

        const d: u32 = try (BigDecimal{ .coeff = root, .exponent = 0 }).precision(allocator);
        std.debug.assert(d > prec);
        const drop: u32 = d - prec;

        var ten_drop = try pow10(allocator, drop);
        defer ten_drop.deinit();
        var q = try Managed.init(allocator);
        errdefer q.deinit();
        {
            var rem = try Managed.init(allocator);
            defer rem.deinit();
            try q.divTrunc(&rem, &root, &ten_drop);
        }

        // Exact half-way test on the *true* root, not on ⌊√N⌋: the midpoint
        // between Q·10^drop and (Q+1)·10^drop is (2Q+1)·10^drop/2, so compare
        // √N against it by comparing 4N against ((2Q+1)·10^drop)² — all
        // integer, no rounding of the comparison itself.
        const half: std.math.Order = blk: {
            var mid = try Managed.init(allocator);
            defer mid.deinit();
            try mid.add(&q, &q);
            try mid.addScalar(&mid, 1);
            try mid.mul(&mid, &ten_drop);
            try mid.mul(&mid, &mid);
            var four_n = try Managed.init(allocator);
            defer four_n.deinit();
            try four_n.add(&n, &n);
            try four_n.add(&four_n, &four_n);
            break :blk four_n.toConst().order(mid.toConst());
        };
        if (roundBump(mode, half, q.isOdd(), false)) try q.addScalar(&q, 1);

        var exp64: i64 = m - @as(i64, k) + @as(i64, drop);
        // Rounding up can carry into an extra digit (…999 → 1000…): renormalise
        // back to `prec` digits by shedding the trailing zero into the exponent.
        if ((try (BigDecimal{ .coeff = q, .exponent = 0 }).precision(allocator)) > prec) {
            var ten = try Managed.initSet(allocator, 10);
            defer ten.deinit();
            var rem = try Managed.init(allocator);
            defer rem.deinit();
            var nq = try Managed.init(allocator);
            defer nq.deinit();
            try nq.divTrunc(&rem, &q, &ten);
            std.debug.assert(rem.eqlZero());
            q.swap(&nq);
            exp64 += 1;
        }
        if (exp64 > std.math.maxInt(i32) or exp64 < std.math.minInt(i32)) return error.Overflow;
        return .{ .coeff = q, .exponent = @intCast(exp64) };
    }

    pub const PowError = Error || error{ NegativeExponent, ResultTooLarge };

    /// `a^n` for a **non-negative integer** `n`, computed exactly — the
    /// `java.math.BigDecimal.pow(int)` contract: the result's exponent is
    /// `a.exponent × n` and no digit is discarded (`1.1^2` is `1.21`, not
    /// `1.2`). `a^0` is `1` for every `a`, including zero, again as Java.
    ///
    /// **Scope boundary.** GDA's general `power` also admits non-integer and
    /// negative exponents, which require `exp`/`ln` on arbitrary-precision
    /// decimals — a transcendental-function project in its own right, not a
    /// wrapper around `std.math.big.int.Managed.pow`. This function
    /// deliberately implements only the integer case; a negative `n` is
    /// `error.NegativeExponent` rather than a silently wrong answer (Java
    /// throws `ArithmeticException` in the same situation).
    ///
    /// **Memory.** This is the one operation whose result grows multiplicatively
    /// with an argument, so the digit budget is not optional: the result has at
    /// most `precision(a) × n` digits, and that product is checked against
    /// `max_result_digits` **before anything is allocated**. Without it,
    /// `pow("1.1", 1000000007)` — a real decTest case — asks for a
    /// ~10^8-digit number and takes the machine down with it.
    pub fn pow(allocator: Allocator, a: BigDecimal, n: i32) PowError!BigDecimal {
        if (n < 0) return error.NegativeExponent;
        const e: u32 = @intCast(n);
        if (e == 0) return .{ .coeff = try Managed.initSet(allocator, 1), .exponent = 0 };
        if (a.isZero()) return .{ .coeff = try Managed.init(allocator), .exponent = 0 };

        // Budget first, allocation second.
        const digits: u64 = try a.precision(allocator);
        if (digits * @as(u64, e) > max_result_digits) return error.ResultTooLarge;

        const exp64: i64 = @as(i64, a.exponent) * @as(i64, e);
        if (exp64 > std.math.maxInt(i32) or exp64 < std.math.minInt(i32)) return error.Overflow;

        var r = try Managed.init(allocator);
        errdefer r.deinit();
        try r.pow(&a.coeff, e);
        return .{ .coeff = r, .exponent = @intCast(exp64) };
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
    var p = try pow10(allocator, shift);
    defer p.deinit();
    var r = try Managed.init(allocator);
    errdefer r.deinit();
    try r.mul(coeff, &p);
    return r;
}

/// `10^k` as an exact arbitrary-precision integer. `k` is bounded by every
/// caller (`max_align_shift` for alignment, `max_result_digits` for
/// `sqrt`/`pow`) before it gets here.
fn pow10(allocator: Allocator, k: u32) Allocator.Error!Managed {
    var ten = try Managed.initSet(allocator, 10);
    defer ten.deinit();
    var r = try Managed.init(allocator);
    errdefer r.deinit();
    try r.pow(&ten, k);
    return r;
}

/// GDA `min`/`max` operand selection: returns `true` when `a` is the answer.
///
/// The numeric comparison is the easy half. The half worth writing down is
/// the tie: when `a` and `b` are numerically equal but stored at different
/// exponents, GDA still names exactly one of them, and which one depends on
/// the sign. For `max`, a positive tie picks the larger exponent and a
/// negative tie the smaller (decTest maxx282/maxx283 and the `-0`/`-0.0`
/// block); `min` mirrors both. Signs can only differ on a numeric tie when
/// both operands are zero, where GDA prefers the positive one.
fn pickA(allocator: Allocator, a: BigDecimal, b: BigDecimal, want_max: bool) BigDecimal.Error!bool {
    switch (try BigDecimal.order(allocator, a, b)) {
        .gt => return want_max,
        .lt => return !want_max,
        .eq => {},
    }
    const a_neg = a.signum() < 0 or (a.isZero() and !a.coeff.isPositive());
    const b_neg = b.signum() < 0 or (b.isZero() and !b.coeff.isPositive());
    if (a_neg != b_neg) return if (want_max) !a_neg else a_neg;
    // Same sign, equal value: the exponent decides, and the sign flips which
    // way. `max` of two positives keeps the larger exponent but `max` of two
    // negatives keeps the smaller one (decTest maxx036 vs maxx282), and `min`
    // mirrors both (mnmx417: `min(-0.100, -0.10)` is `-0.10`).
    return if (a_neg)
        (a.exponent <= b.exponent) == want_max
    else
        (a.exponent >= b.exponent) == want_max;
}

/// The one rounding-mode judgment call in the module, factored out of
/// `roundedDivMag` so `sqrt` decides ties by exactly the same rule rather
/// than growing a second, subtly different copy of this switch.
///
///   `half`        `2·remainder` compared against the divisor — `.lt` below
///                 the half-way point, `.eq` an exact tie, `.gt` above it.
///                 (For `sqrt` it is the equivalent exact comparison of the
///                 true root against the midpoint.)
///   `q_odd`       parity of the truncated quotient, for the `half_even`
///                 tie-break.
///   `result_neg`  sign the result will eventually carry — the directed modes
///                 `ceiling`/`floor` are the only ones that depend on it.
///
/// Callers must only reach this with a **nonzero** discarded remainder; an
/// exact result needs no decision and every mode agrees on it.
fn roundBump(mode: RoundingMode, half: std.math.Order, q_odd: bool, result_neg: bool) bool {
    return switch (mode) {
        .up => true,
        .down => false,
        .ceiling => !result_neg,
        .floor => result_neg,
        .half_up => half != .lt,
        .half_down => half == .gt,
        .half_even => switch (half) {
            .gt => true,
            .lt => false,
            .eq => q_odd,
        },
    };
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

    // `roundBump` mirrors root.zig `divRoundMag`'s switch exactly, mode-for-mode:
    //   half_up   bump on 2r >= d   (r >= d−r)          → half != .lt
    //   half_down bump on 2r >  d   (r >  d−r)          → half == .gt
    //   half_even above/below half decide; a tie rounds to even (bump iff q odd)
    //   up/down   unconditional; ceiling/floor sign-directed (q is a magnitude,
    //             so the eventual sign is `result_neg`).
    if (roundBump(mode, half, q.isOdd(), result_neg)) try q.addScalar(&q, 1);
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

test "add: max_align_shift is exactly 1_000_000, not merely 'the configured value' (F4)" {
    // F4 (2026-08-11 re-audit): `max_align_shift` is the module's only DoS
    // guard on the exponent-alignment path, reachable straight from `parse`
    // (a hostile/typo'd exponent needs no other gate before it drives `add`),
    // and nothing referenced the delivered literal — a 9x raise to
    // `9_000_000` passed `test-decimal` clean. This test writes the boundary
    // as literals (1_000_000 / 1_000_001), not `BigDecimal.max_align_shift`,
    // so a change to the constant moves these numbers out from under the
    // test instead of moving with it.
    var a = try BigDecimal.parse(talloc, "1E1000000"); // exponent = 1_000_000
    defer a.deinit();
    var b = try BigDecimal.parse(talloc, "1"); // exponent = 0
    defer b.deinit();

    // Exactly at the ceiling: succeeds (the guard, not merely the constant,
    // must let this through — see the M1 mutation note in the audit log).
    var sum = try BigDecimal.add(talloc, a, b);
    defer sum.deinit();

    var a2 = try BigDecimal.parse(talloc, "1E1000001"); // exponent = 1_000_001
    defer a2.deinit();
    // One past the ceiling: refused before any 10^1_000_001 integer is
    // materialised, not silently allowed through.
    try testing.expectError(error.Overflow, BigDecimal.add(talloc, a2, b));
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

// ---------------------------------------------------------------------------
// Accessors, remainder, min/max — unit tests. The decTest conformance tables
// follow below.
// ---------------------------------------------------------------------------

test "precision — significant digits, exactly at the powers of ten" {
    const cases = [_]struct { s: []const u8, want: u32 }{
        .{ .s = "0", .want = 1 }, // Java/GDA: zero has one digit, not zero
        .{ .s = "0.000", .want = 1 },
        .{ .s = "1", .want = 1 },
        .{ .s = "9", .want = 1 },
        .{ .s = "10", .want = 2 },
        .{ .s = "99", .want = 2 },
        .{ .s = "100", .want = 3 },
        .{ .s = "999", .want = 3 },
        .{ .s = "1000", .want = 4 },
        .{ .s = "1001", .want = 4 },
        // Scale and sign are irrelevant — only the coefficient counts.
        .{ .s = "-0.00123", .want = 3 },
        .{ .s = "1.2300", .want = 5 },
        .{ .s = "1e100", .want = 1 },
        .{ .s = "9" ** 100, .want = 100 },
        .{ .s = "1" ++ "0" ** 200, .want = 201 },
    };
    for (cases) |c| {
        var d = dec(c.s);
        defer d.deinit();
        try testing.expectEqual(c.want, try d.precision(talloc));
    }
}

test "signum" {
    var a = dec("-0.001");
    defer a.deinit();
    try testing.expectEqual(@as(i8, -1), a.signum());
    var b = dec("0.000");
    defer b.deinit();
    try testing.expectEqual(@as(i8, 0), b.signum());
    var c = dec("1e-400");
    defer c.deinit();
    try testing.expectEqual(@as(i8, 1), c.signum());
    // A negated zero is still zero — the sign bit does not make it negative.
    b.negate();
    try testing.expectEqual(@as(i8, 0), b.signum());
}

test "scaleByPowerOfTen — exponent-only, exact, overflow is typed" {
    var a = dec("1.23");
    defer a.deinit();
    var up = try BigDecimal.scaleByPowerOfTen(a, 3);
    defer up.deinit();
    try expectStr(up, "1230");
    try testing.expectEqual(@as(i32, 1), up.exponent); // coefficient untouched
    var down = try BigDecimal.scaleByPowerOfTen(a, -3);
    defer down.deinit();
    try expectStr(down, "0.00123");

    var edge = dec("5");
    defer edge.deinit();
    edge.exponent = std.math.maxInt(i32) - 1;
    try testing.expectError(error.Overflow, BigDecimal.scaleByPowerOfTen(edge, 5));
}

test "stripTrailingZeros is normalize, not a second implementation" {
    // Same function value, so there is no way for the two to drift apart.
    try testing.expectEqual(
        @intFromPtr(&BigDecimal.normalize),
        @intFromPtr(&BigDecimal.stripTrailingZeros),
    );
    var a = dec("600.0");
    defer a.deinit();
    var s = try BigDecimal.stripTrailingZeros(talloc, a);
    defer s.deinit();
    try expectStr(s, "600");
    try testing.expectEqual(@as(i32, 2), s.exponent); // Java prints this as 6E+2
}

test "remainder — sign follows the dividend, exponent is min(ea, eb)" {
    // The two mutations this pins down: taking the divisor's sign (that is
    // `modulo`, not `remainder`), and using the dividend's exponent alone.
    const cases = [_]struct { a: []const u8, b: []const u8, want: []const u8, exp: i32 }{
        .{ .a = "2.4", .b = "1", .want = "0.4", .exp = -1 },
        .{ .a = "2.4", .b = "-1", .want = "0.4", .exp = -1 }, // divisor sign ignored
        .{ .a = "-2.4", .b = "1", .want = "-0.4", .exp = -1 }, // dividend sign kept
        .{ .a = "-2.4", .b = "-1", .want = "-0.4", .exp = -1 },
        .{ .a = "5", .b = "2.000", .want = "1.000", .exp = -3 }, // divisor's finer scale wins
        .{ .a = "2.400", .b = "2", .want = "0.400", .exp = -3 },
    };
    for (cases) |c| {
        var a = dec(c.a);
        defer a.deinit();
        var b = dec(c.b);
        defer b.deinit();
        var got = try BigDecimal.remainder(talloc, a, b);
        defer got.deinit();
        try expectStr(got, c.want);
        try testing.expectEqual(c.exp, got.exponent);
    }

    var one = dec("1");
    defer one.deinit();
    var zero = dec("0");
    defer zero.deinit();
    try testing.expectError(error.DivisionByZero, BigDecimal.remainder(talloc, one, zero));

    // Beyond any fixed-width type: an exact remainder of 200-digit operands.
    var big_a = dec("1" ++ "0" ** 200);
    defer big_a.deinit();
    var big_b = dec("7");
    defer big_b.deinit();
    var r = try BigDecimal.remainder(talloc, big_a, big_b);
    defer r.deinit();
    try expectStr(r, "2"); // 10^200 mod 7 (10^6 ≡ 1 mod 7, 200 mod 6 = 2, 10^2 ≡ 2)
}

test "min/max — sign matters, magnitude alone does not" {
    var a = dec("-5");
    defer a.deinit();
    var b = dec("2");
    defer b.deinit();
    var mx = try BigDecimal.max(talloc, a, b);
    defer mx.deinit();
    try expectStr(mx, "2"); // a magnitude comparison would answer -5
    var mn = try BigDecimal.min(talloc, a, b);
    defer mn.deinit();
    try expectStr(mn, "-5");

    // Numeric tie, different scale: GDA still names one, and which one
    // depends on the sign. Positive → max keeps the larger exponent.
    var p1 = dec("1.0");
    defer p1.deinit();
    var p2 = dec("1");
    defer p2.deinit();
    var tie_max = try BigDecimal.max(talloc, p1, p2);
    defer tie_max.deinit();
    try testing.expectEqual(@as(i32, 0), tie_max.exponent);
    var tie_min = try BigDecimal.min(talloc, p1, p2);
    defer tie_min.deinit();
    try testing.expectEqual(@as(i32, -1), tie_min.exponent);
    // Negative → mirrored.
    var n1 = dec("-1.0");
    defer n1.deinit();
    var n2 = dec("-1");
    defer n2.deinit();
    var ntie_max = try BigDecimal.max(talloc, n1, n2);
    defer ntie_max.deinit();
    try testing.expectEqual(@as(i32, -1), ntie_max.exponent);
    var ntie_min = try BigDecimal.min(talloc, n1, n2);
    defer ntie_min.deinit();
    try testing.expectEqual(@as(i32, 0), ntie_min.exponent);
}

test "sqrt — errors and the correctly-rounded contract" {
    var neg = dec("-1");
    defer neg.deinit();
    try testing.expectError(error.NegativeOperand, BigDecimal.sqrt(talloc, neg, 9, .half_even));

    var two = dec("2");
    defer two.deinit();
    try testing.expectError(error.PrecisionTooLarge, BigDecimal.sqrt(talloc, two, 0, .half_even));
    try testing.expectError(
        error.PrecisionTooLarge,
        BigDecimal.sqrt(talloc, two, BigDecimal.max_result_digits + 1, .half_even),
    );

    // √2 to 60 digits, against the published decimal expansion. A
    // "Newton until it stops changing" implementation is right to within an
    // ulp and will disagree with the last digit here sooner or later; this is
    // the one that says so.
    var r = try BigDecimal.sqrt(talloc, two, 60, .half_even);
    defer r.deinit();
    try expectStr(r, "1.41421356237309504880168872420969807856967187537694807317668");

    // Exact root keeps the ideal exponent ⌊e/2⌋ — √1.00 is 1.0, not 1.
    var e1 = dec("1.00");
    defer e1.deinit();
    var er = try BigDecimal.sqrt(talloc, e1, 9, .half_even);
    defer er.deinit();
    try expectStr(er, "1.0");
    try testing.expectEqual(@as(i32, -1), er.exponent);

    // Rounding that carries into an extra digit renormalises back to `prec`.
    var carry = dec("0.99999999999999");
    defer carry.deinit();
    var cr = try BigDecimal.sqrt(talloc, carry, 5, .half_even);
    defer cr.deinit();
    try expectStr(cr, "1.0000");
    try testing.expectEqual(@as(u32, 5), try cr.precision(talloc));
}

test "sqrt — the five directed rounding modes are observable without a tie (F3)" {
    // F3 (2026-08-11 re-audit): `sqrt.vec`'s rounding column is 3203
    // `half_even` + 65 `half_up` vectors, but a sqrt tie is essentially
    // unreachable (the true root would need to terminate in `5·10^(drop-1)`),
    // so every one of those vectors lands where the choice makes no
    // difference — forcing `half_up` to behave as `half_even` inside `sqrt`
    // passed the whole `test-decimal` suite clean. The five DIRECTED modes
    // (`up`/`down`/`ceiling`/`floor`/`half_down`), by contrast, ARE
    // observable in `sqrt` without any tie, and had zero vectors and zero
    // local tests before this. This pins all five at once, at the exact
    // boundary the audit's own evidence cites.
    //
    // sqrt(2) = 1.41421356237309504880... — at 9 significant digits the next
    // (10th) digit is 2 (< 5, not a tie): `down`/`floor` truncate toward
    // zero, `up`/`ceiling` round away from zero, and `half_down` agrees with
    // `down` since the discarded digit is unambiguously below the halfway
    // point. `sqrt`'s result is never negative, so `ceiling`≡`up` and
    // `floor`≡`down` here by construction — not a redundant check, since it
    // pins that `roundBump`'s `result_neg` branch is fed `false` correctly
    // for a `sqrt` result rather than left at some other default.
    var two = dec("2");
    defer two.deinit();

    const Case = struct { mode: RoundingMode, want: []const u8 };
    const cases = [_]Case{
        .{ .mode = .down, .want = "1.41421356" },
        .{ .mode = .floor, .want = "1.41421356" },
        .{ .mode = .half_down, .want = "1.41421356" },
        .{ .mode = .up, .want = "1.41421357" },
        .{ .mode = .ceiling, .want = "1.41421357" },
    };
    for (cases) |c| {
        var r = try BigDecimal.sqrt(talloc, two, 9, c.mode);
        defer r.deinit();
        try expectStr(r, c.want);
    }
}

test "pow — exact, and the digit budget refuses before it allocates" {
    var a = dec("1.1");
    defer a.deinit();

    // Java BigDecimal.pow(int): exact, result exponent = a.exponent × n.
    var p2 = try BigDecimal.pow(talloc, a, 2);
    defer p2.deinit();
    try expectStr(p2, "1.21");
    var p0 = try BigDecimal.pow(talloc, a, 0);
    defer p0.deinit();
    try expectStr(p0, "1");

    // A negative exponent is refused outright — never silently zero, never a
    // truncated reciprocal. (Java throws here for the same reason.)
    try testing.expectError(error.NegativeExponent, BigDecimal.pow(talloc, a, -1));

    // THE memory guard. decTest power.decTest really does contain exponent
    // 1000000007; `1.1 ^ 1000000007` has ~10^8 digits and computing it would
    // exhaust this machine. The refusal is computed from precision(a) × n
    // before a single limb is allocated.
    try testing.expectError(error.ResultTooLarge, BigDecimal.pow(talloc, a, 1_000_000_007));
    try testing.expectError(error.ResultTooLarge, BigDecimal.pow(talloc, a, 50_001)); // 2 × 50001 > 100000
    // …and one digit under the budget still works, so the guard is a real
    // boundary and not a blanket refusal.
    var ok = try BigDecimal.pow(talloc, a, 50_000);
    defer ok.deinit();
    try testing.expectEqual(@as(i32, -50_000), ok.exponent);

    // Exponent-arithmetic overflow is separate from the digit budget.
    var tiny = dec("2e-2000000000");
    defer tiny.deinit();
    try testing.expectError(error.Overflow, BigDecimal.pow(talloc, tiny, 3));
}

// ---------------------------------------------------------------------------
// decTest conformance tables — remainder / min / max / square-root / power.
//
// Provenance: the same IBM / Mike Cowlishaw "General Decimal Arithmetic
// Testcases" v2.62 suite as the KAT blocks above, "Reproduced with permission
// ... Copyright 1997, 2009 by International Business Machines Corporation"
// (https://speleotrove.com/decimal/dectest.html) — see NOTICE.
//
// These tables are two to three orders of magnitude larger than the
// hand-picked blocks above (3268 square-root cases alone), so they live in
// `src/testdata/*.vec` and are `@embedFile`d rather than inlined. Each file's
// header records the source file, the line format, and — case by case, with
// counts — exactly which source cases were NOT wired and under which rule.
// The extraction is mechanical (a script; see SPEC.md), never by eye.
//
// Every check asserts the **exponent** as well as the digits, because for
// these five operations the scale of the result is part of the specification:
// `remainder` takes min(ea, eb), `min`/`max` resolve a numeric tie by
// exponent, `square-root` has an ideal exponent for exact roots, and `pow`'s
// is `a.exponent × n`. A digits-only comparison would pass while all four
// rules were wrong.
// ---------------------------------------------------------------------------

/// Line reader for `testdata/*.vec`: skips blank and `#` lines, splits the
/// rest on `|` into exactly `n` fields.
const VecReader = struct {
    it: std.mem.SplitIterator(u8, .scalar),

    fn init(data: []const u8) VecReader {
        return .{ .it = std.mem.splitScalar(u8, data, '\n') };
    }

    fn next(self: *VecReader, comptime n: usize) ?[n][]const u8 {
        while (self.it.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;
            var fields: [n][]const u8 = undefined;
            var parts = std.mem.splitScalar(u8, line, '|');
            var i: usize = 0;
            while (parts.next()) |p| : (i += 1) {
                std.debug.assert(i < n); // malformed vector file
                fields[i] = p;
            }
            std.debug.assert(i == n);
            return fields;
        }
        return null;
    }
};

fn expectVec(d: BigDecimal, want: []const u8, want_exp: []const u8) !void {
    try expectStr(d, want);
    try testing.expectEqual(try std.fmt.parseInt(i32, want_exp, 10), d.exponent);
}

test "decTest: remainder.decTest" {
    var r = VecReader.init(@embedFile("testdata/remainder.vec"));
    var n: usize = 0;
    while (r.next(5)) |f| : (n += 1) {
        var a = try BigDecimal.parse(talloc, f[1]);
        defer a.deinit();
        var b = try BigDecimal.parse(talloc, f[2]);
        defer b.deinit();
        var got = try BigDecimal.remainder(talloc, a, b);
        defer got.deinit();
        expectVec(got, f[3], f[4]) catch |err| {
            std.debug.print("decTest {s} (remainder.decTest): {s} rem {s}\n", .{ f[0], f[1], f[2] });
            return err;
        };
    }
    try testing.expectEqual(@as(usize, 279), n); // the whole file, not a prefix
}

test "decTest: min.decTest and max.decTest" {
    inline for (.{ "min", "max" }) |op| {
        var r = VecReader.init(@embedFile("testdata/" ++ op ++ ".vec"));
        var n: usize = 0;
        while (r.next(5)) |f| : (n += 1) {
            var a = try BigDecimal.parse(talloc, f[1]);
            defer a.deinit();
            var b = try BigDecimal.parse(talloc, f[2]);
            defer b.deinit();
            var got = if (comptime std.mem.eql(u8, op, "min"))
                try BigDecimal.min(talloc, a, b)
            else
                try BigDecimal.max(talloc, a, b);
            defer got.deinit();
            expectVec(got, f[3], f[4]) catch |err| {
                std.debug.print("decTest {s} ({s}.decTest): {s}, {s}\n", .{ f[0], op, f[1], f[2] });
                return err;
            };
        }
        try testing.expectEqual(@as(usize, 105), n);
    }
}

test "decTest: squareroot.decTest" {
    var r = VecReader.init(@embedFile("testdata/sqrt.vec"));
    var n: usize = 0;
    while (r.next(6)) |f| : (n += 1) {
        var a = try BigDecimal.parse(talloc, f[1]);
        defer a.deinit();
        const prec = try std.fmt.parseInt(u32, f[2], 10);
        const mode = std.meta.stringToEnum(RoundingMode, f[3]).?;
        var got = try BigDecimal.sqrt(talloc, a, prec, mode);
        defer got.deinit();
        expectVec(got, f[4], f[5]) catch |err| {
            std.debug.print(
                "decTest {s} (squareroot.decTest): sqrt({s}) at precision {d}, {s}\n",
                .{ f[0], f[1], prec, f[3] },
            );
            return err;
        };
    }
    try testing.expectEqual(@as(usize, 3268), n);
}

test "decTest: power.decTest (integer exponents)" {
    var r = VecReader.init(@embedFile("testdata/pow.vec"));
    var n: usize = 0;
    while (r.next(5)) |f| : (n += 1) {
        var a = try BigDecimal.parse(talloc, f[1]);
        defer a.deinit();
        const e = try std.fmt.parseInt(i32, f[2], 10);
        var got = try BigDecimal.pow(talloc, a, e);
        defer got.deinit();
        expectVec(got, f[3], f[4]) catch |err| {
            std.debug.print("decTest {s} (power.decTest): {s} ^ {d}\n", .{ f[0], f[1], e });
            return err;
        };
    }
    try testing.expectEqual(@as(usize, 130), n);
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
