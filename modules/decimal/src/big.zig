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
//! reference only). Test data is our own: a few hand-written known-answer
//! tests inline, and generated conformance tables (`src/testdata/conform_*.vec`,
//! produced by `tools/py_conform.py`, expected values from Python's `decimal`
//! module) — see the "conformance tables" comment below and NOTICE.

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
    /// Exact (not `sizeInBaseUpperBound`, which is only an upper bound): a
    /// bit-length estimate checked against a power of ten on the stack; past
    /// 64 limbs (~1200 digits) std's `log10Alloc`, whose scratch is why this
    /// takes an allocator and can fail.
    pub fn precision(self: BigDecimal, allocator: Allocator) Allocator.Error!u32 {
        if (self.coeff.eqlZero()) return 1;
        // Borrow the limbs as a positive Const: log10 asserts a positive,
        // nonzero operand, and cloning just to drop a sign bit would be
        // wasteful on a large coefficient.
        const mag: bigint.Const = .{ .limbs = self.coeff.limbs[0..self.coeff.len()], .positive = true };
        return digitCount(allocator, mag);
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

        var exp_lit: i64 = 0;
        if (i < s.len and (s[i] == 'e' or s[i] == 'E')) {
            i += 1;
            var exp_neg = false;
            if (i < s.len and (s[i] == '+' or s[i] == '-')) {
                exp_neg = s[i] == '-';
                i += 1;
            }
            var exp_digits: u32 = 0;
            var exp_sig: u32 = 0;
            var exp_too_long = false;
            while (i < s.len) : (i += 1) {
                if (!std.ascii.isDigit(s[i])) return error.InvalidCharacter;
                // Cap accumulation width (not value range): ~15 digits is
                // already far past i32, so this only stops the i64
                // accumulator itself from overflowing on a pathological
                // input like a 40-digit exponent literal.
                exp_digits += 1;
                // Leading zeros carry no value; count only significant digits so
                // `1e0000000000000012` is 12, not a truncated read.
                if (exp_sig > 0 or s[i] != '0') {
                    exp_sig += 1;
                    if (exp_sig <= 15) exp_lit = exp_lit * 10 + @as(i64, s[i] - '0') else exp_too_long = true;
                }
            }
            if (exp_digits == 0) return error.InvalidCharacter;
            // More than 15 significant digits is far past i32: out of range.
            if (exp_too_long) return error.Overflow;
            if (exp_neg) exp_lit = -exp_lit;
        }
        if (i != s.len) return error.InvalidCharacter;

        const exponent64: i64 = exp_lit - frac_digits;
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

    /// Canonical **plain-notation** string (`toSci`/`toEng` give GDA's
    /// scientific/engineering forms). Unlike the
    /// fixed-scale `Decimal.toString`, trailing zeros are **not** trimmed:
    /// `coeff`/`exponent` *is* the value's actual stored precision (Java
    /// `BigDecimal` / GDA semantics — `1.50` and `1.5` are distinct
    /// `BigDecimal`s with different scales that happen to `order()` equal;
    /// see the exact add/mul KATs below, which only
    /// pass because trailing zeros are preserved). Zero always prints as
    /// plain `"0"` regardless of `exponent` or its sign bit; `toSci` and
    /// `toStringFixed` show a zero's scale (`0.00`, `0E+2`), and no function
    /// here surfaces a negative zero (see `negate`'s doc comment).
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

    // `format` (`{f}`), `toSci`, `toEng` and `toStringFixed` live in the S2
    // section at the end of the struct; they need an allocator for the digits.

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
            if (smallMag(&a.coeff)) |ma| if (smallMag(&b.coeff)) |mb| {
                const sa: i256 = if (a.coeff.isPositive()) ma else -@as(i256, ma);
                const sb: i256 = if (b.coeff.isPositive()) mb else -@as(i256, mb);
                const sum = sa + sb;
                return .{ .coeff = try managedFromU256(allocator, @abs(sum), sum < 0), .exponent = a.exponent };
            };
            return .{ .coeff = try addSigned(allocator, &a.coeff, &b.coeff), .exponent = a.exponent };
        }
        const lo_exp = @min(a.exponent, b.exponent);
        if (a.exponent > b.exponent) {
            const shift = try alignShift(a.exponent, lo_exp);
            var a_scaled = try scaleUp(allocator, &a.coeff, shift);
            defer a_scaled.deinit();
            return .{ .coeff = try addSigned(allocator, &a_scaled, &b.coeff), .exponent = lo_exp };
        } else {
            const shift = try alignShift(b.exponent, lo_exp);
            var b_scaled = try scaleUp(allocator, &b.coeff, shift);
            defer b_scaled.deinit();
            return .{ .coeff = try addSigned(allocator, &a.coeff, &b_scaled), .exponent = lo_exp };
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
        if (smallMag(&a.coeff)) |ma| if (smallMag(&b.coeff)) |mb| {
            const neg = a.coeff.isPositive() != b.coeff.isPositive();
            return .{ .coeff = try managedFromU256(allocator, std.math.mulWide(u128, ma, mb), neg), .exponent = @intCast(exp64) };
        };
        var r = try Managed.initCapacity(allocator, a.coeff.len() + b.coeff.len() + 1);
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
    // Float bridge — the ONLY place an `f64` meets this type. Nothing
    // above or below calls these: no arithmetic path (`add`/`sub`/`mul`/
    // `div`/`rescale`/`sqrt`/`pow`/…) takes, returns or computes with a
    // float, so the module's no-float guarantee holds for every
    // computation; a pipeline that never calls these entry points is
    // float-free. Even here no floating-point *arithmetic* happens: an
    // `f64` is only bit-inspected on the way in (`f64Binary`,
    // `f64Shortest`) and handed to `std.fmt.parseFloat` on the way out.
    // -----------------------------------------------------------------

    /// `NotFinite` = the input was NaN or ±Inf (refused, never a trap and
    /// never a silent 0). The rest is `rescale`'s error set.
    pub const FromFloatError = error{NotFinite} || Error;

    /// The **exact** value of a finite `f64` — Python's `Decimal.from_float`.
    /// An `f64` is `m × 2^e`, so it is a terminating decimal: for `e < 0`,
    /// `m × 2^e = m × 5^(-e) × 10^e`, and the result is `m × 5^(-e)` at
    /// exponent `e` (`0.1` becomes the 55-digit
    /// `0.1000000000000000055511151231257827021181583404541015625`; the
    /// smallest subnormal is 751 significant digits). `m` is taken odd, so
    /// the exponent is the shortest one that still holds the value exactly
    /// (`0.5` is `5` at exponent −1). Nothing is rounded. `-0.0` and `0.0`
    /// both give zero. `error.NotFinite` on NaN / ±Inf.
    pub fn fromFloatExact(allocator: Allocator, x: f64) (error{NotFinite} || Allocator.Error)!BigDecimal {
        const p = try f64Binary(x);
        var coeff = try Managed.initSet(allocator, p.m);
        errdefer coeff.deinit();
        var exponent: i32 = 0;
        if (p.m != 0) {
            if (p.e >= 0) {
                var shifted = try Managed.init(allocator);
                errdefer shifted.deinit();
                try shifted.shiftLeft(&coeff, @intCast(p.e));
                coeff.deinit();
                coeff = shifted;
            } else {
                var five = try Managed.initSet(allocator, 5);
                defer five.deinit();
                var p5 = try Managed.init(allocator);
                defer p5.deinit();
                try p5.pow(&five, @intCast(-p.e));
                var prod = try Managed.init(allocator);
                errdefer prod.deinit();
                try prod.mul(&coeff, &p5);
                coeff.deinit();
                coeff = prod;
                exponent = p.e;
            }
            coeff.setSign(!p.neg);
        }
        return .{ .coeff = coeff, .exponent = exponent };
    }

    /// `x` converted **exactly** (`fromFloatExact`) and then rounded to
    /// `new_scale` fractional digits (result exponent `-new_scale`; a negative
    /// scale rounds to tens/hundreds/…) with the caller's explicit `mode` —
    /// the same `rescale` path every other rounding-sensitive op uses, so
    /// there is exactly one rounding step and no double rounding. Consequence
    /// worth knowing: `2.675` is stored as `2.67499999999999982…`, i.e.
    /// *below* the tie, so `fromFloat(2.675, 2, .half_up)` is `2.67`, not
    /// `2.68` — this is what Python's `Decimal(2.675).quantize(Decimal('0.01'),
    /// ROUND_HALF_UP)` gives. For "what the user typed" use `fromFloatShortest`.
    /// `error.NotFinite` on NaN / ±Inf; `error.Overflow` when the scale or
    /// the digits to drop exceed `max_align_shift`.
    pub fn fromFloat(allocator: Allocator, x: f64, new_scale: i32, mode: RoundingMode) FromFloatError!BigDecimal {
        const exponent: i32 = std.math.cast(i32, -@as(i64, new_scale)) orelse return error.Overflow;
        var exact = try fromFloatExact(allocator, x);
        defer exact.deinit();
        return rescale(allocator, exact, exponent, mode);
    }

    /// The **shortest decimal that round-trips** to `x` — what Zig's `{d}`/`{e}`
    /// float formatting prints and Python's `repr(x)` shows: `0.1` is exactly
    /// `1` at exponent −1, not the 55-digit binary expansion. This is the
    /// "what the user typed" reading; it is not the value of the `f64`
    /// (`toFloat(fromFloatShortest(x)) == x` for every finite `x`, but
    /// `fromFloatShortest(x)` and `fromFloatExact(x)` differ). No rounding is
    /// involved (≤ 17 significant digits); use `rescale` afterwards to
    /// quantize. `error.NotFinite` on NaN / ±Inf.
    pub fn fromFloatShortest(allocator: Allocator, x: f64) (error{NotFinite} || Allocator.Error)!BigDecimal {
        const p = try f64Shortest(x);
        var coeff = try Managed.initSet(allocator, p.digits);
        errdefer coeff.deinit();
        if (p.digits != 0) coeff.setSign(!p.neg);
        return .{ .coeff = coeff, .exponent = p.exp10 };
    }

    /// The nearest `f64` to this value, **correctly rounded, ties to even**
    /// (IEEE 754 roundTiesToEven), subnormals included. Implemented by
    /// writing the exact digits as `<coeff>e<exponent>` and handing them to
    /// `std.fmt.parseFloat(f64, …)`, which is correctly rounded for any
    /// number of digits (Eisel–Lemire with an exact big-decimal fallback);
    /// no floating-point arithmetic is done here. Exponent-only magnitudes
    /// are short-circuited first, so a hostile exponent (`1e2000000000`)
    /// never reaches the parser as a huge string.
    ///
    /// **Out of range is not an error** (total function, like Python's
    /// `float(Decimal('1e400'))` → `inf`, and like IEEE conversion): a value
    /// beyond the largest finite `f64` (or exactly at the rounding tie above
    /// it) is `±inf`; a value below half of the smallest subnormal
    /// underflows to a signed zero (`-1e-400` → `-0.0`; an actual zero
    /// `BigDecimal` is `+0.0`). Consequence: the conversion is not
    /// invertible at the edges — `fromFloat` refuses the `inf` it produces.
    /// Only allocation can fail.
    pub fn toFloat(self: BigDecimal, allocator: Allocator) Allocator.Error!f64 {
        if (self.isZero()) return 0.0;
        const digits = try self.coeff.toConst().toStringAlloc(allocator, 10, .lower);
        defer allocator.free(digits);
        const neg = digits[0] == '-';
        // Decimal exponent of the leading digit: value ∈ [10^adj, 10^(adj+1)).
        const adj: i64 = @as(i64, @intCast(digits.len - @as(usize, @intFromBool(neg)))) - 1 + self.exponent;
        // f64 max ≈ 1.8e308 and half the smallest subnormal ≈ 2.5e-324, so
        // these cut-offs are safely outside the rounding window.
        if (adj > 310) return if (neg) -std.math.inf(f64) else std.math.inf(f64);
        if (adj < -326) return std.math.copysign(@as(f64, 0.0), if (neg) -1.0 else 1.0);
        const text = try allocator.print("{s}e{d}", .{ digits, self.exponent });
        defer allocator.free(text);
        // Well-formed by construction: optional '-', decimal digits, 'e', integer.
        return std.fmt.parseFloat(f64, text) catch unreachable;
    }

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
    /// `-2.4 rem 1 = -0.4` while `2.4 rem -1 = 0.4` (`-2.4 rem 1` and `2.4 rem -1` differ in sign only).
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
    /// precision, so it just returns the exact answer. Reference-implementation cases of that kind are
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
        // `-2.4 rem 1` versus `2.4 rem -1` tells the two apart.)
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
    /// terms (`max(-1.0, -1.00)` is `-1.00`). Signs never actually differ on a
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
    /// output: `1.1 ^ 1000000007` (a plausible request, e.g. from a fuzzer)
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
    /// exposed for consistency with the rest of the module, and the generated
    /// conformance table replays every mode.
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

        // Rounding path. Gain k = prec+1 decimal digits of root by scaling the
        // radicand by 10^(2k); √(N·10^2k) = √N·10^k, so ⌊√·⌋ then has at least
        // k+1 ≥ prec+2 digits — enough to place the half-way point exactly.
        const k: u32 = prec + 1;
        var n = try scaleUp(allocator, &n0, 2 * k);
        defer n.deinit();

        var root = try isqrt(allocator, &n);
        defer root.deinit();

        // Exactness from the one root: ⌊√(N·10^2k)⌋² == N·10^2k iff N is a
        // perfect square (√N = R/10^k is rational, hence an integer) — exact
        // in the strict sense (R² == N·10^2k), never "close enough": a
        // mis-detected exact root would emit the ideal exponent for an
        // inexact value. Then the exact root R/10^k is returned as is when it
        // fits `prec` digits.
        const root_is_exact = blk: {
            var sq = try Managed.init(allocator);
            defer sq.deinit();
            try sq.mul(&root, &root);
            break :blk sq.toConst().order(n.toConst()) == .eq;
        };
        if (root_is_exact) {
            var ten_k = try pow10(allocator, k);
            defer ten_k.deinit();
            var exact_root = try Managed.init(allocator);
            errdefer exact_root.deinit();
            var rem = try Managed.init(allocator);
            defer rem.deinit();
            try exact_root.divTrunc(&rem, &root, &ten_k);
            std.debug.assert(rem.eqlZero());
            const fits = exact_root.eqlZero() or
                (try (BigDecimal{ .coeff = exact_root, .exponent = 0 }).precision(allocator)) <= prec;
            if (fits) {
                if (m > std.math.maxInt(i32) or m < std.math.minInt(i32)) return error.Overflow;
                return .{ .coeff = exact_root, .exponent = @intCast(m) };
            }
            exact_root.deinit();
        }

        const d: u32 = try (BigDecimal{ .coeff = root, .exponent = 0 }).precision(allocator);
        std.debug.assert(d > prec);
        const drop: u32 = d - prec;

        var ten_drop = try pow10(allocator, drop);
        defer ten_drop.deinit();
        var q = try Managed.init(allocator);
        errdefer q.deinit();
        // The discarded part of ⌊√N⌋ is zero AND ⌊√N⌋² == N exactly iff the root
        // is exact at the kept digits (e.g. √100.00 at 2 digits is exactly 10):
        // then no rounding decision exists and every mode must agree. Without
        // this, `up`/`ceiling`/`round_05up` would bump an exact root.
        var exact_discard = false;
        {
            var rem = try Managed.init(allocator);
            defer rem.deinit();
            try q.divTrunc(&rem, &root, &ten_drop);
            exact_discard = rem.eqlZero() and root_is_exact;
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
        if (!exact_discard and roundBump(mode, half, q.isOdd(), try lastDigit05(allocator, mode, &q), false))
            try q.addScalar(&q, 1);

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
    /// `pow("1.1", 1000000007)` asks for a
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

    // -----------------------------------------------------------------
    // Context-precision rounding (GDA "significant digits" semantics), the
    // other half of the integer division family, a total order and the
    // text forms GDA defines. Everything here is exact except where a
    // `mode` is taken; expected values are frozen from Python `decimal`
    // (tools/py_oracle.py -> src/testdata/s2_oracle.vec).
    // -----------------------------------------------------------------

    /// Outcome of an operation rounded to a number of significant digits, with
    /// the two GDA condition flags it would have raised:
    ///   `rounded`  digits were discarded (even if they were all zeros:
    ///              `1.200` to 2 digits is `1.2`, rounded but not inexact);
    ///   `inexact`  a nonzero part was discarded, so `value` differs from the
    ///              true result.
    /// The caller owns `value` (`deinit`).
    pub const Rounded = struct {
        value: BigDecimal,
        inexact: bool,
        rounded: bool,

        pub fn deinit(self: *Rounded) void {
            self.value.deinit();
        }
    };

    /// `InvalidPrecision` = `prec == 0` (GDA precision is at least 1).
    pub const PrecError = Error || error{InvalidPrecision};
    /// `PrecisionTooLarge` = `prec > max_result_digits` (the digit budget).
    pub const DivPrecError = DivError || error{ InvalidPrecision, PrecisionTooLarge };

    /// Round `a` to `prec` significant digits with `mode` — GDA's unary `plus`
    /// under a context of precision `prec` (Python `Context(prec=prec,
    /// rounding=mode).plus(a)`). A value that already has at most `prec` digits
    /// is returned unchanged (no trailing zeros are added or removed, flags
    /// clear). Otherwise the surplus low digits are dropped through the same
    /// `roundedDivMag` decision as `rescale`; a carry that makes the coefficient
    /// `prec + 1` digits long (`9.99` to 2 digits is `10`, not `10.0`) is folded
    /// back into the exponent, so the result never has more than `prec` digits.
    /// `error.Overflow` if the exponent leaves `i32` or more than
    /// `max_align_shift` digits must be dropped.
    pub fn roundToPrecision(allocator: Allocator, a: BigDecimal, prec: u32, mode: RoundingMode) PrecError!Rounded {
        if (prec == 0) return error.InvalidPrecision;
        const digits = try a.precision(allocator);
        if (digits <= prec) return .{ .value = try a.clone(), .inexact = false, .rounded = false };

        const drop: u32 = digits - prec; // >= 1, and a is nonzero (zero has 1 digit)
        if (drop > max_align_shift) return error.Overflow;
        var exp64: i64 = @as(i64, a.exponent) + drop;
        if (exp64 > std.math.maxInt(i32)) return error.Overflow;
        const result_neg = !a.coeff.isPositive();

        var num = try a.coeff.clone();
        defer num.deinit();
        num.abs();
        var ten_drop = try pow10(allocator, drop);
        defer ten_drop.deinit();
        var q = try Managed.init(allocator);
        errdefer q.deinit();
        var r = try Managed.init(allocator);
        defer r.deinit();
        try q.divTrunc(&r, &num, &ten_drop);
        const inexact = !r.eqlZero();
        if (inexact) try applyRounding(allocator, &q, &r, &ten_drop, result_neg, mode);
        try foldCarry(allocator, &q, &exp64, prec);
        if (result_neg) q.negate();
        return .{ .value = .{ .coeff = q, .exponent = @intCast(exp64) }, .inexact = inexact, .rounded = true };
    }

    /// `a / b` rounded to `prec` significant digits (GDA `divide` under a
    /// context of that precision; Python `Context(prec=prec, rounding=mode)
    /// .divide(a, b)`) — the context-precision counterpart of `div`, which
    /// takes a result scale instead.
    ///
    /// An **exact** quotient that fits in `prec` digits is returned exactly, with
    /// trailing zeros removed as far as the *ideal exponent*
    /// `a.exponent - b.exponent` allows (`100/10` is `10`, `2.40/2` is `1.20`,
    /// `1/4` is `0.25`), flags clear -- except `rounded` when the exact
    /// quotient has more than `prec` digits at the ideal exponent and sheds
    /// zeros (`2550E+7` at 3 digits is `255E+8`). An inexact quotient has exactly `prec`
    /// digits and sets `inexact` and `rounded`. A zero dividend gives zero at the
    /// ideal exponent. `error.DivisionByZero` on `b = 0`;
    /// `error.InvalidPrecision` on `prec = 0`; `error.PrecisionTooLarge` past
    /// `max_result_digits`; `error.Overflow` when an alignment needs more than
    /// `max_align_shift` digits or the exponent leaves `i32`.
    pub fn divPrec(allocator: Allocator, a: BigDecimal, b: BigDecimal, prec: u32, mode: RoundingMode) DivPrecError!Rounded {
        if (prec == 0) return error.InvalidPrecision;
        if (prec > max_result_digits) return error.PrecisionTooLarge;
        if (b.isZero()) return error.DivisionByZero;
        const ideal: i64 = @as(i64, a.exponent) - @as(i64, b.exponent);
        if (ideal > std.math.maxInt(i32) or ideal < std.math.minInt(i32)) return error.Overflow;
        if (a.isZero()) {
            return .{
                .value = .{ .coeff = try Managed.init(allocator), .exponent = @intCast(ideal) },
                .inexact = false,
                .rounded = false,
            };
        }
        if (try divPrecSmall(allocator, a, b, prec, mode, ideal)) |r| return r;
        return divPrecGeneral(allocator, a, b, prec, mode, ideal);
    }

    /// `divPrec` on `std.math.big.int` (any size), after the zero and
    /// argument checks.
    fn divPrecGeneral(allocator: Allocator, a: BigDecimal, b: BigDecimal, prec: u32, mode: RoundingMode, ideal: i64) DivPrecError!Rounded {
        const result_neg = a.coeff.isPositive() != b.coeff.isPositive();
        const da: i64 = try a.precision(allocator);
        const db: i64 = try b.precision(allocator);

        // Read-only magnitude views: a shallow copy shares the limbs, and
        // `abs` touches only the copy's sign (never deinit or write these).
        var num = a.coeff;
        num.abs();
        var den = b.coeff;
        den.abs();

        // Scale by 10^s so the truncated quotient has `prec` or `prec + 1`
        // digits (da + s digits over db digits); one more step down if it has
        // the extra digit, which leaves exactly `prec`.
        var s: i64 = @as(i64, prec) + db - da;
        var n2 = try Managed.init(allocator);
        defer n2.deinit();
        var d2 = try Managed.init(allocator);
        defer d2.deinit();
        var q = try Managed.init(allocator);
        errdefer q.deinit();
        var r = try Managed.init(allocator);
        defer r.deinit();
        var divisor: *const Managed = &den;
        var attempt: u8 = 0;
        while (true) : (attempt += 1) {
            const mag: i64 = if (s < 0) -s else s;
            if (mag > max_align_shift) return error.Overflow;
            var p = try pow10(allocator, @intCast(mag));
            defer p.deinit();
            if (s >= 0) {
                try n2.mul(&num, &p);
                divisor = &den;
                try q.divTrunc(&r, &n2, divisor);
            } else {
                try d2.mul(&den, &p);
                divisor = &d2;
                try q.divTrunc(&r, &num, divisor);
            }
            const qd = try (BigDecimal{ .coeff = q, .exponent = 0 }).precision(allocator);
            if (qd <= prec) break;
            std.debug.assert(attempt == 0 and qd == prec + 1);
            s -= 1;
        }

        var e: i64 = ideal - s;
        const exact = r.eqlZero();
        if (exact) {
            // Strip trailing zeros down toward the ideal exponent only.
            var ten = try Managed.initSet(allocator, 10);
            defer ten.deinit();
            var quo = try Managed.init(allocator);
            defer quo.deinit();
            var rem = try Managed.init(allocator);
            defer rem.deinit();
            while (e < ideal) {
                try quo.divTrunc(&rem, &q, &ten);
                if (!rem.eqlZero()) break;
                q.swap(&quo);
                e += 1;
            }
        } else {
            try applyRounding(allocator, &q, &r, divisor, result_neg, mode);
            try foldCarry(allocator, &q, &e, prec);
        }
        if (e > std.math.maxInt(i32) or e < std.math.minInt(i32)) return error.Overflow;
        if (result_neg) q.negate();
        // An exact quotient above the ideal exponent had to shed trailing zeros to fit
        // `prec` digits: GDA (and Python) flag that as Rounded, though not Inexact.
        return .{ .value = .{ .coeff = q, .exponent = @intCast(e) }, .inexact = !exact, .rounded = !exact or e > ideal };
    }

    // -----------------------------------------------------------------
    // Transcendental functions: exp, ln, log10 and real-exponent power,
    // correctly rounded to `prec` significant digits in every RoundingMode.
    // -----------------------------------------------------------------

    /// Largest `prec` the transcendental functions accept. Their cost grows
    /// roughly with the square of the working precision (a few hundred
    /// milliseconds at the cap), so this is the bound that keeps a hostile
    /// `prec` from becoming a hang; `error.PrecisionTooLarge` beyond it.
    pub const max_transcendental_prec: u32 = 2000;

    /// Largest working precision (digits) the Ziv loop may climb to while
    /// deciding a rounding. It is far beyond anything a non-adversarial input
    /// needs (each extra digit makes an undecided rounding ten times less
    /// likely); hitting it is `error.PrecisionTooLarge`, never a wrong digit
    /// and never an endless loop. An argument that is within 10^-6000 of a
    /// rounding boundary (`ln(1 + 10^-5000)`) is the only way to reach it.
    pub const max_work_digits: u32 = 6000;

    /// `Overflow` = the result's exponent leaves `i32` (GDA's overflow and
    /// underflow are one typed error here), or `|exponent| >= 1E+16` for `power`.
    pub const TranscendentalError = Error || error{ InvalidPrecision, PrecisionTooLarge };
    /// `NonPositiveOperand` = `a <= 0` (GDA: `ln(0)` is `-Infinity`, `ln(<0)` invalid).
    pub const LnError = TranscendentalError || error{NonPositiveOperand};
    /// `NegativeBase` = negative base with a non-integer exponent; `DivisionByZero`
    /// = zero to a negative power; `ZeroToZero` = `0^0` (GDA invalid operation).
    pub const PowerError = TranscendentalError || error{ NegativeBase, DivisionByZero, ZeroToZero };

    /// `e^a` correctly rounded to `prec` significant digits under `mode`.
    ///
    /// Correctly rounded means: the digits returned are those of the true
    /// real number `e^a` rounded once, in `mode`, to `prec` digits -- decided
    /// by an interval (Ziv strategy): the value is computed with a rigorous
    /// error bound at growing working precision until both ends of the
    /// interval round to the same result. **This holds for all eight modes.**
    /// Python's `decimal` only guarantees it for `half_even` (libmpdec rounds
    /// `exp`/`ln`/`log10` half-even whatever the context says); here the mode
    /// is honoured, and `half_even` agrees with Python digit for digit.
    ///
    /// `exp(0)` is exactly `1` (flags clear). Every other result is inexact
    /// and has exactly `prec` digits. An argument with `|a| < 10^-(prec+2)` is
    /// answered in constant time (`1 +- tiny`). `error.Overflow` when the result
    /// exponent leaves `i32` (`|a|` beyond about 4.9e9).
    ///
    /// Method (ported in structure, not in code, from libmpdec's `_mpd_qexp`:
    /// argument reduction plus Taylor series, with the correct-rounding loop
    /// of `mpd_qexp`): `a = q*ln10 + r` with `|r| <= ln10/2`, `e^r` by its
    /// Taylor series in fixed point, the factor `10^q` an exponent shift.
    pub fn exp(allocator: Allocator, a: BigDecimal, prec: u32, mode: RoundingMode) TranscendentalError!Rounded {
        try checkTrPrec(prec);
        if (a.isZero()) return one_exact(allocator);
        const adj = try a.adjusted(allocator);
        if (adj >= 10) return error.Overflow;
        const neg = !a.coeff.isPositive();
        if (adj < -(@as(i64, prec) + 2)) {
            // 1 +- tiny: any value strictly between 1 and the next/previous
            // representable number rounds the same as 10^-(prec+2) away from 1.
            const n: u32 = prec + 2;
            var v = BigDecimal{ .coeff = try pow10(allocator, n), .exponent = -@as(i32, @intCast(n)) };
            defer v.deinit();
            if (neg) try v.coeff.addScalar(&v.coeff, -1) else try v.coeff.addScalar(&v.coeff, 1);
            return roundedInexact(allocator, v, prec, mode);
        }
        var extra: u32 = 10;
        while (true) : (extra = extra * 2) {
            const wt: u32 = prec + extra + @as(u32, @intCast(@max(adj + 1, 0)));
            if (wt > max_work_digits) return error.PrecisionTooLarge;
            var t = try scaleToFixed(allocator, a, wt);
            defer t.deinit();
            var e = try expFixed(allocator, &t.v, t.err, wt);
            defer e.deinit();
            if (try decideInterval(allocator, &e.man, e.err, e.exp10, false, prec, mode)) |r| return r;
        }
    }

    /// Natural logarithm of `a`, correctly rounded to `prec` significant digits
    /// under `mode` (all eight modes; see `exp` for what that means and how it
    /// differs from Python). `ln(1)` is exactly `0` (flags clear); every other
    /// result is inexact with exactly `prec` digits. `error.NonPositiveOperand`
    /// for `a <= 0`.
    ///
    /// Method (after libmpdec's `_mpd_qln` in structure): `a = m * 10^k`, `m`
    /// scaled into `[0.7, 1.4)` by powers of two, `ln m = 2*atanh((m-1)/(m+1))`
    /// summed as a series in fixed point, plus `k*ln10 - j*ln2` from the same
    /// kind of series. A result near zero (`a` near 1) widens the working
    /// precision until it has enough significant digits; an `a` within
    /// `10^-max_work_digits` of 1 is `error.PrecisionTooLarge`.
    pub fn ln(allocator: Allocator, a: BigDecimal, prec: u32, mode: RoundingMode) LnError!Rounded {
        try checkTrPrec(prec);
        if (a.isZero() or !a.coeff.isPositive()) return error.NonPositiveOperand;
        if (try isExactlyOne(allocator, a)) return zero_exact(allocator);
        var extra: u32 = 10;
        var w: u32 = prec + extra;
        while (true) {
            if (w > max_work_digits) return error.PrecisionTooLarge;
            var l = try lnFixed(allocator, a, w);
            defer l.deinit();
            const dg = try digitsOf(allocator, &l.v);
            if (dg < prec + 6) {
                // x is close to 1: too few significant digits yet.
                w += (prec + 6 - dg) + 10;
                continue;
            }
            if (try decideInterval(allocator, &l.v, l.err, -@as(i64, w), false, prec, mode)) |r| return r;
            extra *= 2;
            w = prec + extra;
        }
    }

    /// Base-10 logarithm of `a`, correctly rounded to `prec` significant digits
    /// under `mode`. An exact power of ten (`1E+3`, `0.01`, `1`) gives its
    /// integer logarithm with exponent 0 and no inexactness (rounded to `prec`
    /// digits only if the integer is longer); everything else is inexact with
    /// exactly `prec` digits. `error.NonPositiveOperand` for `a <= 0`.
    /// Computed as `ln(a) / ln10` in fixed point with a propagated error bound.
    pub fn log10(allocator: Allocator, a: BigDecimal, prec: u32, mode: RoundingMode) LnError!Rounded {
        try checkTrPrec(prec);
        if (a.isZero() or !a.coeff.isPositive()) return error.NonPositiveOperand;
        {
            var n = try normalize(allocator, a);
            defer n.deinit();
            if (((n.coeff.toInt(u8)) catch 0) == 1) {
                // coefficient 1: a = 10^exponent, the logarithm is the exponent.
                var k = BigDecimal{ .coeff = try Managed.initSet(allocator, n.exponent), .exponent = 0 };
                defer k.deinit();
                return roundPrec(allocator, k, prec, mode);
            }
        }
        var extra: u32 = 10;
        var w: u32 = prec + extra;
        while (true) {
            if (w > max_work_digits) return error.PrecisionTooLarge;
            var q = try log10Fixed(allocator, a, w);
            defer q.deinit();
            const dg = try digitsOf(allocator, &q.v);
            if (dg < prec + 6) {
                w += (prec + 6 - dg) + 10;
                continue;
            }
            if (try decideInterval(allocator, &q.v, q.err, -@as(i64, w), false, prec, mode)) |r| return r;
            extra *= 2;
            w = prec + extra;
        }
    }

    /// `base^exponent` for any decimal exponent, rounded to `prec` significant
    /// digits under `mode` (GDA `power`; Python `Context.power`).
    ///
    /// * Integer-valued exponent that fits `i32` and whose exact power is
    ///   within `max_result_digits`: the power is computed **exactly** (`pow`)
    ///   and rounded once (a negative exponent divides `1` by the exact power
    ///   with `divPrec`). Ideal exponents and flags are those of that exact
    ///   result (`1.1^2` is `1.21`, flags clear). Negative bases are fine.
    /// * Anything else (a fractional exponent, or an integer too large for
    ///   that): `exp(exponent * ln(base))` evaluated with a rigorous error
    ///   bound and the same Ziv loop as `exp`. The result is inexact with
    ///   exactly `prec` digits -- even when the true value happens to be exact
    ///   (`4^0.5` is `2.0000` at `prec` 5, flagged inexact), as in Python;
    ///   such an exact value is detected (`x^(p/q)` tested exactly) so every
    ///   mode, and a tie, still rounds it correctly. A negative base with an
    ///   integer exponent too large for the exact path keeps the sign by parity.
    /// * `exponent = 0` is `1` (flags clear), but `0^0` is `error.ZeroToZero`;
    ///   `0^positive` is `0`; `0^negative` is `error.DivisionByZero`; a negative
    ///   base with a non-integer exponent is `error.NegativeBase`.
    ///
    /// `error.Overflow` when the result exponent leaves `i32`, when the product
    /// `exponent * ln(base)` exceeds about 4.9e9 in magnitude, or when
    /// `|exponent| >= 1E+16`. Like `exp`, correct in all eight modes (Python:
    /// `half_even` only; its integer powers are also not always correctly
    /// rounded).
    pub fn power(allocator: Allocator, base: BigDecimal, exponent: BigDecimal, prec: u32, mode: RoundingMode) PowerError!Rounded {
        try checkTrPrec(prec);
        if (exponent.isZero()) {
            if (base.isZero()) return error.ZeroToZero;
            return one_exact(allocator);
        }
        var yn = try normalize(allocator, exponent);
        defer yn.deinit();
        const y_neg = !yn.coeff.isPositive();
        const y_int = yn.exponent >= 0;
        if (base.isZero()) {
            if (y_neg) return error.DivisionByZero;
            return zero_exact(allocator);
        }
        const base_neg = !base.coeff.isPositive();
        if (base_neg and !y_int) return error.NegativeBase;

        var result_neg = false;
        if (y_int) {
            // Exact path: the exponent as an i32, within the digit budget.
            if (try smallInt(allocator, yn)) |n| {
                const mag: u64 = if (n < 0) @intCast(-@as(i64, n)) else @intCast(n);
                const digits: u64 = try base.precision(allocator);
                if (digits * mag <= max_result_digits) {
                    var p = pow(allocator, base, @intCast(mag)) catch |e| switch (e) {
                        error.ResultTooLarge, error.NegativeExponent => unreachable,
                        else => |x| return x,
                    };
                    defer p.deinit();
                    if (n > 0) return roundPrec(allocator, p, prec, mode);
                    var one = try fromInt(allocator, 1);
                    defer one.deinit();
                    return divPrec(allocator, one, p, prec, mode) catch |e| switch (e) {
                        error.InvalidPrecision => unreachable,
                        else => |x| return x,
                    };
                }
            }
            // Too large for the exact path: real path, sign from parity.
            if (base_neg) result_neg = yn.exponent == 0 and yn.coeff.isOdd();
        }
        var mag_base = try base.clone();
        defer mag_base.deinit();
        mag_base.absVal();
        if (try isExactlyOne(allocator, mag_base)) {
            if (!y_int) return paddedOne(allocator, prec);
            var one = try one_exact(allocator);
            if (result_neg) one.value.coeff.negate();
            return one;
        }

        const adj_y = try yn.adjusted(allocator);
        if (adj_y > 15) return error.Overflow;
        // ceil(|y|), at least 1.
        var abs_y: u128 = blk: {
            var c = try yn.coeff.clone();
            defer c.deinit();
            c.abs();
            if (yn.exponent >= 0) {
                var sh = try scaleUp(allocator, &c, @intCast(yn.exponent));
                defer sh.deinit();
                break :blk sh.toInt(u128) catch return error.Overflow;
            }
            var d = try pow10(allocator, @intCast(@min(-@as(i64, yn.exponent), max_align_shift)));
            defer d.deinit();
            var qq = try Managed.init(allocator);
            defer qq.deinit();
            var rr = try Managed.init(allocator);
            defer rr.deinit();
            try qq.divTrunc(&rr, &c, &d);
            break :blk (qq.toInt(u128) catch return error.Overflow) + 1;
        };
        if (abs_y == 0) abs_y = 1;
        const dy: u32 = @as(u32, @intCast(@max(adj_y + 1, 0))) + 3;

        var extra: u32 = 10;
        while (true) : (extra = extra * 2) {
            const wt: u32 = prec + extra;
            const wl: u32 = wt + dy;
            if (wl > max_work_digits) return error.PrecisionTooLarge;
            var l = try lnFixed(allocator, mag_base, wl);
            defer l.deinit();
            // T = L * y at scale wt (L at scale wl, y = yc * 10^ye).
            var tv = try Managed.init(allocator);
            defer tv.deinit();
            try tv.mul(&l.v, &yn.coeff);
            const shift: i64 = @as(i64, yn.exponent) - @as(i64, dy);
            if (shift >= 0) {
                if (shift > max_align_shift) return error.Overflow;
                var sh = try scaleUp(allocator, &tv, @intCast(shift));
                tv.swap(&sh);
                sh.deinit();
            } else {
                if (-shift > max_align_shift) return error.Overflow;
                var d = try pow10(allocator, @intCast(-shift));
                defer d.deinit();
                var rr = try Managed.init(allocator);
                defer rr.deinit();
                var qq = try Managed.init(allocator);
                defer qq.deinit();
                try qq.divTrunc(&rr, &tv, &d);
                tv.swap(&qq);
            }
            const scale_div: u128 = std.math.pow(u128, 10, dy);
            const t_err: u128 = (l.err * abs_y + scale_div - 1) / scale_div + 2;
            var e = try expFixed(allocator, &tv, t_err, wt);
            defer e.deinit();
            if (try decideInterval(allocator, &e.man, e.err, e.exp10, result_neg, prec, mode)) |r| return r;
            if (!y_int and extra >= 20) {
                if (try exactPowerCandidate(allocator, mag_base, yn, &e, prec, mode)) |r| return r;
            }
        }
    }

    /// GDA `divide-integer` / Python `a // b`: the integer part of `a / b`,
    /// truncated toward zero, with exponent 0 (zero is `0`). Exact. Both
    /// operands are aligned to a common exponent first (`max_align_shift`
    /// applies). `error.DivisionByZero` on `b = 0`.
    pub fn divideInteger(allocator: Allocator, a: BigDecimal, b: BigDecimal) DivError!BigDecimal {
        if (b.isZero()) return error.DivisionByZero;
        var al = try alignPair(allocator, a, b);
        defer al.deinit();
        var q = try Managed.init(allocator);
        errdefer q.deinit();
        var r = try Managed.init(allocator);
        defer r.deinit();
        try q.divTrunc(&r, &al.an, &al.bn);
        if (q.eqlZero()) q.setSign(true); // no negative zero
        return .{ .coeff = q, .exponent = 0 };
    }

    /// GDA `remainder-near` / Python `a.remainder_near(b)`: `a - b·n` where `n`
    /// is the integer **nearest** `a / b` (a tie goes to the even `n`). Unlike
    /// `remainder` the sign may be either, and `|result| <= |b| / 2`. Exponent
    /// `min(a.exponent, b.exponent)`. Exact. As `remainder`, no
    /// `Division_impossible` (there is no context precision). `error
    /// .DivisionByZero` on `b = 0`.
    pub fn remainderNear(allocator: Allocator, a: BigDecimal, b: BigDecimal) DivError!BigDecimal {
        if (b.isZero()) return error.DivisionByZero;
        var al = try alignPair(allocator, a, b);
        defer al.deinit();
        var q = try Managed.init(allocator);
        defer q.deinit();
        var r = try Managed.init(allocator);
        errdefer r.deinit();
        try q.divTrunc(&r, &al.an, &al.bn); // truncated: r has a's sign
        if (!r.eqlZero()) {
            var ar = try r.clone();
            defer ar.deinit();
            ar.abs();
            var ab = try al.bn.clone();
            defer ab.deinit();
            ab.abs();
            var twice = try Managed.init(allocator);
            defer twice.deinit();
            try twice.add(&ar, &ar);
            const c = twice.toConst().order(ab.toConst());
            if (c == .gt or (c == .eq and q.isOdd())) {
                // Step to the other neighbouring multiple: toward the other side
                // of zero by |b|.
                if (r.isPositive()) try r.sub(&r, &ab) else try r.add(&r, &ab);
            }
        }
        if (r.eqlZero()) r.setSign(true);
        return .{ .coeff = r, .exponent = al.lo };
    }

    /// GDA `compare-total` for finite numbers (Python `a.compare_total(b)`):
    /// a total order. Numerically smaller is `.lt`; numerically equal values are
    /// ordered by exponent so that **`1.0` is greater than `1.00`** (a larger
    /// exponent is the greater representation of a positive value, the smaller
    /// of a negative one: `-1.0 < -1.00`). `.eq` only when value and exponent
    /// both agree. Zero has no sign here (this type surfaces no negative zero),
    /// so `0E+2 > 0.00`. Unlike `order` it distinguishes `eql` operands.
    pub fn compareTotal(allocator: Allocator, a: BigDecimal, b: BigDecimal) Error!std.math.Order {
        const num = try order(allocator, a, b);
        if (num != .eq) return num;
        const c = std.math.order(a.exponent, b.exponent);
        const negative = !a.isZero() and !a.coeff.isPositive(); // equal values: same sign
        return if (negative) c.invert() else c;
    }

    /// GDA `max-magnitude` (Python `max_mag`): the operand with the larger
    /// absolute value, as an owned clone. Equal magnitudes fall back to `max`
    /// (so `max_mag(-1.0, 1.00)` is `1.00`).
    pub fn maxMag(allocator: Allocator, a: BigDecimal, b: BigDecimal) Error!BigDecimal {
        return if (try pickMag(allocator, a, b, true)) a.clone() else b.clone();
    }

    /// GDA `min-magnitude` (Python `min_mag`): the smaller absolute value;
    /// equal magnitudes fall back to `min`.
    pub fn minMag(allocator: Allocator, a: BigDecimal, b: BigDecimal) Error!BigDecimal {
        return if (try pickMag(allocator, a, b, false)) a.clone() else b.clone();
    }

    /// GDA `adjusted`: the exponent of the most significant digit,
    /// `exponent + precision - 1` (`123E+2` is 4, `0.00123` is -3). Zero has one
    /// digit, so it is its own exponent. Fits `i64` always.
    pub fn adjusted(self: BigDecimal, allocator: Allocator) Allocator.Error!i64 {
        return @as(i64, self.exponent) + @as(i64, try self.precision(allocator)) - 1;
    }

    // -----------------------------------------------------------------
    // Text forms. `toStringAlloc`/`format` stay plain notation (zero is
    // always "0"); these are the GDA forms that keep a zero's scale.
    // -----------------------------------------------------------------

    /// GDA `to-scientific-string` (what Python's `str(Decimal)` prints):
    /// `coefficient` and exponent are shown exactly as stored. Plain notation
    /// when `exponent <= 0` and the adjusted exponent is >= -6
    /// (`123.45`, `0.000001`, **`0.00`** — zero keeps its scale), otherwise
    /// `d.dddE+n` / `dE-n` (`1.2E+3`, `1E-7`, `0E+2`). No negative zero.
    /// Round-trips through `parse` (value and exponent).
    pub fn toSci(self: BigDecimal, allocator: Allocator) Allocator.Error![]u8 {
        return self.toExpString(allocator, false);
    }

    /// GDA `to-engineering-string` (Python `to_eng_string`): like `toSci`, but
    /// the exponent is a multiple of three and 1–3 digits precede the point
    /// (`123E+3`, `1.2E+6`; `1E+1` is `10`, zero-padded; a zero is `0.00E+3`).
    pub fn toEng(self: BigDecimal, allocator: Allocator) Allocator.Error![]u8 {
        return self.toExpString(allocator, true);
    }

    fn toExpString(self: BigDecimal, allocator: Allocator, eng: bool) Allocator.Error![]u8 {
        const zero = self.isZero();
        const raw = try self.coeff.toConst().toStringAlloc(allocator, 10, .lower);
        defer allocator.free(raw);
        const neg = !zero and raw[0] == '-';
        const digits: []const u8 = if (zero) "0" else if (neg) raw[1..] else raw;

        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        if (neg) try out.append(allocator, '-');
        const e: i64 = self.exponent;
        const n: i64 = @intCast(digits.len);
        const adj = e + n - 1;
        if (e <= 0 and adj >= -6) {
            try appendPlain(&out, allocator, digits, e);
            return out.toOwnedSlice(allocator);
        }
        var sfx: [24]u8 = undefined;
        if (!eng) {
            try out.append(allocator, digits[0]);
            if (digits.len > 1) {
                try out.append(allocator, '.');
                try out.appendSlice(allocator, digits[1..]);
            }
            try out.appendSlice(allocator, std.fmt.bufPrint(&sfx, "E{s}{d}", .{ if (adj < 0) "-" else "+", @abs(adj) }) catch unreachable);
            return out.toOwnedSlice(allocator);
        }
        if (zero) {
            // The exponent rounds *up* to a multiple of three; the difference
            // becomes fractional zeros ("0E+1" is "0.00E+3").
            const ee = e + @mod(-e, 3);
            try out.append(allocator, '0');
            if (ee > e) {
                try out.append(allocator, '.');
                try out.appendNTimes(allocator, '0', @intCast(ee - e));
            }
            try out.appendSlice(allocator, std.fmt.bufPrint(&sfx, "E{s}{d}", .{ if (ee < 0) "-" else "+", @abs(ee) }) catch unreachable);
            return out.toOwnedSlice(allocator);
        }
        const m = @mod(adj, 3);
        const ee = adj - m;
        const ints: usize = @intCast(m + 1);
        if (digits.len <= ints) {
            try out.appendSlice(allocator, digits);
            try out.appendNTimes(allocator, '0', ints - digits.len);
        } else {
            try out.appendSlice(allocator, digits[0..ints]);
            try out.append(allocator, '.');
            try out.appendSlice(allocator, digits[ints..]);
        }
        if (ee != 0) try out.appendSlice(allocator, std.fmt.bufPrint(&sfx, "E{s}{d}", .{ if (ee < 0) "-" else "+", @abs(ee) }) catch unreachable);
        return out.toOwnedSlice(allocator);
    }

    /// Fixed-places plain notation: round to exactly `places` fractional digits
    /// with `mode` (`rescale` to exponent `-places`) and print it with that many
    /// digits, trailing zeros and a zero included — `1.5` at 3 places is
    /// `1.500`, `0` at 2 is `0.00`. A negative `places` rounds to
    /// tens/hundreds/… and prints an integer (`1250` at -2, `half_up`: `1300`).
    /// No negative zero (`-0.4` at 0 places is `0`). `error.Overflow` as
    /// `rescale`.
    pub fn toStringFixed(self: BigDecimal, allocator: Allocator, places: i32, mode: RoundingMode) Error![]u8 {
        const exp64: i64 = -@as(i64, places);
        if (exp64 > std.math.maxInt(i32)) return error.Overflow;
        var r = try rescale(allocator, self, @intCast(exp64), mode);
        defer r.deinit();
        const zero = r.isZero();
        const raw = try r.coeff.toConst().toStringAlloc(allocator, 10, .lower);
        defer allocator.free(raw);
        const neg = !zero and raw[0] == '-';
        const digits: []const u8 = if (zero) "0" else if (neg) raw[1..] else raw;
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        if (neg) try out.append(allocator, '-');
        if (r.exponent > 0 and zero) {
            try out.append(allocator, '0');
        } else {
            try appendPlain(&out, allocator, digits, r.exponent);
        }
        return out.toOwnedSlice(allocator);
    }

    /// `std.fmt` integration: `{f}` prints the plain notation of
    /// `toStringAlloc` (zero is `0`; use `toSci` to keep a zero's scale).
    /// Needs memory for the digits, taken from the coefficient's own
    /// allocator; a failure surfaces as `error.WriteFailed`.
    pub fn format(self: BigDecimal, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        const allocator = self.coeff.allocator;
        const s = self.toStringAlloc(allocator) catch return error.WriteFailed;
        defer allocator.free(s);
        try writer.writeAll(s);
    }
};

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// A finite `f64` as sign × `m` × 2^`e`, `m` odd (or 0 with `e == 0`).
/// Pure bit inspection — no floating-point arithmetic. Shared with root.zig's
/// `Decimal.fromFloat`; not part of the public API (root.zig does not
/// re-export it).
pub const F64Binary = struct { neg: bool, m: u64, e: i32 };

pub fn f64Binary(x: f64) error{NotFinite}!F64Binary {
    const bits: u64 = @bitCast(x);
    const neg = (bits >> 63) != 0;
    const exp_bits: u32 = @intCast((bits >> 52) & 0x7ff);
    const frac: u64 = bits & ((@as(u64, 1) << 52) - 1);
    if (exp_bits == 0x7ff) return error.NotFinite; // NaN or ±Inf
    var m: u64 = undefined;
    var e: i32 = undefined;
    if (exp_bits == 0) {
        m = frac; // subnormal (or zero): frac × 2^-1074
        e = -1074;
    } else {
        m = frac | (@as(u64, 1) << 52); // normal: (2^52 + frac) × 2^(exp - 1075)
        e = @as(i32, @intCast(exp_bits)) - 1075;
    }
    if (m == 0) return .{ .neg = neg, .m = 0, .e = 0 };
    const tz: u6 = @intCast(@ctz(m));
    return .{ .neg = neg, .m = m >> tz, .e = e + @as(i32, tz) };
}

/// A finite `f64` as sign × `digits` × 10^`exp10`, `digits` the shortest
/// decimal significand that round-trips (what Zig's `{d}`/`{e}` print;
/// ≤ 17 digits, no trailing zeros except for the value 0). Shared with
/// root.zig; not re-exported.
pub const F64Decimal = struct { neg: bool, digits: u64, exp10: i32 };

pub fn f64Shortest(x: f64) error{NotFinite}!F64Decimal {
    if (!std.math.isFinite(x)) return error.NotFinite;
    // Scientific, full precision (no `precision` option) = shortest
    // round-trip: "-1.5e0", "1e-1", "5e-324", "1.7976931348623157e308".
    var buf: [std.fmt.float.min_buffer_size]u8 = undefined;
    const text = std.fmt.float.render(&buf, x, .{ .mode = .scientific }) catch unreachable; // 53 bytes always suffice
    var i: usize = 0;
    const neg = text[0] == '-';
    if (neg) i += 1;
    var digits: u64 = 0;
    var frac_digits: i32 = 0;
    var seen_dot = false;
    while (text[i] != 'e') : (i += 1) {
        if (text[i] == '.') {
            seen_dot = true;
            continue;
        }
        digits = digits * 10 + (text[i] - '0');
        if (seen_dot) frac_digits += 1;
    }
    const exp = std.fmt.parseInt(i32, text[i + 1 ..], 10) catch unreachable; // "e" + optional '-' + digits
    return .{ .neg = neg, .digits = digits, .exp10 = if (digits == 0) 0 else exp - frac_digits };
}

/// Plain-notation body for an unsigned digit string at `exponent`: digits and
/// zeros for `exponent >= 0`, otherwise the point inserted (leading `0.` and
/// zero padding when the digits are fewer than the fractional places).
fn appendPlain(out: *std.ArrayList(u8), allocator: Allocator, digits: []const u8, exponent: i64) Allocator.Error!void {
    if (exponent >= 0) {
        try out.appendSlice(allocator, digits);
        try out.appendNTimes(allocator, '0', @intCast(exponent));
        return;
    }
    const frac: usize = @intCast(-exponent);
    if (digits.len > frac) {
        const int_len = digits.len - frac;
        try out.appendSlice(allocator, digits[0..int_len]);
        try out.append(allocator, '.');
        try out.appendSlice(allocator, digits[int_len..]);
    } else {
        try out.appendSlice(allocator, "0.");
        try out.appendNTimes(allocator, '0', frac - digits.len);
        try out.appendSlice(allocator, digits);
    }
}

/// Both operands' coefficients widened (exactly) to the smaller exponent.
const Aligned = struct {
    an: Managed,
    bn: Managed,
    lo: i32,

    fn deinit(self: *Aligned) void {
        self.an.deinit();
        self.bn.deinit();
    }
};

fn alignPair(allocator: Allocator, a: BigDecimal, b: BigDecimal) BigDecimal.Error!Aligned {
    const lo = @min(a.exponent, b.exponent);
    var an = if (a.exponent == lo)
        try a.coeff.clone()
    else
        try scaleUp(allocator, &a.coeff, try alignShift(a.exponent, lo));
    errdefer an.deinit();
    const bn = if (b.exponent == lo)
        try b.coeff.clone()
    else
        try scaleUp(allocator, &b.coeff, try alignShift(b.exponent, lo));
    return .{ .an = an, .bn = bn, .lo = lo };
}

/// `max_mag`/`min_mag` operand selection (`true` = `a`): larger/smaller
/// absolute value; equal magnitudes defer to the `max`/`min` rule.
fn pickMag(allocator: Allocator, a: BigDecimal, b: BigDecimal, want_max: bool) BigDecimal.Error!bool {
    var aa = try a.clone();
    defer aa.deinit();
    aa.absVal();
    var bb = try b.clone();
    defer bb.deinit();
    bb.absVal();
    switch (try BigDecimal.order(allocator, aa, bb)) {
        .gt => return want_max,
        .lt => return !want_max,
        .eq => return pickA(allocator, a, b, want_max),
    }
}

/// After rounding up, a coefficient can have grown to `prec + 1` digits
/// (`99 + 1 = 100`): it is then exactly `10^prec`, so drop one trailing zero
/// into the exponent.
fn foldCarry(allocator: Allocator, q: *Managed, exp: *i64, prec: u32) Allocator.Error!void {
    if ((try (BigDecimal{ .coeff = q.*, .exponent = 0 }).precision(allocator)) <= prec) return;
    var ten = try Managed.initSet(allocator, 10);
    defer ten.deinit();
    var quo = try Managed.init(allocator);
    defer quo.deinit();
    var rem = try Managed.init(allocator);
    defer rem.deinit();
    try quo.divTrunc(&rem, q, &ten);
    std.debug.assert(rem.eqlZero());
    q.swap(&quo);
    exp.* += 1;
}

/// The rounding decision for a **nonzero** remainder `r` of `q = ⌊num/den⌋`
/// (`result_neg`: sign of the eventual result), applied to `q` in place.
/// Shared by `roundedDivMag`, `roundToPrecision` and `divPrec`.
fn applyRounding(
    allocator: Allocator,
    q: *Managed,
    r: *const Managed,
    den: *const Managed,
    result_neg: bool,
    mode: RoundingMode,
) Allocator.Error!void {
    var two_r = try Managed.init(allocator);
    defer two_r.deinit();
    try two_r.add(r, r);
    const half = two_r.order(den.*);
    if (roundBump(mode, half, q.isOdd(), try lastDigit05(allocator, mode, q), result_neg)) try q.addScalar(q, 1);
}

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

// ---------------------------------------------------------------------------
// Transcendental-function support. Everything is integer fixed point:
// a value is an integer `v` meaning v * 10^-w, carried with a conservative
// absolute error bound `err` (in units of 10^-w) that every step adds to.
// The final rounding is decided by rounding BOTH ends of [v-err, v+err]
// (Ziv): if they agree the true value rounds the same; otherwise the caller
// raises the working precision and tries again.
// ---------------------------------------------------------------------------

fn checkTrPrec(prec: u32) error{ InvalidPrecision, PrecisionTooLarge }!void {
    if (prec == 0) return error.InvalidPrecision;
    if (prec > BigDecimal.max_transcendental_prec) return error.PrecisionTooLarge;
}

fn digitsOf(allocator: Allocator, m: *const Managed) Allocator.Error!u32 {
    return (BigDecimal{ .coeff = m.*, .exponent = 0 }).precision(allocator);
}

/// `round(a, prec, mode)` of a value with `error.InvalidPrecision` ruled out.
fn roundPrec(allocator: Allocator, a: BigDecimal, prec: u32, mode: RoundingMode) BigDecimal.Error!BigDecimal.Rounded {
    return BigDecimal.roundToPrecision(allocator, a, prec, mode) catch |e| switch (e) {
        error.InvalidPrecision => unreachable,
        else => |x| return x,
    };
}

/// A result that is mathematically inexact: always flagged so, with `rounded`.
fn roundedInexact(allocator: Allocator, v: BigDecimal, prec: u32, mode: RoundingMode) BigDecimal.Error!BigDecimal.Rounded {
    var r = try roundPrec(allocator, v, prec, mode);
    r.inexact = true;
    r.rounded = true;
    return r;
}

fn one_exact(allocator: Allocator) Allocator.Error!BigDecimal.Rounded {
    return .{ .value = .{ .coeff = try Managed.initSet(allocator, 1), .exponent = 0 }, .inexact = false, .rounded = false };
}

fn zero_exact(allocator: Allocator) Allocator.Error!BigDecimal.Rounded {
    return .{ .value = .{ .coeff = try Managed.init(allocator), .exponent = 0 }, .inexact = false, .rounded = false };
}

/// `1` written with `prec` digits (`1.0000`), flagged inexact+rounded: what
/// Python returns for `1 ** 0.5`.
fn paddedOne(allocator: Allocator, prec: u32) BigDecimal.Error!BigDecimal.Rounded {
    var c = try pow10(allocator, prec - 1);
    errdefer c.deinit();
    return .{ .value = .{ .coeff = c, .exponent = -@as(i32, @intCast(prec - 1)) }, .inexact = true, .rounded = true };
}

fn isExactlyOne(allocator: Allocator, a: BigDecimal) BigDecimal.Error!bool {
    var n = try BigDecimal.normalize(allocator, a);
    defer n.deinit();
    return n.exponent == 0 and (n.coeff.toInt(u8) catch 0) == 1;
}

/// The (already normalized, integer-valued) `y` as an `i32` if it fits.
fn smallInt(allocator: Allocator, y: BigDecimal) BigDecimal.Error!?i32 {
    if (y.exponent > 10) return null;
    var c = try scaleUp(allocator, &y.coeff, @intCast(y.exponent));
    defer c.deinit();
    return c.toInt(i32) catch null;
}

const Fx = struct {
    v: Managed,
    err: u128,
    fn deinit(self: *Fx) void {
        self.v.deinit();
    }
};

const ExpOut = struct {
    /// value = man * 10^exp10, within `err` units of the last place of `man`.
    man: Managed,
    err: u128,
    exp10: i64,
    fn deinit(self: *ExpOut) void {
        self.man.deinit();
    }
};

/// out = trunc(a * b / den)
fn mulDivTrunc(allocator: Allocator, out: *Managed, a: *const Managed, b: *const Managed, den: *const Managed) Allocator.Error!void {
    var p = try Managed.init(allocator);
    defer p.deinit();
    try p.mul(a, b);
    var r = try Managed.init(allocator);
    defer r.deinit();
    try out.divTrunc(&r, &p, den);
}

/// Σ z^(2k+1)/(2k+1) over k >= 0, for |z| <= 0.2 at scale `s` = 10^w, summed
/// until the power underflows to zero. Per term the error is below 4 units
/// (floor in the power and in the division, damped by z^2 <= 0.04); the tail
/// after the last term is below 3 units; an error `z_err` in z moves the sum
/// by at most 1.5 * z_err (derivative 1/(1-z^2)).
fn atanhSeries(allocator: Allocator, z: *const Managed, s: *const Managed, z_err: u128) BigDecimal.Error!Fx {
    var z2 = try Managed.init(allocator);
    defer z2.deinit();
    try mulDivTrunc(allocator, &z2, z, z, s);
    var zp = try z.clone();
    defer zp.deinit();
    var sum = try Managed.init(allocator);
    errdefer sum.deinit();
    var term = try Managed.init(allocator);
    defer term.deinit();
    var rem = try Managed.init(allocator);
    defer rem.deinit();
    var div = try Managed.init(allocator);
    defer div.deinit();
    var k: u64 = 0;
    while (!zp.eqlZero()) : (k += 1) {
        try div.set(2 * k + 1);
        try term.divTrunc(&rem, &zp, &div);
        try sum.add(&sum, &term);
        try mulDivTrunc(allocator, &zp, &zp, &z2, s);
    }
    return .{ .v = sum, .err = 4 * @as(u128, k) + 10 + (3 * z_err + 1) / 2 };
}

const LnConsts = struct {
    ln2: Fx,
    ln10: Fx,
    fn deinit(self: *LnConsts) void {
        self.ln2.deinit();
        self.ln10.deinit();
    }
};

/// ln 2 = 2 atanh(1/3) and ln 10 = 3 ln 2 + 2 atanh(1/9) at scale `s` = 10^w.
fn lnConsts(allocator: Allocator, s: *const Managed) BigDecimal.Error!LnConsts {
    var rem = try Managed.init(allocator);
    defer rem.deinit();
    var d = try Managed.initSet(allocator, 3);
    defer d.deinit();
    var z = try Managed.init(allocator);
    defer z.deinit();
    try z.divTrunc(&rem, s, &d);
    var l2 = try atanhSeries(allocator, &z, s, 1);
    errdefer l2.deinit();
    try l2.v.add(&l2.v, &l2.v);
    l2.err *= 2;

    try d.set(9);
    try z.divTrunc(&rem, s, &d);
    var s9 = try atanhSeries(allocator, &z, s, 1);
    defer s9.deinit();
    var l10 = try Managed.init(allocator);
    errdefer l10.deinit();
    try d.set(3);
    try l10.mul(&l2.v, &d);
    try l10.add(&l10, &s9.v);
    try l10.add(&l10, &s9.v);
    return .{ .ln2 = l2, .ln10 = .{ .v = l10, .err = 3 * l2.err + 2 * s9.err } };
}

fn digitsU64(n: u64) u32 {
    var d: u32 = 1;
    var x = n;
    while (x >= 10) : (x /= 10) d += 1;
    return d;
}

/// acc += k * v
fn addScaled(allocator: Allocator, acc: *Managed, v: *const Managed, k: i64) Allocator.Error!void {
    var kk = try Managed.initSet(allocator, k);
    defer kk.deinit();
    var t = try Managed.init(allocator);
    defer t.deinit();
    try t.mul(v, &kk);
    try acc.add(acc, &t);
}

/// ln(a) for a > 0 at scale `w_out`, absolute error `err` units. Computed at
/// a few more digits (room for the k*ln10 term) and truncated.
fn lnFixed(allocator: Allocator, a: BigDecimal, w_out: u32) BigDecimal.Error!Fx {
    const d: u32 = try a.precision(allocator);
    // a = m * 10^a1 with m = coeff / 10^d in [0.1, 1)
    const a1: i64 = @as(i64, a.exponent) + d;
    const extra: u32 = digitsU64(@abs(a1)) + 4;
    const w: u32 = w_out + extra;
    var s = try pow10(allocator, w);
    defer s.deinit();

    // M = m * 10^w (exact when the coefficient has at most w digits).
    var m = try Managed.init(allocator);
    defer m.deinit();
    var m_err: u128 = 0;
    if (d <= w) {
        var up = try scaleUp(allocator, &a.coeff, w - d);
        m.swap(&up);
        up.deinit();
    } else {
        var dd = try pow10(allocator, d - w);
        defer dd.deinit();
        var rem = try Managed.init(allocator);
        defer rem.deinit();
        try m.divTrunc(&rem, &a.coeff, &dd);
        m_err = 1;
    }
    // Scale by 2^i so that m * 2^i lies in [0.707, 1.414).
    var i: u6 = 0;
    {
        const thr = [_]u32{ 707, 354, 177 };
        var m1000 = try Managed.init(allocator);
        defer m1000.deinit();
        var t = try Managed.initSet(allocator, 1000);
        defer t.deinit();
        try m1000.mul(&m, &t);
        while (i < 3) : (i += 1) {
            try t.set(thr[i]);
            var st = try Managed.init(allocator);
            defer st.deinit();
            try st.mul(&s, &t);
            if (m1000.order(st) != .lt) break;
        }
    }
    try m.shiftLeft(&m, i);
    const z_err: u128 = 1 + (m_err << i);

    var num = try Managed.init(allocator);
    defer num.deinit();
    try num.sub(&m, &s);
    var den = try Managed.init(allocator);
    defer den.deinit();
    try den.add(&m, &s);
    var z = try Managed.init(allocator);
    defer z.deinit();
    try mulDivTrunc(allocator, &z, &num, &s, &den);

    var series = try atanhSeries(allocator, &z, &s, z_err);
    defer series.deinit();
    var total = try Managed.init(allocator);
    errdefer total.deinit();
    try total.add(&series.v, &series.v);
    var err: u128 = 2 * series.err;

    if (i != 0 or a1 != 0) {
        var c = try lnConsts(allocator, &s);
        defer c.deinit();
        if (i != 0) {
            try addScaled(allocator, &total, &c.ln2.v, -@as(i64, i));
            err += @as(u128, i) * c.ln2.err;
        }
        if (a1 != 0) {
            try addScaled(allocator, &total, &c.ln10.v, a1);
            err += @as(u128, @abs(a1)) * c.ln10.err;
        }
    }

    // Back to scale w_out.
    var tdiv = try pow10(allocator, extra);
    defer tdiv.deinit();
    var rem = try Managed.init(allocator);
    defer rem.deinit();
    var out = try Managed.init(allocator);
    errdefer out.deinit();
    try out.divTrunc(&rem, &total, &tdiv);
    total.deinit();
    const div_u: u128 = std.math.pow(u128, 10, extra);
    return .{ .v = out, .err = (err + div_u - 1) / div_u + 1 };
}

/// log10(a) = ln(a) / ln(10) at scale `w`.
fn log10Fixed(allocator: Allocator, a: BigDecimal, w: u32) BigDecimal.Error!Fx {
    var l = try lnFixed(allocator, a, w);
    defer l.deinit();
    var s = try pow10(allocator, w);
    defer s.deinit();
    var c = try lnConsts(allocator, &s);
    defer c.deinit();
    var q = try Managed.init(allocator);
    errdefer q.deinit();
    try mulDivTrunc(allocator, &q, &l.v, &s, &c.ln10.v);
    // |q| in whole units, rounded up, scales the error of ln10.
    var qa = try q.clone();
    defer qa.deinit();
    qa.abs();
    var whole = try Managed.init(allocator);
    defer whole.deinit();
    var rem = try Managed.init(allocator);
    defer rem.deinit();
    try whole.divTrunc(&rem, &qa, &s);
    const qw: u128 = (whole.toInt(u64) catch std.math.maxInt(u64)) + 1;
    return .{ .v = q, .err = (l.err + qw * c.ln10.err) / 2 + 3 };
}

/// The decimal `a` as a fixed-point integer at scale `w` (error 0 or 1).
fn scaleToFixed(allocator: Allocator, a: BigDecimal, w: u32) BigDecimal.Error!Fx {
    const shift: i64 = @as(i64, a.exponent) + w;
    if (shift >= 0) {
        if (shift > BigDecimal.max_align_shift) return error.Overflow;
        return .{ .v = try scaleUp(allocator, &a.coeff, @intCast(shift)), .err = 0 };
    }
    if (-shift > BigDecimal.max_align_shift) {
        // Far below the working precision: truncates to zero (error 1 unit).
        return .{ .v = try Managed.init(allocator), .err = 1 };
    }
    var d = try pow10(allocator, @intCast(-shift));
    defer d.deinit();
    var q = try Managed.init(allocator);
    errdefer q.deinit();
    var rem = try Managed.init(allocator);
    defer rem.deinit();
    try q.divTrunc(&rem, &a.coeff, &d);
    return .{ .v = q, .err = 1 };
}

/// e^t for t = T * 10^-wt (error `t_err` units of 10^-wt). Reduces
/// t = q ln10 + r, |r| <= ln10/2, sums the Taylor series of e^r at 12 more
/// digits and returns mantissa * 10^(q - w2). `error.Overflow` when |t| is so
/// large that the result exponent cannot fit `i32`.
fn expFixed(allocator: Allocator, t: *const Managed, t_err: u128, wt: u32) BigDecimal.Error!ExpOut {
    const w2: u32 = wt + 12;
    {
        const dg = try digitsOf(allocator, t);
        if (!t.eqlZero() and dg > wt + 10) return error.Overflow; // |t| >= 1e10
    }
    var s = try pow10(allocator, w2);
    defer s.deinit();
    var t2 = try scaleUp(allocator, t, 12);
    defer t2.deinit();
    var c = try lnConsts(allocator, &s);
    defer c.deinit();

    // q = round(t2 / ln10)
    var two_t = try Managed.init(allocator);
    defer two_t.deinit();
    try two_t.add(&t2, &t2);
    try two_t.add(&two_t, &c.ln10.v);
    var two_l = try Managed.init(allocator);
    defer two_l.deinit();
    try two_l.add(&c.ln10.v, &c.ln10.v);
    var qm = try Managed.init(allocator);
    defer qm.deinit();
    var rem = try Managed.init(allocator);
    defer rem.deinit();
    try qm.divFloor(&rem, &two_t, &two_l);
    const q: i64 = qm.toInt(i64) catch return error.Overflow;

    var r = try t2.clone();
    defer r.deinit();
    {
        var qq = try Managed.initSet(allocator, q);
        defer qq.deinit();
        var prod = try Managed.init(allocator);
        defer prod.deinit();
        try prod.mul(&c.ln10.v, &qq);
        try r.sub(&r, &prod);
    }
    const rho: u128 = t_err * std.math.pow(u128, 10, 12) + @as(u128, @abs(q)) * c.ln10.err;

    var sum = try s.clone();
    errdefer sum.deinit();
    var term = try s.clone();
    defer term.deinit();
    var kk = try Managed.init(allocator);
    defer kk.deinit();
    var tq = try Managed.init(allocator);
    defer tq.deinit();
    var k: u64 = 1;
    while (true) : (k += 1) {
        try mulDivTrunc(allocator, &term, &term, &r, &s);
        try kk.set(k);
        try tq.divTrunc(&rem, &term, &kk);
        term.swap(&tq);
        if (term.eqlZero()) break;
        try sum.add(&sum, &term);
    }
    const err: u128 = 2 * @as(u128, k) + 10 + (34 * rho + 9) / 10;
    const exp10: i64 = q - @as(i64, w2);
    const dg: i64 = try digitsOf(allocator, &sum);
    if (exp10 < std.math.minInt(i32) or exp10 + dg > std.math.maxInt(i32) - 1) return error.Overflow;
    return .{ .man = sum, .err = err, .exp10 = exp10 };
}

/// Round both ends of man +- err (times 10^exp10, negated when `neg`) to
/// `prec` digits; the rounding is decided when they agree, else null.
fn decideInterval(allocator: Allocator, man: *const Managed, err: u128, exp10: i64, neg: bool, prec: u32, mode: RoundingMode) BigDecimal.Error!?BigDecimal.Rounded {
    if (exp10 < std.math.minInt(i32) or exp10 > std.math.maxInt(i32)) return error.Overflow;
    var e = try Managed.initSet(allocator, err);
    defer e.deinit();
    var lo = try Managed.init(allocator);
    defer lo.deinit();
    var hi = try Managed.init(allocator);
    defer hi.deinit();
    try lo.sub(man, &e);
    try hi.add(man, &e);
    if (lo.eqlZero() or hi.eqlZero() or lo.isPositive() != hi.isPositive()) return null;
    if (neg) {
        lo.negate();
        hi.negate();
    }
    const bl = BigDecimal{ .coeff = lo, .exponent = @intCast(exp10) };
    const bh = BigDecimal{ .coeff = hi, .exponent = @intCast(exp10) };
    if ((try bl.precision(allocator)) <= prec or (try bh.precision(allocator)) <= prec) return null;
    var rl = try roundPrec(allocator, bl, prec, mode);
    errdefer rl.deinit();
    var rh = try roundPrec(allocator, bh, prec, mode);
    defer rh.deinit();
    if (rl.value.exponent != rh.value.exponent or rl.value.coeff.order(rh.value.coeff) != .eq) {
        rl.deinit();
        return null;
    }
    rl.inexact = true;
    rl.rounded = true;
    return rl;
}

/// When `base^y` (y = p/q, non-integer) is itself a decimal number, the
/// Ziv interval straddles that number forever in the directed modes (and at a
/// tie). Test the two candidates the interval points at -- the midpoint
/// rounded to `prec` and to `prec + 1` digits -- for exactness by raising to
/// the integer power q (candidate^q == base^p), and round the exact value.
fn exactPowerCandidate(allocator: Allocator, base: BigDecimal, y: BigDecimal, e: *const ExpOut, prec: u32, mode: RoundingMode) BigDecimal.Error!?BigDecimal.Rounded {
    if (y.exponent < -18 or e.exp10 < std.math.minInt(i32) or e.exp10 > std.math.maxInt(i32)) return null;
    // y = coeff * 10^-k = p / q in lowest terms.
    const k: u32 = @intCast(-y.exponent);
    var ten_k = try pow10(allocator, k);
    defer ten_k.deinit();
    var g = try Managed.init(allocator);
    defer g.deinit();
    try g.gcd(&y.coeff, &ten_k);
    var rem = try Managed.init(allocator);
    defer rem.deinit();
    var p = try Managed.init(allocator);
    defer p.deinit();
    try p.divTrunc(&rem, &y.coeff, &g);
    var qd = try Managed.init(allocator);
    defer qd.deinit();
    try qd.divTrunc(&rem, &ten_k, &g);
    const qn = qd.toInt(i32) catch return null;
    const pneg = !p.isPositive();
    var pa = try p.clone();
    defer pa.deinit();
    pa.abs();
    const pn = pa.toInt(i32) catch return null;
    const base_digits: u64 = try base.precision(allocator);
    if (base_digits * @as(u64, @intCast(pn)) > BigDecimal.max_result_digits) return null;

    const mid = BigDecimal{ .coeff = e.man, .exponent = @intCast(e.exp10) };
    const widths = [_]u32{ prec, prec + 1 };
    for (widths) |wd| {
        var cand = try roundPrec(allocator, mid, wd, .half_even);
        defer cand.deinit();
        const cd: u64 = try cand.value.precision(allocator);
        if (cd * @as(u64, @intCast(qn)) > BigDecimal.max_result_digits) continue;
        var cq = BigDecimal.pow(allocator, cand.value, qn) catch continue;
        defer cq.deinit();
        var bp = BigDecimal.pow(allocator, base, pn) catch continue;
        defer bp.deinit();
        if (pneg) {
            // cand^q * base^|p| == 1
            var prod = try BigDecimal.mul(allocator, cq, bp);
            defer prod.deinit();
            var one = try BigDecimal.fromInt(allocator, 1);
            defer one.deinit();
            if (!(try BigDecimal.eql(allocator, prod, one))) continue;
        } else if (!(try BigDecimal.eql(allocator, cq, bp))) continue;

        // Exact value found: pad to `prec` digits or round the extra digit.
        const have: u32 = try cand.value.precision(allocator);
        if (have < prec) {
            const pad = prec - have;
            var c2 = try scaleUp(allocator, &cand.value.coeff, pad);
            errdefer c2.deinit();
            const ex: i64 = @as(i64, cand.value.exponent) - pad;
            if (ex < std.math.minInt(i32)) return error.Overflow;
            return .{ .value = .{ .coeff = c2, .exponent = @intCast(ex) }, .inexact = true, .rounded = true };
        }
        return try roundedInexact(allocator, cand.value, prec, mode);
    }
    return null;
}

/// `10^k` as an exact arbitrary-precision integer. `k` is bounded by every
/// caller (`max_align_shift` for alignment, `max_result_digits` for
/// `sqrt`/`pow`) before it gets here.
fn pow10(allocator: Allocator, k: u32) Allocator.Error!Managed {
    if (!limb64 or k > pow10_by_limbs_max) {
        // Huge exponents: `pow`'s squaring wins over k/19 linear steps.
        var ten = try Managed.initSet(allocator, 10);
        defer ten.deinit();
        var r = try Managed.init(allocator);
        errdefer r.deinit();
        try r.pow(&ten, k);
        return r;
    }
    var r = try Managed.initCapacity(allocator, k / 19 + 2);
    r.setMetadata(true, pow10Into(r.limbs, k));
    return r;
}

const Limb = std.math.big.Limb;
/// The limb-level fast paths below assume 64-bit limbs (10^19 per limb, a
/// u128 in two limbs); on 32-bit targets every caller takes the general path.
const limb64 = @bitSizeOf(Limb) == 64;

/// 10^0 .. 10^19 — every power of ten a limb holds.
const pow10_limb = blk: {
    var t: [20]u64 = undefined;
    t[0] = 1;
    for (1..t.len) |i| t[i] = t[i - 1] * 10;
    break :blk t;
};

/// Above this exponent `pow10` switches to `Managed.pow` (quadratic vs. squaring).
const pow10_by_limbs_max = 2000;

/// `limbs[0..len] *= m` in place; returns the new length. `limbs` must have
/// room for one more limb.
fn mulLimbInPlace(limbs: []Limb, len: usize, m: Limb) usize {
    var carry: Limb = 0;
    for (limbs[0..len]) |*l| {
        const p = @as(u128, l.*) * m + carry;
        l.* = @truncate(p);
        carry = @intCast(p >> 64);
    }
    if (carry == 0) return len;
    limbs[len] = carry;
    return len + 1;
}

/// Write 10^k into `limbs` (at least k/19 + 2 long); returns its length.
fn pow10Into(limbs: []Limb, k: u32) usize {
    limbs[0] = pow10_limb[k % 19];
    var len: usize = 1;
    var left = k / 19;
    while (left > 0) : (left -= 1) len = mulLimbInPlace(limbs, len, pow10_limb[19]);
    return len;
}

/// Decimal digits of a positive, nonzero magnitude, without allocating up to
/// `digit_count_stack_limbs` limbs (std's `log10` divides by 10^19 once per
/// limb and allocates its scratch — it dominated `divPrec` and `sqrt`).
/// The bit length gives a lower bound `est` with 10^est <= value; the count is
/// the first d > est with value < 10^d, found by comparing against 10^d.
fn digitCount(allocator: Allocator, mag: bigint.Const) Allocator.Error!u32 {
    std.debug.assert(mag.positive and !mag.eqlZero());
    const n = mag.limbs.len;
    if (!limb64) return @intCast(try mag.log10Alloc(allocator) + 1);
    if (n == 1) return digitsOfLimb(mag.limbs[0]);
    if (n > digit_count_stack_limbs) return @intCast(try mag.log10Alloc(allocator) + 1);
    const bits: u64 = @as(u64, n) * 64 - @clz(mag.limbs[n - 1]);
    // 78913 / 2^18 < log10(2): a lower bound on floor((bits - 1) * log10 2).
    const est: u32 = @intCast(((bits - 1) * 78913) >> 18);
    var buf: [digit_count_stack_limbs + 4]Limb = undefined;
    var d: u32 = est + 1;
    var p: bigint.Const = .{ .limbs = buf[0..pow10Into(&buf, d)], .positive = true };
    while (mag.order(p) != .lt) : (d += 1) {
        p.limbs = buf[0..mulLimbInPlace(&buf, p.limbs.len, 10)];
    }
    return d;
}

const digit_count_stack_limbs = 64;

// ---------------------------------------------------------------------------
// Two-limb fast paths. A coefficient of up to 38 digits (Python's default
// context is 28) fits a u128; there `add`, `mul` and `divPrec` run on
// machine integers instead of `std.math.big.int`, whose per-call set-up,
// scratch allocations and generic long division cost several times the
// arithmetic at this size. Every path computes exactly what the general one
// does (the tests cross-check them on random operands).
// ---------------------------------------------------------------------------

/// The magnitude of `c` when it fits two limbs.
fn smallMag(c: *const Managed) ?u128 {
    if (!limb64) return null;
    const n = c.len();
    if (n > 2) return null;
    const hi: u128 = if (n == 2) c.limbs[1] else 0;
    return (hi << 64) | c.limbs[0];
}

/// A new `Managed` holding `±v`.
fn managedFromU256(allocator: Allocator, v: u256, negative: bool) Allocator.Error!Managed {
    var r = try Managed.initCapacity(allocator, 4);
    var len: usize = 0;
    var x = v;
    while (true) {
        r.limbs[len] = @truncate(x);
        len += 1;
        x >>= 64;
        if (x == 0) break;
    }
    r.setMetadata(!negative or v == 0, len);
    return r;
}

fn digitsOfU128(v: u128) u32 {
    if (v >> 64 == 0) return digitsOfLimb(@intCast(v));
    var d: u32 = 20;
    while (d < 39 and v >= pow10_u128[d]) d += 1;
    return d;
}

/// 10^0 .. 10^38.
const pow10_u128 = blk: {
    var t: [39]u128 = undefined;
    t[0] = 1;
    for (1..t.len) |i| t[i] = t[i - 1] * 10;
    break :blk t;
};

/// 10^0 .. 10^76.
const pow10_u256 = blk: {
    var t: [77]u256 = undefined;
    t[0] = 1;
    for (1..t.len) |i| t[i] = t[i - 1] * 10;
    break :blk t;
};

/// `n / d` and `n % d` for a quotient that fits a u128 (`n < d·2^128`):
/// Knuth's algorithm D with 64-bit digits, the remainder kept as a u256.
fn divWide(n: u256, d: u128) struct { q: u128, r: u128 } {
    std.debug.assert(d != 0 and n >> 128 < d);
    if (n >> 128 == 0) {
        const a: u128 = @intCast(n);
        return .{ .q = a / d, .r = a % d };
    }
    if (d >> 64 == 0) {
        const b: u64 = @intCast(d);
        var rem: u64 = 0;
        var q: u256 = 0;
        var i: u9 = 256;
        while (i > 0) {
            i -= 64;
            const cur = (@as(u128, rem) << 64) | @as(u64, @truncate(n >> @intCast(i)));
            const ql: u64 = @intCast(cur / b);
            rem = @intCast(cur - @as(u128, ql) * b);
            q |= @as(u256, ql) << @intCast(i);
        }
        return .{ .q = @intCast(q), .r = rem };
    }
    // Normalise: the divisor's top bit set; n < d·2^128 keeps n·2^sh in u256.
    const sh: u7 = @intCast(@clz(d));
    const dn: u128 = d << sh;
    var rem: u256 = n << sh;
    const v1: u64 = @intCast(dn >> 64);
    const v0: u64 = @truncate(dn);
    var q: u128 = 0;
    var j: u9 = 64;
    while (true) {
        // Estimate the quotient digit from the top two remainder digits.
        const top: u128 = @truncate(rem >> @intCast(j + 64));
        var qhat: u128 = top / v1;
        var rhat: u128 = top - qhat * v1;
        const below: u64 = @truncate(rem >> @intCast(j));
        while (qhat >> 64 != 0 or qhat * v0 > ((rhat << 64) | below)) {
            qhat -= 1;
            rhat += v1;
            if (rhat >> 64 != 0) break;
        }
        var prod: u256 = (@as(u256, qhat) * dn) << @intCast(j);
        while (prod > rem) {
            qhat -= 1;
            prod -= @as(u256, dn) << @intCast(j);
        }
        rem -= prod;
        q |= qhat << @intCast(j);
        if (j == 0) break;
        j -= 64;
    }
    return .{ .q = q, .r = @intCast(rem >> sh) };
}

/// `a + b` (signed), straight on the limbs: `Managed.add`'s generic set-up
/// cost about as much as the carry loop itself at a few limbs.
fn addSigned(allocator: Allocator, a: *const Managed, b: *const Managed) Allocator.Error!Managed {
    const al = a.limbs[0..a.len()];
    const bl = b.limbs[0..b.len()];
    const ap = a.isPositive();
    const bp = b.isPositive();
    var r = try Managed.initCapacity(allocator, @max(al.len, bl.len) + 1);
    if (ap == bp) {
        const big_, const small_ = if (al.len >= bl.len) .{ al, bl } else .{ bl, al };
        var carry: u1 = 0;
        for (big_, 0..) |x, i| {
            const y: Limb = if (i < small_.len) small_[i] else 0;
            const s1 = @addWithOverflow(x, y);
            const s2 = @addWithOverflow(s1[0], carry);
            r.limbs[i] = s2[0];
            carry = s1[1] | s2[1];
        }
        var len = big_.len;
        if (carry != 0) {
            r.limbs[len] = 1;
            len += 1;
        }
        r.setMetadata(ap, len);
        return r;
    }
    // Opposite signs: the larger magnitude minus the smaller, its sign.
    const ord = (bigint.Const{ .limbs = al, .positive = true }).orderAbs(.{ .limbs = bl, .positive = true });
    if (ord == .eq) {
        r.limbs[0] = 0;
        r.setMetadata(true, 1);
        return r;
    }
    const big_, const small_, const positive = if (ord == .gt) .{ al, bl, ap } else .{ bl, al, bp };
    var borrow: u1 = 0;
    for (big_, 0..) |x, i| {
        const y: Limb = if (i < small_.len) small_[i] else 0;
        const d1 = @subWithOverflow(x, y);
        const d2 = @subWithOverflow(d1[0], borrow);
        r.limbs[i] = d2[0];
        borrow = d1[1] | d2[1];
    }
    std.debug.assert(borrow == 0);
    var len = big_.len;
    while (len > 1 and r.limbs[len - 1] == 0) len -= 1;
    r.setMetadata(positive, len);
    return r;
}

/// ⌊√n⌋ for a positive `n`: Brent and Zimmermann's SqrtInt (as in std's
/// `Managed.sqrt`), started from a double-precision estimate instead of
/// 2^⌈bits/2⌉. The start is still ≥ ⌊√n⌋, which the loop needs, but has ~52
/// correct bits instead of one, so two or three divisions replace about
/// log2(bits) — the dominant cost of `BigDecimal.sqrt`.
fn isqrt(allocator: Allocator, n: *const Managed) Allocator.Error!Managed {
    std.debug.assert(n.isPositive() and !n.eqlZero());
    const bits = n.toConst().bitCountAbs();
    // top = ⌊n / 2^e⌋ with e even and top below 2^106: √n < (√top + 1)·2^(e/2),
    // and +2 covers the double's rounding of √top (≤ 2^53, so ±1 at most).
    const e: usize = if (bits > 104) (bits - 104 + 1) & ~@as(usize, 1) else 0;
    var top: u128 = 0;
    {
        var shifted = try Managed.init(allocator);
        defer shifted.deinit();
        try shifted.shiftRight(n, e);
        top = shifted.toInt(u128) catch unreachable;
    }
    const est: u128 = @as(u128, @intFromFloat(@sqrt(@as(f64, @floatFromInt(top))))) + 2;
    var s = try Managed.initSet(allocator, est);
    errdefer s.deinit();
    try s.shiftLeft(&s, e / 2);
    var t = try Managed.init(allocator);
    defer t.deinit();
    var rem = try Managed.init(allocator);
    defer rem.deinit();
    var u = try Managed.init(allocator);
    defer u.deinit();
    while (true) {
        try t.divTrunc(&rem, n, &s);
        try t.add(&t, &s);
        try u.shiftRight(&t, 1);
        if (u.toConst().order(s.toConst()).compare(.gte)) return s;
        s.swap(&u);
    }
}

/// `divPrec` for two-limb operands and `prec <= 37`; null when the operands
/// do not fit (the caller takes the general path).
fn divPrecSmall(
    allocator: Allocator,
    a: BigDecimal,
    b: BigDecimal,
    prec: u32,
    mode: RoundingMode,
    ideal: i64,
) Allocator.Error!?BigDecimal.Rounded {
    if (prec > 37) return null;
    const num = smallMag(&a.coeff) orelse return null;
    const den = smallMag(&b.coeff) orelse return null;
    const result_neg = a.coeff.isPositive() != b.coeff.isPositive();
    const da: i64 = digitsOfU128(num);
    const db: i64 = digitsOfU128(den);
    var s: i64 = @as(i64, prec) + db - da;
    var q: u128 = undefined;
    var r: u128 = undefined;
    var divisor: u128 = undefined;
    while (true) {
        if (s >= 0) {
            // num·10^s < 10^(prec+db) <= 10^75: inside u256, and q < 10^38.
            const qr = divWide(@as(u256, num) * pow10_u256[@intCast(s)], den);
            q = qr.q;
            r = qr.r;
            divisor = den;
        } else {
            // den·10^-s < 10^(da-prec) <= 10^38.
            divisor = den * pow10_u128[@intCast(-s)];
            q = num / divisor;
            r = num % divisor;
        }
        if (digitsOfU128(q) <= prec) break;
        s -= 1;
    }
    var e: i64 = ideal - s;
    const exact = r == 0;
    if (exact) {
        while (e < ideal and q % 10 == 0) {
            q /= 10;
            e += 1;
        }
    } else {
        const half: std.math.Order = if (r < divisor - r) .lt else if (r == divisor - r) .eq else .gt;
        const last = q % 10;
        if (roundBump(mode, half, q & 1 == 1, last == 0 or last == 5, result_neg)) q += 1;
        if (q == pow10_u128[prec]) {
            q /= 10;
            e += 1;
        }
    }
    if (e > std.math.maxInt(i32) or e < std.math.minInt(i32)) return null; // general path reports it
    return .{
        .value = .{ .coeff = try managedFromU256(allocator, q, result_neg), .exponent = @intCast(e) },
        .inexact = !exact,
        .rounded = !exact or e > ideal,
    };
}

fn digitsOfLimb(v: u64) u32 {
    var d: u32 = 1;
    while (d < 20 and v >= pow10_limb[d]) d += 1;
    return d;
}

/// GDA `min`/`max` operand selection: returns `true` when `a` is the answer.
///
/// The numeric comparison is the easy half. The half worth writing down is
/// the tie: when `a` and `b` are numerically equal but stored at different
/// exponents, GDA still names exactly one of them, and which one depends on
/// the sign. For `max`, a positive tie picks the larger exponent and a
/// negative tie the smaller (`max(-1.0, -1.00)` is `-1.00`, and the
/// `-0`/`-0.0` block); `min` mirrors both. Signs can only differ on a numeric tie when
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
    // negatives keeps the smaller one (`max(-1.0, -1.00)` is `-1.00`, unlike two
    // positives), and `min` mirrors both (`min(-0.100, -0.10)` is `-0.10`).
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
///   `q_05`        whether the last digit of the truncated quotient is 0 or 5,
///                 for `round_05up` (computed only when the mode needs it, see
///                 `lastDigit05`; `false` otherwise).
///   `result_neg`  sign the result will eventually carry — the directed modes
///                 `ceiling`/`floor` are the only ones that depend on it.
///
/// Callers must only reach this with a **nonzero** discarded remainder; an
/// exact result needs no decision and every mode agrees on it.
fn roundBump(mode: RoundingMode, half: std.math.Order, q_odd: bool, q_05: bool, result_neg: bool) bool {
    return switch (mode) {
        .round_05up => q_05,
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
    if (roundBump(mode, half, q.isOdd(), try lastDigit05(allocator, mode, &q), result_neg)) try q.addScalar(&q, 1);
    return q;
}

/// For `round_05up` only: is the last decimal digit of `q` 0 or 5? (One
/// `divTrunc` by 10; the limb's low bits cannot answer it because 2^64 is not
/// a multiple of 10.) Every other mode does not look at it, so it costs nothing
/// there and returns `false`.
fn lastDigit05(allocator: Allocator, mode: RoundingMode, q: *const Managed) Allocator.Error!bool {
    if (mode != .round_05up) return false;
    var ten = try Managed.initSet(allocator, 10);
    defer ten.deinit();
    var quo = try Managed.init(allocator);
    defer quo.deinit();
    var rem = try Managed.init(allocator);
    defer rem.deinit();
    try quo.divTrunc(&rem, q, &ten);
    const d = rem.toInt(u8) catch unreachable; // 0..9
    return d == 0 or d == 5;
}

// ---------------------------------------------------------------------------
// Tests — exact ops (parse/format/add/sub/mul/compare/normalize/widen-rescale)
// ---------------------------------------------------------------------------

const testing = std.testing;
const talloc = testing.allocator;

test "two-limb fast paths agree with the general ones" {
    if (!limb64) return error.SkipZigTest; // the fast paths are off on 32-bit limbs
    var prng = std.Random.DefaultPrng.init(0xdec1);
    const rnd = prng.random();
    const modes = [_]RoundingMode{ .half_even, .half_up, .half_down, .up, .down, .ceiling, .floor, .round_05up };
    var n: usize = 0;
    while (n < 20000) : (n += 1) {
        var ops: [2]BigDecimal = undefined;
        for (&ops) |*o| {
            // 1..38 digits, sign, small exponent; some exact quotients via
            // small values and powers of ten.
            const digits = rnd.intRangeAtMost(u32, 1, 38);
            var v: u128 = rnd.int(u128) % pow10_u128[digits];
            if (rnd.boolean()) v = (v % 1000) * pow10_u128[rnd.uintLessThan(u32, 30)];
            if (v == 0) v = 1; // divPrec rejects a zero divisor before the fast path
            o.* = .{ .coeff = try Managed.initSet(talloc, v), .exponent = rnd.intRangeAtMost(i32, -40, 40) };
            if (rnd.boolean()) o.coeff.negate();
        }
        defer for (&ops) |*o| o.deinit();
        const a = ops[0];
        var b = ops[1];
        if (rnd.uintLessThan(u8, 4) == 0) b.exponent = a.exponent; // exercise add's fast path
        const prec = rnd.intRangeAtMost(u32, 1, 37);
        const mode = modes[rnd.uintLessThan(usize, modes.len)];
        const ideal: i64 = @as(i64, a.exponent) - @as(i64, b.exponent);

        var fast = (try divPrecSmall(talloc, a, b, prec, mode, ideal)).?;
        defer fast.value.deinit();
        var slow = try BigDecimal.divPrecGeneral(talloc, a, b, prec, mode, ideal);
        defer slow.value.deinit();
        try testing.expect(fast.value.coeff.toConst().eql(slow.value.coeff.toConst()));
        try testing.expectEqual(slow.value.exponent, fast.value.exponent);
        try testing.expectEqual(slow.inexact, fast.inexact);
        try testing.expectEqual(slow.rounded, fast.rounded);

        // add / mul: the fast result against Managed's.
        var s_fast = try BigDecimal.add(talloc, a, b);
        defer s_fast.deinit();
        var p_fast = try BigDecimal.mul(talloc, a, b);
        defer p_fast.deinit();
        var p_slow = try Managed.init(talloc);
        defer p_slow.deinit();
        try p_slow.mul(&a.coeff, &b.coeff);
        try testing.expect(p_fast.coeff.toConst().eql(p_slow.toConst()));
        if (a.exponent == b.exponent) {
            var s_slow = try Managed.init(talloc);
            defer s_slow.deinit();
            try s_slow.add(&a.coeff, &b.coeff);
            try testing.expect(s_fast.coeff.toConst().eql(s_slow.toConst()));
        }
    }
}

test "addSigned agrees with Managed.add on multi-limb operands" {
    var prng = std.Random.DefaultPrng.init(0xadd5);
    const rnd = prng.random();
    var n: usize = 0;
    while (n < 5000) : (n += 1) {
        var ops: [2]Managed = undefined;
        for (&ops) |*o| {
            o.* = try Managed.initCapacity(talloc, 8);
            const len = rnd.intRangeAtMost(usize, 1, 8);
            for (o.limbs[0..len]) |*l| l.* = switch (rnd.uintLessThan(u8, 4)) {
                0 => 0,
                1 => std.math.maxInt(Limb),
                else => rnd.int(Limb),
            };
            var nl = len;
            while (nl > 1 and o.limbs[nl - 1] == 0) nl -= 1;
            o.setMetadata(rnd.boolean() or (nl == 1 and o.limbs[0] == 0), nl);
        }
        defer for (&ops) |*o| o.deinit();
        if (rnd.uintLessThan(u8, 8) == 0) try ops[1].copy(ops[0].toConst()); // a + a
        if (rnd.uintLessThan(u8, 8) == 0) { // a + (-a) = 0
            try ops[1].copy(ops[0].toConst());
            ops[1].negate();
        }
        var got = try addSigned(talloc, &ops[0], &ops[1]);
        defer got.deinit();
        var want = try Managed.init(talloc);
        defer want.deinit();
        try want.add(&ops[0], &ops[1]);
        try testing.expect(got.toConst().eql(want.toConst()));
    }
}

test "isqrt agrees with Managed.sqrt" {
    var prng = std.Random.DefaultPrng.init(0x5a7);
    const rnd = prng.random();
    var n: usize = 0;
    while (n < 3000) : (n += 1) {
        var x = try Managed.initCapacity(talloc, 12);
        defer x.deinit();
        const len = rnd.intRangeAtMost(usize, 1, 12);
        for (x.limbs[0..len]) |*l| l.* = rnd.int(Limb);
        if (x.limbs[len - 1] == 0) x.limbs[len - 1] = 1;
        x.setMetadata(true, len);
        // Perfect squares and their neighbours too.
        if (rnd.boolean()) {
            try x.mul(&x, &x);
            if (rnd.boolean()) try x.addScalar(&x, -1) else if (rnd.boolean()) try x.addScalar(&x, 1);
            if (x.eqlZero()) try x.set(1);
        }
        var got = try isqrt(talloc, &x);
        defer got.deinit();
        var want = try Managed.init(talloc);
        defer want.deinit();
        try want.sqrt(&x);
        try testing.expect(got.toConst().eql(want.toConst()));
    }
}

test "digitCount: every power of ten and its neighbours, up to 1300 digits" {
    var p = try Managed.initSet(talloc, 1);
    defer p.deinit();
    var ten = try Managed.initSet(talloc, 10);
    defer ten.deinit();
    var below = try Managed.init(talloc);
    defer below.deinit();
    var k: u32 = 0;
    while (k < 1300) : (k += 1) {
        try testing.expectEqual(k + 1, try digitCount(talloc, p.toConst()));
        if (k > 0) {
            try below.sub(&p, &ten);
            try below.addScalar(&below, 9); // 10^k - 1
            try testing.expectEqual(k, try digitCount(talloc, below.toConst()));
        }
        try p.mul(&p, &ten);
    }
}

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
    const huge = strRepeat("9", 40) ++ "." ++ strRepeat("1", 40);
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
// Hand-written known-answer tests for the exact add/mul/rescale paths and the
// rounded-division core (`roundedDivMag`, reached through `div`/`rescale`).
// The large generated tables (Python `decimal` as oracle) follow further down,
// in the "conformance tables" section.
//
// Trailing zeros are significant here (`1.25 + 1.25 = 2.50`, `2.5 * 4 = 10.0`):
// `toStringAlloc` keeps them, which is what these cases pin down. Zero results
// are left to the generated tables, which compare `toSci` and so see the
// exponent of a zero.
// ---------------------------------------------------------------------------

test "KAT: exact add" {
    const Case = struct { a: []const u8, b: []const u8, want: []const u8 };
    const cases = [_]Case{
        .{ .a = "1", .b = "1", .want = "2" },
        .{ .a = "5.75", .b = "3.3", .want = "9.05" },
        .{ .a = "5", .b = "-3", .want = "2" },
        .{ .a = "-5", .b = "-3", .want = "-8" },
        .{ .a = "-7", .b = "2.5", .want = "-4.5" },
        .{ .a = "0.7", .b = "0.3", .want = "1.0" },
        .{ .a = "1.25", .b = "1.25", .want = "2.50" },
        .{ .a = "1.23456789", .b = "1.00000011", .want = "2.23456800" },
    };
    for (cases) |c| {
        var a = try BigDecimal.parse(talloc, c.a);
        defer a.deinit();
        var b = try BigDecimal.parse(talloc, c.b);
        defer b.deinit();
        var got = try BigDecimal.add(talloc, a, b);
        defer got.deinit();
        expectStr(got, c.want) catch |err| {
            std.debug.print("KAT add {s} + {s} failed\n", .{ c.a, c.b });
            return err;
        };
    }
}

test "KAT: exact mul" {
    const Case = struct { a: []const u8, b: []const u8, want: []const u8 };
    const cases = [_]Case{
        .{ .a = "2", .b = "3", .want = "6" },
        .{ .a = "5", .b = "2", .want = "10" },
        .{ .a = "1.20", .b = "2", .want = "2.40" },
        .{ .a = "1.20", .b = "-2", .want = "-2.40" },
        .{ .a = "-1.20", .b = "-2", .want = "2.40" },
        .{ .a = "5.09", .b = "7.1", .want = "36.139" },
        .{ .a = "2.5", .b = "4", .want = "10.0" },
        .{ .a = "2.50", .b = "4", .want = "10.00" },
    };
    for (cases) |c| {
        var a = try BigDecimal.parse(talloc, c.a);
        defer a.deinit();
        var b = try BigDecimal.parse(talloc, c.b);
        defer b.deinit();
        var got = try BigDecimal.mul(talloc, a, b);
        defer got.deinit();
        expectStr(got, c.want) catch |err| {
            std.debug.print("KAT mul {s} * {s} failed\n", .{ c.a, c.b });
            return err;
        };
    }
}

const DivCase = struct { a: []const u8, b: []const u8, scale: i32, mode: RoundingMode, want: []const u8 };

pub const div_kat_vectors = [_]DivCase{
    .{ .a = "1", .b = "1", .scale = 0, .mode = .half_up, .want = "1" },
    .{ .a = "1", .b = "2", .scale = 1, .mode = .half_up, .want = "0.5" },
    .{ .a = "1", .b = "3", .scale = 9, .mode = .half_up, .want = "0.333333333" },
    .{ .a = "2", .b = "3", .scale = 9, .mode = .half_up, .want = "0.666666667" },
    .{ .a = "5", .b = "0.20", .scale = 0, .mode = .half_up, .want = "25" },
    // Exact half-way ties (2r == d) under half_up: the quotients above terminate or are
    // not ties, so these are the positive control for the bump-on-tie branch (a
    // mutation skipping the bump once passed the suite clean).
    .{ .a = "5", .b = "2", .scale = 0, .mode = .half_up, .want = "3" }, // 2.5 -> 3
    .{ .a = "1", .b = "2", .scale = 0, .mode = .half_up, .want = "1" }, // 0.5 -> 1
    .{ .a = "7", .b = "2", .scale = 0, .mode = .half_up, .want = "4" }, // 3.5 -> 4
};

const RescaleCase = struct { a: []const u8, exponent: i32, mode: RoundingMode, want: []const u8 };

pub const rescale_kat_vectors = [_]RescaleCase{
    .{ .a = "0.1", .exponent = -2, .mode = .half_up, .want = "0.10" }, // widening is exact
    .{ .a = "0.9", .exponent = 0, .mode = .half_up, .want = "1" },
    .{ .a = "12345.5", .exponent = 0, .mode = .half_even, .want = "12346" }, // tie, odd -> bumps to even
    .{ .a = "12346.5", .exponent = 0, .mode = .half_even, .want = "12346" }, // tie, even -> stays
    .{ .a = "12345.4", .exponent = 0, .mode = .half_even, .want = "12345" }, // below tie -> down
    .{ .a = "12345.6", .exponent = 0, .mode = .half_even, .want = "12346" }, // above tie -> up
};

test "KAT: div/rescale (roundedDivMag)" {
    for (div_kat_vectors) |c| {
        var a = try BigDecimal.parse(talloc, c.a);
        defer a.deinit();
        var b = try BigDecimal.parse(talloc, c.b);
        defer b.deinit();
        var got = try BigDecimal.div(talloc, a, b, c.scale, c.mode);
        defer got.deinit();
        expectStr(got, c.want) catch |err| {
            std.debug.print("KAT div {s} / {s} failed\n", .{ c.a, c.b });
            return err;
        };
    }
    for (rescale_kat_vectors) |c| {
        var a = try BigDecimal.parse(talloc, c.a);
        defer a.deinit();
        var got = try BigDecimal.rescale(talloc, a, c.exponent, c.mode);
        defer got.deinit();
        expectStr(got, c.want) catch |err| {
            std.debug.print("KAT rescale {s} failed\n", .{c.a});
            return err;
        };
    }
}

// ---------------------------------------------------------------------------
// Accessors, remainder, min/max — unit tests. The generated conformance tables
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
        .{ .s = strRepeat("9", 100), .want = 100 },
        .{ .s = "1" ++ strRepeat("0", 200), .want = 201 },
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
    var big_a = dec("1" ++ strRepeat("0", 200));
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

    // THE memory guard. An exponent such as 1000000007 is entirely plausible input;
    // `1.1 ^ 1000000007` has ~10^8 digits and computing it would
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
// Conformance tables — add / mul / quantize / divide / divPrec / remainder /
// min / max / square-root / power.
//
// Generated by `tools/py_conform.py` (seeded, deterministic): the operands are
// random plus designed edge classes, every expected value comes from Python's
// `decimal` module (the General Decimal Arithmetic reference implementation),
// and the files are `src/testdata/conform_*.vec`, `@embedFile`d here. Python is
// not needed at test time. Each file's header records the line format; the
// generator's header lists the contract it respects (no signed zero, no
// NaN/Infinity, integer non-negative `pow` exponents only, ...).
//
// Every check compares `toSci` and asserts the **exponent** as well, because
// for these operations the scale of the result is part of the specification:
// `remainder` takes min(ea, eb), `min`/`max` resolve a numeric tie by
// exponent, `square-root` has an ideal exponent for exact roots, and `pow`'s
// is `a.exponent × n`. A digits-only comparison would pass while all of those
// rules were wrong. The expected case count of every file is asserted, so a
// truncated file fails.
// ---------------------------------------------------------------------------

/// Line reader for `testdata/*.vec`: skips blank and `#` lines, splits the
/// rest on `|` into exactly `n` fields.
const VecReader = struct {
    it: std.mem.SplitIterator(u8, .scalar),
    line_no: usize = 0,

    fn init(data: []const u8) VecReader {
        return .{ .it = std.mem.splitScalar(u8, data, '\n') };
    }

    fn next(self: *VecReader, comptime n: usize) ?[n][]const u8 {
        while (self.it.next()) |raw| {
            self.line_no += 1;
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

/// `want` is `ERR:<name>` or a to-scientific string; `want_exp` the exponent the
/// result must carry (`-` for an error). Takes the error union of a `BigDecimal`.
fn expectVec(got_in: anytype, want: []const u8, want_exp: []const u8) !void {
    if (std.mem.startsWith(u8, want, "ERR:")) {
        if (got_in) |v| {
            var vv = v;
            vv.deinit();
            return error.ExpectedError;
        } else |err| try testing.expectEqualStrings(want[4..], @errorName(err));
        return;
    }
    var v = got_in catch |err| {
        std.debug.print("unexpected error {s}\n", .{@errorName(err)});
        return err;
    };
    defer v.deinit();
    const s = try v.toSci(talloc);
    defer talloc.free(s);
    try testing.expectEqualStrings(want, s);
    try testing.expectEqual(try std.fmt.parseInt(i32, want_exp, 10), v.exponent);
}

/// Replays `data` through `run` (one call per case, `n` fields each). Reports up
/// to 20 failing lines in one go, then fails; `count` pins the case number.
fn replay(comptime n: usize, data: []const u8, count: usize, comptime run: fn ([n][]const u8) anyerror!void) !void {
    var r = VecReader.init(data);
    var seen: usize = 0;
    var failed: usize = 0;
    while (r.next(n)) |f| : (seen += 1) {
        run(f) catch |err| {
            failed += 1;
            if (failed <= 20) {
                std.debug.print("conformance case (file line {d}) failed with {s}:", .{ r.line_no, @errorName(err) });
                for (f) |x| std.debug.print(" |{s}", .{x});
                std.debug.print("\n", .{});
            }
        };
    }
    try testing.expectEqual(@as(usize, 0), failed);
    try testing.expectEqual(count, seen); // the whole file, not a prefix
}

fn bigOf(s: []const u8) !BigDecimal {
    return BigDecimal.parse(talloc, s);
}

fn runAdd(f: [4][]const u8) anyerror!void {
    var a = try bigOf(f[0]);
    defer a.deinit();
    var b = try bigOf(f[1]);
    defer b.deinit();
    try expectVec(BigDecimal.add(talloc, a, b), f[2], f[3]);
}

fn runMul(f: [4][]const u8) anyerror!void {
    var a = try bigOf(f[0]);
    defer a.deinit();
    var b = try bigOf(f[1]);
    defer b.deinit();
    try expectVec(BigDecimal.mul(talloc, a, b), f[2], f[3]);
}

fn runQuant(f: [5][]const u8) anyerror!void {
    var a = try bigOf(f[0]);
    defer a.deinit();
    const mode = std.meta.stringToEnum(RoundingMode, f[2]).?;
    try expectVec(BigDecimal.rescale(talloc, a, try std.fmt.parseInt(i32, f[1], 10), mode), f[3], f[4]);
}

fn runDiv(f: [6][]const u8) anyerror!void {
    var a = try bigOf(f[0]);
    defer a.deinit();
    var b = try bigOf(f[1]);
    defer b.deinit();
    const mode = std.meta.stringToEnum(RoundingMode, f[3]).?;
    try expectVec(BigDecimal.div(talloc, a, b, try std.fmt.parseInt(i32, f[2], 10), mode), f[4], f[5]);
}

fn runDivPrec(f: [8][]const u8) anyerror!void {
    var a = try bigOf(f[0]);
    defer a.deinit();
    var b = try bigOf(f[1]);
    defer b.deinit();
    const mode = std.meta.stringToEnum(RoundingMode, f[3]).?;
    const got = BigDecimal.divPrec(talloc, a, b, try std.fmt.parseInt(u32, f[2], 10), mode);
    if (std.mem.startsWith(u8, f[4], "ERR:")) {
        if (got) |v| {
            var vv = v;
            vv.value.deinit();
            return error.ExpectedError;
        } else |err| return testing.expectEqualStrings(f[4][4..], @errorName(err));
    }
    var v = try got;
    defer v.deinit();
    const s = try v.value.toSci(talloc);
    defer talloc.free(s);
    try testing.expectEqualStrings(f[4], s);
    try testing.expectEqual(try std.fmt.parseInt(i32, f[5], 10), v.value.exponent);
    try testing.expectEqual(f[6][0] == '1', v.inexact);
    try testing.expectEqual(f[7][0] == '1', v.rounded);
}

fn runRem(f: [4][]const u8) anyerror!void {
    var a = try bigOf(f[0]);
    defer a.deinit();
    var b = try bigOf(f[1]);
    defer b.deinit();
    try expectVec(BigDecimal.remainder(talloc, a, b), f[2], f[3]);
}

fn runMin(f: [4][]const u8) anyerror!void {
    var a = try bigOf(f[0]);
    defer a.deinit();
    var b = try bigOf(f[1]);
    defer b.deinit();
    try expectVec(BigDecimal.min(talloc, a, b), f[2], f[3]);
}

fn runMax(f: [4][]const u8) anyerror!void {
    var a = try bigOf(f[0]);
    defer a.deinit();
    var b = try bigOf(f[1]);
    defer b.deinit();
    try expectVec(BigDecimal.max(talloc, a, b), f[2], f[3]);
}

fn runSqrt(f: [5][]const u8) anyerror!void {
    var a = try bigOf(f[0]);
    defer a.deinit();
    const mode = std.meta.stringToEnum(RoundingMode, f[2]).?;
    try expectVec(BigDecimal.sqrt(talloc, a, try std.fmt.parseInt(u32, f[1], 10), mode), f[3], f[4]);
}

fn runPow(f: [4][]const u8) anyerror!void {
    var a = try bigOf(f[0]);
    defer a.deinit();
    try expectVec(BigDecimal.pow(talloc, a, try std.fmt.parseInt(i32, f[1], 10)), f[2], f[3]);
}

test "conformance: add (exact)" {
    try replay(4, @embedFile("testdata/conform_add.vec"), COUNT_ADD, runAdd);
}

test "conformance: mul (exact)" {
    try replay(4, @embedFile("testdata/conform_mul.vec"), COUNT_MUL, runMul);
}

test "conformance: quantize / rescale, all rounding modes" {
    try replay(5, @embedFile("testdata/conform_quant.vec"), COUNT_QUANT, runQuant);
}

test "conformance: div at a given scale, all rounding modes" {
    try replay(6, @embedFile("testdata/conform_div.vec"), COUNT_DIV, runDiv);
}

test "conformance: divPrec at a given precision, all rounding modes" {
    try replay(8, @embedFile("testdata/conform_divprec.vec"), COUNT_DIVPREC, runDivPrec);
}

test "conformance: remainder" {
    try replay(4, @embedFile("testdata/conform_rem.vec"), COUNT_REM, runRem);
}

test "conformance: min" {
    try replay(4, @embedFile("testdata/conform_min.vec"), COUNT_MIN, runMin);
}

test "conformance: max" {
    try replay(4, @embedFile("testdata/conform_max.vec"), COUNT_MAX, runMax);
}

test "conformance: square root, precisions 1..60 and large, all rounding modes" {
    try replay(5, @embedFile("testdata/conform_sqrt.vec"), COUNT_SQRT, runSqrt);
}

test "conformance: pow (integer exponents, typed errors)" {
    try replay(4, @embedFile("testdata/conform_pow.vec"), COUNT_POW, runPow);
}

const COUNT_ADD = 1044;
const COUNT_MUL = 702;
const COUNT_QUANT = 5044;
const COUNT_DIV = 1700;
const COUNT_DIVPREC = 1820;
const COUNT_REM = 1272;
const COUNT_MIN = 976;
const COUNT_MAX = 976;
const COUNT_SQRT = 3411;
const COUNT_POW = 1034;

// ---------------------------------------------------------------------------
// Float bridge — every expected value below comes from an EXTERNAL oracle:
// Python 3's `decimal` module (exact `Decimal(float)` construction, `quantize`
// with each ROUND_* mode) and `float(Decimal(str))` / `float(str)` (correctly
// rounded, ties to even). The Python expression is quoted at each check; the
// modes are always listed in `RoundingMode` order:
//   [HALF_EVEN, HALF_UP, HALF_DOWN, UP, DOWN, CEILING, FLOOR].
// ---------------------------------------------------------------------------

const float_modes = [_]RoundingMode{ .half_even, .half_up, .half_down, .up, .down, .ceiling, .floor };

fn expectFromFloat(x: f64, new_scale: i32, want: [7][]const u8) !void {
    for (float_modes, want) |m, w| {
        var d = try BigDecimal.fromFloat(talloc, x, new_scale, m);
        defer d.deinit();
        expectStr(d, w) catch |err| {
            std.debug.print("fromFloat({d}, {d}, .{s}) expected {s}\n", .{ x, new_scale, @tagName(m), w });
            return err;
        };
    }
}

fn expectShortestRescaled(x: f64, new_scale: i32, want: [7][]const u8) !void {
    for (float_modes, want) |m, w| {
        var s = try BigDecimal.fromFloatShortest(talloc, x);
        defer s.deinit();
        var d = try BigDecimal.rescale(talloc, s, -new_scale, m);
        defer d.deinit();
        try expectStr(d, w);
    }
}

fn expectBits(want: f64, got: f64) !void {
    try testing.expectEqual(@as(u64, @bitCast(want)), @as(u64, @bitCast(got)));
}

fn toF(s: []const u8) !f64 {
    var d = try BigDecimal.parse(talloc, s);
    defer d.deinit();
    return d.toFloat(talloc);
}

// float(2**1024 - 2**971) == Decimal(1.7976931348623157e308), the largest finite f64.
const f64_max_digits =
    "179769313486231570814527423731704356798070567525844996598917476803157260780028538760589558632766" ++
    "878171540458953514382464234321326889464182768467546703537516986049910576551282076245490090389328" ++
    "944075868508455133942304583236903222948165808559332123348274797826204144723168738177180919299881" ++
    "250404026184124858368";
// Decimal(5e-324) — the smallest subnormal, 751 significant digits.
const f64_min_subnormal_digits =
    "0.0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
    "000000000000000000000000000000000000049406564584124654417656879286822137236505980261432476442558" ++
    "568250067550727020875186529983636163599237979656469544571773092665671035593979639877479601078187" ++
    "812630071319031140452784581716784898210368871863605699873072305000638740915356498438731247339727" ++
    "316961514003171538539807412623856559117102665855668676818703956031062493194527159149245532930545" ++
    "654440112748012970999954193198940908041656332452475714786901472678015935523861155013480352649347" ++
    "201937902681071074917033322268447533357208324319360923828934583680601060115061698097530783422773" ++
    "183292479049825247307763759272478746560847782037344696995336470179726777175851256605511991315048" ++
    "911014510378627381672509558373897335989936648099411642057026370902792427675445652290875386825064" ++
    "19718265533447265625";
// 2**1024 - 2**970: exactly half an ulp above the largest finite f64 — the
// round-half-even tie that goes UP to 2**1024, i.e. float(...) == inf.
const f64_overflow_tie_digits =
    "179769313486231580793728971405303415079934132710037826936173778980444968292764750946649017977587" ++
    "207096330286416692887910946555547851940402630657488671505820681908902000708383676273854845817711" ++
    "531764475730270069855571366959622842914819860834936475292719074168444365510704342711559699508093" ++
    "042880177904174497792";

test "float bridge: fromFloatExact is the exact binary value (Python Decimal(float))" {
    // Decimal(0.1)
    var a = try BigDecimal.fromFloatExact(talloc, 0.1);
    defer a.deinit();
    try expectStr(a, "0.1000000000000000055511151231257827021181583404541015625");
    // Decimal(0.5) — the exponent is minimal (odd significand): coeff 5, exp -1.
    var h = try BigDecimal.fromFloatExact(talloc, 0.5);
    defer h.deinit();
    try testing.expectEqual(@as(i32, -1), h.exponent);
    try expectStr(h, "0.5");
    // Decimal(-1.5), Decimal(3.0), Decimal(2.675)
    var n = try BigDecimal.fromFloatExact(talloc, -1.5);
    defer n.deinit();
    try expectStr(n, "-1.5");
    var i = try BigDecimal.fromFloatExact(talloc, 3.0);
    defer i.deinit();
    try expectStr(i, "3");
    var t = try BigDecimal.fromFloatExact(talloc, 2.675);
    defer t.deinit();
    try expectStr(t, "2.67499999999999982236431605997495353221893310546875");
    // Decimal(1e22) — an integer with trailing zeros stays exact at exponent >= 0.
    var e22 = try BigDecimal.fromFloatExact(talloc, 1e22);
    defer e22.deinit();
    try expectStr(e22, "10000000000000000000000");
    // Decimal(0.0) and Decimal(-0.0) are both zero here (no signed zero surfaced).
    var z = try BigDecimal.fromFloatExact(talloc, -@as(f64, 0.0));
    defer z.deinit();
    try testing.expect(z.isZero());
}

test "float bridge: extremes are exact (Decimal(5e-324), Decimal(1.7976931348623157e308))" {
    var lo = try BigDecimal.fromFloatExact(talloc, 5e-324);
    defer lo.deinit();
    try testing.expectEqual(@as(i32, -1074), lo.exponent);
    try expectStr(lo, f64_min_subnormal_digits);
    var hi = try BigDecimal.fromFloatExact(talloc, 1.7976931348623157e308);
    defer hi.deinit();
    try expectStr(hi, f64_max_digits);
    var neg = try BigDecimal.fromFloatExact(talloc, -1.7976931348623157e308);
    defer neg.deinit();
    const s = try neg.toStringAlloc(talloc);
    defer talloc.free(s);
    try testing.expectEqualStrings("-", s[0..1]);
    try testing.expectEqualStrings(f64_max_digits, s[1..]);
}

test "float bridge: fromFloat rounds the exact value once, with the given mode" {
    // [str(Decimal(0.1).quantize(Decimal('0.01'), m)) for m in modes]
    try expectFromFloat(0.1, 2, .{ "0.10", "0.10", "0.10", "0.11", "0.10", "0.11", "0.10" });
    // Decimal(0.125) is an exact tie at 2 places:
    // [str(Decimal(0.125).quantize(Decimal('0.01'), m)) for m in modes]
    try expectFromFloat(0.125, 2, .{ "0.12", "0.13", "0.12", "0.13", "0.12", "0.13", "0.12" });
    // [str(Decimal(-0.125).quantize(Decimal('0.01'), m)) for m in modes]
    try expectFromFloat(-0.125, 2, .{ "-0.12", "-0.13", "-0.12", "-0.13", "-0.12", "-0.12", "-0.13" });
    // The classic trap: 2.675 is stored BELOW the tie (2.67499999999999982...),
    // so half-up and half-even both give 2.67.
    // [str(Decimal(2.675).quantize(Decimal('0.01'), m)) for m in modes]
    try expectFromFloat(2.675, 2, .{ "2.67", "2.67", "2.67", "2.68", "2.67", "2.68", "2.67" });
    // [str(Decimal(-2.675).quantize(Decimal('0.01'), m)) for m in modes]
    try expectFromFloat(-2.675, 2, .{ "-2.67", "-2.67", "-2.67", "-2.68", "-2.67", "-2.67", "-2.68" });
    // Widening is exact: Decimal(0.5).quantize(Decimal('0.001')) -> 0.500
    try expectFromFloat(0.5, 3, .{ "0.500", "0.500", "0.500", "0.500", "0.500", "0.500", "0.500" });
    // Negative scale (round to hundreds): Decimal(1234.5).quantize(Decimal('1E+2')) -> 1.2E+3
    try expectFromFloat(1234.5, -2, .{ "1200", "1200", "1200", "1300", "1200", "1300", "1200" });
}

test "float bridge: fromFloatShortest is what the user typed (Python repr / Decimal(repr(x)))" {
    // repr(0.1) == '0.1'
    var a = try BigDecimal.fromFloatShortest(talloc, 0.1);
    defer a.deinit();
    try expectStr(a, "0.1");
    try testing.expectEqual(@as(i32, -1), a.exponent);
    // repr(-2.675) == '-2.675'
    var b = try BigDecimal.fromFloatShortest(talloc, -2.675);
    defer b.deinit();
    try expectStr(b, "-2.675");
    // repr(5e-324) == '5e-324', repr(1.7976931348623157e308) == '1.7976931348623157e+308'
    var lo = try BigDecimal.fromFloatShortest(talloc, 5e-324);
    defer lo.deinit();
    try testing.expectEqual(@as(i32, -324), lo.exponent);
    try testing.expectEqual(@as(u64, 5), try lo.coeff.toConst().toInt(u64));
    var hi = try BigDecimal.fromFloatShortest(talloc, 1.7976931348623157e308);
    defer hi.deinit();
    try testing.expectEqual(@as(i32, 292), hi.exponent);
    try testing.expectEqual(@as(u64, 17976931348623157), try hi.coeff.toConst().toInt(u64));
    // repr(1e22) == '1e+22'; repr(123456789012345678.0) == '1.2345678901234568e+17'
    var e22 = try BigDecimal.fromFloatShortest(talloc, 1e22);
    defer e22.deinit();
    try expectStr(e22, "10000000000000000000000");
    var big17 = try BigDecimal.fromFloatShortest(talloc, 123456789012345678.0);
    defer big17.deinit();
    try expectStr(big17, "123456789012345680");
    var z = try BigDecimal.fromFloatShortest(talloc, 0.0);
    defer z.deinit();
    try testing.expect(z.isZero());
    // The typed 2.675 IS a tie, unlike the binary value:
    // [str(Decimal(repr(2.675)).quantize(Decimal('0.01'), m)) for m in modes]
    try expectShortestRescaled(2.675, 2, .{ "2.68", "2.68", "2.67", "2.68", "2.67", "2.68", "2.67" });
}

test "float bridge: NaN and +-Inf are refused with an error, never 0 or a trap" {
    const bad = [_]f64{ std.math.nan(f64), std.math.inf(f64), -std.math.inf(f64) };
    for (bad) |x| {
        try testing.expectError(error.NotFinite, BigDecimal.fromFloat(talloc, x, 2, .half_even));
        try testing.expectError(error.NotFinite, BigDecimal.fromFloatExact(talloc, x));
        try testing.expectError(error.NotFinite, BigDecimal.fromFloatShortest(talloc, x));
    }
}

test "float bridge: fromFloat scale range is a typed error" {
    try testing.expectError(error.Overflow, BigDecimal.fromFloat(talloc, 0.1, std.math.minInt(i32), .half_even));
    try testing.expectError(error.Overflow, BigDecimal.fromFloat(talloc, 0.1, std.math.maxInt(i32), .half_even));
}

test "float bridge: toFloat is the correctly rounded nearest f64 (Python float(Decimal(s)))" {
    // float(Decimal('0.1')) -> 0.1 ; float(Decimal('2.5')) -> 2.5
    try expectBits(0.1, try toF("0.1"));
    try expectBits(2.5, try toF("2.5"));
    try expectBits(-2.5, try toF("-2.5"));
    // float(Decimal('123456789.123456789012')) -> 123456789.12345679
    try expectBits(123456789.12345679, try toF("123456789.123456789012"));
    // Exactly half-way between two doubles: ties to EVEN.
    // float(Decimal('9007199254740993')) -> 9007199254740992.0  (down to even)
    try expectBits(9007199254740992.0, try toF("9007199254740993"));
    // float(Decimal('9007199254740995')) -> 9007199254740996.0  (up to even)
    try expectBits(9007199254740996.0, try toF("9007199254740995"));
    // Subnormals: float(Decimal('1e-323')) -> 1e-323 ; float(Decimal('4.9e-324')) -> 5e-324
    try expectBits(1e-323, try toF("1e-323"));
    try expectBits(5e-324, try toF("4.9e-324"));
    // Below / just above half of the smallest subnormal (2.4703282292062327208e-324 is the tie):
    // float(Decimal('2.4703282292062327e-324')) -> 0.0 ; float(Decimal('2.4703282292062328e-324')) -> 5e-324
    try expectBits(0.0, try toF("2.4703282292062327e-324"));
    try expectBits(5e-324, try toF("2.4703282292062328e-324"));
    // The exact 751-digit expansion of 5e-324 converts back to it (long-input path).
    try expectBits(5e-324, try toF(f64_min_subnormal_digits));
    // Largest finite double: its exact digits, and a value that still rounds down to it.
    // float(Decimal('1.797693134862315807e308')) -> 1.7976931348623157e+308
    try expectBits(1.7976931348623157e308, try toF(f64_max_digits));
    try expectBits(1.7976931348623157e308, try toF("1.797693134862315807e308"));
}

test "float bridge: toFloat out of range is +-inf / signed zero, not an error" {
    // Decision: a total function, like IEEE conversion and like Python's
    // float(Decimal): float(Decimal('1e400')) -> inf ; float(Decimal('-1e400')) -> -inf
    // float(Decimal('1e-400')) -> 0.0 ; float(Decimal('-1e-400')) -> -0.0
    try expectBits(std.math.inf(f64), try toF("1e400"));
    try expectBits(-std.math.inf(f64), try toF("-1e400"));
    try expectBits(0.0, try toF("1e-400"));
    try expectBits(-@as(f64, 0.0), try toF("-1e-400"));
    // float(str(2**1024 - 2**970)) -> inf : the tie above the largest double rounds to even = 2**1024.
    try expectBits(std.math.inf(f64), try toF(f64_overflow_tie_digits));
    // Hostile exponents never build a huge string.
    try expectBits(std.math.inf(f64), try toF("1e2000000000"));
    try expectBits(0.0, try toF("1e-2000000000"));
    // A zero BigDecimal is +0.0 whatever its exponent.
    try expectBits(0.0, try toF("0"));
    try expectBits(0.0, try toF("0e5"));
}

test "float bridge: toFloat(fromFloatShortest(x)) == x and toFloat(fromFloatExact(x)) == x over random bit patterns" {
    var prng = std.Random.DefaultPrng.init(0xF10A7_B21D6E);
    const rand = prng.random();
    const fixed = [_]f64{ 0.1, 2.675, 5e-324, -5e-324, 1.7976931348623157e308, 2.2250738585072014e-308, 2.225073858507201e-308, 1.0, 1e22, 123456789012345678.0, 0.0 };
    var checked: usize = 0;
    var i: usize = 0;
    while (i < 3000 + fixed.len) : (i += 1) {
        const x: f64 = if (i < fixed.len) fixed[i] else @bitCast(rand.int(u64));
        if (!std.math.isFinite(x)) continue;
        var s = try BigDecimal.fromFloatShortest(talloc, x);
        defer s.deinit();
        try testing.expect(x == try s.toFloat(talloc));
        var e = try BigDecimal.fromFloatExact(talloc, x);
        defer e.deinit();
        try testing.expect(x == try e.toFloat(talloc));
        checked += 1;
    }
    // Random u64 patterns are non-finite only when the exponent field is all
    // ones (1 in 2048): the sample is essentially full.
    try testing.expect(checked > 2900);
}

// ── fuzz: arbitrary-precision decimal string parse, never panics ───────────
//
// Same untrusted-text boundary as `Decimal.parse`, but unbounded in
// significand width — a hostile digit run of thousands of characters is
// exactly the shape this arena-backed parser has to reject or accept
// without a fixed-width assumption tripping it up.

/// `testkit.fuzz.seed`: a corpus entry is NOT the literal. `Smith.slice` reads
/// a little-endian `u32` length first, so a raw literal loses four octets.
const seed = @import("testkit").fuzz.seed;

/// Literals in the format `Smith.slice` reads (see `testkit.fuzz`), lifted
/// from `parse + format roundtrip`, `parse rejects`, the exponent-range tests
/// and `arbitrary precision exceeds the fixed-scale Decimal's i128 range`.
///
/// The point of this parser is that it is unbounded in significand width, so
/// the corpus carries the long ones deliberately: the 81-character
/// 40-nines-dot-40-ones literal, and a 200-digit run. Both fit the 256-octet
/// buffer — ⚠ a seed over it reads back EMPTY, not truncated.
const parse_seeds = [_][]const u8{
    seed("0"),
    seed("123"),
    seed("-123.456"),
    seed("0.001"),
    seed("1.50"), // trailing zeros preserved, unlike the fixed-scale Decimal
    seed("2.08e9"),
    seed("1.23e-4"),
    seed("1E1000000"), // an exponent a fixed-scale decimal cannot hold
    seed(strRepeat("9", 40) ++ "." ++ strRepeat("1", 40)), // 81 characters, far past i128
    seed(strRepeat("9", 200)), // a hostile digit run, which is what this parser is for
    seed(""), // InvalidCharacter — and the ONE input the collapsed harness ran
    seed("abc"), // InvalidCharacter
    seed("1.2.3"), // InvalidCharacter
    seed("1e"), // InvalidCharacter
    seed("--1"), // InvalidCharacter
    seed("."), // InvalidCharacter
    seed("1e99999999999999999999"), // Overflow: the exponent itself
};

test "fuzz: parse never panics on arbitrary text" {
    try testing.fuzz({}, fuzzParse, .{ .corpus = &parse_seeds });
}

fn fuzzParse(_: void, smith: *std.testing.Smith) !void {
    const alphabet = "0123456789+-.eE";
    var buf: [256]u8 = undefined;
    // One `smith.slice` call first, never `smith.bytes` followed by a ranged
    // length (see the sibling in `root.zig`).
    const len: usize = smith.slice(&buf);
    // ⚠ A `--fuzz`-only aid: on a corpus replay `Smith` is already drained, so
    // `boolWeighted` is false throughout and every seed reaches `parse`
    // verbatim.
    for (buf[0..len]) |*c| {
        if (smith.boolWeighted(1, 4)) c.* = alphabet[c.* % alphabet.len];
    }
    var src: fz.ScriptSource = .{ .cur = .{ .bytes = buf[0..len] } };
    try fz.bigParseHarness(fz.ScriptSource, &src, testing.allocator);
}

const fz = @import("fuzz_test.zig");

test "corpus: every literal reaches BigDecimal.parse, and the counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment. It is
    // also the only thing that would notice a seed growing past the harness
    // buffer — such a seed reads back EMPTY, silently.
    //
    // `digits` (total octets delivered) is pinned beside `parsed` because it
    // is the number the empty input provably cannot move, and because it
    // notices a seed being shortened as well as dropped — the long significand
    // literals are the whole point of this parser.
    var nonempty: usize = 0;
    var parsed: usize = 0;
    var digits: usize = 0;
    // ⛔ The alphabet-substitution loop is replayed here, not skipped. The
    // harness's comment claims it is inert on a corpus replay; a guard that
    // leaves the loop out cannot hold that claim up, and would keep reporting
    // the same `digits` while a seed with a tail quietly mangled its literal.
    var substituted: usize = 0;
    const alphabet = "0123456789+-.eE";
    for (parse_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [256]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        digits += len;
        for (buf[0..len]) |*c| {
            if (smith.boolWeighted(1, 4)) {
                c.* = alphabet[c.* % alphabet.len];
                substituted += 1;
            }
        }
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        if (BigDecimal.parse(arena.allocator(), buf[0..len])) |_| parsed += 1 else |_| {}
    }
    // One seed IS the empty literal, a legal member of a refusal corpus.
    try testing.expectEqual(parse_seeds.len - 1, nonempty);
    // Measured 2026-09-07: with the collapsing draw, 0 non-empty, 0 parsed and
    // 0 octets delivered — one empty string seventeen times. After:
    try testing.expectEqual(@as(usize, 10), parsed);
    try testing.expectEqual(@as(usize, 360), digits);
    // The harness's claim, now executable: measured 2026-09-08 at 0. Every
    // seed reaches `BigDecimal.parse` verbatim, because `testkit.fuzz.seed`
    // leaves no tail and `boolWeighted` on an exhausted input is `false`. ⛔ A
    // non-zero value here would mean a quarter of the corpus's own literals
    // were being rewritten into something else before the parser saw them.
    try testing.expectEqual(@as(usize, 0), substituted);
}

// ---------------------------------------------------------------------------
// Mutation run 2026-10-04: boundary and short-circuit pins. Each test kills
// mutants the earlier suite let survive (SPEC.md "Mutation run 2026-10-04").
// Expected values come from the stated invariant or from Python 3 `decimal`
// (the General Decimal Arithmetic reference), noted per test.
// ---------------------------------------------------------------------------

test "parse: exponent literal bounds are the i32 range, inclusive" {
    const max_i32 = std.math.maxInt(i32);
    const min_i32 = std.math.minInt(i32);
    var hi = dec("1e2147483647");
    defer hi.deinit();
    try testing.expectEqual(@as(i32, max_i32), hi.exponent);
    var lo = dec("1e-2147483648");
    defer lo.deinit();
    try testing.expectEqual(@as(i32, min_i32), lo.exponent);
    // 0.1e-2147483647: the fraction digit lowers the exponent to exactly i32 min.
    var lo2 = dec("0.1e-2147483647");
    defer lo2.deinit();
    try testing.expectEqual(@as(i32, min_i32), lo2.exponent);
    try testing.expectError(error.Overflow, BigDecimal.parse(talloc, "1e2147483648"));
    try testing.expectError(error.Overflow, BigDecimal.parse(talloc, "1e-2147483649"));
}

test "parse: a 15-digit exponent literal with leading zeros keeps its last digit" {
    // Python: Decimal('1e000000000000012') == Decimal('1E+12').
    var a = dec("1e000000000000012");
    defer a.deinit();
    try testing.expectEqual(@as(i32, 12), a.exponent);
}

test "mul / scaleByPowerOfTen / pow: an exponent landing exactly on the i32 limits is fine" {
    const max_i32 = std.math.maxInt(i32);
    const min_i32 = std.math.minInt(i32);
    var hi = dec("1e2147483647");
    defer hi.deinit();
    var lo = dec("1e-2147483648");
    defer lo.deinit();
    var one = dec("1");
    defer one.deinit();

    var p = try BigDecimal.mul(talloc, hi, one);
    defer p.deinit();
    try testing.expectEqual(@as(i32, max_i32), p.exponent);
    var q = try BigDecimal.mul(talloc, lo, one);
    defer q.deinit();
    try testing.expectEqual(@as(i32, min_i32), q.exponent);

    var s1 = try BigDecimal.scaleByPowerOfTen(one, max_i32);
    defer s1.deinit();
    try testing.expectEqual(@as(i32, max_i32), s1.exponent);
    var s2 = try BigDecimal.scaleByPowerOfTen(one, min_i32);
    defer s2.deinit();
    try testing.expectEqual(@as(i32, min_i32), s2.exponent);

    // a^1 == a, so its exponent (== the limit) must survive pow's exponent check.
    var w1 = try BigDecimal.pow(talloc, hi, 1);
    defer w1.deinit();
    try testing.expectEqual(@as(i32, max_i32), w1.exponent);
    var w2 = try BigDecimal.pow(talloc, lo, 1);
    defer w2.deinit();
    try testing.expectEqual(@as(i32, min_i32), w2.exponent);
}

test "normalize: stops at the i32 exponent ceiling instead of overflowing it" {
    var a = dec("10e2147483647"); // coefficient 10 at the largest exponent
    defer a.deinit();
    var n = try BigDecimal.normalize(talloc, a);
    defer n.deinit();
    // The value 10 * 10^max cannot be re-expressed with a larger exponent, so
    // the coefficient stays 10 (a wrap or trap here would be the bug).
    try testing.expectEqual(@as(i32, std.math.maxInt(i32)), n.exponent);
    try testing.expectEqual(@as(i64, 10), try n.coeff.toConst().toInt(i64));
}

test "div / rescale: zero results carry the requested exponent" {
    // GDA quantize gives the requested exponent even for zero:
    // Python Decimal('0.00').quantize(Decimal('1E+2')) = Decimal('0E+2').
    var z = dec("0.00");
    defer z.deinit();
    var five = dec("5");
    defer five.deinit();
    var r = try BigDecimal.rescale(talloc, z, 2, .half_even);
    defer r.deinit();
    try testing.expect(r.isZero());
    try testing.expectEqual(@as(i32, 2), r.exponent);
    // Java BigDecimal.ZERO.divide(x, scale, mode) has that scale: exponent = -scale.
    var q = try BigDecimal.div(talloc, z, five, 3, .half_even);
    defer q.deinit();
    try testing.expect(q.isZero());
    try testing.expectEqual(@as(i32, -3), q.exponent);
}

test "div: an alignment shift of exactly max_align_shift is allowed, one more is Overflow" {
    const lim: i32 = @intCast(BigDecimal.max_align_shift);
    var one = dec("1");
    defer one.deinit();
    // numerator side: shift = target_scale
    var a = try BigDecimal.div(talloc, one, one, lim, .down);
    defer a.deinit();
    try testing.expectEqual(-lim, a.exponent);
    // 10^1000000 has 3321929 bits (floor(1e6 * log2(10)) + 1); `precision` would be needlessly slow here.
    try testing.expectEqual(@as(usize, 3_321_929), a.coeff.bitCountAbs());
    try testing.expectError(error.Overflow, BigDecimal.div(talloc, one, one, lim + 1, .down));
    // divisor side: shift = target_scale + a.exponent - b.exponent = -lim; 1e-lim / 1 -> 0 (.down)
    var tiny = dec("1e-1000000");
    defer tiny.deinit();
    var b = try BigDecimal.div(talloc, tiny, one, 0, .down);
    defer b.deinit();
    try testing.expect(b.isZero());
    var tinier = dec("1e-1000001");
    defer tinier.deinit();
    try testing.expectError(error.Overflow, BigDecimal.div(talloc, tinier, one, 0, .down));
}

test "toFloat: 1.5e308 is finite (the infinity cut-off is above f64 max)" {
    // Python: float(Decimal('1.5e308')) == 1.5e308; f64 max is 1.7976931348623157e308.
    var a = dec("1.5e308");
    defer a.deinit();
    try expectBits(1.5e308, try a.toFloat(talloc));
}

test "min/max: -0 versus +0 follows total order (Python: max -> 0, min -> -0)" {
    var pz = dec("0");
    defer pz.deinit();
    var nz = dec("0");
    defer nz.deinit();
    nz.negate(); // negative zero is representable (see `negate`)
    try testing.expect(!nz.coeff.isPositive());

    var m1 = try BigDecimal.max(talloc, nz, pz);
    defer m1.deinit();
    try testing.expect(m1.coeff.isPositive());
    var m2 = try BigDecimal.max(talloc, pz, nz);
    defer m2.deinit();
    try testing.expect(m2.coeff.isPositive());
    var n1 = try BigDecimal.min(talloc, nz, pz);
    defer n1.deinit();
    try testing.expect(!n1.coeff.isPositive());
    var n2 = try BigDecimal.min(talloc, pz, nz);
    defer n2.deinit();
    try testing.expect(!n2.coeff.isPositive());
}

test "sqrt: the digit budgets are inclusive and -0 is not a negative operand" {
    const lim = BigDecimal.max_result_digits;
    // prec == limit is allowed (exact root 2 returns before any heavy work);
    // prec == limit + 1 is not.
    var four = dec("4");
    defer four.deinit();
    var two = try BigDecimal.sqrt(talloc, four, lim, .half_even);
    defer two.deinit();
    try expectStr(two, "2");
    try testing.expectError(error.PrecisionTooLarge, BigDecimal.sqrt(talloc, four, lim + 1, .half_even));

    // A radicand of exactly `lim` digits is allowed. Python, prec=5:
    // sqrt(Decimal(10)**99999) = 3.1623E+49999 -> coefficient 31623, exponent 49995.
    var wide = dec("1" ++ strRepeat("0", 99999));
    defer wide.deinit();
    var r = try BigDecimal.sqrt(talloc, wide, 5, .half_even);
    defer r.deinit();
    try testing.expectEqual(@as(i32, 49995), r.exponent);
    try testing.expectEqual(@as(i64, 31623), try r.coeff.toConst().toInt(i64));
    var too_wide = dec("1" ++ strRepeat("0", 100000));
    defer too_wide.deinit();
    try testing.expectError(error.PrecisionTooLarge, BigDecimal.sqrt(talloc, too_wide, 5, .half_even));

    // Python: Decimal('-0').sqrt() == Decimal('-0') -- valid, not Invalid_operation.
    var nz = dec("0");
    defer nz.deinit();
    nz.negate();
    var z = try BigDecimal.sqrt(talloc, nz, 5, .half_even);
    defer z.deinit();
    try testing.expect(z.isZero());
}

test "rescale / div: an exact quotient is never bumped, whatever the mode" {
    const modes = [_]RoundingMode{ .half_even, .half_up, .half_down, .up, .down, .ceiling, .floor };
    var a = dec("1.50");
    defer a.deinit();
    var six = dec("6");
    defer six.deinit();
    var neg_six = dec("-6");
    defer neg_six.deinit();
    var three = dec("3");
    defer three.deinit();
    for (modes) |mode| {
        // Python: Decimal('1.50').quantize(Decimal('0.1'), rounding=ROUND_UP) = 1.5 (digit dropped is 0)
        var r = try BigDecimal.rescale(talloc, a, -1, mode);
        defer r.deinit();
        try expectStr(r, "1.5");
        // 6/3 = 2 and -6/3 = -2 exactly.
        var q = try BigDecimal.div(talloc, six, three, 0, mode);
        defer q.deinit();
        try expectStr(q, "2");
        var nq = try BigDecimal.div(talloc, neg_six, three, 0, mode);
        defer nq.deinit();
        try expectStr(nq, "-2");
    }
}

test "parse: long exponent literals are read by value, never truncated" {
    // Python: Decimal('1e0000000000000012') == Decimal('1E+12'); leading zeros are not digits of value.
    var a = dec("1e0000000000000012");
    defer a.deinit();
    try testing.expectEqual(@as(i32, 12), a.exponent);
    var b = dec("1e-" ++ strRepeat("0", 40) ++ "12");
    defer b.deinit();
    try testing.expectEqual(@as(i32, -12), b.exponent);
    // 16 significant digits is far past i32: the module's out-of-range error, not a wrong value.
    try testing.expectError(error.Overflow, BigDecimal.parse(talloc, "1e1000000000000000"));
    try testing.expectError(error.Overflow, BigDecimal.parse(talloc, "1e-" ++ strRepeat("9", 40)));
    // Junk after a long literal is still malformed.
    try testing.expectError(error.InvalidCharacter, BigDecimal.parse(talloc, "1e" ++ strRepeat("9", 40) ++ "x"));
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    const rep_result = comptime blk: {
        @setEvalBranchQuota(n * (s.len + 4) + 1000);
        var buf: [s.len * n:0]u8 = undefined;
        for (0..n) |i| @memcpy(buf[i * s.len ..][0..s.len], s);
        const rep_final = buf;
        break :blk rep_final;
    };
    return &rep_result;
}
