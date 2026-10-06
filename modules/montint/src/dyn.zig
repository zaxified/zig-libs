// SPDX-License-Identifier: MIT
//! `DynModint(max_bits)` — an odd modulus chosen at RUN time (value AND limb
//! count), up to `max_bits` wide, with a constant-time element API built only
//! from `Modint`'s primitives.
//!
//! Why it exists: `rsa`, `paillier` and `threshold_ecdsa` each carried a private
//! copy of the same "slot" machinery (a `MontParams` struct, `montSlot`,
//! `montView`) so their secret modexps could run on `Modint` while every other
//! secret operation — the reduction of a ciphertext into the mod-p domain, the
//! CRT (Garner) recombination, products — stayed in `std.crypto.ff`. Measured
//! 2026-10-02 (ctgrind, Zig 0.16, ReleaseFast), `std.crypto.ff` is not
//! constant-time there: `montgomeryMul`'s extra-reduction select, `reduce`'s
//! `shiftIn`/compare and `toBytes` compile to conditional jumps. This type is
//! the run-time counterpart of `Field(p)`: one constant-time implementation
//! of the whole element API, so a consumer can drop `std.crypto.ff` for
//! secrets instead of patching each site.
//!
//! **Slots.** A modulus of `n` limbs runs on `Modint(64·L)` with `L` the
//! smallest multiple of `step` that is `≥ n` (and `≥ min_limbs`). Every
//! operation dispatches on `L` through an `inline while` over the slots, so
//! code size grows with `max_bits / (64·step)`. `L` follows from the modulus's
//! bit LENGTH, which is treated as public (it is the key size); the modulus's
//! VALUE is not, and nothing below branches on it — `rsa` builds one of these
//! for each secret CRT prime.
//!
//! **Elements** are `Elem = [max_limbs]u64`, little-endian, in the NORMAL
//! domain (not Montgomery), canonical (`< m`), limbs at or above `L` zero.
//! Normal-domain elements cost one extra Montgomery multiply per `mul`, and
//! buy the property the CRT code needs: an element of one modulus is a valid
//! input to another's `reduceLimbs` or, when it is already smaller, to its
//! arithmetic, with no domain conversion in between.
//!
//! **Operand contract** (as in `Modint`): every element handed in is `< m`.
//! Values that may be wider go through `reduceLimbs`/`reduceBytesBE`, which
//! reduce one digit at a time, a digit being `min(64, bits(m) − 1)` bits wide
//! — always `< m`, so `montMul` never sees an operand `≥ m`, down to the
//! smallest odd modulus `3`.
//!
//! The only value-dependent branches are the ones the API returns: the
//! accept/reject of `elemFromBytesBE` and `fromLimbs`, the `bool` of `isZero`,
//! `eql` and `divExact`, and `powPublic`'s exponent walk (public by contract).

const std = @import("std");
const montint = @import("montint.zig");
const limbs = @import("limbs.zig");
const nt = @import("nt.zig");
const blackBox = nt.blackBox;
const mulLow = nt.mulLow;
const nzBit = nt.nzBit;
const condSwap = nt.condSwap;
const condNeg = nt.condNeg;
const addMasked = nt.addMasked;
const blend = nt.blend;
const sar1 = nt.sar1;
const halveMod = nt.halveMod;
const divstepCount = nt.divstepCount;

/// Slot granularity in limbs: a modulus runs on the next multiple of this.
pub const step: usize = 4;
/// Smallest slot.
pub const min_limbs: usize = 4;

pub fn DynModint(comptime max_bits: comptime_int) type {
    comptime std.debug.assert(max_bits > 64);
    const raw_limbs = (max_bits + 63) / 64;
    const top_slot = @max(min_limbs, (raw_limbs + step - 1) / step * step);

    return struct {
        const Self = @This();

        pub const Error = montint.Error;
        /// Limb capacity of an element (the largest slot).
        pub const max_limbs: usize = top_slot;
        /// A normal-domain element, see the file doc.
        pub const Elem = [max_limbs]u64;
        pub const zero: Elem = [_]u64{0} ** max_limbs;

        /// The active slot (limb count the arithmetic runs at).
        L: usize,
        /// The modulus's bit length, fixed at construction (public: the key
        /// size) so no later call scans the value for it again.
        nbits: usize,
        /// The modulus, low `L` limbs live, the rest zero.
        m: Elem,
        /// `-m[0]⁻¹ mod 2^64`.
        n0inv: u64,
        /// `R² mod m`, `R = 2^(64·L)`.
        r2: Elem,
        /// `R mod m` (one in the Montgomery domain).
        one_mont: Elem,
        /// Digit width of the reducers: `min(64, bits(m) − 1)`.
        digit_bits: u7,
        /// `2^digit_bits·R mod m` — the Horner step of the reducers.
        digit_mont: Elem,

        fn Mod(comptime s: usize) type {
            return montint.Modint(s * 64);
        }

        inline fn view(self: *const Self, comptime s: usize) Mod(s) {
            return .{
                .m = self.m[0..s].*,
                .n0inv = self.n0inv,
                .r2 = self.r2[0..s].*,
                .one_mont = self.one_mont[0..s].*,
            };
        }

        fn slotFor(n: usize) usize {
            return @max(min_limbs, (n + step - 1) / step * step);
        }

        // ── construction ────────────────────────────────────────────────────

        /// Build from a little-endian limb value. Rejects an even modulus and
        /// one below 3. Constant-time in the value except for its bit
        /// length, which this scans for (it picks the slot) and treats as
        /// public — `fromLimbsBits` takes the length from the caller instead.
        pub fn fromLimbs(v: *const Elem) Error!Self {
            if (v[0] & 1 == 0) return error.EvenModulus;
            const n = activeLimbs(v);
            if (n == 1 and v[0] < 3) return error.ModulusTooSmall;
            return build(v, (n - 1) * 64 + (64 - @clz(v[n - 1])));
        }

        /// Build from a limb value whose bit length the caller knows — the
        /// key size of a secret prime. Nothing reads the value to find its
        /// length, and the checks (exactly `nbits` bits, odd, `≥ 3`) are
        /// combined bitwise into one verdict: `error.NonCanonical` if `v` is
        /// not an odd `nbits`-bit number of at least 2 bits.
        pub fn fromLimbsBits(v: *const Elem, nbits: usize) Error!Self {
            if (nbits < 2) return error.ModulusTooSmall;
            if (nbits > 64 * max_limbs) return error.Overflow;
            const top = nbits - 1;
            var bad: u64 = ~v[0] & 1; // even
            for (v, 0..) |w, i| {
                // bits at or above position nbits must be zero
                const allowed: u64 = if (i < top / 64) ~@as(u64, 0) else if (i == top / 64)
                    (if (top % 64 == 63) ~@as(u64, 0) else (@as(u64, 2) << @intCast(top % 64)) - 1)
                else
                    0;
                bad |= w & ~allowed;
            }
            bad |= ~(v[top / 64] >> @intCast(top % 64)) & 1; // top bit set
            if (bad != 0) return error.NonCanonical;
            return build(v, nbits);
        }

        fn build(v: *const Elem, nbits: usize) Self {
            const d: u7 = @intCast(@min(64, nbits - 1));
            const slot = slotFor((nbits + 63) / 64);
            comptime var s: usize = min_limbs;
            inline while (s <= max_limbs) : (s += step) {
                if (s == slot) {
                    const mm = Mod(s).fromElemUnchecked(v[0..s].*);
                    var self: Self = .{
                        .L = s,
                        .nbits = nbits,
                        .m = zero,
                        .n0inv = mm.n0inv,
                        .r2 = zero,
                        .one_mont = zero,
                        .digit_bits = d,
                        .digit_mont = zero,
                    };
                    self.m[0..s].* = mm.m;
                    self.r2[0..s].* = mm.r2;
                    self.one_mont[0..s].* = mm.one_mont;
                    // 2^d < m: d ≤ bits − 1, and an odd m exceeds the even
                    // 2^(bits − 1).
                    var t = [_]u64{0} ** s;
                    if (d == 64) t[1] = 1 else t[0] = @as(u64, 1) << @intCast(d);
                    self.digit_mont[0..s].* = mm.toMontgomery(&t);
                    return self;
                }
            }
            unreachable;
        }

        /// Build from a big-endian byte string (leading zero bytes allowed).
        /// The load is branchless in the byte values (see `loadBE`).
        pub fn fromBytesBE(be: []const u8) Error!Self {
            var v = try loadBE(be);
            defer std.crypto.secureZero(u64, &v);
            return fromLimbs(&v);
        }

        /// Number of limbs up to the top non-zero one. Branches on which
        /// limbs are zero from the top down — the bit LENGTH, public here.
        fn activeLimbs(v: *const Elem) usize {
            var i: usize = max_limbs;
            while (i > 0) : (i -= 1) {
                if (v[i - 1] != 0) return i;
            }
            return 0;
        }

        /// Bit length of the modulus.
        pub fn bits(self: *const Self) usize {
            return self.nbits;
        }

        /// Byte length of the modulus (the width of its minimal encoding).
        pub fn byteLen(self: *const Self) usize {
            return (self.bits() + 7) / 8;
        }

        // ── loading and storing ─────────────────────────────────────────────

        /// Big-endian bytes → an `Elem`, with no branch on the byte values:
        /// bytes past the capacity are OR-ed together and the single
        /// `error.Overflow` decision is taken on that sum.
        pub fn loadBE(be: []const u8) Error!Elem {
            var v = zero;
            var excess: u8 = 0;
            for (be, 0..) |b, i| {
                const pos = be.len - 1 - i; // byte position from the LSB
                if (pos / 8 < max_limbs) {
                    v[pos / 8] |= @as(u64, b) << @intCast(8 * (pos % 8));
                } else {
                    excess |= b;
                }
            }
            if (excess != 0) return error.Overflow;
            return v;
        }

        /// Parse a canonical element (`< m`) from big-endian bytes.
        /// Constant-time up to the accept/reject outcome.
        pub fn elemFromBytesBE(self: *const Self, be: []const u8) Error!Elem {
            const v = try loadBE(be);
            var t = v;
            const borrow = limbs.subInto(&t, &self.m); // 1 ⟺ v < m
            std.crypto.secureZero(u64, &t);
            if (borrow == 0) return error.NonCanonical;
            return v;
        }

        /// Write `e` big-endian into all of `out`, zero-padded on the left.
        /// `out.len ≥ byteLen()` (enough for any canonical element); a shorter
        /// `out` panics in every optimize mode instead of truncating — the
        /// lengths are public. Branches on positions only.
        pub fn toBytesBE(self: *const Self, e: *const Elem, out: []u8) void {
            if (out.len < self.byteLen()) @panic("montint: DynModint.toBytesBE output shorter than the modulus");
            for (out, 0..) |*o, i| {
                const pos = out.len - 1 - i;
                o.* = if (pos / 8 < max_limbs) @truncate(e[pos / 8] >> @intCast(8 * (pos % 8))) else 0;
            }
        }

        // ── std.crypto.ff bridge ────────────────────────────────────────────

        /// A `std.crypto.ff` value (`Uint`, or an `Fe`'s `.v`) as an `Elem`.
        /// `ff` keeps 63 active bits per 64-bit limb; this repacks them by
        /// position only, with no branch on the value — unlike `ff`'s own
        /// `toBytes`, which branches in ReleaseFast. Reads the whole limb
        /// buffer (`ff` keeps limbs past `limbs_len` zero), so the repack does
        /// not depend on the length either. The value must fit `max_limbs`.
        /// A Montgomery-form `Fe` must be converted by its owner first.
        pub fn elemFromFf(u: anytype) Elem {
            const Limb = @TypeOf(u.limbs_buffer[0]);
            const t_bits = @bitSizeOf(Limb) - 1;
            var out = zero;
            for (u.limbs_buffer, 0..) |limb, i| {
                const pos = i * t_bits;
                const idx = pos / 64;
                if (idx >= max_limbs) break; // public position
                const w = @as(u128, limb) << @intCast(pos % 64);
                out[idx] |= @truncate(w);
                if (idx + 1 < max_limbs) out[idx + 1] |= @truncate(w >> 64);
            }
            return out;
        }

        /// `e` as an `Fe` of the `std.crypto.ff` modulus `m` (normal domain),
        /// the positional inverse of `elemFromFf` — what `Fe.fromBytes(m, …)`
        /// gives for a value already `< m`, without its value-dependent
        /// canonicality checks. `e` must be `< m`.
        pub fn elemToFf(comptime Fe: type, m: anytype, e: *const Elem) Fe {
            var fe: Fe = .{ .v = @TypeOf(m.v).zero };
            const Limb = @TypeOf(fe.v.limbs_buffer[0]);
            const t_bits = @bitSizeOf(Limb) - 1;
            const t_mask: u128 = (@as(u128, 1) << t_bits) - 1;
            for (&fe.v.limbs_buffer, 0..) |*limb, i| {
                const pos = i * t_bits;
                const idx = pos / 64;
                const lo: u128 = if (idx < max_limbs) e[idx] else 0;
                const hi: u128 = if (idx + 1 < max_limbs) e[idx + 1] else 0;
                limb.* = @intCast(((lo | hi << 64) >> @intCast(pos % 64)) & t_mask);
            }
            fe.v.limbs_len = m.v.limbs_len;
            return fe;
        }

        /// A `DynModint` for a `std.crypto.ff` modulus, branchless in its
        /// value (`rsa` builds one per secret CRT prime this way).
        pub fn fromFf(m: anytype) Error!Self {
            var v = elemFromFf(&m.v);
            defer std.crypto.secureZero(u64, &v);
            return fromLimbs(&v);
        }

        // ── reduction ───────────────────────────────────────────────────────

        /// `x mod m` for a little-endian value of any limb count. Horner over
        /// `digit_bits`-bit digits (each `< m`), two Montgomery multiplies per
        /// digit; the work depends on `x.len` and the modulus's bit length
        /// only.
        pub fn reduceLimbs(self: *const Self, x: []const u64) Elem {
            return self.horner(LimbDigits{ .x = x }, 64 * x.len);
        }

        /// `int(be) mod m` for a big-endian string of any length.
        pub fn reduceBytesBE(self: *const Self, be: []const u8) Elem {
            return self.horner(ByteDigits{ .be = be }, 8 * be.len);
        }

        fn horner(self: *const Self, src: anytype, total_bits: usize) Elem {
            const d: usize = self.digit_bits;
            const mask: u64 = if (d == 64) ~@as(u64, 0) else (@as(u64, 1) << @intCast(d)) - 1;
            comptime var s: usize = min_limbs;
            inline while (s <= max_limbs) : (s += step) {
                if (s == self.L) {
                    const v = self.view(s);
                    const step_mont = self.digit_mont[0..s];
                    var acc = [_]u64{0} ** s;
                    var k: usize = (total_bits + d - 1) / d;
                    while (k > 0) {
                        k -= 1;
                        var digit = [_]u64{0} ** s;
                        digit[0] = src.at(k * d) & mask;
                        acc = v.montMul(&acc, step_mont);
                        const digit_mont = v.toMontgomery(&digit);
                        acc = v.add(&acc, &digit_mont);
                    }
                    var out = zero;
                    out[0..s].* = v.fromMontgomery(&acc);
                    return out;
                }
            }
            unreachable;
        }

        /// 64 bits of a little-endian limb string from bit `off` on (zero
        /// past the end). Branches on positions only.
        const LimbDigits = struct {
            x: []const u64,
            fn at(self: LimbDigits, off: usize) u64 {
                const i = off / 64;
                const lo: u128 = if (i < self.x.len) self.x[i] else 0;
                const hi: u128 = if (i + 1 < self.x.len) self.x[i + 1] else 0;
                return @truncate((lo | hi << 64) >> @intCast(off % 64));
            }
        };

        /// 64 bits of a big-endian byte string from bit `off` (counted from
        /// the least significant end) on. Branches on positions only.
        const ByteDigits = struct {
            be: []const u8,
            fn at(self: ByteDigits, off: usize) u64 {
                var w: u128 = 0;
                for (0..9) |j| {
                    const pos = off / 8 + j;
                    const byte: u128 = if (pos < self.be.len) self.be[self.be.len - 1 - pos] else 0;
                    w |= byte << @intCast(8 * j);
                }
                return @truncate(w >> @intCast(off % 8));
            }
        };

        // ── predicates ──────────────────────────────────────────────────────

        pub fn isZero(e: *const Elem) bool {
            var acc: u64 = 0;
            for (e) |w| acc |= w;
            return acc == 0;
        }

        pub fn eql(a: *const Elem, b: *const Elem) bool {
            var acc: u64 = 0;
            for (a, b) |x, y| acc |= x ^ y;
            return acc == 0;
        }

        /// `a` if `on`, else `b`, without a branch: the mask is laundered
        /// through an asm barrier so LLVM cannot turn the blend back into a
        /// jump on `on` (the montint `blackBox` lesson). `on` may be secret —
        /// as long as the caller does not branch on it either.
        pub fn select(on: bool, a: *const Elem, b: *const Elem) Elem {
            const mask = blackBox(0 -% @as(u64, @intFromBool(on)));
            var out: Elem = undefined;
            for (&out, a, b) |*o, x, y| o.* = (x & mask) | (y & ~mask);
            return out;
        }

        // ── arithmetic (operands `< m`) ─────────────────────────────────────

        pub fn add(self: *const Self, a: *const Elem, b: *const Elem) Elem {
            comptime var s: usize = min_limbs;
            inline while (s <= max_limbs) : (s += step) {
                if (s == self.L) {
                    var out = zero;
                    out[0..s].* = self.view(s).add(a[0..s], b[0..s]);
                    return out;
                }
            }
            unreachable;
        }

        pub fn sub(self: *const Self, a: *const Elem, b: *const Elem) Elem {
            comptime var s: usize = min_limbs;
            inline while (s <= max_limbs) : (s += step) {
                if (s == self.L) {
                    var out = zero;
                    out[0..s].* = self.view(s).sub(a[0..s], b[0..s]);
                    return out;
                }
            }
            unreachable;
        }

        pub fn neg(self: *const Self, a: *const Elem) Elem {
            return self.sub(&zero, a);
        }

        /// `a·b mod m` (normal domain: two Montgomery multiplies).
        pub fn mul(self: *const Self, a: *const Elem, b: *const Elem) Elem {
            comptime var s: usize = min_limbs;
            inline while (s <= max_limbs) : (s += step) {
                if (s == self.L) {
                    var out = zero;
                    out[0..s].* = self.view(s).mul(a[0..s], b[0..s]);
                    return out;
                }
            }
            unreachable;
        }

        pub fn sq(self: *const Self, a: *const Elem) Elem {
            return self.mul(a, a);
        }

        /// `base^exp mod m`, constant-time in both (`Modint.powMont`: all
        /// `64·L` exponent bits are walked). Only the low `L` limbs of `exp`
        /// are read — an exponent must be `< 2^(64·L)`, which every exponent
        /// `< m` (or `< m'` for a modulus `m'` in the same slot) is.
        pub fn pow(self: *const Self, base: *const Elem, exp: *const Elem) Elem {
            comptime var s: usize = min_limbs;
            inline while (s <= max_limbs) : (s += step) {
                if (s == self.L) {
                    var out = zero;
                    out[0..s].* = self.view(s).powMont(base[0..s], exp[0..s]);
                    return out;
                }
            }
            unreachable;
        }

        /// `base^e mod m` for a PUBLIC exponent: left-to-right square-and-
        /// multiply over `e`'s actual bit length (65537 costs 16 squarings
        /// and one multiply). **Variable-time in `e`** by design; constant-
        /// time in `base` and `m`.
        pub fn powPublic(self: *const Self, base: *const Elem, e_be: []const u8) Elem {
            comptime var s: usize = min_limbs;
            inline while (s <= max_limbs) : (s += step) {
                if (s == self.L) {
                    const v = self.view(s);
                    const b_mont = v.toMontgomery(base[0..s]);
                    var acc = v.one_mont;
                    var seen = false;
                    for (e_be) |byte| {
                        var bit: u8 = 0x80;
                        while (bit != 0) : (bit >>= 1) {
                            if (seen) acc = v.montSqr(&acc);
                            if (byte & bit != 0) {
                                acc = if (seen) v.montMul(&acc, &b_mont) else b_mont;
                                seen = true;
                            }
                        }
                    }
                    var out = zero;
                    out[0..s].* = v.fromMontgomery(&acc);
                    return out;
                }
            }
            unreachable;
        }

        /// Exact division by the modulus: if `m` divides `x` and the quotient
        /// is `< 2^(64·L)`, writes `x / m` to `q` and returns `true`; else
        /// returns `false` (`q` then holds garbage). Constant-time in `x` and
        /// `m` up to that verdict.
        ///
        /// Hensel division: `q = x·m⁻¹ mod 2^(64·L)` is the quotient whenever
        /// the division is exact and the quotient fits, and the product `q·m`
        /// compared against all of `x` decides whether it was. The Paillier
        /// L-function `L(u) = (u − 1)/n` is this operation — the variable-
        /// time `std.math.big.int.divFloor` it replaces leaked a value derived
        /// from the plaintext and `λ`.
        pub fn divExact(self: *const Self, x: []const u64, q: *Elem) bool {
            comptime var s: usize = min_limbs;
            inline while (s <= max_limbs) : (s += step) {
                if (s == self.L) {
                    const m = self.m[0..s];
                    const inv = nt.invPow2(s, m);
                    var xl = [_]u64{0} ** s;
                    for (0..s) |i| xl[i] = if (i < x.len) x[i] else 0;
                    var qq: [s]u64 = undefined;
                    mulLow(s, &qq, &xl, &inv);
                    // q·m against all of x.
                    var prod: [2 * s]u64 = undefined;
                    limbs.mulSchoolbook(&prod, &qq, m);
                    var diff: u64 = 0;
                    const n = @max(x.len, 2 * s);
                    for (0..n) |i| {
                        const xi: u64 = if (i < x.len) x[i] else 0;
                        const pi: u64 = if (i < 2 * s) prod[i] else 0;
                        diff |= xi ^ pi;
                    }
                    q.* = zero;
                    q[0..s].* = qq;
                    std.crypto.secureZero(u64, &xl);
                    std.crypto.secureZero(u64, &prod);
                    return diff == 0;
                }
            }
            unreachable;
        }

        // ── primality ───────────────────────────────────────────────────────

        /// Miller-Rabin with `rounds` witnesses from `random`: `false` if one
        /// proves this (odd) modulus composite, and for `rounds = 0` (no
        /// evidence either way — refused rather than answered "prime"). A
        /// composite passes one round with probability at most 1/4 (the
        /// witnesses are near-uniform over `[2, m − 2]`, see `witness`), so
        /// `rounds` rounds bound it by `4^−rounds`. Build the modulus with
        /// `fromLimbsBits` from the candidate's known length, so nothing
        /// scans the secret value.
        ///
        /// Constant-time in the modulus's value along the path a PRIME takes
        /// — this runs on the secret candidates of RSA/Paillier/aux prime
        /// searches, where `std.crypto.ff`'s pow branched on its windows:
        /// `m − 1 = d·2^s` comes from `nt.oddPart` (masked shifts); the
        /// ladder is `pow` modulo the secret `m`; a witness is a random
        /// string reduced by `reduceBytesBE`, with no compare against `m`
        /// and no retry loop; and a round's verdicts (`x = 1` at the start,
        /// `x = −1` at any of the `s` squarings) are OR-ed before the one
        /// branch, which a prime always passes. What stays observable: `s`
        /// itself, through the
        /// number of squarings (the 2-adic valuation of `p − 1`: about two
        /// bits of a random prime on average, nothing for `p ≡ 3 mod 4`),
        /// and everything about a REJECTED candidate, a value thrown away.
        pub fn isProbablePrime(self: *const Self, random: std.Random, rounds: usize) bool {
            if (rounds == 0) return false; // no witness, no evidence: never "prime"
            if (self.nbits < 3) return true; // the only odd 2-bit modulus is 3
            var one = zero;
            one[0] = 1;
            var mm1 = self.m;
            defer std.crypto.secureZero(u64, &mm1);
            mm1[0] &= ~@as(u64, 1); // m odd: m − 1 clears bit 0
            var split = nt.oddPart(max_limbs, &mm1);
            defer std.crypto.secureZero(u64, &split.u);

            var buf: [witness_buf_len]u8 = undefined;
            defer std.crypto.secureZero(u8, &buf);
            var round: usize = 0;
            while (round < rounds) : (round += 1) {
                var a = self.witness(random, &buf, &mm1);
                defer std.crypto.secureZero(u64, &a);
                var x = self.pow(&a, &split.u);
                defer std.crypto.secureZero(u64, &x);
                var pass = @intFromBool(eql(&x, &one)) | @intFromBool(eql(&x, &mm1));
                var j: usize = 1;
                while (j < split.t) : (j += 1) {
                    x = self.sq(&x);
                    pass |= @intFromBool(eql(&x, &mm1));
                }
                if (pass == 0) return false;
            }
            return true;
        }

        /// Room for `bits + 64` random bits (`bits ≤ 64·max_limbs`).
        const witness_buf_len = 8 * max_limbs + 8;

        /// One Miller-Rabin witness, near-uniform over `[2, m − 2]`: `bits + 64`
        /// random bits reduced mod `m` (statistical distance from uniform below
        /// `2^−64`), then `0`, `1` and `m − 1` — which every odd `m` passes, so
        /// they would spend a round proving nothing — replaced by `2` under a
        /// mask. The witness depends on the secret `m`, so it stays inside
        /// constant-time code (`pow`) and is zeroed by the caller.
        fn witness(self: *const Self, random: std.Random, buf: *[witness_buf_len]u8, mm1: *const Elem) Elem {
            const wlen = (self.nbits + 64 + 7) / 8;
            random.bytes(buf[0..wlen]);
            var a = self.reduceBytesBE(buf[0..wlen]);
            var above1: u64 = a[0] >> 1; // non-zero ⟺ a ≥ 2
            for (a[1..]) |w| above1 |= w;
            var ne_mm1: u64 = 0; // non-zero ⟺ a ≠ m − 1
            for (a, mm1) |x, y| ne_mm1 |= x ^ y;
            const trivial = blackBox((nzBit(above1) & nzBit(ne_mm1)) -% 1);
            var two = zero;
            two[0] = 2;
            blend(max_limbs, &a, &two, trivial);
            return a;
        }

        // ── inversion ───────────────────────────────────────────────────────

        /// `a⁻¹ mod m`: if `gcd(a, m) = 1`, writes the inverse (`< m`) to
        /// `out` and returns `true`; else returns `false` (`out` then holds
        /// garbage). `a ≥ m` — including any non-zero limb above the slot,
        /// which the arithmetic would otherwise drop — is refused the same
        /// way (`false`), never answered with the inverse of a truncated
        /// value; reduce a wider operand with `reduceLimbs` first.
        /// Constant-time in `a` and in the modulus's value up to that
        /// verdict; the work depends on the modulus's bit length only.
        ///
        /// Bernstein–Yang divsteps ("Fast constant-time gcd computation and
        /// modular inversion", 2019, §11), one step at a time: `f = m`,
        /// `g = a`, `δ = 1`, and per step
        ///
        ///     if δ > 0 and g odd:  (δ, f, g) ← (1 − δ, g, (g − f)/2)
        ///     elif g odd:          (δ, f, g) ← (1 + δ, f, (g + f)/2)
        ///     else:                (δ, f, g) ← (1 + δ, f, g/2)
        ///
        /// with every branch a masked blend. `d`, `e` track `f ≡ d·a`,
        /// `g ≡ e·a (mod m)`, the halving of `g` becoming a multiplication of
        /// `e` by `2⁻¹ mod m`. After the paper's bound — `⌊(49b + 57)/17⌋`
        /// steps for `b ≥ 46` bits, `⌊(49b + 80)/17⌋` below (Theorem 11.2,
        /// `f² + 4g² ≤ 5·2^(2b)` holds for `0 ≤ g < f < 2^b`) — `g = 0` and
        /// `f = ±gcd(a, m)`. The verdict checks both, so a bound that ever
        /// fell short would refuse, not return a wrong inverse.
        ///
        /// One step at a time costs `O(b)` limb passes per step, `O(b²/64)`
        /// in all — about 6 000 steps of 33-limb passes at 2048 bits. That
        /// is for key setup and provers, not for a per-message hot path
        /// (batched 62-step transition matrices are the Backlog item).
        pub fn inverse(self: *const Self, a: *const Elem, out: *Elem) bool {
            // a < m over all of `Elem`, limbs above the slot included: folded
            // into the verdict, not branched on.
            var t = a.*;
            const below: u1 = limbs.subInto(&t, &self.m); // 1 ⟺ a < m
            std.crypto.secureZero(u64, &t);
            comptime var s: usize = min_limbs;
            inline while (s <= max_limbs) : (s += step) {
                if (s == self.L) {
                    const ok = self.inverseSlot(s, a, out);
                    return @as(u1, @intFromBool(ok)) & below == 1;
                }
            }
            unreachable;
        }

        fn inverseSlot(self: *const Self, comptime s: usize, a: *const Elem, out: *Elem) bool {
            const v = self.view(s);
            const W = s + 1; // f, g: two's complement, one sign limb on top
            var f = [_]u64{0} ** W;
            f[0..s].* = self.m[0..s].*;
            var g = [_]u64{0} ** W;
            g[0..s].* = a[0..s].*;
            var d = [_]u64{0} ** s;
            var e = [_]u64{0} ** s;
            e[0] = 1;
            const zero_s = [_]u64{0} ** s;
            defer std.crypto.secureZero(u64, &f);
            defer std.crypto.secureZero(u64, &g);
            defer std.crypto.secureZero(u64, &d);
            defer std.crypto.secureZero(u64, &e);

            // δ is a small signed counter (|δ| ≤ steps + 1); held as u64.
            var delta: u64 = 1;
            var k: usize = divstepCount(self.nbits);
            while (k > 0) : (k -= 1) {
                // δ > 0 ⟺ −δ < 0 (no overflow: δ is small).
                const pos: u64 = @bitCast(@as(i64, @bitCast(0 -% delta)) >> 63);
                const swap = blackBox(pos & (0 -% (g[0] & 1)));
                delta = (delta ^ swap) -% swap; // δ ← −δ under swap
                // (f, g) ← (g, −f), (d, e) ← (e, −d) under swap
                condSwap(W, &f, &g, swap);
                condNeg(W, &g, swap);
                condSwap(s, &d, &e, swap);
                const ne = v.sub(&zero_s, &e);
                blend(s, &e, &ne, swap);
                // g odd (always after a swap): g ← g + f, e ← e + d
                const odd = blackBox(0 -% (g[0] & 1));
                addMasked(W, &g, &f, odd);
                const ed = v.add(&e, &d);
                blend(s, &e, &ed, odd);
                // g ← g/2 (exact), e ← e/2 mod m
                sar1(W, &g);
                halveMod(s, &e, self.m[0..s]);
                delta +%= 1;
            }

            // g = 0 and f = ±1; the inverse is d·f.
            var gz: u64 = 0;
            for (g) |w| gz |= w;
            var plus: u64 = f[0] ^ 1; // f = 1
            var minus: u64 = ~f[0]; // f = −1 (all ones)
            for (f[1..]) |w| {
                plus |= w;
                minus |= ~w;
            }
            const neg_f = blackBox(nzBit(minus) -% 1); // all ones iff f = −1
            const nd = v.sub(&zero_s, &d);
            blend(s, &d, &nd, neg_f);
            out.* = zero;
            out[0..s].* = d;
            // ok ⟺ g = 0 and (f = 1 or f = −1)
            const bad = nzBit(gz) | (nzBit(plus) & nzBit(minus));
            return bad == 0;
        }

        /// `m⁻¹ mod n` for any `n ≥ 2` — **even included** — where `m` is
        /// this modulus: if `gcd(m, n) = 1`, writes the inverse (`< n`) to
        /// `out` and returns `true`; else returns `false` (`out` then holds
        /// garbage). Constant-time in `n` and `m` up to that verdict. `n`
        /// may be wider than `m` (an `Elem` of this type's full capacity).
        ///
        /// The even case is the one `inverse` cannot take (divsteps need an
        /// odd modulus), and the one the callers have: `d = Ñ⁻¹ mod φ(Ñ)`,
        /// `e⁻¹ mod (p − 1)`. It goes through the odd side instead: with
        /// `z = n⁻¹ mod m` (`inverse`, on `n mod m`), `n·z = 1 + k·m` for an
        /// integer `0 ≤ k < n`, and `m·(n − k) = n·m − n·z + 1 ≡ 1 (mod n)`.
        /// `k = (n·z − 1)/m` is an exact division, done as a Hensel division
        /// (a product with `m⁻¹ mod 2^(64·max_limbs)`, which holds all of
        /// `k`), so the answer `n − k` needs no reduction modulo `n`.
        pub fn inverseOfModulus(self: *const Self, n: *const Elem, out: *Elem) bool {
            var r = self.reduceLimbs(n);
            defer std.crypto.secureZero(u64, &r);
            var z: Elem = undefined;
            defer std.crypto.secureZero(u64, &z);
            const ok = self.inverse(&r, &z);

            var t: Elem = undefined;
            defer std.crypto.secureZero(u64, &t);
            mulLow(max_limbs, &t, n, &z); // n·z (< n·m, ≥ 1 when ok)
            var one = zero;
            one[0] = 1;
            _ = limbs.subInto(&t, &one);
            const minv = nt.invPow2(max_limbs, &self.m);
            var kq: Elem = undefined;
            defer std.crypto.secureZero(u64, &kq);
            mulLow(max_limbs, &kq, &t, &minv); // k = (n·z − 1)/m
            out.* = n.*;
            _ = limbs.subInto(out, &kq);

            // n ≥ 2: some bit above bit 0.
            var hi: u64 = n[0] >> 1;
            for (n[1..]) |w| hi |= w;
            return (@intFromBool(ok) & nzBit(hi)) == 1;
        }
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const Managed = std.math.big.int.Managed;

/// A big.int from an `Elem` (or any limb slice).
fn toBig(gpa: std.mem.Allocator, v: []const u64) !Managed {
    var r = try Managed.init(gpa);
    errdefer r.deinit();
    try r.ensureCapacity(v.len + 1);
    @memset(r.limbs, 0);
    @memcpy(r.limbs[0..v.len], v);
    r.normalize(v.len + 1);
    return r;
}

/// `a mod m` into a fresh big.int (no aliasing between divFloor's operands).
fn modBig(gpa: std.mem.Allocator, a: *const Managed, m: *const Managed) !Managed {
    var q = try Managed.init(gpa);
    defer q.deinit();
    var r = try Managed.init(gpa);
    errdefer r.deinit();
    try q.divFloor(&r, a, m);
    return r;
}

/// `x ← x mod m`.
fn reduceBig(gpa: std.mem.Allocator, x: *Managed, m: *const Managed) !void {
    var r = try modBig(gpa, x, m);
    defer r.deinit();
    try x.copy(r.toConst());
}

fn expectElemEqBig(gpa: std.mem.Allocator, want: *const Managed, got: []const u64) !void {
    var g = try toBig(gpa, got);
    defer g.deinit();
    if (!g.eql(want.*)) {
        std.debug.print("want {f}\n got {f}\n", .{ want.*, g });
        return error.TestExpectedEqual;
    }
}

/// A random odd modulus of exactly `nbits` bits.
fn randModulus(comptime D: type, rnd: std.Random, nbits: usize) D.Elem {
    var v = D.zero;
    const n = (nbits + 63) / 64;
    for (v[0..n]) |*w| w.* = rnd.int(u64);
    const top_bits: u6 = @intCast(nbits - (n - 1) * 64 - 1);
    v[n - 1] &= (@as(u64, 2) << top_bits) -% 1; // keep top_bits+1 bits
    v[n - 1] |= @as(u64, 1) << top_bits; // exact bit length
    v[0] |= 1;
    return v;
}

/// A random element `< m` (draw below the modulus's top limb, then reduce
/// through the big.int oracle is circular — so mask to bits−1 instead).
fn randBelow(comptime D: type, rnd: std.Random, mod: *const D) D.Elem {
    var v = D.zero;
    const nbits = mod.bits() - 1;
    const n = (nbits + 63) / 64;
    for (v[0..n]) |*w| w.* = rnd.int(u64);
    const rem = nbits - (n - 1) * 64;
    if (rem < 64) v[n - 1] &= (@as(u64, 1) << @intCast(rem)) - 1;
    return v;
}

fn diffAgainstBigInt(comptime max_bits: comptime_int, sizes: []const usize, seed: u64) !void {
    const D = DynModint(max_bits);
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    for (sizes) |nbits| {
        var round: usize = 0;
        while (round < 6) : (round += 1) {
            const mv = randModulus(D, rnd, nbits);
            const mod = try D.fromLimbs(&mv);
            try testing.expectEqual(nbits, mod.bits());
            var bm = try toBig(gpa, &mv);
            defer bm.deinit();

            const a = randBelow(D, rnd, &mod);
            const b = randBelow(D, rnd, &mod);
            var ba = try toBig(gpa, &a);
            defer ba.deinit();
            var bb = try toBig(gpa, &b);
            defer bb.deinit();
            var want = try Managed.init(gpa);
            defer want.deinit();

            // add / sub / neg / mul
            try want.add(&ba, &bb);
            try reduceBig(gpa, &want, &bm);
            try expectElemEqBig(gpa, &want, &mod.add(&a, &b));
            try want.sub(&ba, &bb);
            if (!want.isPositive() and !want.eqlZero()) try want.add(&want, &bm);
            try expectElemEqBig(gpa, &want, &mod.sub(&a, &b));
            try testing.expect(D.isZero(&mod.add(&a, &mod.neg(&a))));
            try want.mul(&ba, &bb);
            try reduceBig(gpa, &want, &bm);
            try expectElemEqBig(gpa, &want, &mod.mul(&a, &b));

            // pow (secret exponent) and powPublic agree with each other and
            // with big.int square-and-multiply over a 70-bit exponent.
            var e = D.zero;
            e[0] = rnd.int(u64);
            e[1] = rnd.int(u6);
            var e_be: [16]u8 = undefined;
            std.mem.writeInt(u128, &e_be, @as(u128, e[1]) << 64 | e[0], .big);
            const p_ct = mod.pow(&a, &e);
            const p_vt = mod.powPublic(&a, &e_be);
            try testing.expect(D.eql(&p_ct, &p_vt));
            {
                var acc = try Managed.initSet(gpa, 1);
                defer acc.deinit();
                var bit: usize = 70;
                while (bit > 0) {
                    bit -= 1;
                    try acc.sqr(&acc);
                    try reduceBig(gpa, &acc, &bm);
                    if ((e[bit / 64] >> @intCast(bit % 64)) & 1 == 1) {
                        try acc.mul(&acc, &ba);
                        try reduceBig(gpa, &acc, &bm);
                    }
                }
                try expectElemEqBig(gpa, &acc, &p_ct);
            }

            // reduceLimbs over a 2×-wide value, reduceBytesBE over an odd length
            var wide: [2 * D.max_limbs + 1]u64 = undefined;
            for (&wide) |*w| w.* = rnd.int(u64);
            var bw = try toBig(gpa, &wide);
            defer bw.deinit();
            try want.copy(bw.toConst());
            try reduceBig(gpa, &want, &bm);
            try expectElemEqBig(gpa, &want, &mod.reduceLimbs(&wide));
            var wb: [8 * D.max_limbs + 5]u8 = undefined;
            rnd.bytes(&wb);
            var wl: [D.max_limbs + 1]u64 = .{0} ** (D.max_limbs + 1);
            for (wb, 0..) |byte, i| {
                const pos = wb.len - 1 - i;
                wl[pos / 8] |= @as(u64, byte) << @intCast(8 * (pos % 8));
            }
            try testing.expect(D.eql(&mod.reduceLimbs(&wl), &mod.reduceBytesBE(&wb)));

            // bytes round trip and the canonical check
            var enc: [8 * D.max_limbs]u8 = undefined;
            mod.toBytesBE(&a, &enc);
            const back = try mod.elemFromBytesBE(&enc);
            try testing.expect(D.eql(&a, &back));
            var m_be: [8 * D.max_limbs]u8 = undefined;
            mod.toBytesBE(&mv, &m_be);
            try testing.expectError(error.NonCanonical, mod.elemFromBytesBE(&m_be));
            const short = m_be[m_be.len - mod.byteLen() ..];
            const mod2 = try D.fromBytesBE(short);
            try testing.expect(D.eql(&mod2.m, &mod.m) and D.eql(&mod2.r2, &mod.r2));

            // divExact: x = q·m divides; x + 1 does not.
            const qv = randBelow(D, rnd, &mod);
            var x: [2 * D.max_limbs]u64 = .{0} ** (2 * D.max_limbs);
            limbs.mulSchoolbook(&x, &qv, &mv);
            var q: D.Elem = undefined;
            try testing.expect(mod.divExact(&x, &q));
            try testing.expect(D.eql(&q, &qv));
            _ = limbs.addWideInto(&x, &[_]u64{1});
            try testing.expect(!mod.divExact(&x, &q));
        }
    }
}

test "DynModint matches std.math.big.int (max 4096: 2..4096-bit moduli)" {
    try diffAgainstBigInt(4096, &.{ 2, 3, 7, 17, 63, 64, 65, 127, 256, 255 + 64, 1024, 1536 + 7, 2048, 4096 }, 0x64796e5f_34303936);
}

test "DynModint matches std.math.big.int (max 8192, Paillier n² widths)" {
    try diffAgainstBigInt(8192, &.{ 2048, 4096, 8192 }, 0x64796e5f_38313932);
}

/// `gcd(a, b) == 1` through big.int.
fn coprimeBig(gpa: std.mem.Allocator, a: *const Managed, b: *const Managed) !bool {
    var g = try Managed.init(gpa);
    defer g.deinit();
    try g.gcd(a, b);
    return g.toConst().orderAgainstScalar(1) == .eq;
}

/// `x·y mod m == 1` through big.int.
fn isInverseBig(gpa: std.mem.Allocator, x: *const Managed, y: *const Managed, m: *const Managed) !bool {
    var p = try Managed.init(gpa);
    defer p.deinit();
    try p.mul(x, y);
    try reduceBig(gpa, &p, m);
    return p.toConst().orderAgainstScalar(1) == .eq;
}

test "DynModint inverse: every a below every odd m < 512 (verdict = gcd, value = inverse)" {
    const D = DynModint(256);
    var mv = D.zero;
    var m: u64 = 3;
    while (m < 512) : (m += 2) {
        mv[0] = m;
        const mod = try D.fromLimbs(&mv);
        var a: u64 = 0;
        while (a < m) : (a += 1) {
            var av = D.zero;
            av[0] = a;
            var y: D.Elem = undefined;
            const ok = mod.inverse(&av, &y);
            try testing.expectEqual(std.math.gcd(a, m) == 1, ok);
            if (ok) {
                try testing.expect(y[0] < m and D.isZero(&(y[1..].* ++ [_]u64{0})));
                try testing.expectEqual(@as(u128, 1), @as(u128, a) * y[0] % m);
            }
        }
    }
}

test "DynModint inverse matches std.math.big.int (64..4096-bit moduli, units and non-units)" {
    const D = DynModint(4096);
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x696e_7665_7273_65);
    const rnd = prng.random();
    for ([_]usize{ 46, 47, 64, 65, 127, 256, 1000, 1024, 2048, 2047 + 64, 4096 }) |nbits| {
        var round: usize = 0;
        while (round < 4) : (round += 1) {
            const mv = randModulus(D, rnd, nbits);
            const mod = try D.fromLimbsBits(&mv, nbits);
            var bm = try toBig(gpa, &mv);
            defer bm.deinit();
            const a = randBelow(D, rnd, &mod);
            var ba = try toBig(gpa, &a);
            defer ba.deinit();
            var y: D.Elem = undefined;
            const ok = mod.inverse(&a, &y);
            try testing.expectEqual(try coprimeBig(gpa, &ba, &bm), ok);
            if (ok) {
                var by = try toBig(gpa, &y);
                defer by.deinit();
                try testing.expect(by.order(bm) == .lt);
                try testing.expect(try isInverseBig(gpa, &ba, &by, &bm));
            }
            // a non-unit: m = 3·k, a = 3·j
            var m3 = D.zero;
            const k_limbs = (nbits - 2 + 63) / 64;
            for (m3[0..k_limbs]) |*w| w.* = rnd.int(u64);
            const rem = (nbits - 2) % 64;
            if (rem != 0) m3[k_limbs - 1] &= (@as(u64, 1) << @intCast(rem)) - 1;
            m3[0] |= 1;
            var three = D.zero;
            three[0] = 3;
            var prod: [2 * D.max_limbs]u64 = undefined;
            limbs.mulSchoolbook(&prod, &m3, &three);
            const mod3 = try D.fromLimbs(prod[0..D.max_limbs]);
            var a3 = D.zero;
            a3[0] = 3 * @as(u64, rnd.int(u32) | 1);
            try testing.expect(!mod3.inverse(&a3, &y));
            try testing.expect(!mod.inverse(&D.zero, &y));
        }
    }
}

test "DynModint inverse edges: 1, m−1, 2 and the smallest modulus" {
    const D = DynModint(1024);
    var prng = std.Random.DefaultPrng.init(11);
    const mv = randModulus(D, prng.random(), 1000);
    const mod = try D.fromLimbs(&mv);
    var one = D.zero;
    one[0] = 1;
    var y: D.Elem = undefined;
    try testing.expect(mod.inverse(&one, &y) and D.eql(&y, &one));
    var m1 = mv;
    m1[0] -= 1;
    try testing.expect(mod.inverse(&m1, &y) and D.eql(&y, &m1)); // (−1)⁻¹ = −1
    var two = D.zero;
    two[0] = 2;
    try testing.expect(mod.inverse(&two, &y));
    try testing.expect(D.eql(&mod.mul(&y, &two), &one));
    var three = D.zero;
    three[0] = 3;
    const m3 = try D.fromLimbs(&three);
    try testing.expect(m3.inverse(&two, &y) and y[0] == 2);
}

test "DynModint inverseOfModulus: m⁻¹ mod n for even and odd n of any width" {
    const D = DynModint(4096);
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6576_656e_6d6f_64);
    const rnd = prng.random();
    // (bits of m, bits of n): a public exponent against p − 1, Ñ against
    // φ(Ñ), and mixed widths both ways.
    const shapes = [_][2]usize{ .{ 2, 64 }, .{ 17, 1024 }, .{ 17, 2048 }, .{ 2048, 2047 }, .{ 2048, 2048 }, .{ 1000, 4096 }, .{ 4096, 300 }, .{ 65, 65 }, .{ 300, 2 } };
    for (shapes) |shape| {
        var round: usize = 0;
        while (round < 6) : (round += 1) {
            const mv = randModulus(D, rnd, shape[0]);
            const mod = try D.fromLimbs(&mv);
            var n = randModulus(D, rnd, shape[1]);
            if (round % 2 == 0) n[0] &= ~@as(u64, 1); // even half the time
            var bm = try toBig(gpa, &mv);
            defer bm.deinit();
            var bn = try toBig(gpa, &n);
            defer bn.deinit();
            var y: D.Elem = undefined;
            const ok = mod.inverseOfModulus(&n, &y);
            const want_ok = (try coprimeBig(gpa, &bm, &bn)) and bn.toConst().orderAgainstScalar(2) != .lt;
            try testing.expectEqual(want_ok, ok);
            if (ok) {
                var by = try toBig(gpa, &y);
                defer by.deinit();
                try testing.expect(by.order(bn) == .lt);
                try testing.expect(try isInverseBig(gpa, &bm, &by, &bn));
            }
        }
    }
    // gcd > 1, n = 0, n = 1, n = 2
    var e = D.zero;
    e[0] = 65537;
    const me = try D.fromLimbs(&e);
    var n = D.zero;
    var y: D.Elem = undefined;
    n[0] = 65537 * 4;
    try testing.expect(!me.inverseOfModulus(&n, &y));
    n[0] = 0;
    try testing.expect(!me.inverseOfModulus(&n, &y));
    n[0] = 1;
    try testing.expect(!me.inverseOfModulus(&n, &y));
    n[0] = 2;
    try testing.expect(me.inverseOfModulus(&n, &y) and y[0] == 1 and D.isZero(&(y[1..].* ++ [_]u64{0})));
    n[0] = 65536; // 65537 ≡ 1 mod 2^16
    try testing.expect(me.inverseOfModulus(&n, &y) and y[0] == 1);
}

test "DynModint isProbablePrime: every odd m < 3000, Carmichael numbers, a 2048-bit safe prime" {
    const D = DynModint(2048);
    var prng = std.Random.DefaultPrng.init(0x6d725f74_657374);
    const rnd = prng.random();
    var mv = D.zero;
    var m: u64 = 3;
    while (m < 3000) : (m += 2) {
        mv[0] = m;
        const nbits = 64 - @clz(m);
        const mod = try D.fromLimbsBits(&mv, nbits);
        var is_prime = true;
        var k: u64 = 3;
        while (k * k <= m) : (k += 2) {
            if (m % k == 0) is_prime = false;
        }
        try testing.expectEqual(is_prime, mod.isProbablePrime(rnd, 24));
    }
    // Carmichael numbers fool Fermat, not Miller-Rabin.
    for ([_]u64{ 561, 1105, 1729, 41041, 825265, 321197185, 5394826801, 232250619601 }) |c| {
        mv[0] = c;
        const mod = try D.fromLimbsBits(&mv, 64 - @clz(c));
        try testing.expect(!mod.isProbablePrime(rnd, 24));
    }
    // A Carmichael number with LARGE factors (Chernick: (6k+1)(12k+1)(18k+1),
    // k = 96076792050576470, factors ~59–61 bits): a random witness is
    // coprime to it, so a Fermat test (`a^(m−1) = 1`) passes every round —
    // the small Carmichael numbers above do not show that, their witnesses
    // hit a factor (mutation 2026-10-03: a Fermat mutant survived them).
    {
        var big: [24]u8 = undefined;
        _ = try std.fmt.hexToBytes(&big, "000c00000000026d14c0000029db0bebf000f0b38f39ee49");
        const cv = try D.loadBE(&big);
        const mod = try D.fromLimbsBits(&cv, 180);
        try testing.expect(!mod.isProbablePrime(rnd, 24));
    }
    // RFC 3526 group 14: a 2048-bit safe prime p, (p − 1)/2 prime too; p − 2
    // and p·(a 64-bit prime) are composite (the latter has p − 1's shape
    // and a large factor, so only a real witness finds it).
    const p_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
    var p_be: [256]u8 = undefined;
    _ = try std.fmt.hexToBytes(&p_be, p_hex);
    const pv = try D.loadBE(&p_be);
    const p = try D.fromLimbsBits(&pv, 2048);
    try testing.expect(p.isProbablePrime(rnd, 24));
    var half = pv;
    for (0..D.max_limbs - 1) |i| half[i] = (half[i] >> 1) | (half[i + 1] << 63);
    half[D.max_limbs - 1] >>= 1;
    try testing.expect((try D.fromLimbsBits(&half, 2047)).isProbablePrime(rnd, 24));
    var pm2 = pv;
    pm2[0] -= 2;
    try testing.expect(!(try D.fromLimbsBits(&pm2, 2048)).isProbablePrime(rnd, 24));
    const D2 = DynModint(2048 + 64);
    var prod: [2 * D2.max_limbs]u64 = .{0} ** (2 * D2.max_limbs);
    var pw = D2.zero;
    @memcpy(pw[0..D.max_limbs], &pv);
    var small = D2.zero;
    small[0] = 0xffff_ffff_ffff_ffc5; // the largest 64-bit prime
    limbs.mulSchoolbook(&prod, &pw, &small);
    const pq = try D2.fromLimbsBits(prod[0..D2.max_limbs], 2048 + 64);
    try testing.expect(!pq.isProbablePrime(rnd, 4));
}

/// `2^127 − 1` (a Mersenne prime) as a `DynModint(256)` modulus.
fn mersenne127() !DynModint(256) {
    const D = DynModint(256);
    var mv = D.zero;
    mv[0] = ~@as(u64, 0);
    mv[1] = (@as(u64, 1) << 63) - 1;
    return D.fromLimbsBits(&mv, 127);
}

test "DynModint isProbablePrime(rounds = 0) proves nothing: refused (review L1)" {
    const D = DynModint(256);
    var prng = std.Random.DefaultPrng.init(0x4c31);
    const rnd = prng.random();
    const p = try mersenne127();
    try testing.expect(!p.isProbablePrime(rnd, 0));
    try testing.expect(p.isProbablePrime(rnd, 1));
    var mv = D.zero;
    mv[0] = 3; // the early answer for the only odd 2-bit modulus
    const three = try D.fromLimbsBits(&mv, 2);
    try testing.expect(!three.isProbablePrime(rnd, 0));
    try testing.expect(three.isProbablePrime(rnd, 1));
    mv[0] = 561; // composite: zero rounds used to call it prime
    const c = try D.fromLimbsBits(&mv, 10);
    try testing.expect(!c.isProbablePrime(rnd, 0));
}

test "DynModint Miller-Rabin witnesses cover [2, m − 2], upper half included (review L2)" {
    const D = DynModint(256);
    var prng = std.Random.DefaultPrng.init(0x4c32);
    const rnd = prng.random();
    var buf: [D.witness_buf_len]u8 = undefined;
    // Small moduli: every value of [2, m − 2] is drawn, nothing outside it.
    for ([_]u64{ 5, 7, 11, 13, 101 }) |m| {
        var mv = D.zero;
        mv[0] = m;
        const mod = try D.fromLimbsBits(&mv, 64 - @clz(m));
        var mm1 = mv;
        mm1[0] -= 1;
        var seen = [_]bool{false} ** 128;
        for (0..4000) |_| {
            const a = mod.witness(rnd, &buf, &mm1);
            for (a[1..]) |w| try testing.expectEqual(@as(u64, 0), w);
            try testing.expect(a[0] >= 2 and a[0] <= m - 2);
            seen[a[0]] = true;
        }
        for (2..m - 1) |v| try testing.expect(seen[v]);
    }
    // 2^127 − 1: the draws spread over the whole range, about half of them in
    // the upper half [2^126, m − 2] (the old draw never left [2, 2^126)).
    const p = try mersenne127();
    var mm1 = p.m;
    mm1[0] -= 1;
    var upper: usize = 0;
    for (0..256) |_| {
        const a = p.witness(rnd, &buf, &mm1);
        try testing.expect(limbs.cmp(&a, &mm1) == .lt);
        try testing.expect(a[0] >= 2 or a[1] != 0);
        upper += @intCast((a[1] >> 62) & 1);
    }
    try testing.expect(upper >= 96 and upper <= 160);
}

test "DynModint inverse refuses a ≥ m, in the slot or above it (review L3)" {
    const D = DynModint(1024);
    var prng = std.Random.DefaultPrng.init(0x4c33);
    const mv = randModulus(D, prng.random(), 300);
    const mod = try D.fromLimbs(&mv);
    try testing.expect(mod.L < D.max_limbs);
    var one = D.zero;
    one[0] = 1;
    var out: D.Elem = undefined;
    var a = D.zero;
    a[0] = 2; // coprime to every odd m
    try testing.expect(mod.inverse(&a, &out));
    try testing.expect(D.eql(&mod.mul(&a, &out), &one));
    // a = m + 2: the same residue, but outside the operand contract
    var am = mv;
    _ = limbs.addInto(&am, &a);
    try testing.expect(!mod.inverse(&am, &out));
    try testing.expect(!mod.inverse(&mv, &out));
    // a = 2 + 2^(64·L): a limb above the slot, which the old code dropped,
    // answering 2⁻¹ — the inverse of a different number
    var wide = a;
    wide[mod.L] = 1;
    try testing.expect(!mod.inverse(&wide, &out));
    var top = a;
    top[D.max_limbs - 1] = @as(u64, 1) << 63;
    try testing.expect(!mod.inverse(&top, &out));
    // inverseOfModulus reduces its `n` first, so a wide `n` is still served:
    // m⁻¹ mod 2^(64·(max_limbs − 1)) is m's Hensel inverse
    var n = D.zero;
    n[D.max_limbs - 1] = 1;
    try testing.expect(mod.inverseOfModulus(&n, &out));
    const hensel = nt.invPow2(D.max_limbs, &mv);
    try testing.expectEqualSlices(u64, hensel[0 .. D.max_limbs - 1], out[0 .. D.max_limbs - 1]);
}

test "DynModint toBytesBE: the modulus's width or wider, zero-padded (review L5)" {
    const p = try mersenne127();
    try testing.expectEqual(@as(usize, 16), p.byteLen());
    var exact: [16]u8 = undefined;
    p.toBytesBE(&p.m, &exact);
    try testing.expectEqualSlices(u8, &([_]u8{0x7f} ++ [_]u8{0xff} ** 15), &exact);
    var wide: [20]u8 = undefined;
    p.toBytesBE(&p.m, &wide);
    try testing.expectEqualSlices(u8, &([_]u8{0} ** 4 ++ [_]u8{0x7f} ++ [_]u8{0xff} ** 15), &wide);
    // A shorter buffer is refused by a panic in every optimize mode (no
    // in-process test can catch one; the ReleaseFast probe in the 2026-10-06
    // CHANGELOG entry shows the old code truncating silently instead).
}

test "DynModint std.crypto.ff bridge round-trips and matches ff's own encoding" {
    const D = DynModint(4096);
    const Ff = std.crypto.ff.Modulus(4096);
    var prng = std.Random.DefaultPrng.init(0x66665f62);
    const rnd = prng.random();
    for ([_]usize{ 65, 1000, 2048, 4096 }) |nbits| {
        const mv = randModulus(D, rnd, nbits);
        const mod = try D.fromLimbs(&mv);
        var m_be: [512]u8 = undefined;
        mod.toBytesBE(&mv, &m_be);
        const fm = try Ff.fromBytes(m_be[512 - mod.byteLen() ..], .big);
        const viaff = try D.fromFf(fm);
        try testing.expect(D.eql(&viaff.m, &mod.m) and D.eql(&viaff.r2, &mod.r2));
        const a = randBelow(D, rnd, &mod);
        var a_be: [512]u8 = undefined;
        mod.toBytesBE(&a, &a_be);
        const fa = try Ff.Fe.fromBytes(fm, &a_be, .big);
        try testing.expect(D.eql(&D.elemFromFf(&fa.v), &a));
        const back = D.elemToFf(Ff.Fe, fm, &a);
        try testing.expect(back.eql(fa));
        var b_be: [512]u8 = undefined;
        try back.toBytes(&b_be, .big);
        try testing.expectEqualSlices(u8, &a_be, &b_be);
        // ff arithmetic on the bridged value agrees with DynModint's
        var want: [512]u8 = undefined;
        try fm.mul(back, fa).toBytes(&want, .big);
        mod.toBytesBE(&mod.mul(&a, &a), &b_be);
        try testing.expectEqualSlices(u8, &want, &b_be);
    }
}

test "DynModint fromLimbsBits: the caller's length, checked in one verdict" {
    const D = DynModint(1024);
    var prng = std.Random.DefaultPrng.init(0x6269_7473);
    const rnd = prng.random();
    for ([_]usize{ 2, 63, 64, 65, 500, 1024 }) |nbits| {
        const mv = randModulus(D, rnd, nbits);
        const a = try D.fromLimbs(&mv);
        const b = try D.fromLimbsBits(&mv, nbits);
        try testing.expect(a.L == b.L and a.nbits == b.nbits and D.eql(&a.r2, &b.r2) and D.eql(&a.digit_mont, &b.digit_mont));
        if (nbits < 1024) try testing.expectError(error.NonCanonical, D.fromLimbsBits(&mv, nbits + 1)); // top bit not set
        if (nbits > 2) try testing.expectError(error.NonCanonical, D.fromLimbsBits(&mv, nbits - 1)); // a bit above
        var even = mv;
        even[0] &= ~@as(u64, 1);
        try testing.expectError(error.NonCanonical, D.fromLimbsBits(&even, nbits));
    }
    var one = D.zero;
    one[0] = 1;
    try testing.expectError(error.ModulusTooSmall, D.fromLimbsBits(&one, 1));
    try testing.expectError(error.Overflow, D.fromLimbsBits(&one, 1025));
}

test "DynModint select" {
    const D = DynModint(256);
    var a = D.zero;
    a[0] = 5;
    a[3] = 7;
    var b = D.zero;
    b[1] = 9;
    try testing.expect(D.eql(&D.select(true, &a, &b), &a));
    try testing.expect(D.eql(&D.select(false, &a, &b), &b));
}

test "DynModint slots: limb count picks the smallest multiple of step" {
    const D = DynModint(4096);
    var v = D.zero;
    v[0] = 1;
    v[1] = 1;
    try testing.expectEqual(@as(usize, 4), (try D.fromLimbs(&v)).L);
    v[4] = 1;
    try testing.expectEqual(@as(usize, 8), (try D.fromLimbs(&v)).L);
    v[63] = 1;
    try testing.expectEqual(@as(usize, 64), (try D.fromLimbs(&v)).L);
    try testing.expectEqual(@as(usize, 64), D.max_limbs);
    try testing.expectEqual(@as(usize, 4), DynModint(65).max_limbs);
}

test "DynModint rejects even, small and oversized moduli" {
    const D = DynModint(256);
    var v = D.zero;
    v[0] = 1;
    try testing.expectError(error.ModulusTooSmall, D.fromLimbs(&v));
    v[1] = 1;
    v[0] = 2;
    try testing.expectError(error.EvenModulus, D.fromLimbs(&v));
    try testing.expectError(error.Overflow, D.fromBytesBE(&([_]u8{1} ++ [_]u8{0} ** 31 ++ [_]u8{1})));
    // leading zero bytes past the capacity are fine
    const ok = try D.fromBytesBE(&([_]u8{0} ** 40 ++ [_]u8{ 1, 0, 0, 0, 0, 0, 0, 0, 3 }));
    try testing.expectEqual(@as(usize, 65), ok.bits());
}

test "DynModint edges: zero and m−1, pow by zero, divExact of zero" {
    const D = DynModint(1024);
    var prng = std.Random.DefaultPrng.init(7);
    const mv = randModulus(D, prng.random(), 1000);
    const mod = try D.fromLimbs(&mv);
    var m1 = mv;
    m1[0] -= 1;
    try testing.expect(D.isZero(&mod.add(&m1, &mod.reduceLimbs(&[_]u64{1}))));
    try testing.expect(D.eql(&mod.sub(&D.zero, &m1), &mod.reduceLimbs(&[_]u64{1})));
    try testing.expect(D.eql(&mod.mul(&m1, &m1), &mod.reduceLimbs(&[_]u64{1})));
    var one = D.zero;
    one[0] = 1;
    try testing.expect(D.eql(&mod.pow(&m1, &D.zero), &one));
    try testing.expect(D.eql(&mod.powPublic(&m1, &.{}), &one));
    try testing.expect(D.isZero(&mod.reduceLimbs(&mv)));
    try testing.expect(D.isZero(&mod.reduceLimbs(&.{})));
    var q: D.Elem = undefined;
    try testing.expect(mod.divExact(&.{}, &q) and D.isZero(&q));
    try testing.expect(mod.divExact(&mv, &q) and D.eql(&q, &one));
    // a quotient of 2^(64·L) does not fit: refused, not truncated
    var big: [2 * D.max_limbs + 1]u64 = .{0} ** (2 * D.max_limbs + 1);
    @memcpy(big[mod.L .. mod.L + D.max_limbs], &mv);
    try testing.expect(!mod.divExact(&big, &q));
    // an exact low half with a non-zero limb above 2·L is still inexact
    var hi: [2 * D.max_limbs + 1]u64 = .{0} ** (2 * D.max_limbs + 1);
    limbs.mulSchoolbook(hi[0 .. 2 * D.max_limbs], &mv, &one);
    try testing.expect(mod.divExact(&hi, &q) and D.eql(&q, &one));
    hi[2 * mod.L] = 1;
    try testing.expect(!mod.divExact(&hi, &q));
}
