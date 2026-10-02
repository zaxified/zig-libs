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
        /// one below 3. Constant-time in the value; the bit length (which
        /// picks the slot) is treated as public.
        pub fn fromLimbs(v: *const Elem) Error!Self {
            if (v[0] & 1 == 0) return error.EvenModulus;
            const n = activeLimbs(v);
            if (n == 1 and v[0] < 3) return error.ModulusTooSmall;
            const nbits = (n - 1) * 64 + (64 - @clz(v[n - 1]));
            const d: u7 = @intCast(@min(64, nbits - 1));
            const slot = slotFor(n);
            comptime var s: usize = min_limbs;
            inline while (s <= max_limbs) : (s += step) {
                if (s == slot) {
                    const mm = try Mod(s).fromElem(v[0..s].*);
                    var self: Self = .{
                        .L = s,
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
            const n = activeLimbs(&self.m);
            return (n - 1) * 64 + (64 - @clz(self.m[n - 1]));
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
        /// `out` must hold the value (`out.len ≥ byteLen()` always does for a
        /// canonical element). Branches on positions only.
        pub fn toBytesBE(self: *const Self, e: *const Elem, out: []u8) void {
            std.debug.assert(out.len >= self.byteLen());
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
                    // inv = m⁻¹ mod 2^(64s): Newton from the 64-bit inverse,
                    // precision doubling each step; the step count depends on
                    // `s` only.
                    var inv = [_]u64{0} ** s;
                    inv[0] = 0 -% self.n0inv;
                    var prec: usize = 64;
                    while (prec < 64 * s) : (prec *= 2) {
                        var t: [s]u64 = undefined;
                        mulLow(s, &t, m, &inv); // m·y
                        var two = [_]u64{0} ** s;
                        two[0] = 2;
                        _ = limbs.subInto(&two, &t); // 2 − m·y
                        var y: [s]u64 = undefined;
                        mulLow(s, &y, &inv, &two);
                        inv = y;
                    }
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
    };
}

/// `z = x·y mod 2^(64n)` — the low half of the schoolbook product.
fn mulLow(comptime n: usize, z: *[n]u64, x: *const [n]u64, y: *const [n]u64) void {
    z.* = [_]u64{0} ** n;
    for (0..n) |i| {
        var carry: u64 = 0;
        for (0..n - i) |j| {
            const p = @as(u128, x[i]) * @as(u128, y[j]) + z[i + j] + carry;
            z[i + j] = @truncate(p);
            carry = @truncate(p >> 64);
        }
    }
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
