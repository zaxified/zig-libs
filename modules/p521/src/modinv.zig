// SPDX-License-Identifier: MIT

//! modinv — constant-time modular inversion for an odd modulus of up to 1024
//! bits by Bernstein–Yang "safegcd" divsteps (eprint 2019/266), in the
//! 62-bit-batched shape libsecp256k1's `modinv64` popularised: batches of 59
//! divsteps, each run on the low 64 bits of `f`/`g` only and collapsed into a
//! 2×2 transition matrix that is then applied ONCE to the full signed-62
//! vectors `(f, g)` and `(d, e)`.
//!
//! ## Why this exists
//!
//! A Fermat inversion `a^(m−2)` costs about 1.25 modular products per bit of
//! the modulus; the divstep inverse costs a fixed number of 64-bit steps and
//! a few hundred `i64×i64→i128` products, several times less at 384 and 521
//! bits. The routine is generic over the modulus (`Safegcd(m)` is one type
//! per modulus) so every field in the module shares one audited routine.
//!
//! ## Shape
//!
//! Values are `Signed62`: `L = ⌈bits/62⌉` signed 64-bit limbs holding 62 bits
//! each, `Σ v[i]·2^(62·i)`, so a full 2^64-limb value maps in without loss and
//! intermediate limbs may go negative. One batch:
//!
//!   1. `divsteps59` — 59 divsteps on `(zeta, f mod 2^64, g mod 2^64)` with
//!      `u,v,q,r` starting at `8·I` so the matrix ends scaled by 2^62;
//!   2. `updateDE` — `(d, e) ← (t·(d, e) + m·(md, me)) / 2^62` with `md, me`
//!      chosen so the division is exact (this is where the modulus enters:
//!      `d`/`e` track `f`/`g` modulo `m`);
//!   3. `updateFG` — `(f, g) ← t·(f, g) / 2^62` (exact by construction).
//!
//! The number of divsteps for a `bits`-bit modulus is the proven bound
//! `⌊(45907·bits + 26313) / 19929⌋` (Wuille / Bernstein–Yang improved bound,
//! the one libsecp256k1 and `crypto-bigint` use; 590 at 256 bits), rounded up
//! to whole batches of 59: 885 at 384 bits, 1239 at 521 bits. After them
//! `g = 0` and `f = ±1` (the gcd, for an input coprime to the modulus); `d`
//! then holds `±x⁻¹` and `normalize` folds the sign of `f` in and brings the
//! result to `[0, m)`. Input `0` yields `0` (the `invert(0) == 0` convention
//! of the fields this serves).
//!
//! ## Constant-time contract
//!
//! Fixed trip counts everywhere (the batch count and 59 divsteps are
//! functions of the PUBLIC modulus). Every data-dependent decision —
//! `zeta < 0`, `g` odd, the signs of `d`/`e` and of the final `f`, the two
//! conditional modulus adds in `normalize` — is a masked select on an
//! all-ones/zero mask, and each mask is laundered through `blackBox` so LLVM
//! cannot recover the 0/1 range and lower it to a branch or a CMOV on the
//! secret. Multiplications are `i64×i64→i128` (`imul`), in the DIT set on
//! every target this collection builds for. The only branch is
//! `if (m[i] != 0)`, on the PUBLIC comptime modulus.

const std = @import("std");

const M62: u64 = (1 << 62) - 1;
const M62i: i64 = @intCast(M62);

/// Optimization barrier: launder a mask through an empty inline-asm so LLVM
/// loses its range knowledge and cannot rewrite the masked select as a
/// branch. No-op at runtime; identity in the comptime interpreter.
inline fn blackBox(x: u64) u64 {
    if (@inComptime()) return x;
    return asm volatile (""
        : [ret] "=r" (-> u64),
        : [x] "0" (x),
    );
}

inline fn blackBoxI(x: i64) i64 {
    return @bitCast(blackBox(@bitCast(x)));
}

/// The 2×2 transition matrix of one batch, scaled by 2^62.
const Trans = struct { u: i64, v: i64, q: i64, r: i64 };

/// 59 divsteps on the low words of `f` and `g`. Returns the new `zeta`
/// (`zeta = −(delta + ½)`, so it starts at −1) and the matrix `t` with
/// `t·(f0, g0) = 2^62·(f', g')`.
fn divsteps59(zeta_in: i64, f0: u64, g0: u64) struct { zeta: i64, t: Trans } {
    var u: u64 = 8;
    var v: u64 = 0;
    var q: u64 = 0;
    var r: u64 = 8;
    var f = f0;
    var g = g0;
    var zeta = zeta_in;
    var i: usize = 3;
    while (i < 62) : (i += 1) {
        // masks: zeta < 0, g odd — both laundered (see the module doc).
        var mask1: u64 = blackBox(@bitCast(zeta >> 63));
        const mask2: u64 = blackBox(0 -% (g & 1));
        // x,y,z = conditionally negated f,u,v.
        const x = (f ^ mask1) -% mask1;
        const y = (u ^ mask1) -% mask1;
        const z = (v ^ mask1) -% mask1;
        // conditionally add x,y,z to g,q,r.
        g +%= x & mask2;
        q +%= y & mask2;
        r +%= z & mask2;
        // from here mask1 means (zeta < 0) AND (g was odd).
        mask1 &= mask2;
        // zeta ← −zeta−2 under mask1, else zeta−1.
        zeta = (zeta ^ @as(i64, @bitCast(mask1))) -% 1;
        // conditionally add g,q,r to f,u,v.
        f +%= g & mask1;
        u +%= q & mask1;
        v +%= r & mask1;
        g >>= 1;
        u <<= 1;
        v <<= 1;
    }
    return .{ .zeta = zeta, .t = .{
        .u = @bitCast(u),
        .v = @bitCast(v),
        .q = @bitCast(q),
        .r = @bitCast(r),
    } };
}

inline fn mul128(a: i64, b: i64) i128 {
    return @as(i128, a) * @as(i128, b);
}

inline fn low62(c: i128) i64 {
    return @as(i64, @truncate(c)) & M62i;
}

/// The inversion routine for one odd modulus `m` (`2 < m < 2^1024`).
pub fn Safegcd(comptime m: u1024) type {
    comptime std.debug.assert(m & 1 == 1 and m > 2);
    return struct {
        /// Bit length of the modulus.
        pub const bits: usize = 1024 - @clz(m);
        /// 64-bit words of an input/output value.
        pub const words: usize = (bits + 63) / 64;
        /// Signed-62 limbs of a working value.
        const L: usize = (bits + 61) / 62;
        /// Proven divstep bound for `bits`-bit inputs, in whole batches.
        pub const batches: usize = ((45907 * bits + 26313) / 19929 + 58) / 59;

        pub const Word = [words]u64;
        const Signed62 = [L]i64;

        const modulus: Signed62 = fromWords(wordsOf(m));
        /// `m⁻¹ mod 2^62`, the Montgomery-style factor that makes the
        /// `updateDE` division exact.
        const modulus_inv62: u64 = blk: {
            const m0: u64 = @truncate(m);
            // m⁻¹ mod 2^64 by Newton iteration (m odd ⇒ m⁻¹ ≡ m mod 8, then
            // each step doubles the correct bits: 3 → 6 → 12 → 24 → 48 → 96).
            var inv: u64 = m0;
            for (0..5) |_| inv *%= 2 -% m0 *% inv;
            std.debug.assert(m0 *% inv == 1);
            break :blk inv & M62;
        };

        fn wordsOf(comptime x: u1024) Word {
            var r: Word = undefined;
            var v = x;
            for (0..words) |i| {
                r[i] = @truncate(v);
                v >>= 64;
            }
            return r;
        }

        /// Full 2^64 words (little-endian, value `< 2^(64·words)`) → signed-62
        /// limbs. All shifts are by comptime constants.
        fn fromWords(a: Word) Signed62 {
            var r: Signed62 = undefined;
            inline for (0..L) |i| {
                var acc: u64 = 0;
                inline for (0..words) |j| {
                    const shift = @as(i32, 64 * j) - @as(i32, 62 * i);
                    if (shift >= 0 and shift < 62) {
                        acc |= a[j] << @intCast(shift);
                    } else if (shift < 0 and shift > -64) {
                        acc |= a[j] >> @intCast(-shift);
                    }
                }
                r[i] = @intCast(acc & M62);
            }
            return r;
        }

        /// Signed-62 limbs → full words. Requires a NORMALIZED value: every
        /// limb in `[0, 2^62)` and the value `< 2^(64·words)`.
        fn toWords(s: Signed62) Word {
            var r: Word = undefined;
            inline for (0..words) |j| {
                var acc: u64 = 0;
                inline for (0..L) |i| {
                    const v: u64 = @intCast(s[i]);
                    const shift = @as(i32, 62 * i) - @as(i32, 64 * j);
                    if (shift >= 0 and shift < 64) {
                        acc |= v << @intCast(shift);
                    } else if (shift < 0 and shift > -62) {
                        acc |= v >> @intCast(-shift);
                    }
                }
                r[j] = acc;
            }
            return r;
        }

        /// `(d, e) ← (t·(d, e) + m·(md, me)) / 2^62`, with `md, me` chosen so
        /// the division is exact. Input and output `d, e` lie in `(−2m, m)`.
        fn updateDE(d: *Signed62, e: *Signed62, t: Trans) void {
            const dv = d.*;
            const ev = e.*;
            // [md, me] = [u, q] if d < 0, plus [v, r] if e < 0.
            const sd: i64 = blackBoxI(dv[L - 1] >> 63);
            const se: i64 = blackBoxI(ev[L - 1] >> 63);
            var md: i64 = (t.u & sd) +% (t.v & se);
            var me: i64 = (t.q & sd) +% (t.r & se);
            var cd: i128 = mul128(t.u, dv[0]) + mul128(t.v, ev[0]);
            var ce: i128 = mul128(t.q, dv[0]) + mul128(t.r, ev[0]);
            // Correct md, me so the low 62 bits of t·(d,e) + m·(md,me) vanish.
            md -%= @intCast((modulus_inv62 *% @as(u64, @truncate(@as(u128, @bitCast(cd)))) +% @as(u64, @bitCast(md))) & M62);
            me -%= @intCast((modulus_inv62 *% @as(u64, @truncate(@as(u128, @bitCast(ce)))) +% @as(u64, @bitCast(me))) & M62);
            cd += mul128(modulus[0], md);
            ce += mul128(modulus[0], me);
            std.debug.assert(low62(cd) == 0);
            std.debug.assert(low62(ce) == 0);
            cd >>= 62;
            ce >>= 62;
            inline for (1..L) |i| {
                cd += mul128(t.u, dv[i]) + mul128(t.v, ev[i]);
                ce += mul128(t.q, dv[i]) + mul128(t.r, ev[i]);
                if (comptime modulus[i] != 0) { // comptime modulus limb: folded away
                    cd += mul128(modulus[i], md);
                    ce += mul128(modulus[i], me);
                }
                d[i - 1] = low62(cd);
                e[i - 1] = low62(ce);
                cd >>= 62;
                ce >>= 62;
            }
            d[L - 1] = @intCast(cd);
            e[L - 1] = @intCast(ce);
        }

        /// `(f, g) ← t·(f, g) / 2^62` (exact by construction of `t`).
        fn updateFG(f: *Signed62, g: *Signed62, t: Trans) void {
            const fv = f.*;
            const gv = g.*;
            var cf: i128 = mul128(t.u, fv[0]) + mul128(t.v, gv[0]);
            var cg: i128 = mul128(t.q, fv[0]) + mul128(t.r, gv[0]);
            std.debug.assert(low62(cf) == 0);
            std.debug.assert(low62(cg) == 0);
            cf >>= 62;
            cg >>= 62;
            inline for (1..L) |i| {
                cf += mul128(t.u, fv[i]) + mul128(t.v, gv[i]);
                cg += mul128(t.q, fv[i]) + mul128(t.r, gv[i]);
                f[i - 1] = low62(cf);
                g[i - 1] = low62(cg);
                cf >>= 62;
                cg >>= 62;
            }
            f[L - 1] = @intCast(cf);
            g[L - 1] = @intCast(cg);
        }

        /// Bring `r` from `(−2m, m)` to `[0, m)`, negating first iff `sign < 0`.
        fn normalize(r: *Signed62, sign: i64) void {
            var v = r.*;
            // Add m if negative: (−2m, m) → (−m, m); then negate on request.
            var cond_add: i64 = blackBoxI(v[L - 1] >> 63);
            inline for (0..L) |i| v[i] +%= modulus[i] & cond_add;
            const cond_negate: i64 = blackBoxI(sign >> 63);
            inline for (0..L) |i| v[i] = (v[i] ^ cond_negate) -% cond_negate;
            // Propagate the top bits so every limb is back in (−2^62, 2^62).
            inline for (0..L - 1) |i| {
                v[i + 1] +%= v[i] >> 62;
                v[i] &= M62i;
            }
            // Still negative ⇒ add m once more: now in [0, m).
            cond_add = blackBoxI(v[L - 1] >> 63);
            inline for (0..L) |i| v[i] +%= modulus[i] & cond_add;
            inline for (0..L - 1) |i| {
                v[i + 1] +%= v[i] >> 62;
                v[i] &= M62i;
            }
            r.* = v;
        }

        /// `x⁻¹ mod m` for `0 ≤ x < m`; `invert(0) == 0`. Constant-time in
        /// `x`; one instantiation per modulus, whose limbs fold into
        /// immediates.
        pub fn invert(x: Word) Word {
            var d: Signed62 = @splat(0);
            var e: Signed62 = @splat(0);
            e[0] = 1;
            var f = modulus;
            var g = fromWords(x);
            var zeta: i64 = -1;
            var i: usize = 0;
            while (i < batches) : (i += 1) {
                const step = divsteps59(zeta, @bitCast(f[0]), @bitCast(g[0]));
                zeta = step.zeta;
                updateDE(&d, &e, step.t);
                updateFG(&f, &g, step.t);
            }
            // The bound guarantees g = 0 and f = ±gcd here.
            normalize(&d, f[L - 1]);
            return toWords(d);
        }
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

/// The moduli this module inverts modulo (base field, scalar field).
const moduli = .{ (1 << 521) - 1, @import("scalar.zig").field_order };

// ── tests ───────────────────────────────────────────────────────────────────

fn toInt(comptime S: type, l: S.Word) u1100 {
    var v: u1100 = 0;
    var i: usize = S.words;
    while (i > 0) {
        i -= 1;
        v = (v << 64) | l[i];
    }
    return v;
}

fn fromInt(comptime S: type, x: u1100) S.Word {
    var r: S.Word = undefined;
    var v = x;
    for (0..S.words) |i| {
        r[i] = @truncate(v);
        v >>= 64;
    }
    return r;
}

fn mulMod(a: u1100, b: u1100, m: u1100) u1100 {
    // Shift-and-add: operands are < 2^521 and the product would not fit.
    var r: u1100 = 0;
    var x = a % m;
    var y = b;
    while (y != 0) : (y >>= 1) {
        if (y & 1 == 1) r = (r + x) % m;
        x = (x + x) % m;
    }
    return r;
}

test "signed-62 limb conversion round-trips" {
    inline for (moduli) |m| {
        const S = Safegcd(m);
        var prng = std.Random.DefaultPrng.init(0x62_62_62);
        const rand = prng.random();
        for (0..500) |_| {
            var a: S.Word = undefined;
            rand.bytes(std.mem.asBytes(&a));
            // Keep the value below 2^bits so it fits the signed-62 limbs.
            if (S.bits % 64 != 0) a[S.words - 1] &= (@as(u64, 1) << @intCast(S.bits % 64)) - 1;
            try std.testing.expectEqual(a, S.toWords(S.fromWords(a)));
        }
        try std.testing.expectEqual(@as(S.Word, @splat(0)), S.toWords(S.fromWords(@splat(0))));
    }
}

test "invert: x·x⁻¹ ≡ 1 for random x and edges; invert(0) == 0" {
    var prng = std.Random.DefaultPrng.init(0x1EE7_5AFE_6CD);
    const rand = prng.random();
    inline for (moduli) |m| {
        const S = Safegcd(m);
        try std.testing.expectEqual(fromInt(S, 0), S.invert(fromInt(S, 0)));
        var edges: [20]u1100 = .{ 1, 2, 3, m - 1, m - 2, m - 3, m >> 1, (m >> 1) + 1, m - 4, 5, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        var n_edges: usize = 11;
        // Values near powers of two (and below the modulus), all-ones runs.
        var k: usize = 32;
        while (k < S.bits and n_edges < 20) : (k += 61) {
            const v: u1100 = (@as(u1100, 1) << @intCast(k)) % m;
            if (v != 0) {
                edges[n_edges] = v;
                n_edges += 1;
            }
        }
        for (edges[0..n_edges]) |x| {
            const inv = toInt(S, S.invert(fromInt(S, x)));
            try std.testing.expect(inv < m);
            try std.testing.expectEqual(@as(u1100, 1), mulMod(x, inv, m));
        }
        for (0..400) |_| {
            var xb: u1100 = 0;
            rand.bytes(std.mem.asBytes(&xb)[0..(S.words * 8)]);
            xb %= m;
            if (xb == 0) continue;
            const inv = toInt(S, S.invert(fromInt(S, xb)));
            try std.testing.expect(inv < m);
            try std.testing.expectEqual(@as(u1100, 1), mulMod(xb, inv, m));
        }
    }
}

// ── mutation 2026-11-25: unit properties of the three batch steps ───────────

fn sToInt(comptime S: type, s: S.Signed62) i2048 {
    var v: i2048 = 0;
    var i: usize = S.L;
    while (i > 0) {
        i -= 1;
        v = (v << 62) + s[i];
    }
    return v;
}

/// Signed-62 limbs of `x` in the form the batch steps produce: every limb in
/// `[0, 2^62)` except the top one, which carries the sign.
fn intToS(comptime S: type, x: i2048) S.Signed62 {
    var r: S.Signed62 = undefined;
    var v = x;
    for (0..S.L - 1) |i| {
        r[i] = @intCast(v & M62);
        v >>= 62;
    }
    r[S.L - 1] = @intCast(v);
    return r;
}

test "mutation 2026-11-25: divsteps59 equals 59 reference divsteps over the integers (zeta and the 2^62-scaled matrix)" {
    var prng = std.Random.DefaultPrng.init(0xD1_57_E9);
    const rand = prng.random();
    for (0..3000) |_| {
        const f0: u64 = rand.int(u64) | 1;
        const g0: u64 = rand.int(u64);
        const zeta0: i64 = rand.intRangeAtMost(i64, -400, 400);
        const step = divsteps59(zeta0, f0, g0);
        // delta + 1/2 = D = -zeta; swap iff D > 0 and g odd (BY19 divstep).
        var D: i128 = -@as(i128, zeta0);
        var f: i128 = f0;
        var g: i128 = g0;
        for (0..59) |_| {
            if (D >= 1 and g & 1 == 1) {
                const nf = g;
                g = @divExact(g - f, 2);
                f = nf;
                D = 2 - D;
            } else {
                if (g & 1 == 1) g += f;
                g = @divExact(g, 2);
                D += 1;
            }
        }
        try std.testing.expectEqual(-D, @as(i128, step.zeta));
        const t = step.t;
        try std.testing.expectEqual(f << 62, @as(i128, t.u) * f0 + @as(i128, t.v) * g0);
        try std.testing.expectEqual(g << 62, @as(i128, t.q) * f0 + @as(i128, t.r) * g0);
    }
}

fn randIn(comptime m: u1024, rand: std.Random) i2048 {
    // Uniform-ish in (-2m, m), with the two ends over-represented.
    const span: u1100 = 3 * @as(u1100, m) - 1;
    var raw: u1100 = 0;
    rand.bytes(std.mem.asBytes(&raw)[0..140]);
    raw %= span;
    const base: i2048 = -2 * @as(i2048, m) + 1;
    return switch (rand.uintLessThan(u8, 4)) {
        0 => base + @as(i2048, @intCast(rand.int(u64))),
        1 => @as(i2048, m) - 1 - @as(i2048, @intCast(rand.int(u64))),
        else => base + @as(i2048, @intCast(raw)),
    };
}

test "mutation 2026-11-25: updateDE keeps d and e in (-2m, m) and divides by 2^62 exactly" {
    var prng = std.Random.DefaultPrng.init(0xDE_DE_62);
    const rand = prng.random();
    inline for (moduli) |m| {
        const S = Safegcd(m);
        const mi: i2048 = m;
        const bound: i64 = 1 << 62;
        for (0..2500) |_| {
            const di = randIn(m, rand);
            const ei = randIn(m, rand);
            // A matrix with |u| + |v| <= 2^62 and |q| + |r| <= 2^62, the
            // bound a divsteps59 matrix obeys; half of them at the extreme.
            var tr: [4]i64 = undefined;
            for ([_]usize{ 0, 2 }) |k| {
                const big = rand.boolean();
                const a: i64 = if (big) bound - rand.intRangeAtMost(i64, 0, 1000) else rand.intRangeAtMost(i64, 0, bound);
                const b: i64 = rand.intRangeAtMost(i64, 0, bound - a);
                tr[k] = if (rand.boolean()) a else -a;
                tr[k + 1] = if (rand.boolean()) b else -b;
            }
            const t: Trans = .{ .u = tr[0], .v = tr[1], .q = tr[2], .r = tr[3] };
            var d = intToS(S, di);
            var e = intToS(S, ei);
            S.updateDE(&d, &e, t);
            const dn = sToInt(S, d);
            const en = sToInt(S, e);
            try std.testing.expect(dn > -2 * mi and dn < mi);
            try std.testing.expect(en > -2 * mi and en < mi);
            const two62: i2048 = @as(i2048, 1) << 62;
            try std.testing.expectEqual(@as(i2048, 0), @mod(dn * two62 - (@as(i2048, t.u) * di + @as(i2048, t.v) * ei), mi));
            try std.testing.expectEqual(@as(i2048, 0), @mod(en * two62 - (@as(i2048, t.q) * di + @as(i2048, t.r) * ei), mi));
        }
    }
}

test "mutation 2026-11-25: normalize reduces any value in (-2m, m), negated or not, into [0, m)" {
    var prng = std.Random.DefaultPrng.init(0x40_12_AA);
    const rand = prng.random();
    inline for (moduli) |m| {
        const S = Safegcd(m);
        const mi: i2048 = m;
        for (0..3000) |_| {
            const x = randIn(m, rand);
            const neg = rand.boolean();
            var r = intToS(S, x);
            // `sign` is the top limb of `f`: -1 for a negative f, 0 or 1 otherwise.
            S.normalize(&r, if (neg) -1 else rand.intRangeAtMost(i64, 0, 1));
            const want = @mod(if (neg) -x else x, mi);
            try std.testing.expectEqual(want, sToInt(S, r));
        }
    }
}
