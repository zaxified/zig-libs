// SPDX-License-Identifier: MIT

//! modinv — constant-time modular inversion for an odd 256-bit modulus by
//! Bernstein–Yang "safegcd" divsteps (eprint 2019/266), in the 62-bit-batched
//! shape libsecp256k1's `modinv64` popularised: 590 divsteps in ten batches of
//! 59, each batch run on the low 64 bits of `f`/`g` only and collapsed into a
//! 2×2 transition matrix that is then applied ONCE to the full 5-limb
//! signed-62 vectors `(f, g)` and `(d, e)`.
//!
//! ## Why this exists
//!
//! Both inversions an ECDSA operation needs — `z⁻¹` for the affine conversion
//! of `k·G` / `u1·G + u2·Q` (base field) and `k⁻¹` / `s⁻¹` (scalar field) —
//! were measured 2026-09-28 at ~12 µs (Fermat `a^(p−2)`, 384 field
//! multiplies) and ~40 µs (std's fiat `divstep`, ONE divstep per 5-limb
//! call, 741 calls) against a ~41 µs constant-time `k·G`. The scalar inverse
//! alone was 45 % of a signature. This module brings both to ~3 µs, and is
//! generic over the modulus so the two fields share one audited routine.
//!
//! ## Shape
//!
//! Values are `Signed62`: five signed 64-bit limbs holding 62 bits each,
//! `Σ v[i]·2^(62·i)`, so a 4-limb 2^64 value maps in without loss and
//! intermediate limbs may go negative. One batch:
//!
//!   1. `divsteps59` — 59 divsteps on `(zeta, f mod 2^64, g mod 2^64)` with
//!      `u,v,q,r` starting at `8·I` so the matrix ends scaled by 2^62;
//!   2. `updateDE` — `(d, e) ← (t·(d, e) + m·(md, me)) / 2^62` with `md, me`
//!      chosen so the division is exact (this is where the modulus enters:
//!      `d`/`e` track `f`/`g` modulo `m`);
//!   3. `updateFG` — `(f, g) ← t·(f, g) / 2^62` (exact by construction).
//!
//! After 590 divsteps `g = 0` and `f = ±1` (the gcd, for an input coprime to
//! the modulus); `d` then holds `±x⁻¹` and `normalize` folds the sign of `f`
//! in and brings the result to `[0, m)`. Input `0` yields `0` (std's
//! `invert(0) == 0` convention).
//!
//! ## Constant-time contract
//!
//! Fixed trip counts everywhere (10 × 59 divsteps, fixed limb loops). Every
//! data-dependent decision — `zeta < 0`, `g` odd, the signs of `d`/`e` and of
//! the final `f`, the two conditional modulus adds in `normalize` — is a
//! masked select on an all-ones/zero mask, and each mask is laundered through
//! `blackBox` so LLVM cannot recover the 0/1 range and lower it to a branch
//! or a CMOV on the secret (the montint `b199192` leak class this collection
//! guards against everywhere). Multiplications are `i64×i64→i128` (`imul`),
//! in the DIT set on every target this collection builds for. The only
//! branch is `if (modulus.v[i] != 0)`, on the PUBLIC comptime modulus.
//!
//! Verified by the differentials in `field.zig` (vs the Fermat inverse and
//! std's field) and `scalar.zig` (vs std's scalar inverse), and by the
//! module's ctgrind harness (`sign` target: the tainted seed reaches both
//! inversions).

const std = @import("std");

/// Five signed 62-bit limbs, little-endian: `Σ v[i]·2^(62·i)`.
pub const Signed62 = struct { v: [5]i64 };

const M62: u64 = (1 << 62) - 1;
const M62i: i64 = @intCast(M62);

/// The per-modulus constants. Build with `init` at comptime.
pub const ModInfo = struct {
    modulus: Signed62,
    /// `m⁻¹ mod 2^62`, the Montgomery-style factor that makes the `updateDE`
    /// division exact (`md ← md − (m⁻¹·cd + md) mod 2^62` leaves
    /// `cd + m·md ≡ cd·(1 − m·m⁻¹) ≡ 0`).
    modulus_inv62: u64,

    pub fn init(comptime m: u256) ModInfo {
        comptime {
            std.debug.assert(m & 1 == 1);
            const limbs: [4]u64 = .{ @truncate(m), @truncate(m >> 64), @truncate(m >> 128), @truncate(m >> 192) };
            // m⁻¹ mod 2^64 by Newton iteration (m odd ⇒ m⁻¹ ≡ m mod 8, then
            // each step doubles the correct bits: 3 → 6 → 12 → 24 → 48 → 96).
            var inv: u64 = limbs[0];
            for (0..5) |_| inv *%= 2 -% limbs[0] *% inv;
            std.debug.assert(limbs[0] *% inv == 1);
            return .{
                .modulus = fromLimbs(limbs),
                .modulus_inv62 = inv & M62,
            };
        }
    }
};

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

/// Four full 2^64 limbs (little-endian, value `< 2^256`) → signed-62 limbs.
pub fn fromLimbs(a: [4]u64) Signed62 {
    return .{ .v = .{
        @intCast(a[0] & M62),
        @intCast(((a[0] >> 62) | (a[1] << 2)) & M62),
        @intCast(((a[1] >> 60) | (a[2] << 4)) & M62),
        @intCast(((a[2] >> 58) | (a[3] << 6)) & M62),
        @intCast(a[3] >> 56),
    } };
}

/// Signed-62 limbs → four full 2^64 limbs. Requires a NORMALIZED value:
/// every limb in `[0, 2^62)` and the top limb `< 2^8` (i.e. value `< 2^256`).
pub fn toLimbs(s: Signed62) [4]u64 {
    const v0: u64 = @intCast(s.v[0]);
    const v1: u64 = @intCast(s.v[1]);
    const v2: u64 = @intCast(s.v[2]);
    const v3: u64 = @intCast(s.v[3]);
    const v4: u64 = @intCast(s.v[4]);
    std.debug.assert(v4 < (1 << 8));
    return .{
        v0 | (v1 << 62),
        (v1 >> 2) | (v2 << 60),
        (v2 >> 4) | (v3 << 58),
        (v3 >> 6) | (v4 << 56),
    };
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

/// `(d, e) ← (t·(d, e) + m·(md, me)) / 2^62`, with `md, me` chosen so the
/// division is exact. Input and output `d, e` lie in `(−2m, m)`.
fn updateDE(d: *Signed62, e: *Signed62, t: Trans, comptime mi: ModInfo) void {
    const dv = d.v;
    const ev = e.v;
    const m = mi.modulus.v;
    // [md, me] = [u, q] if d < 0, plus [v, r] if e < 0.
    const sd: i64 = blackBoxI(dv[4] >> 63);
    const se: i64 = blackBoxI(ev[4] >> 63);
    var md: i64 = (t.u & sd) +% (t.v & se);
    var me: i64 = (t.q & sd) +% (t.r & se);
    var cd: i128 = mul128(t.u, dv[0]) + mul128(t.v, ev[0]);
    var ce: i128 = mul128(t.q, dv[0]) + mul128(t.r, ev[0]);
    // Correct md, me so the low 62 bits of t·(d,e) + m·(md,me) vanish.
    md -%= @intCast((mi.modulus_inv62 *% @as(u64, @truncate(@as(u128, @bitCast(cd)))) +% @as(u64, @bitCast(md))) & M62);
    me -%= @intCast((mi.modulus_inv62 *% @as(u64, @truncate(@as(u128, @bitCast(ce)))) +% @as(u64, @bitCast(me))) & M62);
    cd += mul128(m[0], md);
    ce += mul128(m[0], me);
    std.debug.assert(low62(cd) == 0);
    std.debug.assert(low62(ce) == 0);
    cd >>= 62;
    ce >>= 62;
    inline for (1..5) |i| {
        cd += mul128(t.u, dv[i]) + mul128(t.v, ev[i]);
        ce += mul128(t.q, dv[i]) + mul128(t.r, ev[i]);
        if (comptime m[i] != 0) { // comptime modulus limb: folded away
            cd += mul128(m[i], md);
            ce += mul128(m[i], me);
        }
        d.v[i - 1] = low62(cd);
        e.v[i - 1] = low62(ce);
        cd >>= 62;
        ce >>= 62;
    }
    d.v[4] = @intCast(cd);
    e.v[4] = @intCast(ce);
}

/// `(f, g) ← t·(f, g) / 2^62` (exact by construction of `t`).
fn updateFG(f: *Signed62, g: *Signed62, t: Trans) void {
    const fv = f.v;
    const gv = g.v;
    var cf: i128 = mul128(t.u, fv[0]) + mul128(t.v, gv[0]);
    var cg: i128 = mul128(t.q, fv[0]) + mul128(t.r, gv[0]);
    std.debug.assert(low62(cf) == 0);
    std.debug.assert(low62(cg) == 0);
    cf >>= 62;
    cg >>= 62;
    inline for (1..5) |i| {
        cf += mul128(t.u, fv[i]) + mul128(t.v, gv[i]);
        cg += mul128(t.q, fv[i]) + mul128(t.r, gv[i]);
        f.v[i - 1] = low62(cf);
        g.v[i - 1] = low62(cg);
        cf >>= 62;
        cg >>= 62;
    }
    f.v[4] = @intCast(cf);
    g.v[4] = @intCast(cg);
}

/// Bring `r` from `(−2m, m)` to `[0, m)`, negating first iff `sign < 0`.
fn normalize(r: *Signed62, sign: i64, comptime mi: ModInfo) void {
    const m = mi.modulus.v;
    var v = r.v;
    // Add m if negative: (−2m, m) → (−m, m); then negate on request.
    var cond_add: i64 = blackBoxI(v[4] >> 63);
    inline for (0..5) |i| v[i] +%= m[i] & cond_add;
    const cond_negate: i64 = blackBoxI(sign >> 63);
    inline for (0..5) |i| v[i] = (v[i] ^ cond_negate) -% cond_negate;
    // Propagate the top bits so every limb is back in (−2^62, 2^62).
    inline for (0..4) |i| {
        v[i + 1] +%= v[i] >> 62;
        v[i] &= M62i;
    }
    // Still negative ⇒ add m once more: now in [0, m).
    cond_add = blackBoxI(v[4] >> 63);
    inline for (0..5) |i| v[i] +%= m[i] & cond_add;
    inline for (0..4) |i| {
        v[i + 1] +%= v[i] >> 62;
        v[i] &= M62i;
    }
    r.v = v;
}

/// `x⁻¹ mod m` for `0 ≤ x < m` (`m` odd, `< 2^256`); `invert(0) == 0`.
/// Constant-time in `x`. `mi` is comptime so the modulus limbs fold into
/// immediates and the `m[i] != 0` tests in `updateDE` disappear from the
/// binary entirely (one instantiation per modulus).
pub fn invert(x: [4]u64, comptime mi: ModInfo) [4]u64 {
    var d = Signed62{ .v = .{ 0, 0, 0, 0, 0 } };
    var e = Signed62{ .v = .{ 1, 0, 0, 0, 0 } };
    var f = mi.modulus;
    var g = fromLimbs(x);
    var zeta: i64 = -1;
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        const step = divsteps59(zeta, @bitCast(f.v[0]), @bitCast(g.v[0]));
        zeta = step.zeta;
        updateDE(&d, &e, step.t, mi);
        updateFG(&f, &g, step.t);
    }
    // 590 divsteps suffice for 256-bit inputs: g is now 0 and f is ±gcd.
    std.debug.assert(g.v[0] == 0 and g.v[1] == 0 and g.v[2] == 0 and g.v[3] == 0 and g.v[4] == 0);
    normalize(&d, f.v[4], mi);
    return toLimbs(d);
}

// ── tests ───────────────────────────────────────────────────────────────────

fn toU256(l: [4]u64) u256 {
    return @as(u256, l[0]) | (@as(u256, l[1]) << 64) | (@as(u256, l[2]) << 128) | (@as(u256, l[3]) << 192);
}

fn fromU256(x: u256) [4]u64 {
    return .{ @truncate(x), @truncate(x >> 64), @truncate(x >> 128), @truncate(x >> 192) };
}

fn mulMod(a: u256, b: u256, m: u256) u256 {
    return @intCast((@as(u512, a) * @as(u512, b)) % m);
}

test "signed-62 limb conversion round-trips" {
    var prng = std.Random.DefaultPrng.init(0x62_62_62);
    const rand = prng.random();
    for (0..2000) |_| {
        var a: [4]u64 = undefined;
        rand.bytes(std.mem.asBytes(&a));
        try std.testing.expectEqual(a, toLimbs(fromLimbs(a)));
    }
    try std.testing.expectEqual([4]u64{ 0, 0, 0, 0 }, toLimbs(fromLimbs(.{ 0, 0, 0, 0 })));
    const all: [4]u64 = .{ std.math.maxInt(u64), std.math.maxInt(u64), std.math.maxInt(u64), std.math.maxInt(u64) };
    try std.testing.expectEqual(all, toLimbs(fromLimbs(all)));
}

test "modulus_inv62 is m⁻¹ mod 2^62 for both P-256 moduli" {
    const p = @import("field.zig").field_order;
    const n = @import("scalar.zig").field_order;
    inline for (.{ p, n }) |m| {
        const mi = comptime ModInfo.init(m);
        const m0: u64 = @truncate(m);
        try std.testing.expectEqual(@as(u64, 1), (m0 *% mi.modulus_inv62) & M62);
        try std.testing.expectEqual(fromU256(m), toLimbs(mi.modulus));
    }
}

test "invert: x·x⁻¹ ≡ 1 for random x and edges, both moduli; invert(0) == 0" {
    const p = @import("field.zig").field_order;
    const n = @import("scalar.zig").field_order;
    var prng = std.Random.DefaultPrng.init(0x1EE7_5AFE_6CD);
    const rand = prng.random();
    inline for (.{ p, n }) |m| {
        const mi = comptime ModInfo.init(m);
        // Edges: 0 (→ 0), 1, 2, m−1, m−2, powers of two, all-ones patterns.
        try std.testing.expectEqual(fromU256(0), invert(fromU256(0), mi));
        const edges = [_]u256{ 1, 2, 3, m - 1, m - 2, m - 3, 1 << 64, 1 << 128, 1 << 192, 1 << 255, (1 << 255) - 1, (1 << 64) - 1, (1 << 128) - 1, m >> 1, (m >> 1) + 1 };
        for (edges) |x| {
            const inv = toU256(invert(fromU256(x), mi));
            try std.testing.expect(inv < m);
            try std.testing.expectEqual(@as(u256, 1), mulMod(x, inv, m));
        }
        for (0..3000) |_| {
            var xb: u256 = undefined;
            rand.bytes(std.mem.asBytes(&xb));
            xb %= m;
            if (xb == 0) continue;
            const inv = toU256(invert(fromU256(xb), mi));
            try std.testing.expect(inv < m);
            try std.testing.expectEqual(@as(u256, 1), mulMod(xb, inv, m));
        }
    }
}
