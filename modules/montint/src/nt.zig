// SPDX-License-Identifier: MIT
//! `nt` — constant-time number theory on plain little-endian limb arrays:
//! `gcd`, `lcm` and the odd part of a value, for the key-setup arithmetic
//! that no odd modulus carries (`λ = lcm(p − 1, q − 1)` of RSA and Paillier).
//!
//! Everything here is constant-time in the VALUES: the work depends on the
//! comptime limb count `n` only, every data-dependent choice is a masked
//! blend (the one branch: `divExact`'s refusal of a non-divisor), and masks derived from secrets go through an asm barrier
//! (`blackBox`, the montint lesson: LLVM turns a recovered `{0, ~0}` mask
//! back into a jump). The divsteps loop and its helpers are shared with
//! `DynModint.inverse`.

const std = @import("std");
const montint = @import("montint.zig");

/// Divsteps that bring `g` to zero for `0 ≤ g < 2^b`, `f` odd, `|f| < 2^b`
/// (Bernstein–Yang 2019, Theorem 11.2: `f² + 4g² ≤ 5·2^(2b)`).
pub fn divstepCount(b: usize) usize {
    return if (b < 46) (49 * b + 80) / 17 else (49 * b + 57) / 17;
}

/// The odd part of `x` and its 2-adic valuation: `x = u·2^t`, `u` odd.
/// `x` must be non-zero (for `x = 0` the result is `u = 0`, `t = 64n`).
/// Shifts one bit at a time under a mask for all `64n` positions.
pub fn oddPart(comptime n: usize, x: *const [n]u64) struct { u: [n]u64, t: usize } {
    var u = x.*;
    var t: usize = 0;
    for (0..64 * n) |_| {
        const even = blackBox(0 -% (~u[0] & 1)); // all ones while u is even
        var s = u;
        shr1(n, &s);
        blend(n, &u, &s, even);
        t += even & 1;
    }
    return .{ .u = u, .t = t };
}

/// `gcd(a, b)` for `a, b ≥ 1`. Odd parts, then divsteps on them (`f = odd(a)`
/// stays odd, as the algorithm needs), then the common power of two shifted
/// back in.
pub fn gcd(comptime n: usize, a: *const [n]u64, b: *const [n]u64) [n]u64 {
    var pa = oddPart(n, a);
    defer std.crypto.secureZero(u64, &pa.u);
    var pb = oddPart(n, b);
    defer std.crypto.secureZero(u64, &pb.u);
    var g = gcdOdd(n, &pa.u, &pb.u);
    shlBy(n, &g, minCt(pa.t, pb.t), 64 * n);
    return g;
}

/// `lcm(a, b)` for `a, b ≥ 1`, `2n` limbs wide (it can be as large as
/// `a·b`): `(odd(a)/g)·odd(b)·2^max(t_a, t_b)` with `g = gcd(odd(a), odd(b))`,
/// the division a Hensel exact division by the odd `g`.
pub fn lcm(comptime n: usize, a: *const [n]u64, b: *const [n]u64) [2 * n]u64 {
    var pa = oddPart(n, a);
    defer std.crypto.secureZero(u64, &pa.u);
    var pb = oddPart(n, b);
    defer std.crypto.secureZero(u64, &pb.u);
    var g = gcdOdd(n, &pa.u, &pb.u);
    defer std.crypto.secureZero(u64, &g);
    // w = odd(a)/g exactly: odd(a)·g⁻¹ mod 2^(64n), the quotient fitting n limbs.
    var ginv = invPow2(n, &g);
    defer std.crypto.secureZero(u64, &ginv);
    var w: [n]u64 = undefined;
    defer std.crypto.secureZero(u64, &w);
    mulLow(n, &w, &pa.u, &ginv);
    var out: [2 * n]u64 = undefined;
    @import("limbs.zig").mulSchoolbook(&out, &w, &pb.u);
    shlBy(2 * n, &out, maxCt(pa.t, pb.t), 64 * n);
    return out;
}

/// `a / b` for a `b ≥ 1` that divides `a` exactly: the power of two in `b`
/// shifted out of `a` (masked one-bit shifts), then a Hensel division by the
/// odd part — `b` may be even, as `p − 1` is. `error.NotDivisible` if
/// `b = 0` or `b ∤ a`: the quotient is checked by `q·b = a` over the full
/// `2n`-limb product, which only an exact quotient meets. Constant-time in
/// `a` and `b` up to that verdict (the one branch).
pub fn divExact(comptime n: usize, a: *const [n]u64, b: *const [n]u64) error{NotDivisible}![n]u64 {
    var pb = oddPart(n, b);
    defer std.crypto.secureZero(u64, &pb.u);
    var s = a.*;
    defer std.crypto.secureZero(u64, &s);
    for (0..64 * n) |i| {
        const on = blackBox(ltMask(i, pb.t));
        var t = s;
        shr1(n, &t);
        blend(n, &s, &t, on);
    }
    var inv = invPow2(n, &pb.u);
    defer std.crypto.secureZero(u64, &inv);
    var q: [n]u64 = undefined;
    mulLow(n, &q, &s, &inv);
    // q·b = a over all 2n limbs, and b ≠ 0 (0·q = 0 would pass for a = 0).
    var prod: [2 * n]u64 = undefined;
    defer std.crypto.secureZero(u64, &prod);
    @import("limbs.zig").mulSchoolbook(&prod, &q, b);
    var diff: u64 = 0;
    for (prod, 0..) |w, i| diff |= w ^ (if (i < n) a[i] else 0);
    var b_or: u64 = 0;
    for (b) |w| b_or |= w;
    if (blackBox(nzBit(diff) | (nzBit(b_or) ^ 1)) != 0) {
        std.crypto.secureZero(u64, &q);
        return error.NotDivisible;
    }
    return q;
}

/// `gcd(f, g)` for an odd `f` and any `g`, both `< 2^(64n)`: divsteps for the
/// full-width bound, then `|f|`.
fn gcdOdd(comptime n: usize, f_in: *const [n]u64, g_in: *const [n]u64) [n]u64 {
    const W = n + 1; // two's complement, one sign limb
    var f = [_]u64{0} ** W;
    f[0..n].* = f_in.*;
    var g = [_]u64{0} ** W;
    g[0..n].* = g_in.*;
    defer std.crypto.secureZero(u64, &f);
    defer std.crypto.secureZero(u64, &g);
    var delta: u64 = 1;
    var k = divstepCount(64 * n);
    while (k > 0) : (k -= 1) {
        const pos: u64 = @bitCast(@as(i64, @bitCast(0 -% delta)) >> 63);
        const swap = blackBox(pos & (0 -% (g[0] & 1)));
        delta = (delta ^ swap) -% swap;
        condSwap(W, &f, &g, swap);
        condNeg(W, &g, swap);
        const odd = blackBox(0 -% (g[0] & 1));
        addMasked(W, &g, &f, odd);
        sar1(W, &g);
        delta +%= 1;
    }
    // f = ±gcd: take the absolute value.
    condNeg(W, &f, blackBox(0 -% (f[W - 1] >> 63)));
    return f[0..n].*;
}

/// `m⁻¹ mod 2^(64n)` for an odd `m`, by Newton from the 64-bit inverse,
/// precision doubling each step; the step count depends on `n` only.
pub fn invPow2(comptime n: usize, m: *const [n]u64) [n]u64 {
    var inv = [_]u64{0} ** n;
    inv[0] = 0 -% montint.negInvMod2_64(m[0]);
    var prec: usize = 64;
    while (prec < 64 * n) : (prec *= 2) {
        var t: [n]u64 = undefined;
        mulLow(n, &t, m, &inv); // m·y
        var two = [_]u64{0} ** n;
        two[0] = 2;
        _ = @import("limbs.zig").subInto(&two, &t); // 2 − m·y
        var y: [n]u64 = undefined;
        mulLow(n, &y, &inv, &two);
        inv = y;
    }
    return inv;
}

/// `z = x·y mod 2^(64n)` — the low half of the schoolbook product.
pub fn mulLow(comptime n: usize, z: *[n]u64, x: *const [n]u64, y: *const [n]u64) void {
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

/// `x ← x·2^k` (low `n` limbs kept) for a secret `k ≤ max`, one masked
/// one-bit shift per position up to the public `max`.
fn shlBy(comptime n: usize, x: *[n]u64, k: usize, max: usize) void {
    for (0..max) |i| {
        const on = blackBox(ltMask(i, k));
        var s = x.*;
        for (0..n - 1) |j| s[n - 1 - j] = (s[n - 1 - j] << 1) | (s[n - 2 - j] >> 63);
        s[0] <<= 1;
        blend(n, x, &s, on);
    }
}

/// All ones iff `a < b` (both far below 2^63), no comparison.
inline fn ltMask(a: usize, b: usize) u64 {
    return @bitCast(@as(i64, @bitCast(@as(u64, a) -% @as(u64, b))) >> 63);
}

fn minCt(a: usize, b: usize) usize {
    const m = blackBox(ltMask(a, b));
    return @intCast((a & m) | (b & ~m));
}

fn maxCt(a: usize, b: usize) usize {
    const m = blackBox(ltMask(a, b));
    return @intCast((b & m) | (a & ~m));
}

// ── shared masked-limb helpers (also `DynModint.inverse`'s) ────────────────

/// 1 if `x ≠ 0`, else 0, without a comparison.
pub inline fn nzBit(x: u64) u64 {
    return (x | (0 -% x)) >> 63;
}

/// `(x, y) ← (y, x)` under an all-ones `mask`, else unchanged.
pub inline fn condSwap(comptime n: usize, x: *[n]u64, y: *[n]u64, mask: u64) void {
    for (x, y) |*a, *b| {
        const t = (a.* ^ b.*) & mask;
        a.* ^= t;
        b.* ^= t;
    }
}

/// `x ← −x` (two's complement over `n` limbs) under an all-ones `mask`.
pub inline fn condNeg(comptime n: usize, x: *[n]u64, mask: u64) void {
    var carry: u64 = mask & 1;
    for (x) |*w| {
        const r = @addWithOverflow(w.* ^ mask, carry);
        w.* = r[0];
        carry = r[1];
    }
}

/// `x ← x + (y & mask)` over `n` limbs (wrapping).
pub inline fn addMasked(comptime n: usize, x: *[n]u64, y: *const [n]u64, mask: u64) void {
    var carry: u1 = 0;
    for (x, y) |*a, b| {
        const r1 = @addWithOverflow(a.*, b & mask);
        const r2 = @addWithOverflow(r1[0], carry);
        a.* = r2[0];
        carry = r1[1] | r2[1];
    }
}

/// `x ← y` under an all-ones `mask`, else unchanged.
pub inline fn blend(comptime n: usize, x: *[n]u64, y: *const [n]u64, mask: u64) void {
    for (x, y) |*a, b| a.* = (b & mask) | (a.* & ~mask);
}

/// Logical shift right by one over `n` limbs.
inline fn shr1(comptime n: usize, x: *[n]u64) void {
    for (0..n - 1) |i| x[i] = (x[i] >> 1) | (x[i + 1] << 63);
    x[n - 1] >>= 1;
}

/// Arithmetic shift right by one over `n` two's-complement limbs.
pub inline fn sar1(comptime n: usize, x: *[n]u64) void {
    for (0..n - 1) |i| x[i] = (x[i] >> 1) | (x[i + 1] << 63);
    x[n - 1] = @bitCast(@as(i64, @bitCast(x[n - 1])) >> 1);
}

/// `e ← e/2 mod m` for `e < m`, `m` odd: `(e + (m if e odd))/2`, the
/// carry of the addition shifted back in on top.
pub inline fn halveMod(comptime n: usize, e: *[n]u64, m: *const [n]u64) void {
    const mask = blackBox(0 -% (e[0] & 1));
    var carry: u1 = 0;
    for (e, m) |*a, b| {
        const r1 = @addWithOverflow(a.*, b & mask);
        const r2 = @addWithOverflow(r1[0], carry);
        a.* = r2[0];
        carry = r1[1] | r2[1];
    }
    for (0..n - 1) |i| e[i] = (e[i] >> 1) | (e[i + 1] << 63);
    e[n - 1] = (e[n - 1] >> 1) | (@as(u64, carry) << 63);
}

/// Optimization barrier, as `Modint`'s: an empty asm the optimizer cannot see
/// through, so a mask derived from a secret bit stays a mask.
pub inline fn blackBox(x: u64) u64 {
    if (@inComptime()) return x;
    return asm volatile (""
        : [ret] "=r" (-> u64),
        : [x] "0" (x),
    );
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const Managed = std.math.big.int.Managed;

fn toBig(gpa: std.mem.Allocator, v: []const u64) !Managed {
    var r = try Managed.init(gpa);
    errdefer r.deinit();
    try r.ensureCapacity(v.len + 1);
    @memset(r.limbs, 0);
    @memcpy(r.limbs[0..v.len], v);
    r.normalize(v.len + 1);
    return r;
}

test "nt gcd/lcm/oddPart: every pair below 600 (one limb)" {
    var a: u64 = 1;
    while (a < 600) : (a += 1) {
        const pa = oddPart(1, &.{a});
        try testing.expectEqual(@as(usize, @ctz(a)), pa.t);
        try testing.expectEqual(a >> @intCast(@ctz(a)), pa.u[0]);
        var b: u64 = 1;
        while (b < 600) : (b += 1) {
            const g = std.math.gcd(a, b);
            try testing.expectEqual(g, gcd(1, &.{a}, &.{b})[0]);
            const l = lcm(1, &.{a}, &.{b});
            try testing.expectEqual(a / g * b, l[0]);
            try testing.expectEqual(@as(u64, 0), l[1]);
        }
    }
}

test "nt gcd/lcm match std.math.big.int (64..4096-bit, shared powers of two and odd factors)" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6e74_6763_64);
    const rnd = prng.random();
    inline for (.{ 1, 2, 16, 64 }) |n| {
        for (0..12) |round| {
            // a = c·x, b = c·y with a random common factor c (sometimes a
            // power of two, sometimes odd, sometimes 1), the RSA shape
            // (p − 1, q − 1 share 2 and a little more) among them.
            var x: [n]u64 = undefined;
            var y: [n]u64 = undefined;
            for (&x, &y) |*xi, *yi| {
                xi.* = rnd.int(u64);
                yi.* = rnd.int(u64);
            }
            x[n - 1] >>= 20;
            y[n - 1] >>= 20;
            x[0] |= 1;
            const c: u64 = switch (round % 4) {
                0 => 1,
                1 => @as(u64, 1) << @intCast(rnd.uintLessThan(u6, 16)),
                2 => rnd.int(u16) | 1,
                else => (rnd.int(u16) | 1) << 3,
            };
            if (round % 3 == 0) y[0] &= ~@as(u64, 0xff); // b with many trailing zeros
            if (y[0] == 0 and n == 1) y[0] = 2;
            var a: [n + 1]u64 = undefined;
            var b: [n + 1]u64 = undefined;
            var carry: u64 = 0;
            for (0..n) |i| {
                const p = @as(u128, x[i]) * c + carry;
                a[i] = @truncate(p);
                carry = @truncate(p >> 64);
            }
            a[n] = carry;
            carry = 0;
            for (0..n) |i| {
                const p = @as(u128, y[i]) * c + carry;
                b[i] = @truncate(p);
                carry = @truncate(p >> 64);
            }
            b[n] = carry;
            // (a, b) fit n limbs: x, y lost 20 top bits, c < 2^19.
            const an: [n]u64 = a[0..n].*;
            const bn: [n]u64 = b[0..n].*;
            var ba = try toBig(gpa, &an);
            defer ba.deinit();
            var bb = try toBig(gpa, &bn);
            defer bb.deinit();
            var want = try Managed.init(gpa);
            defer want.deinit();
            try want.gcd(&ba, &bb);
            var got = try toBig(gpa, &gcd(n, &an, &bn));
            defer got.deinit();
            try testing.expect(got.eql(want));
            // lcm = a·b / gcd
            var prod = try Managed.init(gpa);
            defer prod.deinit();
            try prod.mul(&ba, &bb);
            var q = try Managed.init(gpa);
            defer q.deinit();
            var r = try Managed.init(gpa);
            defer r.deinit();
            try q.divFloor(&r, &prod, &want);
            var gl = try toBig(gpa, &lcm(n, &an, &bn));
            defer gl.deinit();
            try testing.expect(gl.eql(q));
        }
    }
}

test "nt divExact: (c·b)/b for odd and even b of every width" {
    var prng = std.Random.DefaultPrng.init(0x6469_7665_78);
    const rnd = prng.random();
    inline for (.{ 1, 4, 16, 64 }) |n| {
        for (0..10) |round| {
            var b: [n]u64 = undefined;
            var c: [n]u64 = undefined;
            for (&b, &c) |*bi, *ci| {
                bi.* = rnd.int(u64);
                ci.* = rnd.int(u64);
            }
            // b·c must fit n limbs: halve both widths.
            const half = (64 * n) / 2 - 1;
            keepLowBits(n, &b, half);
            keepLowBits(n, &c, half);
            if (round % 2 == 0) b[0] &= ~@as(u64, 0xf); // even b, 2^4 | b
            b[0] |= @as(u64, 1) << 4; // b ≠ 0
            var a: [2 * n]u64 = undefined;
            @import("limbs.zig").mulSchoolbook(&a, &c, &b);
            try testing.expectEqualSlices(u64, &c, &(try divExact(n, a[0..n], &b)));
        }
    }
}

fn keepLowBits(comptime n: usize, x: *[n]u64, bits: usize) void {
    for (x, 0..) |*w, i| {
        const lo = 64 * i;
        if (lo >= bits) w.* = 0 else if (bits - lo < 64) w.* &= (@as(u64, 1) << @intCast(bits - lo)) - 1;
    }
}

test "nt divExact refuses a zero or non-dividing divisor (review L4)" {
    const z = [_]u64{0} ** 4;
    var a = z;
    var b = z;
    a[0] = 7;
    b[0] = 2; // even, 2 ∤ 7: the shifted-out low bit was not zero
    try testing.expectError(error.NotDivisible, divExact(4, &a, &b));
    b[0] = 3; // odd, 3 ∤ 7: the Hensel quotient's product overflows n limbs
    try testing.expectError(error.NotDivisible, divExact(4, &a, &b));
    b[0] = 6; // even AND an odd part that does not divide
    a[0] = 8;
    try testing.expectError(error.NotDivisible, divExact(4, &a, &b));
    // b = 0: nothing divides by it, 0 included (the old code answered 0/0 = 0)
    try testing.expectError(error.NotDivisible, divExact(4, &a, &z));
    try testing.expectError(error.NotDivisible, divExact(4, &z, &z));
    // b | a in the high limbs only: 2^255 / 2^200, 0 / b
    var hi = z;
    hi[3] = @as(u64, 1) << 63;
    var p200 = z;
    p200[3] = @as(u64, 1) << 8;
    const q = try divExact(4, &hi, &p200);
    try testing.expectEqualSlices(u64, &.{ @as(u64, 1) << 55, 0, 0, 0 }, &q);
    b[0] = 3;
    try testing.expectEqualSlices(u64, &z, &(try divExact(4, &z, &b)));
    // b ∤ a by one: (3·c + 1)/3 over a full-width c
    const c = [_]u64{ 0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210, 0x1111_2222_3333_4444, 0x0555_6666_7777_8888 };
    var a3 = z;
    var carry: u64 = 0;
    for (&a3, c) |*o, ci| {
        const w = @as(u128, ci) * 3 + carry;
        o.* = @truncate(w);
        carry = @intCast(w >> 64);
    }
    try testing.expectEqualSlices(u64, &c, &(try divExact(4, &a3, &b)));
    a3[0] += 1;
    try testing.expectError(error.NotDivisible, divExact(4, &a3, &b));
}

test "nt oddPart of a power of two and of 2^(64n) − 1" {
    var p2 = [_]u64{0} ** 4;
    p2[3] = @as(u64, 1) << 63;
    const r = oddPart(4, &p2);
    try testing.expectEqual(@as(usize, 255), r.t);
    try testing.expectEqual(@as(u64, 1), r.u[0]);
    const all = [_]u64{~@as(u64, 0)} ** 4;
    const r2 = oddPart(4, &all);
    try testing.expectEqual(@as(usize, 0), r2.t);
    try testing.expectEqualSlices(u64, &all, &r2.u);
}
