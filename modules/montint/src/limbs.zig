// SPDX-License-Identifier: MIT

//! limbs — low-level multi-precision primitives over **full radix-2^64 limbs**
//! (little-endian `[]u64`). This is the deliberate structural departure from
//! `std.crypto.ff`, which reserves a carry bit per limb (a 63-bit redundant
//! representation) and therefore cannot use the host's native add-with-carry /
//! `MULX` widening multiply. Full 2^64 limbs are what the amd64
//! `MULX/ADCX/ADOX` core needs, and what OpenSSL's `x86_64-mont5` uses.
//!
//! Everything here is portable, deterministic, and unit-tested. It holds the
//! carry/borrow/compare helpers the Montgomery layer builds on, plus a plain
//! (non-modular) schoolbook and Karatsuba full-product — the building blocks
//! for the deferred large-size SOS path (see SPEC.md "Karatsuba / large sizes")
//! and a mutually-cross-checking correctness anchor. The Montgomery multiply
//! itself uses interleaved CIOS (see `montint.zig`), not these.

const std = @import("std");

/// Add `y` into `x` (both `n` limbs), returning the outgoing carry (0 or 1).
pub fn addInto(x: []u64, y: []const u64) u1 {
    std.debug.assert(x.len == y.len);
    var carry: u1 = 0;
    for (x, y) |*xi, yi| {
        const s = @addWithOverflow(xi.*, yi);
        const s2 = @addWithOverflow(s[0], carry);
        xi.* = s2[0];
        carry = s[1] | s2[1];
    }
    return carry;
}

/// Subtract `y` from `x` (both `n` limbs), returning the outgoing borrow (0/1).
pub fn subInto(x: []u64, y: []const u64) u1 {
    std.debug.assert(x.len == y.len);
    var borrow: u1 = 0;
    for (x, y) |*xi, yi| {
        const d = @subWithOverflow(xi.*, yi);
        const d2 = @subWithOverflow(d[0], borrow);
        xi.* = d2[0];
        borrow = d[1] | d2[1];
    }
    return borrow;
}

/// Constant-time comparison of two `n`-limb little-endian values.
/// Returns `.lt` / `.eq` / `.gt`. No secret-dependent branch or early exit:
/// every limb is inspected regardless of where the values first differ.
pub fn cmp(x: []const u64, y: []const u64) std.math.Order {
    std.debug.assert(x.len == y.len);
    var lt: u1 = 0;
    var gt: u1 = 0;
    for (x, y) |xi, yi| {
        const is_lt: u1 = @intFromBool(xi < yi);
        const is_gt: u1 = @intFromBool(xi > yi);
        // Higher limbs decide; only overwrite when this limb differs.
        const diff: u1 = is_lt | is_gt;
        const keep: u1 = diff ^ 1;
        lt = (lt & keep) | is_lt;
        gt = (gt & keep) | is_gt;
    }
    if (lt == 1) return .lt;
    if (gt == 1) return .gt;
    return .eq;
}

/// Constant-time limb select: returns `a` if `on`, else `b` (no branch).
pub inline fn select(on: u1, a: u64, b: u64) u64 {
    const mask: u64 = 0 -% @as(u64, on);
    return b ^ (mask & (a ^ b));
}

/// Schoolbook full product: `z[0..2n] = x[0..n] * y[0..n]`. Reference multiply.
pub fn mulSchoolbook(z: []u64, x: []const u64, y: []const u64) void {
    const n = x.len;
    std.debug.assert(y.len == n and z.len == 2 * n);
    @memset(z, 0);
    for (0..n) |i| {
        var carry: u64 = 0;
        for (0..n) |j| {
            const p = @as(u128, x[i]) * @as(u128, y[j]) + z[i + j] + carry;
            z[i + j] = @truncate(p);
            carry = @truncate(p >> 64);
        }
        z[i + n] = carry;
    }
}

/// Add `small` (≤ `big.len` limbs) into `big`, propagating the carry through
/// `big`'s upper limbs. Returns the final outgoing carry.
pub fn addWideInto(big: []u64, small: []const u64) u1 {
    std.debug.assert(small.len <= big.len);
    var carry: u1 = 0;
    for (big, 0..) |*bi, i| {
        const s = @as(u128, bi.*) + @as(u128, if (i < small.len) small[i] else 0) + carry;
        bi.* = @truncate(s);
        carry = @truncate(s >> 64);
    }
    return carry;
}

/// Subtract `small` (≤ `big.len` limbs) from `big`, propagating the borrow.
/// Returns the final outgoing borrow.
pub fn subWideInto(big: []u64, small: []const u64) u1 {
    std.debug.assert(small.len <= big.len);
    var borrow: u1 = 0;
    for (big, 0..) |*bi, i| {
        const s = @as(i128, bi.*) - @as(i128, if (i < small.len) small[i] else 0) - borrow;
        bi.* = @truncate(@as(u128, @bitCast(s)));
        borrow = @intFromBool(s < 0);
    }
    return borrow;
}

/// Below this many limbs, Karatsuba falls back to schoolbook. (Descriptive of
/// the crossover; the exact tuned value is a bench-time question — see SPEC.)
pub const karatsuba_threshold: usize = 16;

/// Single-level Karatsuba full product `z[0..2n] = x[0..n] * y[0..n]` (falls
/// back to schoolbook below the threshold; handles odd `n` via unequal halves).
/// Correctness anchor for `mulSchoolbook`; building block for the deferred
/// large-size SOS Montgomery path. `scratch` must hold ≥ `4*(n/2+1)` limbs.
pub fn mulKaratsuba(z: []u64, x: []const u64, y: []const u64, scratch: []u64) void {
    const n = x.len;
    std.debug.assert(y.len == n and z.len == 2 * n);
    if (n < karatsuba_threshold or n < 2) {
        mulSchoolbook(z, x, y);
        return;
    }
    const h = n / 2; // low half = h limbs, high half = nh limbs (nh ≥ h)
    const nh = n - h;
    const hs = nh + 1; // sum width (holds the +1 carry limb)
    const xl = x[0..h];
    const xh = x[h..n];
    const yl = y[0..h];
    const yh = y[h..n];

    // z0 = xl·yl → z[0..2h]; z2 = xh·yh → z[2h..2n].
    mulSchoolbook(z[0 .. 2 * h], xl, yl);
    mulSchoolbook(z[2 * h .. 2 * n], xh, yh);

    var off: usize = 0;
    const sx = scratch[off .. off + hs];
    off += hs;
    const sy = scratch[off .. off + hs];
    off += hs;
    const mid = scratch[off .. off + 2 * hs];

    // sx = xl + xh, sy = yl + yh (each ≤ nh limbs + 1 carry limb).
    @memset(sx, 0);
    @memset(sy, 0);
    @memcpy(sx[0..h], xl);
    @memcpy(sy[0..h], yl);
    sx[nh] = addInto(sx[0..nh], xh); // xl (zero-extended) + xh, carry → sx[nh]
    sy[nh] = addInto(sy[0..nh], yh);

    // mid = sx·sy − z0 − z2 = xl·yh + xh·yl (fits in 2·hs limbs, ≥ 0).
    mulSchoolbook(mid, sx, sy);
    _ = subWideInto(mid, z[0 .. 2 * h]); // − z0
    _ = subWideInto(mid, z[2 * h .. 2 * n]); // − z2

    // z += mid << (h·64).
    _ = addWideInto(z[h .. 2 * n], mid);
}

test "addInto / subInto round-trip with carry" {
    var x = [_]u64{ 0xffff_ffff_ffff_ffff, 0x0, 0x1 };
    const y = [_]u64{ 0x1, 0x0, 0x0 };
    const c = addInto(&x, &y);
    try std.testing.expectEqual(@as(u1, 0), c);
    try std.testing.expectEqual(@as(u64, 0), x[0]);
    try std.testing.expectEqual(@as(u64, 1), x[1]);
    const b = subInto(&x, &y);
    try std.testing.expectEqual(@as(u1, 0), b);
    try std.testing.expectEqual(@as(u64, 0xffff_ffff_ffff_ffff), x[0]);
}

test "cmp is a total order and CT-shaped" {
    const a = [_]u64{ 5, 9, 1 };
    const b = [_]u64{ 6, 9, 1 };
    const c = [_]u64{ 5, 9, 1 };
    try std.testing.expectEqual(std.math.Order.lt, cmp(&a, &b));
    try std.testing.expectEqual(std.math.Order.gt, cmp(&b, &a));
    try std.testing.expectEqual(std.math.Order.eq, cmp(&a, &c));
}

test "select is a branchless mux" {
    try std.testing.expectEqual(@as(u64, 0xaa), select(1, 0xaa, 0xbb));
    try std.testing.expectEqual(@as(u64, 0xbb), select(0, 0xaa, 0xbb));
}

test "Karatsuba == schoolbook on random inputs (the mutual anchor)" {
    var prng = std.Random.DefaultPrng.init(0xDEADBEEF);
    const rand = prng.random();
    inline for ([_]usize{ 1, 2, 3, 16, 17, 32, 33, 64 }) |n| {
        var x: [n]u64 = undefined;
        var y: [n]u64 = undefined;
        for (&x) |*v| v.* = rand.int(u64);
        for (&y) |*v| v.* = rand.int(u64);
        var zs: [2 * n]u64 = undefined;
        var zk: [2 * n]u64 = undefined;
        var scratch: [8 * n]u64 = undefined;
        mulSchoolbook(&zs, &x, &y);
        mulKaratsuba(&zk, &x, &y, &scratch);
        try std.testing.expectEqualSlices(u64, &zs, &zk);
    }
}
