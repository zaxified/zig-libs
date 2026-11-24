// SPDX-License-Identifier: MIT
//! msm — multi-scalar multiplication `sum_i scalars[i] * points[i]` in `G1`
//! and `G2` (Pippenger's bucket method), plus the variable-time Jacobian
//! additions it runs on. Moved here from `kzg.zig` (where it was `G1`-only)
//! so callers outside KZG — batch signature verification, threshold and
//! aggregation code, consumers of the module — get it for both groups.
//!
//! **Public data only.** Every addition here branches on its inputs (the
//! degenerate cases `P == Q`, `P == -Q`, identity) and the bucket a point
//! lands in depends on the scalar's digits, so running time and memory
//! access reveal the scalars. Never pass a secret scalar or a secret point;
//! the constant-time paths are `g1`/`g2` `Jacobian.scalarMul`.
//!
//! The formulas are EFD `add-2007-bl` and its mixed variant `madd-2007-bl`
//! (`Z2 = 1`), the same ones `g1.zig`/`g2.zig` use in constant-time form;
//! they are written once over the coordinate field, so `Fp` (`G1`) and
//! `Fp2` (`G2`) share them.

const std = @import("std");
const g1 = @import("g1.zig");
const g2 = @import("g2.zig");
const scalarmod = @import("scalar.zig");

pub const Fr = scalarmod.Fr;

pub const MsmError = error{
    /// `points.len != scalars.len`.
    LengthMismatch,
} || std.mem.Allocator.Error;

/// Variable-time Jacobian + Jacobian addition for either group (`J` is
/// `g1.Jacobian` or `g2.Jacobian`). Public data only — see the file comment.
pub fn addVartime(comptime J: type, a: J, b: J) J {
    if (a.isIdentity()) return b;
    if (b.isIdentity()) return a;
    const z1z1 = a.z.square();
    const z2z2 = b.z.square();
    const ua = a.x.mul(z2z2); // U1
    const ub = b.x.mul(z1z1); // U2
    const sa = a.y.mul(b.z).mul(z2z2); // S1
    const sb = b.y.mul(a.z).mul(z1z1); // S2
    const h = ub.sub(ua);
    const s_diff = sb.sub(sa);
    if (h.isZero()) {
        if (s_diff.isZero()) return a.double(); // P == Q
        return J.identity; // P == -Q
    }
    const i = h.add(h).square();
    const j = h.mul(i);
    const rr = s_diff.add(s_diff);
    const v = ua.mul(i);
    const x3 = rr.square().sub(j).sub(v.add(v));
    const s1j = sa.mul(j);
    const y3 = rr.mul(v.sub(x3)).sub(s1j.add(s1j));
    const z3 = a.z.add(b.z).square().sub(z1z1).sub(z2z2).mul(h);
    return .{ .x = x3, .y = y3, .z = z3 };
}

/// Variable-time Jacobian + Affine ("mixed") addition, the bucket
/// accumulation step. `G` is the `g1` or `g2` namespace.
pub fn mixedAddVartime(comptime G: type, a: G.Jacobian, b: G.Affine) G.Jacobian {
    if (b.infinity) return a;
    if (a.isIdentity()) return G.Jacobian.fromAffine(b);
    const z1z1 = a.z.square();
    const ub = b.x.mul(z1z1); // U2
    const sb = b.y.mul(a.z).mul(z1z1); // S2
    const h = ub.sub(a.x);
    const s_diff = sb.sub(a.y);
    if (h.isZero()) {
        if (s_diff.isZero()) return a.double(); // P == Q
        return G.Jacobian.identity; // P == -Q
    }
    const hh = h.square();
    const i = blk: { // I = 4*HH
        const hh2 = hh.add(hh);
        break :blk hh2.add(hh2);
    };
    const j = h.mul(i);
    const rr = s_diff.add(s_diff);
    const v = a.x.mul(i);
    const x3 = rr.square().sub(j).sub(v.add(v));
    const yj = a.y.mul(j);
    const y3 = rr.mul(v.sub(x3)).sub(yj.add(yj));
    const z3 = a.z.add(h).square().sub(z1z1).sub(hh);
    return .{ .x = x3, .y = y3, .z = z3 };
}

/// Pippenger window width `c` for `n` points with signed digits: one
/// more than the unsigned `windowBitsUnsigned`, so `2^(c-1)` buckets — the
/// same count as before — and fewer windows.
fn windowBits(n: usize) usize {
    return windowBitsUnsigned(n) + 1;
}

/// The unsigned window width `c ≈ log2(n) - 4`, capped at 8.
fn windowBitsUnsigned(n: usize) usize {
    if (n < 4) return 2;
    if (n < 16) return 3;
    if (n < 64) return 4;
    if (n < 256) return 5;
    if (n < 1024) return 6;
    if (n < 4096) return 7;
    return 8;
}

/// Bits `[bit_off, bit_off + c)` of a 32-byte big-endian scalar, as the
/// little-endian window digit.
fn windowDigit(bytes: *const [32]u8, bit_off: usize, c: usize) usize {
    var digit: usize = 0;
    for (0..c) |i| {
        const b = bit_off + i;
        if (b >= 256) break;
        const bit: usize = (bytes[31 - (b >> 3)] >> @as(u3, @intCast(b & 7))) & 1;
        digit |= bit << @as(std.math.Log2Int(usize), @intCast(i));
    }
    return digit;
}

/// The signed base-`2^c` digits of a 256-bit scalar, least significant
/// first: `s = Σ d_w·2^(c·w)` with `d_w ∈ [-2^(c-1), 2^(c-1))` (a raw digit
/// `≥ 2^(c-1)` becomes `raw - 2^c` and carries 1 into the next window).
/// `out.len` must be `ceil(256 / c) + 1` (the last window takes the carry).
fn signedDigits(bytes: *const [32]u8, c: usize, out: []i16) void {
    const half: i32 = @as(i32, 1) << @as(u5, @intCast(c - 1));
    var carry: i32 = 0;
    for (out, 0..) |*d, w| {
        var v: i32 = @as(i32, @intCast(windowDigit(bytes, w * c, c))) + carry;
        carry = 0;
        if (v >= half) {
            v -= 2 * half;
            carry = 1;
        }
        d.* = @intCast(v);
    }
    std.debug.assert(carry == 0);
}

/// `sum_i scalars[i] * points[i]` in the group `G` (the `g1` or `g2`
/// namespace). Pippenger over SIGNED `c`-bit digits (`signedDigits`): per
/// window a point goes into bucket `|d|` (negated for `d < 0`), so
/// `2^(c-1)` buckets do the work of `2^c - 1` unsigned ones and `c` can be
/// one larger for the same bucket count (fewer windows). The buckets are
/// summed with the running-sum trick (`sum_d d * bucket[d]` in
/// `2 * 2^(c-1)` additions), and windows are folded most significant
/// first with `c` doublings between them — `O(n * 256 / c)` additions
/// against naive double-and-add's `O(n * 256)`. The signed-digit form is
/// what blst's and arkworks' Pippenger use (named, not read); the unsigned
/// form this replaced stays as `msmUnsignedRef`, the bench baseline. An
/// empty input is the identity; identity points and zero scalars drop
/// out. Allocates the digits and the buckets. Public data only.
pub fn msm(comptime G: type, allocator: std.mem.Allocator, points: []const G.Affine, scalars: []const Fr) MsmError!G.Jacobian {
    if (points.len != scalars.len) return error.LengthMismatch;
    if (points.len == 0) return G.Jacobian.identity;

    const c = windowBits(points.len);
    const n_windows = (256 + c - 1) / c + 1;
    // Every scalar's signed digits once up front (each window re-reads them).
    const digits = try allocator.alloc(i16, n_windows * scalars.len);
    defer allocator.free(digits);
    for (scalars, 0..) |s, i| {
        const bytes = s.toBytes();
        signedDigits(&bytes, c, digits[i * n_windows ..][0..n_windows]);
    }

    const n_buckets = @as(usize, 1) << @as(std.math.Log2Int(usize), @intCast(c - 1));
    const buckets = try allocator.alloc(G.Jacobian, n_buckets);
    defer allocator.free(buckets);

    var acc = G.Jacobian.identity;
    var w = n_windows;
    while (w > 0) {
        w -= 1;
        if (w != n_windows - 1) {
            for (0..c) |_| acc = acc.double();
        }

        @memset(buckets, G.Jacobian.identity);
        var any = false;
        for (points, 0..) |point, i| {
            const d = digits[i * n_windows + w];
            if (d == 0) continue;
            const b: usize = @abs(d) - 1;
            const q = if (d > 0) point else negAffine(G, point);
            buckets[b] = mixedAddVartime(G, buckets[b], q);
            any = true;
        }
        if (!any) continue;

        // sum_d (d+1) * buckets[d] via the running-sum trick.
        var running = G.Jacobian.identity;
        var window_sum = G.Jacobian.identity;
        var d = n_buckets;
        while (d > 0) {
            d -= 1;
            running = addVartime(G.Jacobian, running, buckets[d]);
            window_sum = addVartime(G.Jacobian, window_sum, running);
        }
        acc = addVartime(G.Jacobian, acc, window_sum);
    }
    return acc;
}

fn negAffine(comptime G: type, p: G.Affine) G.Affine {
    if (p.infinity) return p;
    return .{ .x = p.x, .y = p.y.neg(), .infinity = false };
}

/// The unsigned-digit Pippenger `msm` ran before the signed digits
/// (`windowBitsUnsigned`, `2^c - 1` buckets): the bench baseline.
fn msmUnsignedRef(comptime G: type, allocator: std.mem.Allocator, points: []const G.Affine, scalars: []const Fr) MsmError!G.Jacobian {
    if (points.len != scalars.len) return error.LengthMismatch;
    if (points.len == 0) return G.Jacobian.identity;
    const scalar_bytes = try allocator.alloc([32]u8, scalars.len);
    defer allocator.free(scalar_bytes);
    for (scalar_bytes, scalars) |*bytes, s| bytes.* = s.toBytes();
    const c = windowBitsUnsigned(points.len);
    const n_buckets = (@as(usize, 1) << @as(std.math.Log2Int(usize), @intCast(c))) - 1;
    const buckets = try allocator.alloc(G.Jacobian, n_buckets);
    defer allocator.free(buckets);
    const n_windows = (256 + c - 1) / c;
    var acc = G.Jacobian.identity;
    var w = n_windows;
    while (w > 0) {
        w -= 1;
        if (w != n_windows - 1) {
            for (0..c) |_| acc = acc.double();
        }
        @memset(buckets, G.Jacobian.identity);
        for (points, scalar_bytes) |point, *bytes| {
            const digit = windowDigit(bytes, w * c, c);
            if (digit == 0) continue;
            buckets[digit - 1] = mixedAddVartime(G, buckets[digit - 1], point);
        }
        var running = G.Jacobian.identity;
        var window_sum = G.Jacobian.identity;
        var d = n_buckets;
        while (d > 0) {
            d -= 1;
            running = addVartime(G.Jacobian, running, buckets[d]);
            window_sum = addVartime(G.Jacobian, window_sum, running);
        }
        acc = addVartime(G.Jacobian, acc, window_sum);
    }
    return acc;
}

/// `msm` in `G1`.
pub fn g1Msm(allocator: std.mem.Allocator, points: []const g1.Affine, scalars: []const Fr) MsmError!g1.Jacobian {
    return msm(g1, allocator, points, scalars);
}

/// `msm` in `G2`.
pub fn g2Msm(allocator: std.mem.Allocator, points: []const g2.Affine, scalars: []const Fr) MsmError!g2.Jacobian {
    return msm(g2, allocator, points, scalars);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

/// The reference: the constant-time per-point `scalarMul`, summed with the
/// constant-time `add` — no shared code with Pippenger or the vartime adds.
fn naive(comptime G: type, points: []const G.Affine, scalars: []const Fr) G.Jacobian {
    var acc = G.Jacobian.identity;
    for (points, scalars) |p, s| acc = acc.add(G.Jacobian.fromAffine(p).scalarMul(s));
    return acc;
}

fn sameMsmAsNaive(comptime G: type, n: usize, seed: u64) !void {
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    const points = try testing.allocator.alloc(G.Affine, n);
    defer testing.allocator.free(points);
    const scalars = try testing.allocator.alloc(Fr, n);
    defer testing.allocator.free(scalars);
    for (points, scalars, 0..) |*p, *s, i| {
        var wide: [64]u8 = undefined;
        rnd.bytes(&wide);
        s.* = Fr.reduceWide(&wide);
        rnd.bytes(&wide);
        p.* = G.Jacobian.fromAffine(G.Affine.generator).scalarMul(Fr.reduceWide(&wide)).toAffine();
        // Degenerate inputs mixed in: identity points, zero and one
        // scalars, a repeated point (bucket P == Q), a point and its
        // negation under equal scalars (P == -Q).
        switch (i % 7) {
            1 => p.* = G.Affine.identity,
            2 => s.* = Fr.zero,
            3 => s.* = Fr.one,
            4 => if (i > 0) {
                p.* = points[i - 1];
                s.* = scalars[i - 1];
            },
            5 => if (i > 0) {
                p.* = G.Jacobian.fromAffine(points[i - 1]).negate().toAffine();
                s.* = scalars[i - 1];
            },
            else => {},
        }
    }
    const got = (try msm(G, testing.allocator, points, scalars)).toAffine();
    const want = naive(G, points, scalars).toAffine();
    try testing.expectEqual(G.toBytesCompressed(want), G.toBytesCompressed(got));
}

test "msm matches the constant-time naive sum in G1 and G2, across window widths and degenerate inputs" {
    // n spans windowBits' 2..5 range; the degenerate pattern repeats
    // every 7 points.
    for ([_]usize{ 1, 3, 8, 21, 70 }, 0..) |n, k| {
        try sameMsmAsNaive(g1, n, 0x6d736d00 + k);
        try sameMsmAsNaive(g2, n, 0x6d736d10 + k);
    }
}

test "msm: empty input is the identity; a length mismatch is an error; all-zero scalars give the identity" {
    try testing.expect((try g2Msm(testing.allocator, &.{}, &.{})).isIdentity());
    const pts = [_]g2.Affine{ g2.Affine.generator, g2.Affine.generator };
    try testing.expectError(error.LengthMismatch, g2Msm(testing.allocator, &pts, &.{Fr.one}));
    try testing.expect((try g2Msm(testing.allocator, &pts, &.{ Fr.zero, Fr.zero })).isIdentity());
    try testing.expectError(error.LengthMismatch, g1Msm(testing.allocator, &.{g1.Affine.generator}, &.{}));
}

test "addVartime / mixedAddVartime agree with the constant-time add on every degenerate class (G2)" {
    const gen = g2.Jacobian.fromAffine(g2.Affine.generator);
    const p = gen.scalarMulBytes(&.{5});
    const q = gen.scalarMulBytes(&.{11});
    const cases = [_][2]g2.Jacobian{
        .{ p, q }, // general
        .{ p, p }, // P == Q
        .{ p, p.negate() }, // P == -Q
        .{ g2.Jacobian.identity, q },
        .{ p, g2.Jacobian.identity },
    };
    for (cases) |cs| {
        const want = g2.toBytesCompressed(cs[0].add(cs[1]).toAffine());
        try testing.expectEqual(want, g2.toBytesCompressed(addVartime(g2.Jacobian, cs[0], cs[1]).toAffine()));
        try testing.expectEqual(want, g2.toBytesCompressed(mixedAddVartime(g2, cs[0], cs[1].toAffine()).toAffine()));
    }
}

test "signedDigits: digits in range and Σ d_w·2^(c·w) == the scalar, every window width" {
    var prng = std.Random.DefaultPrng.init(0x516e);
    const rnd = prng.random();
    for (0..64) |t| {
        var wide: [64]u8 = undefined;
        rnd.bytes(&wide);
        const s: Fr = switch (t) {
            0 => Fr.zero,
            1 => Fr.one,
            2 => Fr.zero.sub(Fr.one), // r - 1
            else => Fr.reduceWide(&wide),
        };
        const bytes = s.toBytes();
        const want = std.mem.readInt(u256, &bytes, .big);
        for (2..10) |c| {
            var digits: [130]i16 = undefined;
            const nw = (256 + c - 1) / c + 1;
            signedDigits(&bytes, c, digits[0..nw]);
            var got: i512 = 0;
            var w = nw;
            while (w > 0) {
                w -= 1;
                const d = digits[w];
                try testing.expect(d >= -(@as(i32, 1) << @intCast(c - 1)) and d < (@as(i32, 1) << @intCast(c - 1)));
                got = got * (@as(i512, 1) << @intCast(c)) + d;
            }
            try testing.expectEqual(@as(i512, want), got);
        }
    }
}

test "signed-digit msm == the unsigned Pippenger it replaced (G1 n = 300, G2 n = 40)" {
    var prng = std.Random.DefaultPrng.init(0x516f);
    const rnd = prng.random();
    inline for (.{ .{ g1, 300 }, .{ g2, 40 } }) |gc| {
        const G = gc[0];
        const n = gc[1];
        var points: [n]G.Affine = undefined;
        var scalars: [n]Fr = undefined;
        var p = G.Jacobian.fromAffine(G.Affine.generator);
        for (&points, &scalars, 0..) |*pt, *s, i| {
            pt.* = p.toAffine();
            p = p.add(G.Jacobian.fromAffine(G.Affine.generator)).double();
            var wide: [64]u8 = undefined;
            rnd.bytes(&wide);
            s.* = if (i % 9 == 0) Fr.zero.sub(Fr.one) else Fr.reduceWide(&wide);
        }
        const got = (try msm(G, testing.allocator, &points, &scalars)).toAffine();
        const want = (try msmUnsignedRef(G, testing.allocator, &points, &scalars)).toAffine();
        try testing.expectEqual(G.toBytesCompressed(want), G.toBytesCompressed(got));
    }
}

test "bench: msm, unsigned vs signed digits (opt-in BLS12_381_BENCH)" {
    const bench = @import("bench.zig");
    if (!bench.enabled()) return error.SkipZigTest;
    const n = 4096; // a blob's Lagrange basis
    const gpa = std.heap.page_allocator; // global-alloc-ok: opt-in bench, one 400 KiB buffer outside the leak checker
    const points = try gpa.alloc(g1.Affine, n);
    defer gpa.free(points);
    const scalars = try gpa.alloc(Fr, n);
    defer gpa.free(scalars);
    var prng = std.Random.DefaultPrng.init(0xbe7c);
    const rnd = prng.random();
    var p = g1.Jacobian.fromAffine(g1.Affine.generator);
    for (points, scalars) |*pt, *s| {
        pt.* = p.toAffine();
        p = p.add(g1.Jacobian.fromAffine(g1.Affine.generator)).double();
        var wide: [64]u8 = undefined;
        rnd.bytes(&wide);
        s.* = Fr.reduceWide(&wide);
    }
    const Ctx = struct { gpa: std.mem.Allocator, points: []const g1.Affine, scalars: []const Fr };
    const S = struct {
        fn unsigned(c: *const Ctx) void {
            std.mem.doNotOptimizeAway(msmUnsignedRef(g1, c.gpa, c.points, c.scalars) catch unreachable);
        }
        fn signed(c: *const Ctx) void {
            std.mem.doNotOptimizeAway(msm(g1, c.gpa, c.points, c.scalars) catch unreachable);
        }
    };
    const ctx: Ctx = .{ .gpa = gpa, .points = points, .scalars = scalars };
    bench.ab("G1 msm n=4096 (A unsigned, B signed)", 4, &ctx, S.unsigned, S.signed);
    const small: Ctx = .{ .gpa = gpa, .points = points[0..64], .scalars = scalars[0..64] };
    bench.ab("G1 msm n=64 (A unsigned, B signed)", 20, &small, S.unsigned, S.signed);
}
