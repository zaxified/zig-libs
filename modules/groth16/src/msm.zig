// SPDX-License-Identifier: MIT
//! Multi-scalar multiplication (MSM) in `G1`/`G2`: `Σ sᵢ·Pᵢ`. The Groth16
//! proof elements are MSMs of witness/quotient coefficients against the
//! proving-key group elements. This is the naive schoolbook MSM (one
//! `scalarMul` per term, accumulated) — the same shape as the sibling
//! `bn254` verifier's own public-input accumulation. REAL and ungated.
//!
//! The naive form is constant-time and is the REFERENCE: the bucket method
//! below (`pippengerG1`/`pippengerG2`, the prover's MSM since 2026-10-02) is
//! tested against it.

const std = @import("std");
const bn254 = @import("bn254");
const field = @import("field.zig");
const Fr = field.Fr;

const G1 = bn254.G1;
const G2 = bn254.G2;

/// `Σ scalarsᵢ · basesᵢ` in `G1`. `scalars.len` must equal `bases.len`.
/// Returns the identity for empty input.
pub fn msmG1(bases: []const G1.Affine, scalars: []const Fr) G1.Jacobian {
    std.debug.assert(bases.len == scalars.len);
    var acc = G1.Jacobian.identity;
    for (bases, scalars) |base, s| {
        acc = acc.add(G1.Jacobian.fromAffine(base).scalarMul(s));
    }
    return acc;
}

/// `Σ scalarsᵢ · basesᵢ` in `G2`. `scalars.len` must equal `bases.len`.
pub fn msmG2(bases: []const G2.Affine, scalars: []const Fr) G2.Jacobian {
    std.debug.assert(bases.len == scalars.len);
    var acc = G2.Jacobian.identity;
    for (bases, scalars) |base, s| {
        acc = acc.add(G2.Jacobian.fromAffine(base).scalarMul(s));
    }
    return acc;
}

// ── Pippenger (bucket) MSM ─────────────────────────────────────────────────
//
// ⚠ VARIABLE-TIME in the scalars: which bucket a base lands in, and whether a
// bucket is still empty, depend on the scalar bits. Every Groth16 prover in
// the survey whose source we could read (arkworks, gnark) makes this trade,
// because the constant-time alternative costs an order of magnitude; the
// scalars here are the WITNESS, so a co-resident attacker who can time or
// cache-probe the prover learns about it. SPEC.md § 5b item 4. The naive
// `msmG1`/`msmG2` above (constant-time `scalarMul` per term) stay as the
// reference this path is tested against.

/// The variable-time group operations are `bn254.msm`'s (`addVartime`,
/// `mixedAddVartime`: public in `bn254` since 2026-11-17, they were a private
/// copy here). Both curves have `a = 0`.
fn VtOps(comptime G: type) type {
    return struct {
        fn addMixed(p: G.Jacobian, q: G.Affine) G.Jacobian {
            return bn254.msm.mixedAddVartime(G, p, q);
        }

        fn add(a: G.Jacobian, b: G.Jacobian) G.Jacobian {
            return bn254.msm.addVartime(G.Jacobian, a, b);
        }
    };
}

/// Window width for `n` terms: about `ln n + 2` (the usual Pippenger
/// optimum), clamped to `[2, 16]`.
fn windowBits(n: usize) u5 {
    if (n < 4) return 2;
    const log2n: usize = std.math.log2_int(usize, n);
    return @intCast(std.math.clamp(log2n * 69 / 100 + 2, 2, 16));
}

/// The `c`-bit digit of little-endian 64-bit limbs starting at bit `bit`.
fn digitAt(limbs: *const [4]u64, bit: usize, c: u5) usize {
    const mask: u64 = (@as(u64, 1) << c) - 1;
    const li = bit / 64;
    const sh: u6 = @intCast(bit % 64);
    var d = limbs[li] >> sh;
    if (@as(usize, sh) + c > 64 and li + 1 < 4) d |= limbs[li + 1] << @intCast(64 - @as(usize, sh));
    return @intCast(d & mask);
}

/// Below this many terms one double-and-add per term beats the buckets: a
/// window pass costs 254 doublings whatever `n` is. `phase2.newZkey` makes
/// one MSM per signal, most of them 1–3 terms with a ±1 coefficient
/// (measured: 10 000 such calls were most of `newZkey`'s time).
const small_msm = 8;

fn Pippenger(comptime G: type) type {
    const J = G.Jacobian;
    const A = G.Affine;
    const Ops = VtOps(G);
    return struct {
        fn small(bases: []const A, scalars: []const Fr) J {
            const minus_one = Fr.zero.sub(Fr.one);
            var acc = J.identity;
            for (bases, scalars) |base, s| {
                if (s.isZero() or base.infinity) continue;
                if (s.eql(Fr.one)) {
                    acc = Ops.addMixed(acc, base);
                    continue;
                }
                if (s.eql(minus_one)) {
                    acc = Ops.addMixed(acc, .{ .x = base.x, .y = base.y.neg() });
                    continue;
                }
                const be = s.toBytes();
                var term = J.identity;
                for (be) |byte| {
                    var bit: u4 = 8;
                    while (bit > 0) {
                        bit -= 1;
                        term = term.double();
                        if ((byte >> @intCast(bit)) & 1 == 1) term = Ops.addMixed(term, base);
                    }
                }
                acc = Ops.add(acc, term);
            }
            return acc;
        }

        fn run(allocator: std.mem.Allocator, bases: []const A, scalars: []const Fr) std.mem.Allocator.Error!J {
            std.debug.assert(bases.len == scalars.len);
            const n = bases.len;
            if (n == 0) return J.identity;
            if (n < small_msm) return small(bases, scalars);

            // Canonical scalars as little-endian limbs, once.
            const limbs = try allocator.alloc([4]u64, n);
            defer {
                // The scalars may be a witness; so may the buckets they chose.
                std.crypto.secureZero(u8, std.mem.sliceAsBytes(limbs));
                allocator.free(limbs);
            }
            for (scalars, limbs) |s, *l| {
                const be = s.toBytes();
                for (0..4) |k| l[k] = std.mem.readInt(u64, be[32 - 8 * (k + 1) ..][0..8], .big);
            }

            const c = windowBits(n);
            const buckets = try allocator.alloc(J, (@as(usize, 1) << c) - 1);
            defer {
                // Which bases sit in which bucket is the scalars' digits.
                std.crypto.secureZero(u8, std.mem.sliceAsBytes(buckets));
                allocator.free(buckets);
            }

            const scalar_bits = 254; // r < 2^254
            const windows = (scalar_bits + @as(usize, c) - 1) / c;
            var acc = J.identity;
            var w = windows;
            while (w > 0) {
                w -= 1;
                for (0..c) |_| acc = acc.double();
                @memset(buckets, J.identity);
                for (bases, limbs) |base, *l| {
                    const d = digitAt(l, w * c, c);
                    if (d != 0) buckets[d - 1] = Ops.addMixed(buckets[d - 1], base);
                }
                // Σ_d d·bucket[d] by the running-sum trick.
                var running = J.identity;
                var window_sum = J.identity;
                var b = buckets.len;
                while (b > 0) {
                    b -= 1;
                    running = Ops.add(running, buckets[b]);
                    window_sum = Ops.add(window_sum, running);
                }
                acc = Ops.add(acc, window_sum);
            }
            return acc;
        }
    };
}

/// `Σ scalarsᵢ · basesᵢ` in `G1` by Pippenger's bucket method — the prover's
/// MSM. Variable-time in the scalars (see the section comment above).
pub fn pippengerG1(allocator: std.mem.Allocator, bases: []const G1.Affine, scalars: []const Fr) std.mem.Allocator.Error!G1.Jacobian {
    return Pippenger(G1).run(allocator, bases, scalars);
}

/// `Σ scalarsᵢ · basesᵢ` in `G2` by Pippenger's bucket method.
pub fn pippengerG2(allocator: std.mem.Allocator, bases: []const G2.Affine, scalars: []const Fr) std.mem.Allocator.Error!G2.Jacobian {
    return Pippenger(G2).run(allocator, bases, scalars);
}

// ── tests ────────────────────────────────────────────────────────────────

const frFromU64 = field.frFromU64;

fn g1Eql(a: G1.Jacobian, b: G1.Jacobian) bool {
    const aa = a.toAffine();
    const bb = b.toAffine();
    if (aa.infinity or bb.infinity) return aa.infinity == bb.infinity;
    return aa.x.eql(bb.x) and aa.y.eql(bb.y);
}

test "msmG1: single term equals scalarMul" {
    const g = G1.Affine.generator;
    const s = frFromU64(7);
    const got = msmG1(&.{g}, &.{s});
    const want = G1.Jacobian.fromAffine(g).scalarMul(s);
    try std.testing.expect(g1Eql(got, want));
}

test "msmG1: linearity — [2]G + [3]G == [5]G" {
    const g = G1.Affine.generator;
    const two = msmG1(&.{ g, g }, &.{ frFromU64(2), frFromU64(3) });
    const five = G1.Jacobian.fromAffine(g).scalarMul(frFromU64(5));
    try std.testing.expect(g1Eql(two, five));
}

test "msmG1: empty input is identity" {
    const got = msmG1(&.{}, &.{});
    try std.testing.expect(got.toAffine().infinity);
}

test "msmG2: single term equals scalarMul" {
    const g = G2.Affine.generator;
    const s = frFromU64(9);
    const got = msmG2(&.{g}, &.{s}).toAffine();
    const want = G2.Jacobian.fromAffine(g).scalarMul(s).toAffine();
    try std.testing.expect(got.x.eql(want.x) and got.y.eql(want.y));
}

fn testPoints(comptime A: type, comptime J: type, out: []A, seed: u64) void {
    var prng = std.Random.DefaultPrng.init(seed);
    var cur = J.fromAffine(A.generator);
    for (out, 0..) |*p, i| {
        // Mix in identities and repeated / negated points: the cases where
        // the variable-time formulas branch.
        p.* = switch (i % 7) {
            3 => A.identity,
            5 => out[i - 1],
            6 => cur.negate().toAffine(),
            else => cur.toAffine(),
        };
        cur = cur.scalarMul(frFromU64(prng.random().int(u64) | 1));
    }
}

fn testScalars(out: []Fr, seed: u64) void {
    var prng = std.Random.DefaultPrng.init(seed);
    for (out, 0..) |*s, i| {
        var b: [64]u8 = undefined;
        prng.random().bytes(&b);
        s.* = switch (i % 5) {
            1 => Fr.zero,
            2 => Fr.one,
            3 => Fr.zero.sub(Fr.one), // r − 1: every digit window populated
            else => Fr.reduceWide(&b),
        };
    }
}

test "pippengerG1 == naive msmG1 across sizes and window widths" {
    const a = std.testing.allocator;
    for ([_]usize{ 1, 2, 3, 7, 8, 9, 33, 130 }) |n| {
        const pts = try a.alloc(G1.Affine, n);
        defer a.free(pts);
        const sc = try a.alloc(Fr, n);
        defer a.free(sc);
        testPoints(G1.Affine, G1.Jacobian, pts, n);
        testScalars(sc, n + 100);
        try std.testing.expect(g1Eql(try pippengerG1(a, pts, sc), msmG1(pts, sc)));
    }
}

test "pippengerG2 == naive msmG2" {
    const a = std.testing.allocator;
    for ([_]usize{ 1, 5, 40 }) |n| {
        const pts = try a.alloc(G2.Affine, n);
        defer a.free(pts);
        const sc = try a.alloc(Fr, n);
        defer a.free(sc);
        testPoints(G2.Affine, G2.Jacobian, pts, n);
        testScalars(sc, n + 7);
        const got = (try pippengerG2(a, pts, sc)).toAffine();
        const want = msmG2(pts, sc).toAffine();
        try std.testing.expectEqual(want.infinity, got.infinity);
        if (!want.infinity) try std.testing.expect(got.x.eql(want.x) and got.y.eql(want.y));
    }
}

test "digitAt crosses limb boundaries" {
    const l: [4]u64 = .{ 0xF000_0000_0000_0000, 0x5, 0, 0x8000_0000_0000_0000 };
    try std.testing.expectEqual(@as(usize, 0b0101_1111), digitAt(&l, 60, 8));
    try std.testing.expectEqual(@as(usize, 1), digitAt(&l, 255, 4));
}
