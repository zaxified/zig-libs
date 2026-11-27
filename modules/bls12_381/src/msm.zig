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
///
/// Bucket accumulation: from `affine_min_n` points on, each window's points
/// are grouped by bucket and summed in rounds of pairwise AFFINE additions
/// whose denominators share one inversion (Montgomery's batch inversion;
/// the "batch affine" step of gnark-crypto's and arkworks' MSM), while a
/// round has at least `affine_min_pairs` pairs to amortise it; what is left
/// of each bucket is folded with Jacobian mixed additions. The result is the
/// same group element either way.
pub fn msm(comptime G: type, allocator: std.mem.Allocator, points: []const G.Affine, scalars: []const Fr) MsmError!G.Jacobian {
    return msmWith(G, allocator, points, scalars, .{});
}

/// Tuning of `msm`'s bucket accumulation; the defaults are what `msm` uses,
/// the fields exist so tests and the bench can force either path.
const Tuning = struct {
    /// Fewest points for which the affine batch-inverted accumulation is
    /// used at all; below it every bucket addition is a Jacobian mixed one.
    min_n: usize = affine_min_n,
    /// A round of pairwise affine additions runs only while it has at least
    /// this many pairs to share one inversion; the rest of each bucket is
    /// folded with Jacobian mixed additions.
    min_pairs: usize = affine_min_pairs,
};

fn msmWith(comptime G: type, allocator: std.mem.Allocator, points: []const G.Affine, scalars: []const Fr, tuning: Tuning) MsmError!G.Jacobian {
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

    const use_affine = points.len >= tuning.min_n;
    var aff: AffineScratch(G) = undefined;
    if (use_affine) aff = try AffineScratch(G).init(allocator, points.len, n_buckets);
    defer if (use_affine) aff.deinit(allocator);

    var acc = G.Jacobian.identity;
    var w = n_windows;
    while (w > 0) {
        w -= 1;
        if (w != n_windows - 1) {
            for (0..c) |_| acc = acc.double();
        }

        @memset(buckets, G.Jacobian.identity);
        var any = false;
        if (use_affine) {
            any = aff.fillBuckets(points, digits, n_windows, w, tuning.min_pairs, buckets);
        } else for (points, 0..) |point, i| {
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

/// Fewest points for which `msm` uses the batch-inverted affine bucket
/// accumulation (measured crossover: see SPEC "MSM").
const affine_min_n: usize = 512;
/// Fewest pairs in a round for its shared inversion to pay: one `Fp.inv`
/// (Fermat, about 450 multiplications) against ~3 multiplications saved per
/// pair, so a round needs on the order of 100 pairs.
const affine_min_pairs: usize = 128;

/// Montgomery's batch inversion: `vals[i] = 1/vals[i]` for all `i` with one
/// field inversion and `3 (n - 1)` multiplications. Every element must be
/// nonzero (the caller substitutes 1 for the slots it does not need).
/// `prefix.len >= vals.len`.
fn batchInvert(comptime F: type, vals: []F, prefix: []F) void {
    if (vals.len == 0) return;
    var run = F.one;
    for (vals, 0..) |v, i| {
        prefix[i] = run;
        run = run.mul(v);
    }
    // A product of nonzero elements is nonzero.
    var inv_run = run.inv() catch unreachable;
    var i = vals.len;
    while (i > 0) {
        i -= 1;
        const v = vals[i];
        vals[i] = inv_run.mul(prefix[i]);
        inv_run = inv_run.mul(v);
    }
}

/// What adding two affine points `a + b` needs.
const PairKind = enum { add, dbl, take_a, take_b, identity };

fn classify(comptime G: type, a: G.Affine, b: G.Affine) PairKind {
    if (a.infinity) return .take_b;
    if (b.infinity) return .take_a;
    if (a.x.eql(b.x)) {
        if (a.y.eql(b.y) and !a.y.isZero()) return .dbl;
        return .identity; // P == -Q (or a point of order 2: 2P = O)
    }
    return .add;
}

/// Scratch for the batch-affine bucket accumulation of one `msm` call:
/// the window's points grouped by bucket plus the batch-inversion arrays.
fn AffineScratch(comptime G: type) type {
    const F = @TypeOf(G.Affine.generator.x);
    return struct {
        const Self = @This();
        /// The window's non-zero-digit points (sign applied), bucket by bucket.
        work: []G.Affine,
        /// First slot of each bucket in `work`, and its current length.
        starts: []usize,
        lens: []usize,
        /// Denominators (then their inverses) and the prefix products.
        den: []F,
        prefix: []F,

        fn init(allocator: std.mem.Allocator, n: usize, n_buckets: usize) std.mem.Allocator.Error!Self {
            const work = try allocator.alloc(G.Affine, n);
            errdefer allocator.free(work);
            const starts = try allocator.alloc(usize, n_buckets);
            errdefer allocator.free(starts);
            const lens = try allocator.alloc(usize, n_buckets);
            errdefer allocator.free(lens);
            const den = try allocator.alloc(F, n / 2 + 1);
            errdefer allocator.free(den);
            const prefix = try allocator.alloc(F, n / 2 + 1);
            return .{ .work = work, .starts = starts, .lens = lens, .den = den, .prefix = prefix };
        }

        fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.work);
            allocator.free(self.starts);
            allocator.free(self.lens);
            allocator.free(self.den);
            allocator.free(self.prefix);
        }

        /// Fill `buckets` (all identity on entry) with window `w`'s bucket
        /// sums; false when no point has a non-zero digit in the window.
        fn fillBuckets(self: *Self, points: []const G.Affine, digits: []const i16, n_windows: usize, w: usize, min_pairs: usize, buckets: []G.Jacobian) bool {
            const lens = self.lens;
            const starts = self.starts;
            const work = self.work;
            @memset(lens, 0);
            var total: usize = 0;
            for (points, 0..) |point, i| {
                const d = digits[i * n_windows + w];
                if (d == 0 or point.infinity) continue;
                lens[@abs(d) - 1] += 1;
                total += 1;
            }
            if (total == 0) return false;
            var off: usize = 0;
            for (lens, starts) |l, *st| {
                st.* = off;
                off += l;
            }
            // Counting-sort placement; `lens` doubles as the fill cursor.
            @memset(lens, 0);
            for (points, 0..) |point, i| {
                const d = digits[i * n_windows + w];
                if (d == 0 or point.infinity) continue;
                const b: usize = @abs(d) - 1;
                work[starts[b] + lens[b]] = if (d > 0) point else negAffine(G, point);
                lens[b] += 1;
            }

            // Rounds of pairwise affine additions, one shared inversion each.
            while (true) {
                var n_pairs: usize = 0;
                for (lens) |l| n_pairs += l / 2;
                if (n_pairs < @max(min_pairs, 1)) break;

                var k: usize = 0;
                for (lens, starts) |l, s| {
                    var j: usize = 0;
                    while (j + 1 < l) : (j += 2) {
                        const a = work[s + j];
                        const b = work[s + j + 1];
                        self.den[k] = switch (classify(G, a, b)) {
                            .add => b.x.sub(a.x),
                            .dbl => a.y.add(a.y),
                            else => F.one,
                        };
                        k += 1;
                    }
                }
                batchInvert(F, self.den[0..k], self.prefix[0..k]);

                k = 0;
                for (lens, starts) |*lp, s| {
                    const l = lp.*;
                    var j: usize = 0;
                    while (j + 1 < l) : (j += 2) {
                        const a = work[s + j];
                        const b = work[s + j + 1];
                        const inv_den = self.den[k];
                        k += 1;
                        work[s + j / 2] = switch (classify(G, a, b)) {
                            .add => addAffine(G, a, b, b.y.sub(a.y).mul(inv_den)),
                            .dbl => blk: {
                                const xx = a.x.square();
                                break :blk addAffine(G, a, a, xx.add(xx).add(xx).mul(inv_den));
                            },
                            .take_a => a,
                            .take_b => b,
                            .identity => G.Affine.identity,
                        };
                    }
                    if (l & 1 == 1) work[s + l / 2] = work[s + l - 1];
                    lp.* = (l + 1) / 2;
                }
            }

            for (lens, starts, buckets) |l, s, *bucket| {
                for (work[s..][0..l]) |p| bucket.* = mixedAddVartime(G, bucket.*, p);
            }
            return true;
        }
    };
}

/// The affine sum `a + b` given the slope `lambda` (`a != -b`; `b == a` for
/// a doubling, where `lambda = 3 x^2 / 2 y`): `x3 = lambda^2 - x1 - x2`,
/// `y3 = lambda (x1 - x3) - y1`.
fn addAffine(comptime G: type, a: G.Affine, b: G.Affine, lambda: @TypeOf(a.x)) G.Affine {
    const x3 = lambda.square().sub(a.x).sub(b.x);
    const y3 = lambda.mul(a.x.sub(x3)).sub(a.y);
    return .{ .x = x3, .y = y3, .infinity = false };
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

/// Random points/scalars for `n`, with identity points, edge scalars
/// (0, 1, r-1), repeated points (bucket P == Q) and negated points (P == -Q)
/// mixed in.
fn randomInputs(comptime G: type, rnd: std.Random, points: []G.Affine, scalars: []Fr) void {
    var p = G.Jacobian.fromAffine(G.Affine.generator);
    for (points, scalars, 0..) |*pt, *s, i| {
        var wide: [64]u8 = undefined;
        rnd.bytes(&wide);
        s.* = Fr.reduceWide(&wide);
        p = p.add(G.Jacobian.fromAffine(G.Affine.generator)).double();
        pt.* = p.toAffine();
        switch (i % 11) {
            1 => pt.* = G.Affine.identity,
            2 => s.* = Fr.zero,
            3 => s.* = Fr.one,
            4 => s.* = Fr.zero.sub(Fr.one),
            5 => if (i > 0) {
                pt.* = points[i - 1];
                s.* = scalars[i - 1];
            },
            6 => if (i > 0) {
                pt.* = G.Jacobian.fromAffine(points[i - 1]).negate().toAffine();
                s.* = scalars[i - 1];
            },
            else => {},
        }
    }
}

fn smallScalar(v: u16) Fr {
    var b: [32]u8 = @splat(0);
    std.mem.writeInt(u16, b[30..32], v, .big);
    return Fr.fromBytes(b) catch unreachable;
}

fn expectPathsAgree(comptime G: type, n: usize, seed: u64) !void {
    var prng = std.Random.DefaultPrng.init(seed);
    const points = try testing.allocator.alloc(G.Affine, n);
    defer testing.allocator.free(points);
    const scalars = try testing.allocator.alloc(Fr, n);
    defer testing.allocator.free(scalars);
    randomInputs(G, prng.random(), points, scalars);
    const jac = (try msmWith(G, testing.allocator, points, scalars, .{ .min_n = std.math.maxInt(usize) })).toAffine();
    const forced = (try msmWith(G, testing.allocator, points, scalars, .{ .min_n = 0, .min_pairs = 1 })).toAffine();
    const dflt = (try msm(G, testing.allocator, points, scalars)).toAffine();
    try testing.expectEqual(G.toBytesCompressed(jac), G.toBytesCompressed(forced));
    try testing.expectEqual(G.toBytesCompressed(jac), G.toBytesCompressed(dflt));
}

test "batch-affine msm == Jacobian-bucket msm, n = 1..70 in G1 and G2 (every round forced)" {
    for (1..71) |n| {
        try expectPathsAgree(g1, n, 0xa5f1000 + n);
        try expectPathsAgree(g2, n, 0xa5f2000 + n);
    }
}

test "batch-affine msm == Jacobian-bucket msm at larger n (default thresholds engage)" {
    for ([_]usize{ 511, 512, 1000, 2049, 8192 }, 0..) |n, k| try expectPathsAgree(g1, n, 0xa5f3000 + k);
    for ([_]usize{ 600, 2100 }, 0..) |n, k| try expectPathsAgree(g2, n, 0xa5f4000 + k);
}

test "batch-affine msm: all points equal / all pairs cancel / all identity / all scalars equal" {
    const n = 300;
    var points: [n]g1.Affine = undefined;
    var scalars: [n]Fr = undefined;
    const forced: Tuning = .{ .min_n = 0, .min_pairs = 1 };
    const gen = g1.Affine.generator;
    const neg_gen = negAffine(g1, gen);
    // Every point equal, one scalar: every bucket pair is a doubling.
    @memset(&points, gen);
    @memset(&scalars, smallScalar(5));
    var got = (try msmWith(g1, testing.allocator, &points, &scalars, forced)).toAffine();
    const want = g1.Jacobian.fromAffine(gen).scalarMul(smallScalar(5 * n)).toAffine();
    try testing.expectEqual(g1.toBytesCompressed(want), g1.toBytesCompressed(got));
    // Alternating P, -P under one scalar: everything cancels.
    for (&points, 0..) |*pt, i| pt.* = if (i % 2 == 0) gen else neg_gen;
    got = (try msmWith(g1, testing.allocator, &points, &scalars, forced)).toAffine();
    try testing.expect(got.infinity);
    // All identity points.
    @memset(&points, g1.Affine.identity);
    try testing.expect((try msmWith(g1, testing.allocator, &points, &scalars, forced)).isIdentity());
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

test "bench: msm, Jacobian vs batch-affine bucket accumulation (opt-in BLS12_381_BENCH)" {
    const bench = @import("bench.zig");
    if (!bench.enabled()) return error.SkipZigTest;
    const gpa = std.heap.page_allocator; // global-alloc-ok: opt-in bench, buffers outside the leak checker
    inline for (.{ g1, g2 }) |G| {
        const max_n = if (G == g1) 65536 else 16384;
        const points = try gpa.alloc(G.Affine, max_n);
        defer gpa.free(points);
        const scalars = try gpa.alloc(Fr, max_n);
        defer gpa.free(scalars);
        var prng = std.Random.DefaultPrng.init(0xbe7d);
        const rnd = prng.random();
        var p = G.Jacobian.fromAffine(G.Affine.generator);
        for (points, scalars) |*pt, *s| {
            pt.* = p.toAffine();
            p = p.add(G.Jacobian.fromAffine(G.Affine.generator)).double();
            var wide: [64]u8 = undefined;
            rnd.bytes(&wide);
            s.* = Fr.reduceWide(&wide);
        }
        const Ctx = struct { points: []const G.Affine, scalars: []const Fr };
        const S = struct {
            fn jac(c: *const Ctx) void {
                std.mem.doNotOptimizeAway(msmWith(G, std.heap.page_allocator, c.points, c.scalars, .{ .min_n = std.math.maxInt(usize) }) catch unreachable);
            }
            fn affine(c: *const Ctx) void {
                std.mem.doNotOptimizeAway(msmWith(G, std.heap.page_allocator, c.points, c.scalars, .{ .min_n = 0 }) catch unreachable);
            }
        };
        inline for (.{ 256, 512, 1024, 4096, 16384, 65536 }) |n| {
            if (n <= max_n) {
                const ctx: Ctx = .{ .points = points[0..n], .scalars = scalars[0..n] };
                const iters = if (n <= 1024) 8 else if (n <= 4096) 2 else 1;
                bench.ab((if (G == g1) "G1" else "G2") ++ " msm n=" ++ std.fmt.comptimePrint("{d}", .{n}) ++ " (A jacobian buckets, B batch-affine)", iters, &ctx, S.jac, S.affine);
            }
        }
    }
}

test "mutation 2026-11-27: the affine bucket rounds terminate for min_pairs = 0 (at least one pair is needed to batch)" {
    const n = 24;
    var points: [n]g1.Affine = undefined;
    var scalars: [n]Fr = undefined;
    var prng = std.Random.DefaultPrng.init(0x0c0ffee);
    for (&points, &scalars) |*p, *s| {
        var wide: [64]u8 = undefined;
        prng.random().bytes(&wide);
        s.* = Fr.reduceWide(&wide);
        prng.random().bytes(&wide);
        p.* = g1.Jacobian.fromAffine(g1.Affine.generator).scalarMul(Fr.reduceWide(&wide)).toAffine();
    }
    const got = (try msmWith(g1, testing.allocator, &points, &scalars, .{ .min_n = 0, .min_pairs = 0 })).toAffine();
    const want = naive(g1, &points, &scalars).toAffine();
    try testing.expectEqual(g1.toBytesCompressed(want), g1.toBytesCompressed(got));
}
