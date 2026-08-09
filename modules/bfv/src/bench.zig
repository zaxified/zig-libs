// SPDX-License-Identifier: MIT

//! bench — ns/op micro-benchmarks for the arithmetic rewrite. Off by default;
//! opt in with `BFV_BENCH`:
//!
//!   BFV_BENCH=1 scripts/capped zig build test-bfv -Doptimize=ReleaseFast
//!
//! Every row times the OLD path and the NEW path in the same binary on the
//! same inputs, so the ratios are the actual claim — not a remembered number:
//!
//!   1. word modmul — `modarith.mulMod` (a real 128-by-64 division, since `q`
//!      is a runtime value) vs Barrett (`Modulus`) vs Shoup.
//!   2. NTT forward/inverse — `forwardRef`/`inverseRef` (the original
//!      division-based bodies) vs the Shoup butterflies.
//!   3. CRT reconstruct — `rns.Basis.reconstruct` (recomputes `∏q`, every
//!      `∏_{k≠i} q_k` and a full `invMod` per call) vs the instance's
//!      `reconstruct` with the constants hoisted to `init`.
//!   4. homomorphic multiply — `mulExactRef` (the O(N²) exact-integer
//!      schoolbook tensor) vs `mulRnsNtt` (the auxiliary-basis RNS-NTT
//!      tensor), swept over ring degree at two modulus sizes. This is the row
//!      that fixes `Bfv.ntt_tensor_min_degree`, the comptime crossover `mul`
//!      dispatches on — `mulRnsNtt` is called DIRECTLY here so both paths are
//!      timed at every degree, including the ones `mul` would not pick.
//!
//! Numbers are noisy on mobile CPUs (turbo/thermal); treat them as ratios.
//! Working sets are deliberately small — this host has been OOM-killed by
//! oversized bench allocations before, so repeat rather than enlarge.

const std = @import("std");
const ma = @import("modarith.zig");
const nttmod = @import("ntt.zig");
const rns = @import("rns.zig");
const params = @import("params.zig");
const bfv = @import("bfv.zig");

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

/// Runtime-opaque so the compiler cannot constant-fold a modulus into a
/// magic-multiply and flatter the division baseline. (An earlier draft of this
/// bench measured `div` at 2 ns/op for exactly that reason — with `q` comptime,
/// `%` is not a division at all.)
var opaque_primes = [_]u64{ 65537, 786433, 1073750017, 4611686018427387617 };

fn benchModmul() void {
    std.mem.doNotOptimizeAway(&opaque_primes);
    const reps: usize = 40;
    const inner: usize = 200_000;
    var xs: [1024]u64 = undefined;
    var ys: [1024]u64 = undefined;
    var prng = std.Random.DefaultPrng.init(1);
    const rnd = prng.random();

    std.debug.print("\n-- word modmul (runtime modulus) --\n", .{});
    for (0..opaque_primes.len) |qi| {
        const q = opaque_primes[qi];
        for (&xs, &ys) |*x, *y| {
            x.* = rnd.uintLessThan(u64, q);
            y.* = rnd.uintLessThan(u64, q);
        }
        const bar = ma.Modulus.init(q) catch continue;
        const sh = ma.Shoup.init(xs[0], q);

        var acc: u64 = 0;
        var t0 = nowNs();
        for (0..reps) |_| for (0..inner) |i| {
            acc +%= ma.mulMod(xs[i & 1023], ys[i & 1023], q);
        };
        const t_div = nowNs() - t0;
        std.mem.doNotOptimizeAway(acc);

        acc = 0;
        t0 = nowNs();
        for (0..reps) |_| for (0..inner) |i| {
            acc +%= bar.mul(xs[i & 1023], ys[i & 1023]);
        };
        const t_bar = nowNs() - t0;
        std.mem.doNotOptimizeAway(acc);

        acc = 0;
        t0 = nowNs();
        for (0..reps) |_| for (0..inner) |i| {
            acc +%= sh.mul(ys[i & 1023], q);
        };
        const t_sh = nowNs() - t0;
        std.mem.doNotOptimizeAway(acc);

        const n: f64 = @floatFromInt(reps * inner);
        const d: f64 = @as(f64, @floatFromInt(t_div)) / n;
        const b: f64 = @as(f64, @floatFromInt(t_bar)) / n;
        const s: f64 = @as(f64, @floatFromInt(t_sh)) / n;
        std.debug.print(
            "q={d:>20} ({d:>2}b)  div {d:>6.2}  barrett {d:>5.2} ({d:>5.1}x)  shoup {d:>5.2} ({d:>5.1}x)  ns/op\n",
            .{ q, 64 - @clz(q), d, b, d / b, s, d / s },
        );
    }
}

fn benchNtt(comptime N: usize, q: u64, iters: usize) void {
    const T = nttmod.Ntt(N);
    const eng = T.init(q) catch return;
    var prng = std.Random.DefaultPrng.init(0x17F);
    const rnd = prng.random();
    var base: T.Poly = undefined;
    for (&base) |*x| x.* = rnd.uintLessThan(u64, q);

    var sink: u64 = 0;
    var a = base;
    var t0 = nowNs();
    for (0..iters) |_| {
        eng.forwardRef(&a);
        eng.inverseRef(&a);
        sink +%= a[0];
    }
    const t_ref = nowNs() - t0;
    std.mem.doNotOptimizeAway(sink);

    a = base;
    t0 = nowNs();
    for (0..iters) |_| {
        eng.forward(&a);
        eng.inverse(&a);
        sink +%= a[0];
    }
    const t_fast = nowNs() - t0;
    std.mem.doNotOptimizeAway(sink);

    const r: f64 = @floatFromInt(t_ref / iters);
    const f: f64 = @floatFromInt(t_fast / iters);
    std.debug.print("N={d:>5}  fwd+inv: div-ref {d:>10.0} ns  shoup {d:>10.0} ns  ({d:>5.2}x)\n", .{ N, r, f, r / f });
}

fn benchReconstruct(comptime P: params.Params, iters: usize) void {
    const B = bfv.Bfv(P);
    const inst = B.init() catch return;
    const basis = rns.Basis.init(P.primes) catch return;
    var prng = std.Random.DefaultPrng.init(0xC27);
    const rnd = prng.random();
    // A corpus of distinct residue vectors, indexed by the loop counter. With a
    // single loop-invariant input the hoisted version is trivially licensed to
    // be lifted out of the loop entirely — an earlier draft of this row read
    // "0.0 ns / 751051x" for exactly that reason, which is a measurement of
    // LICM, not of the code.
    var corpus: [256][P.primes.len]u64 = undefined;
    for (&corpus) |*r| for (0..P.primes.len) |i| {
        r[i] = rnd.uintLessThan(u64, P.primes[i]);
    };

    var sink: u128 = 0;
    var t0 = nowNs();
    for (0..iters) |it| sink +%= basis.reconstruct(&corpus[it & 255]);
    const t_ref = nowNs() - t0;
    std.mem.doNotOptimizeAway(sink);

    t0 = nowNs();
    for (0..iters) |it| sink +%= inst.reconstruct(&corpus[it & 255]);
    const t_fast = nowNs() - t0;
    std.mem.doNotOptimizeAway(sink);

    const r: f64 = @as(f64, @floatFromInt(t_ref)) / @as(f64, @floatFromInt(iters));
    const f: f64 = @as(f64, @floatFromInt(t_fast)) / @as(f64, @floatFromInt(iters));
    std.debug.print("L={d}  CRT reconstruct: rns.Basis {d:>9.1} ns  hoisted {d:>7.1} ns  ({d:>6.1}x)\n", .{ P.primes.len, r, f, r / f });
}

/// Two ~30-bit NTT primes with `2048 | q−1`, so the same pair is valid for
/// every `N ≤ 1024` and the multiply rows differ ONLY in the ring degree.
const bench_primes: []const u64 = &.{ 1073750017, 1073754113 };
/// The `test_mul` pair (`q ≈ 2^35.6`). `65537−1 = 2^16` and `786433−1 = 3·2^18`,
/// so both stay NTT-friendly well past the degrees swept here.
const small_primes: []const u64 = &.{ 65537, 786433 };

fn benchMulQ(comptime prime_set: []const u64, comptime n: usize, iters: usize) void {
    benchMul(params.Params{ .n = n, .t = 16, .primes = prime_set }, iters);
}

fn benchMul(comptime P: params.Params, iters: usize) void {
    const n = P.n;
    const B = bfv.Bfv(P);
    const inst = B.init() catch return;
    var prng = std.Random.DefaultPrng.init(0xB1F);
    const rnd = prng.random();

    var x = B.Ciphertext{ .components = .{ B.Ring.zero(.coeff), B.Ring.zero(.coeff), B.Ring.zero(.coeff) }, .len = 2 };
    var y = x;
    for (0..2) |c| {
        for (0..P.primes.len) |i| {
            for (0..n) |j| {
                x.components[c].limbs[i][j] = rnd.uintLessThan(u64, P.primes[i]);
                y.components[c].limbs[i][j] = rnd.uintLessThan(u64, P.primes[i]);
            }
        }
    }

    var sink: u64 = 0;
    var t0 = nowNs();
    for (0..iters) |_| sink +%= inst.mulExactRef(&x, &y).components[0].limbs[0][0];
    const t_ref = nowNs() - t0;
    std.mem.doNotOptimizeAway(sink);

    t0 = nowNs();
    for (0..iters) |_| sink +%= inst.mulRnsNtt(&x, &y).components[0].limbs[0][0];
    const t_fast = nowNs() - t0;
    std.mem.doNotOptimizeAway(sink);

    const r: f64 = @as(f64, @floatFromInt(t_ref)) / @as(f64, @floatFromInt(iters)) / 1000.0;
    const f: f64 = @as(f64, @floatFromInt(t_fast)) / @as(f64, @floatFromInt(iters)) / 1000.0;
    std.debug.print(
        "N={d:>4} (num_aux={d})  HomMul: schoolbook {d:>10.1} us  RNS-NTT {d:>9.3} us  ({d:>6.1}x)\n",
        .{ n, B.num_aux, r, f, r / f },
    );
}

test "bench (opt-in via BFV_BENCH)" {
    if (std.testing.environ.getPosix("BFV_BENCH") == null) return error.SkipZigTest;
    std.debug.print("\n=== bfv arithmetic bench (old path vs new path, same binary) ===\n", .{});
    benchModmul();

    std.debug.print("\n-- negacyclic NTT (forward + inverse round trip) --\n", .{});
    benchNtt(16, 786433, 200_000);
    benchNtt(256, 1073750017, 20_000);
    benchNtt(1024, 1073750017, 5_000);

    std.debug.print("\n-- exact CRT reconstruction (one coefficient) --\n", .{});
    benchReconstruct(params.test_mul, 200_000);
    benchReconstruct(params.bfv_toy, 200_000);

    std.debug.print("\n-- homomorphic multiply, q ~ 2^36 (test_mul primes, num_aux=2) --\n", .{});
    benchMul(params.test_mul, 2_000); // the shipped set the mul anchors use
    benchMulQ(small_primes, 32, 1_000);
    benchMulQ(small_primes, 64, 500);
    benchMulQ(small_primes, 256, 60);
    benchMulQ(small_primes, 512, 15);

    std.debug.print("\n-- homomorphic multiply, q ~ 2^60 (num_aux=3) --\n", .{});
    benchMulQ(bench_primes, 16, 2_000);
    benchMulQ(bench_primes, 32, 1_000);
    benchMulQ(bench_primes, 64, 500);
    benchMulQ(bench_primes, 256, 40);
    benchMulQ(bench_primes, 512, 10);
    std.debug.print("\n", .{});
}
