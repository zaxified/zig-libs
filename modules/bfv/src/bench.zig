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

fn randomCiphertext(comptime B: type, comptime P: params.Params, rnd: std.Random) B.Ciphertext {
    var x = B.Ciphertext{ .components = .{ B.Ring.zero(.coeff), B.Ring.zero(.coeff), B.Ring.zero(.coeff) }, .len = 2 };
    for (0..2) |c| {
        for (0..P.primes.len) |i| {
            for (0..P.n) |j| x.components[c].limbs[i][j] = rnd.uintLessThan(u64, P.primes[i]);
        }
    }
    return x;
}

fn benchMul(comptime P: params.Params, iters: usize) void {
    const n = P.n;
    const B = bfv.Bfv(P);
    const inst = B.init() catch return;
    var prng = std.Random.DefaultPrng.init(0xB1F);
    const rnd = prng.random();

    const x = randomCiphertext(B, P, rnd);
    const y = randomCiphertext(B, P, rnd);

    // The WHOLE 3-component result is kept alive. Reading a single limb here
    // would let LLVM dead-code two thirds of the rescale (and part of the
    // tensor) out of every path — differently in each, since the paths produce
    // their components differently. That is not a measurement of either.
    var t0 = nowNs();
    for (0..iters) |_| {
        var r = inst.mulExactRef(&x, &y);
        std.mem.doNotOptimizeAway(&r);
    }
    const t_ref = nowNs() - t0;

    t0 = nowNs();
    for (0..iters) |_| {
        var r = inst.mulRnsNtt(&x, &y);
        std.mem.doNotOptimizeAway(&r);
    }
    const t_fast = nowNs() - t0;

    t0 = nowNs();
    for (0..iters) |_| {
        var r = inst.mulBehz(&x, &y);
        std.mem.doNotOptimizeAway(&r);
    }
    const t_behz = nowNs() - t0;

    const r: f64 = @as(f64, @floatFromInt(t_ref)) / @as(f64, @floatFromInt(iters)) / 1000.0;
    const f: f64 = @as(f64, @floatFromInt(t_fast)) / @as(f64, @floatFromInt(iters)) / 1000.0;
    const h: f64 = @as(f64, @floatFromInt(t_behz)) / @as(f64, @floatFromInt(iters)) / 1000.0;
    std.debug.print(
        "N={d:>4} (aux={d}/rs={d})  HomMul: schoolbook {d:>10.1} us  RNS-NTT+intdiv {d:>9.3} us  BEHZ {d:>9.3} us  (BEHZ vs schoolbook {d:>6.1}x, vs RNS-NTT {d:>5.2}x)\n",
        .{ n, B.num_aux, B.num_rs, r, f, h, r / h, f / h },
    );
}

/// The row that IS the finding: `⌊t/q·T⌉`, per tensor coefficient, computed
/// (a) the old way — CRT-lift the auxiliary residues into an exact
/// `TensorI = i(2·log q + …)` and do two big-integer divisions — versus
/// (b) BEHZ, from residues only. The two start from different representations
/// of the SAME tensor on purpose: needing the exact integer to exist at all is
/// precisely what the old rescale cost.
fn benchRescale(comptime P: params.Params, iters: usize) void {
    const B = bfv.Bfv(P);
    const inst = B.init() catch return;
    var prng = std.Random.DefaultPrng.init(0x5CA1E);
    const rnd = prng.random();
    const x = randomCiphertext(B, P, rnd);
    const y = randomCiphertext(B, P, rnd);

    // A REAL tensor, so the operand magnitudes are the ones the rescale
    // actually sees (a uniform random `TensorI` would be far too large and a
    // small one far too easy).
    var lift: [3][P.n]B.TensorI = undefined;
    inst.tensorExactLift(&x, &y, &lift);
    var tq: [3]B.Ring = undefined;
    var ta: [3][B.num_rs + 1][P.n]u64 = undefined;
    inst.tensorAll(&x, &y, &tq, &ta);

    var t0 = nowNs();
    for (0..iters) |_| {
        var r = inst.rescaleTensor(&lift[0]);
        std.mem.doNotOptimizeAway(&r);
    }
    const t_old = nowNs() - t0;

    t0 = nowNs();
    for (0..iters) |_| {
        var r = inst.rescaleRns(&tq[0], &ta[0]);
        std.mem.doNotOptimizeAway(&r);
    }
    const t_new = nowNs() - t0;

    const per = @as(f64, @floatFromInt(iters)) * @as(f64, @floatFromInt(P.n));
    const o: f64 = @as(f64, @floatFromInt(t_old)) / per;
    const nn: f64 = @as(f64, @floatFromInt(t_new)) / per;
    std.debug.print(
        "log2 q={d:>3} L={d} (rs={d})  rescale/coeff: exact-integer {d:>8.1} ns  BEHZ-RNS {d:>8.1} ns  ({d:>6.2}x)\n",
        .{ B.q_bits, P.primes.len, B.num_rs, o, nn, o / nn },
    );
}

test "bench (opt-in via BFV_BENCH)" {
    if (@import("builtin").target.os.tag == .windows or std.testing.environ.getPosix("BFV_BENCH") == null) return error.SkipZigTest;
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

    // Wide moduli: past the old `u128` ceiling, where the exact-integer
    // rescale's divisions get genuinely wide. The schoolbook column is why
    // these use N=8/16 — it is O(N²) in `TensorI`.
    std.debug.print("\n-- homomorphic multiply, wide q (past the old u128 ceiling) --\n", .{});
    benchMul(wide_q180, 400);
    benchMul(wide_q300, 200);

    // Where does BEHZ start to pay? It costs `L` extra prime-NTT sets (the
    // main-basis tensor) and saves the whole exact-integer rescale, so the
    // crossover is a function of `log q`, not of `N`. Sweep it at a fixed
    // degree with a growing prime chain — this is what sets
    // `Bfv.behz_min_tensor_bits`.
    std.debug.print("\n-- crossover sweep: N=256, growing log q (30-bit primes) --\n", .{});
    inline for (.{ 2, 3, 4, 5 }) |k| {
        benchMul(params.Params{ .n = 256, .t = 16, .primes = narrow_chain[0..k] }, 60);
    }
    std.debug.print("\n-- crossover sweep: N=256, growing log q (60-bit primes) --\n", .{});
    inline for (.{ 2, 3, 4, 5, 6 }) |k| {
        benchMul(params.Params{ .n = 256, .t = 16, .primes = wide_chain[0..k] }, 40);
    }

    std.debug.print("\n-- the rescale itself: `t/q` rounding, per tensor coefficient --\n", .{});
    benchRescale(params.test_mul, 3_000);
    benchRescale(params.bfv_toy, 200);
    // The two `log q = 120` sets that land on OPPOSITE sides of the whole-mul
    // crossover: the rescale saving is the same, the transform overhead is not.
    benchRescale(params.Params{ .n = 256, .t = 16, .primes = narrow_chain[0..4] }, 100);
    benchRescale(params.Params{ .n = 256, .t = 16, .primes = wide_chain[0..2] }, 100);
    benchRescale(wide_q180, 400);
    benchRescale(wide_q300, 200);

    std.debug.print("\n-- security-grade set (N=8192, log q=218): one HomMul --\n", .{});
    // Own thread: a `Ring` is 256 KiB here and `mulBehz`'s working set is a
    // few MiB, past the default test-runner stack.
    if (std.Thread.spawn(.{ .stack_size = 256 << 20 }, benchSecurity, .{})) |th| {
        th.join();
    } else |_| {}
    std.debug.print("\n", .{});
}

/// Five 30-bit primes with `2048 | q−1` — the fine end of the crossover sweep
/// (`log q` = 60 / 90 / 120 / 150).
const narrow_chain = [_]u64{
    1073707009, 1073698817, 1073692673, 1073682433, 1073668097,
};

/// Six 60-bit primes with `2048 | q−1`, so a prefix of any length is a valid
/// chain for every `N ≤ 1024` and the crossover sweep varies ONLY `log q`.
const wide_chain = [_]u64{
    1152921504606830593, 1152921504606791681, 1152921504606748673,
    1152921504606683137, 1152921504606631937, 1152921504606601217,
};

/// `q ≈ 2^180` / `q ≈ 2^300` at a small degree — both impossible before the
/// `u128` ceiling came off.
const wide_q180 = params.Params{
    .n = 16,
    .t = 16,
    .primes = &.{ 1152921504606845473, 1152921504606844513, 1152921504606844417 },
};
const wide_q300 = params.Params{
    .n = 8,
    .t = 4,
    .primes = &.{
        1152921504606846577, 1152921504606846097, 1152921504606845777,
        1152921504606845473, 1152921504606844913,
    },
};

/// One multiply at the shipped security-grade parameters. Only the BEHZ path is
/// timed: `mulExactRef` is `O(N²)` over a 467-bit integer at N=8192 (hours),
/// and `mulRnsNtt` needs a 512-bit CRT plus two 467-bit divisions per
/// coefficient — the reason to quote is that neither is a usable baseline,
/// which is the finding.
fn benchSecurity() void {
    const P = params.sec_n8192_logq218;
    const B = bfv.Bfv(P);
    const inst = B.init() catch return;
    var prng = std.Random.DefaultPrng.init(0x5EC0);
    const rnd = prng.random();
    const x = randomCiphertext(B, P, rnd);
    const y = randomCiphertext(B, P, rnd);
    const iters: usize = 5;
    const t0 = nowNs();
    for (0..iters) |_| {
        var r = inst.mulBehz(&x, &y);
        std.mem.doNotOptimizeAway(&r);
    }
    const dt = nowNs() - t0;
    std.debug.print(
        "N={d} log2 q={d} L={d} (aux={d}/rs={d})  BEHZ HomMul {d:>8.2} ms\n",
        .{ P.n, B.q_bits, P.primes.len, B.num_aux, B.num_rs, @as(f64, @floatFromInt(dt)) / @as(f64, @floatFromInt(iters)) / 1e6 },
    );
}
