// SPDX-License-Identifier: MIT

//! bench — the measurement behind `poly.ntt_min_degree` and behind the claim
//! that the exact NTT ring multiply is worth its code. Off by default
//! (`error.SkipZigTest`); run it with `TFHE_BENCH`:
//!
//!   TFHE_BENCH=1 scripts/lib/capped zig build test-tfhe -Doptimize=ReleaseFast
//!
//! **What it answers.** The audit finding (`tfhe` F1) said the `O(N²)`
//! schoolbook `mul` dominates the bootstrap end to end. Two numbers settle
//! whether the replacement earns its place:
//!
//!   1. `mulSchoolbook` vs `mul` on the SAME random inputs in the SAME binary,
//!      per degree — including the degrees below the dispatch threshold, where
//!      the transform is expected to LOSE. That sweep is what
//!      `poly.ntt_min_degree` is set from, and the loop also asserts the two
//!      paths agree bit for bit so a mis-optimised measurement cannot pass.
//!   2. End-to-end gate bootstrap at the `toy` parameter set (`N = 256`),
//!      which issues `n·2·(2ℓ) = 1024` ring multiplies, unprepared and with
//!      the bootstrap key prepared in the NTT domain.
//!   3. The boolean layer at `tfhers_default` (tfhe-rs's DEFAULT_PARAMETERS):
//!      key generation, preparation, one AND gate, one MUX.
//!
//! Sizing: the largest working set is (3): a 53 MB bootstrap key, its 105 MB
//! prepared copy and a 25 MB key-switch key, ~185 MB at peak. Run under
//! `hw run` (an oversized benchmark in this repo once OOM-killed the host's
//! editor).

const std = @import("std");
const polymod = @import("poly.zig");
const ntt = @import("ntt.zig");
const params = @import("params.zig");
const tfhe = @import("tfhe.zig");

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

fn enabled() bool {
    if (@import("builtin").target.os.tag == .windows) return false;
    return std.testing.environ.getPosix("TFHE_BENCH") != null;
}

test "bench: schoolbook vs exact-NTT ring multiply, per degree" {
    if (!enabled()) return error.SkipZigTest;

    var prng = std.Random.DefaultPrng.init(0xB0A7);
    const rnd = prng.random();
    std.debug.print("\n  N     schoolbook          ntt      speedup\n", .{});

    inline for (.{ 16, 32, 64, 128, 256, 512, 1024, 2048 }) |N| {
        const P = polymod.Poly(N);
        // Repeat rather than enlarge: keep the working set at two polys.
        const reps: usize = if (N <= 128) 1000 else if (N <= 512) 100 else 25;
        var ra: [N]u32 = undefined;
        var rb: [N]u32 = undefined;
        for (&ra) |*x| x.* = rnd.int(u32);
        for (&rb) |*x| x.* = rnd.int(u32);
        const a = P.fromCoeffs(ra);
        const b = P.fromCoeffs(rb);

        // Correctness gate on the timed values themselves: if the optimiser
        // folded either path away, or the paths disagree, this fails.
        // Call the transform DIRECTLY rather than through `mul`: otherwise
        // every degree below `ntt_min_degree` would time schoolbook against
        // schoolbook and the table could never show WHERE the crossover is —
        // which is the one thing this sweep exists to answer.
        try std.testing.expectEqualSlices(u32, &P.mulSchoolbook(&a, &b).c, &ntt.Engine(N).mulTorus(&a.c, &b.c));

        // Methodology: each iteration feeds the previous result back into the
        // input, so neither loop is loop-invariant and neither can be hoisted;
        // the two paths alternate and the MINIMUM of three passes is taken, so
        // a cold first pass cannot manufacture a speedup. (Without this, the
        // degrees BELOW the dispatch threshold — where both calls are literally
        // the same function — reported a 1.15x "speedup", which is the size of
        // the bias this removes.)
        var sink: u32 = 1;
        var slow_min: u64 = std.math.maxInt(u64);
        var fast_min: u64 = std.math.maxInt(u64);
        var aa = a;
        for (0..3) |_| {
            const t0 = nowNs();
            for (0..reps) |_| {
                aa.c[1] = sink;
                sink +%= P.mulSchoolbook(&aa, &b).c[0];
            }
            const t1 = nowNs();
            for (0..reps) |_| {
                aa.c[1] = sink;
                sink +%= ntt.Engine(N).mulTorus(&aa.c, &b.c)[0];
            }
            const t2 = nowNs();
            slow_min = @min(slow_min, t1 - t0);
            fast_min = @min(fast_min, t2 - t1);
        }
        std.mem.doNotOptimizeAway(sink);

        const slow_ns = @as(f64, @floatFromInt(slow_min)) / @as(f64, @floatFromInt(reps));
        const fast_ns = @as(f64, @floatFromInt(fast_min)) / @as(f64, @floatFromInt(reps));
        std.debug.print("{d:>5} {d:>12.2}ns {d:>10.2}ns {d:>8.2}x\n", .{ N, slow_ns, fast_ns, slow_ns / fast_ns });
    }
    std.debug.print("  (dispatch threshold poly.ntt_min_degree = {d})\n", .{polymod.ntt_min_degree});
}

test "bench: end-to-end gate bootstrap at the toy parameter set" {
    if (!enabled()) return error.SkipZigTest;

    const Toy = tfhe.Tfhe(params.toy);
    var prng = std.Random.DefaultPrng.init(0xB007);
    const rnd = prng.random();
    const small = Toy.lweKeyGenForTest(64, rnd);
    const glwe = Toy.glweKeyGenForTest(rnd);
    var bsk = try Toy.bootstrapKeyGenForTest(std.testing.allocator, &small, &glwe, rnd);
    defer bsk.deinit(std.testing.allocator);
    var ksk = try Toy.keySwitchKeyGenForTest(std.testing.allocator, &glwe, &small, rnd);
    defer ksk.deinit(std.testing.allocator);

    // Identity LUT over a 2-slot message space — the same one the harness's
    // end-to-end anchor uses.
    const id = Toy.testPolynomial(2, .{ Toy.encodeBit(0), Toy.encodeBit(1) });

    const ct = Toy.lweEncryptForTest(64, &small, Toy.encodeBit(1), rnd);
    const reps: usize = 10;
    var sink: u32 = 0;
    const t0 = nowNs();
    for (0..reps) |_| sink +%= Toy.bootstrap(&bsk, &ksk, &id, &ct).b;
    const t1 = nowNs();
    std.mem.doNotOptimizeAway(sink);

    const per_ms = @as(f64, @floatFromInt(t1 - t0)) / @as(f64, @floatFromInt(reps)) / 1.0e6;
    // n·2·(2ℓ) ring multiplies per bootstrap: one per GGSW row per component.
    const muls = params.toy.n * 2 * (2 * params.toy.ell);
    std.debug.print("\n  bootstrap (N={d}, n={d}): {d:.2} ms  [{d} ring muls/boot]\n", .{
        params.toy.N, params.toy.n, per_ms, muls,
    });
    // The bootstrap must still be CORRECT at the speed it just reported.
    try std.testing.expectEqual(@as(u32, 1), Toy.lweDecryptBit(64, &small, &Toy.bootstrap(&bsk, &ksk, &id, &ct)));
}

test "bench: boolean gates at tfhers_default (tfhe-rs DEFAULT_PARAMETERS)" {
    if (!enabled()) return error.SkipZigTest;

    const D = tfhe.Tfhe(params.tfhers_default);
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = std.testing.allocator;

    const t0 = nowNs();
    var ck = D.ClientKey.generate(io);
    defer ck.deinit();
    var bsk = try D.bootstrapKeyGen(gpa, &ck.lwe, &ck.glwe, io);
    defer bsk.deinit(gpa);
    const t1 = nowNs();
    const ksk = try D.keySwitchKeyGen(gpa, &ck.glwe, &ck.lwe, io);
    const t2 = nowNs();
    var sk = try D.ServerKey.fromKeys(gpa, &bsk, ksk);
    defer sk.deinit(gpa);
    const t3 = nowNs();

    const a = ck.encrypt(true, io);
    const b = ck.encrypt(false, io);
    const reps = 5;
    var r: D.LweN = undefined;
    const g0 = nowNs();
    for (0..reps) |_| r = sk.@"and"(&a, &b);
    const g1 = nowNs();
    for (0..reps) |_| r = sk.mux(&a, &b, &a);
    const g2 = nowNs();
    try std.testing.expect(!ck.decrypt(&r));
    try std.testing.expect(!ck.decrypt(&sk.@"and"(&a, &b)));

    const ms = struct {
        fn f(x: u64, y: u64) f64 {
            return @as(f64, @floatFromInt(y - x)) / 1.0e6;
        }
    }.f;
    std.debug.print("\n  tfhers_default: bsk keygen {d:.0} ms, ksk keygen {d:.0} ms, prepare {d:.0} ms; AND {d:.1} ms, MUX {d:.1} ms\n", .{
        ms(t0, t1), ms(t1, t2), ms(t2, t3), ms(g0, g1) / reps, ms(g1, g2) / reps,
    });
}
