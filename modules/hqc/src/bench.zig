// SPDX-License-Identifier: MIT

//! bench — KEM operation timings. Off by default; opt in with `HQC_BENCH`:
//!
//!   HQC_BENCH=1 scripts/capped zig build test-hqc -Doptimize=ReleaseFast -Dcpu=native
//!
//! ## Why this file exists
//!
//! It was written 2026-09-09 to price ONE change: the `asm volatile` mask
//! barrier in `prng.writeSupportToVector`. That barrier is what stops LLVM
//! turning the module's masked scatter back into a secret-dependent branch
//! (38 of `decaps`'s 52 ctgrind contexts, see `SPEC.md`), and it sits in the
//! innermost loop of a scan that runs `omega × words` times per call — about
//! 18 000 iterations for hqc-128. A barrier there is exactly the shape that
//! can block vectorisation, so "it is only one line" is not an argument; the
//! cost had to be a number.
//!
//! ⛔ A barrier's cost cannot be measured by timing the module ONCE. Both arms
//! have to come from the same binary shape and the same machine minutes, so
//! this reports a MINIMUM over repetitions rather than a mean: the minimum is
//! the run least disturbed by the scheduler, and on a mobile CPU the mean is
//! mostly thermal history. Compare arms by re-running with the barrier removed
//! and diffing these numbers; do not compare against a figure written down on
//! another day.
//!
//! Working sets are single key pairs and single ciphertexts — a few kilobytes.
//! Nothing here allocates a large buffer, deliberately: an oversized benchmark
//! in this repository once OOM-killed the host's editor.

const std = @import("std");
const root = @import("root.zig");

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

/// Minimum wall time over `reps` calls, in nanoseconds.
fn minNs(comptime reps: usize, comptime f: fn () void) u64 {
    var best: u64 = std.math.maxInt(u64);
    var i: usize = 0;
    while (i < reps) : (i += 1) {
        const t0 = nowNs();
        f();
        const dt = nowNs() - t0;
        if (dt < best) best = dt;
    }
    return best;
}

test "bench (opt-in via HQC_BENCH)" {
    if (@import("builtin").target.os.tag == .windows or
        std.testing.environ.getPosix("HQC_BENCH") == null) return error.SkipZigTest;

    const Kem = root.Hqc128;
    const seed = [_]u8{0x5a} ** 32;
    const coins = [_]u8{0xa5} ** Kem.coins_bytes;

    const kp = Kem.keypair(&seed);
    const enc = Kem.encaps(kp.ek, &coins);

    const S = struct {
        var kp_ek: Kem.EncapsKey = undefined;
        var kp_dk: Kem.DecapsKey = undefined;
        var ct: Kem.Ciphertext = undefined;
        var sd: [32]u8 = undefined;
        var cn: [Kem.coins_bytes]u8 = undefined;

        fn benchKeypair() void {
            const r = Kem.keypair(&sd);
            std.mem.doNotOptimizeAway(r.ek[0]);
        }
        fn benchEncaps() void {
            const r = Kem.encaps(kp_ek, &cn);
            std.mem.doNotOptimizeAway(r.ct[0]);
        }
        fn benchDecaps() void {
            const r = Kem.decaps(kp_dk, ct);
            std.mem.doNotOptimizeAway(r[0]);
        }
    };
    S.kp_ek = kp.ek;
    S.kp_dk = kp.dk;
    S.ct = enc.ct;
    S.sd = seed;
    S.cn = coins;

    const reps = 200;
    const kg = minNs(reps, S.benchKeypair);
    const en = minNs(reps, S.benchEncaps);
    const de = minNs(reps, S.benchDecaps);

    std.debug.print(
        \\
        \\hqc-128 (min of {d} runs, ns/op)
        \\  keypair {d:>10}
        \\  encaps  {d:>10}
        \\  decaps  {d:>10}
        \\
    , .{ reps, kg, en, de });
}

// Workload for a sampling profile (audit M4). Off by default; opt in with
// `HQC_PROFILE`. `scripts/vm/run.sh hqc` builds it ReleaseFast for the host
// CPU and runs it under `perf record` as root in a disposable guest, because
// the dev host's `perf_event_paranoid=4` refuses perf to users.
//
// Each operation loops inside its own `noinline` wrapper. ReleaseFast inlines
// everything beneath them, so without the wrappers a flat profile could not
// tell keypair from encaps from decaps; `perf report --sort sym,srcline` then
// splits each wrapper by source line. Iteration counts are sized for a few
// thousand samples per operation at a few kHz, not for timing — use the
// `HQC_BENCH` test above for numbers to compare.
//
// `HQC_PROFILE=keypair|encaps|decaps` runs that one operation, so each gets a
// `perf record` of its own and nothing needs a call graph to split them; any
// other value runs all three.
test "profile workload for perf (opt-in via HQC_PROFILE)" {
    if (@import("builtin").target.os.tag == .windows) return error.SkipZigTest;
    const sel = std.testing.environ.getPosix("HQC_PROFILE") orelse return error.SkipZigTest;
    const only = for ([_][]const u8{ "keypair", "encaps", "decaps" }) |name| {
        if (std.mem.eql(u8, sel, name)) break name;
    } else null;

    const Kem = root.Hqc128;
    const P = struct {
        var ek: Kem.EncapsKey = undefined;
        var dk: Kem.DecapsKey = undefined;
        var ct: Kem.Ciphertext = undefined;
        var sd: [32]u8 = [_]u8{0x5a} ** 32;
        var cn: [Kem.coins_bytes]u8 = [_]u8{0xa5} ** Kem.coins_bytes;

        noinline fn profKeypair(n: usize) void {
            for (0..n) |_| std.mem.doNotOptimizeAway(Kem.keypair(&sd).ek[0]);
        }
        noinline fn profEncaps(n: usize) void {
            for (0..n) |_| std.mem.doNotOptimizeAway(Kem.encaps(ek, &cn).ct[0]);
        }
        noinline fn profDecaps(n: usize) void {
            for (0..n) |_| std.mem.doNotOptimizeAway(Kem.decaps(dk, ct)[0]);
        }
    };
    const kp = Kem.keypair(&P.sd);
    P.ek = kp.ek;
    P.dk = kp.dk;
    P.ct = Kem.encaps(kp.ek, &P.cn).ct;

    const n = 4000;
    const ops = [_]struct { name: []const u8, run: *const fn (usize) void }{
        .{ .name = "keypair", .run = P.profKeypair },
        .{ .name = "encaps", .run = P.profEncaps },
        .{ .name = "decaps", .run = P.profDecaps },
    };
    for (ops) |op| {
        if (only) |o| if (!std.mem.eql(u8, o, op.name)) continue;
        const t0 = nowNs();
        op.run(n);
        // Under `perf record` this includes the sampling overhead, which in a
        // KVM guest is large; it is a sanity check, not a benchmark.
        std.debug.print("\nhqc-128 profile workload: {s} x{d}, {d} ns/op\n", .{ op.name, n, (nowNs() - t0) / n });
    }
}
