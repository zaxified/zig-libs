// SPDX-License-Identifier: MIT

//! bench — the A/B timing helper behind this module's opt-in speed tests.
//! Off by default; opt in with `BLS12_381_BENCH`:
//!
//!   BLS12_381_BENCH=1 zig build test-bls12_381 -Doptimize=ReleaseFast -Dtest-filter=bench
//!
//! Each optimisation keeps the form it replaced as its test oracle; the bench
//! test next to it times the two INTERLEAVED (A, B, A, B, … over `rounds`
//! rounds, best of each), so a noisy host moves both sides alike and the
//! printed ratio B/A is the claim. Linux only (monotonic clock).

const std = @import("std");
const builtin = @import("builtin");

/// Whether the opt-in bench is on for this run.
pub fn enabled() bool {
    return builtin.target.os.tag == .linux and std.testing.environ.getPosix("BLS12_381_BENCH") != null;
}

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

/// Time `a(ctx)` and `b(ctx)` interleaved, `iters` calls per sample, `rounds`
/// samples each; print the best µs/op of each side and the ratio b/a.
pub fn ab(
    comptime label: []const u8,
    comptime iters: usize,
    ctx: anytype,
    comptime a: fn (@TypeOf(ctx)) void,
    comptime b: fn (@TypeOf(ctx)) void,
) void {
    const rounds = 7;
    var best_a: u64 = std.math.maxInt(u64);
    var best_b: u64 = std.math.maxInt(u64);
    var worst_a: u64 = 0;
    var worst_b: u64 = 0;
    for (0..rounds) |_| {
        var t0 = nowNs();
        for (0..iters) |_| a(ctx);
        const da = nowNs() - t0;
        t0 = nowNs();
        for (0..iters) |_| b(ctx);
        const db = nowNs() - t0;
        best_a = @min(best_a, da);
        best_b = @min(best_b, db);
        worst_a = @max(worst_a, da);
        worst_b = @max(worst_b, db);
    }
    const fa: f64 = @floatFromInt(best_a);
    const fb: f64 = @floatFromInt(best_b);
    const n: f64 = @floatFromInt(iters);
    std.debug.print("bench {s}: A {d:.1} us  B {d:.1} us  B/A {d:.3}  (spread A {d:.1}%, B {d:.1}%)\n", .{
        label,
        fa / n / 1000.0,
        fb / n / 1000.0,
        fb / fa,
        (@as(f64, @floatFromInt(worst_a)) - fa) / fa * 100.0,
        (@as(f64, @floatFromInt(worst_b)) - fb) / fb * 100.0,
    });
}
