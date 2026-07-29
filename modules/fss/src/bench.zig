// SPDX-License-Identifier: MIT

//! bench — opt-in measurement of `evalFull` (tree-reuse prefix evaluation)
//! against the per-point `eval` loop it replaces in consumers:
//!
//!   FSS_BENCH=1 zig build test-fss -Doptimize=ReleaseFast
//!
//! Two shapes, matching the two ways `pir` drives the DPF:
//!   - full domain: `Dpf(16, 8)`, all 65536 points — the `O(N·n)` vs `O(N)`
//!     PRG-call asymptotic, measured;
//!   - short prefix in a big domain: `Dpf(20, 8)`, first 500 points of a 2^20
//!     domain — pins that `evalFull`'s cost follows the PREFIX length, not the
//!     domain size (the pir "generously-sized domain" case).
//!
//! Each route's output is asserted equal to the other before timing is
//! trusted, so the two timings are provably timings of the same computation.
//! Numbers are noisy on mobile CPUs (turbo/thermal); treat them as ratios.

const std = @import("std");
const fss = @import("root.zig");

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

fn benchCase(
    comptime D: type,
    comptime label: []const u8,
    comptime prefix_len: usize,
    alpha: D.Index,
    naive: []D.Elem,
    fast: []D.Elem,
) !void {
    const s0 = [_]u8{0x3C} ** 16;
    const s1 = [_]u8{0xC3} ** 16;
    const keys = D.genWithSeeds(alpha, 1, s0, s1);

    // correctness first: both routes must agree, or the timing is of nothing
    for (0..prefix_len) |x| naive[x] = D.eval(0, keys[0], @intCast(x));
    D.evalFull(0, keys[0], fast[0..prefix_len]);
    try std.testing.expectEqualSlices(D.Elem, naive[0..prefix_len], fast[0..prefix_len]);

    const reps = 3;
    var t_naive: u64 = std.math.maxInt(u64);
    var t_fast: u64 = std.math.maxInt(u64);
    var sink: D.Elem = 0;
    for (0..reps) |_| {
        const a = nowNs();
        for (0..prefix_len) |x| naive[x] = D.eval(0, keys[0], @intCast(x));
        const b = nowNs();
        D.evalFull(0, keys[0], fast[0..prefix_len]);
        const c = nowNs();
        t_naive = @min(t_naive, b - a);
        t_fast = @min(t_fast, c - b);
        sink ^= naive[prefix_len - 1] ^ fast[prefix_len - 1];
    }
    std.mem.doNotOptimizeAway(sink);
    std.debug.print(
        "{s}: eval-loop {d:>10} ns  evalFull {d:>9} ns  ({d} pts, {d:.1} ns/pt vs {d:.1} ns/pt, speedup {d:.1}x)\n",
        .{
            label,
            t_naive,
            t_fast,
            prefix_len,
            @as(f64, @floatFromInt(t_naive)) / prefix_len,
            @as(f64, @floatFromInt(t_fast)) / prefix_len,
            @as(f64, @floatFromInt(t_naive)) / @as(f64, @floatFromInt(t_fast)),
        },
    );
}

test "bench (opt-in via FSS_BENCH)" {
    if (std.testing.environ.getPosix("FSS_BENCH") == null) return error.SkipZigTest;
    std.debug.print("\n=== fss evalFull vs per-point eval ===\n", .{});
    const gpa = std.heap.page_allocator;

    // full domain, n=16
    {
        const D = fss.Dpf(16, 8);
        const naive = try gpa.alloc(D.Elem, D.domain_size);
        defer gpa.free(naive);
        const fast = try gpa.alloc(D.Elem, D.domain_size);
        defer gpa.free(fast);
        try benchCase(D, "n=16 full 2^16", D.domain_size, 12345, naive, fast);
    }
    // short prefix of a 2^20 domain
    {
        const D = fss.Dpf(20, 8);
        const naive = try gpa.alloc(D.Elem, 500);
        defer gpa.free(naive);
        const fast = try gpa.alloc(D.Elem, 500);
        defer gpa.free(fast);
        try benchCase(D, "n=20 prefix 500", 500, 123, naive, fast);
    }
}
