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

/// The multi-point analogue: the interleaved `k`-tree walk against the
/// per-point `evalEach` loop it replaces in `pir.Multi(k)`'s server. Same
/// discipline — the two routes' outputs are asserted equal, element for
/// element and instance for instance, before either timing is trusted.
fn benchMulti(
    comptime M: type,
    comptime label: []const u8,
    prefix_len: usize,
    naive: []M.Elem, // prefix_len * k
    fast: []M.Elem, // prefix_len * k
) !void {
    const k = M.points;
    var alphas: [k]M.Index = undefined;
    var betas: [k]M.Elem = undefined;
    var s0: [k][16]u8 = undefined;
    var s1: [k][16]u8 = undefined;
    for (0..k) |j| {
        alphas[j] = @intCast((j * 37 + 11) % M.domain_size);
        betas[j] = 1;
        s0[j] = @splat(@truncate(j * 2 + 1));
        s1[j] = @splat(@truncate(j * 2 + 128));
    }
    const keys = try M.genWithSeeds(alphas, betas, s0, s1);

    const Sink = struct {
        out: []M.Elem,
        fn emit(self: @This(), x: usize, shares: *const [k]M.Elem) void {
            for (shares, 0..) |v, j| self.out[x * k + j] = v;
        }
    };
    const naiveRoute = struct {
        fn run(key: M.Key, out: []M.Elem, count: usize) void {
            var each: [k]M.Elem = undefined;
            for (0..count) |x| {
                M.evalEach(0, key, @intCast(x), &each);
                for (each, 0..) |v, j| out[x * k + j] = v;
            }
        }
    }.run;

    naiveRoute(keys[0], naive, prefix_len);
    M.evalEachFullWith(0, keys[0], prefix_len, Sink{ .out = fast }, Sink.emit);
    try std.testing.expectEqualSlices(M.Elem, naive[0 .. prefix_len * k], fast[0 .. prefix_len * k]);

    const reps = 3;
    var t_naive: u64 = std.math.maxInt(u64);
    var t_fast: u64 = std.math.maxInt(u64);
    var sink: M.Elem = 0;
    for (0..reps) |_| {
        const a = nowNs();
        naiveRoute(keys[0], naive, prefix_len);
        const b = nowNs();
        M.evalEachFullWith(0, keys[0], prefix_len, Sink{ .out = fast }, Sink.emit);
        const c = nowNs();
        t_naive = @min(t_naive, b - a);
        t_fast = @min(t_fast, c - b);
        sink ^= naive[prefix_len * k - 1] ^ fast[prefix_len * k - 1];
    }
    std.mem.doNotOptimizeAway(sink);
    std.debug.print(
        "{s}: evalEach-loop {d:>10} ns  interleaved {d:>9} ns  ({d} pts x k={d}, speedup {d:.1}x)\n",
        .{
            label,
            t_naive,
            t_fast,
            prefix_len,
            k,
            @as(f64, @floatFromInt(t_naive)) / @as(f64, @floatFromInt(t_fast)),
        },
    );
}

/// SHA-256 PRG vs fixed-key-AES PRG, at the three granularities that matter:
/// the raw expansion, a full `Gen` (keys/sec), and a full-domain `evalFull`
/// (evaluations/sec). Deliberately small buffers and many repetitions — the
/// point is throughput per operation, not a big allocation.
fn benchPrgPair(comptime n_bits: usize) !void {
    const reps = 3;

    inline for (.{ fss.prg.Sha256Prg, fss.prg.Aes128Mmo }) |P| {
        const D = fss.DpfWith(P, n_bits, 8);
        const s0 = [_]u8{0x3C} ** 16;
        const s1 = [_]u8{0xC3} ** 16;

        // (a) raw PRG expansions
        const expansions = 1 << 20;
        var t_prg: u64 = std.math.maxInt(u64);
        var acc: u8 = 0;
        for (0..reps) |_| {
            const p = P.init();
            var seed: [16]u8 = @splat(0x17);
            const a = nowNs();
            for (0..expansions) |_| {
                const e = p.expand(seed);
                seed = e.s_l;
            }
            const b = nowNs();
            t_prg = @min(t_prg, b - a);
            acc ^= seed[0];
        }

        // (b) Gen
        const gens = 1 << 12;
        var t_gen: u64 = std.math.maxInt(u64);
        for (0..reps) |_| {
            const a = nowNs();
            for (0..gens) |i| {
                const keys = D.genWithSeeds(@intCast(i % D.domain_size), 1, s0, s1);
                acc ^= keys[0].cw[0].s_cw[0];
            }
            const b = nowNs();
            t_gen = @min(t_gen, b - a);
        }

        // (c) evalFull over the whole (small) domain
        var out: [1 << n_bits]D.Elem = undefined;
        const keys = D.genWithSeeds(7, 1, s0, s1);
        var t_eval: u64 = std.math.maxInt(u64);
        for (0..reps) |_| {
            const a = nowNs();
            for (0..16) |_| D.evalFull(0, keys[0], &out);
            const b = nowNs();
            t_eval = @min(t_eval, b - a);
        }
        std.mem.doNotOptimizeAway(acc);
        std.mem.doNotOptimizeAway(out[0]);

        const per = struct {
            fn rate(count: u64, ns: u64) f64 {
                return @as(f64, @floatFromInt(count)) * 1e9 / @as(f64, @floatFromInt(ns));
            }
        }.rate;
        std.debug.print(
            "{s:<11} expand {d:>12.0}/s   Gen(n={d}) {d:>10.0} keys/s   evalFull {d:>12.0} evals/s\n",
            .{
                P.id,
                per(expansions, t_prg),
                n_bits,
                per(gens, t_gen),
                per(16 * (1 << n_bits), t_eval),
            },
        );
    }
}

test "bench (opt-in via FSS_BENCH)" {
    if (@import("builtin").target.os.tag == .windows or std.testing.environ.getPosix("FSS_BENCH") == null) return error.SkipZigTest;

    std.debug.print(
        "\n=== fss PRG: SHA-256 vs fixed-key AES (hardware AES: {}) ===\n",
        .{std.crypto.core.aes.has_hardware_support},
    );
    try benchPrgPair(12);

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

    std.debug.print("\n=== fss Mpf interleaved k-tree walk vs per-point evalEach ===\n", .{});
    // full domain, n=14, k=4 (deliberately small: the naive route is
    // k·N·n hashes and this file must stay a few seconds, not minutes)
    {
        const M = fss.Mpf(14, 8, 4);
        const n = M.domain_size * M.points;
        const naive = try gpa.alloc(M.Elem, n);
        defer gpa.free(naive);
        const fast = try gpa.alloc(M.Elem, n);
        defer gpa.free(fast);
        try benchMulti(M, "n=14 k=4 full 2^14", M.domain_size, naive, fast);
    }
    // the pir shape: a small record count inside a generously sized domain
    {
        const M = fss.Mpf(20, 8, 8);
        const n = 500 * M.points;
        const naive = try gpa.alloc(M.Elem, n);
        defer gpa.free(naive);
        const fast = try gpa.alloc(M.Elem, n);
        defer gpa.free(fast);
        try benchMulti(M, "n=20 k=8 prefix 500", 500, naive, fast);
    }
}
