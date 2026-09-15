// SPDX-License-Identifier: MIT

//! bench — µs/op micro-benchmarks for ct25519 (audit C9: the module had no
//! benchmark and no recorded number, so C3's 2.81× gap had nowhere to show
//! up and nowhere to regress). Off by default; opt in with `CT25519_BENCH`:
//!
//!   CT25519_BENCH=1 scripts/modtest ct25519 -Doptimize=ReleaseFast
//!
//! ⚠ Numbers only mean something at ReleaseFast; the header line prints the
//! mode so a Debug run cannot be mistaken for one.
//!
//! Every comparison is an A/B INSIDE one process: each subject pair is run
//! in interleaved rounds with alternating order, CPU time per op, and the
//! table prints median, min and max per arm plus the paired ratio range —
//! because a single number from a shared machine is a single instant, not a
//! measurement. The pairs:
//!
//! - `mulBase` (fixed-base comb, C3) vs `mul(basePoint, s)` — the window
//!   ladder over the comptime table, which IS the pre-C3 `mulBase`;
//! - `mulRistrettoBase` (comb) vs `mulRistretto(basePoint, s)` (ladder);
//! - `mulRistretto` over a runtime point (ladder, unchanged by C3) vs std's
//!   `Ristretto255.mul` — the control pair: C3 changed neither side, so its
//!   ratio should sit near 1 and a drift there says the machine moved.
//!
//! Each op's output byte is folded into a printed checksum so the optimiser
//! cannot drop the work (a loop whose result nobody reads measures nothing).

const std = @import("std");
const builtin = @import("builtin");
const ct = @import("root.zig");

const Edwards25519 = ct.Edwards25519;
const Ristretto255 = ct.Ristretto255;

fn cpuNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.PROCESS_CPUTIME_ID, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn lessThan(_: void, a: f64, b: f64) bool {
    return a < b;
}

const rounds = 7;
const nscalars = 64;

const Op = enum { comb_base, ladder_base, comb_ristretto, ladder_ristretto, ladder_var, std_var };

fn run(op: Op, iters: usize, scalars: *const [nscalars][32]u8, pv: Ristretto255) u8 {
    var acc: u8 = 0;
    for (0..iters) |i| {
        const s = scalars[i % nscalars];
        const b: [32]u8 = switch (op) {
            .comb_base => ct.mulBase(s).toBytes(),
            .ladder_base => ct.mul(Edwards25519.basePoint, s).toBytes(),
            .comb_ristretto => ct.mulRistrettoBase(s).toBytes(),
            .ladder_ristretto => ct.mulRistretto(Ristretto255.basePoint, s).toBytes(),
            .ladder_var => ct.mulRistretto(pv, s).toBytes(),
            .std_var => (pv.mul(s) catch unreachable).toBytes(),
        };
        acc ^= b[i % 32];
    }
    return acc;
}

fn pair(name: []const u8, a: Op, b: Op, iters: usize, scalars: *const [nscalars][32]u8, pv: Ristretto255) u8 {
    var ua: [rounds]f64 = undefined;
    var ub: [rounds]f64 = undefined;
    var chk: u8 = run(a, iters / 4, scalars, pv) ^ run(b, iters / 4, scalars, pv);
    for (0..rounds) |r| {
        for (0..2) |slot| {
            const do_a = (slot == 0) == (r % 2 == 0);
            const t0 = cpuNs();
            chk ^= run(if (do_a) a else b, iters, scalars, pv);
            const us = @as(f64, @floatFromInt(cpuNs() - t0)) / 1000.0 / @as(f64, @floatFromInt(iters));
            if (do_a) ua[r] = us else ub[r] = us;
        }
    }
    var ratio: [rounds]f64 = undefined;
    for (&ratio, ua, ub) |*q, x, y| q.* = y / x;
    std.mem.sort(f64, &ua, {}, lessThan);
    std.mem.sort(f64, &ub, {}, lessThan);
    std.mem.sort(f64, &ratio, {}, lessThan);
    const m = rounds / 2;
    std.debug.print("{s:<28} {t:<16} {d:>7.1} [{d:.1}..{d:.1}]   {t:<16} {d:>7.1} [{d:.1}..{d:.1}]   B/A median {d:.2}x  paired [{d:.2}..{d:.2}]\n", .{
        name, a, ua[m], ua[0], ua[rounds - 1], b, ub[m], ub[0], ub[rounds - 1], ub[m] / ua[m], ratio[0], ratio[rounds - 1],
    });
    return chk;
}

test "bench (opt-in via CT25519_BENCH)" {
    if (builtin.target.os.tag != .linux or std.testing.environ.getPosix("CT25519_BENCH") == null) return error.SkipZigTest;
    std.debug.print("\n=== ct25519 bench (mode={t}, {d} rounds interleaved, µs/op CPU time, median [min..max]) ===\n", .{ builtin.mode, rounds });
    var prng = std.Random.DefaultPrng.init(0xC3_BE_4C);
    const random = prng.random();
    var scalars: [nscalars][32]u8 = undefined;
    for (&scalars) |*s| random.bytes(s);
    for (&scalars) |*s| s.* = Edwards25519.scalar.reduce(s.*); // std refuses nothing reduced and nonzero
    const pv = try Ristretto255.fromBytes((try Ristretto255.basePoint.mul([_]u8{7} ++ [_]u8{0} ** 31)).toBytes());

    const iters = 2000;
    var chk: u8 = 0;
    chk ^= pair("base point, Edwards", .comb_base, .ladder_base, iters, &scalars, pv);
    chk ^= pair("base point, ristretto255", .comb_ristretto, .ladder_ristretto, iters, &scalars, pv);
    chk ^= pair("runtime point (control)", .ladder_var, .std_var, iters, &scalars, pv);
    std.debug.print("checksum={d}\n", .{chk});
}
